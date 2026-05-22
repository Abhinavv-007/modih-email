// GET /api/inbox/mine — return signed-in user's inboxes and address history.
//
// Powers account history and cross-device sync. Live inboxes come from the
// inboxes table; durable address history comes from admin_events so expired or
// deleted temporary inboxes can still appear as previous addresses.

import { verifyFirebaseToken } from "../../_auth-helper.js";
import { ok, err } from "../../_api-helpers.js";

export async function onRequestGet(context) {
  const { env, request } = context;
  try {
    const authHeader = request.headers.get("Authorization") || "";
    if (!authHeader.startsWith("Bearer ")) {
      return err("UNAUTHORIZED", "Sign in required.", 401);
    }
    const token = authHeader.slice(7).trim();
    if (!token) return err("UNAUTHORIZED", "Sign in required.", 401);

    const user = await verifyFirebaseToken(token);
    if (!user?.uid) return err("UNAUTHORIZED", "Invalid auth token.", 401);

    const planRow = await env.DB
      .prepare("SELECT plan FROM user_plans WHERE uid = ?")
      .bind(user.uid)
      .first();
    const plan = ["pro", "developer"].includes(planRow?.plan) ? planRow.plan : "free";

    const now = Math.floor(Date.now() / 1000);
    // We tolerate the `reserved` column being missing on older deploys.
    let rows;
    try {
      const result = await env.DB
        .prepare(
          `SELECT id, email, created_at, expires_at, reserved
             FROM inboxes
            WHERE creator_uid = ?
              AND (expires_at = 0 OR expires_at > ?)
            ORDER BY created_at DESC`
        )
        .bind(user.uid, now)
        .all();
      rows = result.results || [];
    } catch (error) {
      if (!String(error?.message || "").includes("reserved")) throw error;
      const result = await env.DB
        .prepare(
          `SELECT id, email, created_at, expires_at
             FROM inboxes
            WHERE creator_uid = ?
              AND (expires_at = 0 OR expires_at > ?)
            ORDER BY created_at DESC`
        )
        .bind(user.uid, now)
        .all();
      rows = (result.results || []).map((r) => ({ ...r, reserved: 0 }));
    }

    const inboxes = rows.map((r) => ({
      id:         r.id,
      email:      r.email,
      created_at: r.created_at,
      expires_at: r.expires_at,
      reserved:   !!r.reserved,
      active:     true,
    }));

    const history = await getAddressHistory(env.DB, user.uid, now, inboxes);

    return ok({
      inboxes,
      history,
      count: inboxes.length,
      history_count: history.length,
      plan,
    });
  } catch (e) {
    console.error("[inbox/mine] error:", e?.message);
    return err("INTERNAL_ERROR", "Failed to load inboxes.", 500);
  }
}

async function getAddressHistory(db, uid, now, activeInboxes) {
  let rows = [];
  try {
    const result = await selectHistoryRows(db, uid, now, true);
    rows = result.results || [];
  } catch (error) {
    // Older local/dev databases may not have admin_events yet. Live inbox sync
    // still works; durable history begins once the migration exists.
    const message = String(error?.message || "");
    if (message.includes("reserved")) {
      const result = await selectHistoryRows(db, uid, now, false);
      rows = result.results || [];
    } else if (message.includes("admin_events")) {
      rows = [];
    } else {
      throw error;
    }
  }

  const byId = new Map();
  for (const row of rows) {
    const id = row.id || row.email;
    if (!id || byId.has(id)) continue;
    byId.set(id, {
      id:         row.id || id,
      email:      row.email,
      created_at: Number(row.created_at) || 0,
      expires_at: Number(row.expires_at) || 0,
      reserved:   !!row.reserved,
      active:     !!row.active,
    });
  }

  // Include live rows created before admin_events existed.
  for (const inbox of activeInboxes) {
    if (!inbox?.id || byId.has(inbox.id)) continue;
    byId.set(inbox.id, { ...inbox, active: true });
  }

  return Array.from(byId.values())
    .filter((item) => item.email)
    .sort((a, b) => (b.created_at || 0) - (a.created_at || 0))
    .slice(0, 100);
}

function selectHistoryRows(db, uid, now, includeReserved) {
  const reservedExpr = includeReserved ? "IFNULL(i.reserved, 0)" : "0";
  return db
    .prepare(
      `SELECT
          e.inbox_id AS id,
          e.inbox_email AS email,
          e.created_at AS created_at,
          i.expires_at AS expires_at,
          ${reservedExpr} AS reserved,
          CASE
            WHEN i.id IS NOT NULL AND (i.expires_at = 0 OR i.expires_at > ?)
            THEN 1 ELSE 0
          END AS active
         FROM admin_events e
         LEFT JOIN inboxes i ON i.id = e.inbox_id
        WHERE e.event_type = 'inbox_created'
          AND e.uid = ?
          AND COALESCE(e.inbox_email, '') != ''
        ORDER BY e.created_at DESC
        LIMIT 200`
    )
    .bind(now, uid)
    .all();
}
