/**
 * GET /api/admin/address                 → list recent issued addresses
 * GET /api/admin/address?q=<search>       → search issued addresses
 * GET /api/admin/address?email=<address>  → full detail for one address
 *
 * Admin-only. Answers, in one place: which user created which address, when,
 * from where, whether it is still live or already expired, and every message
 * that address has received (current messages + historical receipts from
 * admin_events, which survive inbox cleanup).
 *
 * The permanent used_addresses ledger is the source of truth for "every
 * address ever issued", so expired-and-cleaned addresses remain visible here.
 * Never returns message bodies — only metadata (from / subject / time / OTP).
 */
import { checkAdminAuth } from "../../_admin-auth.js";
import { secureId } from "../../_api-helpers.js";

async function safeAll(env, sql, ...binds) {
  try {
    if (!env?.DB) return [];
    const stmt = env.DB.prepare(sql);
    const r = await (binds.length ? stmt.bind(...binds) : stmt).all();
    return r?.results ?? [];
  } catch {
    return [];
  }
}

async function safeFirst(env, sql, ...binds) {
  try {
    if (!env?.DB) return null;
    const stmt = env.DB.prepare(sql);
    return await (binds.length ? stmt.bind(...binds) : stmt).first();
  } catch {
    return null;
  }
}

// Read a live inbox row for an address, tolerating a pre-migration schema that
// lacks the `blocked` column (treated as blocked = 0 until the migration runs).
async function getLiveInbox(env, email) {
  const cols = "id, email, creator_uid, creator_email, creator_ip, creator_plan, created_at, expires_at, IFNULL(reserved,0) AS reserved";
  let row = await safeFirst(env, `SELECT ${cols}, IFNULL(blocked,0) AS blocked FROM inboxes WHERE email = ?`, email);
  if (row) return row;
  // Either no row, or the blocked column is missing → retry without it.
  row = await safeFirst(env, `SELECT ${cols} FROM inboxes WHERE email = ?`, email);
  if (row) row.blocked = 0;
  return row;
}

// Basic address shape guard — keeps the LIKE/= lookups tidy and bounded.
function normalizeAddress(raw) {
  const s = String(raw || "").trim().toLowerCase();
  if (s.length < 1 || s.length > 254) return "";
  if (!/^[a-z0-9._%+\-@]+$/.test(s)) return "";
  return s;
}

export async function onRequestGet({ request, env }) {
  const auth = await checkAdminAuth(request, env);
  if (!auth.ok) return auth.response;

  const url = new URL(request.url);
  const now = Math.floor(Date.now() / 1000);

  // Single-message body view (admin can read the full email content).
  const msgId = url.searchParams.get("msg");
  if (msgId) {
    if (!/^[a-zA-Z0-9]{1,40}$/.test(msgId)) return json({ ok: false, error: "bad message id" }, 400);
    const m = await safeFirst(
      env,
      `SELECT id, inbox_id, from_address, from_name, subject, body_html, body_text, received_at FROM messages WHERE id = ?`,
      msgId,
    );
    if (!m) return json({ ok: false, found: false }, 404);
    return json({ ok: true, found: true, message: m });
  }

  const email = normalizeAddress(url.searchParams.get("email") || "");
  if (email) {
    return Response.json(await addressDetail(env, email, now), {
      headers: { "cache-control": "private, no-store" },
    });
  }

  // ── List / search mode ─────────────────────────────────────────────────
  const q = normalizeAddress(url.searchParams.get("q") || "");
  const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit") || "50", 10) || 50, 1), 200);

  const rows = q
    ? await safeAll(
        env,
        `SELECT email, first_used_at, creator_uid, creator_ip
           FROM used_addresses WHERE email LIKE ? ORDER BY first_used_at DESC LIMIT ?`,
        `%${q}%`,
        limit,
      )
    : await safeAll(
        env,
        `SELECT email, first_used_at, creator_uid, creator_ip
           FROM used_addresses ORDER BY first_used_at DESC LIMIT ?`,
        limit,
      );

  const items = await Promise.all(
    rows.map(async (r) => {
      const live = await getLiveInbox(env, r.email);
      const msgCount = await safeFirst(
        env,
        `SELECT COUNT(*) AS n FROM admin_events WHERE event_type = 'message_received' AND inbox_email = ?`,
        r.email,
      );
      return {
        email: r.email,
        first_used_at: r.first_used_at,
        creator_uid: r.creator_uid,
        creator_email: live?.creator_email || null,
        creator_ip: r.creator_ip,
        status: liveStatus(live, now),
        expires_at: live?.expires_at ?? null,
        reserved: live ? Boolean(live.reserved) : false,
        messages_received: msgCount?.n ?? 0,
      };
    }),
  );

  const total = await safeFirst(env, `SELECT COUNT(*) AS n FROM used_addresses`);

  return Response.json(
    {
      service: "modih-mail",
      generatedAt: now,
      total_addresses_ever_issued: total?.n ?? null,
      count: items.length,
      query: q || null,
      addresses: items,
      auth_via: auth.via,
    },
    { headers: { "cache-control": "private, no-store" } },
  );
}

function liveStatus(liveInbox, now) {
  if (!liveInbox) return "expired"; // in ledger but no live inbox row → cleaned up
  if (liveInbox.blocked) return "blocked";
  if (liveInbox.reserved) return "reserved";
  if (liveInbox.expires_at && liveInbox.expires_at > 0 && liveInbox.expires_at <= now) return "expiring";
  return "active";
}

// safeRun executes a mutating statement, tolerating a missing `blocked` column
// on pre-migration schemas by retrying without it where a fallback is provided.
async function safeRun(env, sql, ...binds) {
  const stmt = env.DB.prepare(sql);
  return (binds.length ? stmt.bind(...binds) : stmt).run();
}

const DAY = 24 * 60 * 60;

// ── POST /api/admin/address  { email, action, ttl_days? } ───────────────────
// actions: block | unblock | reactivate | extend
export async function onRequestPost({ request, env }) {
  const auth = await checkAdminAuth(request, env);
  if (!auth.ok) return auth.response;

  let body;
  try { body = await request.json(); } catch { body = {}; }
  const email = normalizeAddress(body.email || "");
  const action = String(body.action || "").toLowerCase();
  const ttlDays = Math.min(Math.max(parseInt(body.ttl_days, 10) || 7, 1), 3650);
  const now = Math.floor(Date.now() / 1000);

  if (!email) return json({ ok: false, error: "email required" }, 400);
  if (!["block", "unblock", "reactivate", "extend"].includes(action)) {
    return json({ ok: false, error: "unknown action" }, 400);
  }

  const ledger = await safeFirst(env, `SELECT email, first_used_at, creator_uid, creator_ip FROM used_addresses WHERE email = ?`, email);
  const live = await safeFirst(env, `SELECT id, creator_uid, creator_email, creator_ip, creator_plan, created_at FROM inboxes WHERE email = ?`, email);

  if (!ledger && !live) return json({ ok: false, error: "address not found" }, 404);

  try {
    if (action === "block") {
      if (!live) return json({ ok: false, error: "address is not live; nothing to block" }, 409);
      await safeRun(env, `UPDATE inboxes SET blocked = 1 WHERE email = ?`, email);
      return json({ ok: true, email, action, status: "blocked" });
    }

    if (action === "unblock" || action === "extend" || action === "reactivate") {
      const newExpiry = now + ttlDays * DAY;
      if (live) {
        if (action === "extend") {
          await safeRun(env, `UPDATE inboxes SET expires_at = ? WHERE email = ?`, newExpiry, email);
        } else {
          // unblock / reactivate both clear the block; reactivate also extends.
          const setExpiry = action === "reactivate" ? `, expires_at = ?` : ``;
          const binds = action === "reactivate" ? [newExpiry, email] : [email];
          await safeRun(env, `UPDATE inboxes SET blocked = 0${setExpiry} WHERE email = ?`, ...binds);
        }
        return json({ ok: true, email, action, expires_at: action === "extend" || action === "reactivate" ? newExpiry : null });
      }

      // No live inbox. Only "reactivate" can bring a cleaned-up address back —
      // recreate a minimal inbox row (admin-owned, fresh expiry, unblocked).
      // The used_addresses ledger already owns the address, so no new row there.
      if (action === "reactivate") {
        const id = "adm" + secureId(13);
        await safeRun(
          env,
          `INSERT INTO inboxes (id, email, owner_token, owner_token_hash, token_version, creator_ip, creator_token, creator_uid, creator_email, creator_plan, created_at, expires_at)
           VALUES (?, ?, '', '', 2, ?, '', ?, ?, ?, ?, ?)`,
          id, email, ledger?.creator_ip || null, ledger?.creator_uid || null, "", "free", now, newExpiry,
        );
        return json({ ok: true, email, action, status: "active", recreated: true, expires_at: newExpiry });
      }
      return json({ ok: false, error: "address is not live" }, 409);
    }

    return json({ ok: false, error: "unhandled action" }, 400);
  } catch (e) {
    return json({ ok: false, error: "action failed: " + (e?.message || "unknown") }, 500);
  }
}

// ── DELETE /api/admin/address?email=… ───────────────────────────────────────
// Deletes the live inbox and its messages. The used_addresses ledger row is
// intentionally KEPT so the address is never reissued to another user.
export async function onRequestDelete({ request, env }) {
  const auth = await checkAdminAuth(request, env);
  if (!auth.ok) return auth.response;

  const url = new URL(request.url);
  const email = normalizeAddress(url.searchParams.get("email") || "");
  if (!email) return json({ ok: false, error: "email required" }, 400);

  const live = await safeFirst(env, `SELECT id FROM inboxes WHERE email = ?`, email);
  if (!live) {
    // Already not live — nothing to delete, but confirm it stays burned.
    const inLedger = await safeFirst(env, `SELECT email FROM used_addresses WHERE email = ?`, email);
    return json({ ok: true, email, deleted: false, still_burned: Boolean(inLedger) });
  }

  try {
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM messages WHERE inbox_id = ?`).bind(live.id),
      env.DB.prepare(`DELETE FROM inboxes WHERE id = ?`).bind(live.id),
    ]);
    return json({ ok: true, email, deleted: true, still_burned: true });
  } catch (e) {
    return json({ ok: false, error: "delete failed: " + (e?.message || "unknown") }, 500);
  }
}

function json(obj, status = 200) {
  return Response.json(obj, { status, headers: { "cache-control": "private, no-store" } });
}

async function addressDetail(env, email, now) {
  const ledger = await safeFirst(env, `SELECT email, first_used_at, creator_uid, creator_ip FROM used_addresses WHERE email = ?`, email);
  const live = await getLiveInbox(env, email);

  if (!ledger && !live) {
    return { service: "modih-mail", generatedAt: now, email, found: false };
  }

  // Current messages (only exist while the inbox is live).
  const currentMessages = live
    ? await safeAll(
        env,
        `SELECT id, from_address, from_name, subject, received_at
           FROM messages WHERE inbox_id = ? ORDER BY received_at DESC LIMIT 200`,
        live.id,
      )
    : [];

  // Historical receipts — survive inbox cleanup, so expired addresses still
  // show what they once received (metadata only, never bodies).
  const history = await safeAll(
    env,
    `SELECT subject, is_otp, created_at
       FROM admin_events
      WHERE event_type = 'message_received' AND inbox_email = ?
      ORDER BY created_at DESC LIMIT 200`,
    email,
  );

  return {
    service: "modih-mail",
    generatedAt: now,
    email,
    found: true,
    status: liveStatus(live, now),
    creator: {
      uid: live?.creator_uid || ledger?.creator_uid || null,
      email: live?.creator_email || null,
      ip: live?.creator_ip || ledger?.creator_ip || null,
      plan: live?.creator_plan || null,
    },
    lifecycle: {
      first_used_at: ledger?.first_used_at ?? live?.created_at ?? null,
      created_at: live?.created_at ?? null,
      expires_at: live?.expires_at ?? null,
      reserved: live ? Boolean(live.reserved) : false,
      blocked: live ? Boolean(live.blocked) : false,
      is_live: Boolean(live),
      inbox_id: live?.id ?? null,
    },
    messages_current: currentMessages.map((m) => ({
      id: m.id,
      from: m.from_address,
      from_name: m.from_name,
      subject: m.subject,
      received_at: m.received_at,
    })),
    messages_history: history.map((h) => ({
      subject: h.subject,
      is_otp: Boolean(h.is_otp),
      received_at: h.created_at,
    })),
  };
}
