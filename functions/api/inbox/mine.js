// GET    /api/inbox/mine            — Pro/Developer: every live inbox the user owns.
// DELETE /api/inbox/mine?id=<uuid>   — Delete a single inbox by id (no owner_token
//                                       required — auth is Firebase UID match).
// DELETE /api/inbox/mine?all=1[&keep=<id>]
//                                    — Bulk-delete every inbox owned by this user,
//                                       optionally keeping one. Used by the
//                                       "Clear inactive inboxes" panel button.
//
// Powers "Sync across devices" — the client merges these into its session list
// so the same set of inboxes shows up regardless of which device created them.

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
    const plan = planRow?.plan || "free";
    if (plan !== "pro" && plan !== "developer") {
      return err(
        "FEATURE_UNAVAILABLE",
        "Cross-device sync is a Pro feature.",
        403,
        { upgrade_required: true, feature: "sync" }
      );
    }

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
    }));

    return ok({ inboxes, count: inboxes.length, plan });
  } catch (e) {
    console.error("[inbox/mine] error:", e?.message);
    return err("INTERNAL_ERROR", "Failed to load inboxes.", 500);
  }
}

// ── DELETE /api/inbox/mine[?id=…] or [?all=1&keep=…] ─────────────────────────
// Pro/Developer-only. Authenticates via Firebase ID token and scopes deletes
// to `creator_uid = user.uid`, so owner_token is not required (this is how
// we let users prune historical "ghost" inboxes that were created on other
// devices/sessions and no longer have their owner token in local storage).
export async function onRequestDelete(context) {
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
    const plan = planRow?.plan || "free";
    if (plan !== "pro" && plan !== "developer") {
      return err(
        "FEATURE_UNAVAILABLE",
        "Inbox management is a Pro feature.",
        403,
        { upgrade_required: true, feature: "sync" }
      );
    }

    const url = new URL(request.url);
    const inboxId = url.searchParams.get("id");
    const all = url.searchParams.get("all") === "1";
    const keep = url.searchParams.get("keep") || null;

    if (!inboxId && !all) {
      return err("VALIDATION_ERROR", "Pass ?id=<inboxId> or ?all=1.", 400);
    }

    // ── Single-id delete ────────────────────────────────────────────────────
    if (inboxId) {
      // Confirm ownership before the cascade.
      const row = await env.DB
        .prepare("SELECT id FROM inboxes WHERE id = ? AND creator_uid = ?")
        .bind(inboxId, user.uid)
        .first();
      if (!row) return err("INBOX_NOT_FOUND", "Inbox not found.", 404);

      await env.DB.batch([
        env.DB.prepare("DELETE FROM messages WHERE inbox_id = ?").bind(inboxId),
        env.DB.prepare("DELETE FROM inboxes WHERE id = ?").bind(inboxId),
      ]);
      return ok({ deleted: 1 });
    }

    // ── Bulk delete (optionally keeping one) ────────────────────────────────
    const params = [user.uid];
    let inboxFilter = "creator_uid = ?";
    if (keep) {
      inboxFilter += " AND id != ?";
      params.push(keep);
    }
    // Always preserve reserved inboxes — bulk-clearing them would surprise
    // the user since reserved means "keep forever".
    inboxFilter += " AND IFNULL(reserved, 0) = 0";

    // Cascade messages first, then the inbox rows themselves.
    const messagesStmt = env.DB
      .prepare(`DELETE FROM messages WHERE inbox_id IN (SELECT id FROM inboxes WHERE ${inboxFilter})`)
      .bind(...params);
    const inboxesStmt = env.DB
      .prepare(`DELETE FROM inboxes WHERE ${inboxFilter}`)
      .bind(...params);

    const [, inboxesResult] = await env.DB.batch([messagesStmt, inboxesStmt]);
    const deleted = inboxesResult?.meta?.changes ?? 0;
    return ok({ deleted });
  } catch (e) {
    console.error("[inbox/mine] DELETE error:", e?.message);
    return err("INTERNAL_ERROR", "Failed to delete inboxes.", 500);
  }
}
