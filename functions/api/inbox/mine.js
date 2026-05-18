// GET /api/inbox/mine — Pro/Developer: return every live inbox this user owns.
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
