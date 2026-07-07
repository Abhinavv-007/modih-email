// POST   /api/inbox/reserve?id=…   — reserve the alias (Pro/Dev, up to 3)
// DELETE /api/inbox/reserve?id=…   — un-reserve the alias
//
// Reserved aliases ignore the periodic cleanup job and survive past their
// nominal expiry until the user un-reserves or deletes them.

import { verifyFirebaseToken } from "../../_auth-helper.js";
import { ok, err } from "../../_api-helpers.js";

const RESERVED_CAP = 3;
const PLAN_RANK = { developer: 3, pro: 2, free: 1 };

function betterPlan(a, b) {
  return (PLAN_RANK[a] || 0) >= (PLAN_RANK[b] || 0) ? a : b;
}

async function getPlanForUser(db, user) {
  const uidRow = await db
    .prepare("SELECT plan FROM user_plans WHERE uid = ?")
    .bind(user.uid)
    .first();

  let plan = uidRow?.plan || "free";
  if (user.email && user.email_verified === true) {
    // Single highest-ranked plan resolved at the DB layer (ORDER BY … LIMIT 1)
    // rather than loading all matching rows and ranking in JS — bounds the work
    // regardless of how many user_plans rows exist for the email (DoS, #17).
    const emailBest = await db
      .prepare(
        `SELECT plan FROM user_plans
          WHERE LOWER(email) = LOWER(?)
          ORDER BY CASE plan
                     WHEN 'developer' THEN 3
                     WHEN 'pro'       THEN 2
                     ELSE 1
                   END DESC
          LIMIT 1`
      )
      .bind(user.email)
      .first();
    plan = betterPlan(plan, emailBest?.plan || "free");
  }

  return ["pro", "developer"].includes(plan) ? plan : "free";
}

async function requireOwnerPaid(request, db, inboxId) {
  if (!inboxId) return { err: err("VALIDATION_ERROR", "id parameter required.", 400) };

  const authHeader = request.headers.get("Authorization") || "";
  if (!authHeader.startsWith("Bearer ")) {
    return { err: err("UNAUTHORIZED", "Sign in required.", 401) };
  }
  const token = authHeader.slice(7).trim();
  if (!token) return { err: err("UNAUTHORIZED", "Sign in required.", 401) };

  let user;
  try {
    user = await verifyFirebaseToken(token);
  } catch (_) {
    return { err: err("UNAUTHORIZED", "Invalid auth token.", 401) };
  }
  if (!user?.uid) return { err: err("UNAUTHORIZED", "Invalid auth token.", 401) };

  const plan = await getPlanForUser(db, user);
  if (plan !== "pro" && plan !== "developer") {
    return {
      err: err("FEATURE_UNAVAILABLE", "Reserved aliases are a Pro feature.", 403, {
        upgrade_required: true,
        feature: "reserve_alias",
      }),
    };
  }

  const inbox = await db
    .prepare("SELECT id, creator_uid FROM inboxes WHERE id = ?")
    .bind(inboxId)
    .first();
  if (!inbox) return { err: err("INBOX_NOT_FOUND", "Inbox not found.", 404) };
  if (inbox.creator_uid !== user.uid) {
    return { err: err("FORBIDDEN", "You do not own this inbox.", 403) };
  }

  return { user, plan, inbox };
}

async function reservedCount(db, uid) {
  try {
    const row = await db
      .prepare("SELECT COUNT(*) as cnt FROM inboxes WHERE creator_uid = ? AND reserved = 1")
      .bind(uid)
      .first();
    return row?.cnt || 0;
  } catch (error) {
    if (!String(error?.message || "").includes("reserved")) throw error;
    return 0;
  }
}

// ── POST /api/inbox/reserve?id=… ─────────────────────────────────────────────
export async function onRequestPost(context) {
  const { env, request } = context;
  const url = new URL(request.url);
  const inboxId = url.searchParams.get("id");

  const ctx = await requireOwnerPaid(request, env.DB, inboxId);
  if (ctx.err) return ctx.err;

  try {
    const used = await reservedCount(env.DB, ctx.user.uid);
    if (used >= RESERVED_CAP) {
      return err(
        "PLAN_LIMIT_EXCEEDED",
        `You can reserve up to ${RESERVED_CAP} aliases. Un-reserve one to make room.`,
        400,
        { used, limit: RESERVED_CAP }
      );
    }

    try {
      await env.DB
        .prepare("UPDATE inboxes SET reserved = 1, expires_at = 0 WHERE id = ?")
        .bind(inboxId)
        .run();
    } catch (error) {
      if (!String(error?.message || "").includes("reserved")) throw error;
      return err("INTERNAL_ERROR", "Reserved-alias support is not deployed yet. Run migrate-pro-features.sql.", 500);
    }

    return ok({ id: inboxId, reserved: true });
  } catch (e) {
    console.error("[inbox/reserve] POST error:", e);
    return err("INTERNAL_ERROR", "Failed to reserve alias.", 500);
  }
}

// ── DELETE /api/inbox/reserve?id=… ───────────────────────────────────────────
export async function onRequestDelete(context) {
  const { env, request } = context;
  const url = new URL(request.url);
  const inboxId = url.searchParams.get("id");

  const ctx = await requireOwnerPaid(request, env.DB, inboxId);
  if (ctx.err) return ctx.err;

  try {
    try {
      await env.DB
        .prepare("UPDATE inboxes SET reserved = 0 WHERE id = ?")
        .bind(inboxId)
        .run();
    } catch (error) {
      if (!String(error?.message || "").includes("reserved")) throw error;
      return err("INTERNAL_ERROR", "Reserved-alias support is not deployed yet. Run migrate-pro-features.sql.", 500);
    }
    return ok({ id: inboxId, reserved: false });
  } catch (e) {
    console.error("[inbox/reserve] DELETE error:", e);
    return err("INTERNAL_ERROR", "Failed to un-reserve alias.", 500);
  }
}
