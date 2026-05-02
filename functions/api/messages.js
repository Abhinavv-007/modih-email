// GET    /api/messages?inbox_id=xxx          — fetch messages (requires X-Owner-Token)
// DELETE /api/messages?inbox_id=xxx          — delete all messages
// DELETE /api/messages?inbox_id=xxx&id=xxx   — delete one message
//
// X-API-Key is optional on GET for developer plan usage tracking.

import {
  validateOwnerToken,
  resolveApiKey,
  isAuthRateLimited,
  recordAuthFailure,
  rateLimit,
  ok,
  err,
  auditLog,
} from "../_api-helpers.js";

const API_MONTHLY_READ_LIMIT = 50000;

// Per-IP rate limits for message endpoints (prevent bulk harvesting / token bruteforce)
const MSG_READ_MAX    = 120;
const MSG_READ_WIN    = 60;    // 120 reads  / 60 s per IP
const MSG_DELETE_MAX  = 30;
const MSG_DELETE_WIN  = 60;    // 30  deletes / 60 s per IP

async function getMonthlyReadCount(db, uid, keyId = null) {
  const now = new Date();
  const monthStart = Math.floor(
    new Date(now.getFullYear(), now.getMonth(), 1).getTime() / 1000
  );
  if (keyId) {
    try {
      const row = await db
        .prepare(
          "SELECT COUNT(*) as cnt FROM api_usage WHERE uid = ? AND key_id = ? AND action = 'message_read' AND created_at >= ?"
        )
        .bind(uid, keyId, monthStart)
        .first();
      return row?.cnt || 0;
    } catch (error) {
      if (!String(error?.message || "").includes("key_id")) throw error;
      return 0;
    }
  }
  const row = await db
    .prepare(
      "SELECT COUNT(*) as cnt FROM api_usage WHERE uid = ? AND action = 'message_read' AND created_at >= ?"
    )
    .bind(uid, monthStart)
    .first();
  return row?.cnt || 0;
}

async function logReadUsage(db, { uid, keyId, endpoint, ip, inboxId, statusCode = 200 }) {
  const now = Math.floor(Date.now() / 1000);
  try {
    await db.prepare(
      `INSERT INTO api_usage
         (uid, key_id, action, endpoint, inbox_id, ip, status_code, created_at)
       VALUES (?, ?, 'message_read', ?, ?, ?, ?, ?)`
    )
      .bind(uid, keyId, endpoint, inboxId, ip, statusCode, now)
      .run();
  } catch (error) {
    try {
      await db.prepare("INSERT INTO api_usage (uid, action, created_at) VALUES (?, 'message_read', ?)")
        .bind(uid, now)
        .run();
    } catch (fallbackError) {
      console.error("[api_usage] write error:", fallbackError?.message || error?.message || fallbackError);
    }
  }

  try {
    await db.prepare(
      `INSERT INTO admin_events
         (event_type, uid, inbox_id, ip, subject, is_otp, metadata, created_at)
       VALUES ('api_usage', ?, ?, ?, 'message_read', 0, ?, ?)`
    )
      .bind(uid, inboxId, ip, endpoint || keyId || "", now)
      .run();
  } catch (_) {}
}

// ── GET /api/messages ────────────────────────────────────────────────────────
export async function onRequestGet(context) {
  const { env, request } = context;
  const ip       = request.headers.get("CF-Connecting-IP") || "unknown";
  const url      = new URL(request.url);
  const inboxId  = url.searchParams.get("inbox_id");
  const ownerToken = request.headers.get("X-Owner-Token") || "";

  if (!inboxId) {
    return err("VALIDATION_ERROR", "inbox_id parameter required.", 400);
  }

  // Per-IP read rate limit (prevents token brute-force via message polling)
  const readAllowed = await rateLimit(env.RATE_LIMIT, `msg_r:${ip}`, MSG_READ_MAX, MSG_READ_WIN);
  if (!readAllowed) {
    return err("RATE_LIMITED", "Too many message read requests. Slow down.", 429);
  }

  // ── Optional API key auth (usage tracking + monthly limit) ──────────────
  const apiKeyHeader = request.headers.get("X-API-Key") || "";
  let apiKeyAuth = null;
  if (apiKeyHeader) {
    if (await isAuthRateLimited(env.RATE_LIMIT, ip, "api_key")) {
      return err("RATE_LIMITED", "Too many failed authentication attempts. Try again later.", 429);
    }

    apiKeyAuth = await resolveApiKey(apiKeyHeader, env.DB, env);
    if (!apiKeyAuth) {
      await recordAuthFailure(env.RATE_LIMIT, ip, "api_key");
      auditLog(env.DB, "api_key.auth_failed", { ip });
      return err("UNAUTHORIZED", "Invalid or revoked API key.", 401);
    }

    const monthlyReads = await getMonthlyReadCount(env.DB, apiKeyAuth.uid);
    if (monthlyReads >= API_MONTHLY_READ_LIMIT) {
      return err(
        "PLAN_LIMIT_EXCEEDED",
        `Monthly API message read limit (${API_MONTHLY_READ_LIMIT.toLocaleString()}) reached. Resets on the 1st of next month.`,
        429,
        { used: monthlyReads, limit: API_MONTHLY_READ_LIMIT }
      );
    }

    const keyMonthlyReads = await getMonthlyReadCount(env.DB, apiKeyAuth.uid, apiKeyAuth.keyId);
    if (keyMonthlyReads >= apiKeyAuth.monthlyReadLimit) {
      return err(
        "KEY_LIMIT_EXCEEDED",
        `This API key has reached its monthly message read limit (${apiKeyAuth.monthlyReadLimit.toLocaleString()}).`,
        429,
        { used: keyMonthlyReads, limit: apiKeyAuth.monthlyReadLimit, key_id: apiKeyAuth.keyId }
      );
    }
  }

  // Owner token is always required (identifies and authorises inbox access)
  if (!ownerToken) {
    return err("UNAUTHORIZED", "Owner token required.", 401);
  }

  // Auth-failure rate limit before token validation (brute-force protection)
  if (await isAuthRateLimited(env.RATE_LIMIT, ip, "inbox_token")) {
    return err("RATE_LIMITED", "Too many failed authentication attempts. Try again later.", 429);
  }

  try {
    const inbox = await env.DB
      .prepare(
        "SELECT id, email, owner_token, owner_token_hash, token_version, created_at, expires_at FROM inboxes WHERE id = ?"
      )
      .bind(inboxId)
      .first();

    if (!inbox) {
      return err("INBOX_NOT_FOUND", "Inbox not found or expired.", 404, { expired: true });
    }

    const now = Math.floor(Date.now() / 1000);
    if (inbox.expires_at > 0 && inbox.expires_at < now) {
      return err("INBOX_EXPIRED", "Inbox has expired.", 404, { expired: true });
    }

    const valid = await validateOwnerToken(inbox, ownerToken, env.TOKEN_PEPPER || "");
    if (!valid) {
      await recordAuthFailure(env.RATE_LIMIT, ip, "inbox_token");
      auditLog(env.DB, "owner_token.invalid", { inboxId, ip });
      return err("FORBIDDEN", "Owner token mismatch.", 403);
    }

    const result = await env.DB
      .prepare(
        "SELECT id, from_address, from_name, subject, body_html, body_text, received_at FROM messages WHERE inbox_id = ? ORDER BY received_at DESC"
      )
      .bind(inboxId)
      .all();

    const messages = result.results || [];

    if (apiKeyAuth) {
      await logReadUsage(env.DB, {
        uid: apiKeyAuth.uid,
        keyId: apiKeyAuth.keyId,
        endpoint: "GET /api/messages",
        ip,
        inboxId,
        statusCode: 200,
      });
    }

    return ok({
      inbox: {
        id:         inbox.id,
        email:      inbox.email,
        created_at: inbox.created_at,
        expires_at: inbox.expires_at,
      },
      messages,
      count: messages.length,
    });
  } catch (e) {
    console.error("Get messages error:", e);
    return err("INTERNAL_ERROR", "Failed to fetch messages.", 500);
  }
}

// ── DELETE /api/messages ─────────────────────────────────────────────────────
export async function onRequestDelete(context) {
  const { env, request } = context;
  const ip         = request.headers.get("CF-Connecting-IP") || "unknown";
  const url        = new URL(request.url);
  const inboxId    = url.searchParams.get("inbox_id");
  const messageId  = url.searchParams.get("id");
  const ownerToken = request.headers.get("X-Owner-Token") || "";

  if (!inboxId) {
    return err("VALIDATION_ERROR", "inbox_id parameter required.", 400);
  }
  if (!ownerToken) {
    return err("UNAUTHORIZED", "Owner token required.", 401);
  }

  // Per-IP delete rate limit
  const delAllowed = await rateLimit(env.RATE_LIMIT, `msg_d:${ip}`, MSG_DELETE_MAX, MSG_DELETE_WIN);
  if (!delAllowed) {
    return err("RATE_LIMITED", "Too many delete requests. Slow down.", 429);
  }

  // Auth-failure rate limit
  if (await isAuthRateLimited(env.RATE_LIMIT, ip, "inbox_token")) {
    return err("RATE_LIMITED", "Too many failed authentication attempts. Try again later.", 429);
  }

  try {
    const inbox = await env.DB
      .prepare("SELECT id, owner_token, owner_token_hash, token_version, expires_at FROM inboxes WHERE id = ?")
      .bind(inboxId)
      .first();

    if (!inbox) {
      return err("INBOX_NOT_FOUND", "Inbox not found.", 404);
    }

    const now = Math.floor(Date.now() / 1000);
    if (inbox.expires_at > 0 && inbox.expires_at < now) {
      return err("INBOX_EXPIRED", "Inbox has expired.", 404, { expired: true });
    }

    const valid = await validateOwnerToken(inbox, ownerToken, env.TOKEN_PEPPER || "");
    if (!valid) {
      await recordAuthFailure(env.RATE_LIMIT, ip, "inbox_token");
      auditLog(env.DB, "owner_token.invalid", { inboxId, ip });
      return err("FORBIDDEN", "Owner token mismatch.", 403);
    }

    if (messageId) {
      await env.DB
        .prepare("DELETE FROM messages WHERE id = ? AND inbox_id = ?")
        .bind(messageId, inboxId)
        .run();
      return ok({ deleted: true, scope: "message" });
    }

    await env.DB
      .prepare("DELETE FROM messages WHERE inbox_id = ?")
      .bind(inboxId)
      .run();
    return ok({ deleted: true, scope: "all_messages" });

  } catch (e) {
    console.error("Delete messages error:", e);
    return err("INTERNAL_ERROR", "Failed to delete messages.", 500);
  }
}
