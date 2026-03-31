// GET /api/messages?inbox_id=xxx     - Get messages (requires X-Owner-Token; X-API-Key also supported for dev plan)
// DELETE /api/messages?inbox_id=xxx   - Delete all messages (requires X-Owner-Token)
// DELETE /api/messages?id=xxx&inbox_id=xxx - Delete single message (requires X-Owner-Token)

function getOwnerToken(request) {
  return request.headers.get("X-Owner-Token") || "";
}

// ── API Key helpers (mirrors inbox.js — kept local to avoid cross-file imports) ──
async function hashKeyMsg(key) {
  const data = new TextEncoder().encode(key);
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function resolveApiKeyMsg(keyValue, db) {
  if (!keyValue || !keyValue.startsWith("mdh_")) return null;
  try {
    const hash = await hashKeyMsg(keyValue);
    const keyRow = await db
      .prepare("SELECT uid FROM api_keys WHERE key_hash = ? AND is_active = 1")
      .bind(hash)
      .first();
    if (!keyRow) return null;
    const planRow = await db
      .prepare("SELECT plan FROM user_plans WHERE uid = ?")
      .bind(keyRow.uid)
      .first();
    if (planRow?.plan !== "developer") return null;
    const now = Math.floor(Date.now() / 1000);
    db.prepare("UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?")
      .bind(now, hash)
      .run()
      .catch(() => {});
    return { uid: keyRow.uid };
  } catch (e) {
    console.error("resolveApiKeyMsg error:", e.message);
    return null;
  }
}

async function getMonthlyReadCount(db, uid) {
  const now = new Date();
  const monthStart = Math.floor(new Date(now.getFullYear(), now.getMonth(), 1).getTime() / 1000);
  const row = await db
    .prepare(
      "SELECT COUNT(*) as cnt FROM api_usage WHERE uid = ? AND action = 'message_read' AND created_at >= ?"
    )
    .bind(uid, monthStart)
    .first();
  return row?.cnt || 0;
}

function logReadUsage(db, uid) {
  const now = Math.floor(Date.now() / 1000);
  db.prepare("INSERT INTO api_usage (uid, action, created_at) VALUES (?, 'message_read', ?)")
    .bind(uid, now)
    .run()
    .catch(() => {});
}

const API_MONTHLY_READ_LIMIT = 50000;

export async function onRequestGet(context) {
  const { env, request } = context;
  const url = new URL(request.url);
  const inboxId = url.searchParams.get("inbox_id");
  const ownerToken = getOwnerToken(request);

  if (!inboxId) {
    return Response.json({ error: "inbox_id parameter required." }, { status: 400 });
  }

  // ── Optional API key auth (tracks usage + enforces monthly read limit) ──
  const apiKeyHeader = request.headers.get("X-API-Key") || "";
  let apiKeyAuth = null;
  if (apiKeyHeader) {
    apiKeyAuth = await resolveApiKeyMsg(apiKeyHeader, env.DB);
    if (!apiKeyAuth) {
      return Response.json({ error: "Invalid or revoked API key." }, { status: 401 });
    }
    const monthlyReads = await getMonthlyReadCount(env.DB, apiKeyAuth.uid);
    if (monthlyReads >= API_MONTHLY_READ_LIMIT) {
      return Response.json({
        error: `Monthly API message read limit (${API_MONTHLY_READ_LIMIT.toLocaleString()}) reached. Resets on the 1st of next month.`,
        used: monthlyReads,
        limit: API_MONTHLY_READ_LIMIT,
      }, { status: 429 });
    }
  }

  // Owner token still required to identify the inbox (whether using API key or not)
  if (!ownerToken) {
    return Response.json({ error: "Owner token required." }, { status: 403 });
  }

  try {
    const inbox = await env.DB.prepare("SELECT id, email, owner_token, created_at, expires_at FROM inboxes WHERE id = ?")
      .bind(inboxId)
      .first();

    if (!inbox) {
      return Response.json({ error: "Inbox not found.", expired: true }, { status: 404 });
    }

    // Check if expired
    const now = Math.floor(Date.now() / 1000);
    if (inbox.expires_at > 0 && inbox.expires_at < now) {
      return Response.json({ error: "Inbox expired.", expired: true }, { status: 404 });
    }

    if (inbox.owner_token !== ownerToken) {
      return Response.json({ error: "Unauthorized." }, { status: 403 });
    }

    const messages = await env.DB.prepare(
      "SELECT id, from_address, from_name, subject, body_html, body_text, received_at FROM messages WHERE inbox_id = ? ORDER BY received_at DESC"
    )
      .bind(inboxId)
      .all();

    // Log API usage after a successful read
    if (apiKeyAuth) logReadUsage(env.DB, apiKeyAuth.uid);

    return Response.json({
      inbox: {
        id: inbox.id,
        email: inbox.email,
        created_at: inbox.created_at,
        expires_at: inbox.expires_at,
      },
      messages: messages.results || [],
    });
  } catch (e) {
    console.error("Get messages error:", e);
    return Response.json({ error: "Failed to fetch messages." }, { status: 500 });
  }
}

export async function onRequestDelete(context) {
  const { env, request } = context;
  const url = new URL(request.url);
  const inboxId = url.searchParams.get("inbox_id");
  const messageId = url.searchParams.get("id");
  const ownerToken = getOwnerToken(request);

  if (!inboxId) {
    return Response.json({ error: "inbox_id parameter required." }, { status: 400 });
  }
  if (!ownerToken) {
    return Response.json({ error: "Owner token required." }, { status: 403 });
  }

  try {
    const inbox = await env.DB.prepare("SELECT id, owner_token, expires_at FROM inboxes WHERE id = ?")
      .bind(inboxId)
      .first();

    if (!inbox) {
      return Response.json({ error: "Inbox not found." }, { status: 404 });
    }

    const now = Math.floor(Date.now() / 1000);
    if (inbox.expires_at > 0 && inbox.expires_at < now) {
      return Response.json({ error: "Inbox expired." }, { status: 404 });
    }

    if (inbox.owner_token !== ownerToken) {
      return Response.json({ error: "Unauthorized." }, { status: 403 });
    }

    if (messageId) {
      await env.DB.prepare("DELETE FROM messages WHERE id = ? AND inbox_id = ?")
        .bind(messageId, inboxId)
        .run();
      return Response.json({ success: true, message: "Message deleted." });
    } else {
      await env.DB.prepare("DELETE FROM messages WHERE inbox_id = ?")
        .bind(inboxId)
        .run();
      return Response.json({ success: true, message: "All messages deleted." });
    }
  } catch (e) {
    console.error("Delete messages error:", e);
    return Response.json({ error: "Failed to delete messages." }, { status: 500 });
  }
}
