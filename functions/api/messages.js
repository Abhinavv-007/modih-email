// GET /api/messages?inbox_id=xxx     - Get messages (requires X-Owner-Token)
// DELETE /api/messages?inbox_id=xxx   - Delete all messages (requires X-Owner-Token)
// DELETE /api/messages?id=xxx&inbox_id=xxx - Delete single message (requires X-Owner-Token)

function getOwnerToken(request) {
  return request.headers.get("X-Owner-Token") || "";
}

export async function onRequestGet(context) {
  const { env, request } = context;
  const url = new URL(request.url);
  const inboxId = url.searchParams.get("inbox_id");
  const ownerToken = getOwnerToken(request);

  if (!inboxId) {
    return Response.json({ error: "inbox_id parameter required." }, { status: 400 });
  }
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
