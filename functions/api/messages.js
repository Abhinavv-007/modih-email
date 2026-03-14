// GET /api/messages?inbox_id=xxx - Get messages for an inbox
// DELETE /api/messages?inbox_id=xxx - Delete all messages for an inbox
// DELETE /api/messages?id=xxx&inbox_id=xxx - Delete single message

export async function onRequestGet(context) {
  const { env, request } = context;
  const url = new URL(request.url);
  const inboxId = url.searchParams.get("inbox_id");

  if (!inboxId) {
    return Response.json({ error: "inbox_id parameter required." }, { status: 400 });
  }

  try {
    // Verify inbox exists and not expired
    const inbox = await env.DB.prepare("SELECT * FROM inboxes WHERE id = ? AND expires_at > ?")
      .bind(inboxId, Math.floor(Date.now() / 1000))
      .first();

    if (!inbox) {
      return Response.json({ error: "Inbox not found or expired.", expired: true }, { status: 404 });
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

  if (!inboxId) {
    return Response.json({ error: "inbox_id parameter required." }, { status: 400 });
  }

  try {
    // Verify inbox exists
    const inbox = await env.DB.prepare("SELECT * FROM inboxes WHERE id = ? AND expires_at > ?")
      .bind(inboxId, Math.floor(Date.now() / 1000))
      .first();

    if (!inbox) {
      return Response.json({ error: "Inbox not found or expired." }, { status: 404 });
    }

    if (messageId) {
      // Delete single message
      await env.DB.prepare("DELETE FROM messages WHERE id = ? AND inbox_id = ?")
        .bind(messageId, inboxId)
        .run();
      return Response.json({ success: true, message: "Message deleted." });
    } else {
      // Delete all messages in inbox
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
