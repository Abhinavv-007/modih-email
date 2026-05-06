import { getAuthUser } from "../../_auth-helper.js";

function isMissingColumn(error, column) {
  const message = String(error?.message || "");
  return message.includes(column) || message.includes("no such column") || message.includes("no such table");
}

export async function onRequestDelete(context) {
  const { env, request } = context;
  const user = await getAuthUser(request);

  if (!user) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    // Try to wipe inbox + message rows tied to this user. The `creator_uid`
    // column was added in a later migration, so older databases may not have
    // it yet — we tolerate that single class of failure and continue.
    try {
      await env.DB.batch([
        env.DB.prepare(
          "DELETE FROM messages WHERE inbox_id IN (SELECT id FROM inboxes WHERE creator_uid = ?)"
        ).bind(user.uid),
        env.DB.prepare("DELETE FROM inboxes WHERE creator_uid = ?").bind(user.uid),
      ]);
    } catch (error) {
      if (!isMissingColumn(error, "creator_uid")) throw error;
    }

    // Wipe everything else in one atomic batch. Previously these ran as four
    // separate awaited statements — if the worker died between them the
    // user's account was left half-deleted (e.g. plan row gone but api_keys
    // still active). Batching both halves the round-trips and gives us
    // all-or-nothing semantics.
    await env.DB.batch([
      env.DB.prepare("DELETE FROM api_usage  WHERE uid = ?").bind(user.uid),
      env.DB.prepare("DELETE FROM api_keys   WHERE uid = ?").bind(user.uid),
      env.DB.prepare("DELETE FROM audit_log  WHERE uid = ?").bind(user.uid),
      env.DB.prepare("DELETE FROM user_plans WHERE uid = ?").bind(user.uid),
    ]);

    try {
      await env.DB.prepare(
        "UPDATE admin_events SET uid = NULL, email = '' WHERE uid = ?"
      ).bind(user.uid).run();
    } catch (error) {
      if (!isMissingColumn(error, "admin_events")) throw error;
    }

    return Response.json({ success: true, deleted: true });
  } catch (error) {
    console.error("Delete account data error:", error?.message || error);
    return Response.json({ error: "Failed to delete account data." }, { status: 500 });
  }
}
