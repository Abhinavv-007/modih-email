// Cloudflare Email Worker for modih.in
// Receives inbound emails via Cloudflare Email Routing and stores them in D1

import PostalMime from 'postal-mime';
import { sanitizeRenderedHtml } from '../functions/_sanitize-html.js';

// ========== SHARED HELPERS ==========
async function cleanupExpired(db) {
  const now = Math.floor(Date.now() / 1000);
  try {
    await db.prepare("DELETE FROM messages WHERE inbox_id IN (SELECT id FROM inboxes WHERE expires_at > 0 AND expires_at < ?)").bind(now).run();
    await db.prepare("DELETE FROM inboxes WHERE expires_at > 0 AND expires_at < ?").bind(now).run();
  } catch (e) {
    console.error("Cleanup error:", e);
  }
}

function isOtpLike(subject, bodyText, bodyHtml) {
  const haystack = `${subject || ""} ${bodyText || ""} ${bodyHtml || ""}`.toLowerCase();
  return haystack.includes("otp") || haystack.includes("verification") || haystack.includes("code");
}

async function logAdminEvent(db, {
  uid = null,
  email = "",
  inboxId = null,
  inboxEmail = "",
  ip = null,
  browserToken = null,
  subject = null,
  isOtp = 0,
  createdAt = Math.floor(Date.now() / 1000),
}) {
  try {
    await db.prepare(
      `INSERT INTO admin_events
         (event_type, uid, email, inbox_id, inbox_email, ip, browser_token, subject, is_otp, metadata, created_at)
       VALUES ('message_received', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        uid,
        email || "",
        inboxId,
        inboxEmail || "",
        ip,
        browserToken,
        subject,
        isOtp ? 1 : 0,
        null,
        createdAt
      )
      .run();
  } catch (error) {
    console.error("[admin_events] message_received write error:", error?.message || error);
  }
}

async function getInboxByEmail(db, to) {
  try {
    return await db.prepare(
      "SELECT id, email, expires_at, IFNULL(blocked,0) AS blocked, creator_uid, creator_email, creator_ip, creator_token FROM inboxes WHERE email = ?"
    ).bind(to).first();
  } catch (error) {
    const msg = String(error?.message || "");
    // Fallback for schemas missing the blocked and/or creator_* columns.
    if (msg.includes("blocked")) {
      try {
        return await db.prepare(
          "SELECT id, email, expires_at, creator_uid, creator_email, creator_ip, creator_token FROM inboxes WHERE email = ?"
        ).bind(to).first();
      } catch (e2) {
        if (!String(e2?.message || "").includes("creator_uid")) throw e2;
        return db.prepare("SELECT id, email, expires_at FROM inboxes WHERE email = ?").bind(to).first();
      }
    }
    if (!msg.includes("creator_uid")) throw error;
    return db.prepare("SELECT id, email, expires_at FROM inboxes WHERE email = ?").bind(to).first();
  }
}

export default {
  // ========== SCHEDULED CRON: purge expired inboxes & messages ==========
  async scheduled(event, env, ctx) {
    await cleanupExpired(env.DB);
  },

  async email(message, env, ctx) {
    const to = (message.to || "").toLowerCase().trim();
    const from = message.from || "";

    if (!to) {
      message.setReject("No recipient");
      return;
    }

    try {
      // Check if inbox exists
      const inbox = await getInboxByEmail(env.DB, to);

      if (!inbox) {
        message.setReject("Mailbox not found");
        return;
      }

      // Reject if expired
      const now = Math.floor(Date.now() / 1000);
      if (inbox.expires_at && inbox.expires_at > 0 && inbox.expires_at < now) {
        message.setReject("Mailbox expired");
        return;
      }

      // Reject if an admin has blocked this address.
      if (inbox.blocked) {
        message.setReject("Mailbox unavailable");
        return;
      }

      // Read raw email
      const rawEmail = await new Response(message.raw).arrayBuffer();
      const parser = new PostalMime();
      const parsed = await parser.parse(rawEmail);

      const subject = parsed.subject || "(no subject)";
      const fromName = (parsed.from && parsed.from.name) ? parsed.from.name : "";
      const fromAddress = (parsed.from && parsed.from.address) ? parsed.from.address : from;

      let bodyHtml = parsed.html || "";
      let bodyText = parsed.text || "";

      // Sanitize HTML — strip active-content tags, event handlers, dangerous
      // URL schemes, and remote images (tracking pixels). The shared
      // sanitizer is also used client-side (public/app.js) for defense in
      // depth. Update functions/_sanitize-html.js to change the rules.
      if (bodyHtml) {
        bodyHtml = sanitizeRenderedHtml(bodyHtml);
      }

      // Limit body size (skip attachments)
      if (bodyHtml.length > 100000) bodyHtml = bodyHtml.substring(0, 100000);
      if (bodyText.length > 50000) bodyText = bodyText.substring(0, 50000);

      // Generate message ID
      const msgId = crypto.randomUUID().replace(/-/g, "").substring(0, 16);
      const receivedAt = Math.floor(Date.now() / 1000);

      await env.DB.prepare(
        "INSERT INTO messages (id, inbox_id, from_address, from_name, subject, body_html, body_text, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
      )
        .bind(msgId, inbox.id, fromAddress, fromName, subject, bodyHtml, bodyText, receivedAt)
        .run();

      await logAdminEvent(env.DB, {
        uid: inbox.creator_uid || null,
        email: inbox.creator_email || "",
        inboxId: inbox.id,
        inboxEmail: inbox.email || to,
        ip: inbox.creator_ip || null,
        browserToken: inbox.creator_token || null,
        subject,
        isOtp: isOtpLike(subject, bodyText, bodyHtml),
        createdAt: receivedAt,
      });

    } catch (e) {
      console.error("Email worker error:", e);
      // Do not re-throw — swallow errors to avoid uncaught exceptions in Cloudflare
    }
  },
};
