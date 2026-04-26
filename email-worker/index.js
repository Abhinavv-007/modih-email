// Cloudflare Email Worker for modih.in
// Receives inbound emails via Cloudflare Email Routing and stores them in D1

import PostalMime from 'postal-mime';

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
      const inbox = await env.DB.prepare(
        "SELECT id, expires_at FROM inboxes WHERE email = ?"
      )
        .bind(to)
        .first();

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
      // URL schemes, and remote images (tracking pixels). Mirrors the client-
      // side sanitizer in public/app.js — keep both in sync if either changes.
      if (bodyHtml) {
        bodyHtml = bodyHtml
          // Strip pairs (tag + content) for execution-capable elements.
          .replace(/<(script|style|iframe|object|form|svg|math|noscript|template)\b[\s\S]*?<\/\1\s*>/gi, "")
          // Strip standalone tags that pull or redirect resources.
          .replace(/<(embed|link|base|meta|source|track)\b[^>]*>/gi, "")
          // Catch any unmatched openers (truncated / malformed HTML).
          .replace(/<\/?(script|style|iframe|object|svg|math|form|noscript|template)\b[^>]*>/gi, "")
          // on* event handlers — quoted, single-quoted, and unquoted forms.
          .replace(/\son\w+\s*=\s*"[^"]*"/gi, "")
          .replace(/\son\w+\s*=\s*'[^']*'/gi, "")
          .replace(/\son\w+\s*=\s*[^\s>]+/gi, "")
          // Dangerous URL schemes including HTML-entity-encoded colon
          // variants (java&#115;cript: etc.).
          .replace(/(javascript|vbscript|livescript|data|blob|file)\s*(?:&#0*58;?|&#x0*3a;?|:)/gi, "blocked:")
          // Block ALL remote images to prevent IP leak via tracking pixels.
          .replace(/<img\b[^>]*>/gi, "[image removed]");
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

    } catch (e) {
      console.error("Email worker error:", e);
      // Do not re-throw — swallow errors to avoid uncaught exceptions in Cloudflare
    }
  },
};
