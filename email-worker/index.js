// Cloudflare Email Worker for modih.in
// Receives inbound emails via Cloudflare Email Routing and stores them in D1

import PostalMime from 'postal-mime';

export default {
  async email(message, env, ctx) {
    const to = message.to;
    const from = message.from;

    try {
      // Check if inbox exists and is not expired
      const inbox = await env.DB.prepare(
        "SELECT * FROM inboxes WHERE email = ? AND expires_at > ?"
      )
        .bind(to, Math.floor(Date.now() / 1000))
        .first();

      if (!inbox) {
        message.setReject("Mailbox not found or expired");
        return;
      }

      // Read raw email
      const rawEmail = await new Response(message.raw).arrayBuffer();
      const parser = new PostalMime();
      const parsed = await parser.parse(rawEmail);

      const subject = parsed.subject || "(no subject)";
      const fromName = parsed.from?.name || "";
      const fromAddress = parsed.from?.address || from;

      let bodyHtml = parsed.html || "";
      let bodyText = parsed.text || "";

      // Sanitize HTML - strip dangerous elements
      if (bodyHtml) {
        bodyHtml = bodyHtml
          .replace(/<script[\s\S]*?<\/script>/gi, "")
          .replace(/<iframe[\s\S]*?<\/iframe>/gi, "")
          .replace(/<form[\s\S]*?<\/form>/gi, "")
          .replace(/<object[\s\S]*?<\/object>/gi, "")
          .replace(/<embed[\s\S]*?>/gi, "")
          .replace(/<link[\s\S]*?>/gi, "")
          .replace(/on\w+="[^"]*"/gi, "")
          .replace(/on\w+='[^']*'/gi, "")
          .replace(/on\w+=[^\s>]+/gi, "")
          .replace(/javascript:/gi, "blocked:")
          .replace(/vbscript:/gi, "blocked:")
          .replace(/<base[\s\S]*?>/gi, "")
          .replace(/<meta[\s\S]*?>/gi, "");
      }

      // Limit body size (skip attachments)
      if (bodyHtml.length > 100000) bodyHtml = bodyHtml.substring(0, 100000);
      if (bodyText.length > 50000) bodyText = bodyText.substring(0, 50000);

      // Generate message ID
      const msgId = crypto.randomUUID().replace(/-/g, "").substring(0, 16);
      const now = Math.floor(Date.now() / 1000);

      await env.DB.prepare(
        "INSERT INTO messages (id, inbox_id, from_address, from_name, subject, body_html, body_text, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
      )
        .bind(msgId, inbox.id, fromAddress, fromName, subject, bodyHtml, bodyText, now)
        .run();

    } catch (e) {
      console.error("Email worker error:", e);
    }
  },
};
