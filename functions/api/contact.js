// HTML-escape arbitrary text before embedding it in the support email body.
// Prevents the contact form from being abused to inject scripts, fake links,
// or arbitrary markup into the operator inbox.
function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Loose RFC-5321-ish format check — rejects obvious garbage and CRLF
// injection attempts that would corrupt the outbound email headers.
function isValidEmail(value) {
  if (typeof value !== "string") return false;
  if (value.length > 254) return false;
  if (/[\r\n]/.test(value)) return false;
  return /^[^\s@]+@[^\s@.]+\.[^\s@]+$/.test(value);
}

export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json().catch(() => ({}));
    const name    = typeof body.name    === "string" ? body.name.trim().slice(0, 200)   : "";
    const email   = typeof body.email   === "string" ? body.email.trim().slice(0, 254)  : "";
    const message = typeof body.message === "string" ? body.message.trim().slice(0, 5000) : "";
    const turnstile_token = typeof body.turnstile_token === "string" ? body.turnstile_token : "";

    if (!name || !email || !message) {
      return new Response(JSON.stringify({ error: 'Missing required fields' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (!isValidEmail(email)) {
      return new Response(JSON.stringify({ error: 'Invalid email address.' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 1. Rate Limiting Check (reuse rate limit logic if available, else simple check)
    const browserToken = request.headers.get('X-Browser-Token');
    if (browserToken && env.RATE_LIMIT) {
      const rlKey = `contact_rl_${browserToken}`;
      const rlValue = await env.RATE_LIMIT.get(rlKey);
      
      if (rlValue && parseInt(rlValue) >= 3) {
        return new Response(JSON.stringify({ error: 'Too many messages. Please try again later.' }), {
          status: 429,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      
      // Increment rate limit counting
      await env.RATE_LIMIT.put(rlKey, (parseInt(rlValue || '0') + 1).toString(), {
        expirationTtl: 3600 // 1 hour
      });
    }

    // 2. Turnstile Verification (optional — only verify if a token was sent)
    if (turnstile_token) {
      const ip = request.headers.get('CF-Connecting-IP');
      const formData = new FormData();
      formData.append('secret', env.TURNSTILE_SECRET);
      formData.append('response', turnstile_token);
      formData.append('remoteip', ip);

      const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        body: formData,
        method: 'POST',
      });

      const outcome = await result.json();
      if (!outcome.success) {
        return new Response(JSON.stringify({ error: 'Security check failed. Please refresh.' }), { 
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    // 3. Send Email using Resend
    if (!env.RESEND_API_KEY) {
      // Allow testing the UI even if the backend key isn't set up yet
      console.log('RESEND_API_KEY not configured. Email would have been:', { name, email, message });
      return new Response(JSON.stringify({ success: true, warning: 'Email logged (API key not configured)' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Strip any control chars from the subject line — they can break the
    // outbound email headers and are not useful in a subject anyway.
    const safeSubjectName = name.replace(/[\x00-\x1F\x7F]/g, "").slice(0, 80);

    const resendRes = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: 'Modih Plan Support <contact-form@modih.in>',
        to: 'abhnv@abhnv.in', // User's primary email address
        reply_to: email, // Extremely helpful so the user can just hit "Reply" to the email!
        subject: `New Plan Purchase Request from ${safeSubjectName}`,
        html: `
          <h3>New message via Modih Mail Contact Form</h3>
          <p><strong>Name:</strong> ${escapeHtml(name)}</p>
          <p><strong>Email:</strong> ${escapeHtml(email)}</p>
          <hr>
          <p><strong>Message:</strong></p>
          <p style="white-space: pre-wrap;">${escapeHtml(message)}</p>
        `
      })
    });

    if (!resendRes.ok) {
      const errorData = await resendRes.json();
      console.error('Resend Error:', errorData);
      return new Response(JSON.stringify({ error: 'Failed to deliver email. Please try again later.' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Success
    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (err) {
    console.error('Contact API Error:', err);
    return new Response(JSON.stringify({ error: 'Internal server error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
