// POST /api/inbox   - Create a new inbox (returns owner_token once)
// DELETE /api/inbox  - Delete an inbox (requires owner_token)

const DOMAIN = "modih.in";
const RATE_LIMIT_MAX = 10;
const RATE_LIMIT_WINDOW = 3600;
const MAX_RANDOM_RETRIES = 5;

// ========== BLOCKED PREFIXES ==========
// Exact names + operational names. Matching is normalized (lowercase, stripped).
const BLOCKED_PREFIXES = new Set([
  // Personal / brand protection
  "abhnv", "abhinav", "modi", "modih",
  // Operational / RFC-reserved
  "admin", "administrator", "support", "security", "postmaster",
  "root", "help", "billing", "abuse", "contact", "team", "mail",
  "info", "noreply", "no-reply", "webmaster", "hostmaster",
  "mailer-daemon", "www", "ftp", "smtp", "imap", "pop",
]);

function normalizePrefix(raw) {
  // Lowercase, strip dots/dashes/underscores for variant matching
  return raw.toLowerCase().replace(/[.\-_]/g, "");
}

function isBlockedPrefix(prefix) {
  const normalized = normalizePrefix(prefix);
  // Check exact match and normalized match
  if (BLOCKED_PREFIXES.has(prefix.toLowerCase())) return true;
  if (BLOCKED_PREFIXES.has(normalized)) return true;
  return false;
}

function generateId() {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let id = "";
  for (let i = 0; i < 16; i++) {
    id += chars[Math.floor(Math.random() * chars.length)];
  }
  return id;
}

function generateOwnerToken() {
  return crypto.randomUUID().replace(/-/g, "");
}

function generateRandomPrefix() {
  const adjectives = ["swift", "cool", "bright", "lucky", "calm", "bold", "keen", "pure", "wise", "warm"];
  const nouns = ["fox", "owl", "ray", "star", "wave", "leaf", "wind", "moon", "dawn", "fire"];
  const adj = adjectives[Math.floor(Math.random() * adjectives.length)];
  const noun = nouns[Math.floor(Math.random() * nouns.length)];
  const num = Math.floor(Math.random() * 999);
  return `${adj}${noun}${num}`;
}

function sanitizePrefix(prefix) {
  return prefix.toLowerCase().replace(/[^a-z0-9._-]/g, "").slice(0, 30);
}

async function checkRateLimit(env, ip) {
  const key = `rate:${ip}`;
  const current = await env.RATE_LIMIT.get(key);
  const parsed = current ? Number.parseInt(current, 10) : 0;
  const count = Number.isFinite(parsed) ? parsed : 0;
  if (count >= RATE_LIMIT_MAX) {
    return false;
  }
  await env.RATE_LIMIT.put(key, String(count + 1), { expirationTtl: RATE_LIMIT_WINDOW });
  return true;
}

// ========== POST /api/inbox — Create inbox ==========
export async function onRequestPost(context) {
  const { env, request } = context;
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";

  try {
    const allowed = await checkRateLimit(env, ip);
    if (!allowed) {
      return Response.json({ error: "Rate limit exceeded. Try again later." }, { status: 429 });
    }

    const body = await request.json().catch(() => ({}));
    const callerToken = request.headers.get("X-Owner-Token") || "";
    const isCustom = !!body.prefix;
    let prefix = isCustom ? sanitizePrefix(body.prefix) : null;

    // Validate custom prefix
    if (isCustom) {
      if (prefix.length < 2) {
        return Response.json({ error: "Prefix must be at least 2 characters." }, { status: 400 });
      }
      if (isBlockedPrefix(prefix)) {
        return Response.json({ error: "This name is reserved and cannot be used." }, { status: 403 });
      }
    }

    // --- Custom prefix path ---
    if (isCustom) {
      const email = `${prefix}@${DOMAIN}`;

      // Check if it already exists
      const existing = await env.DB.prepare("SELECT id, email, created_at, owner_token FROM inboxes WHERE email = ?")
        .bind(email)
        .first();

      if (existing) {
        // Re-claim: caller must prove ownership
        if (callerToken && callerToken === existing.owner_token) {
          return Response.json({
            id: existing.id,
            email: existing.email,
            created_at: existing.created_at,
            owner_token: existing.owner_token,
          });
        }
        // No token or wrong token → reject
        return Response.json({ error: "Email already taken. Try another prefix." }, { status: 409 });
      }

      // Insert new inbox
      const id = generateId();
      const ownerToken = generateOwnerToken();
      const now = Math.floor(Date.now() / 1000);

      try {
        await env.DB.prepare("INSERT INTO inboxes (id, email, owner_token, created_at, expires_at) VALUES (?, ?, ?, ?, 0)")
          .bind(id, email, ownerToken, now)
          .run();
      } catch (e) {
        // UNIQUE constraint race — another request inserted between our SELECT and INSERT
        if (e.message && e.message.includes("UNIQUE")) {
          return Response.json({ error: "Email already taken. Try another prefix." }, { status: 409 });
        }
        throw e;
      }

      return Response.json({
        id,
        email,
        created_at: now,
        owner_token: ownerToken,
      });
    }

    // --- Random prefix path (with retry) ---
    for (let attempt = 0; attempt < MAX_RANDOM_RETRIES; attempt++) {
      const randomPrefix = generateRandomPrefix();
      const email = `${randomPrefix}@${DOMAIN}`;
      const id = generateId();
      const ownerToken = generateOwnerToken();
      const now = Math.floor(Date.now() / 1000);

      try {
        await env.DB.prepare("INSERT INTO inboxes (id, email, owner_token, created_at, expires_at) VALUES (?, ?, ?, ?, 0)")
          .bind(id, email, ownerToken, now)
          .run();

        return Response.json({
          id,
          email,
          created_at: now,
          owner_token: ownerToken,
        });
      } catch (e) {
        // UNIQUE collision on random name — retry with a different name
        if (e.message && e.message.includes("UNIQUE")) {
          continue;
        }
        throw e;
      }
    }

    return Response.json({ error: "Failed to generate a unique address. Please try again." }, { status: 500 });
  } catch (e) {
    console.error("Create inbox error:", e);
    return Response.json({ error: "Failed to create inbox." }, { status: 500 });
  }
}

// ========== DELETE /api/inbox — Delete inbox & cascaded messages ==========
export async function onRequestDelete(context) {
  const { env, request } = context;
  const url = new URL(request.url);
  const inboxId = url.searchParams.get("id");
  const ownerToken = request.headers.get("X-Owner-Token");

  if (!inboxId) {
    return Response.json({ error: "id parameter required." }, { status: 400 });
  }
  if (!ownerToken) {
    return Response.json({ error: "Owner token required." }, { status: 403 });
  }

  try {
    const inbox = await env.DB.prepare("SELECT id, owner_token FROM inboxes WHERE id = ?")
      .bind(inboxId)
      .first();

    if (!inbox) {
      return Response.json({ error: "Inbox not found." }, { status: 404 });
    }

    if (inbox.owner_token !== ownerToken) {
      return Response.json({ error: "Unauthorized." }, { status: 403 });
    }

    // Delete messages first (in case CASCADE isn't enabled at runtime)
    await env.DB.prepare("DELETE FROM messages WHERE inbox_id = ?").bind(inboxId).run();
    await env.DB.prepare("DELETE FROM inboxes WHERE id = ?").bind(inboxId).run();

    return Response.json({ success: true, message: "Inbox and all messages deleted." });
  } catch (e) {
    console.error("Delete inbox error:", e);
    return Response.json({ error: "Failed to delete inbox." }, { status: 500 });
  }
}
