// POST /api/inbox - Create a new inbox
// GET /api/inbox?email=xxx - Get inbox info

const DOMAIN = "modih.in";
const INBOX_TTL = 30 * 60; // 30 minutes in seconds
const RATE_LIMIT_MAX = 10; // max inboxes per IP per hour
const RATE_LIMIT_WINDOW = 3600; // 1 hour

function generateId() {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let id = "";
  for (let i = 0; i < 16; i++) {
    id += chars[Math.floor(Math.random() * chars.length)];
  }
  return id;
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
  const count = current ? parseInt(current) : 0;
  if (count >= RATE_LIMIT_MAX) {
    return false;
  }
  await env.RATE_LIMIT.put(key, String(count + 1), { expirationTtl: RATE_LIMIT_WINDOW });
  return true;
}

async function cleanupExpired(db) {
  const now = Math.floor(Date.now() / 1000);
  try {
    await db.prepare("DELETE FROM messages WHERE inbox_id IN (SELECT id FROM inboxes WHERE expires_at < ?)").bind(now).run();
    await db.prepare("DELETE FROM inboxes WHERE expires_at < ?").bind(now).run();
  } catch (e) {
    console.error("Cleanup error:", e);
  }
}

export async function onRequestPost(context) {
  const { env, request } = context;
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";

  try {
    // Rate limit check
    const allowed = await checkRateLimit(env, ip);
    if (!allowed) {
      return Response.json({ error: "Rate limit exceeded. Try again later." }, { status: 429 });
    }

    // Cleanup expired inboxes
    await cleanupExpired(env.DB);

    const body = await request.json().catch(() => ({}));
    let prefix = body.prefix ? sanitizePrefix(body.prefix) : generateRandomPrefix();

    if (prefix.length < 2) {
      return Response.json({ error: "Prefix must be at least 2 characters." }, { status: 400 });
    }

    const email = `${prefix}@${DOMAIN}`;

    // Check if inbox already exists and is active
    const existing = await env.DB.prepare("SELECT * FROM inboxes WHERE email = ? AND expires_at > ?")
      .bind(email, Math.floor(Date.now() / 1000))
      .first();

    if (existing) {
      return Response.json({
        id: existing.id,
        email: existing.email,
        created_at: existing.created_at,
        expires_at: existing.expires_at,
      });
    }

    const id = generateId();
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + INBOX_TTL;

    await env.DB.prepare("INSERT INTO inboxes (id, email, created_at, expires_at) VALUES (?, ?, ?, ?)")
      .bind(id, email, now, expiresAt)
      .run();

    return Response.json({
      id,
      email,
      created_at: now,
      expires_at: expiresAt,
    });
  } catch (e) {
    console.error("Create inbox error:", e);
    return Response.json({ error: "Failed to create inbox." }, { status: 500 });
  }
}

export async function onRequestGet(context) {
  const { env, request } = context;
  const url = new URL(request.url);
  const email = url.searchParams.get("email");

  if (!email) {
    return Response.json({ error: "Email parameter required." }, { status: 400 });
  }

  try {
    const inbox = await env.DB.prepare("SELECT * FROM inboxes WHERE email = ? AND expires_at > ?")
      .bind(email, Math.floor(Date.now() / 1000))
      .first();

    if (!inbox) {
      return Response.json({ error: "Inbox not found or expired." }, { status: 404 });
    }

    return Response.json({
      id: inbox.id,
      email: inbox.email,
      created_at: inbox.created_at,
      expires_at: inbox.expires_at,
    });
  } catch (e) {
    console.error("Get inbox error:", e);
    return Response.json({ error: "Failed to get inbox." }, { status: 500 });
  }
}
