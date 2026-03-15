// POST /api/inbox   - Create a new inbox (returns owner_token once)
// DELETE /api/inbox  - Delete an inbox (requires owner_token)

const DOMAIN = "modih.in";
const INBOX_TTL = 3 * 60 * 60; // 3 hours in seconds (free tier)
const RATE_LIMIT_MAX = 10;
const RATE_LIMIT_WINDOW = 3600;
const MAX_RANDOM_RETRIES = 5;

// ========== FREE TIER LIMITS ==========
const FREE_MAX_CREATIONS_24H = 3;
const FREE_MAX_ACTIVE_INBOXES = 1;
const FREE_TURNSTILE_THRESHOLD = 2; // require turnstile after 2nd creation in 24h
const TWENTY_FOUR_HOURS = 24 * 60 * 60;

const TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

async function cleanupExpired(db) {
  const now = Math.floor(Date.now() / 1000);
  try {
    await db.prepare("DELETE FROM messages WHERE inbox_id IN (SELECT id FROM inboxes WHERE expires_at > 0 AND expires_at < ?)").bind(now).run();
    await db.prepare("DELETE FROM inboxes WHERE expires_at > 0 AND expires_at < ?").bind(now).run();
  } catch (e) {
    console.error("Cleanup error:", e);
  }
}

// ========== BLOCKED PREFIXES ==========
const BLOCKED_PREFIXES = new Set([
  "abhnv", "abhinav", "modi", "modih",
  "admin", "administrator", "support", "security", "postmaster",
  "root", "help", "billing", "abuse", "contact", "team", "mail",
  "info", "noreply", "no-reply", "webmaster", "hostmaster",
  "mailer-daemon", "www", "ftp", "smtp", "imap", "pop",
]);

function normalizePrefix(raw) {
  return raw.toLowerCase().replace(/[.\-_]/g, "");
}

function isBlockedPrefix(prefix) {
  const normalized = normalizePrefix(prefix);
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

// ========== VISITOR TRACKING ==========
async function getVisitorCreationCount(db, ip, browserToken) {
  const since = Math.floor(Date.now() / 1000) - TWENTY_FOUR_HOURS;
  try {
    // Count by IP OR browser token (whichever is higher = stricter)
    const byIp = await db.prepare(
      "SELECT COUNT(*) as cnt FROM visitor_actions WHERE ip = ? AND created_at > ?"
    ).bind(ip, since).first();

    const byToken = await db.prepare(
      "SELECT COUNT(*) as cnt FROM visitor_actions WHERE browser_token = ? AND created_at > ?"
    ).bind(browserToken, since).first();

    const ipCount = byIp ? byIp.cnt : 0;
    const tokenCount = byToken ? byToken.cnt : 0;
    return Math.max(ipCount, tokenCount);
  } catch (e) {
    console.error("Visitor count error:", e);
    return 0;
  }
}

async function logVisitorAction(db, ip, browserToken) {
  const now = Math.floor(Date.now() / 1000);
  try {
    await db.prepare(
      "INSERT INTO visitor_actions (ip, browser_token, action, created_at) VALUES (?, ?, 'inbox_create', ?)"
    ).bind(ip, browserToken, now).run();
  } catch (e) {
    console.error("Log visitor action error:", e);
  }
}

async function getActiveInboxCount(db, ip, browserToken) {
  const now = Math.floor(Date.now() / 1000);
  try {
    // Check active inboxes created by this visitor (within the last 24h window, not expired)
    const result = await db.prepare(
      "SELECT COUNT(*) as cnt FROM inboxes i INNER JOIN visitor_actions v ON v.created_at >= (i.created_at - 5) AND v.created_at <= (i.created_at + 5) WHERE (v.ip = ? OR v.browser_token = ?) AND i.expires_at > ?"
    ).bind(ip, browserToken, now).first();
    return result ? result.cnt : 0;
  } catch (e) {
    console.error("Active inbox count error:", e);
    return 0;
  }
}

// ========== TURNSTILE VERIFICATION ==========
async function verifyTurnstile(secret, token, ip) {
  if (!secret || !token) return false;
  try {
    const res = await fetch(TURNSTILE_VERIFY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        secret,
        response: token,
        remoteip: ip,
      }),
    });
    const data = await res.json();
    return data.success === true;
  } catch (e) {
    console.error("Turnstile verify error:", e);
    return false;
  }
}

// ========== POST /api/inbox — Create inbox ==========
export async function onRequestPost(context) {
  const { env, request } = context;
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const browserToken = request.headers.get("X-Browser-Token") || "unknown";

  try {
    const allowed = await checkRateLimit(env, ip);
    if (!allowed) {
      return Response.json({ error: "Rate limit exceeded. Try again later." }, { status: 429 });
    }

    // Cleanup expired inboxes (frees up addresses)
    await cleanupExpired(env.DB);

    const body = await request.json().catch(() => ({}));
    const callerToken = request.headers.get("X-Owner-Token") || "";
    const isCustom = !!body.prefix;

    // ========== FREE TIER: Block custom prefixes ==========
    if (isCustom) {
      return Response.json({
        error: "Custom prefixes are a Pro feature. Upgrade to choose your own email name.",
        upgrade_required: true,
        feature: "custom_prefix",
      }, { status: 403 });
    }

    // ========== FREE TIER: Check visitor limits ==========
    const creationsToday = await getVisitorCreationCount(env.DB, ip, browserToken);

    // Hard block after max creations
    if (creationsToday >= FREE_MAX_CREATIONS_24H) {
      return Response.json({
        error: `You've reached the free limit of ${FREE_MAX_CREATIONS_24H} inboxes per day. Upgrade to Pro for more.`,
        upgrade_required: true,
        feature: "creation_limit",
        creations_today: creationsToday,
        max_creations: FREE_MAX_CREATIONS_24H,
      }, { status: 429 });
    }

    // Check active inbox limit
    const activeCount = await getActiveInboxCount(env.DB, ip, browserToken);
    if (activeCount >= FREE_MAX_ACTIVE_INBOXES) {
      return Response.json({
        error: "Free accounts are limited to 1 active inbox. Delete your current inbox or wait for it to expire, or upgrade to Pro.",
        upgrade_required: true,
        feature: "active_limit",
        active_count: activeCount,
        max_active: FREE_MAX_ACTIVE_INBOXES,
      }, { status: 429 });
    }

    // Require Turnstile after threshold
    const turnstileRequired = creationsToday >= (FREE_TURNSTILE_THRESHOLD - 1);
    if (turnstileRequired) {
      const turnstileToken = body.turnstile_token || "";
      const turnstileSecret = env.TURNSTILE_SECRET || "";

      if (!turnstileToken) {
        return Response.json({
          error: "Please complete the verification challenge.",
          turnstile_required: true,
          creations_today: creationsToday,
          max_creations: FREE_MAX_CREATIONS_24H,
        }, { status: 428 });
      }

      const valid = await verifyTurnstile(turnstileSecret, turnstileToken, ip);
      if (!valid) {
        return Response.json({
          error: "Verification failed. Please try again.",
          turnstile_required: true,
        }, { status: 403 });
      }
    }

    // --- Random prefix path (with retry) ---
    for (let attempt = 0; attempt < MAX_RANDOM_RETRIES; attempt++) {
      const randomPrefix = generateRandomPrefix();
      const email = `${randomPrefix}@${DOMAIN}`;
      const id = generateId();
      const ownerToken = generateOwnerToken();
      const now = Math.floor(Date.now() / 1000);
      const expiresAt = now + INBOX_TTL;

      try {
        await env.DB.prepare("INSERT INTO inboxes (id, email, owner_token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)")
          .bind(id, email, ownerToken, now, expiresAt)
          .run();

        // Log this creation for visitor tracking
        await logVisitorAction(env.DB, ip, browserToken);

        return Response.json({
          id,
          email,
          created_at: now,
          expires_at: expiresAt,
          owner_token: ownerToken,
          creations_today: creationsToday + 1,
          max_creations: FREE_MAX_CREATIONS_24H,
          turnstile_required: (creationsToday + 1) >= (FREE_TURNSTILE_THRESHOLD - 1),
        });
      } catch (e) {
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
