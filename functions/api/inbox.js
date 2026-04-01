// POST   /api/inbox  — Create a new inbox (returns owner_token once, never stored)
// DELETE /api/inbox  — Delete an inbox (requires X-Owner-Token)

import { verifyFirebaseToken } from "../_auth-helper.js";
import {
  secureBase64url,
  secureId,
  hmacHex,
  validateOwnerToken,
  resolveApiKey,
  checkAuthRateLimit,
  rateLimit,
  ok,
  err,
  auditLog,
} from "../_api-helpers.js";

const DOMAIN = "modih.in";
const RATE_LIMIT_MAX    = 10;
const RATE_LIMIT_WINDOW = 3600;
const MAX_RANDOM_RETRIES = 5;

// ========== PLAN LIMITS ==========
const PLAN_CONFIG = {
  free: {
    ttl:          3 * 60 * 60,   // 3 hours
    maxDaily:     3,
    maxActive:    1,
    turnstileAt:  2,             // require captcha after 2nd creation
    customPrefix: false,
    noTurnstile:  false,
  },
  pro: {
    ttl:          7 * 24 * 60 * 60,  // 7 days
    maxDaily:     25,
    maxActive:    10,
    turnstileAt:  99999,
    customPrefix: true,
    noTurnstile:  true,
  },
  developer: {
    ttl:          30 * 24 * 60 * 60, // 30 days
    maxDaily:     999999,
    maxActive:    999999,
    turnstileAt:  99999,
    customPrefix: true,
    noTurnstile:  true,
  },
};

const TWENTY_FOUR_HOURS = 24 * 60 * 60;
const TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const API_MONTHLY_CREATE_LIMIT = 5000;

// ========== HELPERS ==========

async function getMonthlyCreateCount(db, uid) {
  const now = new Date();
  const monthStart = Math.floor(
    new Date(now.getFullYear(), now.getMonth(), 1).getTime() / 1000
  );
  const row = await db
    .prepare(
      "SELECT COUNT(*) as cnt FROM api_usage WHERE uid = ? AND action = 'inbox_create' AND created_at >= ?"
    )
    .bind(uid, monthStart)
    .first();
  return row?.cnt || 0;
}

function logApiUsage(db, uid, action) {
  const now = Math.floor(Date.now() / 1000);
  db.prepare("INSERT INTO api_usage (uid, action, created_at) VALUES (?, ?, ?)")
    .bind(uid, action, now)
    .run()
    .catch(() => {});
}

// Resolve Firebase Bearer token to a plan (free | pro | developer)
async function getPlan(request, db) {
  try {
    const authHeader = request.headers.get("Authorization") || "";
    if (!authHeader.startsWith("Bearer ")) return "free";
    const token = authHeader.slice(7).trim();
    if (!token) return "free";

    const user = await verifyFirebaseToken(token);
    if (!user?.uid) return "free";

    const row = await db
      .prepare("SELECT plan FROM user_plans WHERE uid = ?")
      .bind(user.uid)
      .first();
    let plan = row?.plan || "free";

    // Fallback: resolve by email in case UID wasn't synced yet (admin upgrade path)
    if (user.email) {
      const emailRows = await db
        .prepare("SELECT plan FROM user_plans WHERE LOWER(email) = LOWER(?)")
        .bind(user.email)
        .all();
      let emailBest = "free";
      for (const r of emailRows.results || []) {
        if (r.plan === "developer") { emailBest = "developer"; break; }
        if (r.plan === "pro") emailBest = "pro";
      }
      const rank = { developer: 3, pro: 2, free: 1 };
      if ((rank[emailBest] || 0) > (rank[plan] || 0)) plan = emailBest;
    }

    return ["pro", "developer"].includes(plan) ? plan : "free";
  } catch (e) {
    console.error("getPlan error:", e.message);
    return "free";
  }
}

async function cleanupExpired(db) {
  const now = Math.floor(Date.now() / 1000);
  try {
    await db
      .prepare("DELETE FROM messages WHERE inbox_id IN (SELECT id FROM inboxes WHERE expires_at > 0 AND expires_at < ?)")
      .bind(now)
      .run();
    await db
      .prepare("DELETE FROM inboxes WHERE expires_at > 0 AND expires_at < ?")
      .bind(now)
      .run();
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
  if (BLOCKED_PREFIXES.has(prefix.toLowerCase())) return true;
  if (BLOCKED_PREFIXES.has(normalizePrefix(prefix))) return true;
  return false;
}

/**
 * Secure random prefix using CSPRNG.
 * Replaces Math.random()-based version to prevent predictability.
 */
function generateRandomPrefix() {
  const adjectives = ["swift", "cool", "bright", "lucky", "calm", "bold", "keen", "pure", "wise", "warm"];
  const nouns      = ["fox",   "owl",  "ray",    "star",  "wave", "leaf", "wind", "moon", "dawn", "fire"];
  const buf = new Uint8Array(4);
  crypto.getRandomValues(buf);
  const adj = adjectives[buf[0] % 10];
  const noun = nouns[buf[1] % 10];
  const num = ((buf[2] << 8) | buf[3]) % 1000; // 0-999 from two bytes, <2% bias
  return `${adj}${noun}${num}`;
}

function sanitizePrefix(prefix) {
  return prefix.toLowerCase().replace(/[^a-z0-9._-]/g, "").slice(0, 30);
}

// ========== VISITOR TRACKING ==========
async function getVisitorCreationCount(db, ip, browserToken) {
  const since = Math.floor(Date.now() / 1000) - TWENTY_FOUR_HOURS;
  try {
    const byIp = await db
      .prepare("SELECT COUNT(*) as cnt FROM visitor_actions WHERE ip = ? AND created_at > ?")
      .bind(ip, since)
      .first();
    const byToken = await db
      .prepare("SELECT COUNT(*) as cnt FROM visitor_actions WHERE browser_token = ? AND created_at > ?")
      .bind(browserToken, since)
      .first();
    return Math.max(byIp?.cnt || 0, byToken?.cnt || 0);
  } catch (e) {
    console.error("Visitor count error:", e);
    return 0;
  }
}

async function logVisitorAction(db, ip, browserToken) {
  const now = Math.floor(Date.now() / 1000);
  try {
    await db
      .prepare("INSERT INTO visitor_actions (ip, browser_token, action, created_at) VALUES (?, ?, 'inbox_create', ?)")
      .bind(ip, browserToken, now)
      .run();
  } catch (e) {
    console.error("Log visitor action error:", e);
  }
}

async function getActiveInboxCount(db, ip, browserToken) {
  const now = Math.floor(Date.now() / 1000);
  try {
    const result = await db
      .prepare(
        "SELECT COUNT(*) as cnt FROM inboxes WHERE (creator_ip = ? OR creator_token = ?) AND expires_at > ?"
      )
      .bind(ip, browserToken, now)
      .first();
    return result?.cnt || 0;
  } catch (e) {
    console.error("Active inbox count error:", e);
    return 0;
  }
}

// ========== TURNSTILE ==========
async function verifyTurnstile(secret, token, ip) {
  if (!secret || !token) return false;
  try {
    const res = await fetch(TURNSTILE_VERIFY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret, response: token, remoteip: ip }),
    });
    const data = await res.json();
    return data.success === true;
  } catch (e) {
    console.error("Turnstile verify error:", e);
    return false;
  }
}

// ========== INSERT HELPER ==========
/**
 * Insert a new inbox row.
 * Stores the HMAC hash of the owner token — never the raw token.
 */
async function insertInbox(db, { id, email, ownerTokenHash, creatorIp, creatorToken, now, expiresAt }) {
  await db
    .prepare(
      `INSERT INTO inboxes
         (id, email, owner_token, owner_token_hash, token_version, creator_ip, creator_token, created_at, expires_at)
       VALUES (?, ?, ?, ?, 2, ?, ?, ?, ?)`
    )
    .bind(id, email, "", ownerTokenHash, creatorIp, creatorToken, now, expiresAt)
    .run();
}

// ========== POST /api/inbox — Create inbox ==========
export async function onRequestPost(context) {
  const { env, request } = context;
  const ip           = request.headers.get("CF-Connecting-IP") || "unknown";
  const browserToken = request.headers.get("X-Browser-Token") || "unknown";

  try {
    // IP-level rate limit (protects against rapid inbox spam from one IP)
    const allowed = await rateLimit(env.RATE_LIMIT, `rate:${ip}`, RATE_LIMIT_MAX, RATE_LIMIT_WINDOW);
    if (!allowed) {
      return err("RATE_LIMITED", "Rate limit exceeded. Try again later.", 429);
    }

    await cleanupExpired(env.DB);

    const body     = await request.json().catch(() => ({}));
    const isCustom = !!body.prefix;

    // ── API Key auth (takes priority over Firebase Bearer token) ─────────
    const apiKeyHeader = request.headers.get("X-API-Key") || "";
    let apiKeyAuth = null;
    if (apiKeyHeader) {
      // Auth-failure rate limit before attempting the lookup
      const authOk = await checkAuthRateLimit(env.RATE_LIMIT, ip, "api_key");
      if (!authOk) {
        return err("RATE_LIMITED", "Too many failed authentication attempts. Try again later.", 429);
      }

      apiKeyAuth = await resolveApiKey(apiKeyHeader, env.DB, env);
      if (!apiKeyAuth) {
        auditLog(env.DB, "api_key.auth_failed", { ip });
        return err("UNAUTHORIZED", "Invalid or revoked API key.", 401);
      }
    }

    // ── Resolve user plan ────────────────────────────────────────────────
    const plan   = apiKeyAuth ? apiKeyAuth.plan : await getPlan(request, env.DB);
    const limits = PLAN_CONFIG[plan] || PLAN_CONFIG.free;

    // ── Monthly creation limit for API key requests ──────────────────────
    if (apiKeyAuth) {
      const monthlyCreates = await getMonthlyCreateCount(env.DB, apiKeyAuth.uid);
      if (monthlyCreates >= API_MONTHLY_CREATE_LIMIT) {
        return err(
          "PLAN_LIMIT_EXCEEDED",
          `Monthly API inbox creation limit (${API_MONTHLY_CREATE_LIMIT.toLocaleString()}) reached. Resets on the 1st of next month.`,
          429,
          { used: monthlyCreates, limit: API_MONTHLY_CREATE_LIMIT }
        );
      }
    }

    // ── Custom prefix gate ───────────────────────────────────────────────
    if (isCustom && !limits.customPrefix) {
      return err(
        "FEATURE_UNAVAILABLE",
        "Custom prefixes are a Pro feature. Upgrade to choose your own email name.",
        403,
        { upgrade_required: true, feature: "custom_prefix" }
      );
    }

    // ── Free-tier checks ─────────────────────────────────────────────────
    if (plan === "free") {
      const creationsToday = await getVisitorCreationCount(env.DB, ip, browserToken);

      if (creationsToday >= limits.maxDaily) {
        return err(
          "PLAN_LIMIT_EXCEEDED",
          `You've reached the free limit of ${limits.maxDaily} inboxes per day. Upgrade to Pro for more.`,
          429,
          {
            upgrade_required: true,
            feature: "creation_limit",
            creations_today: creationsToday,
            max_creations: limits.maxDaily,
          }
        );
      }

      const activeCount = await getActiveInboxCount(env.DB, ip, browserToken);
      if (activeCount >= limits.maxActive) {
        return err(
          "PLAN_LIMIT_EXCEEDED",
          "Free accounts are limited to 1 active inbox. Delete your current inbox or wait for it to expire, or upgrade to Pro.",
          429,
          {
            upgrade_required: true,
            feature: "active_limit",
            active_count: activeCount,
            max_active: limits.maxActive,
          }
        );
      }

      // Turnstile after threshold
      const turnstileRequired = creationsToday >= (limits.turnstileAt - 1);
      if (turnstileRequired) {
        const turnstileToken  = body.turnstile_token || "";
        const turnstileSecret = env.TURNSTILE_SECRET || "";
        if (!turnstileToken) {
          return err(
            "CAPTCHA_REQUIRED",
            "Please complete the verification challenge.",
            428,
            { creations_today: creationsToday, max_creations: limits.maxDaily }
          );
        }
        const valid = await verifyTurnstile(turnstileSecret, turnstileToken, ip);
        if (!valid) {
          return err("CAPTCHA_FAILED", "Verification failed. Please try again.", 403);
        }
      }

      // ── Free: random prefix only ──────────────────────────────────────
      const now       = Math.floor(Date.now() / 1000);
      const expiresAt = now + limits.ttl;
      for (let attempt = 0; attempt < MAX_RANDOM_RETRIES; attempt++) {
        const id            = secureId(16);
        const rawToken      = secureBase64url(32);
        const ownerTokenHash = await hmacHex(rawToken, env.TOKEN_PEPPER || "");
        const randomPrefix  = generateRandomPrefix();
        const email         = `${randomPrefix}@${DOMAIN}`;
        try {
          await insertInbox(env.DB, {
            id, email, ownerTokenHash,
            creatorIp: ip, creatorToken: browserToken,
            now, expiresAt,
          });
          await logVisitorAction(env.DB, ip, browserToken);
          auditLog(env.DB, "inbox.created", { inboxId: id, ip });
          return ok({
            id,
            email,
            created_at:       now,
            expires_at:       expiresAt,
            owner_token:      rawToken,   // shown once — never stored
            plan,
            creations_today:  creationsToday + 1,
            max_creations:    limits.maxDaily,
            turnstile_required: (creationsToday + 1) >= (limits.turnstileAt - 1),
          }, 201);
        } catch (e) {
          if (e.message?.includes("UNIQUE")) continue;
          throw e;
        }
      }
      return err("INTERNAL_ERROR", "Failed to generate a unique address. Please try again.", 500);
    }

    // ── Pro / Developer path ─────────────────────────────────────────────
    const now       = Math.floor(Date.now() / 1000);
    const expiresAt = now + limits.ttl;

    if (isCustom) {
      const prefix = sanitizePrefix(body.prefix);
      if (!prefix || prefix.length < 2) {
        return err("VALIDATION_ERROR", "Custom prefix must be at least 2 characters.", 400);
      }
      if (isBlockedPrefix(prefix)) {
        return err("VALIDATION_ERROR", "That prefix is reserved. Please choose a different one.", 400);
      }

      const id             = secureId(16);
      const rawToken       = secureBase64url(32);
      const ownerTokenHash = await hmacHex(rawToken, env.TOKEN_PEPPER || "");
      const email          = `${prefix}@${DOMAIN}`;
      try {
        await insertInbox(env.DB, {
          id, email, ownerTokenHash,
          creatorIp: ip, creatorToken: browserToken,
          now, expiresAt,
        });
        if (apiKeyAuth) logApiUsage(env.DB, apiKeyAuth.uid, "inbox_create");
        auditLog(env.DB, "inbox.created", { uid: apiKeyAuth?.uid, inboxId: id, ip });
        return ok({ id, email, created_at: now, expires_at: expiresAt, owner_token: rawToken, plan }, 201);
      } catch (e) {
        if (e.message?.includes("UNIQUE")) {
          return err("CONFLICT", "That email prefix is already taken. Please try a different one.", 409);
        }
        throw e;
      }
    }

    // Pro/Dev random prefix
    for (let attempt = 0; attempt < MAX_RANDOM_RETRIES; attempt++) {
      const id             = secureId(16);
      const rawToken       = secureBase64url(32);
      const ownerTokenHash = await hmacHex(rawToken, env.TOKEN_PEPPER || "");
      const prefix         = generateRandomPrefix();
      const email          = `${prefix}@${DOMAIN}`;
      try {
        await insertInbox(env.DB, {
          id, email, ownerTokenHash,
          creatorIp: ip, creatorToken: browserToken,
          now, expiresAt,
        });
        if (apiKeyAuth) logApiUsage(env.DB, apiKeyAuth.uid, "inbox_create");
        auditLog(env.DB, "inbox.created", { uid: apiKeyAuth?.uid, inboxId: id, ip });
        return ok({ id, email, created_at: now, expires_at: expiresAt, owner_token: rawToken, plan }, 201);
      } catch (e) {
        if (e.message?.includes("UNIQUE")) continue;
        throw e;
      }
    }
    return err("INTERNAL_ERROR", "Failed to generate a unique address. Please try again.", 500);

  } catch (e) {
    console.error("Create inbox error:", e);
    return err("INTERNAL_ERROR", "Failed to create inbox.", 500);
  }
}


// ========== DELETE /api/inbox — Delete inbox & cascaded messages ==========
export async function onRequestDelete(context) {
  const { env, request } = context;
  const url        = new URL(request.url);
  const inboxId    = url.searchParams.get("id");
  const ownerToken = request.headers.get("X-Owner-Token") || "";
  const ip         = request.headers.get("CF-Connecting-IP") || "unknown";

  if (!inboxId) {
    return err("VALIDATION_ERROR", "id parameter required.", 400);
  }
  if (!ownerToken) {
    return err("UNAUTHORIZED", "Owner token required.", 401);
  }

  // Brute-force protection
  const authOk = await checkAuthRateLimit(env.RATE_LIMIT, ip, "inbox_token");
  if (!authOk) {
    return err("RATE_LIMITED", "Too many failed authentication attempts. Try again later.", 429);
  }

  try {
    const inbox = await env.DB
      .prepare("SELECT id, owner_token, owner_token_hash, token_version FROM inboxes WHERE id = ?")
      .bind(inboxId)
      .first();

    if (!inbox) {
      return err("INBOX_NOT_FOUND", "Inbox not found.", 404);
    }

    const valid = await validateOwnerToken(inbox, ownerToken, env.TOKEN_PEPPER || "");
    if (!valid) {
      auditLog(env.DB, "owner_token.invalid", { inboxId, ip });
      return err("FORBIDDEN", "Owner token mismatch.", 403);
    }

    await env.DB.prepare("DELETE FROM messages WHERE inbox_id = ?").bind(inboxId).run();
    await env.DB.prepare("DELETE FROM inboxes WHERE id = ?").bind(inboxId).run();

    auditLog(env.DB, "inbox.deleted", { inboxId, ip });
    return ok({ deleted: true });

  } catch (e) {
    console.error("Delete inbox error:", e);
    return err("INTERNAL_ERROR", "Failed to delete inbox.", 500);
  }
}
