/**
 * Shared security utilities for the Modih Mail API.
 *
 * Token security model
 * ────────────────────
 * Owner tokens   32 random bytes → base64url (256-bit entropy)
 *                DB stores HMAC-SHA256(token, TOKEN_PEPPER)  ← never the raw token
 *                Raw token returned once at inbox creation, never again.
 *
 * API keys       "modih-" + 16 random bytes as hex (128-bit entropy)
 *                DB stores HMAC-SHA256(SHA-256(rawKey), API_KEY_PEPPER)
 *                Existing rows (SHA-256 only) auto-migrate on first successful use.
 *
 * Response envelope
 * ─────────────────
 * Success  { success: true,  data: {...}, meta: { request_id } }
 * Error    { success: false, error: { code, message, ...extras }, meta: { request_id } }
 */

// ── Token / ID generation ────────────────────────────────────────────────────

/**
 * n random bytes as lowercase hex (2n chars).
 */
export function secureHex(byteCount = 32) {
  const buf = new Uint8Array(byteCount);
  crypto.getRandomValues(buf);
  return Array.from(buf, b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * n random bytes as base64url, no padding.
 * 32 bytes → 43 chars, 256 bits. Safe for HTTP headers and URLs.
 */
export function secureBase64url(byteCount = 32) {
  const buf = new Uint8Array(byteCount);
  crypto.getRandomValues(buf);
  return btoa(String.fromCharCode(...buf))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Cryptographically secure alphanumeric ID (replaces Math.random()-based generateId).
 * Uses rejection sampling for uniform distribution over a-z0-9.
 * 216 = floor(256/36)*36 — bytes ≥ 216 are skipped.
 */
export function secureId(length = 16) {
  const CHARS = "abcdefghijklmnopqrstuvwxyz0123456789";
  const buf = new Uint8Array(length * 3); // 3× headroom — rejection hits ~15% of bytes
  crypto.getRandomValues(buf);
  let id = "";
  for (const b of buf) {
    if (id.length >= length) break;
    if (b < 216) id += CHARS[b % 36];
  }
  return id.padEnd(length, "a"); // vanishingly unlikely to reach this
}

// ── Hashing ──────────────────────────────────────────────────────────────────

/**
 * SHA-256(str) → lowercase hex.
 * Used only for legacy API key hash lookup during the migration window.
 */
export async function sha256Hex(str) {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(str)
  );
  return Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * HMAC-SHA256(data, pepper) → lowercase hex.
 * All secrets stored in the DB use this scheme.
 *
 * If pepper is absent the function falls back to plain SHA-256 and logs a
 * loud warning so missing secrets are caught during development/staging.
 * In production TOKEN_PEPPER and API_KEY_PEPPER must always be set.
 */
export async function hmacHex(data, pepper) {
  if (!pepper) {
    console.warn("[security] PEPPER not configured — hashing without a secret key. Set TOKEN_PEPPER / API_KEY_PEPPER.");
    return sha256Hex(data);
  }
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(pepper),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data)
  );
  return Array.from(new Uint8Array(sig), b => b.toString(16).padStart(2, "0")).join("");
}

// ── Constant-time comparison ─────────────────────────────────────────────────

/**
 * Constant-time string comparison — prevents timing-oracle attacks on tokens.
 * Always iterates the full length of the expected value.
 * Returns false immediately (not constant-time) for length mismatches, which
 * is safe here: a length mismatch leaks no useful information about the secret.
 */
export function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// ── Owner token validation ───────────────────────────────────────────────────

/**
 * Validate a provided owner token against a DB inbox row.
 *
 * token_version = 1 (legacy)  raw string in owner_token column, direct compare
 * token_version = 2 (current) HMAC in owner_token_hash column
 *
 * V1 inboxes expire within their TTL (max 30 days). Once all v1 inboxes have
 * expired this branch can be removed.
 */
export async function validateOwnerToken(inbox, provided, pepper) {
  if (!inbox || !provided || typeof provided !== "string") return false;

  if (inbox.token_version === 2) {
    if (!inbox.owner_token_hash) return false;
    const expected = await hmacHex(provided, pepper);
    return safeEqual(inbox.owner_token_hash, expected);
  }

  // Legacy v1 — plain compare (still constant-time via safeEqual)
  return safeEqual(inbox.owner_token || "", provided);
}

// ── API Key resolution ───────────────────────────────────────────────────────

/**
 * Resolve an X-API-Key header value against the DB.
 *
 * Two-phase lookup with transparent migration:
 *   1. Try key_hash_peppered = HMAC-SHA256(SHA-256(rawKey), API_KEY_PEPPER)
 *   2. Fall back to legacy key_hash = SHA-256(rawKey)
 *      → on match, writes the peppered hash automatically (fire-and-forget)
 *
 * Format validation: "modih-" + exactly 32 lowercase hex chars.
 *
 * @returns {{ uid: string, plan: "developer", keyId: string, monthlyCreateLimit: number, monthlyReadLimit: number } | null}
 */
export async function resolveApiKey(keyValue, db, env) {
  if (!keyValue || typeof keyValue !== "string") return null;
  if (!keyValue.startsWith("modih-")) return null;

  // Strict format check — rejects obviously malformed inputs fast
  const rest = keyValue.slice(6);
  if (!/^[0-9a-f]{32}$/.test(rest)) return null;

  try {
    const pepper = env.API_KEY_PEPPER || "";
    const rawHash = await sha256Hex(keyValue);
    const pepperedHash = await hmacHex(rawHash, pepper);

    // 1. Peppered lookup (new keys and already-migrated old keys)
    let keyRow = await lookupApiKeyRow(db, "key_hash_peppered", pepperedHash);

    let needsMigration = false;
    if (!keyRow) {
      // 2. Legacy SHA-256-only lookup (pre-migration keys)
      keyRow = await lookupApiKeyRow(db, "key_hash", rawHash);
      if (!keyRow) return null;
      needsMigration = true;
    }

    const now = Math.floor(Date.now() / 1000);
    const planRow = await getCurrentPlanRow(db, keyRow.uid);
    if (planRow?.plan !== "developer") return null;
    if (planRow.plan_expires_at && Number(planRow.plan_expires_at) <= now) {
      db.prepare(
        "UPDATE user_plans SET plan = 'free', updated_at = ?, plan_expires_at = NULL WHERE uid = ?"
      ).bind(now, keyRow.uid).run().catch(() => {});
      return null;
    }

    // Touch last_used_at (best-effort, non-blocking)
    db.prepare("UPDATE api_keys SET last_used_at = ? WHERE id = ?")
      .bind(now, keyRow.id)
      .run()
      .catch(() => {});

    // Auto-migrate legacy key on first successful use
    if (needsMigration) {
      db.prepare("UPDATE api_keys SET key_hash_peppered = ? WHERE id = ?")
        .bind(pepperedHash, keyRow.id)
        .run()
        .catch(() => {});
    }

    return {
      uid: keyRow.uid,
      plan: "developer",
      keyId: keyRow.id,
      monthlyCreateLimit: normalizeApiLimit(keyRow.monthly_create_limit, 5000),
      monthlyReadLimit: normalizeApiLimit(keyRow.monthly_read_limit, 50000),
    };
  } catch (e) {
    console.error("[auth] resolveApiKey error:", e.message);
    return null;
  }
}

async function getCurrentPlanRow(db, uid) {
  try {
    return await db
      .prepare("SELECT plan, plan_expires_at FROM user_plans WHERE uid = ?")
      .bind(uid)
      .first();
  } catch (e) {
    if (!String(e?.message || "").includes("plan_expires_at")) throw e;
    return db.prepare("SELECT plan FROM user_plans WHERE uid = ?").bind(uid).first();
  }
}

async function lookupApiKeyRow(db, hashColumn, hashValue) {
  try {
    return await db
      .prepare(`SELECT id, uid, monthly_create_limit, monthly_read_limit FROM api_keys WHERE ${hashColumn} = ? AND is_active = 1`)
      .bind(hashValue)
      .first();
  } catch (e) {
    // Keeps existing keys working during deploys where code reaches production
    // before the D1 limit columns are migrated.
    if (!String(e?.message || "").includes("monthly_create_limit")) throw e;
    return db
      .prepare(`SELECT id, uid FROM api_keys WHERE ${hashColumn} = ? AND is_active = 1`)
      .bind(hashValue)
      .first();
  }
}

function normalizeApiLimit(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : fallback;
}

// ── Rate limiting ────────────────────────────────────────────────────────────

/**
 * KV-backed sliding-window rate limiter.
 * Returns true if the request is within the limit (allowed).
 * Increments the counter on every call. Fails open on KV errors.
 */
export async function rateLimit(kv, key, max, windowSecs) {
  try {
    const count = parseInt(await kv.get(key) || "0", 10);
    if (count >= max) return false;
    await kv.put(key, String(count + 1), { expirationTtl: windowSecs });
    return true;
  } catch {
    return true; // fail open — never block legitimate traffic on KV failure
  }
}

/**
 * Track auth failures per IP per action and return false when the threshold
 * is exceeded (brute-force protection).
 *
 * Default: 10 failures per 15 minutes per IP per action type.
 * Key format: af:{action}:{ip}
 */
export async function checkAuthRateLimit(kv, ip, action, max = 10, windowSecs = 900) {
  return rateLimit(kv, `af:${action}:${ip}`, max, windowSecs);
}

// ── Response helpers ─────────────────────────────────────────────────────────

/** 16 random hex chars (64 bits) for per-request correlation. */
export function newRequestId() {
  const buf = new Uint8Array(8);
  crypto.getRandomValues(buf);
  return Array.from(buf, b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Standard success response envelope.
 * { success: true, data: {...}, meta: { request_id } }
 */
export function ok(data, status = 200) {
  return Response.json(
    { success: true, data, meta: { request_id: newRequestId() } },
    { status }
  );
}

/**
 * Standard error response envelope.
 * { success: false, error: { code, message, ...extra }, meta: { request_id } }
 *
 * @param {string} code    SCREAMING_SNAKE_CASE machine-readable code
 * @param {string} message Human-readable explanation
 * @param {number} status  HTTP status code
 * @param {object} [extra] Additional fields merged into the error object
 */
export function err(code, message, status, extra = {}) {
  return Response.json(
    {
      success: false,
      error: { code, message, ...extra },
      meta: { request_id: newRequestId() },
    },
    { status }
  );
}

// ── Audit logging ────────────────────────────────────────────────────────────

/**
 * Append a security event row to audit_log (best-effort, non-blocking).
 *
 * NEVER pass tokens, keys, or their hashes in details — only safe metadata.
 * The audit log is for observability, not forensics.
 *
 * @param {D1Database} db
 * @param {string}     event   e.g. "api_key.created", "owner_token.invalid"
 * @param {object}     [opts]  uid?, inboxId?, ip?, extra?
 */
export function auditLog(db, event, { uid = null, inboxId = null, ip = null, extra = {} } = {}) {
  const now = Math.floor(Date.now() / 1000);
  db.prepare(
    "INSERT INTO audit_log (event, uid, inbox_id, ip, details, created_at) VALUES (?, ?, ?, ?, ?, ?)"
  )
    .bind(event, uid, inboxId, ip, JSON.stringify(extra), now)
    .run()
    .catch(e => console.error("[audit] write error:", e.message));
}
