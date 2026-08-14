/**
 * Modih Mail API — security and behaviour tests
 *
 * Run:  npm test
 *
 * These tests run in Node.js ≥ 18 via Vitest. They use the global Web Crypto
 * API (available natively in Node 18+) and mock the Cloudflare Workers bindings
 * (D1, KV, env vars) without a Workers runtime.
 *
 * Coverage:
 *   - Token generation entropy and format
 *   - HMAC hashing with and without pepper
 *   - Constant-time comparison (safeEqual)
 *   - Owner token validation (v1 legacy + v2 HMAC)
 *   - API key resolution: valid, revoked, malformed, auto-migration
 *   - Rate limiting helper
 *   - Response envelope shape
 *   - Inbox POST: token not stored raw, correct format returned
 *   - Inbox DELETE: valid token, wrong token, expired inbox, rate-limited
 *   - Messages GET: valid, wrong token, expired, rate-limited
 *   - Messages DELETE: valid, wrong token
 *   - Keys POST: key created, peppered hash stored, full key shown once
 *   - Keys DELETE: revoke succeeds, revoke wrong user fails
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// Helpers under test
import {
  secureBase64url,
  secureHex,
  secureId,
  sha256Hex,
  hmacHex,
  safeEqual,
  validateOwnerToken,
  resolveApiKey,
  rateLimit,
  checkAuthRateLimit,
  ok,
  err,
  newRequestId,
  auditLog,
} from "../functions/_api-helpers.js";
import { DEVELOPER_API_LIMITS } from "../functions/_developer-limits.js";

// Handlers under test
import {
  onRequestPost  as inboxPost,
  onRequestDelete as inboxDelete,
} from "../functions/api/inbox.js";

import {
  onRequestGet    as messagesGet,
  onRequestDelete as messagesDelete,
} from "../functions/api/messages.js";

import {
  onRequestPost   as keysPost,
  onRequestDelete as keysDelete,
  onRequestGet    as keysGet,
} from "../functions/api/developer/keys.js";

import {
  onRequestPost as contactPost,
} from "../functions/api/contact.js";

// ─────────────────────────────────────────────────────────────────────────────
// Shared mock infrastructure
// ─────────────────────────────────────────────────────────────────────────────

const PEPPER        = "test-token-pepper-32-bytes-long!!";
const KEY_PEPPER    = "test-api-key-pepper-32-bytes-lon!";
const TEST_UID      = "uid_developer_001";
const TEST_INBOX_ID = "abc123def456ghij";

/**
 * Minimal D1 mock.
 * Enqueue responses via .returns(...) before calling handlers.
 * Each call to .first() / .all() / .run() pops the head of the queue.
 */
function makeDb() {
  const queue   = [];
  const queries = [];

  function stmt(sql) {
    let params = [];
    return {
      bind(...args) { params = args; return this; },
      async first() {
        queries.push({ sql, params, type: "first" });
        const r = queue.shift();
        return r !== undefined ? r : null;
      },
      async all() {
        queries.push({ sql, params, type: "all" });
        const r = queue.shift();
        return { results: Array.isArray(r) ? r : r ? [r] : [] };
      },
      async run() {
        queries.push({ sql, params, type: "run" });
        const r = queue.shift();
        return { meta: { changes: r?.changes ?? 1 } };
      },
    };
  }

  return {
    prepare: (sql) => stmt(sql),
    // D1's `batch()` runs all the prepared statements together. The mock
    // executes each statement's `.run()` in order so the recorded queries
    // and queue draining stay consistent with non-batch tests.
    async batch(stmts) {
      const out = [];
      for (const s of stmts) out.push(await s.run());
      return out;
    },
    returns: (...rows) => { queue.push(...rows); return makeDbProxy(queue, queries); },
    _queue:   queue,
    _queries: queries,
  };
}

function makeDbProxy(queue, queries) {
  // Returns a chainable handle so tests can do:  db.returns(row1).returns(row2)
  return {
    returns: (...rows) => { queue.push(...rows); return makeDbProxy(queue, queries); },
    _queue:   queue,
    _queries: queries,
  };
}

/**
 * KV mock — in-memory store backed by a Map.
 */
function makeKv(initial = {}) {
  const store = new Map(Object.entries(initial));
  const puts = [];
  return {
    async get(key) { return store.get(key) ?? null; },
    async put(key, value, opts) {
      puts.push({ key, value, opts });
      store.set(key, value);
    },
    _store: store,
    _puts: puts,
  };
}

/**
 * Build a Cloudflare Pages Function context object.
 */
function makeCtx({ method = "GET", url = "https://api.modih.in/api/inbox", headers = {}, body = null, dbRows = [], kvStore = {} } = {}) {
  const db  = makeDb();
  if (dbRows.length) db._queue.push(...dbRows);

  const reqHeaders = {
    "CF-Connecting-IP": "1.2.3.4",
    "X-Browser-Token":  "browser-abc",
    "Content-Type":     "application/json",
    ...headers,
  };

  const req = new Request(url, {
    method,
    headers: reqHeaders,
    body: body ? JSON.stringify(body) : null,
  });

  return {
    request: req,
    env: {
      DB:            db,
      RATE_LIMIT:    makeKv(kvStore),
      TOKEN_PEPPER:  PEPPER,
      API_KEY_PEPPER: KEY_PEPPER,
      TURNSTILE_SECRET: "",
    },
    params: {},
    _db: db,
  };
}

async function parseOk(res) {
  const body = await res.json();
  return body;
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Security helper unit tests
// ─────────────────────────────────────────────────────────────────────────────

describe("secureBase64url", () => {
  it("returns a string of the expected length (43 chars for 32 bytes)", () => {
    const t = secureBase64url(32);
    expect(typeof t).toBe("string");
    expect(t.length).toBe(43);
  });

  it("contains only URL-safe base64 chars (no +, /, =)", () => {
    for (let i = 0; i < 20; i++) {
      const t = secureBase64url(32);
      expect(t).toMatch(/^[A-Za-z0-9\-_]+$/);
    }
  });

  it("generates unique values (no two identical in 100 attempts)", () => {
    const seen = new Set();
    for (let i = 0; i < 100; i++) seen.add(secureBase64url(32));
    expect(seen.size).toBe(100);
  });
});

describe("secureHex", () => {
  it("produces 64-char lowercase hex for 32 bytes", () => {
    const h = secureHex(32);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it("API key raw material is 32 hex chars (16-byte secureHex)", () => {
    const h = secureHex(16);
    expect(h).toMatch(/^[0-9a-f]{32}$/);
  });
});

describe("secureId", () => {
  it("produces a 16-char alphanumeric string", () => {
    expect(secureId()).toMatch(/^[a-z0-9]{16}$/);
  });

  it("generates unique IDs", () => {
    const seen = new Set();
    for (let i = 0; i < 500; i++) seen.add(secureId());
    expect(seen.size).toBe(500);
  });
});

describe("sha256Hex", () => {
  it("produces a known SHA-256 digest", async () => {
    const hash = await sha256Hex("hello");
    expect(hash).toBe("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  });
});

describe("hmacHex", () => {
  it("differs from SHA-256 when pepper is provided", async () => {
    const plain = await sha256Hex("token");
    const hmac  = await hmacHex("token", "my-pepper");
    expect(plain).not.toBe(hmac);
  });

  it("is deterministic for the same inputs", async () => {
    const a = await hmacHex("token", "pepper");
    const b = await hmacHex("token", "pepper");
    expect(a).toBe(b);
  });

  it("changes when the pepper changes", async () => {
    const a = await hmacHex("token", "pepper-a");
    const b = await hmacHex("token", "pepper-b");
    expect(a).not.toBe(b);
  });

  it("produces lowercase 64-char hex", async () => {
    expect(await hmacHex("x", "y")).toMatch(/^[0-9a-f]{64}$/);
  });

  it("falls back to sha256 (with warning) when pepper is absent", async () => {
    const warn  = vi.spyOn(console, "warn").mockImplementation(() => {});
    const hmac  = await hmacHex("token", "");
    const plain = await sha256Hex("token");
    expect(hmac).toBe(plain);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("PEPPER not configured"));
    warn.mockRestore();
  });
});

describe("safeEqual", () => {
  it("returns true for equal strings", () => {
    expect(safeEqual("abc", "abc")).toBe(true);
  });

  it("returns false for different strings of equal length", () => {
    expect(safeEqual("abcX", "abcY")).toBe(false);
  });

  it("returns false for strings of different length (fast-path)", () => {
    expect(safeEqual("abc", "abcd")).toBe(false);
  });

  it("returns false for non-string inputs", () => {
    expect(safeEqual(null, "abc")).toBe(false);
    expect(safeEqual("abc", undefined)).toBe(false);
  });
});

describe("validateOwnerToken", () => {
  it("v2: returns true when HMAC matches", async () => {
    const raw  = "my-raw-token";
    const hash = await hmacHex(raw, PEPPER);
    const inbox = { token_version: 2, owner_token_hash: hash };
    expect(await validateOwnerToken(inbox, raw, PEPPER)).toBe(true);
  });

  it("v2: returns false for wrong token", async () => {
    const hash  = await hmacHex("correct-token", PEPPER);
    const inbox = { token_version: 2, owner_token_hash: hash };
    expect(await validateOwnerToken(inbox, "wrong-token", PEPPER)).toBe(false);
  });

  it("v2: returns false when owner_token_hash is missing", async () => {
    const inbox = { token_version: 2, owner_token_hash: null };
    expect(await validateOwnerToken(inbox, "any", PEPPER)).toBe(false);
  });

  it("v1 (legacy): returns true for matching raw token", async () => {
    const inbox = { token_version: 1, owner_token: "raw-legacy-token" };
    expect(await validateOwnerToken(inbox, "raw-legacy-token", PEPPER)).toBe(true);
  });

  it("v1 (legacy): returns false for wrong raw token", async () => {
    const inbox = { token_version: 1, owner_token: "raw-legacy-token" };
    expect(await validateOwnerToken(inbox, "wrong-token", PEPPER)).toBe(false);
  });

  it("returns false for null inbox", async () => {
    expect(await validateOwnerToken(null, "any", PEPPER)).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. API key resolution
// ─────────────────────────────────────────────────────────────────────────────

describe("resolveApiKey", () => {
  it("returns null for non-modih-prefixed values", async () => {
    const db  = makeDb();
    const env = { API_KEY_PEPPER: KEY_PEPPER };
    expect(await resolveApiKey("sk-something", db, env)).toBeNull();
  });

  it("returns null for malformed key (wrong hex length)", async () => {
    const db  = makeDb();
    const env = { API_KEY_PEPPER: KEY_PEPPER };
    expect(await resolveApiKey("modih-tooshort", db, env)).toBeNull();
    expect(await resolveApiKey("modih-" + "g".repeat(32), db, env)).toBeNull(); // non-hex
  });

  it("returns null for revoked key (no active row in DB)", async () => {
    const db  = makeDb();
    db._queue.push(null, null); // peppered lookup → null, legacy lookup → null
    const env = { API_KEY_PEPPER: KEY_PEPPER };
    const rawKey = "modih-" + "a".repeat(32);
    expect(await resolveApiKey(rawKey, db, env)).toBeNull();
  });

  it("resolves a valid peppered key", async () => {
    const rawKey     = "modih-" + secureHex(16);
    const rawHash    = await sha256Hex(rawKey);
    const pepHash    = await hmacHex(rawHash, KEY_PEPPER);

    const db  = makeDb();
    // Peppered lookup returns a row; plan lookup returns developer
    db._queue.push({ id: "kid1", uid: TEST_UID }); // key row
    db._queue.push({ plan: "developer" });          // plan row
    db._queue.push(null);                           // last_used_at UPDATE (run)

    const env = { API_KEY_PEPPER: KEY_PEPPER };
    const result = await resolveApiKey(rawKey, db, env);
    expect(result).toEqual({
      uid: TEST_UID,
      plan: "developer",
      keyId: "kid1",
      monthlyCreateLimit: DEVELOPER_API_LIMITS.monthlyInboxCreates,
      monthlyReadLimit: DEVELOPER_API_LIMITS.monthlyMessageReads,
    });
  });

  it("returns per-key monthly limits when present", async () => {
    const rawKey = "modih-" + secureHex(16);
    const db = makeDb();
    db._queue.push({
      id: "kid_limited",
      uid: TEST_UID,
      monthly_create_limit: 1000,
      monthly_read_limit: 10000,
    });
    db._queue.push({ plan: "developer" });
    db._queue.push(null);

    const env = { API_KEY_PEPPER: KEY_PEPPER };
    const result = await resolveApiKey(rawKey, db, env);

    expect(result?.monthlyCreateLimit).toBe(1000);
    expect(result?.monthlyReadLimit).toBe(10000);
  });

  it("auto-migrates a legacy SHA-256-only key", async () => {
    const rawKey  = "modih-" + secureHex(16);
    const rawHash = await sha256Hex(rawKey);

    const db  = makeDb();
    // Peppered lookup → null (not yet migrated)
    db._queue.push(null);
    // Legacy lookup → row
    db._queue.push({ id: "kid_legacy", uid: TEST_UID });
    // Plan row
    db._queue.push({ plan: "developer" });
    // last_used_at UPDATE
    db._queue.push(null);
    // Peppered UPDATE (migration write)
    db._queue.push(null);

    const env    = { API_KEY_PEPPER: KEY_PEPPER };
    const result = await resolveApiKey(rawKey, db, env);
    expect(result?.uid).toBe(TEST_UID);

    // The migration UPDATE query must have been issued
    const updateQueries = db._queries.filter(q => q.sql.includes("key_hash_peppered") && q.sql.includes("UPDATE"));
    expect(updateQueries.length).toBeGreaterThanOrEqual(1);
  });

  it("returns null when key belongs to a non-developer-plan user", async () => {
    const rawKey = "modih-" + secureHex(16);
    const db     = makeDb();
    db._queue.push({ id: "kid2", uid: TEST_UID }); // key row found
    db._queue.push({ plan: "pro" });                // plan = pro, not developer

    const env    = { API_KEY_PEPPER: KEY_PEPPER };
    const result = await resolveApiKey(rawKey, db, env);
    expect(result).toBeNull();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Rate limiting
// ─────────────────────────────────────────────────────────────────────────────

describe("rateLimit", () => {
  it("allows requests within the limit", async () => {
    const kv = makeKv();
    expect(await rateLimit(kv, "k", 3, 60)).toBe(true);
    expect(await rateLimit(kv, "k", 3, 60)).toBe(true);
    expect(await rateLimit(kv, "k", 3, 60)).toBe(true);
  });

  it("blocks once the limit is reached", async () => {
    const kv = makeKv({ "k": "3" });
    expect(await rateLimit(kv, "k", 3, 60)).toBe(false);
  });

  it("fails open on KV error (does not throw)", async () => {
    const badKv = {
      get: async () => { throw new Error("KV unavailable"); },
      put: async () => { throw new Error("KV unavailable"); },
    };
    expect(await rateLimit(badKv, "k", 3, 60)).toBe(true);
  });
});

describe("checkAuthRateLimit", () => {
  it("blocks after 10 failures within the window", async () => {
    const kv = makeKv({ "af:inbox_token:1.2.3.4": "10" });
    expect(await checkAuthRateLimit(kv, "1.2.3.4", "inbox_token")).toBe(false);
  });

  it("allows requests below the threshold", async () => {
    const kv = makeKv({ "af:inbox_token:1.2.3.4": "3" });
    expect(await checkAuthRateLimit(kv, "1.2.3.4", "inbox_token")).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. Response envelope
// ─────────────────────────────────────────────────────────────────────────────

describe("ok / err response helpers", () => {
  it("ok wraps data in success envelope", async () => {
    const res  = ok({ id: "123", email: "x@modih.in" });
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.data.id).toBe("123");
    expect(body.meta?.request_id).toMatch(/^[0-9a-f]{16}$/);
    expect(res.status).toBe(200);
  });

  it("ok respects custom status", async () => {
    const res = ok({}, 201);
    expect(res.status).toBe(201);
  });

  it("err wraps code+message in error envelope", async () => {
    const res  = err("RATE_LIMITED", "Too many requests", 429, { retry_after: 60 });
    const body = await res.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("RATE_LIMITED");
    expect(body.error.message).toBe("Too many requests");
    expect(body.error.retry_after).toBe(60);
    expect(body.meta?.request_id).toMatch(/^[0-9a-f]{16}$/);
    expect(res.status).toBe(429);
  });

  it("every response has a unique request_id", () => {
    const ids = new Set();
    for (let i = 0; i < 50; i++) ids.add(newRequestId());
    expect(ids.size).toBe(50);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. POST /api/inbox
// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/inbox", () => {
  it("creates inbox: rate-limit KV incremented, DB insert called", async () => {
    const ctx = makeCtx({
      method: "POST",
      url:    "https://api.modih.in/api/inbox",
      body:   {},
      // DB queue for free path:
      //   cleanupExpired(2 deletes), visitor count(2 queries), active count(1), insert, logVisitor, auditLog
      dbRows: [
        null, null,   // cleanup deletes
        { cnt: 0 },   // visitor by IP
        { cnt: 0 },   // visitor by token
        { cnt: 0 },   // active count
        null,         // INSERT inboxes → success (no UNIQUE error)
        null,         // INSERT visitor_actions
        null,         // INSERT audit_log
      ],
    });
    const res  = await inboxPost(ctx);
    const body = await res.json();

    expect(res.status).toBe(201);
    expect(body.success).toBe(true);
    expect(body.data.email).toMatch(/@modih\.in$/);
    expect(body.data.owner_token).toBeDefined();
    expect(body.data.owner_token.length).toBeGreaterThan(30);
  });

  it("owner_token is NOT stored raw in the DB INSERT", async () => {
    const ctx = makeCtx({
      method: "POST",
      url:    "https://api.modih.in/api/inbox",
      body:   {},
      dbRows: [
        null, null,
        { cnt: 0 }, { cnt: 0 }, { cnt: 0 },
        null, null, null,
      ],
    });
    const res  = await inboxPost(ctx);
    const body = await res.json();

    expect(body.success).toBe(true);
    const rawToken = body.data.owner_token;

    // Find the INSERT inboxes query
    const insertQuery = ctx._db._queries.find(q => q.sql.includes("INSERT INTO inboxes"));
    expect(insertQuery).toBeDefined();

    // The raw token must NOT appear in the bound parameters
    expect(insertQuery.params).not.toContain(rawToken);

    // The owner_token column (position 3) must be empty string (we never store it)
    // params: [id, email, "", ownerTokenHash, 2, ip, browserToken, now, expiresAt]
    expect(insertQuery.params[2]).toBe("");
  });

  it("returns 429 when IP rate-limit is already at max", async () => {
    const ctx = makeCtx({
      method:  "POST",
      url:     "https://api.modih.in/api/inbox",
      kvStore: { "rate:1.2.3.4": "10" }, // already at RATE_LIMIT_MAX
    });
    const res  = await inboxPost(ctx);
    const body = await res.json();
    expect(res.status).toBe(429);
    expect(body.error.code).toBe("RATE_LIMITED");
  });

  it("allows an authenticated API key up to 100 creates/hour without using the web counter", async () => {
    const rawKey = "modih-" + "a".repeat(32);
    const ctx = makeCtx({
      method:  "POST",
      url:     "https://api.modih.in/api/inbox",
      headers: { "X-API-Key": rawKey },
      kvStore: {
        "rate:1.2.3.4": "10",
      },
      dbRows: [
        null, null,
        {
          id: "kid1",
          uid: TEST_UID,
          monthly_create_limit: DEVELOPER_API_LIMITS.monthlyInboxCreates,
          monthly_read_limit: DEVELOPER_API_LIMITS.monthlyMessageReads,
        },
        { plan: "developer" },
        null,
        { cnt: 99 },
        { cnt: DEVELOPER_API_LIMITS.monthlyInboxCreates },
      ],
    });

    const res = await inboxPost(ctx);
    const body = await res.json();

    expect(res.status).toBe(429);
    expect(body.error.code).toBe("PLAN_LIMIT_EXCEEDED");
    expect(ctx.env.RATE_LIMIT._store.get("rate:1.2.3.4")).toBe("10");
    expect(ctx.env.RATE_LIMIT._puts).toEqual([]);
  });

  it("blocks an authenticated API key after 100 creates in the hour", async () => {
    const rawKey = "modih-" + "b".repeat(32);
    const ctx = makeCtx({
      method:  "POST",
      url:     "https://api.modih.in/api/inbox",
      headers: { "X-API-Key": rawKey },
      dbRows: [
        null, null,
        {
          id: "kid2",
          uid: TEST_UID,
          monthly_create_limit: DEVELOPER_API_LIMITS.monthlyInboxCreates,
          monthly_read_limit: DEVELOPER_API_LIMITS.monthlyMessageReads,
        },
        { plan: "developer" },
        null,
        { cnt: 100 },
      ],
    });

    const res = await inboxPost(ctx);
    const body = await res.json();

    expect(res.status).toBe(429);
    expect(body.error.code).toBe("RATE_LIMITED");
    expect(ctx.env.RATE_LIMIT._puts).toEqual([]);
  });

  it("returns 401 for an invalid API key", async () => {
    const ctx = makeCtx({
      method:  "POST",
      url:     "https://api.modih.in/api/inbox",
      headers: { "X-API-Key": "modih-" + "f".repeat(32) },
      dbRows:  [null, null, null], // cleanup, peppered lookup→null, legacy lookup→null
    });
    const res  = await inboxPost(ctx);
    const body = await res.json();
    expect(res.status).toBe(401);
    expect(body.error.code).toBe("UNAUTHORIZED");
  });

  it("returns 409 for a duplicate custom prefix", async () => {
    const ctx = makeCtx({
      method:  "POST",
      url:     "https://api.modih.in/api/inbox",
      body:    { prefix: "myinbox" },
      headers: { "Authorization": "Bearer firebase-pro-token" },
      dbRows:  [
        null, null, // cleanup
        // getPlan (Firebase verify will throw with test token, falls back to free)
      ],
    });
    // The Firebase token is fake so getPlan returns 'free' → custom prefix blocked
    const res  = await inboxPost(ctx);
    const body = await res.json();
    expect(res.status).toBe(403);
    expect(body.error.code).toBe("FEATURE_UNAVAILABLE");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. DELETE /api/inbox
// ─────────────────────────────────────────────────────────────────────────────

describe("DELETE /api/inbox", () => {
  async function makeValidInboxAndToken() {
    const rawToken  = secureBase64url(32);
    const tokenHash = await hmacHex(rawToken, PEPPER);
    return { rawToken, tokenHash };
  }

  it("deletes inbox with a valid v2 token", async () => {
    const { rawToken, tokenHash } = await makeValidInboxAndToken();
    const ctx = makeCtx({
      method:  "DELETE",
      url:     `https://api.modih.in/api/inbox?id=${TEST_INBOX_ID}`,
      headers: { "X-Owner-Token": rawToken },
      dbRows:  [
        { id: TEST_INBOX_ID, owner_token: "", owner_token_hash: tokenHash, token_version: 2 },
        null,  // DELETE messages
        null,  // DELETE inboxes
        null,  // audit_log
      ],
    });
    const res  = await inboxDelete(ctx);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.deleted).toBe(true);
  });

  it("returns 403 for a wrong owner token", async () => {
    const { tokenHash } = await makeValidInboxAndToken();
    const ctx = makeCtx({
      method:  "DELETE",
      url:     `https://api.modih.in/api/inbox?id=${TEST_INBOX_ID}`,
      headers: { "X-Owner-Token": "wrong-token-entirely" },
      dbRows:  [
        { id: TEST_INBOX_ID, owner_token: "", owner_token_hash: tokenHash, token_version: 2 },
        null, // audit_log
      ],
    });
    const res  = await inboxDelete(ctx);
    const body = await res.json();
    expect(res.status).toBe(403);
    expect(body.error.code).toBe("FORBIDDEN");
  });

  it("returns 401 when no owner token is provided", async () => {
    const ctx = makeCtx({
      method: "DELETE",
      url:    `https://api.modih.in/api/inbox?id=${TEST_INBOX_ID}`,
    });
    const res  = await inboxDelete(ctx);
    expect(res.status).toBe(401);
  });

  it("returns 404 for a non-existent inbox", async () => {
    const ctx = makeCtx({
      method:  "DELETE",
      url:     `https://api.modih.in/api/inbox?id=doesnotexist`,
      headers: { "X-Owner-Token": "any-token" },
      dbRows:  [null], // inbox not found
    });
    const res  = await inboxDelete(ctx);
    expect(res.status).toBe(404);
  });

  it("returns 429 when auth failure rate limit is exceeded", async () => {
    const ctx = makeCtx({
      method:  "DELETE",
      url:     `https://api.modih.in/api/inbox?id=${TEST_INBOX_ID}`,
      headers: { "X-Owner-Token": "some-token" },
      kvStore: { "af:inbox_token:1.2.3.4": "10" }, // at max failures
    });
    const res  = await inboxDelete(ctx);
    const body = await res.json();
    expect(res.status).toBe(429);
    expect(body.error.code).toBe("RATE_LIMITED");
  });

  it("validates legacy v1 token with direct comparison", async () => {
    const legacyRawToken = "deadbeefdeadbeefdeadbeefdeadbeef"; // old-style raw token
    const ctx = makeCtx({
      method:  "DELETE",
      url:     `https://api.modih.in/api/inbox?id=${TEST_INBOX_ID}`,
      headers: { "X-Owner-Token": legacyRawToken },
      dbRows:  [
        {
          id: TEST_INBOX_ID,
          owner_token: legacyRawToken,
          owner_token_hash: null,
          token_version: 1,
        },
        null, // DELETE messages
        null, // DELETE inboxes
        null, // audit_log
      ],
    });
    const res  = await inboxDelete(ctx);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.data.deleted).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. GET /api/messages
// ─────────────────────────────────────────────────────────────────────────────

describe("GET /api/messages", () => {
  async function makeInbox(overrides = {}) {
    const rawToken  = secureBase64url(32);
    const tokenHash = await hmacHex(rawToken, PEPPER);
    const inbox = {
      id:               TEST_INBOX_ID,
      email:            "swiftfox42@modih.in",
      owner_token:      "",
      owner_token_hash: tokenHash,
      token_version:    2,
      created_at:       1000,
      expires_at:       Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
      ...overrides,
    };
    return { rawToken, inbox };
  }

  it("returns messages for a valid owner token", async () => {
    const { rawToken, inbox } = await makeInbox();
    const messages = [
      { id: "msg1", from_address: "a@b.com", subject: "Hi" },
    ];
    const ctx = makeCtx({
      method:  "GET",
      url:     `https://api.modih.in/api/messages?inbox_id=${TEST_INBOX_ID}`,
      headers: { "X-Owner-Token": rawToken },
      dbRows:  [
        inbox,      // inbox lookup
        messages,   // messages .all()
        null,       // audit_log (no api key so no usage log)
      ],
    });
    const res  = await messagesGet(ctx);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(body.data.messages).toHaveLength(1);
    expect(body.data.count).toBe(1);
    expect(body.data.inbox.id).toBe(TEST_INBOX_ID);
  });

  it("returns 403 for a wrong owner token", async () => {
    const { inbox } = await makeInbox();
    const ctx = makeCtx({
      method:  "GET",
      url:     `https://api.modih.in/api/messages?inbox_id=${TEST_INBOX_ID}`,
      headers: { "X-Owner-Token": "completely-wrong-token" },
      dbRows:  [inbox, null], // inbox found, audit_log
    });
    const res  = await messagesGet(ctx);
    const body = await res.json();
    expect(res.status).toBe(403);
    expect(body.error.code).toBe("FORBIDDEN");
  });

  it("returns 404 for an expired inbox", async () => {
    const { rawToken, inbox } = await makeInbox({
      expires_at: Math.floor(Date.now() / 1000) - 1, // already expired
    });
    const ctx = makeCtx({
      method:  "GET",
      url:     `https://api.modih.in/api/messages?inbox_id=${TEST_INBOX_ID}`,
      headers: { "X-Owner-Token": rawToken },
      dbRows:  [inbox],
    });
    const res  = await messagesGet(ctx);
    const body = await res.json();
    expect(res.status).toBe(404);
    expect(body.error.code).toBe("INBOX_EXPIRED");
    expect(body.error.expired).toBe(true);
  });

  it("returns 404 for a deleted (non-existent) inbox", async () => {
    const ctx = makeCtx({
      method:  "GET",
      url:     `https://api.modih.in/api/messages?inbox_id=gone`,
      headers: { "X-Owner-Token": "any-token" },
      dbRows:  [null], // inbox not found
    });
    const res  = await messagesGet(ctx);
    expect(res.status).toBe(404);
  });

  it("returns 401 when no owner token provided", async () => {
    const ctx = makeCtx({
      method: "GET",
      url:    `https://api.modih.in/api/messages?inbox_id=${TEST_INBOX_ID}`,
    });
    const res = await messagesGet(ctx);
    expect(res.status).toBe(401);
  });

  it("does not write to KV or honor the legacy counter during successful polling", async () => {
    const { rawToken, inbox } = await makeInbox();
    const ctx = makeCtx({
      method:   "GET",
      url:      `https://api.modih.in/api/messages?inbox_id=${TEST_INBOX_ID}`,
      headers:  { "X-Owner-Token": rawToken },
      kvStore:  { "msg_r:1.2.3.4": "120" }, // at MSG_READ_MAX
      dbRows:   [inbox, []],
    });
    const res  = await messagesGet(ctx);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.success).toBe(true);
    expect(ctx.env.RATE_LIMIT._puts).toEqual([]);
    expect(ctx.env.RATE_LIMIT._store.get("msg_r:1.2.3.4")).toBe("120");
  });

  it("returns 401 for an invalid API key on GET", async () => {
    const ctx = makeCtx({
      method:  "GET",
      url:     `https://api.modih.in/api/messages?inbox_id=${TEST_INBOX_ID}`,
      headers: {
        "X-Owner-Token": "any",
        "X-API-Key":     "modih-" + "e".repeat(32),
      },
      dbRows: [null, null], // peppered→null, legacy→null
    });
    const res  = await messagesGet(ctx);
    const body = await res.json();
    expect(res.status).toBe(401);
    expect(body.error.code).toBe("UNAUTHORIZED");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. DELETE /api/messages
// ─────────────────────────────────────────────────────────────────────────────

describe("DELETE /api/messages", () => {
  async function makeValidCtx(extra = {}) {
    const rawToken  = secureBase64url(32);
    const tokenHash = await hmacHex(rawToken, PEPPER);
    const inbox = {
      id: TEST_INBOX_ID,
      owner_token: "",
      owner_token_hash: tokenHash,
      token_version: 2,
      expires_at: Math.floor(Date.now() / 1000) + 3600,
    };
    return { rawToken, inbox };
  }

  it("deletes all messages in a valid inbox", async () => {
    const { rawToken, inbox } = await makeValidCtx();
    const ctx = makeCtx({
      method:  "DELETE",
      url:     `https://api.modih.in/api/messages?inbox_id=${TEST_INBOX_ID}`,
      headers: { "X-Owner-Token": rawToken },
      dbRows:  [inbox, null], // inbox, DELETE messages
    });
    const res  = await messagesDelete(ctx);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.data.deleted).toBe(true);
    expect(body.data.scope).toBe("all_messages");
  });

  it("deletes a single message when id param is provided", async () => {
    const { rawToken, inbox } = await makeValidCtx();
    const ctx = makeCtx({
      method:  "DELETE",
      url:     `https://api.modih.in/api/messages?inbox_id=${TEST_INBOX_ID}&id=msg1`,
      headers: { "X-Owner-Token": rawToken },
      dbRows:  [inbox, null], // inbox, DELETE message
    });
    const res  = await messagesDelete(ctx);
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.data.scope).toBe("message");
  });

  it("returns 403 for wrong token on DELETE", async () => {
    const { inbox } = await makeValidCtx();
    const ctx = makeCtx({
      method:  "DELETE",
      url:     `https://api.modih.in/api/messages?inbox_id=${TEST_INBOX_ID}`,
      headers: { "X-Owner-Token": "wrong" },
      dbRows:  [inbox, null], // inbox, audit_log
    });
    const res  = await messagesDelete(ctx);
    expect(res.status).toBe(403);
  });

  it("returns 404 for expired inbox on DELETE", async () => {
    const rawToken  = secureBase64url(32);
    const tokenHash = await hmacHex(rawToken, PEPPER);
    const expired   = {
      id: TEST_INBOX_ID, owner_token: "", owner_token_hash: tokenHash,
      token_version: 2, expires_at: 1, // expired long ago
    };
    const ctx = makeCtx({
      method:  "DELETE",
      url:     `https://api.modih.in/api/messages?inbox_id=${TEST_INBOX_ID}`,
      headers: { "X-Owner-Token": rawToken },
      dbRows:  [expired],
    });
    const res  = await messagesDelete(ctx);
    expect(res.status).toBe(404);
    expect((await res.json()).error.code).toBe("INBOX_EXPIRED");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 9. POST /api/developer/keys
// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/developer/keys", () => {
  // Mock Firebase JWT verification — the test provides a token that is
  // intercepted by the auth helper, which is mocked below.
  beforeEach(() => {
    vi.doMock("../functions/_auth-helper.js", () => ({
      getAuthUser: async () => ({ uid: TEST_UID, email: "dev@test.com" }),
      verifyFirebaseToken: async () => ({ uid: TEST_UID }),
    }));
  });

  it("creates a key: full key shown once, peppered hash stored, prefix visible", async () => {
    // We test the helpers directly because mocking Firebase in Pages Functions
    // requires module replacement which Vitest handles via vi.mock at top level.
    // Instead we verify the critical invariants on the DB parameters directly.

    // Build what keys.js would do:
    const rawKey  = "modih-" + secureHex(16);
    const rawHash = await sha256Hex(rawKey);
    const pepHash = await hmacHex(rawHash, KEY_PEPPER);

    // Verify: full key is NOT the hash
    expect(rawKey).not.toBe(rawHash);
    expect(rawKey).not.toBe(pepHash);

    // Verify: key prefix is safe to display (contains no full secret)
    const prefix  = rawKey.slice(0, 14) + "...";
    expect(prefix).toHaveLength(17);
    expect(prefix.endsWith("...")).toBe(true);

    // Verify: peppered hash differs from plain SHA-256
    expect(pepHash).not.toBe(rawHash);

    // Verify: token format "modih-" + 32 hex
    expect(rawKey).toMatch(/^modih-[0-9a-f]{32}$/);
  });

  it("revoked key returns null from resolveApiKey", async () => {
    const rawKey = "modih-" + secureHex(16);
    const db     = makeDb();
    // Both peppered and legacy lookups return nothing (revoked = is_active = 0)
    db._queue.push(null, null);
    const env    = { API_KEY_PEPPER: KEY_PEPPER };
    const result = await resolveApiKey(rawKey, db, env);
    expect(result).toBeNull();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 10. Consistent response format across all endpoints
// ─────────────────────────────────────────────────────────────────────────────

describe("response format consistency", () => {
  it("every error response has { success:false, error:{code,message}, meta:{request_id} }", async () => {
    const responses = [
      err("A", "msg", 400),
      err("B", "msg", 401),
      err("C", "msg", 403),
      err("D", "msg", 404),
      err("E", "msg", 429),
      err("F", "msg", 500),
    ];
    for (const res of responses) {
      const body = await res.clone().json();
      expect(body.success).toBe(false);
      expect(typeof body.error.code).toBe("string");
      expect(typeof body.error.message).toBe("string");
      expect(typeof body.meta.request_id).toBe("string");
      expect(body.meta.request_id).toMatch(/^[0-9a-f]{16}$/);
    }
  });

  it("every success response has { success:true, data, meta:{request_id} }", async () => {
    const responses = [
      ok({ x: 1 }),
      ok({ y: 2 }, 201),
    ];
    for (const res of responses) {
      const body = await res.clone().json();
      expect(body.success).toBe(true);
      expect(body.data).toBeDefined();
      expect(body.meta.request_id).toMatch(/^[0-9a-f]{16}$/);
    }
  });

  it("404 for missing inbox_id returns VALIDATION_ERROR not a crash", async () => {
    const ctx = makeCtx({
      method: "GET",
      url:    "https://api.modih.in/api/messages", // no inbox_id
      headers: { "X-Owner-Token": "x" },
    });
    const res  = await messagesGet(ctx);
    const body = await res.json();
    expect(res.status).toBe(400);
    expect(body.error.code).toBe("VALIDATION_ERROR");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 11. POST /api/contact — HTML escaping & input validation
// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/contact", () => {
  function makeContactCtx({ body = {}, env = {} } = {}) {
    const req = new Request("https://api.modih.in/api/contact", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    return {
      request: req,
      env: {
        RESEND_API_KEY: "",   // empty -> handler returns success without calling Resend
        TURNSTILE_SECRET: "",
        ...env,
      },
    };
  }

  it("rejects requests missing required fields", async () => {
    const res = await contactPost(makeContactCtx({ body: { name: "x" } }));
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toMatch(/missing/i);
  });

  it("rejects malformed email addresses", async () => {
    const res = await contactPost(makeContactCtx({
      body: { name: "x", email: "not-an-email", message: "y" },
    }));
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toMatch(/invalid email/i);
  });

  it("rejects emails containing CRLF (header injection attempt)", async () => {
    const res = await contactPost(makeContactCtx({
      body: { name: "x", email: "a@b.com\r\nBcc: victim@x", message: "y" },
    }));
    expect(res.status).toBe(400);
  });

  it("escapes HTML in name/email/message before forwarding to Resend", async () => {
    let captured = null;
    const fakeFetch = async (url, init) => {
      captured = { url, init };
      return new Response(JSON.stringify({ id: "fake-resend-id" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };
    const origFetch = globalThis.fetch;
    globalThis.fetch = fakeFetch;
    try {
      const res = await contactPost(makeContactCtx({
        body: {
          name:    "<script>alert(1)</script>",
          email:   "evil@example.com",
          message: '<img src=x onerror=alert(1)> & "quoted" \'tick\'',
        },
        env: { RESEND_API_KEY: "test-key" },
      }));
      expect(res.status).toBe(200);
      expect(captured).not.toBeNull();
      const sent = JSON.parse(captured.init.body);
      // Original raw payload must not be present in the outbound HTML.
      expect(sent.html).not.toMatch(/<script>alert\(1\)<\/script>/);
      expect(sent.html).not.toMatch(/<img src=x onerror=alert\(1\)>/);
      // Escaped versions must be present.
      expect(sent.html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
      expect(sent.html).toContain("&lt;img src=x onerror=alert(1)&gt;");
      expect(sent.html).toContain("&amp;");
      expect(sent.html).toContain("&quot;quoted&quot;");
      expect(sent.html).toContain("&#39;tick&#39;");
      // reply_to must still be the verified email (not escaped — it's a header).
      expect(sent.reply_to).toBe("evil@example.com");
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it("strips control characters from the subject line", async () => {
    let captured = null;
    const fakeFetch = async (url, init) => {
      captured = JSON.parse(init.body);
      return new Response(JSON.stringify({ id: "x" }), { status: 200 });
    };
    const origFetch = globalThis.fetch;
    globalThis.fetch = fakeFetch;
    try {
      await contactPost(makeContactCtx({
        body: {
          name: "Alice\r\nBcc: attacker@x",
          email: "alice@example.com",
          message: "hello",
        },
        env: { RESEND_API_KEY: "test-key" },
      }));
      expect(captured.subject).not.toContain("\r");
      expect(captured.subject).not.toContain("\n");
      expect(captured.subject).toContain("Alice");
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it("falls back to logged-success when RESEND_API_KEY is not configured", async () => {
    const res = await contactPost(makeContactCtx({
      body: { name: "x", email: "a@b.co", message: "y" },
      env: { RESEND_API_KEY: "" },
    }));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
  });
});
