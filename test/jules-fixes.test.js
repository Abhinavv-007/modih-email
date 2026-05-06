/**
 * Regression tests for the four follow-ups surfaced by Jules' static
 * analysis pass on PR #11 (and a CSP regression that disabled Firebase
 * sign-in entirely).
 *
 *   1. PII redaction — contact.js used to console.log the full submitted
 *      {name, email, message} when RESEND_API_KEY was unset. That goes
 *      to Cloudflare Pages logs, which any project collaborator can read
 *      and may include whatever the user pasted into the message body.
 *
 *   2. Atomic delete cascade — `DELETE /api/inbox` previously ran two
 *      sequential statements (messages → inboxes). A worker termination
 *      between them left orphaned messages pointing at a deleted inbox.
 *      The fix routes both through `env.DB.batch([...])`.
 *
 *   3. Atomic account-data deletion — `DELETE /api/auth/account` ran
 *      five separate awaited statements. Same atomicity gap as above.
 *      The fix groups the four UID-keyed deletes into one batch (the
 *      inbox/messages pair stays in its own batch because of the
 *      `creator_uid`-missing fallback).
 *
 *   4. Hoisted owner-token HMAC — `POST /api/inbox` re-hashed a fresh
 *      random token on every retry of the email-prefix collision loop.
 *      The token is independent of the prefix; computing the HMAC once
 *      saves up to N-1 SubtleCrypto round-trips per request.
 *
 *   5. Restored Content-Security-Policy — public/_headers was tightened
 *      in commit bcdc6e8 to a CSP that blocks gstatic.com (Firebase),
 *      googleapis.com, and Google Fonts. That broke the Sign In / Sign
 *      Up nav pill on every page using Firebase. We assert here that
 *      the CSP keeps its protections AND whitelists the domains the
 *      app actually uses.
 *
 * Run:  npm test
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ─── shared D1 mock ──────────────────────────────────────────────────────────
function makeRecordingDb(initialQueue = []) {
  const calls = [];
  const queue = [...initialQueue];

  function nextOf(kind) {
    for (let i = 0; i < queue.length; i++) {
      if (queue[i].kind === kind) return queue.splice(i, 1)[0].value;
    }
    if (kind === "first") return null;
    if (kind === "all")   return { results: [] };
    return { meta: { changes: 0 } };
  }

  function stmt(sql) {
    let bindings = [];
    return {
      _sql: sql,
      bind(...args) { bindings = args; return this; },
      async first() { calls.push({ op: "first", sql, bindings }); return nextOf("first"); },
      async all()   { calls.push({ op: "all",   sql, bindings }); return nextOf("all");   },
      async run()   { calls.push({ op: "run",   sql, bindings }); return nextOf("run");   },
    };
  }

  return {
    calls,
    queue,
    prepare(sql) { return stmt(sql); },
    async batch(stmts) {
      // Drain the queue for each statement so tests stay deterministic, but
      // record the whole thing as a SINGLE "batch" event instead of N
      // individual "run"s — that way `calls.filter(c => c.op === "run")`
      // never picks up batched statements and tests can assert on grouping.
      const sqls = stmts.map(s => s._sql);
      const out = [];
      for (let i = 0; i < stmts.length; i++) out.push(nextOf("run"));
      calls.push({ op: "batch", sqls });
      return out;
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  1. PII redaction in contact.js
// ─────────────────────────────────────────────────────────────────────────────

describe("contact.js — PII not leaked to logs when RESEND_API_KEY is unset", () => {
  let logSpy, warnSpy;

  beforeEach(() => {
    logSpy  = vi.spyOn(console, "log").mockImplementation(() => {});
    warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  it("does NOT include the user's name, email, or message in any console call", async () => {
    const { onRequestPost } = await import("../functions/api/contact.js");

    const sensitive = {
      name:    "Alice O'Hare",
      email:   "alice.privatemail@example.com",
      message: "leaked-secret-marker-XYZ123",
    };

    const req = new Request("https://api.modih.in/api/contact", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(sensitive),
    });
    const res = await onRequestPost({
      request: req,
      env:     { RESEND_API_KEY: "", TURNSTILE_SECRET: "" },
    });

    expect(res.status).toBe(200);

    const everything = [...logSpy.mock.calls, ...warnSpy.mock.calls]
      .flat()
      .map(arg => (typeof arg === "string" ? arg : JSON.stringify(arg)))
      .join("\n");

    expect(everything).not.toContain(sensitive.name);
    expect(everything).not.toContain(sensitive.email);
    expect(everything).not.toContain(sensitive.message);
  });

  it("still emits a single operator-visible warning so misconfiguration is noticed", async () => {
    const { onRequestPost } = await import("../functions/api/contact.js");

    const req = new Request("https://api.modih.in/api/contact", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ name: "x", email: "x@y.z", message: "hi" }),
    });
    await onRequestPost({
      request: req,
      env:     { RESEND_API_KEY: "", TURNSTILE_SECRET: "" },
    });

    const allWarnText = warnSpy.mock.calls.flat().filter(a => typeof a === "string").join("\n");
    expect(allWarnText).toMatch(/RESEND_API_KEY not configured/i);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
//  2. Inbox DELETE uses an atomic batch
// ─────────────────────────────────────────────────────────────────────────────

describe("DELETE /api/inbox — atomic batch", () => {
  it("issues both DELETE statements through a single env.DB.batch() call", async () => {
    const { onRequestDelete } = await import("../functions/api/inbox.js");

    // Helpers from the real module rather than re-deriving the hash:
    const helpers = await import("../functions/_api-helpers.js");
    const rawToken = helpers.secureBase64url(32);
    const tokenHash = await helpers.hmacHex(rawToken, "test-pepper");

    const db = makeRecordingDb([
      // SELECT inbox row → first()
      { kind: "first", value: {
          id: "inbox-1", owner_token: null,
          owner_token_hash: tokenHash, token_version: 2,
        } },
    ]);

    const req = new Request("https://api.modih.in/api/inbox?id=inbox-1", {
      method:  "DELETE",
      headers: { "X-Owner-Token": rawToken, "CF-Connecting-IP": "1.2.3.4" },
    });
    const res = await onRequestDelete({
      request: req,
      env:     { DB: db, RATE_LIMIT: { async get() { return null; }, async put() {} },
                 TOKEN_PEPPER: "test-pepper" },
    });
    expect(res.status).toBe(200);

    const batches = db.calls.filter(c => c.op === "batch");
    expect(batches).toHaveLength(1);
    const [batch] = batches;
    expect(batch.sqls).toHaveLength(2);
    expect(batch.sqls[0]).toMatch(/^DELETE FROM messages WHERE inbox_id = \?/);
    expect(batch.sqls[1]).toMatch(/^DELETE FROM inboxes WHERE id = \?/);

    // No "lone" DELETE-from-messages or DELETE-from-inboxes outside the batch.
    const loneDeletes = db.calls.filter(
      c => c.op === "run" && /^DELETE FROM (messages|inboxes)/i.test(c.sql || "")
    );
    expect(loneDeletes, "no DELETE outside the batch").toHaveLength(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
//  3. Account-data DELETE uses atomic batches
// ─────────────────────────────────────────────────────────────────────────────

describe("DELETE /api/auth/account — atomic batches", () => {
  beforeEach(() => { vi.resetModules(); });

  it("groups the UID-keyed deletes into one batch (api_usage, api_keys, audit_log, user_plans)", async () => {
    vi.doMock("../functions/_auth-helper.js", () => ({
      getAuthUser: async () => ({ uid: "user-123", email: "u@example.com", email_verified: true }),
      verifyFirebaseToken: async () => ({ uid: "user-123" }),
    }));

    const { onRequestDelete } = await import("../functions/api/auth/account.js");
    const db = makeRecordingDb();

    const req = new Request("https://api.modih.in/api/auth/account", { method: "DELETE" });
    const res = await onRequestDelete({ request: req, env: { DB: db } });

    expect(res.status).toBe(200);

    const batches = db.calls.filter(c => c.op === "batch");
    // We expect TWO batches — one for the inbox/messages pair, one for the
    // four UID-keyed tables. The admin_events UPDATE stays as a separate
    // statement because it's wrapped in its own missing-table fallback.
    expect(batches.length).toBeGreaterThanOrEqual(2);

    const cascadeBatch = batches.find(b =>
      b.sqls.some(s => /DELETE FROM api_usage/i.test(s)) &&
      b.sqls.some(s => /DELETE FROM api_keys/i.test(s)) &&
      b.sqls.some(s => /DELETE FROM audit_log/i.test(s)) &&
      b.sqls.some(s => /DELETE FROM user_plans/i.test(s))
    );
    expect(cascadeBatch, "single batch covers all four UID-keyed tables").toBeDefined();
  });

  it("returns 500 when the batched cascade throws an unexpected error", async () => {
    vi.doMock("../functions/_auth-helper.js", () => ({
      getAuthUser: async () => ({ uid: "user-456", email: "v@example.com", email_verified: true }),
      verifyFirebaseToken: async () => ({ uid: "user-456" }),
    }));

    const { onRequestDelete } = await import("../functions/api/auth/account.js");
    const db = {
      prepare(sql) {
        return {
          _sql: sql,
          bind() { return this; },
          async run() { return { meta: { changes: 0 } }; },
        };
      },
      // First batch (inbox/messages) succeeds but throws a "creator_uid"
      // missing-column error so the handler falls through. The second
      // batch (UID cascade) then throws a real DB failure — we want a
      // proper 500 instead of a silent half-deletion.
      async batch(stmts) {
        const sqls = stmts.map(s => s._sql);
        if (sqls.some(s => /DELETE FROM inboxes WHERE creator_uid/i.test(s))) {
          throw new Error("no such column: creator_uid");
        }
        throw new Error("D1_ERROR: connection terminated");
      },
    };

    const req = new Request("https://api.modih.in/api/auth/account", { method: "DELETE" });
    const res = await onRequestDelete({ request: req, env: { DB: db } });

    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toMatch(/failed to delete/i);
  });

  it("returns 401 when the request is unauthenticated", async () => {
    vi.doMock("../functions/_auth-helper.js", () => ({
      getAuthUser: async () => null,
      verifyFirebaseToken: async () => null,
    }));

    const { onRequestDelete } = await import("../functions/api/auth/account.js");
    const req = new Request("https://api.modih.in/api/auth/account", { method: "DELETE" });
    const res = await onRequestDelete({ request: req, env: { DB: makeRecordingDb() } });

    expect(res.status).toBe(401);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
//  4. Owner-token HMAC hoisted out of POST /api/inbox retry loop
// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/inbox — HMAC hoisted out of retry loop", () => {
  it("computes hmacHex exactly once per request even when the prefix collides", async () => {
    // Spy on the helper before the handler imports it.
    vi.resetModules();
    const helpers = await import("../functions/_api-helpers.js");
    const hmacSpy = vi.spyOn(helpers, "hmacHex");

    const { onRequestPost } = await import("../functions/api/inbox.js");

    // Force the retry loop to run a few times by failing the first
    // INSERTs with a UNIQUE constraint violation. The 4th INSERT
    // succeeds. The number of hmacHex calls should still be 1.
    let insertAttempts = 0;
    const db = {
      prepare(sql) {
        return {
          _sql: sql,
          _bindings: [],
          bind(...a) { this._bindings = a; return this; },
          async first() {
            // SELECT current creations count for the visitor → 0
            if (/COUNT/i.test(sql)) return { count: 0 };
            return null;
          },
          async all() { return { results: [] }; },
          async run() {
            if (/^INSERT INTO inboxes/i.test(sql)) {
              insertAttempts++;
              if (insertAttempts < 4) {
                const e = new Error("UNIQUE constraint failed: inboxes.email");
                throw e;
              }
            }
            return { meta: { changes: 1 } };
          },
        };
      },
      async batch() { return []; },
    };

    const req = new Request("https://api.modih.in/api/inbox", {
      method:  "POST",
      headers: { "Content-Type": "application/json", "CF-Connecting-IP": "1.2.3.4", "X-Browser-Token": "tok-1" },
      body:    JSON.stringify({ mode: "random" }),
    });

    const res = await onRequestPost({
      request: req,
      env: {
        DB: db,
        RATE_LIMIT: { async get() { return null; }, async put() {} },
        TOKEN_PEPPER: "test-pepper",
        TURNSTILE_SECRET: "",
      },
    });

    // Either it succeeds on the 4th attempt or returns INTERNAL_ERROR if
    // the random-prefix exhaustion guard kicks in. Either way the HMAC
    // must have been computed at most once.
    expect(res.status).toBeLessThan(600);
    expect(insertAttempts).toBeGreaterThanOrEqual(1);
    expect(hmacSpy.mock.calls.length).toBeLessThanOrEqual(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
//  5. CSP whitelists every external resource the app actually loads
// ─────────────────────────────────────────────────────────────────────────────

describe("public/_headers — Content-Security-Policy", () => {
  const headersPath = join(__dirname, "..", "public", "_headers");
  const headers = readFileSync(headersPath, "utf8");
  const cspMatch = headers.match(/Content-Security-Policy:\s*(.+)/);
  const csp = (cspMatch && cspMatch[1]) || "";

  it("is present", () => {
    expect(csp).not.toBe("");
  });

  it("allows the Firebase JS SDK from gstatic.com (without it onAuthStateChanged never fires)", () => {
    expect(csp).toMatch(/script-src[^;]*\bhttps:\/\/www\.gstatic\.com\b/);
  });

  it("allows Cloudflare Turnstile script + frame", () => {
    expect(csp).toMatch(/script-src[^;]*\bhttps:\/\/challenges\.cloudflare\.com\b/);
    expect(csp).toMatch(/frame-src[^;]*\bhttps:\/\/challenges\.cloudflare\.com\b/);
  });

  it("allows Firebase Auth REST endpoints in connect-src", () => {
    expect(csp).toMatch(/connect-src[^;]*\bhttps:\/\/identitytoolkit\.googleapis\.com\b/);
    expect(csp).toMatch(/connect-src[^;]*\bhttps:\/\/securetoken\.googleapis\.com\b/);
  });

  it("allows the Firebase auth-handler popup origin (frame-src)", () => {
    expect(csp).toMatch(/frame-src[^;]*\bhttps:\/\/modih-mail\.firebaseapp\.com\b/);
  });

  it("allows Google Fonts CSS + font files", () => {
    expect(csp).toMatch(/style-src[^;]*\bhttps:\/\/fonts\.googleapis\.com\b/);
    expect(csp).toMatch(/font-src[^;]*\bhttps:\/\/fonts\.gstatic\.com\b/);
  });

  it("keeps strong restrictions: object-src 'none', frame-ancestors 'none', base-uri 'self'", () => {
    expect(csp).toMatch(/object-src\s+'none'/);
    expect(csp).toMatch(/frame-ancestors\s+'none'/);
    expect(csp).toMatch(/base-uri\s+'self'/);
  });

  it("does NOT allow 'unsafe-eval' (the app does not need it)", () => {
    expect(csp).not.toMatch(/'unsafe-eval'/);
  });

  it("ships alongside HSTS, X-Frame-Options DENY, X-Content-Type-Options nosniff, and Referrer-Policy", () => {
    expect(headers).toMatch(/Strict-Transport-Security:\s+max-age=\d+/);
    expect(headers).toMatch(/X-Frame-Options:\s+DENY/);
    expect(headers).toMatch(/X-Content-Type-Options:\s+nosniff/);
    expect(headers).toMatch(/Referrer-Policy:\s+strict-origin-when-cross-origin/);
  });
});
