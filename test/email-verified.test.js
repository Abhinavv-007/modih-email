/**
 * Regression tests for the unverified-email account-takeover vector.
 *
 * Pre-fix behaviour:
 *
 *   1. `GET /api/auth/me` looked up `user_plans` rows by `LOWER(email)`
 *      regardless of `email_verified`, then DELETED any orphan row with
 *      that email but a different UID. An attacker who created a
 *      Firebase account using a victim's email — without verifying it —
 *      could inherit the victim's paid plan and *delete* the victim's
 *      legitimate plan row.
 *
 *   2. `getAuthContext` inside `functions/api/inbox.js` did the same
 *      email-based fallback for plan resolution, with the same gap.
 *
 * Post-fix behaviour: any email-driven plan lookup or destructive
 * cleanup MUST require `email_verified === true`. UID-based lookup is
 * unaffected.
 *
 * The tests work by mocking `_auth-helper.js` (which exports both
 * `getAuthUser` and `verifyFirebaseToken`) and a tiny D1 stub that
 * records every prepared query, so we can assert exactly which lookups
 * the handler chose to run.
 *
 * Run:  npm test
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

const VERIFIED_UID    = "uid-verified";
const UNVERIFIED_UID  = "uid-unverified";
const SHARED_EMAIL    = "victim@example.com";
const VICTIM_UID      = "uid-victim-original";

// ─── tiny D1 stub ────────────────────────────────────────────────────────────
//
// We push pre-canned results in the order the handler will consume them
// and record every (sql, bindings) pair. The handler's queries are stable:
//
//   me.js: expireExpired → SELECT byUID → SELECT byEmail (only when
//          email_verified) → INSERT/UPDATE → DELETE orphans → INSERT auth_seen
//
//   inbox.js getAuthContext: expireExpired → SELECT byUID → SELECT byEmail
//          (only when email_verified)
//
// We don't need every column populated — just the SELECTs that drive the
// branching decisions.
function makeRecordingDb({ byUidPlan = null, byEmailPlans = [] } = {}) {
  const calls = [];
  const queue = [];

  // ── Order matters: see the comment above for the call sequence. ──
  // expireExpiredPlans (UPDATE) → run() consumes nothing
  queue.push({ kind: "run", value: { meta: { changes: 0 } } });
  // SELECT byUID → first()
  queue.push({
    kind: "first",
    value: byUidPlan ? { uid: VERIFIED_UID, email: SHARED_EMAIL, plan: byUidPlan } : null,
  });
  // SELECT byEmail → first() (only consumed if email_verified). The handler
  // now resolves the single highest-ranked plan at the DB layer via
  // ORDER BY … LIMIT 1, so we return just that one row (DoS fix, #17).
  const planRank = { developer: 3, pro: 2, free: 1 };
  const bestEmailPlan = byEmailPlans.length
    ? byEmailPlans.reduce((best, p) => ((planRank[p] || 0) > (planRank[best] || 0) ? p : best))
    : null;
  queue.push({
    kind: "first",
    value: bestEmailPlan ? { plan: bestEmailPlan } : null,
  });
  // INSERT or UPDATE on user_plans → run()
  queue.push({ kind: "run", value: { meta: { changes: 1 } } });
  // DELETE orphans → run() (only consumed if email_verified)
  queue.push({ kind: "run", value: { meta: { changes: 0 } } });
  // INSERT into admin_events (logAuthSeen) → run()
  queue.push({ kind: "run", value: { meta: { changes: 1 } } });

  function nextOf(kind) {
    for (let i = 0; i < queue.length; i++) {
      if (queue[i].kind === kind) {
        return queue.splice(i, 1)[0].value;
      }
    }
    if (kind === "first") return null;
    if (kind === "all")   return { results: [] };
    return { meta: { changes: 0 } };
  }

  return {
    calls,
    prepare(sql) {
      const stmt = {
        _sql: sql,
        _bindings: [],
        bind(...args) { stmt._bindings = args; return stmt; },
        async first() {
          calls.push({ sql, bindings: stmt._bindings, op: "first" });
          return nextOf("first");
        },
        async all() {
          calls.push({ sql, bindings: stmt._bindings, op: "all" });
          return nextOf("all");
        },
        async run() {
          calls.push({ sql, bindings: stmt._bindings, op: "run" });
          return nextOf("run");
        },
      };
      return stmt;
    },
  };
}

function makeRequestWithBearer(token = "pretend-jwt") {
  return new Request("https://api.modih.in/api/auth/me", {
    method:  "GET",
    headers: {
      "Authorization":     `Bearer ${token}`,
      "CF-Connecting-IP":  "203.0.113.7",
      "User-Agent":        "vitest",
    },
  });
}

// ─────────────────────────────────────────────────────────────────────────────
//  /api/auth/me — email_verified gate on plan lookup AND orphan deletion
// ─────────────────────────────────────────────────────────────────────────────

describe("/api/auth/me — email_verified gate", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it("UNVERIFIED email: ignores email-based plan match (no inheritance)", async () => {
    vi.doMock("../functions/_auth-helper.js", () => ({
      getAuthUser: async () => ({
        uid:            UNVERIFIED_UID,
        email:          SHARED_EMAIL,
        email_verified: false,                      // ← key
      }),
      verifyFirebaseToken: async () => ({ uid: UNVERIFIED_UID }),
    }));
    const { onRequestGet } = await import("../functions/api/auth/me.js");
    const db  = makeRecordingDb({ byUidPlan: null, byEmailPlans: ["pro", "developer"] });
    const ctx = { request: makeRequestWithBearer(), env: { DB: db } };

    const res  = await onRequestGet(ctx);
    expect(res.status).toBe(200);
    const body = await res.json();

    // The attacker DID NOT inherit the paid plan attached to that email.
    expect(body.plan).toBe("free");
    expect(body.email_verified).toBe(false);

    // No SELECT … WHERE LOWER(email) = LOWER(?) was ever executed.
    const emailLookup = db.calls.find(
      c => c.op === "first" && /WHERE\s+LOWER\(email\)/i.test(c.sql)
    );
    expect(emailLookup, "no email-based plan lookup for unverified user").toBeUndefined();

    // Equally important: no DELETE WHERE email = ? AND uid != ? — the
    // legitimate user's plan row is safe.
    const orphanDelete = db.calls.find(
      c => c.op === "run" &&
           /^DELETE FROM user_plans/i.test(c.sql.trim()) &&
           /uid\s*!=\s*\?/i.test(c.sql)
    );
    expect(orphanDelete, "no destructive orphan cleanup for unverified user").toBeUndefined();
  });

  it("VERIFIED email: inherits the best plan and cleans up orphan rows", async () => {
    vi.doMock("../functions/_auth-helper.js", () => ({
      getAuthUser: async () => ({
        uid:            VERIFIED_UID,
        email:          SHARED_EMAIL,
        email_verified: true,                       // ← key
      }),
      verifyFirebaseToken: async () => ({ uid: VERIFIED_UID }),
    }));
    const { onRequestGet } = await import("../functions/api/auth/me.js");
    const db  = makeRecordingDb({ byUidPlan: null, byEmailPlans: ["pro"] });
    const ctx = { request: makeRequestWithBearer(), env: { DB: db } };

    const res  = await onRequestGet(ctx);
    expect(res.status).toBe(200);
    const body = await res.json();

    expect(body.plan).toBe("pro");
    expect(body.email_verified).toBe(true);

    // The verified path DOES run the email-based lookup …
    const emailLookup = db.calls.find(
      c => c.op === "first" && /WHERE\s+LOWER\(email\)/i.test(c.sql)
    );
    expect(emailLookup, "verified user triggers email lookup").toBeTruthy();
    expect(emailLookup.bindings).toEqual([SHARED_EMAIL]);

    // … and the orphan-row cleanup DELETE.
    const orphanDelete = db.calls.find(
      c => c.op === "run" &&
           /^DELETE FROM user_plans/i.test(c.sql.trim()) &&
           /uid\s*!=\s*\?/i.test(c.sql)
    );
    expect(orphanDelete, "verified user runs orphan cleanup").toBeTruthy();
  });

  it("VERIFIED but no email on the token: no email-based work happens", async () => {
    vi.doMock("../functions/_auth-helper.js", () => ({
      getAuthUser: async () => ({
        uid:            VERIFIED_UID,
        email:          null,
        email_verified: true,
      }),
      verifyFirebaseToken: async () => ({ uid: VERIFIED_UID }),
    }));
    const { onRequestGet } = await import("../functions/api/auth/me.js");
    const db  = makeRecordingDb({ byUidPlan: "free", byEmailPlans: [] });
    const ctx = { request: makeRequestWithBearer(), env: { DB: db } };

    const res = await onRequestGet(ctx);
    expect(res.status).toBe(200);

    const emailLookup = db.calls.find(
      c => c.op === "first" && /WHERE\s+LOWER\(email\)/i.test(c.sql)
    );
    expect(emailLookup).toBeUndefined();

    const orphanDelete = db.calls.find(
      c => c.op === "run" &&
           /^DELETE FROM user_plans/i.test(c.sql.trim()) &&
           /uid\s*!=\s*\?/i.test(c.sql)
    );
    expect(orphanDelete).toBeUndefined();
  });

  it("simulates the takeover scenario end-to-end (post-fix victim is safe)", async () => {
    // Story:
    //   - The admin previously assigned `pro` to `victim@example.com`,
    //     row owned by `uid-victim-original`.
    //   - Attacker registers a Firebase account using the same email
    //     but never verifies it.
    //   - Attacker hits /api/auth/me hoping to inherit `pro` and
    //     delete the legitimate row.
    //
    // Pre-fix, the attacker would receive `{ plan: "pro" }` and the
    // legitimate `uid-victim-original` row would be DELETED. Post-fix,
    // both lookups are skipped because `email_verified === false`.
    vi.doMock("../functions/_auth-helper.js", () => ({
      getAuthUser: async () => ({
        uid:            "attacker-uid",
        email:          SHARED_EMAIL,
        email_verified: false,
      }),
      verifyFirebaseToken: async () => ({ uid: "attacker-uid" }),
    }));
    const { onRequestGet } = await import("../functions/api/auth/me.js");

    const db  = makeRecordingDb({ byUidPlan: null, byEmailPlans: ["pro"] });
    const ctx = { request: makeRequestWithBearer(), env: { DB: db } };

    const res  = await onRequestGet(ctx);
    const body = await res.json();
    expect(body.plan).toBe("free");

    // The victim's row would only be deleted by the orphan-cleanup
    // DELETE. Confirm we never issued one.
    const orphanDelete = db.calls.find(
      c => c.op === "run" &&
           /^DELETE FROM user_plans/i.test(c.sql.trim()) &&
           /uid\s*!=\s*\?/i.test(c.sql)
    );
    expect(orphanDelete).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
//  inbox.js getAuthContext — email_verified gate (smoke test via POST handler)
// ─────────────────────────────────────────────────────────────────────────────

describe("inbox.js getAuthContext — email_verified gate", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it("UNVERIFIED email: does NOT consult user_plans by email", async () => {
    // We mock verifyFirebaseToken to return an unverified-email user,
    // then try to call POST /api/inbox. The POST path bails out for
    // many reasons (missing Turnstile, missing prefix, etc.) — what
    // we care about is the SQL that getAuthContext emits while
    // resolving the plan, BEFORE any of that downstream logic runs.

    const calls = [];
    const db = {
      prepare(sql) {
        const stmt = {
          _bindings: [],
          bind(...args) { stmt._bindings = args; return stmt; },
          async first() { calls.push({ sql, op: "first", bindings: stmt._bindings }); return null; },
          async all()   { calls.push({ sql, op: "all",   bindings: stmt._bindings }); return { results: [] }; },
          async run()   { calls.push({ sql, op: "run",   bindings: stmt._bindings }); return { meta: { changes: 0 } }; },
        };
        return stmt;
      },
    };

    vi.doMock("../functions/_auth-helper.js", () => ({
      getAuthUser: async () => ({ uid: UNVERIFIED_UID, email: SHARED_EMAIL, email_verified: false }),
      verifyFirebaseToken: async () => ({
        uid:            UNVERIFIED_UID,
        email:          SHARED_EMAIL,
        email_verified: false,
      }),
    }));

    const inbox = await import("../functions/api/inbox.js");
    const req = new Request("https://api.modih.in/api/inbox", {
      method:  "POST",
      headers: {
        "Authorization":    "Bearer pretend-jwt",
        "CF-Connecting-IP": "203.0.113.99",
        "Content-Type":     "application/json",
      },
      body: JSON.stringify({ prefix: "" }),
    });

    // Don't care about the response shape — just that getAuthContext
    // ran and DIDN'T issue an email-based lookup.
    await inbox.onRequestPost({
      request: req,
      env: {
        DB: db,
        RATE_LIMIT: { async get() { return null; }, async put() {} },
        TURNSTILE_SECRET: "",
        EMAIL_DOMAIN: "modih.in",
      },
    }).catch(() => {});

    const emailLookup = calls.find(
      c => c.op === "first" && /WHERE\s+LOWER\(email\)/i.test(c.sql)
    );
    expect(emailLookup, "no email lookup for unverified-email user").toBeUndefined();
  });

  it("VERIFIED email: DOES consult user_plans by email", async () => {
    const calls = [];
    const db = {
      prepare(sql) {
        const stmt = {
          _bindings: [],
          bind(...args) { stmt._bindings = args; return stmt; },
          async first() { calls.push({ sql, op: "first", bindings: stmt._bindings }); return null; },
          async all()   { calls.push({ sql, op: "all",   bindings: stmt._bindings }); return { results: [] }; },
          async run()   { calls.push({ sql, op: "run",   bindings: stmt._bindings }); return { meta: { changes: 0 } }; },
        };
        return stmt;
      },
    };

    vi.doMock("../functions/_auth-helper.js", () => ({
      getAuthUser: async () => ({ uid: VERIFIED_UID, email: SHARED_EMAIL, email_verified: true }),
      verifyFirebaseToken: async () => ({
        uid:            VERIFIED_UID,
        email:          SHARED_EMAIL,
        email_verified: true,
      }),
    }));

    const inbox = await import("../functions/api/inbox.js");
    const req = new Request("https://api.modih.in/api/inbox", {
      method:  "POST",
      headers: {
        "Authorization":    "Bearer pretend-jwt",
        "CF-Connecting-IP": "203.0.113.100",
        "Content-Type":     "application/json",
      },
      body: JSON.stringify({ prefix: "" }),
    });

    await inbox.onRequestPost({
      request: req,
      env: {
        DB: db,
        RATE_LIMIT: { async get() { return null; }, async put() {} },
        TURNSTILE_SECRET: "",
        EMAIL_DOMAIN: "modih.in",
      },
    }).catch(() => {});

    const emailLookup = calls.find(
      c => c.op === "first" && /WHERE\s+LOWER\(email\)/i.test(c.sql)
    );
    expect(emailLookup, "verified email triggers email lookup").toBeTruthy();
  });
});
