/**
 * Tests for GET /api/admin/address — the admin per-address explorer.
 * Verifies admin auth is enforced and that list + detail modes assemble
 * creator, lifecycle status, and message metadata from the ledger, live
 * inboxes, messages, and admin_events.
 */
import { describe, it, expect } from "vitest";
import {
  onRequestGet as addressGet,
  onRequestPost as addressPost,
  onRequestDelete as addressDelete,
} from "../functions/api/admin/address.js";

const ADMIN_SECRET = "correct-horse-battery-staple-12345";

// KV mock that never blocks (rate-limit + session lookups).
function makeKv(initial = {}) {
  const store = new Map(Object.entries(initial));
  return {
    async get(k) { return store.get(k) ?? null; },
    async put(k, v) { store.set(k, v); },
    async delete(k) { store.delete(k); },
  };
}

// Route DB queries by a matcher against the SQL text. Records executed
// statements so tests can assert which mutations ran.
function makeRoutedDb(routes) {
  const executed = [];
  const db = {
    executed,
    prepare(sql) {
      let params = [];
      const run = (kind) => {
        for (const [needle, val] of routes) {
          if (sql.includes(needle)) {
            const out = typeof val === "function" ? val(params) : val;
            if (kind === "all") return { results: Array.isArray(out) ? out : out ? [out] : [] };
            if (kind === "first") return Array.isArray(out) ? (out[0] ?? null) : (out ?? null);
            return { meta: { changes: 1 } };
          }
        }
        return kind === "all" ? { results: [] } : kind === "first" ? null : { meta: { changes: 0 } };
      };
      return {
        _sql: sql,
        bind(...a) { params = a; return this; },
        async first() { return run("first"); },
        async all() { return run("all"); },
        async run() { executed.push({ sql, params }); return run("run"); },
      };
    },
    async batch(stmts) {
      const out = [];
      for (const s of stmts) out.push(await s.run());
      return out;
    },
  };
  return db;
}

function ctx({ url, secret = ADMIN_SECRET, db }) {
  const headers = { "CF-Connecting-IP": "203.0.113.9" };
  if (secret) headers["X-Admin-Secret"] = secret;
  return {
    request: new Request(url, { headers }),
    env: { ADMIN_SECRET, RATE_LIMIT: makeKv(), DB: db },
  };
}

describe("GET /api/admin/address", () => {
  it("rejects a request without the admin secret", async () => {
    const res = await addressGet(ctx({ url: "https://x/api/admin/address", secret: null, db: makeRoutedDb([]) }));
    expect(res.status).toBe(401);
  });

  it("detail mode returns creator, active status, and messages", async () => {
    const db = makeRoutedDb([
      ["FROM used_addresses WHERE email", { email: "abc@modih.in", first_used_at: 1000, creator_uid: "u1", creator_ip: "1.1.1.1" }],
      ["FROM inboxes WHERE email", { id: "inbox1", email: "abc@modih.in", creator_uid: "u1", creator_email: "owner@x.com", creator_ip: "1.1.1.1", creator_plan: "pro", created_at: 1000, expires_at: 9999999999, reserved: 0 }],
      ["FROM messages WHERE inbox_id", [{ id: "m1", from_address: "svc@google.com", from_name: "Google", subject: "Your code", received_at: 1200 }]],
      ["event_type = 'message_received' AND inbox_email", [{ subject: "Your code", is_otp: 1, created_at: 1200 }]],
    ]);
    const res = await addressGet(ctx({ url: "https://x/api/admin/address?email=abc@modih.in", db }));
    expect(res.status).toBe(200);
    const b = await res.json();
    expect(b.found).toBe(true);
    expect(b.status).toBe("active");
    expect(b.creator.email).toBe("owner@x.com");
    expect(b.creator.plan).toBe("pro");
    expect(b.messages_current).toHaveLength(1);
    expect(b.messages_current[0].from).toBe("svc@google.com");
    expect(b.messages_history[0].is_otp).toBe(true);
  });

  it("detail mode marks a ledger-only (expired/cleaned) address as expired", async () => {
    const db = makeRoutedDb([
      ["FROM used_addresses WHERE email", { email: "old@modih.in", first_used_at: 10, creator_uid: "u9", creator_ip: "2.2.2.2" }],
      ["FROM inboxes WHERE email", null], // no live inbox — cleaned up
      ["event_type = 'message_received' AND inbox_email", [{ subject: "Old receipt", is_otp: 0, created_at: 50 }]],
    ]);
    const res = await addressGet(ctx({ url: "https://x/api/admin/address?email=old@modih.in", db }));
    const b = await res.json();
    expect(b.found).toBe(true);
    expect(b.status).toBe("expired");
    expect(b.messages_current).toHaveLength(0);
    expect(b.messages_history).toHaveLength(1);
  });

  it("list mode returns addresses with live status and message counts", async () => {
    const db = makeRoutedDb([
      ["FROM used_addresses ORDER BY", [
        { email: "a@modih.in", first_used_at: 300, creator_uid: "u1", creator_ip: "1.1.1.1" },
        { email: "b@modih.in", first_used_at: 200, creator_uid: null, creator_ip: "2.2.2.2" },
      ]],
      ["FROM inboxes WHERE email", { id: "i1", creator_email: "o@x.com", expires_at: 9999999999, reserved: 0, blocked: 0 }],
      ["COUNT(*) AS n FROM admin_events", { n: 3 }],
      ["COUNT(*) AS n FROM used_addresses", { n: 2 }],
    ]);
    const res = await addressGet(ctx({ url: "https://x/api/admin/address", db }));
    const b = await res.json();
    expect(b.total_addresses_ever_issued).toBe(2);
    expect(b.addresses).toHaveLength(2);
    expect(b.addresses[0].email).toBe("a@modih.in");
    expect(b.addresses[0].status).toBe("active");
    expect(b.addresses[0].messages_received).toBe(3);
  });

  it("rejects a malformed email param gracefully (falls back to list mode)", async () => {
    const db = makeRoutedDb([["FROM used_addresses ORDER BY", []], ["COUNT(*) AS n FROM used_addresses", { n: 0 }]]);
    const res = await addressGet(ctx({ url: "https://x/api/admin/address?email=%3Cscript%3E", db }));
    expect(res.status).toBe(200);
    const b = await res.json();
    // Not treated as a valid address lookup; list mode responded.
    expect(b).toHaveProperty("addresses");
  });

  it("returns a single message body via ?msg=", async () => {
    const db = makeRoutedDb([
      ["FROM messages WHERE id", { id: "m1", inbox_id: "i1", from_address: "a@b.com", subject: "Hi", body_html: "<p>hello</p>", body_text: "hello", received_at: 10 }],
    ]);
    const res = await addressGet(ctx({ url: "https://x/api/admin/address?msg=m1", db }));
    const b = await res.json();
    expect(b.ok).toBe(true);
    expect(b.message.body_html).toBe("<p>hello</p>");
  });
});

describe("admin address controls", () => {
  const postCtx = (bodyObj, db) => ({
    request: new Request("https://x/api/admin/address", {
      method: "POST",
      headers: { "X-Admin-Secret": ADMIN_SECRET, "CF-Connecting-IP": "1.1.1.1", "Content-Type": "application/json" },
      body: JSON.stringify(bodyObj),
    }),
    env: { ADMIN_SECRET, RATE_LIMIT: makeKv(), DB: db },
  });

  it("requires admin auth for POST", async () => {
    const res = await addressPost({
      request: new Request("https://x/api/admin/address", { method: "POST", body: "{}" }),
      env: { ADMIN_SECRET, RATE_LIMIT: makeKv(), DB: makeRoutedDb([]) },
    });
    expect(res.status).toBe(401);
  });

  it("blocks a live address (sets blocked = 1)", async () => {
    const db = makeRoutedDb([
      ["FROM used_addresses WHERE email", { email: "a@modih.in", first_used_at: 1 }],
      ["FROM inboxes WHERE email", { id: "i1", creator_uid: "u1" }],
      ["UPDATE inboxes SET blocked = 1", { changes: 1 }],
    ]);
    const res = await addressPost(postCtx({ email: "a@modih.in", action: "block" }, db));
    const b = await res.json();
    expect(b.ok).toBe(true);
    expect(b.status).toBe("blocked");
    expect(db.executed.some(e => /UPDATE inboxes SET blocked = 1/.test(e.sql))).toBe(true);
  });

  it("reactivate recreates a cleaned-up (ledger-only) address", async () => {
    const db = makeRoutedDb([
      ["FROM used_addresses WHERE email", { email: "old@modih.in", first_used_at: 1, creator_uid: "u9", creator_ip: "2.2.2.2" }],
      ["FROM inboxes WHERE email", null], // not live
      ["INSERT INTO inboxes", { changes: 1 }],
    ]);
    const res = await addressPost(postCtx({ email: "old@modih.in", action: "reactivate", ttl_days: 7 }, db));
    const b = await res.json();
    expect(b.ok).toBe(true);
    expect(b.recreated).toBe(true);
    expect(db.executed.some(e => /INSERT INTO inboxes/.test(e.sql))).toBe(true);
  });

  it("block on a non-live address is refused", async () => {
    const db = makeRoutedDb([
      ["FROM used_addresses WHERE email", { email: "gone@modih.in", first_used_at: 1 }],
      ["FROM inboxes WHERE email", null],
    ]);
    const res = await addressPost(postCtx({ email: "gone@modih.in", action: "block" }, db));
    expect(res.status).toBe(409);
  });

  it("DELETE drops the inbox + messages but keeps the ledger (still burned)", async () => {
    const db = makeRoutedDb([
      ["FROM inboxes WHERE email", { id: "i1" }],
      ["DELETE FROM messages WHERE inbox_id", { changes: 2 }],
      ["DELETE FROM inboxes WHERE id", { changes: 1 }],
    ]);
    const res = await addressDelete({
      request: new Request("https://x/api/admin/address?email=a@modih.in", {
        method: "DELETE",
        headers: { "X-Admin-Secret": ADMIN_SECRET, "CF-Connecting-IP": "1.1.1.1" },
      }),
      env: { ADMIN_SECRET, RATE_LIMIT: makeKv(), DB: db },
    });
    const b = await res.json();
    expect(b.ok).toBe(true);
    expect(b.deleted).toBe(true);
    expect(b.still_burned).toBe(true);
    // The permanent ledger must NOT be deleted.
    expect(db.executed.some(e => /DELETE FROM used_addresses/.test(e.sql))).toBe(false);
  });
});
