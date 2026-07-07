/**
 * Tests for GET /api/admin/address — the admin per-address explorer.
 * Verifies admin auth is enforced and that list + detail modes assemble
 * creator, lifecycle status, and message metadata from the ledger, live
 * inboxes, messages, and admin_events.
 */
import { describe, it, expect } from "vitest";
import { onRequestGet as addressGet } from "../functions/api/admin/address.js";

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

// Route DB queries by a matcher against the SQL text.
function makeRoutedDb(routes) {
  return {
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
        bind(...a) { params = a; return this; },
        async first() { return run("first"); },
        async all() { return run("all"); },
        async run() { return run("run"); },
      };
    },
  };
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
      ["creator_email, expires_at", { creator_email: "o@x.com", expires_at: 9999999999, reserved: 0 }],
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
});
