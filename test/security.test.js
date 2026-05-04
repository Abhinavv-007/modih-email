/**
 * Security regression tests
 *
 *   1. HTML sanitizer — must strip script/style/iframe/svg/object content,
 *      every variant of `on*` event handlers (whitespace OR slash delimited,
 *      quoted/unquoted, mixed casing, html-entity-encoded), `javascript:`
 *      and friends in URLs, and remote `<img>` tags. Safe formatting
 *      (paragraphs, links, bold, line breaks, tables) MUST survive.
 *
 *   2. Admin auth — constant-time comparison, generic error responses,
 *      and per-IP rate limiting after repeated failures.
 *
 * Run:  npm test  (all suites)  or  npx vitest run test/security.test.js
 */

import { describe, it, expect } from "vitest";

import { sanitizeRenderedHtml } from "../functions/_sanitize-html.js";

import {
  onRequestGet    as adminGet,
  onRequestPost   as adminPost,
  onRequestPatch  as adminPatch,
  onRequestDelete as adminDelete,
} from "../functions/api/admin/users.js";

// ────────────────────────────────────────────────────────────────────────────
//  Test helpers — minimal mocks for KV + D1 + Pages Function context
// ────────────────────────────────────────────────────────────────────────────

const REAL_ADMIN_SECRET = "correct-horse-battery-staple-12345";

function makeKv(initial = {}) {
  const store = new Map(Object.entries(initial));
  return {
    async get(key) { return store.get(key) ?? null; },
    async put(key, value, _opts) { store.set(key, value); },
    _store: store,
  };
}

/**
 * D1 mock — only needs to swallow the calls the admin auth path makes
 * (audit log inserts, plan expiry sweeps). We don't need real query
 * results because the auth check fails before any data is read.
 */
function makeDb() {
  return {
    prepare() {
      const stmt = {
        bind() { return stmt; },
        async first()  { return null; },
        async all()    { return { results: [] }; },
        async run()    { return { meta: { changes: 0 } }; },
      };
      return stmt;
    },
  };
}

function makeAdminCtx({
  method = "GET",
  url = "https://api.modih.in/api/admin/users?range=30d",
  ip = "203.0.113.45",
  secret = REAL_ADMIN_SECRET,
  expectedSecret = REAL_ADMIN_SECRET,
  rateLimit = makeKv(),
  body = null,
} = {}) {
  const headers = { "CF-Connecting-IP": ip, "Content-Type": "application/json" };
  if (secret !== undefined && secret !== null) {
    headers["X-Admin-Secret"] = secret;
  }
  const request = new Request(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null,
  });
  return {
    request,
    env: {
      ADMIN_SECRET: expectedSecret,
      RATE_LIMIT:   rateLimit,
      DB:           makeDb(),
    },
  };
}

// ────────────────────────────────────────────────────────────────────────────
//  1. HTML SANITIZER — slash-delimiter and other XSS bypasses
// ────────────────────────────────────────────────────────────────────────────

describe("sanitizeRenderedHtml — non-HTML inputs", () => {
  it("returns empty string for null / undefined / non-strings", () => {
    expect(sanitizeRenderedHtml(null)).toBe("");
    expect(sanitizeRenderedHtml(undefined)).toBe("");
    expect(sanitizeRenderedHtml(123)).toBe("");
    expect(sanitizeRenderedHtml({})).toBe("");
  });

  it("returns plain text unchanged", () => {
    expect(sanitizeRenderedHtml("hello world")).toBe("hello world");
  });
});

describe("sanitizeRenderedHtml — safe HTML survives", () => {
  it("preserves paragraphs, bold, italics, line breaks", () => {
    const safe = "<p>Hello <strong>world</strong> <em>!</em></p><br>line two";
    expect(sanitizeRenderedHtml(safe)).toBe(safe);
  });

  it("preserves links with safe schemes", () => {
    const safe = '<a href="https://example.com">link</a>';
    expect(sanitizeRenderedHtml(safe)).toBe(safe);
  });

  it("preserves tables, lists, headings, divs", () => {
    const safe =
      "<table><tr><td>cell</td></tr></table>" +
      "<ul><li>one</li><li>two</li></ul>" +
      "<h1>Title</h1><div>content</div>";
    expect(sanitizeRenderedHtml(safe)).toBe(safe);
  });
});

describe("sanitizeRenderedHtml — script/style/iframe/svg pairs", () => {
  it("strips a <script> tag and its body", () => {
    const out = sanitizeRenderedHtml('<script>alert(1)</script>safe');
    expect(out).not.toMatch(/script/i);
    expect(out).not.toMatch(/alert/i);
    expect(out).toContain("safe");
  });

  it("strips <style>", () => {
    expect(sanitizeRenderedHtml('<style>body{}</style>x')).not.toMatch(/style/i);
  });

  it("strips <iframe>", () => {
    expect(sanitizeRenderedHtml('<iframe src="x"></iframe>x')).not.toMatch(/iframe/i);
  });

  it("strips <svg/onload=...> via the unmatched-opener rule", () => {
    const out = sanitizeRenderedHtml('<svg/onload=alert(1)>safe');
    expect(out).not.toMatch(/svg/i);
    expect(out).not.toMatch(/alert/i);
    expect(out).toContain("safe");
  });

  it("strips a malformed/unclosed <script>", () => {
    const out = sanitizeRenderedHtml('<script src="x">no closer here');
    expect(out).not.toMatch(/<script/i);
  });
});

describe("sanitizeRenderedHtml — event handler attribute bypass payloads", () => {
  // These are the canonical XSS bypasses from the task description.
  // Each must yield output where:
  //   - the active tag/attribute is gone or de-fanged, AND
  //   - no remaining attribute named `on…` is present.
  const cases = [
    { name: 'whitespace, double quoted',  payload: '<a onclick="alert(1)">x</a>' },
    { name: 'slash delim, double quoted', payload: '<a/onclick="alert(1)">x</a>' },
    { name: 'whitespace, unquoted',       payload: '<img src=x onerror=alert(1)>' },
    { name: 'slash delim, unquoted',      payload: '<img/src=x/onerror=alert(1)>' },
    { name: 'svg/onload',                 payload: '<svg/onload=alert(1)>' },
    { name: 'mixed casing',               payload: '<img/src=x/oNeRrOr=alert(1)>' },
    { name: 'space-then-slash mix',       payload: '<a /onclick=alert(1)>x</a>' },
    { name: 'tab delimited',              payload: '<a\tonclick="alert(1)">x</a>' },
    { name: 'newline delimited',          payload: '<a\nonclick="alert(1)">x</a>' },
    { name: 'single quoted',              payload: "<a onclick='alert(1)'>x</a>" },
    { name: 'slash + single quoted',      payload: "<a/onclick='alert(1)'>x</a>" },
  ];

  for (const { name, payload } of cases) {
    it(`removes XSS from: ${name} — ${payload}`, () => {
      const out = sanitizeRenderedHtml(payload);
      expect(out, "no on* handler remains").not.toMatch(/\bon\w+\s*=/i);
      expect(out, "no slash-delimited on* handler remains").not.toMatch(/\/on\w+\s*=/i);
      expect(out, "alert(1) is not invocable").not.toMatch(/alert\s*\(/);
    });
  }
});

describe("sanitizeRenderedHtml — dangerous URL schemes", () => {
  it("neutralises javascript: in href", () => {
    const out = sanitizeRenderedHtml('<a href="javascript:alert(1)">x</a>');
    expect(out).not.toMatch(/javascript:/i);
    expect(out).toContain("blocked:");
  });

  it("neutralises HTML-entity-encoded javascript:", () => {
    const out = sanitizeRenderedHtml('<a href="java&#115;cript:alert(1)">x</a>');
    expect(out).toMatch(/blocked:/);
    expect(out).not.toMatch(/cript:/i); // the 'c' may remain after entity decoding
  });

  it("neutralises vbscript:, data:, blob:, file:", () => {
    for (const scheme of ["vbscript", "data", "blob", "file"]) {
      const out = sanitizeRenderedHtml(`<a href="${scheme}:foo">x</a>`);
      expect(out, scheme).not.toMatch(new RegExp(`${scheme}:`, "i"));
    }
  });
});

describe("sanitizeRenderedHtml — image blocking", () => {
  it("removes ANY <img> (tracking pixel + onerror combo)", () => {
    const cases = [
      "<img src='x'>",
      '<img src="https://attacker.example/pixel.gif">',
      "<img/src=x/onerror=alert(1)>",
      "<IMG SRC=x>",
    ];
    for (const c of cases) {
      const out = sanitizeRenderedHtml(c);
      expect(out, c).not.toMatch(/<img/i);
      expect(out, c).toContain("[image removed]");
    }
  });
});

describe("sanitizeRenderedHtml — null byte and weird inputs", () => {
  it("strips embedded NULs that some parsers ignore", () => {
    const payload = '<scr\u0000ipt>alert(1)</scr\u0000ipt>';
    const out = sanitizeRenderedHtml(payload);
    expect(out).not.toMatch(/script/i);
  });

  it("does not blow up on nested malformed content", () => {
    // Should return *something* (possibly empty), but not throw.
    const big = `<svg><script>alert(1)</script><img/src=x/onerror=alert(1)>`;
    const out = sanitizeRenderedHtml(big);
    expect(typeof out).toBe("string");
    expect(out).not.toMatch(/script/i);
    expect(out).not.toMatch(/alert\s*\(/);
  });
});

// ────────────────────────────────────────────────────────────────────────────
//  2. ADMIN AUTH — timing-safe comparison + brute-force protection
// ────────────────────────────────────────────────────────────────────────────

describe("admin auth — secret comparison", () => {
  it("returns 401 when no X-Admin-Secret header is present", async () => {
    const ctx = makeAdminCtx({ secret: null });
    const res = await adminGet(ctx);
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error).toBe("Unauthorized");
  });

  it("returns 401 when X-Admin-Secret is empty", async () => {
    const ctx = makeAdminCtx({ secret: "" });
    const res = await adminGet(ctx);
    expect(res.status).toBe(401);
  });

  it("returns 401 with a generic body when the secret is wrong", async () => {
    const ctx = makeAdminCtx({ secret: "definitely-wrong" });
    const res = await adminGet(ctx);
    expect(res.status).toBe(401);
    const body = await res.json();
    // Generic error — never reveals "close", "partial", "wrong length".
    expect(body.error).toBe("Unauthorized");
    expect(JSON.stringify(body)).not.toMatch(/correct|partial|close|length|prefix/i);
  });

  it("rejects a partial prefix match (timing-safe)", async () => {
    const ctx = makeAdminCtx({
      secret: REAL_ADMIN_SECRET.slice(0, 3),  // "cor"
      expectedSecret: REAL_ADMIN_SECRET,
    });
    const res = await adminGet(ctx);
    expect(res.status).toBe(401);
  });

  it("accepts the correct secret and proceeds (200 or 5xx, not 401/429)", async () => {
    const ctx = makeAdminCtx();
    const res = await adminGet(ctx);
    // The downstream call may 500 because our DB mock returns no rows for
    // the analytics queries — what matters is that auth passed (not 401/429).
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(429);
  });

  it("refuses access when ADMIN_SECRET is unset on the server", async () => {
    const ctx = makeAdminCtx({ expectedSecret: "", secret: "anything" });
    const res = await adminGet(ctx);
    expect(res.status).toBe(401);
  });
});

describe("admin auth — rate limiting", () => {
  it("locks out after the threshold of failed non-empty attempts", async () => {
    const kv = makeKv();
    const ip = "198.51.100.7";

    // 8 wrong attempts — each MUST 401 (no premature lockout).
    for (let i = 0; i < 8; i++) {
      const ctx = makeAdminCtx({ secret: `bad-${i}`, ip, rateLimit: kv });
      const res = await adminGet(ctx);
      expect(res.status, `attempt ${i + 1}`).toBe(401);
    }

    // The 9th attempt must be rate-limited (429), even with the correct
    // secret — the gate is closed.
    const blockedWithCorrect = await adminGet(
      makeAdminCtx({ secret: REAL_ADMIN_SECRET, ip, rateLimit: kv })
    );
    expect(blockedWithCorrect.status).toBe(429);
    const body = await blockedWithCorrect.json();
    expect(body.error).toMatch(/too many/i);
    expect(blockedWithCorrect.headers.get("Retry-After")).toBeTruthy();
  });

  it("does NOT count empty-secret probes against the rate limit", async () => {
    const kv = makeKv();
    const ip = "198.51.100.8";

    // 100 empty attempts shouldn't lock out — these are honest "logged out"
    // probes from the gate page reload, not brute-force guesses.
    for (let i = 0; i < 100; i++) {
      const res = await adminGet(makeAdminCtx({ secret: "", ip, rateLimit: kv }));
      expect(res.status).toBe(401);
    }

    // The legitimate operator can still log in.
    const res = await adminGet(makeAdminCtx({ secret: REAL_ADMIN_SECRET, ip, rateLimit: kv }));
    expect(res.status).not.toBe(429);
  });

  it("isolates rate limits per IP", async () => {
    const kv = makeKv();
    const ipBad  = "198.51.100.9";
    const ipGood = "203.0.113.50";

    // Burn through the bad IP's allowance.
    for (let i = 0; i < 10; i++) {
      await adminGet(makeAdminCtx({ secret: "wrong", ip: ipBad, rateLimit: kv }));
    }

    // The good IP must be unaffected.
    const res = await adminGet(makeAdminCtx({ secret: REAL_ADMIN_SECRET, ip: ipGood, rateLimit: kv }));
    expect(res.status).not.toBe(429);
  });

  it("applies rate limiting to POST/PATCH/DELETE too — not just GET", async () => {
    const kv = makeKv();
    const ip = "198.51.100.10";

    for (let i = 0; i < 8; i++) {
      await adminPost(makeAdminCtx({
        method: "POST",
        url: "https://api.modih.in/api/admin/users",
        secret: `bad-${i}`,
        ip,
        rateLimit: kv,
        body: { uid: "x", plan: "pro" },
      }));
    }

    const res = await adminPatch(makeAdminCtx({
      method: "PATCH",
      url: "https://api.modih.in/api/admin/users",
      secret: REAL_ADMIN_SECRET,
      ip,
      rateLimit: kv,
      body: { uid: "x", plan: "pro" },
    }));
    expect(res.status).toBe(429);

    const res2 = await adminDelete(makeAdminCtx({
      method: "DELETE",
      url: "https://api.modih.in/api/admin/users?uid=x",
      secret: REAL_ADMIN_SECRET,
      ip,
      rateLimit: kv,
    }));
    expect(res2.status).toBe(429);
  });
});
