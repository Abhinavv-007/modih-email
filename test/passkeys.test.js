/**
 * Tests for the WebAuthn admin login path.
 *
 *   • _webauthn.js primitives  — base64url, CBOR decoder, authData parser,
 *     DER-to-raw ECDSA signature converter, COSE → JWK conversion.
 *
 *   • _admin-auth.js shared gate — session-cookie path bypasses the failed-
 *     secret rate limit; expired/forged cookies cleanly fall through.
 *
 *   • passkeys endpoint         — request validation, challenge lifecycle,
 *     and a complete register-then-login round trip using a real P-256
 *     key pair as a stand-in authenticator.
 *
 * Run:  npm test  (all suites)  or  npx vitest run test/passkeys.test.js
 */

import { describe, it, expect } from "vitest";

import {
  b64uToBytes,
  bytesToB64u,
  bytesEqual,
  cborDecode,
  parseAuthData,
  derToRawEcdsa,
  coseToJwkJson,
  importStoredJwkEs256,
  verifyEs256,
  newChallenge,
} from "../functions/_webauthn.js";

import { onRequestPost as passkeysPost } from "../functions/api/admin/passkeys.js";
import {
  onRequestGet as adminGet,
} from "../functions/api/admin/users.js";

const REAL_ADMIN_SECRET = "correct-horse-battery-staple-12345";

// ────────────────────────────────────────────────────────────────────────────
//  Mock KV / D1 / request helpers
// ────────────────────────────────────────────────────────────────────────────

function makeKv(initial = {}) {
  const store = new Map(Object.entries(initial));
  return {
    async get(key) { return store.get(key) ?? null; },
    async put(key, value /*, _opts */) { store.set(key, value); },
    async delete(key) { store.delete(key); },
    _store: store,
  };
}

/**
 * Tiny D1 mock that backs `admin_passkeys` with an in-memory array. Only the
 * SQL fragments used by the passkeys endpoint are recognised; everything else
 * returns empty results so unrelated audit-log inserts are no-ops.
 */
function makePasskeyDb({ passkeys = [] } = {}) {
  let nextId = 1;
  const rows = passkeys.map(p => ({ id: nextId++, ...p }));
  const db = {
    _rows: rows,
    prepare(sql) {
      let bound = [];
      const stmt = {
        bind(...args) { bound = args; return stmt; },
        async first() {
          if (/FROM admin_passkeys[\s\S]*WHERE credential_id/.test(sql)) {
            return rows.find(r => r.credential_id === bound[0]) || null;
          }
          return null;
        },
        async all() {
          if (/FROM admin_passkeys/.test(sql)) {
            return { results: rows };
          }
          return { results: [] };
        },
        async run() {
          if (/^INSERT INTO admin_passkeys/.test(sql)) {
            const [credential_id, public_key_jwk, sign_count, transports, label, aaguid, created_at] = bound;
            if (rows.some(r => r.credential_id === credential_id)) {
              throw new Error("UNIQUE constraint failed");
            }
            rows.push({
              id: nextId++,
              credential_id,
              public_key_jwk,
              algorithm: -7,
              sign_count,
              transports,
              label,
              aaguid,
              created_at,
              last_used_at: null,
            });
            return { meta: { changes: 1 } };
          }
          if (/^UPDATE admin_passkeys SET sign_count/.test(sql)) {
            const [sign_count, last_used_at, id] = bound;
            const row = rows.find(r => r.id === id);
            if (row) { row.sign_count = sign_count; row.last_used_at = last_used_at; }
            return { meta: { changes: 1 } };
          }
          if (/^DELETE FROM admin_passkeys/.test(sql)) {
            const [id] = bound;
            const ix = rows.findIndex(r => r.id === id);
            if (ix >= 0) rows.splice(ix, 1);
            return { meta: { changes: 1 } };
          }
          return { meta: { changes: 0 } };
        },
      };
      return stmt;
    },
  };
  return db;
}

function makeRequest({
  method = "POST",
  url = "https://admin.modih.in/api/admin/passkeys",
  ip = "203.0.113.45",
  secret = null,
  cookie = null,
  body = null,
} = {}) {
  const headers = { "CF-Connecting-IP": ip, "Content-Type": "application/json" };
  if (secret) headers["X-Admin-Secret"] = secret;
  if (cookie) headers["Cookie"] = cookie;
  return new Request(url, {
    method,
    headers,
    body: body == null ? undefined : JSON.stringify(body),
  });
}

function makePasskeyCtx(opts = {}) {
  const {
    db = makePasskeyDb(),
    kv = makeKv(),
    expectedSecret = REAL_ADMIN_SECRET,
    rpId = "admin.modih.in",
    origin = "https://admin.modih.in",
    request = makeRequest(opts.request),
  } = opts;
  return {
    request,
    env: {
      ADMIN_SECRET: expectedSecret,
      RATE_LIMIT: kv,
      DB: db,
      WEBAUTHN_RP_ID: rpId,
      WEBAUTHN_ORIGIN: origin,
    },
    _kv: kv,
    _db: db,
  };
}

// ────────────────────────────────────────────────────────────────────────────
//  1. base64url + bytesEqual
// ────────────────────────────────────────────────────────────────────────────

describe("base64url helpers", () => {
  it("round-trips arbitrary bytes", () => {
    const raw = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    expect(bytesToB64u(raw)).toBe("AAEC-vv8_f7_");
    expect(Array.from(b64uToBytes(bytesToB64u(raw)))).toEqual(Array.from(raw));
  });

  it("decodes unpadded input", () => {
    expect(Array.from(b64uToBytes("AQID"))).toEqual([1, 2, 3]);
    expect(Array.from(b64uToBytes("AQ"))).toEqual([1]);
  });

  it("rejects non-string input", () => {
    expect(() => b64uToBytes(null)).toThrow();
  });
});

describe("bytesEqual", () => {
  it("returns true for identical arrays", () => {
    expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
  });
  it("returns false for length mismatch", () => {
    expect(bytesEqual(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
  });
  it("returns false for content mismatch", () => {
    expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
  });
});

// ────────────────────────────────────────────────────────────────────────────
//  2. CBOR decoder (hand-crafted byte sequences)
// ────────────────────────────────────────────────────────────────────────────

describe("cborDecode", () => {
  it("decodes small unsigned integers", () => {
    expect(cborDecode(new Uint8Array([0x00]))).toBe(0);
    expect(cborDecode(new Uint8Array([0x17]))).toBe(23);
    expect(cborDecode(new Uint8Array([0x18, 0xff]))).toBe(255);
    expect(cborDecode(new Uint8Array([0x19, 0x12, 0x34]))).toBe(0x1234);
  });

  it("decodes negative integers (-1 - n)", () => {
    expect(cborDecode(new Uint8Array([0x20]))).toBe(-1);   // 0x20 = major 1, info 0 → -1
    expect(cborDecode(new Uint8Array([0x26]))).toBe(-7);   // ES256 alg
  });

  it("decodes byte strings", () => {
    const got = cborDecode(new Uint8Array([0x43, 0x01, 0x02, 0x03])); // bstr len 3
    expect(got).toBeInstanceOf(Uint8Array);
    expect(Array.from(got)).toEqual([1, 2, 3]);
  });

  it("decodes text strings", () => {
    expect(cborDecode(new Uint8Array([0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f]))).toBe("hello");
  });

  it("decodes maps with mixed keys (int + text)", () => {
    // { 1: 2, "fmt": "none" }
    const bytes = new Uint8Array([
      0xa2,
      0x01, 0x02,
      0x63, 0x66, 0x6d, 0x74,
      0x64, 0x6e, 0x6f, 0x6e, 0x65,
    ]);
    const map = cborDecode(bytes);
    expect(map).toBeInstanceOf(Map);
    expect(map.get(1)).toBe(2);
    expect(map.get("fmt")).toBe("none");
  });

  it("decodes simple values (true / false / null)", () => {
    expect(cborDecode(new Uint8Array([0xf4]))).toBe(false);
    expect(cborDecode(new Uint8Array([0xf5]))).toBe(true);
    expect(cborDecode(new Uint8Array([0xf6]))).toBe(null);
  });

  it("rejects truncated input", () => {
    expect(() => cborDecode(new Uint8Array([0x18]))).toThrow(/truncated/);
  });
});

// ────────────────────────────────────────────────────────────────────────────
//  3. parseAuthData
// ────────────────────────────────────────────────────────────────────────────

describe("parseAuthData", () => {
  it("parses the baseline 37-byte form (no attested data)", () => {
    const bytes = new Uint8Array(37);
    bytes.set(new Uint8Array([1, 2, 3]), 0);             // partial rpIdHash
    bytes[32] = 0x01;                                     // user-present
    bytes[33] = 0; bytes[34] = 0; bytes[35] = 0; bytes[36] = 5; // counter = 5
    const parsed = parseAuthData(bytes);
    expect(parsed.userPresent).toBe(true);
    expect(parsed.userVerified).toBe(false);
    expect(parsed.signCount).toBe(5);
    expect(parsed.credId).toBeNull();
  });

  it("extracts AAGUID, credId and coseKey when AT flag is set", () => {
    const credId = new Uint8Array([10, 20, 30, 40]);
    const coseKey = new Uint8Array([0xa1, 0x01, 0x02]); // tiny placeholder
    const buf = new Uint8Array(55 + credId.length + coseKey.length);
    buf[32] = 0x41;                          // user-present + attested-data
    buf[33] = 0; buf[34] = 0; buf[35] = 0; buf[36] = 1;
    // 37..52 = aaguid (zeros)
    buf[53] = 0; buf[54] = credId.length;
    buf.set(credId, 55);
    buf.set(coseKey, 55 + credId.length);
    const parsed = parseAuthData(buf);
    expect(parsed.userPresent).toBe(true);
    expect(parsed.aaguid).toBeInstanceOf(Uint8Array);
    expect(Array.from(parsed.credId)).toEqual(Array.from(credId));
    expect(Array.from(parsed.coseKey)).toEqual(Array.from(coseKey));
  });

  it("throws on truncated input", () => {
    expect(() => parseAuthData(new Uint8Array(10))).toThrow(/too short/);
  });
});

// ────────────────────────────────────────────────────────────────────────────
//  4. DER → IEEE-P1363 ECDSA conversion
// ────────────────────────────────────────────────────────────────────────────

describe("derToRawEcdsa", () => {
  it("converts a normal DER (r,s) sequence to 64 bytes", () => {
    // SEQUENCE(70) { INT(32) 0x11... , INT(32) 0x22... }
    const r = new Uint8Array(32).fill(0x11);
    const s = new Uint8Array(32).fill(0x22);
    const der = new Uint8Array([
      0x30, 0x44,
      0x02, 0x20, ...r,
      0x02, 0x20, ...s,
    ]);
    const raw = derToRawEcdsa(der);
    expect(raw.length).toBe(64);
    expect(Array.from(raw.slice(0, 32))).toEqual(Array.from(r));
    expect(Array.from(raw.slice(32))).toEqual(Array.from(s));
  });

  it("strips the leading 0x00 sign byte before zero-padding", () => {
    // r is 33 bytes (0x00 || 32 bytes 0x80...) — common when MSB is set
    const rPadded = new Uint8Array([0x00, ...new Uint8Array(32).fill(0x80)]);
    const s = new Uint8Array(32).fill(0x22);
    const der = new Uint8Array([
      0x30, 0x45,
      0x02, 0x21, ...rPadded,
      0x02, 0x20, ...s,
    ]);
    const raw = derToRawEcdsa(der);
    expect(raw.length).toBe(64);
    expect(raw[0]).toBe(0x80);
    expect(Array.from(raw.slice(32))).toEqual(Array.from(s));
  });

  it("left-pads short integers up to 32 bytes", () => {
    // r is only 30 bytes
    const rShort = new Uint8Array(30).fill(0x77);
    const s = new Uint8Array(32).fill(0x33);
    const der = new Uint8Array([
      0x30, 0x42,
      0x02, 0x1e, ...rShort,
      0x02, 0x20, ...s,
    ]);
    const raw = derToRawEcdsa(der);
    expect(raw.length).toBe(64);
    expect(raw[0]).toBe(0);
    expect(raw[1]).toBe(0);
    expect(raw[2]).toBe(0x77);
  });

  it("throws on a non-SEQUENCE prefix", () => {
    expect(() => derToRawEcdsa(new Uint8Array([0x02, 0x01, 0xaa]))).toThrow(/SEQUENCE/);
  });
});

// ────────────────────────────────────────────────────────────────────────────
//  5. End-to-end register + login (acts as a real authenticator using
//     subtle.generateKey + subtle.sign — no native passkey hardware needed)
// ────────────────────────────────────────────────────────────────────────────

// ── tiny CBOR encoder, only what tests need ──────────────────────────────────
function cborMajorHeader(major, n) {
  if (n < 24) return new Uint8Array([(major << 5) | n]);
  if (n < 256) return new Uint8Array([(major << 5) | 24, n]);
  if (n < 65536) return new Uint8Array([(major << 5) | 25, (n >> 8) & 0xff, n & 0xff]);
  throw new Error("encoder: unsupported size");
}
function cborUint(n) { return cborMajorHeader(0, n); }
function cborNeg(n)  { return cborMajorHeader(1, -1 - n); } // n must be negative
function cborBstr(bytes) {
  return concat(cborMajorHeader(2, bytes.length), bytes);
}
function cborTstr(text) {
  const bytes = new TextEncoder().encode(text);
  return concat(cborMajorHeader(3, bytes.length), bytes);
}
function cborMap(entries) {
  const parts = [cborMajorHeader(5, entries.length)];
  for (const [k, v] of entries) {
    parts.push(typeof k === "string" ? cborTstr(k) : (k < 0 ? cborNeg(k) : cborUint(k)));
    parts.push(v);
  }
  return concat(...parts);
}
function concat(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

async function digest(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

async function generateAuthenticator() {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const x = b64uToBytes(jwk.x);
  const y = b64uToBytes(jwk.y);
  const credId = new Uint8Array(16);
  crypto.getRandomValues(credId);
  return { ...pair, credId, coseKey: cborMap([
    [1, cborUint(2)],            // kty = EC2
    [3, cborNeg(-7)],            // alg = ES256
    [-1, cborUint(1)],           // crv = P-256
    [-2, cborBstr(x)],           // x
    [-3, cborBstr(y)],           // y
  ]) };
}

function buildAuthData({ rpIdHash, flags = 0x41, signCount = 0, aaguid = new Uint8Array(16), credId, coseKey }) {
  const idLen = new Uint8Array([(credId.length >> 8) & 0xff, credId.length & 0xff]);
  const counterBytes = new Uint8Array([
    (signCount >>> 24) & 0xff,
    (signCount >>> 16) & 0xff,
    (signCount >>> 8) & 0xff,
    signCount & 0xff,
  ]);
  const flagsByte = new Uint8Array([flags]);
  return concat(rpIdHash, flagsByte, counterBytes, aaguid, idLen, credId, coseKey);
}

async function buildClientData({ type, challenge, origin }) {
  const json = JSON.stringify({ type, challenge, origin });
  const bytes = new TextEncoder().encode(json);
  return { bytes, b64u: bytesToB64u(bytes) };
}

async function rawToDer(rawSig) {
  // P1363 → DER for ES256: SEQUENCE { INTEGER r, INTEGER s }
  const r = encodeAsn1Int(rawSig.slice(0, 32));
  const s = encodeAsn1Int(rawSig.slice(32));
  const seqBody = concat(r, s);
  return concat(new Uint8Array([0x30, seqBody.length]), seqBody);
}

function encodeAsn1Int(value) {
  let v = value;
  // Strip leading zeros (but keep at least one byte).
  while (v.length > 1 && v[0] === 0) v = v.slice(1);
  // If MSB is set, prepend a 0 to mark positive.
  if (v[0] & 0x80) v = concat(new Uint8Array([0]), v);
  return concat(new Uint8Array([0x02, v.length]), v);
}

describe("WebAuthn end-to-end (register + login)", () => {
  it("registers a passkey and then signs in with it, issuing a session cookie", async () => {
    const ctx = makePasskeyCtx();
    const rpIdHash = await digest(new TextEncoder().encode(ctx.env.WEBAUTHN_RP_ID));

    // ── 1. register/begin (admin secret required) ─────────────────────────
    const beginReq = makeRequest({
      secret: REAL_ADMIN_SECRET,
      body: { action: "register/begin" },
    });
    const beginRes = await passkeysPost({ ...ctx, request: beginReq });
    expect(beginRes.status).toBe(200);
    const beginData = await beginRes.json();
    expect(typeof beginData.challenge).toBe("string");
    expect(beginData.rp.id).toBe(ctx.env.WEBAUTHN_RP_ID);
    expect(beginData.pubKeyCredParams).toEqual([{ type: "public-key", alg: -7 }]);

    // ── 2. simulate the authenticator's response ──────────────────────────
    const authn = await generateAuthenticator();
    const clientData = await buildClientData({
      type: "webauthn.create",
      challenge: beginData.challenge,
      origin: ctx.env.WEBAUTHN_ORIGIN,
    });
    const authData = buildAuthData({
      rpIdHash,
      credId: authn.credId,
      coseKey: authn.coseKey,
      signCount: 0,
    });
    const attestationObject = cborMap([
      ["fmt", cborTstr("none")],
      ["attStmt", cborMap([])],
      ["authData", cborBstr(authData)],
    ]);

    // ── 3. register/finish ────────────────────────────────────────────────
    const finishReq = makeRequest({
      secret: REAL_ADMIN_SECRET,
      body: {
        action: "register/finish",
        label: "Yubikey 5C",
        transports: ["usb"],
        credential: {
          id: bytesToB64u(authn.credId),
          response: {
            clientDataJSON: clientData.b64u,
            attestationObject: bytesToB64u(attestationObject),
          },
        },
      },
    });
    const finishRes = await passkeysPost({ ...ctx, request: finishReq });
    expect(finishRes.status).toBe(200);
    const finishData = await finishRes.json();
    expect(finishData.ok).toBe(true);
    expect(finishData.label).toBe("Yubikey 5C");

    // ── 4. login/begin ────────────────────────────────────────────────────
    const lbReq = makeRequest({ body: { action: "login/begin" } });
    const lbRes = await passkeysPost({ ...ctx, request: lbReq });
    expect(lbRes.status).toBe(200);
    const lbData = await lbRes.json();
    expect(lbData.allowCredentials).toEqual([
      { type: "public-key", id: bytesToB64u(authn.credId) },
    ]);

    // ── 5. construct a valid assertion ────────────────────────────────────
    const authClientData = await buildClientData({
      type: "webauthn.get",
      challenge: lbData.challenge,
      origin: ctx.env.WEBAUTHN_ORIGIN,
    });
    const authAuthData = buildAuthData({
      rpIdHash,
      credId: authn.credId,
      coseKey: new Uint8Array(0),  // unused at login
      flags: 0x01,                  // user-present, no AT flag
      signCount: 7,
    });
    // For login, authData has NO attestedCredData section — re-build manually.
    const minimalAuthData = (() => {
      const flags = 0x01;
      const sc = 7;
      const counter = new Uint8Array([0, 0, 0, sc]);
      return concat(rpIdHash, new Uint8Array([flags]), counter);
    })();
    const clientDataHash = await digest(authClientData.bytes);
    const signed = concat(minimalAuthData, clientDataHash);
    const rawSig = new Uint8Array(await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      authn.privateKey,
      signed,
    ));
    const derSig = await rawToDer(rawSig);

    const lfReq = makeRequest({
      body: {
        action: "login/finish",
        credential: {
          id: bytesToB64u(authn.credId),
          response: {
            clientDataJSON: authClientData.b64u,
            authenticatorData: bytesToB64u(minimalAuthData),
            signature: bytesToB64u(derSig),
            userHandle: null,
          },
        },
      },
    });
    const lfRes = await passkeysPost({ ...ctx, request: lfReq });
    expect(lfRes.status).toBe(200);
    expect((await lfRes.json()).ok).toBe(true);
    const setCookie = lfRes.headers.get("Set-Cookie") || "";
    expect(setCookie).toMatch(/^admin_session=/);
    expect(setCookie).toMatch(/HttpOnly/);
    expect(setCookie).toMatch(/SameSite=Strict/);
  });

  it("rejects login when the challenge is not in the KV (replay or stale)", async () => {
    const ctx = makePasskeyCtx();
    const stale = "not-a-real-challenge";
    const clientData = await buildClientData({
      type: "webauthn.get",
      challenge: stale,
      origin: ctx.env.WEBAUTHN_ORIGIN,
    });
    const req = makeRequest({
      body: {
        action: "login/finish",
        credential: {
          id: "anything",
          response: {
            clientDataJSON: clientData.b64u,
            authenticatorData: bytesToB64u(new Uint8Array(37)),
            signature: bytesToB64u(new Uint8Array(64)),
          },
        },
      },
    });
    const res = await passkeysPost({ ...ctx, request: req });
    expect(res.status).toBe(401);
    expect((await res.json()).error).toMatch(/challenge/i);
  });

  it("rejects register/finish when origin doesn't match the request", async () => {
    const ctx = makePasskeyCtx();
    // Pre-seed a valid challenge so we don't fail on that step.
    const challenge = newChallenge();
    await ctx._kv.put(`wa:reg:${challenge}`, "1");
    const clientData = await buildClientData({
      type: "webauthn.create",
      challenge,
      origin: "https://attacker.example.com",
    });
    const req = makeRequest({
      secret: REAL_ADMIN_SECRET,
      body: {
        action: "register/finish",
        credential: {
          id: "x",
          response: {
            clientDataJSON: clientData.b64u,
            attestationObject: bytesToB64u(new Uint8Array([0xa0])),
          },
        },
      },
    });
    const res = await passkeysPost({ ...ctx, request: req });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/origin/i);
  });
});

// ────────────────────────────────────────────────────────────────────────────
//  6. Cookie-path admin auth: a valid session bypasses the failed-secret
//     rate limit, expired/forged cookies fall through, and the existing
//     X-Admin-Secret path keeps working.
// ────────────────────────────────────────────────────────────────────────────

describe("admin auth — session cookie path", () => {
  it("authenticates with a valid admin_session cookie and no X-Admin-Secret", async () => {
    const kv = makeKv();
    await kv.put("admin_sess:goodtoken", JSON.stringify({ ts: Date.now() }));

    const request = new Request("https://admin.modih.in/api/admin/users?range=30d", {
      method: "GET",
      headers: {
        "CF-Connecting-IP": "203.0.113.55",
        "Cookie": "admin_session=goodtoken",
      },
    });
    const ctx = {
      request,
      env: { ADMIN_SECRET: REAL_ADMIN_SECRET, RATE_LIMIT: kv, DB: makePasskeyDb() },
    };
    const res = await adminGet(ctx);
    // 200 (authenticated) — body contents come from our bare D1 mock and may
    // be empty, but the auth gate must have let the request through.
    expect([200, 500]).toContain(res.status); // not 401/429
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(429);
  });

  it("ignores forged session cookies (no KV entry) and falls back to the secret path", async () => {
    const kv = makeKv();
    const request = new Request("https://admin.modih.in/api/admin/users?range=30d", {
      method: "GET",
      headers: {
        "CF-Connecting-IP": "203.0.113.56",
        "Cookie": "admin_session=forged-no-kv",
      },
    });
    const ctx = { request, env: { ADMIN_SECRET: REAL_ADMIN_SECRET, RATE_LIMIT: kv, DB: makePasskeyDb() } };
    const res = await adminGet(ctx);
    expect(res.status).toBe(401);
  });

  it("does NOT lock out a session-authenticated operator after 8 failed secret attempts", async () => {
    const kv = makeKv();
    // Burn the per-IP rate limit
    await kv.put("af:admin_secret:198.51.100.99", "9", { expirationTtl: 900 });
    await kv.put("admin_sess:resilient", JSON.stringify({ ts: Date.now() }));
    const request = new Request("https://admin.modih.in/api/admin/users?range=30d", {
      method: "GET",
      headers: {
        "CF-Connecting-IP": "198.51.100.99",
        "Cookie": "admin_session=resilient",
      },
    });
    const ctx = { request, env: { ADMIN_SECRET: REAL_ADMIN_SECRET, RATE_LIMIT: kv, DB: makePasskeyDb() } };
    const res = await adminGet(ctx);
    // Cookie wins over the rate limit.
    expect(res.status).not.toBe(429);
    expect(res.status).not.toBe(401);
  });
});

// ────────────────────────────────────────────────────────────────────────────
//  7. Endpoint validation
// ────────────────────────────────────────────────────────────────────────────

describe("/api/admin/passkeys — request validation", () => {
  it("returns 400 for invalid JSON bodies", async () => {
    const ctx = makePasskeyCtx();
    const req = new Request("https://admin.modih.in/api/admin/passkeys", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{not json",
    });
    const res = await passkeysPost({ ...ctx, request: req });
    expect(res.status).toBe(400);
  });

  it("returns 400 for unknown actions", async () => {
    const ctx = makePasskeyCtx();
    const req = makeRequest({ body: { action: "phish-the-user" } });
    const res = await passkeysPost({ ...ctx, request: req });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/unknown/i);
  });

  it("requires the admin gate for register/begin", async () => {
    const ctx = makePasskeyCtx();
    const req = makeRequest({ body: { action: "register/begin" } });
    const res = await passkeysPost({ ...ctx, request: req });
    expect(res.status).toBe(401);
  });

  it("returns 404 from login/begin when no passkeys are registered yet", async () => {
    const ctx = makePasskeyCtx();
    const req = makeRequest({ body: { action: "login/begin" } });
    const res = await passkeysPost({ ...ctx, request: req });
    expect(res.status).toBe(404);
  });

  it("availability returns false when there are no passkeys", async () => {
    const ctx = makePasskeyCtx();
    const req = makeRequest({ body: { action: "available" } });
    const res = await passkeysPost({ ...ctx, request: req });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ available: false });
  });

  it("availability returns true once a passkey is registered", async () => {
    const ctx = makePasskeyCtx({ db: makePasskeyDb({ passkeys: [{ credential_id: "x", public_key_jwk: "{}", sign_count: 0 }] }) });
    const req = makeRequest({ body: { action: "available" } });
    const res = await passkeysPost({ ...ctx, request: req });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ available: true });
  });

  it("logout clears the session cookie regardless of state", async () => {
    const ctx = makePasskeyCtx();
    const req = makeRequest({ body: { action: "logout" } });
    const res = await passkeysPost({ ...ctx, request: req });
    expect(res.status).toBe(200);
    expect(res.headers.get("Set-Cookie")).toMatch(/admin_session=;[^]*Max-Age=0/);
  });
});

// ────────────────────────────────────────────────────────────────────────────
//  8. COSE key conversion
// ────────────────────────────────────────────────────────────────────────────

describe("coseToJwkJson (ES256 / P-256)", () => {
  it("imports a hand-crafted EC2 key and round-trips back to JWK", async () => {
    // Generate a key with subtle and re-encode it as COSE so we have a valid
    // (x, y) pair that imports cleanly.
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const x = b64uToBytes(jwk.x);
    const y = b64uToBytes(jwk.y);
    const cose = cborMap([
      [1, cborUint(2)], [3, cborNeg(-7)],
      [-1, cborUint(1)], [-2, cborBstr(x)], [-3, cborBstr(y)],
    ]);
    const jwkJson = await coseToJwkJson(cose);
    const parsed = JSON.parse(jwkJson);
    expect(parsed.kty).toBe("EC");
    expect(parsed.crv).toBe("P-256");
    expect(parsed.x).toBe(jwk.x);
    expect(parsed.y).toBe(jwk.y);

    // The re-imported key verifies a signature made with the original.
    const key = await importStoredJwkEs256(jwkJson);
    const data = new TextEncoder().encode("hello");
    const rawSig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, data));
    const der = await (async () => {
      const r = encodeAsn1Int(rawSig.slice(0, 32));
      const s = encodeAsn1Int(rawSig.slice(32));
      const body = concat(r, s);
      return concat(new Uint8Array([0x30, body.length]), body);
    })();
    expect(await verifyEs256(key, der, data)).toBe(true);
  });

  it("rejects non-ES256 algorithms", async () => {
    // alg = -257 (RS256) is unsupported here.
    const cose = cborMap([
      [1, cborUint(2)], [3, cborNeg(-257)],
      [-1, cborUint(1)],
      [-2, cborBstr(new Uint8Array(32))],
      [-3, cborBstr(new Uint8Array(32))],
    ]);
    await expect(coseToJwkJson(cose)).rejects.toThrow(/ES256/);
  });
});
