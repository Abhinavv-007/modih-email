/**
 * Minimal WebAuthn server helpers — Workers/Pages Functions runtime.
 *
 * Only ES256 (COSE alg -7, the default for Apple/Android passkeys) is
 * supported. The implementation is deliberately small and dependency-free:
 *
 *  • base64url <-> Uint8Array helpers
 *  • a CBOR decoder limited to the subset attestation objects use
 *  • COSE_Key (EC2 / P-256) → JWK → SubtleCrypto verifier
 *  • DER ECDSA → IEEE-P1363 fixed-length signature converter
 *  • challenge / origin / RP-ID validators against the structured clientDataJSON
 *
 * Callers in `functions/api/admin/passkeys.js` orchestrate registration and
 * login on top of these primitives.
 */

// ── base64url ────────────────────────────────────────────────────────────────

export function b64uToBytes(input) {
  if (typeof input !== "string") throw new Error("b64u: not a string");
  const pad = "=".repeat((4 - (input.length % 4)) % 4);
  const b64 = (input + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64u(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ── CBOR decoder (subset used by WebAuthn) ───────────────────────────────────
//
// Supports: unsigned ints, negative ints, byte strings, text strings, arrays,
// maps, false/true/null/undefined. No tags, no floats, no indefinite-length
// items — none of which appear in attestationObject or COSE keys.

class CborReader {
  constructor(bytes) {
    this.b = bytes;
    this.pos = 0;
  }
  ensure(n) {
    if (this.pos + n > this.b.length) throw new Error("cbor: truncated input");
  }
  readByte() {
    this.ensure(1);
    return this.b[this.pos++];
  }
  readN(n) {
    this.ensure(n);
    const slice = this.b.slice(this.pos, this.pos + n);
    this.pos += n;
    return slice;
  }
  readUint(info) {
    if (info < 24) return info;
    if (info === 24) return this.readByte();
    if (info === 25) {
      const a = this.readByte();
      const b = this.readByte();
      return (a << 8) | b;
    }
    if (info === 26) {
      const a = this.readByte();
      const b = this.readByte();
      const c = this.readByte();
      const d = this.readByte();
      // unsigned 32-bit; numbers up to 2^32 stay safe in JS
      return a * 0x1000000 + ((b << 16) | (c << 8) | d);
    }
    if (info === 27) {
      // 64-bit lengths shouldn't appear in attestation objects
      throw new Error("cbor: 64-bit lengths not supported");
    }
    throw new Error("cbor: reserved info value " + info);
  }
  readItem() {
    const initial = this.readByte();
    const major = initial >> 5;
    const info = initial & 0x1f;

    switch (major) {
      case 0: // unsigned int
        return this.readUint(info);
      case 1: // negative int  (value = -1 - n)
        return -1 - this.readUint(info);
      case 2: // byte string
        return this.readN(this.readUint(info));
      case 3: { // text string
        const bytes = this.readN(this.readUint(info));
        return new TextDecoder().decode(bytes);
      }
      case 4: { // array
        const len = this.readUint(info);
        const arr = new Array(len);
        for (let i = 0; i < len; i++) arr[i] = this.readItem();
        return arr;
      }
      case 5: { // map
        const len = this.readUint(info);
        // Use a Map so non-string keys (COSE keys are integers) round-trip cleanly.
        const m = new Map();
        for (let i = 0; i < len; i++) {
          const k = this.readItem();
          const v = this.readItem();
          m.set(k, v);
        }
        return m;
      }
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        if (info === 23) return undefined;
        throw new Error("cbor: unsupported simple value " + info);
      default:
        throw new Error("cbor: unsupported major type " + major);
    }
  }
}

export function cborDecode(bytes) {
  const reader = new CborReader(bytes);
  const out = reader.readItem();
  return out;
}

// ── authData parser ──────────────────────────────────────────────────────────
//
// authData = rpIdHash(32) || flags(1) || signCount(4) || [attestedCredData] || [extensions]
// attestedCredData = aaguid(16) || credIdLen(2) || credId(N) || COSE_Key(rest)

export function parseAuthData(authData) {
  if (!(authData instanceof Uint8Array) || authData.length < 37) {
    throw new Error("authData: too short");
  }
  const rpIdHash = authData.slice(0, 32);
  const flags = authData[32];
  const signCount =
    (authData[33] << 24) |
    (authData[34] << 16) |
    (authData[35] << 8) |
    authData[36];
  const userPresent = (flags & 0x01) === 0x01;
  const userVerified = (flags & 0x04) === 0x04;
  const attestedDataIncluded = (flags & 0x40) === 0x40;

  let aaguid = null;
  let credId = null;
  let coseKey = null;

  if (attestedDataIncluded) {
    if (authData.length < 55) throw new Error("authData: attested data truncated");
    aaguid = authData.slice(37, 53);
    const credIdLen = (authData[53] << 8) | authData[54];
    if (authData.length < 55 + credIdLen) throw new Error("authData: credId truncated");
    credId = authData.slice(55, 55 + credIdLen);
    coseKey = authData.slice(55 + credIdLen);
  }

  return {
    rpIdHash,
    flags,
    signCount: signCount >>> 0,
    userPresent,
    userVerified,
    aaguid,
    credId,
    coseKey, // CBOR bytes — caller decodes
  };
}

// ── COSE_Key → CryptoKey (ES256 only) ────────────────────────────────────────

export async function importCoseEs256(coseBytes) {
  const decoded = cborDecode(coseBytes);
  if (!(decoded instanceof Map)) throw new Error("cose: not a map");

  // COSE labels: 1=kty, 3=alg, -1=crv, -2=x, -3=y
  const kty = decoded.get(1);
  const alg = decoded.get(3);
  const crv = decoded.get(-1);
  const x = decoded.get(-2);
  const y = decoded.get(-3);

  if (kty !== 2) throw new Error("cose: kty must be 2 (EC2), got " + kty);
  if (alg !== -7) throw new Error("cose: only ES256 (alg -7) supported, got " + alg);
  if (crv !== 1) throw new Error("cose: crv must be 1 (P-256), got " + crv);
  if (!(x instanceof Uint8Array) || x.length !== 32) throw new Error("cose: bad x");
  if (!(y instanceof Uint8Array) || y.length !== 32) throw new Error("cose: bad y");

  const jwk = {
    kty: "EC",
    crv: "P-256",
    x: bytesToB64u(x),
    y: bytesToB64u(y),
    ext: true,
  };

  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
}

/**
 * Re-export the JWK form so callers can persist the public key in D1 without
 * hanging onto a CryptoKey across requests. Round-trips via importCoseEs256
 * → exportKey("jwk") → JSON.stringify.
 */
export async function coseToJwkJson(coseBytes) {
  const key = await importCoseEs256(coseBytes);
  const jwk = await crypto.subtle.exportKey("jwk", key);
  return JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y });
}

export async function importStoredJwkEs256(jwkJson) {
  const jwk = JSON.parse(jwkJson);
  return crypto.subtle.importKey(
    "jwk",
    { ...jwk, ext: true },
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
}

// ── DER ECDSA → IEEE-P1363 (raw r||s) ────────────────────────────────────────
//
// WebAuthn ES256 signatures arrive ASN.1 DER-encoded:
//   30 LEN 02 RLEN R 02 SLEN S
// SubtleCrypto.verify expects the raw 64-byte concatenation.

export function derToRawEcdsa(derBytes) {
  if (!(derBytes instanceof Uint8Array)) throw new Error("der: not bytes");
  if (derBytes[0] !== 0x30) throw new Error("der: expected SEQUENCE");

  let pos = 1;
  // length (short or long form)
  if (derBytes[pos] & 0x80) {
    pos += 1 + (derBytes[pos] & 0x7f);
  } else {
    pos += 1;
  }

  if (derBytes[pos] !== 0x02) throw new Error("der: expected r INTEGER");
  pos += 1;
  let rLen = derBytes[pos];
  pos += 1;
  let r = derBytes.slice(pos, pos + rLen);
  pos += rLen;

  if (derBytes[pos] !== 0x02) throw new Error("der: expected s INTEGER");
  pos += 1;
  let sLen = derBytes[pos];
  pos += 1;
  let s = derBytes.slice(pos, pos + sLen);

  // Strip leading 0x00 sign bytes; left-pad to 32.
  r = stripPad(r, 32);
  s = stripPad(s, 32);

  const out = new Uint8Array(64);
  out.set(r, 0);
  out.set(s, 32);
  return out;
}

function stripPad(integer, target) {
  let trimmed = integer;
  while (trimmed.length > target && trimmed[0] === 0) trimmed = trimmed.slice(1);
  if (trimmed.length > target) throw new Error("der: integer overflow");
  if (trimmed.length === target) return trimmed;
  const padded = new Uint8Array(target);
  padded.set(trimmed, target - trimmed.length);
  return padded;
}

// ── Hashing helpers ──────────────────────────────────────────────────────────

export async function sha256(bytes) {
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(buf);
}

export async function sha256Of(text) {
  return sha256(new TextEncoder().encode(text));
}

// ── clientDataJSON validation ────────────────────────────────────────────────

export function parseClientDataJson(b64u) {
  const bytes = b64uToBytes(b64u);
  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new Error("clientDataJSON: not valid JSON");
  }
  if (!parsed || typeof parsed !== "object") throw new Error("clientDataJSON: not an object");
  return { bytes, parsed };
}

export function expectField(parsed, key, expected) {
  if (parsed[key] !== expected) {
    throw new Error(`clientDataJSON: ${key} mismatch`);
  }
}

// ── ECDSA verification entry point ───────────────────────────────────────────

export async function verifyEs256(publicKey, signatureDer, signedBytes) {
  const raw = derToRawEcdsa(signatureDer);
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    raw,
    signedBytes
  );
}

// ── Challenge / session helpers ──────────────────────────────────────────────

export function newChallenge() {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  return bytesToB64u(buf);
}

export function newSessionToken() {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  return bytesToB64u(buf);
}

/**
 * Resolve the RP ID and expected origin for the current request.
 *
 * On Cloudflare Pages the deployed origin (e.g. https://modih.in) is the only
 * value we should accept. For local development with `wrangler pages dev` we
 * also allow the loopback so the gate is exercisable end-to-end.
 *
 * Set `env.WEBAUTHN_RP_ID` and `env.WEBAUTHN_ORIGIN` in production to override
 * the request-derived defaults.
 */
export function resolveRpAndOrigin(request, env) {
  const url = new URL(request.url);
  const rpId = env?.WEBAUTHN_RP_ID || url.hostname;
  const origin =
    env?.WEBAUTHN_ORIGIN || `${url.protocol}//${url.host}`;
  return { rpId, origin };
}
