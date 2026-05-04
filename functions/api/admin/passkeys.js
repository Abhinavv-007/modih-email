// /api/admin/passkeys
// All requests are POST with a JSON body { action, ... }. Splitting WebAuthn
// across multiple files would be more conventional, but the protocol is small
// enough that a single action-router keeps the diff focused.
//
//   register/begin   → admin gate required (existing secret OR session cookie)
//   register/finish  → admin gate required, persists a new authenticator
//   list             → admin gate required
//   delete           → admin gate required
//   login/begin      → public, returns a challenge + the registered cred IDs
//   login/finish     → public, verifies the assertion and issues a session cookie
//   logout           → public, clears the session cookie

import { auditLog } from "../../_api-helpers.js";
import {
  checkAdminAuth,
  buildSessionCookie,
  clearSessionCookie,
  isSecureRequest,
  issueAdminSession,
  readSessionCookie,
  revokeAdminSession,
  clientIp,
  ADMIN_SESSION_TTL,
} from "../../_admin-auth.js";
import {
  b64uToBytes,
  bytesEqual,
  bytesToB64u,
  cborDecode,
  coseToJwkJson,
  importStoredJwkEs256,
  newChallenge,
  newSessionToken,
  parseAuthData,
  parseClientDataJson,
  resolveRpAndOrigin,
  sha256,
  sha256Of,
  verifyEs256,
} from "../../_webauthn.js";

const CHALLENGE_TTL = 5 * 60; // 5 minutes
const RP_NAME = "MODIH Mail Admin";

const json = (body, init = {}) => Response.json(body, init);
const fail = (message, status = 400, extraHeaders = {}) =>
  Response.json({ error: message }, { status, headers: extraHeaders });

export async function onRequestPost(context) {
  const { request, env } = context;
  let body;
  try {
    body = await request.json();
  } catch {
    return fail("Invalid JSON body.");
  }

  const action = body?.action;
  switch (action) {
    case "register/begin":   return registerBegin(request, env);
    case "register/finish":  return registerFinish(request, env, body);
    case "available":        return availability(request, env);
    case "login/begin":      return loginBegin(request, env);
    case "login/finish":     return loginFinish(request, env, body);
    case "list":             return listPasskeys(request, env);
    case "delete":           return deletePasskey(request, env, body);
    case "logout":           return logout(request, env);
    default:
      return fail("Unknown action.");
  }
}

// ── Registration ─────────────────────────────────────────────────────────────

async function registerBegin(request, env) {
  const auth = await checkAdminAuth(request, env);
  if (!auth.ok) return auth.response;

  const { rpId } = resolveRpAndOrigin(request, env);
  const challenge = newChallenge();
  await env.RATE_LIMIT.put(`wa:reg:${challenge}`, "1", { expirationTtl: CHALLENGE_TTL });

  const existing = await listCredentialIds(env.DB);

  return json({
    challenge,
    rp: { id: rpId, name: RP_NAME },
    user: {
      // Single admin user; the id is opaque and constant for this gate.
      id: "modih-admin",
      name: "modih-admin",
      displayName: RP_NAME,
    },
    pubKeyCredParams: [
      // Only ES256 is implemented server-side.
      { type: "public-key", alg: -7 },
    ],
    timeout: 60000,
    attestation: "none",
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
    excludeCredentials: existing.map(id => ({ type: "public-key", id })),
  });
}

async function registerFinish(request, env, body) {
  const auth = await checkAdminAuth(request, env);
  if (!auth.ok) return auth.response;

  const { credential, label, transports } = body || {};
  if (!credential || typeof credential !== "object") {
    return fail("Missing credential.");
  }
  const { id, response } = credential;
  if (!id || !response?.clientDataJSON || !response?.attestationObject) {
    return fail("Incomplete credential.");
  }

  let clientData;
  try {
    clientData = parseClientDataJson(response.clientDataJSON);
  } catch (err) {
    return fail(`clientDataJSON: ${err.message}`);
  }
  if (clientData.parsed.type !== "webauthn.create") {
    return fail("clientDataJSON.type must be webauthn.create.");
  }

  const { rpId, origin } = resolveRpAndOrigin(request, env);
  if (clientData.parsed.origin !== origin) {
    return fail("Origin mismatch.");
  }

  const challenge = clientData.parsed.challenge;
  const consumed = await consumeChallenge(env, "reg", challenge);
  if (!consumed) {
    return fail("Stale or unknown challenge.");
  }

  // Decode attestationObject (CBOR) → { fmt, attStmt, authData }
  let attObj;
  try {
    attObj = cborDecode(b64uToBytes(response.attestationObject));
  } catch (err) {
    return fail(`attestationObject: ${err.message}`);
  }
  if (!(attObj instanceof Map)) return fail("attestationObject: not a map.");
  const authData = attObj.get("authData");
  if (!(authData instanceof Uint8Array)) return fail("attestationObject: no authData.");

  let parsed;
  try {
    parsed = parseAuthData(authData);
  } catch (err) {
    return fail(`authData: ${err.message}`);
  }
  if (!parsed.userPresent) return fail("User-present flag missing.");
  if (!parsed.coseKey || !parsed.credId) return fail("Attested credential data missing.");

  const expectedRpHash = await sha256Of(rpId);
  if (!bytesEqual(parsed.rpIdHash, expectedRpHash)) {
    return fail("RP-ID mismatch.");
  }

  let publicKeyJwk;
  try {
    publicKeyJwk = await coseToJwkJson(parsed.coseKey);
  } catch (err) {
    return fail(`Public key: ${err.message}`);
  }

  const credIdB64u = bytesToB64u(parsed.credId);
  if (credIdB64u !== id) {
    return fail("Credential ID mismatch between authenticator and clientData.");
  }

  const now = Math.floor(Date.now() / 1000);
  const aaguidHex = parsed.aaguid
    ? Array.from(parsed.aaguid, b => b.toString(16).padStart(2, "0")).join("")
    : null;
  const safeLabel = sanitizeLabel(label) || `Passkey ${now}`;
  const transportsCsv = sanitizeTransports(transports);

  try {
    await env.DB.prepare(
      `INSERT INTO admin_passkeys
         (credential_id, public_key_jwk, algorithm, sign_count, transports, label, aaguid, created_at, last_used_at)
       VALUES (?, ?, -7, ?, ?, ?, ?, ?, NULL)`
    ).bind(
      credIdB64u,
      publicKeyJwk,
      parsed.signCount,
      transportsCsv,
      safeLabel,
      aaguidHex,
      now
    ).run();
  } catch (err) {
    if (String(err?.message || "").includes("UNIQUE")) {
      return fail("This passkey is already registered.", 409);
    }
    return fail("Could not persist passkey.", 500);
  }

  auditLog(env.DB, "admin_passkey.registered", { ip: clientIp(request), label: safeLabel });

  return json({ ok: true, credential_id: credIdB64u, label: safeLabel });
}

// ── Login ────────────────────────────────────────────────────────────────────

async function availability(_request, env) {
  const ids = await listCredentialIds(env.DB);
  return json({ available: ids.length > 0 });
}

async function loginBegin(request, env) {
  const { rpId } = resolveRpAndOrigin(request, env);
  const allowCredentials = (await listCredentialIds(env.DB)).map(id => ({
    type: "public-key",
    id,
  }));
  if (allowCredentials.length === 0) {
    return fail("No passkeys are registered yet.", 404);
  }
  const challenge = newChallenge();
  await env.RATE_LIMIT.put(`wa:auth:${challenge}`, "1", { expirationTtl: CHALLENGE_TTL });

  return json({
    challenge,
    rpId,
    timeout: 60000,
    userVerification: "preferred",
    allowCredentials,
  });
}

async function loginFinish(request, env, body) {
  const { credential } = body || {};
  if (!credential || typeof credential !== "object") return fail("Missing credential.");
  const { id, response } = credential;
  if (!id || !response?.clientDataJSON || !response?.authenticatorData || !response?.signature) {
    return fail("Incomplete assertion.");
  }

  let clientData;
  try {
    clientData = parseClientDataJson(response.clientDataJSON);
  } catch (err) {
    return fail(`clientDataJSON: ${err.message}`);
  }
  if (clientData.parsed.type !== "webauthn.get") {
    return fail("clientDataJSON.type must be webauthn.get.");
  }

  const { rpId, origin } = resolveRpAndOrigin(request, env);
  if (clientData.parsed.origin !== origin) return fail("Origin mismatch.");

  const consumed = await consumeChallenge(env, "auth", clientData.parsed.challenge);
  if (!consumed) return fail("Stale or unknown challenge.", 401);

  // Look up the stored credential row.
  let stored;
  try {
    stored = await env.DB.prepare(
      `SELECT id, credential_id, public_key_jwk, sign_count
         FROM admin_passkeys
        WHERE credential_id = ?
        LIMIT 1`
    ).bind(id).first();
  } catch {
    stored = null;
  }
  if (!stored) return fail("Unknown credential.", 401);

  const authenticatorData = b64uToBytes(response.authenticatorData);
  let parsed;
  try {
    parsed = parseAuthData(authenticatorData);
  } catch (err) {
    return fail(`authenticatorData: ${err.message}`);
  }

  const expectedRpHash = await sha256Of(rpId);
  if (!bytesEqual(parsed.rpIdHash, expectedRpHash)) return fail("RP-ID mismatch.", 401);
  if (!parsed.userPresent) return fail("User-present flag missing.", 401);

  // signedBytes = authenticatorData || SHA-256(clientDataJSON)
  const clientDataHash = await sha256(clientData.bytes);
  const signed = new Uint8Array(authenticatorData.length + clientDataHash.length);
  signed.set(authenticatorData, 0);
  signed.set(clientDataHash, authenticatorData.length);

  let key;
  try {
    key = await importStoredJwkEs256(stored.public_key_jwk);
  } catch {
    return fail("Stored key import failed.", 500);
  }

  let valid;
  try {
    const sigDer = b64uToBytes(response.signature);
    valid = await verifyEs256(key, sigDer, signed);
  } catch {
    valid = false;
  }
  if (!valid) {
    auditLog(env.DB, "admin_passkey.invalid", { ip: clientIp(request) });
    return fail("Signature verification failed.", 401);
  }

  // Replay protection — both 0 is fine (some authenticators don't track),
  // otherwise the new counter MUST be strictly greater than the stored one.
  const newCounter = parsed.signCount;
  if (newCounter !== 0 || stored.sign_count !== 0) {
    if (newCounter <= stored.sign_count) {
      auditLog(env.DB, "admin_passkey.counter_regression", { ip: clientIp(request) });
      return fail("Authenticator counter regressed (possible cloning).", 401);
    }
  }

  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(
    `UPDATE admin_passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?`
  ).bind(newCounter, now, stored.id).run().catch(() => {});

  // Issue session.
  const token = newSessionToken();
  await issueAdminSession(env, token, { ip: clientIp(request), via: "passkey" });
  auditLog(env.DB, "admin_passkey.login", { ip: clientIp(request) });

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": buildSessionCookie(token, {
        secure: isSecureRequest(request),
        maxAge: ADMIN_SESSION_TTL,
      }),
    },
  });
}

// ── List / delete / logout ───────────────────────────────────────────────────

async function listPasskeys(request, env) {
  const auth = await checkAdminAuth(request, env);
  if (!auth.ok) return auth.response;
  let rows = [];
  try {
    const result = await env.DB.prepare(
      `SELECT id, credential_id, label, transports, aaguid, created_at, last_used_at
         FROM admin_passkeys
        ORDER BY created_at DESC`
    ).all();
    rows = result?.results || [];
  } catch {
    rows = [];
  }
  return json({ passkeys: rows });
}

async function deletePasskey(request, env, body) {
  const auth = await checkAdminAuth(request, env);
  if (!auth.ok) return auth.response;
  const id = Number(body?.id);
  if (!Number.isFinite(id) || id <= 0) return fail("Invalid passkey id.");
  try {
    await env.DB.prepare(`DELETE FROM admin_passkeys WHERE id = ?`).bind(id).run();
  } catch {
    return fail("Could not delete passkey.", 500);
  }
  auditLog(env.DB, "admin_passkey.deleted", { ip: clientIp(request), id });
  return json({ ok: true });
}

async function logout(request, env) {
  const token = readSessionCookie(request);
  if (token) await revokeAdminSession(env, token);
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": clearSessionCookie(),
    },
  });
}

// ── Internal helpers ─────────────────────────────────────────────────────────

async function consumeChallenge(env, kind, challenge) {
  if (!challenge || typeof challenge !== "string") return false;
  const key = `wa:${kind}:${challenge}`;
  const found = await env.RATE_LIMIT.get(key);
  if (!found) return false;
  await env.RATE_LIMIT.delete(key);
  return true;
}

async function listCredentialIds(db) {
  try {
    const result = await db.prepare(
      `SELECT credential_id FROM admin_passkeys`
    ).all();
    return (result?.results || []).map(r => r.credential_id);
  } catch {
    return [];
  }
}

function sanitizeLabel(value) {
  if (typeof value !== "string") return "";
  const trimmed = value.trim().slice(0, 64);
  return trimmed.replace(/[^\w\s.\-()/+@]/g, "");
}

function sanitizeTransports(value) {
  const allowed = ["usb", "nfc", "ble", "internal", "hybrid", "smart-card"];
  if (!Array.isArray(value)) return null;
  const filtered = value.filter(v => typeof v === "string" && allowed.includes(v));
  return filtered.length ? filtered.join(",") : null;
}
