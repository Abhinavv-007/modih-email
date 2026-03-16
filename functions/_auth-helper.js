/**
 * Firebase JWT Verifier — Cloudflare Workers
 *
 * Verifies Firebase ID tokens using Google's public JWK keys.
 * This is the correct, cryptographically-sound approach for Workers —
 * no REST API calls to Firebase, no API keys needed.
 *
 * Keys: https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com
 */

const FIREBASE_PROJECT_ID = "modih-mail";
const JWKS_URL = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
const ISSUER = `https://securetoken.google.com/${FIREBASE_PROJECT_ID}`;

// base64url → Uint8Array
function b64ToBytes(str) {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(base64.length + (4 - (base64.length % 4)) % 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

// Decode a base64url JWT segment into a JSON object
function decodeSegment(seg) {
  return JSON.parse(new TextDecoder().decode(b64ToBytes(seg)));
}

/**
 * Verify a Firebase ID token.
 * Returns decoded user info or throws on failure.
 */
export async function verifyFirebaseToken(idToken) {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("Malformed JWT");

  const [headerB64, payloadB64, sigB64] = parts;
  const header  = decodeSegment(headerB64);
  const payload = decodeSegment(payloadB64);

  // ── Claim validation ───────────────────────────────────────────────────
  const now = Math.floor(Date.now() / 1000);
  if (!payload.sub)                       throw new Error("Missing sub");
  if (payload.exp <= now)                 throw new Error("Token expired");
  if (payload.iat > now + 300)            throw new Error("Token issued in future");
  if (payload.iss !== ISSUER)             throw new Error(`Wrong issuer: ${payload.iss}`);
  if (payload.aud !== FIREBASE_PROJECT_ID) throw new Error(`Wrong audience: ${payload.aud}`);

  // ── Fetch Google's public key set (cached at CF edge for 1 h) ─────────
  const jwksRes = await fetch(JWKS_URL, { cf: { cacheTtl: 3600, cacheEverything: true } });
  if (!jwksRes.ok) throw new Error(`JWKS fetch failed: ${jwksRes.status}`);
  const { keys } = await jwksRes.json();

  const jwk = keys?.find(k => k.kid === header.kid);
  if (!jwk) throw new Error(`No JWK found for kid=${header.kid}`);

  // ── Import key & verify signature ──────────────────────────────────────
  const cryptoKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },
    false,
    ["verify"]
  );

  const signedData  = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature   = b64ToBytes(sigB64);
  const valid       = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", cryptoKey, signature, signedData);

  if (!valid) throw new Error("Invalid signature");

  return {
    uid:            payload.sub,
    email:          payload.email          || null,
    email_verified: payload.email_verified === true,
    name:           payload.name           || null,
    picture:        payload.picture        || null,
  };
}

/**
 * Extract + verify Firebase token from Authorization: Bearer <token> header.
 * Returns user info or null.
 */
export async function getAuthUser(request) {
  const authHeader = request.headers.get("Authorization") || "";
  if (!authHeader.startsWith("Bearer ")) return null;
  const token = authHeader.slice(7).trim();
  if (!token) return null;

  try {
    return await verifyFirebaseToken(token);
  } catch (e) {
    console.error("Firebase JWT verification failed:", e.message);
    return null;
  }
}
