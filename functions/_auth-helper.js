/**
 * Firebase ID Token Verifier for Cloudflare Workers
 * Verifies Firebase JWT tokens using WebCrypto + Firebase public keys.
 * No Firebase Admin SDK required.
 */

const FIREBASE_PROJECT_ID = "modih-in";
const FIREBASE_PUBLIC_KEYS_URL =
  "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";

let cachedKeys = null;
let cacheTime = 0;

async function getFirebasePublicKeys() {
  const now = Date.now();
  // Cache keys for 1 hour
  if (cachedKeys && now - cacheTime < 3600000) return cachedKeys;

  const res = await fetch(FIREBASE_PUBLIC_KEYS_URL);
  if (!res.ok) throw new Error("Failed to fetch Firebase public keys");

  const keys = await res.json();
  cachedKeys = keys;
  cacheTime = now;
  return keys;
}

function base64UrlDecode(str) {
  const padded = str + "==".slice(0, (4 - (str.length % 4)) % 4);
  const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function parseJwt(token) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT format");
  const header = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[0])));
  const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[1])));
  return { header, payload, rawParts: parts };
}

async function importCertKey(certPem) {
  // Strip PEM headers and convert to bytes
  const b64 = certPem
    .replace(/-----BEGIN CERTIFICATE-----/, "")
    .replace(/-----END CERTIFICATE-----/, "")
    .replace(/\s/g, "");

  const binaryDer = base64UrlDecode(b64);

  // Import as X.509 certificate (SubjectPublicKeyInfo extraction via CryptoKey)
  const cert = await crypto.subtle.importKey(
    "raw",
    binaryDer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  ).catch(async () => {
    // Fallback: try as spki
    return crypto.subtle.importKey(
      "spki",
      binaryDer,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );
  });
  return cert;
}

/**
 * Verify a Firebase ID token.
 * Returns the decoded payload { uid, email, email_verified, ... } or throws.
 */
export async function verifyFirebaseToken(idToken) {
  const { header, payload, rawParts } = parseJwt(idToken);

  // Basic claim checks
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now) throw new Error("Token expired");
  if (payload.iat > now + 300) throw new Error("Token issued in future");
  if (payload.aud !== FIREBASE_PROJECT_ID) throw new Error("Invalid audience");
  if (payload.iss !== `https://securetoken.google.com/${FIREBASE_PROJECT_ID}`)
    throw new Error("Invalid issuer");
  if (!payload.sub) throw new Error("Missing subject");

  // Get Firebase public keys
  const keys = await getFirebasePublicKeys();
  const certPem = keys[header.kid];
  if (!certPem) throw new Error("Unknown key ID");

  // Verify signature
  const signingInput = new TextEncoder().encode(`${rawParts[0]}.${rawParts[1]}`);
  const signature = base64UrlDecode(rawParts[2]);

  let publicKey;
  try {
    // Parse the X.509 cert to extract the public key
    const certBytes = Uint8Array.from(
      atob(certPem.replace(/-----[^-]+-----/g, "").replace(/\s/g, "")),
      (c) => c.charCodeAt(0)
    );
    publicKey = await crypto.subtle.importKey(
      "spki",
      certBytes,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );
  } catch {
    // If direct SPKI import fails, try the whole cert data
    const certBytes = Uint8Array.from(
      atob(certPem.replace(/-----[^-]+-----/g, "").replace(/\s/g, "")),
      (c) => c.charCodeAt(0)
    );
    publicKey = await crypto.subtle.importKey(
      "raw",
      certBytes,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );
  }

  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, signature, signingInput);
  if (!valid) throw new Error("Invalid token signature");

  return {
    uid: payload.sub,
    email: payload.email || null,
    email_verified: payload.email_verified || false,
    name: payload.name || null,
    picture: payload.picture || null,
  };
}

/**
 * Extract and verify Firebase token from Authorization header.
 * Returns decoded payload or null if missing/invalid.
 */
export async function getAuthUser(request) {
  const authHeader = request.headers.get("Authorization") || "";
  if (!authHeader.startsWith("Bearer ")) return null;
  const token = authHeader.slice(7);

  try {
    return await verifyFirebaseToken(token);
  } catch (e) {
    console.error("Token verification failed:", e.message);
    return null;
  }
}
