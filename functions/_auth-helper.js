/**
 * Firebase Token Verifier — Cloudflare Workers
 *
 * Uses Firebase Identity Toolkit REST API to verify ID tokens.
 * This approach is simple, reliable, and avoids complex WebCrypto
 * X.509 certificate parsing which can fail in Workers environments.
 *
 * POST https://identitytoolkit.googleapis.com/v1/accounts:lookup
 */

const FIREBASE_API_KEY = "AIzaSyA9smn_wjvJ9F8Oe-wZzLzOGqHKwAXXXCA";
const LOOKUP_URL = `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_API_KEY}`;

/**
 * Verify a Firebase ID token via the REST API.
 * Returns { uid, email, email_verified, name, picture } or null if invalid.
 */
export async function verifyFirebaseToken(idToken) {
  const res = await fetch(LOOKUP_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ idToken }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err?.error?.message || `Firebase lookup failed: ${res.status}`);
  }

  const data = await res.json();
  const user = data.users?.[0];
  if (!user) throw new Error("No user returned from Firebase lookup");

  return {
    uid: user.localId,
    email: user.email || null,
    email_verified: user.emailVerified === true,
    name: user.displayName || null,
    picture: user.photoUrl || null,
  };
}

/**
 * Extract and verify Firebase token from Authorization header.
 * Returns decoded user object or null if missing/invalid.
 */
export async function getAuthUser(request) {
  const authHeader = request.headers.get("Authorization") || "";
  if (!authHeader.startsWith("Bearer ")) return null;
  const token = authHeader.slice(7).trim();
  if (!token) return null;

  try {
    return await verifyFirebaseToken(token);
  } catch (e) {
    console.error("Firebase token verification failed:", e.message);
    return null;
  }
}
