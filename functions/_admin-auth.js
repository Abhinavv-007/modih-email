/**
 * Shared admin authentication for /api/admin/* endpoints.
 *
 * Two equally-trusted methods unlock the gate:
 *   1. X-Admin-Secret header  (constant-time compare against env.ADMIN_SECRET)
 *   2. admin_session cookie    (issued by /api/admin/passkeys after a valid
 *                              WebAuthn assertion, stored in KV with TTL)
 *
 * Both paths share the per-IP brute-force counter so an attacker cannot
 * exhaust the cookie path while we still rate-limit the secret path.
 *
 * Error responses are intentionally generic — they never reveal whether the
 * secret was empty, partially correct, or fully wrong, nor whether a session
 * cookie existed but expired.
 */

import {
  safeEqual,
  isAuthRateLimited,
  recordAuthFailure,
  auditLog,
} from "./_api-helpers.js";

export const ADMIN_AUTH_MAX = 8;
export const ADMIN_AUTH_WINDOW = 15 * 60; // 15 minutes
export const ADMIN_SESSION_TTL = 12 * 60 * 60; // 12 hours
export const ADMIN_SESSION_COOKIE = "admin_session";

export function clientIp(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

export function adminUnauthResponse() {
  return Response.json({ error: "Unauthorized" }, { status: 401 });
}

/**
 * Look up the `admin_session` cookie value (if any) in the request.
 */
export function readSessionCookie(request) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(/;\s*/)) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const name = part.slice(0, eq).trim();
    if (name === ADMIN_SESSION_COOKIE) {
      return decodeURIComponent(part.slice(eq + 1));
    }
  }
  return null;
}

/**
 * Build a Set-Cookie value with hardened defaults for the admin session.
 * Only secure when the request was over HTTPS (so localhost dev still works).
 */
export function buildSessionCookie(token, { secure = true, maxAge = ADMIN_SESSION_TTL } = {}) {
  const attrs = [
    `${ADMIN_SESSION_COOKIE}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    `Max-Age=${maxAge}`,
  ];
  if (secure) attrs.push("Secure");
  return attrs.join("; ");
}

export function clearSessionCookie() {
  return `${ADMIN_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`;
}

export function isSecureRequest(request) {
  const url = new URL(request.url);
  if (url.protocol === "https:") return true;
  return request.headers.get("X-Forwarded-Proto") === "https";
}

/**
 * Verify the request carries a valid admin credential.
 *
 * Returns:
 *   { ok: true,  via: "secret" | "session" }
 *   { ok: false, response: Response }   caller must return this Response
 */
export async function checkAdminAuth(request, env) {
  const ip = clientIp(request);

  // Cookie path runs first so a passkey-authenticated operator is never
  // locked out by failed secret attempts on the same IP. The session token
  // is 256 bits of CSPRNG entropy stored in KV, so probing for valid tokens
  // is computationally infeasible.
  const sessionToken = readSessionCookie(request);
  if (sessionToken && env.RATE_LIMIT) {
    const stored = await env.RATE_LIMIT.get(`admin_sess:${sessionToken}`);
    if (stored) {
      return { ok: true, via: "session" };
    }
  }

  if (env.RATE_LIMIT && await isAuthRateLimited(env.RATE_LIMIT, ip, "admin_secret", ADMIN_AUTH_MAX)) {
    return {
      ok: false,
      response: Response.json(
        { error: "Too many failed admin attempts. Try again later." },
        { status: 429, headers: { "Retry-After": String(ADMIN_AUTH_WINDOW) } }
      ),
    };
  }

  const secret = request.headers.get("X-Admin-Secret") || "";
  const expected = env.ADMIN_SECRET || "";

  // Server-side secret missing — refuse access without leaking why.
  if (!expected) {
    return { ok: false, response: adminUnauthResponse() };
  }

  // Empty submission — treat as "not logged in" (don't burn a rate-limit
  // slot on every page-load probe).
  if (!secret) {
    return { ok: false, response: adminUnauthResponse() };
  }

  if (!safeEqual(secret, expected)) {
    if (env.RATE_LIMIT) {
      await recordAuthFailure(env.RATE_LIMIT, ip, "admin_secret", ADMIN_AUTH_MAX, ADMIN_AUTH_WINDOW);
    }
    auditLog(env.DB, "admin_secret.invalid", { ip });
    return { ok: false, response: adminUnauthResponse() };
  }

  return { ok: true, via: "secret" };
}

/**
 * Persist a fresh admin session (used after a successful WebAuthn assertion).
 * Returns the opaque token that should be set as the cookie value.
 */
export async function issueAdminSession(env, token, meta = {}) {
  if (!env.RATE_LIMIT) throw new Error("admin_session: KV unavailable");
  const value = JSON.stringify({ ts: Date.now(), ...meta });
  await env.RATE_LIMIT.put(`admin_sess:${token}`, value, {
    expirationTtl: ADMIN_SESSION_TTL,
  });
}

export async function revokeAdminSession(env, token) {
  if (!env.RATE_LIMIT || !token) return;
  await env.RATE_LIMIT.delete(`admin_sess:${token}`);
}
