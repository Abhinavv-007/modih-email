// GET    /api/developer/keys         — list API keys (developer plan + Firebase auth)
// POST   /api/developer/keys         — create a new API key
// DELETE /api/developer/keys?id=xxx  — revoke (soft-delete) a key

import { getAuthUser } from "../../_auth-helper.js";
import {
  secureHex,
  sha256Hex,
  hmacHex,
  ok,
  err,
  auditLog,
} from "../../_api-helpers.js";

const MAX_ACTIVE_KEYS = 10;

async function requireDeveloper(request, db) {
  const user = await getAuthUser(request);
  if (!user) return null;
  const row = await db
    .prepare("SELECT plan FROM user_plans WHERE uid = ?")
    .bind(user.uid)
    .first();
  if (row?.plan !== "developer") return null;
  return user;
}

// ── GET /api/developer/keys ──────────────────────────────────────────────────
export async function onRequestGet(context) {
  const { env, request } = context;

  const user = await requireDeveloper(request, env.DB);
  if (!user) {
    return err("FORBIDDEN", "Developer plan required.", 403);
  }

  const keys = await env.DB
    .prepare(
      "SELECT id, name, key_prefix, created_at, last_used_at, is_active FROM api_keys WHERE uid = ? ORDER BY created_at DESC"
    )
    .bind(user.uid)
    .all();

  return ok({ keys: keys.results || [] });
}

// ── POST /api/developer/keys ─────────────────────────────────────────────────
export async function onRequestPost(context) {
  const { env, request } = context;

  const user = await requireDeveloper(request, env.DB);
  if (!user) {
    return err("FORBIDDEN", "Developer plan required.", 403);
  }

  const body = await request.json().catch(() => ({}));
  const name = String(body.name || "Default Key").slice(0, 50).trim() || "Default Key";

  const countRow = await env.DB
    .prepare("SELECT COUNT(*) as cnt FROM api_keys WHERE uid = ? AND is_active = 1")
    .bind(user.uid)
    .first();

  if ((countRow?.cnt || 0) >= MAX_ACTIVE_KEYS) {
    return err(
      "KEY_LIMIT_REACHED",
      `Maximum ${MAX_ACTIVE_KEYS} active API keys allowed. Revoke an existing key first.`,
      400
    );
  }

  // "modih-" + 32 hex chars (128 bits entropy)
  const rawKey    = "modih-" + secureHex(16);
  const keyPrefix = rawKey.slice(0, 14) + "..."; // display-only prefix

  // Hashing strategy:
  //   key_hash          = SHA-256(rawKey)               — kept for legacy lookup compat
  //   key_hash_peppered = HMAC-SHA256(SHA-256, PEPPER)   — new secure scheme
  const pepper        = env.API_KEY_PEPPER || "";
  const rawHash       = await sha256Hex(rawKey);
  const pepperedHash  = await hmacHex(rawHash, pepper);

  const id  = secureHex(16); // 32 hex chars as key row ID
  const now = Math.floor(Date.now() / 1000);

  await env.DB
    .prepare(
      "INSERT INTO api_keys (id, uid, name, key_prefix, key_hash, key_hash_peppered, created_at, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, 1)"
    )
    .bind(id, user.uid, name, keyPrefix, rawHash, pepperedHash, now)
    .run();

  auditLog(env.DB, "api_key.created", { uid: user.uid, extra: { key_id: id, name } });

  // Return full key ONCE — it is never stored and cannot be recovered
  return ok({
    id,
    name,
    key:        rawKey,       // shown once only
    key_prefix: keyPrefix,    // safe to display in dashboard
    created_at: now,
    is_active:  true,
  }, 201);
}

// ── DELETE /api/developer/keys?id=xxx ────────────────────────────────────────
export async function onRequestDelete(context) {
  const { env, request } = context;

  const url   = new URL(request.url);
  const keyId = url.searchParams.get("id");

  if (!keyId) {
    return err("VALIDATION_ERROR", "id parameter required.", 400);
  }

  const user = await requireDeveloper(request, env.DB);
  if (!user) {
    return err("FORBIDDEN", "Developer plan required.", 403);
  }

  // Soft-delete: is_active = 0 preserves audit trail and last_used_at
  const result = await env.DB
    .prepare("UPDATE api_keys SET is_active = 0 WHERE id = ? AND uid = ?")
    .bind(keyId, user.uid)
    .run();

  if ((result.meta?.changes ?? 0) === 0) {
    return err("KEY_NOT_FOUND", "API key not found or already revoked.", 404);
  }

  auditLog(env.DB, "api_key.revoked", { uid: user.uid, extra: { key_id: keyId } });
  return ok({ revoked: true });
}
