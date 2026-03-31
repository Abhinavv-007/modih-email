// GET    /api/developer/keys         — List API keys (requires Firebase auth + developer plan)
// POST   /api/developer/keys         — Create a new API key
// DELETE /api/developer/keys?id=xxx  — Revoke (soft-delete) a key

import { getAuthUser } from "../../_auth-helper.js";

const MAX_ACTIVE_KEYS = 10;

async function hashKey(key) {
  const data = new TextEncoder().encode(key);
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

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

// GET /api/developer/keys
export async function onRequestGet(context) {
  const { env, request } = context;

  const user = await requireDeveloper(request, env.DB);
  if (!user) {
    return Response.json({ error: "Developer plan required." }, { status: 403 });
  }

  const keys = await env.DB
    .prepare(
      "SELECT id, name, key_prefix, created_at, last_used_at, is_active FROM api_keys WHERE uid = ? ORDER BY created_at DESC"
    )
    .bind(user.uid)
    .all();

  return Response.json({ keys: keys.results || [] });
}

// POST /api/developer/keys
export async function onRequestPost(context) {
  const { env, request } = context;

  const user = await requireDeveloper(request, env.DB);
  if (!user) {
    return Response.json({ error: "Developer plan required." }, { status: 403 });
  }

  const body = await request.json().catch(() => ({}));
  const name = String(body.name || "Default Key").slice(0, 50).trim() || "Default Key";

  // Enforce max active key limit
  const countRow = await env.DB
    .prepare("SELECT COUNT(*) as cnt FROM api_keys WHERE uid = ? AND is_active = 1")
    .bind(user.uid)
    .first();

  if ((countRow?.cnt || 0) >= MAX_ACTIVE_KEYS) {
    return Response.json(
      { error: `Maximum ${MAX_ACTIVE_KEYS} active API keys allowed. Revoke an existing key first.` },
      { status: 400 }
    );
  }

  // Generate key: mdh_ + 32 random hex chars = 36 chars total
  const keyBytes = new Uint8Array(16);
  crypto.getRandomValues(keyBytes);
  const rawKey = "mdh_" + Array.from(keyBytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  // Store only the prefix for display (never store the full key)
  const keyPrefix = rawKey.slice(0, 12) + "...";
  const keyHash = await hashKey(rawKey);

  const id = crypto.randomUUID().replace(/-/g, "");
  const now = Math.floor(Date.now() / 1000);

  await env.DB
    .prepare(
      "INSERT INTO api_keys (id, uid, name, key_prefix, key_hash, created_at, is_active) VALUES (?, ?, ?, ?, ?, ?, 1)"
    )
    .bind(id, user.uid, name, keyPrefix, keyHash, now)
    .run();

  // Return full key ONCE — it is never stored or shown again
  return Response.json({
    id,
    name,
    key: rawKey,
    key_prefix: keyPrefix,
    created_at: now,
    is_active: 1,
  });
}

// DELETE /api/developer/keys?id=xxx
export async function onRequestDelete(context) {
  const { env, request } = context;

  const url = new URL(request.url);
  const keyId = url.searchParams.get("id");

  if (!keyId) {
    return Response.json({ error: "id parameter required." }, { status: 400 });
  }

  const user = await requireDeveloper(request, env.DB);
  if (!user) {
    return Response.json({ error: "Developer plan required." }, { status: 403 });
  }

  // Soft-delete: mark as inactive, keep for audit trail
  const result = await env.DB
    .prepare("UPDATE api_keys SET is_active = 0 WHERE id = ? AND uid = ?")
    .bind(keyId, user.uid)
    .run();

  if ((result.meta?.changes ?? 0) === 0) {
    return Response.json({ error: "Key not found or already revoked." }, { status: 404 });
  }

  return Response.json({ success: true });
}
