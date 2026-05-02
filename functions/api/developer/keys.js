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
const PLAN_CREATE_LIMIT = 5000;
const PLAN_READ_LIMIT = 50000;

async function requireDeveloper(request, db) {
  const user = await getAuthUser(request);
  if (!user) return null;
  const row = await getCurrentPlanRow(db, user.uid);
  if (row?.plan !== "developer") return null;
  if (row.plan_expires_at && Number(row.plan_expires_at) <= Math.floor(Date.now() / 1000)) {
    db.prepare("UPDATE user_plans SET plan = 'free', updated_at = ?, plan_expires_at = NULL WHERE uid = ?")
      .bind(Math.floor(Date.now() / 1000), user.uid)
      .run()
      .catch(() => {});
    return null;
  }
  return user;
}

async function getCurrentPlanRow(db, uid) {
  try {
    return await db
      .prepare("SELECT plan, plan_expires_at FROM user_plans WHERE uid = ?")
      .bind(uid)
      .first();
  } catch (error) {
    if (!String(error?.message || "").includes("plan_expires_at")) throw error;
    return db.prepare("SELECT plan FROM user_plans WHERE uid = ?").bind(uid).first();
  }
}

function getMonthStart() {
  const now = new Date();
  return Math.floor(new Date(now.getFullYear(), now.getMonth(), 1).getTime() / 1000);
}

function normalizeLimit(value, fallback, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(0, Math.min(max, Math.floor(n)));
}

function normalizeKeyRow(row) {
  return {
    ...row,
    monthly_create_limit: normalizeLimit(row.monthly_create_limit, PLAN_CREATE_LIMIT, PLAN_CREATE_LIMIT),
    monthly_read_limit: normalizeLimit(row.monthly_read_limit, PLAN_READ_LIMIT, PLAN_READ_LIMIT),
  };
}

async function selectKeys(db, uid) {
  try {
    return await db
      .prepare(
        `SELECT id, name, key_prefix, monthly_create_limit, monthly_read_limit, created_at, last_used_at, is_active
         FROM api_keys
         WHERE uid = ?
         ORDER BY created_at DESC`
      )
      .bind(uid)
      .all();
  } catch (error) {
    if (!String(error?.message || "").includes("monthly_create_limit")) throw error;
    return db
      .prepare(
        `SELECT id, name, key_prefix, created_at, last_used_at, is_active
         FROM api_keys
         WHERE uid = ?
         ORDER BY created_at DESC`
      )
      .bind(uid)
      .all();
  }
}

async function selectKey(db, uid, keyId) {
  try {
    return await db
      .prepare(
        `SELECT id, name, key_prefix, monthly_create_limit, monthly_read_limit, created_at, last_used_at, is_active
         FROM api_keys
         WHERE id = ? AND uid = ?`
      )
      .bind(keyId, uid)
      .first();
  } catch (error) {
    if (!String(error?.message || "").includes("monthly_create_limit")) throw error;
    return db
      .prepare(
        `SELECT id, name, key_prefix, created_at, last_used_at, is_active
         FROM api_keys
         WHERE id = ? AND uid = ?`
      )
      .bind(keyId, uid)
      .first();
  }
}

async function getUsageByKey(db, uid, monthStart) {
  try {
    const usage = await db
      .prepare(
        `SELECT key_id, action, COUNT(*) as cnt
         FROM api_usage
         WHERE uid = ? AND key_id IS NOT NULL AND created_at >= ?
         GROUP BY key_id, action`
      )
      .bind(uid, monthStart)
      .all();

    const usageMap = new Map();
    for (const row of usage.results || []) {
      const current = usageMap.get(row.key_id) || { inbox_create: 0, message_read: 0 };
      current[row.action] = row.cnt || 0;
      usageMap.set(row.key_id, current);
    }
    return usageMap;
  } catch (error) {
    if (!String(error?.message || "").includes("key_id")) throw error;
    return new Map();
  }
}

async function getKeyUsage(db, uid, keyId, monthStart) {
  try {
    const rows = await db
      .prepare(
        `SELECT action, COUNT(*) as cnt
         FROM api_usage
         WHERE uid = ? AND key_id = ? AND created_at >= ?
         GROUP BY action`
      )
      .bind(uid, keyId, monthStart)
      .all();

    const usage = { inbox_create: 0, message_read: 0 };
    for (const row of rows.results || []) {
      usage[row.action] = row.cnt || 0;
    }
    return usage;
  } catch (error) {
    if (!String(error?.message || "").includes("key_id")) throw error;
    return { inbox_create: 0, message_read: 0 };
  }
}

async function getRecentUsage(db, uid, keyId) {
  try {
    const rows = await db
      .prepare(
        `SELECT action, endpoint, inbox_id, ip, status_code, created_at
         FROM api_usage
         WHERE uid = ? AND key_id = ?
         ORDER BY created_at DESC
         LIMIT 50`
      )
      .bind(uid, keyId)
      .all();
    return rows.results || [];
  } catch (error) {
    if (!String(error?.message || "").includes("key_id")) throw error;
    return [];
  }
}

// ── GET /api/developer/keys ──────────────────────────────────────────────────
export async function onRequestGet(context) {
  const { env, request } = context;

  const user = await requireDeveloper(request, env.DB);
  if (!user) {
    return err("FORBIDDEN", "Developer plan required.", 403);
  }

  const url = new URL(request.url);
  const keyId = url.searchParams.get("id");
  const monthStart = getMonthStart();

  if (keyId) {
    const key = await selectKey(env.DB, user.uid, keyId);
    if (!key) return err("KEY_NOT_FOUND", "API key not found.", 404);

    const normalized = normalizeKeyRow(key);
    const [usage, recent] = await Promise.all([
      getKeyUsage(env.DB, user.uid, keyId, monthStart),
      getRecentUsage(env.DB, user.uid, keyId),
    ]);

    return ok({
      key: {
        ...normalized,
        usage: {
          inbox_create: usage.inbox_create,
          message_read: usage.message_read,
          month_start: monthStart,
        },
        recent,
      },
    });
  }

  const keys = await selectKeys(env.DB, user.uid);
  const usageMap = await getUsageByKey(env.DB, user.uid, monthStart);
  const rows = (keys.results || []).map((row) => {
    const key = normalizeKeyRow(row);
    const usage = usageMap.get(key.id) || { inbox_create: 0, message_read: 0 };
    return {
      ...key,
      usage: {
        inbox_create: usage.inbox_create,
        message_read: usage.message_read,
        month_start: monthStart,
      },
    };
  });

  return ok({ keys: rows });
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
  const monthlyCreateLimit = normalizeLimit(
    body.monthly_create_limit ?? body.monthlyCreateLimit,
    PLAN_CREATE_LIMIT,
    PLAN_CREATE_LIMIT
  );
  const monthlyReadLimit = normalizeLimit(
    body.monthly_read_limit ?? body.monthlyReadLimit,
    PLAN_READ_LIMIT,
    PLAN_READ_LIMIT
  );

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
      `INSERT INTO api_keys
         (id, uid, name, key_prefix, key_hash, key_hash_peppered, monthly_create_limit, monthly_read_limit, created_at, is_active)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`
    )
    .bind(id, user.uid, name, keyPrefix, rawHash, pepperedHash, monthlyCreateLimit, monthlyReadLimit, now)
    .run();

  auditLog(env.DB, "api_key.created", {
    uid: user.uid,
    extra: { key_id: id, name, monthly_create_limit: monthlyCreateLimit, monthly_read_limit: monthlyReadLimit },
  });

  // Return full key ONCE — it is never stored and cannot be recovered
  return ok({
    id,
    name,
    key:        rawKey,       // shown once only
    key_prefix: keyPrefix,    // safe to display in dashboard
    monthly_create_limit: monthlyCreateLimit,
    monthly_read_limit: monthlyReadLimit,
    created_at: now,
    is_active:  true,
    usage: {
      inbox_create: 0,
      message_read: 0,
      month_start: getMonthStart(),
    },
  }, 201);
}

// ── PATCH /api/developer/keys?id=xxx ─────────────────────────────────────────
export async function onRequestPatch(context) {
  const { env, request } = context;

  const url = new URL(request.url);
  const keyId = url.searchParams.get("id");

  if (!keyId) {
    return err("VALIDATION_ERROR", "id parameter required.", 400);
  }

  const user = await requireDeveloper(request, env.DB);
  if (!user) {
    return err("FORBIDDEN", "Developer plan required.", 403);
  }

  const existing = await selectKey(env.DB, user.uid, keyId);
  if (!existing) return err("KEY_NOT_FOUND", "API key not found.", 404);

  const body = await request.json().catch(() => ({}));
  const monthlyCreateLimit = normalizeLimit(
    body.monthly_create_limit ?? body.monthlyCreateLimit,
    existing.monthly_create_limit ?? PLAN_CREATE_LIMIT,
    PLAN_CREATE_LIMIT
  );
  const monthlyReadLimit = normalizeLimit(
    body.monthly_read_limit ?? body.monthlyReadLimit,
    existing.monthly_read_limit ?? PLAN_READ_LIMIT,
    PLAN_READ_LIMIT
  );

  await env.DB
    .prepare("UPDATE api_keys SET monthly_create_limit = ?, monthly_read_limit = ? WHERE id = ? AND uid = ?")
    .bind(monthlyCreateLimit, monthlyReadLimit, keyId, user.uid)
    .run();

  auditLog(env.DB, "api_key.limits_updated", {
    uid: user.uid,
    extra: { key_id: keyId, monthly_create_limit: monthlyCreateLimit, monthly_read_limit: monthlyReadLimit },
  });

  return ok({
    id: keyId,
    monthly_create_limit: monthlyCreateLimit,
    monthly_read_limit: monthlyReadLimit,
  });
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
