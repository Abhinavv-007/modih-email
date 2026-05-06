/**
 * GET /api/admin/health
 *
 * Extended health check for LaunchOps. Unlike the public `/api/health`,
 * this one is gated by the admin secret and reports schema versions,
 * table counts, KV reachability, and a brief migration sanity check.
 */
import { checkAdminAuth } from "../../_admin-auth.js";

async function safeFirst(env, sql, ...binds) {
  try {
    if (!env?.DB) return null;
    const stmt = env.DB.prepare(sql);
    return await (binds.length ? stmt.bind(...binds) : stmt).first();
  } catch (e) {
    return { error: e?.message || "query failed" };
  }
}

async function checkKv(kv, key) {
  if (!kv) return { reachable: false };
  try {
    await kv.get(key);
    return { reachable: true };
  } catch (e) {
    return { reachable: false, error: e?.message || "kv read failed" };
  }
}

async function tableExists(env, name) {
  if (!env?.DB) return false;
  try {
    const r = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name = ?")
      .bind(name)
      .first();
    return !!r;
  } catch {
    return false;
  }
}

export async function onRequestGet({ request, env }) {
  const auth = await checkAdminAuth(request, env);
  if (!auth.ok) return auth.response;

  const startedAt = Date.now();

  const [
    inboxes,
    messages,
    apiKeys,
    apiUsage,
    adminEvents,
    auditLog,
    userPlans,
    rateLimitKv,
    sessionKv,
  ] = await Promise.all([
    safeFirst(env, `SELECT COUNT(*) AS n FROM inboxes`),
    safeFirst(env, `SELECT COUNT(*) AS n FROM messages`),
    safeFirst(env, `SELECT COUNT(*) AS n FROM api_keys`),
    safeFirst(env, `SELECT COUNT(*) AS n FROM api_usage`),
    safeFirst(env, `SELECT COUNT(*) AS n FROM admin_events`),
    safeFirst(env, `SELECT COUNT(*) AS n FROM audit_log`),
    safeFirst(env, `SELECT COUNT(*) AS n FROM user_plans`),
    checkKv(env.RATE_LIMIT, "__health_probe__"),
    checkKv(env.SESSIONS, "__health_probe__"),
  ]);

  const required = [
    "inboxes",
    "messages",
    "api_keys",
    "api_usage",
    "admin_events",
    "audit_log",
    "user_plans",
    "admin_passkeys",
    "visitor_actions",
  ];
  const tablePresence = Object.fromEntries(
    await Promise.all(required.map(async (name) => [name, await tableExists(env, name)])),
  );

  const missingTables = required.filter((t) => !tablePresence[t]);
  const ok = missingTables.length === 0;

  return Response.json(
    {
      ok,
      service: "modih-mail",
      ts: Math.floor(Date.now() / 1000),
      version: "phase-2-admin-api",
      latency_ms: Date.now() - startedAt,
      bindings: {
        db: !!env.DB,
        rate_limit_kv: rateLimitKv,
        session_kv: sessionKv,
        admin_secret_set: !!env.ADMIN_SECRET,
        token_pepper_set: !!env.TOKEN_PEPPER,
        api_key_pepper_set: !!env.API_KEY_PEPPER,
      },
      tables: {
        present: tablePresence,
        missing: missingTables,
      },
      counts: {
        inboxes: inboxes?.n ?? null,
        messages: messages?.n ?? null,
        api_keys: apiKeys?.n ?? null,
        api_usage: apiUsage?.n ?? null,
        admin_events: adminEvents?.n ?? null,
        audit_log: auditLog?.n ?? null,
        user_plans: userPlans?.n ?? null,
      },
      auth_via: auth.via,
    },
    {
      status: ok ? 200 : 503,
      headers: { "cache-control": "private, no-store" },
    },
  );
}
