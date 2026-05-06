/**
 * GET /api/admin/api-keys/summary
 *
 * Per-key usage breakdown. Admin-only — never exposes key material, only
 * the key prefix (first ~12 chars, already shown to the owner) and
 * aggregate counts derived from api_usage. Default range is the last
 * 30 days.
 *
 * Response shape:
 *   {
 *     service, generatedAt, range,
 *     counts: { total, active, retired },
 *     keys: [{
 *       id, uid, name, key_prefix, monthly_create_limit, monthly_read_limit,
 *       is_active, created_at, last_used_at,
 *       usage: {
 *         total, success, errors, error_rate_pct,
 *         creates, reads, last_seen
 *       }
 *     }]
 *   }
 */
import { checkAdminAuth } from "../../../_admin-auth.js";

const RANGE_SECONDS = {
  "7d": 7 * 24 * 60 * 60,
  "30d": 30 * 24 * 60 * 60,
  "90d": 90 * 24 * 60 * 60,
  "365d": 365 * 24 * 60 * 60,
};

async function safeAll(env, sql, ...binds) {
  try {
    if (!env?.DB) return [];
    const stmt = env.DB.prepare(sql);
    const r = await (binds.length ? stmt.bind(...binds) : stmt).all();
    return r?.results ?? [];
  } catch {
    return [];
  }
}

async function safeFirst(env, sql, ...binds) {
  try {
    if (!env?.DB) return null;
    const stmt = env.DB.prepare(sql);
    return await (binds.length ? stmt.bind(...binds) : stmt).first();
  } catch {
    return null;
  }
}

export async function onRequestGet({ request, env }) {
  const auth = await checkAdminAuth(request, env);
  if (!auth.ok) return auth.response;

  const url = new URL(request.url);
  const rawRange = url.searchParams.get("range") || "30d";
  const range = RANGE_SECONDS[rawRange] || rawRange === "all" ? rawRange : "30d";
  const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit") || "100", 10) || 100, 1), 500);
  const now = Math.floor(Date.now() / 1000);
  const since = range === "all" ? 0 : now - (RANGE_SECONDS[range] || RANGE_SECONDS["30d"]);

  const [counts, keys, usage] = await Promise.all([
    safeFirst(
      env,
      `SELECT
         COUNT(*) AS total,
         SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) AS active,
         SUM(CASE WHEN is_active = 0 THEN 1 ELSE 0 END) AS retired
       FROM api_keys`,
    ),
    safeAll(
      env,
      `SELECT id, uid, name, key_prefix, monthly_create_limit, monthly_read_limit,
              is_active, created_at, last_used_at
       FROM api_keys
       ORDER BY COALESCE(last_used_at, 0) DESC, created_at DESC
       LIMIT ?`,
      limit,
    ),
    safeAll(
      env,
      `SELECT
         key_id,
         COUNT(*) AS total,
         SUM(CASE WHEN status_code IS NULL OR status_code < 400 THEN 1 ELSE 0 END) AS success,
         SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS errors,
         SUM(CASE WHEN action = 'inbox_create' THEN 1 ELSE 0 END) AS creates,
         SUM(CASE WHEN action = 'message_read' THEN 1 ELSE 0 END) AS reads,
         MAX(created_at) AS last_seen
       FROM api_usage
       WHERE created_at >= ? AND key_id IS NOT NULL
       GROUP BY key_id`,
      since,
    ),
  ]);

  const usageByKey = new Map();
  for (const u of usage) {
    usageByKey.set(u.key_id, {
      total: Number(u.total) || 0,
      success: Number(u.success) || 0,
      errors: Number(u.errors) || 0,
      creates: Number(u.creates) || 0,
      reads: Number(u.reads) || 0,
      last_seen: u.last_seen ?? null,
    });
  }

  const enriched = keys.map((k) => {
    const u = usageByKey.get(k.id) ?? { total: 0, success: 0, errors: 0, creates: 0, reads: 0, last_seen: null };
    return {
      id: k.id,
      uid: k.uid,
      name: k.name,
      key_prefix: k.key_prefix,
      monthly_create_limit: k.monthly_create_limit,
      monthly_read_limit: k.monthly_read_limit,
      is_active: !!k.is_active,
      created_at: k.created_at,
      last_used_at: k.last_used_at,
      usage: {
        ...u,
        error_rate_pct: u.total > 0 ? Number(((u.errors / u.total) * 100).toFixed(2)) : null,
      },
    };
  });

  return Response.json(
    {
      service: "modih-mail",
      generatedAt: now,
      range,
      counts: {
        total: counts?.total ?? null,
        active: counts?.active ?? null,
        retired: counts?.retired ?? null,
      },
      keys: enriched,
      auth_via: auth.via,
    },
    { headers: { "cache-control": "private, no-store" } },
  );
}
