/**
 * GET /api/admin/inboxes/summary
 *
 * Inbox-focused breakdown for LaunchOps. Returns total inbox count, split
 * by creator plan, expiring soon, and the last few created inboxes
 * (admin-only — includes UIDs and creator emails). Auth shared with the
 * rest of /api/admin/*.
 */
import { checkAdminAuth } from "../../../_admin-auth.js";

const RANGE_SECONDS = {
  "7d": 7 * 24 * 60 * 60,
  "30d": 30 * 24 * 60 * 60,
  "90d": 90 * 24 * 60 * 60,
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
  const range = RANGE_SECONDS[url.searchParams.get("range") || ""] ? url.searchParams.get("range") : "30d";
  const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit") || "25", 10) || 25, 1), 200);
  const now = Math.floor(Date.now() / 1000);
  const since = now - RANGE_SECONDS[range];

  const [total, rangeCount, expiringSoon, anonCount, recent, byPlan] = await Promise.all([
    safeFirst(env, `SELECT COUNT(*) AS n FROM inboxes`),
    safeFirst(env, `SELECT COUNT(*) AS n FROM inboxes WHERE created_at >= ?`, since),
    safeFirst(env, `SELECT COUNT(*) AS n FROM inboxes WHERE expires_at > 0 AND expires_at <= ?`, now + 60 * 60),
    safeFirst(env, `SELECT COUNT(*) AS n FROM inboxes WHERE creator_uid IS NULL OR creator_uid = ''`),
    safeAll(
      env,
      `SELECT id, email, creator_uid, creator_email, creator_plan, creator_ip, created_at, expires_at, token_version
       FROM inboxes ORDER BY created_at DESC LIMIT ?`,
      limit,
    ),
    safeAll(env, `SELECT COALESCE(creator_plan,'unknown') AS plan, COUNT(*) AS n FROM inboxes GROUP BY creator_plan ORDER BY n DESC`),
  ]);

  return Response.json(
    {
      service: "modih-mail",
      generatedAt: now,
      range,
      counts: {
        total: total?.n ?? null,
        in_range: rangeCount?.n ?? null,
        expiring_within_1h: expiringSoon?.n ?? null,
        anonymous: anonCount?.n ?? null,
      },
      plans: byPlan.map((r) => ({ plan: r.plan, count: r.n })),
      recent: recent.map((r) => ({
        id: r.id,
        email: r.email,
        creator_uid: r.creator_uid,
        creator_email: r.creator_email,
        creator_plan: r.creator_plan,
        creator_ip: r.creator_ip,
        token_version: r.token_version,
        created_at: r.created_at,
        expires_at: r.expires_at,
      })),
      auth_via: auth.via,
    },
    { headers: { "cache-control": "private, no-store" } },
  );
}
