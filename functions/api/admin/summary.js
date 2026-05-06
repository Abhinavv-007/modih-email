/**
 * GET /api/admin/summary
 *
 * One-shot aggregate read for the lnch.in LaunchOps "Modih" panel and any
 * other admin-only dashboard. Server-to-server: callers must present the
 * same admin credential as `/api/admin/users` (X-Admin-Secret header or
 * the admin_session cookie issued after a passkey assertion).
 *
 * Returns user / inbox / message / api-key counts, plan distribution,
 * 24h volumes, error rates, and the latest few admin events. Each query
 * is independently fault-tolerant — a missing table never 500s the whole
 * payload — so a freshly-migrated environment still gets a usable shape.
 *
 * Optional `?range=7d|30d|90d|365d|all` parameter (default 30d) controls
 * the trailing window for the per-range volume + error counts. The 24h
 * block is always present alongside the chosen range.
 */
import { checkAdminAuth } from "../../_admin-auth.js";

const RANGE_SECONDS = {
  "7d": 7 * 24 * 60 * 60,
  "30d": 30 * 24 * 60 * 60,
  "90d": 90 * 24 * 60 * 60,
  "365d": 365 * 24 * 60 * 60,
};

function normalizeRange(raw) {
  return raw && (raw === "all" || RANGE_SECONDS[raw]) ? raw : "30d";
}

function getSince(range, now) {
  return range === "all" ? 0 : now - RANGE_SECONDS[range];
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

export async function onRequestGet({ request, env }) {
  const auth = await checkAdminAuth(request, env);
  if (!auth.ok) return auth.response;

  const url = new URL(request.url);
  const range = normalizeRange(url.searchParams.get("range"));
  const now = Math.floor(Date.now() / 1000);
  const day = now - 24 * 60 * 60;
  const since = getSince(range, now);
  const sinceClause = (column) =>
    range === "all" ? `1=1` : `${column} >= ${since}`;

  // Run everything in parallel — each query is wrapped so one missing
  // column (e.g. on an environment that hasn't run a migration yet)
  // doesn't take the whole response down.
  const [
    userCount,
    paidUsers,
    planSplit,
    inboxesAll,
    inboxes24h,
    inboxesRange,
    messagesAll,
    messages24h,
    messagesRange,
    apiKeysActive,
    apiKeysCount,
    apiUsage24h,
    apiUsageRange,
    apiErrors24h,
    apiErrorsRange,
    recentAdminEvents,
    storageRow,
  ] = await Promise.all([
    safeFirst(env, `SELECT COUNT(*) AS n FROM user_plans`),
    safeFirst(env, `SELECT COUNT(*) AS n FROM user_plans WHERE plan IN ('pro','developer')`),
    safeAll(env, `SELECT plan, COUNT(*) AS n FROM user_plans GROUP BY plan ORDER BY n DESC`),
    safeFirst(env, `SELECT COUNT(*) AS n FROM inboxes`),
    safeFirst(env, `SELECT COUNT(*) AS n FROM inboxes WHERE created_at >= ?`, day),
    safeFirst(env, `SELECT COUNT(*) AS n FROM inboxes WHERE ${sinceClause("created_at")}`),
    safeFirst(env, `SELECT COUNT(*) AS n FROM messages`),
    safeFirst(env, `SELECT COUNT(*) AS n FROM messages WHERE received_at >= ?`, day),
    safeFirst(env, `SELECT COUNT(*) AS n FROM messages WHERE ${sinceClause("received_at")}`),
    safeFirst(env, `SELECT COUNT(*) AS n FROM api_keys WHERE is_active = 1`),
    safeFirst(env, `SELECT COUNT(*) AS n FROM api_keys`),
    safeFirst(env, `SELECT COUNT(*) AS n FROM api_usage WHERE created_at >= ?`, day),
    safeFirst(env, `SELECT COUNT(*) AS n FROM api_usage WHERE ${sinceClause("created_at")}`),
    safeFirst(env, `SELECT COUNT(*) AS n FROM api_usage WHERE created_at >= ? AND status_code >= 400`, day),
    safeFirst(env, `SELECT COUNT(*) AS n FROM api_usage WHERE ${sinceClause("created_at")} AND status_code >= 400`),
    safeAll(
      env,
      `SELECT id, event_type, uid, email, inbox_email, subject, is_otp, created_at
       FROM admin_events ORDER BY created_at DESC LIMIT 25`,
    ),
    // Storage size estimates — Cloudflare D1 doesn't expose disk usage
    // directly, but row counts for the heaviest tables are a reasonable
    // proxy for the dashboard.
    safeFirst(env, `SELECT
      (SELECT COUNT(*) FROM messages) AS messages_total,
      (SELECT COUNT(*) FROM inboxes)  AS inboxes_total,
      (SELECT COUNT(*) FROM admin_events) AS events_total
    `),
  ]);

  const usage24h = apiUsage24h?.n ?? 0;
  const errors24h = apiErrors24h?.n ?? 0;
  const usageRange = apiUsageRange?.n ?? 0;
  const errorsRange = apiErrorsRange?.n ?? 0;

  return Response.json(
    {
      service: "modih-mail",
      generatedAt: now,
      range,
      counts: {
        users: userCount?.n ?? null,
        paid_users: paidUsers?.n ?? null,
        inboxes: inboxesAll?.n ?? null,
        messages: messagesAll?.n ?? null,
        api_keys: apiKeysCount?.n ?? null,
        api_keys_active: apiKeysActive?.n ?? null,
        admin_events: storageRow?.events_total ?? null,
      },
      plans: planSplit.map((row) => ({ plan: row.plan, count: row.n })),
      last24h: {
        inboxes_created: inboxes24h?.n ?? null,
        messages_received: messages24h?.n ?? null,
        api_requests: usage24h,
        api_errors: errors24h,
        error_rate_pct: usage24h > 0 ? Number(((errors24h / usage24h) * 100).toFixed(2)) : null,
      },
      window: {
        range,
        inboxes_created: inboxesRange?.n ?? null,
        messages_received: messagesRange?.n ?? null,
        api_requests: usageRange,
        api_errors: errorsRange,
        error_rate_pct: usageRange > 0 ? Number(((errorsRange / usageRange) * 100).toFixed(2)) : null,
      },
      recent_events: recentAdminEvents.map((e) => ({
        id: e.id,
        type: e.event_type,
        uid: e.uid,
        email: e.email,
        inbox: e.inbox_email,
        subject: e.subject,
        is_otp: !!e.is_otp,
        ts: e.created_at,
      })),
      auth_via: auth.via,
    },
    {
      headers: {
        // Admin payload — never CDN-cache.
        "cache-control": "private, no-store",
      },
    },
  );
}
