/**
 * GET /api/public/summary
 *
 * Tiny aggregate stats for the lnch.in public landing. Everything here is
 * intentionally public-safe: total counts and 24h volumes only — never
 * per-user, per-key, or per-IP.
 *
 * The response is cacheable (60s s-maxage) and consumed by lnch.in's
 * `/api/public/projects` endpoint to render the modih card.
 */
function jsonResponse(data, init = {}) {
  return new Response(JSON.stringify(data), {
    ...init,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "public, max-age=30, s-maxage=60, stale-while-revalidate=300",
      ...(init.headers || {}),
    },
  });
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

export async function onRequestGet({ env }) {
  const nowSec = Math.floor(Date.now() / 1000);
  const since = nowSec - 24 * 60 * 60;

  // Each query is independently fault-tolerant — if one fails we still
  // return a usable object instead of a 500.
  const [users, plans, inboxesAll, inboxes24h, messagesAll, messages24h, apiReq24h, apiErr24h] = await Promise.all([
    safeFirst(env, "SELECT COUNT(*) AS n FROM user_plans"),
    safeFirst(
      env,
      "SELECT COUNT(*) AS n FROM user_plans WHERE plan IN ('pro','developer')",
    ),
    safeFirst(env, "SELECT COUNT(*) AS n FROM inboxes"),
    safeFirst(env, "SELECT COUNT(*) AS n FROM inboxes WHERE created_at >= ?", since),
    safeFirst(env, "SELECT COUNT(*) AS n FROM messages"),
    safeFirst(env, "SELECT COUNT(*) AS n FROM messages WHERE received_at >= ?", since),
    safeFirst(env, "SELECT COUNT(*) AS n FROM api_usage WHERE created_at >= ?", since),
    safeFirst(
      env,
      "SELECT COUNT(*) AS n FROM api_usage WHERE created_at >= ? AND status_code >= 400",
      since,
    ),
  ]);

  const apiReq = apiReq24h?.n ?? 0;
  const apiErr = apiErr24h?.n ?? 0;
  const errorRate = apiReq > 0 ? Number(((apiErr / apiReq) * 100).toFixed(2)) : null;

  return jsonResponse({
    service: "modih-mail",
    generatedAt: nowSec,
    counts: {
      users: users?.n ?? null,
      paid_users: plans?.n ?? null,
      inboxes: inboxesAll?.n ?? null,
      messages: messagesAll?.n ?? null,
    },
    last24h: {
      inboxes_created: inboxes24h?.n ?? null,
      messages_received: messages24h?.n ?? null,
      api_requests: apiReq,
      api_errors: apiErr,
      error_rate_pct: errorRate,
    },
  });
}
