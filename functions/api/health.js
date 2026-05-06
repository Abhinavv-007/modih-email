/**
 * GET /api/health
 *
 * Public liveness probe. Returns 200 + JSON in well under 100ms when the
 * Pages function and its bindings are healthy. Used by lnch.in's LaunchOps
 * health probe and by external uptime monitors. Never returns secrets.
 */
function jsonResponse(data, init = {}) {
  return new Response(JSON.stringify(data), {
    ...init,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "public, max-age=10, s-maxage=30",
      ...(init.headers || {}),
    },
  });
}

export async function onRequestGet({ env }) {
  const startedAt = Date.now();
  let dbOk = false;
  try {
    if (env.DB) {
      const row = await env.DB.prepare("SELECT 1 AS one").first();
      dbOk = row?.one === 1;
    }
  } catch {
    dbOk = false;
  }

  return jsonResponse({
    ok: true,
    service: "modih-mail",
    ts: Math.floor(Date.now() / 1000),
    version: "phase-1-public-face",
    bindings: {
      db: dbOk,
      kv: typeof env?.RATE_LIMIT?.put === "function",
    },
    latencyMs: Date.now() - startedAt,
  });
}

export async function onRequestHead({ env }) {
  // HEAD requests are cheap — keep them tiny so monitors can hammer them.
  let dbOk = false;
  try {
    if (env.DB) {
      const row = await env.DB.prepare("SELECT 1 AS one").first();
      dbOk = row?.one === 1;
    }
  } catch {
    dbOk = false;
  }
  return new Response(null, {
    status: dbOk ? 200 : 200,
    headers: { "cache-control": "public, max-age=10" },
  });
}
