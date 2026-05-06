/**
 * GET /api/admin/audit
 *
 * Returns recent rows from the structured `audit_log` table for LaunchOps
 * to render the security event trail. Filterable by event prefix, uid,
 * inbox_id, IP, or time range.
 *
 * Query params:
 *   range  — 7d | 30d (default) | 90d | 365d | all
 *   event  — exact match or prefix match if it ends with '%'
 *   uid    — exact match
 *   inbox  — inbox_id exact match
 *   ip     — exact match
 *   limit  — 1..500, default 100
 *
 * Audit rows never contain secret material, so it's safe to surface them
 * to the operator. We still gate behind `checkAdminAuth`.
 */
import { checkAdminAuth } from "../../_admin-auth.js";

const RANGE_SECONDS = {
  "7d": 7 * 24 * 60 * 60,
  "30d": 30 * 24 * 60 * 60,
  "90d": 90 * 24 * 60 * 60,
  "365d": 365 * 24 * 60 * 60,
};

async function safeAll(env, sql, binds) {
  try {
    if (!env?.DB) return [];
    const stmt = env.DB.prepare(sql);
    const r = await (binds?.length ? stmt.bind(...binds) : stmt).all();
    return r?.results ?? [];
  } catch {
    return [];
  }
}

async function safeFirst(env, sql, binds) {
  try {
    if (!env?.DB) return null;
    const stmt = env.DB.prepare(sql);
    return await (binds?.length ? stmt.bind(...binds) : stmt).first();
  } catch {
    return null;
  }
}

export async function onRequestGet({ request, env }) {
  const auth = await checkAdminAuth(request, env);
  if (!auth.ok) return auth.response;

  const url = new URL(request.url);
  const rawRange = url.searchParams.get("range") || "30d";
  const range = rawRange === "all" || RANGE_SECONDS[rawRange] ? rawRange : "30d";
  const event = (url.searchParams.get("event") || "").trim();
  const uid = (url.searchParams.get("uid") || "").trim();
  const inbox = (url.searchParams.get("inbox") || "").trim();
  const ip = (url.searchParams.get("ip") || "").trim();
  const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit") || "100", 10) || 100, 1), 500);
  const now = Math.floor(Date.now() / 1000);
  const since = range === "all" ? 0 : now - RANGE_SECONDS[range];

  const where = [];
  const binds = [];
  if (since > 0) {
    where.push("created_at >= ?");
    binds.push(since);
  }
  if (event) {
    if (event.endsWith("%")) {
      where.push("event LIKE ?");
      binds.push(event);
    } else {
      where.push("event = ?");
      binds.push(event);
    }
  }
  if (uid) {
    where.push("uid = ?");
    binds.push(uid);
  }
  if (inbox) {
    where.push("inbox_id = ?");
    binds.push(inbox);
  }
  if (ip) {
    where.push("ip = ?");
    binds.push(ip);
  }

  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const [rows, totals] = await Promise.all([
    safeAll(
      env,
      `SELECT id, event, uid, inbox_id, ip, details, created_at
       FROM audit_log ${whereSql}
       ORDER BY created_at DESC LIMIT ?`,
      [...binds, limit],
    ),
    safeAll(
      env,
      `SELECT event, COUNT(*) AS n FROM audit_log ${whereSql}
       GROUP BY event ORDER BY n DESC LIMIT 20`,
      binds,
    ),
  ]);

  const inWindow = await safeFirst(
    env,
    `SELECT COUNT(*) AS n FROM audit_log ${whereSql}`,
    binds,
  );

  return Response.json(
    {
      service: "modih-mail",
      generatedAt: now,
      range,
      filter: { event, uid, inbox, ip, limit },
      counts: {
        in_window: inWindow?.n ?? null,
      },
      top_events: totals.map((r) => ({ event: r.event, count: r.n })),
      rows: rows.map((r) => {
        let details = null;
        if (r.details) {
          try {
            details = JSON.parse(r.details);
          } catch {
            details = r.details;
          }
        }
        return {
          id: r.id,
          event: r.event,
          uid: r.uid,
          inbox_id: r.inbox_id,
          ip: r.ip,
          details,
          created_at: r.created_at,
        };
      }),
      auth_via: auth.via,
    },
    { headers: { "cache-control": "private, no-store" } },
  );
}
