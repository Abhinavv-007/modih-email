/**
 * GET /api/admin/messages/summary
 *
 * Message volume + composition breakdown for LaunchOps. Returns total
 * message count, OTP/auth split (from admin_events.is_otp), top sender
 * domains over the chosen window, and the last few messages received
 * (subject + from + inbox — never the body).
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

  const [total, rangeCount, otpCount, recent, topSenders] = await Promise.all([
    safeFirst(env, `SELECT COUNT(*) AS n FROM messages`),
    safeFirst(env, `SELECT COUNT(*) AS n FROM messages WHERE received_at >= ?`, since),
    safeFirst(
      env,
      `SELECT COUNT(*) AS n FROM admin_events WHERE event_type = 'message_received' AND is_otp = 1 AND created_at >= ?`,
      since,
    ),
    safeAll(
      env,
      `SELECT id, inbox_id, from_address, from_name, subject, received_at
       FROM messages ORDER BY received_at DESC LIMIT ?`,
      limit,
    ),
    safeAll(
      env,
      `SELECT
         CASE
           WHEN INSTR(from_address, '@') > 0
             THEN SUBSTR(from_address, INSTR(from_address, '@') + 1)
           ELSE from_address
         END AS domain,
         COUNT(*) AS n
       FROM messages
       WHERE received_at >= ?
       GROUP BY domain
       ORDER BY n DESC
       LIMIT 15`,
      since,
    ),
  ]);

  const inRange = rangeCount?.n ?? 0;
  const otpInRange = otpCount?.n ?? 0;

  return Response.json(
    {
      service: "modih-mail",
      generatedAt: now,
      range,
      counts: {
        total: total?.n ?? null,
        in_range: inRange,
        otp_in_range: otpInRange,
        otp_rate_pct: inRange > 0 ? Number(((otpInRange / inRange) * 100).toFixed(2)) : null,
      },
      top_sender_domains: topSenders.map((r) => ({ domain: r.domain, count: r.n })),
      recent: recent.map((r) => ({
        id: r.id,
        inbox_id: r.inbox_id,
        from: r.from_address,
        from_name: r.from_name,
        subject: r.subject,
        received_at: r.received_at,
      })),
      auth_via: auth.via,
    },
    { headers: { "cache-control": "private, no-store" } },
  );
}
