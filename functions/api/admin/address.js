/**
 * GET /api/admin/address                 → list recent issued addresses
 * GET /api/admin/address?q=<search>       → search issued addresses
 * GET /api/admin/address?email=<address>  → full detail for one address
 *
 * Admin-only. Answers, in one place: which user created which address, when,
 * from where, whether it is still live or already expired, and every message
 * that address has received (current messages + historical receipts from
 * admin_events, which survive inbox cleanup).
 *
 * The permanent used_addresses ledger is the source of truth for "every
 * address ever issued", so expired-and-cleaned addresses remain visible here.
 * Never returns message bodies — only metadata (from / subject / time / OTP).
 */
import { checkAdminAuth } from "../../_admin-auth.js";

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

// Basic address shape guard — keeps the LIKE/= lookups tidy and bounded.
function normalizeAddress(raw) {
  const s = String(raw || "").trim().toLowerCase();
  if (s.length < 1 || s.length > 254) return "";
  if (!/^[a-z0-9._%+\-@]+$/.test(s)) return "";
  return s;
}

export async function onRequestGet({ request, env }) {
  const auth = await checkAdminAuth(request, env);
  if (!auth.ok) return auth.response;

  const url = new URL(request.url);
  const email = normalizeAddress(url.searchParams.get("email") || "");
  const now = Math.floor(Date.now() / 1000);

  if (email) {
    return Response.json(await addressDetail(env, email, now), {
      headers: { "cache-control": "private, no-store" },
    });
  }

  // ── List / search mode ─────────────────────────────────────────────────
  const q = normalizeAddress(url.searchParams.get("q") || "");
  const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit") || "50", 10) || 50, 1), 200);

  const rows = q
    ? await safeAll(
        env,
        `SELECT email, first_used_at, creator_uid, creator_ip
           FROM used_addresses WHERE email LIKE ? ORDER BY first_used_at DESC LIMIT ?`,
        `%${q}%`,
        limit,
      )
    : await safeAll(
        env,
        `SELECT email, first_used_at, creator_uid, creator_ip
           FROM used_addresses ORDER BY first_used_at DESC LIMIT ?`,
        limit,
      );

  const items = await Promise.all(
    rows.map(async (r) => {
      const live = await safeFirst(env, `SELECT creator_email, expires_at, IFNULL(reserved,0) AS reserved FROM inboxes WHERE email = ?`, r.email);
      const msgCount = await safeFirst(
        env,
        `SELECT COUNT(*) AS n FROM admin_events WHERE event_type = 'message_received' AND inbox_email = ?`,
        r.email,
      );
      return {
        email: r.email,
        first_used_at: r.first_used_at,
        creator_uid: r.creator_uid,
        creator_email: live?.creator_email || null,
        creator_ip: r.creator_ip,
        status: liveStatus(live, now),
        expires_at: live?.expires_at ?? null,
        reserved: live ? Boolean(live.reserved) : false,
        messages_received: msgCount?.n ?? 0,
      };
    }),
  );

  const total = await safeFirst(env, `SELECT COUNT(*) AS n FROM used_addresses`);

  return Response.json(
    {
      service: "modih-mail",
      generatedAt: now,
      total_addresses_ever_issued: total?.n ?? null,
      count: items.length,
      query: q || null,
      addresses: items,
      auth_via: auth.via,
    },
    { headers: { "cache-control": "private, no-store" } },
  );
}

function liveStatus(liveInbox, now) {
  if (!liveInbox) return "expired"; // in ledger but no live inbox row → cleaned up
  if (liveInbox.reserved) return "reserved";
  if (liveInbox.expires_at && liveInbox.expires_at > 0 && liveInbox.expires_at <= now) return "expiring";
  return "active";
}

async function addressDetail(env, email, now) {
  const ledger = await safeFirst(env, `SELECT email, first_used_at, creator_uid, creator_ip FROM used_addresses WHERE email = ?`, email);
  const live = await safeFirst(
    env,
    `SELECT id, email, creator_uid, creator_email, creator_ip, creator_plan, created_at, expires_at, IFNULL(reserved,0) AS reserved
       FROM inboxes WHERE email = ?`,
    email,
  );

  if (!ledger && !live) {
    return { service: "modih-mail", generatedAt: now, email, found: false };
  }

  // Current messages (only exist while the inbox is live).
  const currentMessages = live
    ? await safeAll(
        env,
        `SELECT id, from_address, from_name, subject, received_at
           FROM messages WHERE inbox_id = ? ORDER BY received_at DESC LIMIT 200`,
        live.id,
      )
    : [];

  // Historical receipts — survive inbox cleanup, so expired addresses still
  // show what they once received (metadata only, never bodies).
  const history = await safeAll(
    env,
    `SELECT subject, is_otp, created_at
       FROM admin_events
      WHERE event_type = 'message_received' AND inbox_email = ?
      ORDER BY created_at DESC LIMIT 200`,
    email,
  );

  return {
    service: "modih-mail",
    generatedAt: now,
    email,
    found: true,
    status: liveStatus(live, now),
    creator: {
      uid: live?.creator_uid || ledger?.creator_uid || null,
      email: live?.creator_email || null,
      ip: live?.creator_ip || ledger?.creator_ip || null,
      plan: live?.creator_plan || null,
    },
    lifecycle: {
      first_used_at: ledger?.first_used_at ?? live?.created_at ?? null,
      created_at: live?.created_at ?? null,
      expires_at: live?.expires_at ?? null,
      reserved: live ? Boolean(live.reserved) : false,
      inbox_id: live?.id ?? null,
    },
    messages_current: currentMessages.map((m) => ({
      id: m.id,
      from: m.from_address,
      from_name: m.from_name,
      subject: m.subject,
      received_at: m.received_at,
    })),
    messages_history: history.map((h) => ({
      subject: h.subject,
      is_otp: Boolean(h.is_otp),
      received_at: h.created_at,
    })),
  };
}
