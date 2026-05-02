// GET /api/admin/users - admin users + analytics (requires X-Admin-Secret)
// POST /api/admin/users - create/upsert a user record { uid, email, plan, duration }
// PATCH /api/admin/users - update plan { uid, plan, duration, custom_expires_at }
// DELETE /api/admin/users?uid=... - delete user subscription record

const VALID_PLANS = new Set(["free", "pro", "developer"]);
const VALID_DURATIONS = new Set(["1m", "3m", "1y", "lifetime", "custom"]);
const RANGE_SECONDS = {
  "7d": 7 * 24 * 60 * 60,
  "30d": 30 * 24 * 60 * 60,
  "90d": 90 * 24 * 60 * 60,
  "365d": 365 * 24 * 60 * 60,
};

function isAdmin(request, env) {
  const secret = request.headers.get("X-Admin-Secret");
  return secret && env.ADMIN_SECRET && secret === env.ADMIN_SECRET;
}

function adminUnauth() {
  return Response.json({ error: "Unauthorized" }, { status: 401 });
}

function jsonError(error, status = 400) {
  return Response.json({ error }, { status });
}

function isMissingColumn(error, column) {
  const message = String(error?.message || "");
  return message.includes(column) || message.includes("no such column");
}

function normalizeRange(raw) {
  return raw && (raw === "all" || RANGE_SECONDS[raw]) ? raw : "30d";
}

function getSince(range, now) {
  return range === "all" ? 0 : now - RANGE_SECONDS[range];
}

function normalizeCount(value) {
  return Number(value || 0);
}

async function expireExpiredPlans(db, now) {
  try {
    await db.prepare(
      `UPDATE user_plans
         SET plan = 'free', updated_at = ?, plan_expires_at = NULL
       WHERE plan != 'free'
         AND plan_expires_at IS NOT NULL
         AND plan_expires_at <= ?`
    ).bind(now, now).run();
  } catch (error) {
    if (!isMissingColumn(error, "plan_expires_at")) throw error;
  }
}

function addMonths(now, months) {
  const date = new Date(now * 1000);
  date.setUTCMonth(date.getUTCMonth() + months);
  return Math.floor(date.getTime() / 1000);
}

function addYears(now, years) {
  const date = new Date(now * 1000);
  date.setUTCFullYear(date.getUTCFullYear() + years);
  return Math.floor(date.getTime() / 1000);
}

function parseCustomExpiry(value, now) {
  if (value === null || value === undefined || value === "") return null;

  const numeric = Number(value);
  if (Number.isFinite(numeric)) {
    const seconds = numeric > 10_000_000_000 ? Math.floor(numeric / 1000) : Math.floor(numeric);
    return seconds > now ? seconds : null;
  }

  const asDate = new Date(String(value).includes("T") ? String(value) : `${value}T23:59:59Z`);
  if (Number.isNaN(asDate.getTime())) return null;
  const seconds = Math.floor(asDate.getTime() / 1000);
  return seconds > now ? seconds : null;
}

function getPlanWindow(plan, duration = "lifetime", customExpiresAt = null, now) {
  if (plan === "free") {
    return { planStartedAt: now, planExpiresAt: null, duration: "free" };
  }

  const normalizedDuration = VALID_DURATIONS.has(duration) ? duration : "lifetime";
  let planExpiresAt = null;

  if (normalizedDuration === "1m") planExpiresAt = addMonths(now, 1);
  if (normalizedDuration === "3m") planExpiresAt = addMonths(now, 3);
  if (normalizedDuration === "1y") planExpiresAt = addYears(now, 1);
  if (normalizedDuration === "custom") {
    planExpiresAt = parseCustomExpiry(customExpiresAt, now);
    if (!planExpiresAt) {
      throw new Error("Custom expiry must be a future date or timestamp.");
    }
  }

  return { planStartedAt: now, planExpiresAt, duration: normalizedDuration };
}

async function selectUserPlans(db, filter, emailSearch) {
  const conditions = [];
  const bindings = [];

  if (filter === "subscribed") conditions.push("plan != 'free'");
  if (emailSearch) {
    conditions.push("(email LIKE ? OR uid LIKE ?)");
    bindings.push(`%${emailSearch}%`, `%${emailSearch}%`);
  }

  const where = conditions.length ? ` WHERE ${conditions.join(" AND ")}` : "";
  const query = `
    SELECT uid, email, plan, created_at, updated_at, plan_started_at, plan_expires_at, plan_source
    FROM user_plans
    ${where}
    ORDER BY created_at DESC
    LIMIT 500
  `;

  try {
    let stmt = db.prepare(query);
    if (bindings.length) stmt = stmt.bind(...bindings);
    const rows = await stmt.all();
    return rows.results || [];
  } catch (error) {
    if (!isMissingColumn(error, "plan_expires_at")) throw error;
    let fallback = "SELECT uid, email, plan, created_at, updated_at FROM user_plans";
    if (where) fallback += where;
    fallback += " ORDER BY created_at DESC LIMIT 500";
    let stmt = db.prepare(fallback);
    if (bindings.length) stmt = stmt.bind(...bindings);
    const rows = await stmt.all();
    return (rows.results || []).map((row) => ({
      ...row,
      plan_started_at: null,
      plan_expires_at: null,
      plan_source: null,
    }));
  }
}

async function safeAll(db, sql, bindings = [], fallback = []) {
  try {
    let stmt = db.prepare(sql);
    if (bindings.length) stmt = stmt.bind(...bindings);
    const rows = await stmt.all();
    return rows.results || [];
  } catch (error) {
    if (
      isMissingColumn(error, "creator_uid") ||
      isMissingColumn(error, "api_usage") ||
      isMissingColumn(error, "admin_events") ||
      isMissingColumn(error, "key_id") ||
      isMissingColumn(error, "status_code")
    ) {
      return fallback;
    }
    throw error;
  }
}

async function safeFirst(db, sql, bindings = {}, fallback = {}) {
  try {
    const bindValues = Array.isArray(bindings) ? bindings : [];
    let stmt = db.prepare(sql);
    if (bindValues.length) stmt = stmt.bind(...bindValues);
    return await stmt.first() || fallback;
  } catch (error) {
    if (
      isMissingColumn(error, "creator_uid") ||
      isMissingColumn(error, "api_usage") ||
      isMissingColumn(error, "api_keys") ||
      isMissingColumn(error, "admin_events") ||
      isMissingColumn(error, "plan_expires_at")
    ) {
      return fallback;
    }
    throw error;
  }
}

async function adminEventsAvailable(db) {
  try {
    await db.prepare("SELECT id FROM admin_events LIMIT 1").all();
    return true;
  } catch (error) {
    if (isMissingColumn(error, "admin_events")) return false;
    throw error;
  }
}

function toMap(rows, key, defaults = {}) {
  const map = new Map();
  for (const row of rows) {
    map.set(row[key], { ...defaults, ...row });
  }
  return map;
}

async function getUserRows(db, { filter, emailSearch, since, useEvents }) {
  const users = await selectUserPlans(db, filter, emailSearch);

  const [inboxRows, messageRows, apiRows, authRows] = await Promise.all([
    useEvents
      ? safeAll(db, `
          SELECT uid, COUNT(*) AS inbox_count, MAX(created_at) AS last_inbox_at
          FROM admin_events
          WHERE event_type = 'inbox_created' AND uid IS NOT NULL AND uid != '' AND created_at >= ?
          GROUP BY uid
        `, [since])
      : safeAll(db, `
          SELECT creator_uid AS uid, COUNT(*) AS inbox_count, MAX(created_at) AS last_inbox_at
          FROM inboxes
          WHERE creator_uid IS NOT NULL AND creator_uid != '' AND created_at >= ?
          GROUP BY creator_uid
        `, [since]),
    useEvents
      ? safeAll(db, `
          SELECT uid, COUNT(*) AS message_count, MAX(created_at) AS last_message_at
          FROM admin_events
          WHERE event_type = 'message_received' AND uid IS NOT NULL AND uid != '' AND created_at >= ?
          GROUP BY uid
        `, [since])
      : safeAll(db, `
          SELECT i.creator_uid AS uid, COUNT(m.id) AS message_count, MAX(m.received_at) AS last_message_at
          FROM messages m
          JOIN inboxes i ON i.id = m.inbox_id
          WHERE i.creator_uid IS NOT NULL AND i.creator_uid != '' AND m.received_at >= ?
          GROUP BY i.creator_uid
        `, [since]),
    safeAll(db, `
      SELECT uid, COUNT(*) AS api_count, MAX(created_at) AS last_api_at
      FROM api_usage
      WHERE created_at >= ?
      GROUP BY uid
    `, [since]),
    useEvents
      ? safeAll(db, `
          SELECT uid, ip, created_at
          FROM admin_events
          WHERE event_type = 'auth_seen'
            AND uid IS NOT NULL
            AND uid != ''
            AND created_at >= ?
          ORDER BY created_at DESC
          LIMIT 2000
        `, [since])
      : [],
  ]);

  const inboxMap = toMap(inboxRows, "uid", { inbox_count: 0, last_inbox_at: null });
  const messageMap = toMap(messageRows, "uid", { message_count: 0, last_message_at: null });
  const apiMap = toMap(apiRows, "uid", { api_count: 0, last_api_at: null });
  const authMap = new Map();
  const ipSets = new Map();
  for (const row of authRows) {
    if (!row.uid) continue;
    if (!authMap.has(row.uid)) {
      authMap.set(row.uid, { last_ip: row.ip || "", last_seen_at: row.created_at || null });
    }
    if (!ipSets.has(row.uid)) ipSets.set(row.uid, new Set());
    if (row.ip) ipSets.get(row.uid).add(row.ip);
  }

  const enriched = users.map((user) => {
    const inbox = inboxMap.get(user.uid) || {};
    const messages = messageMap.get(user.uid) || {};
    const api = apiMap.get(user.uid) || {};
    const auth = authMap.get(user.uid) || {};
    const lastActivityAt = Math.max(
      Number(inbox.last_inbox_at || 0),
      Number(messages.last_message_at || 0),
      Number(api.last_api_at || 0),
      Number(auth.last_seen_at || 0),
      Number(user.updated_at || 0)
    ) || null;

    return {
      ...user,
      type: "user",
      inbox_count: normalizeCount(inbox.inbox_count),
      message_count: normalizeCount(messages.message_count),
      api_count: normalizeCount(api.api_count),
      last_ip: auth.last_ip || "",
      last_seen_at: auth.last_seen_at || null,
      ip_count: ipSets.get(user.uid)?.size || 0,
      last_inbox_at: inbox.last_inbox_at || null,
      last_message_at: messages.last_message_at || null,
      last_api_at: api.last_api_at || null,
      last_activity_at: lastActivityAt,
    };
  });

  if (filter === "subscribed") return enriched;

  const search = (emailSearch || "").trim().toLowerCase();
  if (search && !("anonymous not signed up guest visitor".includes(search))) {
    return enriched;
  }

  const anonymousInboxes = useEvents
    ? await safeAll(db, `
        SELECT anon_id, creator_ip, creator_token, COUNT(*) AS inbox_count, MAX(created_at) AS last_inbox_at
        FROM (
          SELECT
            COALESCE(NULLIF(browser_token, ''), NULLIF(ip, ''), 'anonymous') AS anon_id,
            ip AS creator_ip,
            browser_token AS creator_token,
            created_at
          FROM admin_events
          WHERE event_type = 'inbox_created' AND (uid IS NULL OR uid = '') AND created_at >= ?
        )
        GROUP BY anon_id
        ORDER BY last_inbox_at DESC
        LIMIT 100
      `, [since])
    : await safeAll(db, `
        SELECT anon_id, creator_ip, creator_token, COUNT(*) AS inbox_count, MAX(created_at) AS last_inbox_at
        FROM (
          SELECT
            COALESCE(NULLIF(creator_token, ''), NULLIF(creator_ip, ''), 'anonymous') AS anon_id,
            creator_ip,
            creator_token,
            created_at
          FROM inboxes
          WHERE (creator_uid IS NULL OR creator_uid = '') AND created_at >= ?
        )
        GROUP BY anon_id
        ORDER BY last_inbox_at DESC
        LIMIT 100
      `, [since]);

  const anonymousMessages = useEvents
    ? await safeAll(db, `
        SELECT anon_id, COUNT(*) AS message_count, MAX(created_at) AS last_message_at
        FROM (
          SELECT
            COALESCE(NULLIF(browser_token, ''), NULLIF(ip, ''), 'anonymous') AS anon_id,
            created_at
          FROM admin_events
          WHERE event_type = 'message_received' AND (uid IS NULL OR uid = '') AND created_at >= ?
        )
        GROUP BY anon_id
      `, [since])
    : await safeAll(db, `
        SELECT anon_id, COUNT(id) AS message_count, MAX(received_at) AS last_message_at
        FROM (
          SELECT
            m.id,
            m.received_at,
            COALESCE(NULLIF(i.creator_token, ''), NULLIF(i.creator_ip, ''), 'anonymous') AS anon_id
          FROM messages m
          JOIN inboxes i ON i.id = m.inbox_id
          WHERE (i.creator_uid IS NULL OR i.creator_uid = '') AND m.received_at >= ?
        )
        GROUP BY anon_id
      `, [since]);
  const anonymousMessageMap = toMap(anonymousMessages, "anon_id", { message_count: 0, last_message_at: null });

  const anonymousRows = anonymousInboxes.map((row) => {
    const messageStats = anonymousMessageMap.get(row.anon_id) || {};
    const lastActivityAt = Math.max(
      Number(row.last_inbox_at || 0),
      Number(messageStats.last_message_at || 0)
    ) || null;
    return {
      uid: `anonymous:${row.anon_id}`,
      email: "Anonymous / not signed up",
      plan: "anonymous",
      type: "anonymous",
      created_at: row.last_inbox_at || null,
      updated_at: row.last_inbox_at || null,
      plan_started_at: null,
      plan_expires_at: null,
      plan_source: null,
      creator_ip: row.creator_ip || "",
      creator_token: row.creator_token || "",
      inbox_count: normalizeCount(row.inbox_count),
      message_count: normalizeCount(messageStats.message_count),
      api_count: 0,
      last_inbox_at: row.last_inbox_at || null,
      last_message_at: messageStats.last_message_at || null,
      last_api_at: null,
      last_activity_at: lastActivityAt,
    };
  });

  return [...enriched, ...anonymousRows].sort((a, b) => (b.last_activity_at || 0) - (a.last_activity_at || 0));
}

async function getStats(db, since, useEvents) {
  const inboxStatsQuery = useEvents
    ? `
      SELECT
        SUM(CASE WHEN event_type = 'inbox_created' THEN 1 ELSE 0 END) AS total_inboxes,
        SUM(CASE WHEN event_type = 'inbox_created' AND uid IS NOT NULL AND uid != '' THEN 1 ELSE 0 END) AS signed_in_inboxes,
        SUM(CASE WHEN event_type = 'inbox_created' AND (uid IS NULL OR uid = '') THEN 1 ELSE 0 END) AS anonymous_inboxes
      FROM admin_events
      WHERE created_at >= ?
    `
    : `
      SELECT
        COUNT(*) AS total_inboxes,
        SUM(CASE WHEN creator_uid IS NOT NULL AND creator_uid != '' THEN 1 ELSE 0 END) AS signed_in_inboxes,
        SUM(CASE WHEN creator_uid IS NULL OR creator_uid = '' THEN 1 ELSE 0 END) AS anonymous_inboxes
      FROM inboxes
      WHERE created_at >= ?
    `;

  const messageStatsQuery = useEvents
    ? `
      SELECT
        SUM(CASE WHEN event_type = 'message_received' THEN 1 ELSE 0 END) AS total_messages,
        SUM(CASE WHEN event_type = 'message_received' AND is_otp = 1 THEN 1 ELSE 0 END) AS otp_messages
      FROM admin_events
      WHERE created_at >= ?
    `
    : `
      SELECT
        COUNT(*) AS total_messages,
        SUM(CASE
          WHEN LOWER(COALESCE(subject, '')) LIKE '%otp%'
            OR LOWER(COALESCE(subject, '')) LIKE '%verification%'
            OR LOWER(COALESCE(subject, '')) LIKE '%code%'
            OR LOWER(COALESCE(body_text, '')) LIKE '%otp%'
            OR LOWER(COALESCE(body_text, '')) LIKE '%verification%'
            OR LOWER(COALESCE(body_text, '')) LIKE '%code%'
            OR LOWER(COALESCE(body_html, '')) LIKE '%otp%'
            OR LOWER(COALESCE(body_html, '')) LIKE '%verification%'
            OR LOWER(COALESCE(body_html, '')) LIKE '%code%'
          THEN 1 ELSE 0 END
        ) AS otp_messages
      FROM messages
      WHERE received_at >= ?
    `;

  const apiStatsQuery = `
    SELECT
      COUNT(*) AS total_api_calls,
      SUM(CASE WHEN action = 'inbox_create' THEN 1 ELSE 0 END) AS api_inbox_creates,
      SUM(CASE WHEN action = 'message_read' THEN 1 ELSE 0 END) AS api_message_reads
    FROM api_usage
    WHERE created_at >= ?
  `;

  const [planRows, totalUsers, inboxStats, messageStats, apiStats, keyStats] = await Promise.all([
    safeAll(db, "SELECT plan, COUNT(*) AS count FROM user_plans GROUP BY plan"),
    safeFirst(db, "SELECT COUNT(*) AS total_users FROM user_plans", [], { total_users: 0 }),
    safeFirst(db, inboxStatsQuery, [since], { total_inboxes: 0, signed_in_inboxes: 0, anonymous_inboxes: 0 }),
    safeFirst(db, messageStatsQuery, [since], { total_messages: 0, otp_messages: 0 }),
    safeFirst(db, apiStatsQuery, [since], { total_api_calls: 0, api_inbox_creates: 0, api_message_reads: 0 }),
    safeFirst(db, "SELECT COUNT(*) AS active_api_keys FROM api_keys WHERE is_active = 1", [], { active_api_keys: 0 }),
  ]);

  const plans = {};
  for (const row of planRows) plans[row.plan] = normalizeCount(row.count);

  return {
    total: normalizeCount(totalUsers.total_users),
    free: plans.free || 0,
    pro: plans.pro || 0,
    developer: plans.developer || 0,
    active_paid: (plans.pro || 0) + (plans.developer || 0),
    total_inboxes: normalizeCount(inboxStats.total_inboxes),
    signed_in_inboxes: normalizeCount(inboxStats.signed_in_inboxes),
    anonymous_inboxes: normalizeCount(inboxStats.anonymous_inboxes),
    total_messages: normalizeCount(messageStats.total_messages),
    otp_messages: normalizeCount(messageStats.otp_messages),
    total_api_calls: normalizeCount(apiStats.total_api_calls),
    api_inbox_creates: normalizeCount(apiStats.api_inbox_creates),
    api_message_reads: normalizeCount(apiStats.api_message_reads),
    active_api_keys: normalizeCount(keyStats.active_api_keys),
  };
}

function normalizeActor(row) {
  if (row.creator_uid) {
    return row.creator_email || row.email || row.uid || row.creator_uid;
  }
  return "Anonymous / not signed up";
}

async function getActivity(db, since, useEvents) {
  const inboxActivityQuery = useEvents
    ? `
      SELECT
        inbox_id AS id,
        inbox_email AS email,
        uid AS creator_uid,
        email AS creator_email,
        ip AS creator_ip,
        browser_token AS creator_token,
        NULL AS creator_plan,
        created_at
      FROM admin_events
      WHERE event_type = 'inbox_created' AND created_at >= ?
      ORDER BY created_at DESC
      LIMIT 80
    `
    : `
      SELECT id, email, creator_uid, creator_email, creator_ip, creator_token, creator_plan, created_at
      FROM inboxes
      WHERE created_at >= ?
      ORDER BY created_at DESC
      LIMIT 80
    `;

  const messageActivityQuery = useEvents
    ? `
      SELECT
        id,
        inbox_id,
        inbox_email,
        uid AS creator_uid,
        email AS creator_email,
        ip AS creator_ip,
        browser_token AS creator_token,
        NULL AS from_address,
        subject,
        created_at AS received_at
      FROM admin_events
      WHERE event_type = 'message_received' AND created_at >= ?
      ORDER BY created_at DESC
      LIMIT 80
    `
    : `
      SELECT
        m.id,
        m.inbox_id,
        i.email AS inbox_email,
        i.creator_uid,
        i.creator_email,
        i.creator_ip,
        i.creator_token,
        m.from_address,
        m.subject,
        m.received_at
      FROM messages m
      LEFT JOIN inboxes i ON i.id = m.inbox_id
      WHERE m.received_at >= ?
      ORDER BY m.received_at DESC
      LIMIT 80
    `;

  const apiActivityQuery = `
    SELECT
      a.uid,
      u.email,
      a.key_id,
      a.action,
      a.endpoint,
      a.inbox_id,
      a.ip,
      a.status_code,
      a.created_at
    FROM api_usage a
    LEFT JOIN user_plans u ON u.uid = a.uid
    WHERE a.created_at >= ?
    ORDER BY a.created_at DESC
    LIMIT 80
  `;

  const loginActivityQuery = `
    SELECT
      e.uid,
      u.email,
      e.ip,
      e.metadata,
      e.created_at
    FROM admin_events e
    LEFT JOIN user_plans u ON u.uid = e.uid
    WHERE e.event_type = 'auth_seen' AND e.created_at >= ?
    ORDER BY e.created_at DESC
    LIMIT 80
  `;

  const [inboxes, messages, api, logins] = await Promise.all([
    safeAll(db, inboxActivityQuery, [since]),
    safeAll(db, messageActivityQuery, [since]),
    safeAll(db, apiActivityQuery, [since]),
    useEvents ? safeAll(db, loginActivityQuery, [since]) : [],
  ]);

  return {
    inboxes: inboxes.map((row) => ({ ...row, actor: normalizeActor(row) })),
    messages: messages.map((row) => ({ ...row, actor: normalizeActor(row) })),
    api: api.map((row) => ({ ...row, actor: row.email || row.uid || "Unknown user" })),
    logins: logins.map((row) => ({ ...row, actor: row.email || row.uid || "Unknown user" })),
  };
}

export async function onRequestGet(context) {
  const { env, request } = context;
  if (!isAdmin(request, env)) return adminUnauth();

  const url = new URL(request.url);
  const filter = url.searchParams.get("filter") || "all";
  const emailSearch = url.searchParams.get("email") || "";
  const range = normalizeRange(url.searchParams.get("range"));
  const now = Math.floor(Date.now() / 1000);
  const since = getSince(range, now);

  try {
    await expireExpiredPlans(env.DB, now);
    const useEvents = await adminEventsAvailable(env.DB);

    const [users, stats, activity] = await Promise.all([
      getUserRows(env.DB, { filter, emailSearch, since, useEvents }),
      getStats(env.DB, since, useEvents),
      getActivity(env.DB, since, useEvents),
    ]);

    return Response.json({
      users,
      stats,
      activity,
      range: { key: range, since, now },
      analytics_source: useEvents ? "admin_events" : "live_tables",
    });
  } catch (e) {
    console.error("Admin users list error:", e);
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function onRequestPost(context) {
  const { env, request } = context;
  if (!isAdmin(request, env)) return adminUnauth();

  try {
    const body = await request.json();
    const uid = String(body.uid || "").trim();
    const email = String(body.email || "").trim();
    const plan = body.plan || "free";
    const duration = body.duration || "lifetime";

    if (!uid) return jsonError("uid is required");
    if (!VALID_PLANS.has(plan)) return jsonError("Invalid plan. Choose: free, pro, developer");

    const now = Math.floor(Date.now() / 1000);
    const window = getPlanWindow(plan, duration, body.custom_expires_at ?? body.expires_at, now);

    const existing = await env.DB.prepare("SELECT uid FROM user_plans WHERE uid = ?").bind(uid).first();
    if (existing) {
      return Response.json(
        { error: "A user with this UID already exists. Use the plan controls to change their plan." },
        { status: 409 }
      );
    }

    try {
      await env.DB.prepare(
        `INSERT INTO user_plans
           (uid, email, plan, plan_started_at, plan_expires_at, plan_source, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, 'admin', ?, ?)`
      ).bind(uid, email, plan, window.planStartedAt, window.planExpiresAt, now, now).run();
    } catch (error) {
      if (!isMissingColumn(error, "plan_expires_at")) throw error;
      await env.DB.prepare(
        "INSERT INTO user_plans (uid, email, plan, created_at, updated_at) VALUES (?, ?, ?, ?, ?)"
      ).bind(uid, email, plan, now, now).run();
    }

    return Response.json({
      success: true,
      uid,
      email,
      plan,
      duration: window.duration,
      plan_expires_at: window.planExpiresAt,
    }, { status: 201 });
  } catch (e) {
    if (String(e?.message || "").includes("Custom expiry")) return jsonError(e.message);
    console.error("Admin create user error:", e);
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function onRequestPatch(context) {
  const { env, request } = context;
  if (!isAdmin(request, env)) return adminUnauth();

  try {
    const body = await request.json();
    const uid = String(body.uid || "").trim();
    const plan = body.plan;
    const duration = body.duration || "lifetime";

    if (!uid || !plan) return jsonError("uid and plan required");
    if (uid.startsWith("anonymous:")) return jsonError("Anonymous activity rows cannot be upgraded.");
    if (!VALID_PLANS.has(plan)) return jsonError("Invalid plan. Choose: free, pro, developer");

    const existing = await env.DB.prepare("SELECT uid FROM user_plans WHERE uid = ?").bind(uid).first();
    if (!existing) return Response.json({ error: "User not found" }, { status: 404 });

    const now = Math.floor(Date.now() / 1000);
    const window = getPlanWindow(plan, duration, body.custom_expires_at ?? body.expires_at, now);

    try {
      await env.DB.prepare(
        `UPDATE user_plans
           SET plan = ?, plan_started_at = ?, plan_expires_at = ?, plan_source = 'admin', updated_at = ?
         WHERE uid = ?`
      ).bind(plan, window.planStartedAt, window.planExpiresAt, now, uid).run();
    } catch (error) {
      if (!isMissingColumn(error, "plan_expires_at")) throw error;
      await env.DB.prepare("UPDATE user_plans SET plan = ?, updated_at = ? WHERE uid = ?")
        .bind(plan, now, uid)
        .run();
    }

    return Response.json({
      success: true,
      uid,
      plan,
      duration: window.duration,
      plan_expires_at: window.planExpiresAt,
    });
  } catch (e) {
    if (String(e?.message || "").includes("Custom expiry")) return jsonError(e.message);
    console.error("Admin update plan error:", e);
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function onRequestDelete(context) {
  const { env, request } = context;
  if (!isAdmin(request, env)) return adminUnauth();

  const url = new URL(request.url);
  const uid = url.searchParams.get("uid");
  if (!uid) return jsonError("uid parameter required");
  if (uid.startsWith("anonymous:")) return jsonError("Anonymous activity rows are not user records.");

  try {
    await env.DB.prepare("DELETE FROM user_plans WHERE uid = ?").bind(uid).run();
    return Response.json({ success: true, message: "User record deleted." });
  } catch (e) {
    console.error("Admin delete user error:", e);
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}
