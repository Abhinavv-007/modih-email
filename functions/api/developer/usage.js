// GET /api/developer/usage — Monthly API usage stats (requires Firebase auth + developer plan)

import { getAuthUser } from "../../_auth-helper.js";

const MONTHLY_LIMITS = {
  inbox_create: 5000,
  message_read: 50000,
};

function getMonthStart() {
  const now = new Date();
  return Math.floor(new Date(now.getFullYear(), now.getMonth(), 1).getTime() / 1000);
}

async function requireDeveloper(request, db) {
  const user = await getAuthUser(request);
  if (!user) return null;
  const row = await getCurrentPlanRow(db, user.uid);
  if (row?.plan !== "developer") return null;
  if (row.plan_expires_at && Number(row.plan_expires_at) <= Math.floor(Date.now() / 1000)) {
    db.prepare("UPDATE user_plans SET plan = 'free', updated_at = ?, plan_expires_at = NULL WHERE uid = ?")
      .bind(Math.floor(Date.now() / 1000), user.uid)
      .run()
      .catch(() => {});
    return null;
  }
  return user;
}

async function getCurrentPlanRow(db, uid) {
  try {
    return await db
      .prepare("SELECT plan, plan_expires_at FROM user_plans WHERE uid = ?")
      .bind(uid)
      .first();
  } catch (error) {
    if (!String(error?.message || "").includes("plan_expires_at")) throw error;
    return db.prepare("SELECT plan FROM user_plans WHERE uid = ?").bind(uid).first();
  }
}

export async function onRequestGet(context) {
  const { env, request } = context;

  const user = await requireDeveloper(request, env.DB);
  if (!user) {
    return Response.json({ error: "Developer plan required." }, { status: 403 });
  }

  const monthStart = getMonthStart();

  const [creates, reads] = await Promise.all([
    env.DB
      .prepare(
        "SELECT COUNT(*) as cnt FROM api_usage WHERE uid = ? AND action = 'inbox_create' AND created_at >= ?"
      )
      .bind(user.uid, monthStart)
      .first(),
    env.DB
      .prepare(
        "SELECT COUNT(*) as cnt FROM api_usage WHERE uid = ? AND action = 'message_read' AND created_at >= ?"
      )
      .bind(user.uid, monthStart)
      .first(),
  ]);

  const now = new Date();
  const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 1);

  return Response.json({
    month_start: monthStart,
    resets_at: Math.floor(nextMonth.getTime() / 1000),
    inbox_creates: {
      used: creates?.cnt || 0,
      limit: MONTHLY_LIMITS.inbox_create,
    },
    message_reads: {
      used: reads?.cnt || 0,
      limit: MONTHLY_LIMITS.message_read,
    },
  });
}
