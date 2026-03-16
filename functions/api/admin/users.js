// GET /api/admin/users — list all users (requires X-Admin-Secret)
// PATCH /api/admin/users — update plan { uid, plan }
// DELETE /api/admin/users?uid=... — delete user record

function isAdmin(request, env) {
  const secret = request.headers.get("X-Admin-Secret");
  return secret && env.ADMIN_SECRET && secret === env.ADMIN_SECRET;
}

function adminUnauth() {
  return Response.json({ error: "Unauthorized" }, { status: 401 });
}

export async function onRequestGet(context) {
  const { env, request } = context;
  if (!isAdmin(request, env)) return adminUnauth();

  const url = new URL(request.url);
  const filter = url.searchParams.get("filter"); // "subscribed"
  const emailSearch = url.searchParams.get("email");

  try {
    let query = "SELECT uid, email, plan, created_at, updated_at FROM user_plans";
    const bindings = [];

    const conditions = [];
    if (filter === "subscribed") {
      conditions.push("plan != 'free'");
    }
    if (emailSearch) {
      conditions.push("email LIKE ?");
      bindings.push(`%${emailSearch}%`);
    }
    if (conditions.length > 0) {
      query += " WHERE " + conditions.join(" AND ");
    }
    query += " ORDER BY created_at DESC LIMIT 500";

    let stmt = env.DB.prepare(query);
    if (bindings.length > 0) {
      stmt = stmt.bind(...bindings);
    }

    const results = await stmt.all();

    // Summary stats
    const statsResult = await env.DB.prepare(
      "SELECT plan, COUNT(*) as count FROM user_plans GROUP BY plan"
    ).all();
    const stats = {};
    (statsResult.results || []).forEach(row => { stats[row.plan] = row.count; });

    return Response.json({
      users: results.results || [],
      stats: {
        total: (results.results || []).length === 500 ? "500+" : results.results?.length ?? 0,
        free: stats.free || 0,
        pro: stats.pro || 0,
        developer: stats.developer || 0,
      }
    });
  } catch (e) {
    console.error("Admin users list error:", e);
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function onRequestPatch(context) {
  const { env, request } = context;
  if (!isAdmin(request, env)) return adminUnauth();

  try {
    const { uid, plan } = await request.json();
    if (!uid || !plan) return Response.json({ error: "uid and plan required" }, { status: 400 });
    if (!["free", "pro", "developer"].includes(plan)) {
      return Response.json({ error: "Invalid plan. Choose: free, pro, developer" }, { status: 400 });
    }

    const now = Math.floor(Date.now() / 1000);
    const result = await env.DB.prepare(
      "UPDATE user_plans SET plan = ?, updated_at = ? WHERE uid = ?"
    ).bind(plan, now, uid).run();

    if (!result.success) return Response.json({ error: "User not found" }, { status: 404 });

    return Response.json({ success: true, uid, plan });
  } catch (e) {
    console.error("Admin update plan error:", e);
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function onRequestDelete(context) {
  const { env, request } = context;
  if (!isAdmin(request, env)) return adminUnauth();

  const url = new URL(request.url);
  const uid = url.searchParams.get("uid");
  if (!uid) return Response.json({ error: "uid parameter required" }, { status: 400 });

  try {
    await env.DB.prepare("DELETE FROM user_plans WHERE uid = ?").bind(uid).run();
    return Response.json({ success: true, message: "User record deleted." });
  } catch (e) {
    console.error("Admin delete user error:", e);
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}
