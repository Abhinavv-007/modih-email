// GET    /api/blocklist          — list a user's blocked senders        (Pro/Dev)
// POST   /api/blocklist          — add a sender to the user's block list (Pro/Dev)
// DELETE /api/blocklist?entry=…  — remove an entry from the block list   (Pro/Dev)
//
// All endpoints require a Firebase Bearer token. Plan must be 'pro' or
// 'developer'. Storage: `user_blocklist (uid, entry, kind, created_at)`
// (see migrate-pro-features.sql).

import { verifyFirebaseToken } from "../_auth-helper.js";
import { ok, err, rateLimit } from "../_api-helpers.js";

const BLOCKLIST_MAX = 500;     // hard cap per user
const RL_MAX        = 60;      // 60 mutations/min/IP
const RL_WIN        = 60;

// Resolve Firebase user + plan. Returns null on auth failure / non-paid.
async function requirePaidUser(request, db) {
  try {
    const authHeader = request.headers.get("Authorization") || "";
    if (!authHeader.startsWith("Bearer ")) return null;
    const token = authHeader.slice(7).trim();
    if (!token) return null;

    const user = await verifyFirebaseToken(token);
    if (!user?.uid) return null;

    const row = await db
      .prepare("SELECT plan FROM user_plans WHERE uid = ?")
      .bind(user.uid)
      .first();
    const plan = row?.plan || "free";
    if (plan !== "pro" && plan !== "developer") return null;

    return { uid: user.uid, plan };
  } catch (e) {
    console.error("[blocklist] auth error:", e?.message);
    return null;
  }
}

function normaliseEntry(raw) {
  const s = String(raw || "").trim().toLowerCase();
  if (!s) return null;
  if (s.length > 254) return null;
  // basic shape: address (has @) or bare domain
  if (s.includes("@")) {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)) return null;
    return { entry: s, kind: "address" };
  }
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(s)) return null;
  return { entry: s, kind: "domain" };
}

// ── GET /api/blocklist ──────────────────────────────────────────────────────
export async function onRequestGet(context) {
  const { env, request } = context;
  const user = await requirePaidUser(request, env.DB);
  if (!user) return err("UNAUTHORIZED", "Pro plan required.", 403, { upgrade_required: true, feature: "blocklist" });

  try {
    const rows = await env.DB
      .prepare("SELECT entry, kind, created_at FROM user_blocklist WHERE uid = ? ORDER BY created_at DESC")
      .bind(user.uid)
      .all();
    const list = (rows.results || []).map((r) => r.entry);
    return ok({ entries: list, kinds: rows.results || [] });
  } catch (e) {
    console.error("[blocklist] GET error:", e);
    return err("INTERNAL_ERROR", "Failed to load block list.", 500);
  }
}

// ── POST /api/blocklist ─────────────────────────────────────────────────────
// Body: { entry: "noreply@spam.com" } or { entry: "spam.com" }
export async function onRequestPost(context) {
  const { env, request } = context;
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";

  const allowed = await rateLimit(env.RATE_LIMIT, `bl_w:${ip}`, RL_MAX, RL_WIN);
  if (!allowed) return err("RATE_LIMITED", "Too many block list updates. Slow down.", 429);

  const user = await requirePaidUser(request, env.DB);
  if (!user) return err("UNAUTHORIZED", "Pro plan required.", 403, { upgrade_required: true, feature: "blocklist" });

  const body = await request.json().catch(() => ({}));
  const parsed = normaliseEntry(body?.entry);
  if (!parsed) return err("VALIDATION_ERROR", "Enter a full email address or a bare domain.", 400);

  try {
    const countRow = await env.DB
      .prepare("SELECT COUNT(*) as cnt FROM user_blocklist WHERE uid = ?")
      .bind(user.uid)
      .first();
    if ((countRow?.cnt || 0) >= BLOCKLIST_MAX) {
      return err("PLAN_LIMIT_EXCEEDED", `Block list is capped at ${BLOCKLIST_MAX} entries.`, 400);
    }

    const now = Math.floor(Date.now() / 1000);
    await env.DB
      .prepare(
        "INSERT OR REPLACE INTO user_blocklist (uid, entry, kind, created_at) VALUES (?, ?, ?, ?)"
      )
      .bind(user.uid, parsed.entry, parsed.kind, now)
      .run();

    return ok({ entry: parsed.entry, kind: parsed.kind });
  } catch (e) {
    console.error("[blocklist] POST error:", e);
    return err("INTERNAL_ERROR", "Failed to add block list entry.", 500);
  }
}

// ── DELETE /api/blocklist?entry=… ───────────────────────────────────────────
export async function onRequestDelete(context) {
  const { env, request } = context;
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const url = new URL(request.url);
  const raw = url.searchParams.get("entry");

  const allowed = await rateLimit(env.RATE_LIMIT, `bl_w:${ip}`, RL_MAX, RL_WIN);
  if (!allowed) return err("RATE_LIMITED", "Too many block list updates. Slow down.", 429);

  const user = await requirePaidUser(request, env.DB);
  if (!user) return err("UNAUTHORIZED", "Pro plan required.", 403, { upgrade_required: true, feature: "blocklist" });

  const parsed = normaliseEntry(raw);
  if (!parsed) return err("VALIDATION_ERROR", "Missing or invalid entry parameter.", 400);

  try {
    await env.DB
      .prepare("DELETE FROM user_blocklist WHERE uid = ? AND entry = ?")
      .bind(user.uid, parsed.entry)
      .run();
    return ok({ removed: parsed.entry });
  } catch (e) {
    console.error("[blocklist] DELETE error:", e);
    return err("INTERNAL_ERROR", "Failed to remove block list entry.", 500);
  }
}
