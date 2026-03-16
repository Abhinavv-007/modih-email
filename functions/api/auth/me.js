// GET /api/auth/me — Verify Firebase token, upsert user_plans, return plan
import { getAuthUser } from "../../_auth-helper.js";

const DISPOSABLE_DOMAINS = new Set([
  "mailinator.com","guerrillamail.com","tempmail.com","throwaway.email",
  "yopmail.com","maildrop.cc","sharklasers.com","guerrillamailblock.com",
  "spam4.me","trashmail.com","trashmail.me","trashmail.net","dispostable.com",
  "mailnull.com","spamgourmet.com","spamgourmet.net","spamgourmet.org",
  "getairmail.com","filzmail.com","zetmail.com","discard.email","spamhereplease.com",
  "fakeinbox.com","tempr.email","trbvm.com","getnada.com","mailnesia.com",
  "mailnull.com","spamfree24.org","spamfree24.de","spamfree24.net",
]);

function isDisposable(email) {
  const domain = (email || "").split("@")[1]?.toLowerCase();
  return domain ? DISPOSABLE_DOMAINS.has(domain) : false;
}

// Plan tier ranking — higher number = higher plan
const PLAN_RANK = { developer: 3, pro: 2, free: 1 };

function bestOfTwo(a, b) {
  return (PLAN_RANK[a] || 0) >= (PLAN_RANK[b] || 0) ? a : b;
}

export async function onRequestGet(context) {
  const { env, request } = context;
  const NO_CACHE = {
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Pragma": "no-cache",
  };

  const user = await getAuthUser(request);
  if (!user) {
    return Response.json({ error: "Unauthorized" }, { status: 401, headers: NO_CACHE });
  }

  const { uid, email, email_verified } = user;

  if (isDisposable(email)) {
    return Response.json(
      { error: "Disposable email addresses are not allowed for premium accounts." },
      { status: 403, headers: NO_CACHE }
    );
  }

  const now = Math.floor(Date.now() / 1000);

  try {
    // ── Step 1: Look up by exact UID ──────────────────────────────────────
    const byUID = await env.DB.prepare(
      "SELECT uid, email, plan FROM user_plans WHERE uid = ?"
    ).bind(uid).first();

    // ── Step 2: Look up highest plan by email (catches admin-upgraded rows) ─
    let emailBestPlan = "free";
    if (email) {
      const emailRows = await env.DB.prepare(
        "SELECT plan FROM user_plans WHERE LOWER(email) = LOWER(?)"
      ).bind(email).all();
      for (const row of (emailRows.results || [])) {
        emailBestPlan = bestOfTwo(emailBestPlan, row.plan);
      }
    }

    // ── Step 3: Resolve final plan ─────────────────────────────────────────
    // Take the highest of: the UID row's plan OR the best plan found by email
    const finalPlan = bestOfTwo(byUID?.plan || "free", emailBestPlan);

    // ── Step 4: Sync the DB so UID row always holds the canonical plan ─────
    if (!byUID) {
      // First login for this UID — insert with best plan found (could be pro if admin added them by email)
      await env.DB.prepare(
        "INSERT INTO user_plans (uid, email, plan, created_at, updated_at) VALUES (?, ?, ?, ?, ?)"
      ).bind(uid, email || "", finalPlan, now, now).run();
    } else if (byUID.plan !== finalPlan || (email && byUID.email !== email)) {
      // Upgrade the UID row to the better plan (never downgrade via this path)
      const upgradedPlan = bestOfTwo(byUID.plan, finalPlan);
      await env.DB.prepare(
        "UPDATE user_plans SET plan = ?, email = ?, updated_at = ? WHERE uid = ?"
      ).bind(upgradedPlan, email || byUID.email, now, uid).run();
    }

    // ── Step 5: Clean up orphan rows with same email but different UID ──────
    if (email) {
      await env.DB.prepare(
        "DELETE FROM user_plans WHERE LOWER(email) = LOWER(?) AND uid != ?"
      ).bind(email, uid).run();
    }

    return Response.json({ uid, email, email_verified, plan: finalPlan }, { headers: NO_CACHE });
  } catch (e) {
    console.error("Auth me error:", e?.message || e);
    return Response.json({ error: "Internal server error" }, { status: 500, headers: NO_CACHE });
  }
}
