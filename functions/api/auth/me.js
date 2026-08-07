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
    // Older databases may not have plan_expires_at until the admin migration runs.
    if (!String(error?.message || "").includes("plan_expires_at")) throw error;
  }
}

async function logAuthSeen(db, { uid, email, ip, userAgent, now }) {
  try {
    await db.prepare(
      `INSERT INTO admin_events
         (event_type, uid, email, ip, subject, is_otp, metadata, created_at)
       VALUES ('auth_seen', ?, ?, ?, ?, 0, ?, ?)`
    )
      .bind(
        uid,
        email || "",
        ip || "unknown",
        "login",
        JSON.stringify({ user_agent: String(userAgent || "").slice(0, 180) }),
        now
      )
      .run();
  } catch (error) {
    if (!String(error?.message || "").includes("admin_events")) throw error;
  }
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
    await expireExpiredPlans(env.DB, now);

    // ── Step 1: Look up by exact UID ──────────────────────────────────────
    const byUID = await env.DB.prepare(
      "SELECT uid, email, plan FROM user_plans WHERE uid = ?"
    ).bind(uid).first();

    // ── Step 2: Look up highest plan by email (catches admin-upgraded rows) ─
    //
    // SECURITY: any email-based lookup MUST require email_verified === true.
    // Otherwise an attacker who registers a Firebase account using a
    // victim's email (without ever verifying it) inherits whatever paid
    // plan the admin had assigned to that email — and Step 5 below would
    // delete the legitimate user's UID row, completing the takeover.
    //
    // Treating an unverified-email Firebase user as a "free" account by
    // default is the safe behaviour: the worst case is that a real user
    // doesn't get their admin-assigned plan until they verify, which is
    // exactly the trust signal we need to honour cross-account inheritance.
    const emailTrusted = Boolean(email) && email_verified === true;

    let emailBestPlan = "free";
    if (emailTrusted) {
      // Resolve the single highest-ranked plan for this email at the DB layer.
      // The previous version pulled EVERY matching row into memory and ranked
      // them in JS, so an attacker who created many user_plans rows for a
      // target email could force unbounded memory/CPU use (application-level
      // DoS, PR #17). ORDER BY … LIMIT 1 caps the work regardless of row count.
      const emailBest = await env.DB.prepare(
        `SELECT plan FROM user_plans
          WHERE LOWER(email) = LOWER(?)
          ORDER BY CASE plan
                     WHEN 'developer' THEN 3
                     WHEN 'pro'       THEN 2
                     ELSE 1
                   END DESC
          LIMIT 1`
      ).bind(email).first();
      if (emailBest?.plan) emailBestPlan = emailBest.plan;
    }

    // ── Step 3: Resolve final plan ─────────────────────────────────────────
    // Take the highest of: the UID row's plan OR the best plan found by email.
    // When `emailTrusted` is false we silently keep `emailBestPlan = "free"`,
    // so the only thing the unverified-email user can see is the plan
    // already attached to their own UID.
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
    //
    // SECURITY: same gate as Step 2. Without it, an unverified-email
    // attacker could DELETE the legitimate user's plan row purely by
    // logging in once. Restrict the destructive cleanup to verified
    // emails — by definition they're the only ones we can claim
    // ownership over.
    if (emailTrusted) {
      await env.DB.prepare(
        "DELETE FROM user_plans WHERE LOWER(email) = LOWER(?) AND uid != ?"
      ).bind(email, uid).run();
    }

    await logAuthSeen(env.DB, {
      uid,
      email,
      ip: request.headers.get("CF-Connecting-IP") || "unknown",
      userAgent: request.headers.get("User-Agent") || "",
      now,
    });

    return Response.json({ uid, email, email_verified, plan: finalPlan }, { headers: NO_CACHE });
  } catch (e) {
    console.error("Auth me error:", e?.message || e);
    return Response.json({ error: "Internal server error" }, { status: 500, headers: NO_CACHE });
  }
}
