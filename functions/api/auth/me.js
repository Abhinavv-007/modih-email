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

export async function onRequestGet(context) {
  const { env, request } = context;

  const user = await getAuthUser(request);
  const NO_CACHE = { "Cache-Control": "no-store, no-cache, must-revalidate", "Pragma": "no-cache" };
  if (!user) {
    return Response.json({ error: "Unauthorized" }, { status: 401, headers: NO_CACHE });
  }

  const { uid, email, email_verified } = user;

  // Block disposable email signups from getting a plan record
  if (isDisposable(email)) {
    return Response.json({ error: "Disposable email addresses are not allowed for premium accounts." }, { status: 403 });
  }

  const now = Math.floor(Date.now() / 1000);

  try {
    // Find existing row by exact Firebase UID
    let existing = await env.DB.prepare(
      "SELECT uid, email, plan FROM user_plans WHERE uid = ?"
    ).bind(uid).first();

    if (email) {
      // Search all rows with this email (important if Admin created a fake-UID row for this email)
      const rowsResult = await env.DB.prepare(
        "SELECT uid, plan FROM user_plans WHERE LOWER(email) = LOWER(?)"
      ).bind(email).all();
      
      const rows = rowsResult.results || [];
      const hasDev = rows.some(r => r.plan === 'developer');
      const hasPro = rows.some(r => r.plan === 'pro');
      const bestPlan = hasDev ? 'developer' : (hasPro ? 'pro' : 'free');

      if (!existing) {
        // First time this exact UID is seen — insert it with the best plan found across the email
        await env.DB.prepare(
          "INSERT INTO user_plans (uid, email, plan, created_at, updated_at) VALUES (?, ?, ?, ?, ?)"
        ).bind(uid, email, bestPlan, now, now).run();
        existing = { uid, email, plan: bestPlan };
      } else {
        // Row exists. Make sure it has the best plan and correct email.
        if (existing.plan !== bestPlan || existing.email !== email) {
          await env.DB.prepare(
            "UPDATE user_plans SET plan = ?, email = ?, updated_at = ? WHERE uid = ?"
          ).bind(bestPlan, email, now, uid).run();
          existing.plan = bestPlan;
        }
      }

      // Cleanup: delete any leftover fake-UID rows made by the Admin panel
      if (rows.length > 0) {
        await env.DB.prepare(
          "DELETE FROM user_plans WHERE LOWER(email) = LOWER(?) AND uid != ?"
        ).bind(email, uid).run();
      }
    } else if (!existing) {
      // No email, completely new anonymous/phone user
      await env.DB.prepare(
        "INSERT INTO user_plans (uid, email, plan, created_at, updated_at) VALUES (?, '', 'free', ?, ?)"
      ).bind(uid, now, now).run();
      existing = { uid, email: "", plan: "free" };
    }

    const plan = existing.plan;

    return Response.json({
      uid,
      email,
      email_verified,
      plan,
    }, { headers: NO_CACHE });
  } catch (e) {
    console.error("Auth me error:", e);
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}
