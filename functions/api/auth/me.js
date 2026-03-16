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
    // Upsert user_plans row
    const existing = await env.DB.prepare(
      "SELECT uid, email, plan FROM user_plans WHERE uid = ?"
    ).bind(uid).first();

    if (!existing) {
      await env.DB.prepare(
        "INSERT INTO user_plans (uid, email, plan, created_at, updated_at) VALUES (?, ?, 'free', ?, ?)"
      ).bind(uid, email || "", now, now).run();
    } else if (existing.email !== email && email) {
      // Update email if changed (OAuth re-link, etc.)
      await env.DB.prepare(
        "UPDATE user_plans SET email = ?, updated_at = ? WHERE uid = ?"
      ).bind(email, now, uid).run();
    }

    const plan = existing ? existing.plan : "free";

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
