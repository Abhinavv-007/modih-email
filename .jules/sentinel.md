## 2024-05-04 - Timing Attack Vulnerability on Admin Secret

**Vulnerability:** The `isAdmin` function in `functions/api/admin/users.js` checked the `X-Admin-Secret` header against the `env.ADMIN_SECRET` environment variable using a standard string comparison (`secret === env.ADMIN_SECRET`). This is vulnerable to timing attacks, as string comparison stops as soon as a character mismatch is found.
**Learning:** Even internal admin secrets need constant-time string comparisons to prevent attackers from guessing the secret one character at a time by measuring response times. The application already had a `safeEqual` function in `_api-helpers.js`, but it wasn't being used consistently for all secret comparisons.
**Prevention:** Always use constant-time comparison functions (like `safeEqual`) when verifying secrets, tokens, hashes, or passwords.
