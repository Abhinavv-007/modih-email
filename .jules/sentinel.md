## 2024-05-06 - Add Security Headers
**Vulnerability:** Missing basic security headers like HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Content-Security-Policy.
**Learning:** For Cloudflare Pages projects, standard security headers can be enforced by adding a `_headers` file in the static build output directory (`public/_headers` in this case).
**Prevention:** Include a standard `_headers` file when setting up new Cloudflare Pages projects to enforce baseline defense-in-depth protections.

## 2025-02-21 - Unsanitized Message Injection
**Vulnerability:** Unsanitized server response messages injected directly into `innerHTML` within `showUpgradeError` in `public/app.js`.
**Learning:** Even internal backend errors may reflect unsanitized input or be later modified to include user-supplied parameters. Injecting error message strings directly into `innerHTML` is a persistent XSS risk.
**Prevention:** Always use `textContent`, or explicitly sanitize error strings with `escapeHtml` before rendering them via `innerHTML`.
