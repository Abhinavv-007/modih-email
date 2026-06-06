## 2024-05-06 - Add Security Headers
**Vulnerability:** Missing basic security headers like HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Content-Security-Policy.
**Learning:** For Cloudflare Pages projects, standard security headers can be enforced by adding a `_headers` file in the static build output directory (`public/_headers` in this case).
**Prevention:** Include a standard `_headers` file when setting up new Cloudflare Pages projects to enforce baseline defense-in-depth protections.

## 2024-06-05 - XSS in `showError`/`showUpgradeError`
**Vulnerability:** API response data directly injected into the DOM using `.innerHTML` without escaping or passed to `textContent` where an API error response parameter could be manipulated to execute arbitrary JS, particularly in `app.js` and auth pages.
**Learning:** `textContent` is safe from XSS, but passing dynamic API values to `.innerHTML` without sanitization creates a DOM-based XSS risk. By sanitizing `msg` with the existing `escapeHtml` or ensuring safe DOM APIs (`textContent`), we can mitigate this.
**Prevention:** Always use `textContent` over `.innerHTML` for rendering plain text strings or API error responses in frontend Javascript. If HTML must be rendered, aggressively sanitize the dynamic parts first via `escapeHtml()`.
