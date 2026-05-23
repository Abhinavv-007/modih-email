## 2024-05-06 - Add Security Headers
**Vulnerability:** Missing basic security headers like HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Content-Security-Policy.
**Learning:** For Cloudflare Pages projects, standard security headers can be enforced by adding a `_headers` file in the static build output directory (`public/_headers` in this case).
**Prevention:** Include a standard `_headers` file when setting up new Cloudflare Pages projects to enforce baseline defense-in-depth protections.
## 2026-05-23 - [XSS Fix]
**Vulnerability:** DOM-based XSS when assigning un-sanitized user input to innerHTML in public/app.js.
**Learning:** Directly assigning user input to innerHTML can lead to XSS vulnerabilities.
**Prevention:** Sanitize user input before assigning it to innerHTML using escapeHtml.
