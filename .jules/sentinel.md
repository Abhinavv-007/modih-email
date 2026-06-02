## 2024-05-06 - Add Security Headers
**Vulnerability:** Missing basic security headers like HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Content-Security-Policy.
**Learning:** For Cloudflare Pages projects, standard security headers can be enforced by adding a `_headers` file in the static build output directory (`public/_headers` in this case).
**Prevention:** Include a standard `_headers` file when setting up new Cloudflare Pages projects to enforce baseline defense-in-depth protections.
## 2024-05-08 - Fix XSS in showUpgradeError
**Vulnerability:** DOM Cross-Site Scripting (XSS) vulnerability via `innerHTML`. The `msg` parameter (which came from `data.error.message`) was directly assigned to `inner.innerHTML` in `public/app.js` without any sanitization.
**Learning:** For client-side DOM updates, assigning external text content directly to `innerHTML` poses a significant XSS risk. While custom sanitizers like `escapeHtml` might exist in the codebase, utilizing native DOM APIs is more robust and less prone to developer error or missing dependencies.
**Prevention:** Prefer using `textContent` (or `innerText`) over `innerHTML` when inserting plain text or API response messages to inherently prevent XSS. If HTML injection is genuinely required, always verify that the input is rigorously sanitized beforehand.
