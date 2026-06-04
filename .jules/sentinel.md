## 2024-05-06 - Add Security Headers
**Vulnerability:** Missing basic security headers like HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Content-Security-Policy.
**Learning:** For Cloudflare Pages projects, standard security headers can be enforced by adding a `_headers` file in the static build output directory (`public/_headers` in this case).
**Prevention:** Include a standard `_headers` file when setting up new Cloudflare Pages projects to enforce baseline defense-in-depth protections.

## 2024-06-04 - Fix XSS in `showUpgradeError`
**Vulnerability:** The API error message `msg` was injected directly into the DOM using `inner.innerHTML = msg || ...`. If the API returned a malicious error message, it would be executed as an XSS payload.
**Learning:** For client-side DOM updates, injecting un-escaped variables (even those originating from API error messages) into `innerHTML` causes Cross-Site Scripting (XSS).
**Prevention:** Always use `textContent` over `innerHTML` when inserting plain text or API response messages. If HTML must be injected, sanitize the dynamic strings first using the local `escapeHtml` utility.
