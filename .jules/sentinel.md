## 2024-05-06 - Add Security Headers
**Vulnerability:** Missing basic security headers like HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Content-Security-Policy.
**Learning:** For Cloudflare Pages projects, standard security headers can be enforced by adding a `_headers` file in the static build output directory (`public/_headers` in this case).
**Prevention:** Include a standard `_headers` file when setting up new Cloudflare Pages projects to enforce baseline defense-in-depth protections.
## 2024-07-06 - Prevent XSS in API Error Rendering
**Vulnerability:** Arbitrary API error messages were injected directly into the DOM using `innerHTML`, creating a potential Cross-Site Scripting (XSS) vulnerability if the API response is compromised or spoofed.
**Learning:** When displaying dynamic textual content (like error messages) from an API, always use `textContent` instead of `innerHTML` to natively escape HTML and prevent injection.
**Prevention:** Establish a project-wide convention to default to `textContent` for all dynamically generated text, reserving `innerHTML` only for sanitized HTML strings.
## 2026-07-16 - Fix attribute injection XSS in escapeHtml
**Vulnerability:** The client-side `escapeHtml` function used `textContent` to `innerHTML` conversion which fails to escape single and double quotes (`'` and `"`), exposing the application to attribute injection XSS.
**Learning:** When escaping HTML entities in client-side utilities, do not rely on `textContent` to `innerHTML` conversion because it does not cover all necessary characters for attribute injection.
**Prevention:** Use a regex-based replacement covering `&`, `<`, `>`, `"`, and `'`.
