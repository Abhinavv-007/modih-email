## 2024-05-06 - Add Security Headers
**Vulnerability:** Missing basic security headers like HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Content-Security-Policy.
**Learning:** For Cloudflare Pages projects, standard security headers can be enforced by adding a `_headers` file in the static build output directory (`public/_headers` in this case).
**Prevention:** Include a standard `_headers` file when setting up new Cloudflare Pages projects to enforce baseline defense-in-depth protections.
## 2024-07-06 - Prevent XSS in API Error Rendering
**Vulnerability:** Arbitrary API error messages were injected directly into the DOM using `innerHTML`, creating a potential Cross-Site Scripting (XSS) vulnerability if the API response is compromised or spoofed.
**Learning:** When displaying dynamic textual content (like error messages) from an API, always use `textContent` instead of `innerHTML` to natively escape HTML and prevent injection.
**Prevention:** Establish a project-wide convention to default to `textContent` for all dynamically generated text, reserving `innerHTML` only for sanitized HTML strings.
## 2024-08-01 - Fix XSS Vulnerability in escapeHtml
**Vulnerability:** The client-side `escapeHtml` utility relied on assigning `textContent` to a temporary DOM element and reading back its `innerHTML`. This approach correctly escaped `<`, `>`, and `&`, but failed to escape single (`'`) and double (`"`) quotes, potentially exposing the application to attribute injection XSS.
**Learning:** When escaping HTML entities in client-side utilities, do not rely on `textContent` to `innerHTML` conversion, as it fails to escape quotes. Use a regex-based replacement covering `&`, `<`, `>`, `"`, and `'`.
**Prevention:** Establish a project-wide convention to use a robust regex-based escaping function for all dynamic content instead of relying on browser DOM manipulation.
