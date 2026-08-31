## 2024-05-06 - Add Security Headers
**Vulnerability:** Missing basic security headers like HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Content-Security-Policy.
**Learning:** For Cloudflare Pages projects, standard security headers can be enforced by adding a `_headers` file in the static build output directory (`public/_headers` in this case).
**Prevention:** Include a standard `_headers` file when setting up new Cloudflare Pages projects to enforce baseline defense-in-depth protections.
## 2024-07-06 - Prevent XSS in API Error Rendering
**Vulnerability:** Arbitrary API error messages were injected directly into the DOM using `innerHTML`, creating a potential Cross-Site Scripting (XSS) vulnerability if the API response is compromised or spoofed.
**Learning:** When displaying dynamic textual content (like error messages) from an API, always use `textContent` instead of `innerHTML` to natively escape HTML and prevent injection.
**Prevention:** Establish a project-wide convention to default to `textContent` for all dynamically generated text, reserving `innerHTML` only for sanitized HTML strings.
## 2024-08-01 - Prevent Attribute Injection XSS in escapeHtml
**Vulnerability:** The client-side utility `escapeHtml` used DOM assignments (`div.textContent` to `div.innerHTML`) to sanitize untrusted strings. While this escapes `<`, `>`, and `&`, it inherently fails to escape single and double quotes (`'` and `"`). Since this function was used to sanitize strings injected into HTML attributes (e.g., `title="${escapeHtml(value)}"`), it created a potential Cross-Site Scripting (XSS) vulnerability via attribute injection.
**Learning:** Browser native DOM property conversion (`textContent` to `innerHTML`) does not escape quotes. When escaping strings for injection into HTML attributes, quotes must be explicitly escaped.
**Prevention:** Always use regex-based string replacements covering all five critical characters (`&`, `<`, `>`, `"`, `'`) for generalized HTML escaping instead of relying on DOM property side-effects.
