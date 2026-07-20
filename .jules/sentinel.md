## 2024-05-06 - Add Security Headers
**Vulnerability:** Missing basic security headers like HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Content-Security-Policy.
**Learning:** For Cloudflare Pages projects, standard security headers can be enforced by adding a `_headers` file in the static build output directory (`public/_headers` in this case).
**Prevention:** Include a standard `_headers` file when setting up new Cloudflare Pages projects to enforce baseline defense-in-depth protections.
## 2024-07-06 - Prevent XSS in API Error Rendering
**Vulnerability:** Arbitrary API error messages were injected directly into the DOM using `innerHTML`, creating a potential Cross-Site Scripting (XSS) vulnerability if the API response is compromised or spoofed.
**Learning:** When displaying dynamic textual content (like error messages) from an API, always use `textContent` instead of `innerHTML` to natively escape HTML and prevent injection.
**Prevention:** Establish a project-wide convention to default to `textContent` for all dynamically generated text, reserving `innerHTML` only for sanitized HTML strings.

## 2026-07-20 - Prevent Attribute Injection XSS in escapeHtml
**Vulnerability:** The client-side `escapeHtml` utility relied on DOM conversion (`div.textContent = text; return div.innerHTML;`) to escape HTML entities. This approach does not escape single (`'`) or double (`"`) quotes, leading to potential Cross-Site Scripting (XSS) via attribute injection when the output is embedded within HTML tag attributes.
**Learning:** The browser's `textContent` property does not mandate escaping quotes because they are safely interpreted inside text nodes. However, when extracted via `innerHTML` and reused within HTML attributes, those unescaped quotes allow attackers to break out of attributes and inject malicious handlers or payloads.
**Prevention:** When escaping HTML entities in client-side utilities, use a regex-based replacement covering `&`, `<`, `>`, `"`, and `'` instead of relying on the browser's DOM node properties.
