## 2024-05-06 - Add Security Headers
**Vulnerability:** Missing basic security headers like HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Content-Security-Policy.
**Learning:** For Cloudflare Pages projects, standard security headers can be enforced by adding a `_headers` file in the static build output directory (`public/_headers` in this case).
**Prevention:** Include a standard `_headers` file when setting up new Cloudflare Pages projects to enforce baseline defense-in-depth protections.
## 2024-07-06 - Prevent XSS in API Error Rendering
**Vulnerability:** Arbitrary API error messages were injected directly into the DOM using `innerHTML`, creating a potential Cross-Site Scripting (XSS) vulnerability if the API response is compromised or spoofed.
**Learning:** When displaying dynamic textual content (like error messages) from an API, always use `textContent` instead of `innerHTML` to natively escape HTML and prevent injection.
**Prevention:** Establish a project-wide convention to default to `textContent` for all dynamically generated text, reserving `innerHTML` only for sanitized HTML strings.
## 2024-07-14 - XSS in HTML Escape Function (DOM manipulation)
**Vulnerability:** The client-side `escapeHtml` function relied on setting `textContent` of a throwaway `div` and reading its `innerHTML`. This pattern correctly escapes `<`, `>`, and `&`, but notoriously fails to escape single and double quotes (`'` and `"`), exposing the app to attribute-injection XSS.
**Learning:** Browser native parsing via `textContent` -> `innerHTML` is an incomplete HTML sanitizer and should not be trusted for full HTML escaping, especially in attribute contexts.
**Prevention:** Always use regex-based string replacements (covering `&`, `<`, `>`, `"`, and `'`) or dedicated sanitization libraries for `escapeHtml` implementations.
