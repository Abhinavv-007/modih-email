## 2024-05-06 - Add Security Headers
**Vulnerability:** Missing basic security headers like HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Content-Security-Policy.
**Learning:** For Cloudflare Pages projects, standard security headers can be enforced by adding a `_headers` file in the static build output directory (`public/_headers` in this case).
**Prevention:** Include a standard `_headers` file when setting up new Cloudflare Pages projects to enforce baseline defense-in-depth protections.
## 2024-07-06 - Prevent XSS in API Error Rendering
**Vulnerability:** Arbitrary API error messages were injected directly into the DOM using `innerHTML`, creating a potential Cross-Site Scripting (XSS) vulnerability if the API response is compromised or spoofed.
**Learning:** When displaying dynamic textual content (like error messages) from an API, always use `textContent` instead of `innerHTML` to natively escape HTML and prevent injection.
**Prevention:** Establish a project-wide convention to default to `textContent` for all dynamically generated text, reserving `innerHTML` only for sanitized HTML strings.
## 2025-05-18 - Insecure HTML Escaping via textContent
**Vulnerability:** The client-side `escapeHtml` function used DOM node `textContent` to `innerHTML` conversion, which fails to escape single and double quotes (`'` and `"`). When the escaped text was injected into HTML attributes, it allowed attribute injection XSS.
**Learning:** Relying on the DOM (`textContent` -> `innerHTML`) for HTML escaping is insufficient for contexts outside of plain text nodes, specifically within tag attributes, because it leaves quotes unescaped.
**Prevention:** Always use a comprehensive regex-based replacement that explicitly covers `&`, `<`, `>`, `"`, and `'` when escaping strings that might be interpolated into HTML templates or attributes.
