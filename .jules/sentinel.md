## 2024-05-06 - Add Security Headers
**Vulnerability:** Missing basic security headers like HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Content-Security-Policy.
**Learning:** For Cloudflare Pages projects, standard security headers can be enforced by adding a `_headers` file in the static build output directory (`public/_headers` in this case).
**Prevention:** Include a standard `_headers` file when setting up new Cloudflare Pages projects to enforce baseline defense-in-depth protections.
## 2025-02-21 - [DOM-based XSS in Error Handling]
**Vulnerability:** The `showUpgradeError` function injected untrusted user input directly into the DOM using `innerHTML` (`inner.innerHTML = msg || ...`), allowing for potential XSS.
**Learning:** Even internal error states that surface from backend responses can be vectors for DOM XSS. Error messages returned from an API should be strictly treated as un-sanitized user input.
**Prevention:** If an API message requires formatting and must be injected using `innerHTML`, the variables must be sanitized on the client using a robust escaping function, or the element should be targeted directly and text updated via `textContent`.
