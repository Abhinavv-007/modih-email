## 2024-05-06 - Add Security Headers
**Vulnerability:** Missing basic security headers like HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Content-Security-Policy.
**Learning:** For Cloudflare Pages projects, standard security headers can be enforced by adding a `_headers` file in the static build output directory (`public/_headers` in this case).
**Prevention:** Include a standard `_headers` file when setting up new Cloudflare Pages projects to enforce baseline defense-in-depth protections.
## 2024-05-24 - [Math.random() for Security Boundaries]
**Vulnerability:** Weak PRNG (`Math.random()`) used for generating email boundaries and fallback UUIDs.
**Learning:** Predictable `Math.random` can lead to collisions or predictability in unique identifiers.
**Prevention:** Use `crypto.getRandomValues()` or `crypto.randomUUID()` when generating tokens, boundaries, or identifiers that require cryptographic randomness.

## 2024-05-24 - [DOM XSS in Error Messages]
**Vulnerability:** Unescaped custom error messages injected via `innerHTML` in `showUpgradeError()`.
**Learning:** Even internal API responses or parameterized strings can carry XSS payloads if inserted directly into DOM elements using `innerHTML`.
**Prevention:** Always use `escapeHtml()` when updating the DOM with potentially unsafe or dynamic strings via `innerHTML`.
