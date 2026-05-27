## 2024-05-06 - Add Security Headers
**Vulnerability:** Missing basic security headers like HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Content-Security-Policy.
**Learning:** For Cloudflare Pages projects, standard security headers can be enforced by adding a `_headers` file in the static build output directory (`public/_headers` in this case).
**Prevention:** Include a standard `_headers` file when setting up new Cloudflare Pages projects to enforce baseline defense-in-depth protections.

## 2024-05-27 - Predictable Math.random() usage
**Vulnerability:** Predictable PRNG using `Math.random()` for multipart boundaries and fallback UUID generation.
**Learning:** In environments without `crypto.randomUUID()`, `Math.random()` is not cryptographically secure and predictable values can lead to MIME boundary confusion or ID collisions.
**Prevention:** Use `crypto.getRandomValues()` to build a fallback UUID generator instead of `Math.random()`.
