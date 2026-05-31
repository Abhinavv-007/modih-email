## 2024-05-06 - Add Security Headers
**Vulnerability:** Missing basic security headers like HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Content-Security-Policy.
**Learning:** For Cloudflare Pages projects, standard security headers can be enforced by adding a `_headers` file in the static build output directory (`public/_headers` in this case).
**Prevention:** Include a standard `_headers` file when setting up new Cloudflare Pages projects to enforce baseline defense-in-depth protections.

## 2024-05-31 - Replace Math.random with crypto.getRandomValues for Security-Sensitive Fallbacks
**Vulnerability:** The application used `Math.random()` to generate fallback UUIDs (`generateFallbackUUID`) and MIME boundary strings (`buildEmlExport`) in `public/app.js`. `Math.random()` is not a cryptographically secure random number generator (CSPRNG), making its outputs predictable and susceptible to potential collisions or security risks in specific attack vectors (like predicting boundaries for multipart responses).
**Learning:** Even for fallbacks or boundary string generation, relying on `Math.random()` in security-adjacent features (like tokens or UUIDs) creates unnecessary predictability. It's easy to overlook when implementing client-side fallbacks for APIs like `crypto.randomUUID()`.
**Prevention:** Always use `crypto.getRandomValues()` or `crypto.randomUUID()` for generating unique, unpredictable identifiers, tokens, and boundary strings across both backend and frontend code to ensure cryptographically secure randomness.
