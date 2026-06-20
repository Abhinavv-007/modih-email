## 2024-05-06 - Add Security Headers
**Vulnerability:** Missing basic security headers like HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Content-Security-Policy.
**Learning:** For Cloudflare Pages projects, standard security headers can be enforced by adding a `_headers` file in the static build output directory (`public/_headers` in this case).
**Prevention:** Include a standard `_headers` file when setting up new Cloudflare Pages projects to enforce baseline defense-in-depth protections.

## 2024-05-15 - Insecure PRNG replaced with CSPRNG in frontend application
**Vulnerability:** Weak PRNG (`Math.random()`) was being used for generating client-side fallback UUIDs and boundary strings.
**Learning:** Even for non-cryptographic keys or boundaries, using `crypto.getRandomValues()` instead of `Math.random()` adds an important defense-in-depth layer against token predictability and collision.
**Prevention:** Always use Web Crypto API `crypto.getRandomValues` or `crypto.randomUUID` in new client side JavaScript where randomness for identifiers or keys is needed.
