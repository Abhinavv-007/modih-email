## 2024-05-06 - Add Security Headers
**Vulnerability:** Missing basic security headers like HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Content-Security-Policy.
**Learning:** For Cloudflare Pages projects, standard security headers can be enforced by adding a `_headers` file in the static build output directory (`public/_headers` in this case).
**Prevention:** Include a standard `_headers` file when setting up new Cloudflare Pages projects to enforce baseline defense-in-depth protections.

## 2024-05-12 - Prevent Application-Level DoS from Unbounded Row Fetch
**Vulnerability:** The application was fetching all `user_plans` records associated with an email and loading them entirely into memory (`.all()`), iterating over them in Node.js/Cloudflare Workers to find the highest-tier plan. An attacker could register an excessive number of rows for a victim's email, causing memory exhaustion and CPU spikes.
**Learning:** Application-side iteration for finding max values scales poorly and poses a DoS vector when the dataset isn't strictly bounded by the application.
**Prevention:** Offload sorting and limits directly to the database. Instead of loading arrays of objects, use SQLite's `ORDER BY CASE` construct combined with `LIMIT 1` (or D1's `.first()`) to let the DB handle it optimally.
