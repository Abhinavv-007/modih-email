## 2024-05-03 - [HTML Sanitization Regex Bypass]
**Vulnerability:** XSS via regex bypass using slashes instead of spaces (e.g. `<svg/onload=alert(1)>`).
**Learning:** Regex-based sanitization relying on `\s` before event handlers like `on*` is insufficient since browsers allow slashes instead of spaces.
**Prevention:** Use `(?:\s|\/)+` to catch both spaces and slashes as separators before attributes.
