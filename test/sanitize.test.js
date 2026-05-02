import { describe, it, expect } from "vitest";

// Expose the sanitizer logic directly for unit testing
function sanitizeRenderedHtml(html) {
  if (typeof html !== "string") return "";
  return html
    .replace(/<(script|style|iframe|object|form|svg|math|noscript|template)\b[\s\S]*?<\/\1\s*>/gi, "")
    .replace(/<(embed|link|base|meta|source|track)\b[^>]*>/gi, "")
    .replace(/<\/?(script|style|iframe|object|svg|math|form|noscript|template)\b[^>]*>/gi, "")
    .replace(/(?:\s|\/)+on\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, "")
    .replace(/(javascript|vbscript|livescript|data|blob|file)\s*(?:&#0*58;?|&#x0*3a;?|:)/gi, "blocked:")
    .replace(/<img\b[^>]*>/gi, "[image removed]");
}

describe("HTML Sanitizer (XSS protection)", () => {
  it("removes inline event handlers separated by whitespaces", () => {
    const html = `<a href="#" onclick="alert(1)">click</a>`;
    expect(sanitizeRenderedHtml(html)).toBe(`<a href="#">click</a>`);
  });

  it("removes inline event handlers separated by slashes (bypass prevention)", () => {
    const html = `<a/onclick=alert(1) href="#">click</a>`;
    expect(sanitizeRenderedHtml(html)).toBe(`<a href="#">click</a>`);
  });

  it("removes inline event handlers separated by multiple slashes or whitespaces", () => {
    const html = `<a // \n onclick="alert(1)">click</a>`;
    expect(sanitizeRenderedHtml(html)).toBe(`<a>click</a>`);
  });

  it("blocks dangerous URL schemes", () => {
    const html = `<a href="javascript:alert(1)">click</a>`;
    expect(sanitizeRenderedHtml(html)).toBe(`<a href="blocked:alert(1)">click</a>`);
  });

  it("removes dangerous tags", () => {
    const html = `<body><script>alert(1)</script></body>`;
    expect(sanitizeRenderedHtml(html)).toBe(`<body></body>`);
  });

  it("blocks remote images", () => {
    const html = `<img src="http://example.com/pixel.gif">`;
    expect(sanitizeRenderedHtml(html)).toBe(`[image removed]`);
  });
});
