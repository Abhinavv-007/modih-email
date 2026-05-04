/**
 * Shared HTML sanitizer for email body rendering.
 *
 * Used by:
 *   - email-worker/index.js (server-side, on inbound email storage)
 *   - public/app.js         (client-side, defense-in-depth before innerHTML)
 *   - functions/api/*       (when the same logic is needed in Pages Functions)
 *
 * Goal: strip active content (script tags, event handlers, dangerous URL
 * schemes, remote images / tracking pixels) while leaving safe formatting
 * (paragraphs, links, bold, line breaks, tables, lists, span/div) intact.
 *
 * The browser/email HTML parser is permissive — it accepts whitespace OR a
 * forward-slash as the separator between attributes inside a tag, so all
 * three of these are equivalent to a parser:
 *
 *     <a onclick="alert(1)">x</a>
 *     <a/onclick="alert(1)">x</a>
 *     <a /onclick="alert(1)">x</a>
 *
 * The previous regex used `\s` only and missed the slash-delimited form.
 * Every "attribute name comes after \s OR /" rule below uses `[\s/]` so we
 * cover both forms.
 *
 * Tests live in test/sanitize.test.js — when changing this file, please add
 * regression tests for any new payload class you intend to block.
 */

/* Pairs of dangerous tags + their content (script body, style body, etc.). */
const STRIP_PAIR_TAGS    = "script|style|iframe|object|form|svg|math|noscript|template";
/* Standalone tags that fetch or redirect resources. */
const STRIP_SINGLE_TAGS  = "embed|link|base|meta|source|track";
/* Catch-all opener (matches even if the closer is malformed/missing). */
const STRIP_OPENER_TAGS  = "script|style|iframe|object|svg|math|form|noscript|template";

/* Dangerous URL scheme prefixes. The `:` may be HTML-entity-encoded. */
const DANGEROUS_SCHEMES  = "javascript|vbscript|livescript|data|blob|file";

const RX_PAIR    = new RegExp(`<(${STRIP_PAIR_TAGS})\\b[\\s\\S]*?<\\/\\1\\s*>`, "gi");
const RX_SINGLE  = new RegExp(`<(${STRIP_SINGLE_TAGS})\\b[^>]*>`, "gi");
const RX_OPENER  = new RegExp(`<\\/?(${STRIP_OPENER_TAGS})\\b[^>]*>`, "gi");

/* Event handler attribute (`on*`) — preceded by whitespace OR slash so
 * `<a/onclick=...>` is caught. Three variants: double-quoted, single-quoted,
 * and unquoted. The unquoted value is bounded by whitespace, slash, or `>`
 * so we don't accidentally swallow the rest of the tag. */
const RX_ON_DBL  = /[\s/]on\w+\s*=\s*"[^"]*"/gi;
const RX_ON_SGL  = /[\s/]on\w+\s*=\s*'[^']*'/gi;
const RX_ON_UNQ  = /[\s/]on\w+\s*=\s*[^\s/>]+/gi;

const RX_SCHEME  = new RegExp(
  `(${DANGEROUS_SCHEMES})\\s*(?:&#0*58;?|&#x0*3a;?|:)`,
  "gi"
);

/* Block ALL <img …> tags entirely (replace with placeholder). Also matches
 * the slash-delimited form `<img/src=x/onerror=…>` because `\b` matches
 * between `g` and `/`. */
const RX_IMG     = /<img\b[^>]*>/gi;

/**
 * Decode numeric HTML entities (`&#NN;` and `&#xNN;`) for ASCII printables
 * BEFORE running the regex rules. The browser will decode these when
 * parsing href/src attribute values, so an attacker can smuggle dangerous
 * scheme names past our `javascript:` check by encoding individual
 * characters: `<a href="java&#115;cript:alert(1)">`.
 *
 * Named entities (`&lt;`, `&gt;`, `&amp;`) are NOT decoded — those are how
 * legitimate authors escape `<`, `>`, `&` for display. Decoding them
 * would turn `&lt;script&gt;` (intentionally inert text) into a live tag.
 */
function decodeNumericAscii(s) {
  return s.replace(/&#(x?)([0-9a-fA-F]+);/g, (match, hex, num) => {
    const code = parseInt(num, hex ? 16 : 10);
    if (!Number.isFinite(code)) return match;
    if (code >= 0x20 && code <= 0x7e) return String.fromCharCode(code);
    return match;
  });
}

/**
 * Sanitize an HTML string for safe rendering as an email body.
 *
 * Strict by design — favours over-blocking (false positives) over letting
 * any attacker-controlled HTML through. Returns "" for non-string inputs.
 */
export function sanitizeRenderedHtml(html) {
  if (typeof html !== "string") return "";

  // Normalise NULL bytes — some parsers ignore them, our regex would not.
  const denul = html.replace(/\u0000/g, "");
  const normalised = decodeNumericAscii(denul);

  return normalised
    .replace(RX_PAIR,   "")
    .replace(RX_SINGLE, "")
    .replace(RX_OPENER, "")
    // Replace event handlers with a single space so the leading delimiter
    // ([\s/]) doesn't disappear and merge two adjacent attribute names.
    .replace(RX_ON_DBL, " ")
    .replace(RX_ON_SGL, " ")
    .replace(RX_ON_UNQ, " ")
    .replace(RX_SCHEME, "blocked:")
    .replace(RX_IMG,    "[image removed]");
}
