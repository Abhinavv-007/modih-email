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

/* ASCII whitespace characters that the WHATWG URL parser strips from URLs
 * BEFORE scheme detection: TAB (\t), LF (\n), CR (\r), and the NULL byte
 * which several browsers also ignore. Embedding any of these inside a
 * scheme name (e.g. `javas\tcript:`, `java&#9;script:`) bypasses a literal
 * `javascript|...` check, because `<a href>` parsing strips the chars
 * before the URL is interpreted. We turn them into a real SPACE — which
 * the URL parser does NOT strip — so the scheme name is corrupted and
 * `j a v a s c r i p t :` is never recognised as `javascript:`.
 */
const URL_BYPASS_CHARS_RX = /[\t\n\r\u0000]/g;

/* Tags can carry attribute values that legitimately contain CR/LF (e.g.
 * a wrapped `style="..."`). We only neutralise the chars when they appear
 * inside `<...>` (where attribute values are parsed), never in body text.
 */
const RX_TAG_INNER = /<[^>]+>/g;

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
 * We also decode TAB (0x09), LF (0x0a) and CR (0x0d) — but to a SPACE
 * rather than the original char. The WHATWG URL parser strips those three
 * chars from URLs before parsing the scheme, so leaving them intact
 * would let `<a href="java&#9;script:alert(1)">` slip past the literal
 * `javascript|...` regex (browser sees `javas\tcript:` → `javascript:`).
 * Replacing them with a real space corrupts the scheme name in a way the
 * URL parser DOES preserve.
 *
 * Named entities (`&lt;`, `&gt;`, `&amp;`) are NOT decoded — those are how
 * legitimate authors escape `<`, `>`, `&` for display. Decoding them
 * would turn `&lt;script&gt;` (intentionally inert text) into a live tag.
 *
 * The few named entities that DO map to URL-bypass whitespace chars
 * (`&Tab;`, `&NewLine;`, `&CR;`, `&LF;`) are handled explicitly by
 * `decodeWhitespaceNamedEntities` below.
 */
function decodeNumericAscii(s) {
  return s.replace(/&#(x?)([0-9a-fA-F]+);/g, (match, hex, num) => {
    const code = parseInt(num, hex ? 16 : 10);
    if (!Number.isFinite(code)) return match;
    if (code === 0x09 || code === 0x0a || code === 0x0d) return " ";
    if (code >= 0x20 && code <= 0x7e) return String.fromCharCode(code);
    return match;
  });
}

/* Named entities that resolve to URL-bypass whitespace (TAB / LF / CR).
 * Replacing each with a literal space prevents the same bypass as
 * `decodeNumericAscii` does for `&#9;` etc. We keep this list tiny so
 * we don't accidentally decode other named entities that legitimate
 * authors rely on. Case matters in HTML5 named entities — `&Tab;`,
 * `&NewLine;`, `&CR;`, `&LF;` are all canonical.
 */
function decodeWhitespaceNamedEntities(s) {
  return s.replace(/&(Tab|NewLine|CR|LF);/g, " ");
}

/* Within `<...>` tag delimiters, replace TAB / LF / CR / NULL with a
 * single space. After the entity decoders above, a payload like
 * `<a href="javas\tcript:alert(1)">` would still bypass the scheme
 * regex if the literal char was supplied directly. This pass kills the
 * bypass without touching body text where these chars are legitimate.
 */
function neutraliseTagBypassChars(s) {
  return s.replace(RX_TAG_INNER, m => m.replace(URL_BYPASS_CHARS_RX, " "));
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
  // Decode `&#9;` / `&#10;` / `&#13;` and printable-ASCII numeric entities.
  // Decode the named whitespace entities (`&Tab;`, `&NewLine;`, `&CR;`,
  // `&LF;`). Both passes turn URL-bypass whitespace into a literal space.
  const decoded = decodeWhitespaceNamedEntities(decodeNumericAscii(denul));
  // Replace any remaining literal TAB / LF / CR / NULL bytes inside tags
  // — these would otherwise be stripped by the URL parser at render time,
  // re-assembling broken scheme names like `javas\tcript:` into a live
  // `javascript:` URL.
  const normalised = neutraliseTagBypassChars(decoded);

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
