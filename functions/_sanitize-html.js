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

/* Pairs of dangerous tags + their content (script body, style body, etc.).
 * NOTE: <style> is deliberately NOT here — it is handled separately by
 * cleanCss() below so that legitimate email typography (font sizes, colours,
 * letter-spacing on verification codes, etc.) survives. Removing it wholesale
 * was making styled emails — Google OTP messages in particular — render as
 * unstyled walls of text. */
const STRIP_PAIR_TAGS    = "script|iframe|object|form|svg|math|noscript|template";
/* Standalone tags that fetch or redirect resources. */
const STRIP_SINGLE_TAGS  = "embed|link|base|meta|source|track";
/* Catch-all opener (matches even if the closer is malformed/missing). */
const STRIP_OPENER_TAGS  = "script|iframe|object|svg|math|form|noscript|template";

/* Dangerous URL scheme prefixes. The `:` may be HTML-entity-encoded.
 * `data:` is handled by RX_DATA_URI below instead of being blanket-blocked,
 * so that inline `data:image/<raster>` images (very common in real email)
 * render while `data:text/html` and friends stay blocked. */
const DANGEROUS_SCHEMES  = "javascript|vbscript|livescript|blob|file";

/* `data:` URIs are allowed ONLY for raster images. `data:image/svg+xml` is
 * NOT whitelisted — SVG can carry <script>, and while the render iframe runs
 * without allow-scripts, blocking it here is cheap defence in depth. Every
 * other `data:` payload (text/html, application/*, …) is neutralised. */
const RX_DATA_URI = /data\s*(?:&#0*58;?|&#x0*3a;?|:)(?!\s*image\/(?:png|jpe?g|gif|webp|bmp|apng|avif)\b)/gi;

/* Match a well-formed <style>…</style> block so its CSS can be scrubbed and
 * kept rather than discarded. */
const RX_STYLE_BLOCK = /<style\b[^>]*>([\s\S]*?)<\/style>/gi;
/* Any leftover (unclosed / malformed) style tag after block extraction. */
const RX_STYLE_STRAY = /<\/?style\b[^>]*>/gi;

/**
 * Scrub the body of a <style> block. In a script-free, no-referrer sandbox the
 * only real risk CSS carries is loading remote resources (open-tracking /
 * exfiltration) via @import or url(). We strip those while preserving all
 * layout/typography rules. `expression()` (dead IE vector) and any inline
 * script/vbscript schemes are neutralised defensively.
 */
function cleanCss(css) {
  return String(css)
    .replace(/@import[^;{}]*;?/gi, "")                       // no remote stylesheets
    .replace(/expression\s*\(/gi, "blocked(")               // dead IE vector
    .replace(/(?:javascript|vbscript)\s*:/gi, "blocked:")
    // Neutralise every url(...) that isn't an inline data:image — this is what
    // stops CSS-driven tracking pixels and remote fetches.
    .replace(/url\(\s*(["']?)\s*(?!data:image\/)[^)]*\1\s*\)/gi, "url()");
}

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

/* Strip ONLY tracking-pixel `<img>` tags (1x1, hidden) — keep the rest so
 * real product / marketing images render. Tracking pixels are width=1,
 * height=1, OR carry display:none / visibility:hidden styles. */
const RX_IMG_TRACKING = /<img\b(?=[^>]*(?:\swidth\s*=\s*["']?1\b|\sheight\s*=\s*["']?1\b|display\s*:\s*none|visibility\s*:\s*hidden))[^>]*>/gi;

/* If an `<img>` survives, neutralise any dangerous attributes that aren't
 * already covered by the generic event-handler stripper. `srcset` can
 * smuggle additional URLs the user never opted into. */
const RX_IMG_SRCSET = /(<img\b[^>]*?)\ssrcset\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi;

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

  // Extract well-formed <style> blocks into sentinels BEFORE the tag strippers
  // run, scrubbing their CSS. Sentinels use U+0001 (already-stripped U+0000's
  // neighbour) which never appears in real email. Anything still carrying a raw
  // <style> tag after this is malformed and gets removed by RX_STYLE_STRAY.
  // Preserve well-formed <style> blocks (with their CSS scrubbed) through the
  // tag strippers below. We cannot simply exclude <style> from the strippers,
  // because RX_STYLE_STRAY must still delete UNCLOSED/malformed style tags
  // (which can otherwise swallow the rest of the document as CSS and hide it).
  //
  // Trick: temporarily rename cleaned blocks to a private <modihstyle> alias
  // that none of the tag regexes match, run the full strip pipeline (which
  // removes any leftover real <style> orphan), then rename the alias back. Any
  // literal "modihstyle" in the untrusted input is removed first so a crafted
  // email cannot smuggle the alias in and forge a style block.
  const withAlias = normalised
    .replace(/modihstyle/gi, "")
    .replace(RX_STYLE_BLOCK, (_m, inner) => `<modihstyle>${cleanCss(inner)}</modihstyle>`);

  const cleaned = withAlias
    .replace(RX_PAIR,   "")
    .replace(RX_SINGLE, "")
    .replace(RX_OPENER, "")
    .replace(RX_STYLE_STRAY, "")
    // Replace event handlers with a single space so the leading delimiter
    // ([\s/]) does not disappear and merge two adjacent attribute names.
    .replace(RX_ON_DBL, " ")
    .replace(RX_ON_SGL, " ")
    .replace(RX_ON_UNQ, " ")
    // data: — blocked for everything except inline raster images.
    .replace(RX_DATA_URI, "blocked:")
    .replace(RX_SCHEME, "blocked:")
    // Drop only tracking pixels (1x1 / hidden) — real `<img>` tags are
    // preserved so genuine email images render. Dangerous src schemes
    // were already neutralised above.
    .replace(RX_IMG_TRACKING, "")
    .replace(RX_IMG_SRCSET,   "$1");

  // Restore the scrubbed style blocks.
  return cleaned
    .replace(/<modihstyle>/g, "<style>")
    .replace(/<\/modihstyle>/g, "</style>");
}
