/**
 * HTML escaping for the handful of places that build markup as strings.
 *
 * An SBOM is a third-party document: every name, id, license expression and
 * description in it is attacker-controllable text that this app renders. Most
 * of it reaches the DOM through Alpine's `x-text`, which escapes on its own, but
 * the views that assemble markup by hand (the JSON-LD highlighter, the palette's
 * match highlighting, the graph tooltip, the supply chain route map) need to do
 * it themselves.
 *
 * There used to be five separate copies of this, covering three different
 * character sets. They each happened to sit in a context their set was adequate
 * for, but nothing enforced that, so the escaping lives here now: one set,
 * covering every character that is special in text content, in a double-quoted
 * attribute, and in a single-quoted attribute alike.
 *
 * @module lib/escape
 */

/** Replacement per special character. Hoisted so it isn't rebuilt per match. */
const HTML_ESCAPES = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;'
};

const HTML_ESCAPE_RE = /[&<>"']/g;

/**
 * Escapes a value for interpolation into markup. Safe in element text, in a
 * quoted attribute, and inside inline SVG, which is why there is only one of
 * these: no call site has to pick the right variant.
 *
 * `null` and `undefined` escape to the empty string rather than to the words
 * "null" and "undefined", since every call site is rendering a value that may
 * legitimately be absent from the document.
 *
 * @param {*} value - Any value; coerced to string
 * @returns {string} The escaped text, or '' for null/undefined
 */
export function escapeHtml(value) {
  if (value == null) return '';
  return String(value).replace(HTML_ESCAPE_RE, (c) => HTML_ESCAPES[c]);
}

/**
 * Alias of {@link escapeHtml}, for call sites building an attribute where that
 * reads clearer. Deliberately the same function: the escape set already covers
 * both quote characters, and offering a genuinely weaker text-only variant next
 * to it is how the original five copies drifted apart.
 *
 * @param {*} value - Any value; coerced to string
 * @returns {string} The escaped text, or '' for null/undefined
 */
export const escapeAttr = escapeHtml;
