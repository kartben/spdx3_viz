/**
 * License helpers: rendering SimpleLicensing/ExpandedLicensing expressions for
 * display, and SPDX License List id/URL utilities.
 *
 * @module lib/licenses
 */

/**
 * Display form of a license expression: substitutes custom `LicenseRef-…` ids
 * with the name of the element they map to via simplelicensing_customIdToUri,
 * so viewers see resolved names instead of opaque LicenseRef tokens. The raw
 * expression is left untouched on the element itself.
 *
 * @param {Object} element - simplelicensing_LicenseExpression element
 * @param {Map} [elementMap] - Map of SPDX IDs to elements
 * @returns {string} Resolved expression, or '' when the element has none
 */
export function displayLicenseExpression(element, elementMap) {
  const expr = element?.simplelicensing_licenseExpression;
  if (!expr) return '';
  const map = element.simplelicensing_customIdToUri;
  if (!Array.isArray(map) || !map.length) return String(expr);
  // Longest key first so one custom id can't clobber another's prefix.
  return map
    .filter((entry) => entry?.key)
    .sort((a, b) => b.key.length - a.key.length)
    .reduce((out, entry) => {
      const name = elementMap?.get(entry.value)?.name || entry.key.replace(/^LicenseRef-/, '');
      return out.split(entry.key).join(name);
    }, String(expr));
}

// The ExpandedLicensing profile defines two named "individual" licenses,
// NoAssertionLicense and NoneLicense, each a singleton with a canonical term
// IRI (e.g. https://spdx.org/rdf/3.0.1/terms/ExpandedLicensing/NoAssertionLicense)
// that the JSON-LD context also compacts to `expandedlicensing_NoAssertionLicense`.
// Match the individual by its trailing token in either form, so it never leaks
// out as a raw id/IRI in the UI.
// See https://spdx.github.io/spdx-spec/v3.0.1/model/ExpandedLicensing/Individuals/
const LICENSE_INDIVIDUAL_RE = /(?:^|[/#_])(NoAssertionLicense|NoneLicense)$/;

// Where the SPDX spec documents these individuals.
const SPDX_INDIVIDUAL_DOC_BASE =
  'https://spdx.github.io/spdx-spec/v3.0.1/model/ExpandedLicensing/Individuals/';

// The two ExpandedLicensing individuals, each with: the SPDX-expression token
// used when composing license expression strings, the human label shown in the
// UI, a short paraphrase for tooltips, and the verbatim spec summary/detail
// (quoted from SPDX 3.0.1) plus a link back to its definition, shown in place of
// license text (these individuals have none).
const LICENSE_INDIVIDUALS = {
  NoAssertionLicense: {
    token: 'NoAssertion',
    label: 'No assertion',
    description:
      'No license asserted: the SPDX creator could not determine it, did not ' +
      'attempt to, or intentionally left it unspecified.',
    summary:
      'An Individual Value for License when no assertion can be made about its actual value.',
    detail:
      'NoAssertionLicense should be used if:\n' +
      '  • the SPDX creator has attempted to but cannot reach a reasonable objective determination;\n' +
      '  • the SPDX creator has made no attempt to determine this field; or\n' +
      '  • the SPDX creator has intentionally provided no information (no meaning should be implied by doing so).',
    docUrl: `${SPDX_INDIVIDUAL_DOC_BASE}NoAssertionLicense/`
  },
  NoneLicense: {
    token: 'NONE',
    label: 'None',
    description: 'The SPDX creator asserts that no license applies.',
    summary:
      'An Individual Value for License where the SPDX data creator determines that no license is present.',
    detail:
      'NoneLicense should be used if the SPDX creator determines there is no license available for this Artifact.',
    docUrl: `${SPDX_INDIVIDUAL_DOC_BASE}NoneLicense/`
  }
};

function matchLicenseIndividual(ref) {
  const match = typeof ref === 'string' && ref.match(LICENSE_INDIVIDUAL_RE);
  return match ? LICENSE_INDIVIDUALS[match[1]] : null;
}

/**
 * SPDX-expression token for an ExpandedLicensing individual license reference
 * ('NoAssertion' / 'NONE'), or '' when the ref isn't one of the individuals.
 * Use when composing a license expression string, not for UI display.
 *
 * @param {string} ref - A license reference (spdxId, CURIE, or term IRI)
 * @returns {string}
 */
export function licenseIndividualToken(ref) {
  return matchLicenseIndividual(ref)?.token || '';
}

/**
 * Human display label for an ExpandedLicensing individual license reference
 * ('No assertion' / 'None'), or '' when the ref isn't one of the individuals.
 *
 * @param {string} ref - A license reference (spdxId, CURIE, or term IRI)
 * @returns {string}
 */
export function licenseIndividualLabel(ref) {
  return matchLicenseIndividual(ref)?.label || '';
}

/**
 * Short explanation of an ExpandedLicensing individual license, for tooltips,
 * or '' when the ref isn't one of the individuals.
 *
 * @param {string} ref - A license reference (spdxId, CURIE, or term IRI)
 * @returns {string}
 */
export function licenseIndividualDescription(ref) {
  return matchLicenseIndividual(ref)?.description || '';
}

/**
 * @typedef {{ label: string, summary: string, detail: string, docUrl: string }} LicenseIndividualInfo
 */

/**
 * Full presentation info for an ExpandedLicensing individual license (label,
 * verbatim SPDX summary/detail, and a link to its spec definition), or null
 * when the ref isn't one of the individuals. Used to show a meaningful
 * definition where a listed license would show its license text.
 *
 * @param {string} ref - A license reference (spdxId, CURIE, or term IRI)
 * @returns {LicenseIndividualInfo|null}
 */
export function licenseIndividualInfo(ref) {
  const individual = matchLicenseIndividual(ref);
  if (!individual) return null;
  const { label, summary, detail, docUrl } = individual;
  return { label, summary, detail, docUrl };
}

// Renders SPDX 3 ExpandedLicensing operator classes (license sets and
// operators) as SPDX license expression strings.
// See https://spdx.github.io/spdx-spec/v3.0.1/model/ExpandedLicensing/

// Set operators and the license-expression keyword they render to.
const LICENSE_SET_OPERATOR = {
  expandedlicensing_ConjunctiveLicenseSet: ' AND ',
  expandedlicensing_DisjunctiveLicenseSet: ' OR '
};

// Binding strength of the set operators: OR is looser than AND, so a member
// binding looser than its parent (an OR set inside an AND set) is parenthesised.
const LICENSE_OPERATOR_PRECEDENCE = {
  expandedlicensing_DisjunctiveLicenseSet: 1,
  expandedlicensing_ConjunctiveLicenseSet: 2
};

function licensePrecedence(ref, elementMap) {
  const el = ref && typeof ref === 'object' ? ref : elementMap?.get(ref);
  return (el && LICENSE_OPERATOR_PRECEDENCE[el.type]) || 3;
}

// Extracts the bare SPDX License List id from a listed-license URL, or '' if
// the string isn't one.
function listedLicenseId(str) {
  const m = typeof str === 'string' && str.match(/^https?:\/\/spdx\.org\/licenses\/([^/?#]+)/i);
  return m ? m[1].replace(/\.(json|html)$/i, '') : '';
}

// Renders one AnyLicenseInfo reference, which may be an inline object, a
// listed-license URL, a NoneLicense/NoAssertionLicense, or an spdxId pointing
// at a graph element. Returns '' when nothing resolves so callers can fall back.
function renderLicenseRef(ref, elementMap, seen) {
  if (ref == null) return '';
  if (typeof ref === 'object') return renderLicenseNode(ref, elementMap, seen);
  const listed = listedLicenseId(ref);
  if (listed) return listed;
  const str = String(ref);
  const individualToken = licenseIndividualToken(str);
  if (individualToken) return individualToken;
  if (str.includes('NoAssertion')) return 'NoAssertion';
  const el = elementMap?.get(str);
  return el ? renderLicenseNode(el, elementMap, seen) : '';
}

function renderLicenseNode(el, elementMap, seen) {
  if (!el || typeof el !== 'object') return '';
  const id = el.spdxId || el['@id'];
  if (id) {
    if (seen.has(id)) return el.name || ''; // guard against pathological cycles
    seen.add(id);
  }

  // A pre-composed SPDX expression string (SimpleLicensing profile) wins.
  if (el.simplelicensing_licenseExpression) return displayLicenseExpression(el, elementMap);

  const joiner = LICENSE_SET_OPERATOR[el.type];
  if (joiner) {
    const parent = LICENSE_OPERATOR_PRECEDENCE[el.type];
    const parts = (el.expandedlicensing_member || [])
      .map((member) => {
        const text = renderLicenseRef(member, elementMap, seen);
        if (!text) return '';
        return licensePrecedence(member, elementMap) < parent ? `(${text})` : text;
      })
      .filter(Boolean);
    return parts.join(joiner);
  }

  if (el.type === 'expandedlicensing_OrLaterOperator') {
    const base = renderLicenseRef(el.expandedlicensing_subjectLicense, elementMap, seen);
    return base ? `${base}+` : '';
  }

  if (el.type === 'expandedlicensing_WithAdditionOperator') {
    const base = renderLicenseRef(el.expandedlicensing_subjectExtendableLicense, elementMap, seen);
    const addition = renderLicenseRef(el.expandedlicensing_subjectAddition, elementMap, seen);
    if (base && addition) return `${base} WITH ${addition}`;
    return base || addition;
  }

  // Leaf license: the listed id from its spdxId URL, or its name.
  return listedLicenseId(id) || el.name || '';
}

/**
 * Renders an SPDX 3 ExpandedLicensing set/operator element as a license
 * expression string, resolving nested members recursively. Returns '' for
 * elements that are not one of the ExpandedLicensing operator classes.
 *
 * @see https://spdx.github.io/spdx-spec/v3.0.1/model/ExpandedLicensing/
 * @param {Object} element - The candidate license element
 * @param {Map<string, Object>} [elementMap] - Map of SPDX IDs to elements
 * @returns {string} The license expression, or '' when not an operator element
 */
export function renderLicenseExpression(element, elementMap) {
  if (!element || typeof element !== 'object') return '';
  const type = element.type;
  const isOperator =
    !!LICENSE_SET_OPERATOR[type] ||
    type === 'expandedlicensing_OrLaterOperator' ||
    type === 'expandedlicensing_WithAdditionOperator';
  return isOperator ? renderLicenseNode(element, elementMap, new Set()) : '';
}

const SPDX_LICENSE_ID_RE = /^[A-Za-z0-9.+-]+$/;
const SPDX_ID_TOKEN_RE = /^[A-Za-z0-9.+-]+(?::[A-Za-z0-9.+-]+)?/;

/**
 * True when the string is a single SPDX License List identifier (not a compound expression).
 *
 * @param {string} value
 * @returns {boolean}
 */
export function isSimpleSpdxLicenseId(value) {
  if (!value || typeof value !== 'string') return false;
  if (/[\s()]/.test(value)) return false;
  if (/\b(AND|OR|WITH)\b/.test(value)) return false;
  return SPDX_LICENSE_ID_RE.test(value);
}

/**
 * Resolves the SPDX license expression string for a license reference.
 *
 * @param {string} id
 * @param {Map<string, Object>} [elementMap]
 * @returns {string}
 */
export function resolveLicenseExpression(id, elementMap) {
  if (!id || id.includes('NoAssertion')) return '';

  const el = elementMap?.get(id);
  if (el?.simplelicensing_licenseExpression) {
    return String(el.simplelicensing_licenseExpression).trim();
  }

  const expandedExpr = renderLicenseExpression(el, elementMap);
  if (expandedExpr) return expandedExpr;

  const urlMatch = id.match(/^https?:\/\/spdx\.org\/licenses\/([^/?#]+)/i);
  if (urlMatch) {
    return urlMatch[1].replace(/\.(json|html)$/i, '');
  }

  if (typeof id === 'string') return id.trim();
  return '';
}

/**
 * Extracts a single SPDX License List identifier from a license reference.
 *
 * @param {string} id - License target id (URL, expression element spdxId, etc.)
 * @param {Map<string, Object>} [elementMap]
 * @returns {string|null}
 */
export function extractSpdxLicenseId(id, elementMap) {
  const expr = resolveLicenseExpression(id, elementMap);
  if (!expr || expr.includes('NoAssertion')) return null;
  if (isSimpleSpdxLicenseId(expr)) return expr;

  const parts = extractLicenseExpressionParts(expr);
  const firstLicense = parts.find((part) => part.kind === 'license');
  return firstLicense?.id || null;
}

/**
 * @typedef {{ id: string, kind: 'license' | 'exception', withLicense?: string }} LicenseExpressionPart
 */

/**
 * Parses an SPDX license expression and returns the distinct fetchable parts.
 *
 * @param {string} expression
 * @returns {LicenseExpressionPart[]}
 */
export function extractLicenseExpressionParts(expression) {
  const expr = String(expression || '').trim();
  if (!expr || expr.includes('NoAssertion')) return [];

  try {
    const tokens = tokenizeLicenseExpression(expr);
    if (!tokens.length) return [];
    const parser = new LicenseExpressionParser(tokens);
    const tree = parser.parseExpression();
    if (parser.peek()?.type !== 'EOF') return [];
    return collectLicenseExpressionParts(tree);
  } catch {
    return [];
  }
}

function tokenizeLicenseExpression(expression) {
  const tokens = [];
  let index = 0;

  while (index < expression.length) {
    if (/\s/.test(expression[index])) {
      index++;
      continue;
    }

    const ch = expression[index];
    if (ch === '(') {
      tokens.push({ type: 'LPAREN' });
      index++;
      continue;
    }
    if (ch === ')') {
      tokens.push({ type: 'RPAREN' });
      index++;
      continue;
    }

    const keyword = expression.slice(index).match(/^(AND|OR|WITH)\b/);
    if (keyword) {
      tokens.push({ type: keyword[1] });
      index += keyword[1].length;
      continue;
    }

    const idMatch = expression.slice(index).match(SPDX_ID_TOKEN_RE);
    if (idMatch) {
      tokens.push({ type: 'ID', value: idMatch[0] });
      index += idMatch[0].length;
      continue;
    }

    throw new Error(`Unexpected character at position ${index}`);
  }

  tokens.push({ type: 'EOF' });
  return tokens;
}

class LicenseExpressionParser {
  constructor(tokens) {
    this.tokens = tokens;
    this.pos = 0;
  }

  peek() {
    return this.tokens[this.pos];
  }

  advance() {
    return this.tokens[this.pos++];
  }

  match(...types) {
    const token = this.peek();
    if (!token || !types.includes(token.type)) return false;
    this.advance();
    return true;
  }

  consume(type) {
    const token = this.peek();
    if (!token || token.type !== type) {
      throw new Error(`Expected ${type}`);
    }
    return this.advance();
  }

  parseExpression() {
    let node = this.parseWithExpr();
    while (this.match('AND', 'OR')) {
      const op = this.tokens[this.pos - 1].type;
      node = { type: 'compound', op, left: node, right: this.parseWithExpr() };
    }
    return node;
  }

  parseWithExpr() {
    let node = this.parsePrimary();
    if (this.match('WITH')) {
      const exception = this.parsePrimary();
      const licenseId = node?.type === 'id' ? node.id : null;
      const exceptionId = exception?.type === 'id' ? exception.id : null;
      if (!licenseId || !exceptionId) throw new Error('Invalid WITH expression');
      return { type: 'with', licenseId, exceptionId };
    }
    return node;
  }

  parsePrimary() {
    if (this.match('LPAREN')) {
      const node = this.parseExpression();
      this.consume('RPAREN');
      return node;
    }

    const token = this.consume('ID');
    return { type: 'id', id: token.value };
  }
}

/**
 * @param {object} node
 * @returns {LicenseExpressionPart[]}
 */
function collectLicenseExpressionParts(node) {
  /** @type {LicenseExpressionPart[]} */
  const parts = [];
  const seen = new Set();

  /** @param {object | null | undefined} current */
  function walk(current) {
    if (!current) return;

    if (current.type === 'id') {
      const key = `license:${current.id}`;
      if (!seen.has(key)) {
        seen.add(key);
        parts.push({ id: current.id, kind: 'license' });
      }
      return;
    }

    if (current.type === 'with') {
      walk({ type: 'id', id: current.licenseId });
      const key = `exception:${current.exceptionId}`;
      if (!seen.has(key)) {
        seen.add(key);
        parts.push({
          id: current.exceptionId,
          kind: 'exception',
          withLicense: current.licenseId
        });
      }
      return;
    }

    if (current.type === 'compound') {
      walk(current.left);
      walk(current.right);
    }
  }

  walk(node);
  return parts;
}

/**
 * JSON URL for license details (CORS-enabled jsDelivr mirror of license-list-data).
 *
 * @param {string} licenseId
 * @returns {string}
 */
export function spdxLicenseJsonUrl(licenseId) {
  return `https://cdn.jsdelivr.net/gh/spdx/license-list-data@master/json/details/${encodeURIComponent(licenseId)}.json`;
}

/**
 * JSON URL for license exception details.
 *
 * @param {string} exceptionId
 * @returns {string}
 */
export function spdxLicenseExceptionJsonUrl(exceptionId) {
  return `https://cdn.jsdelivr.net/gh/spdx/license-list-data@master/json/exceptions/${encodeURIComponent(exceptionId)}.json`;
}

/**
 * Canonical SPDX License List page for a license identifier.
 *
 * @param {string} licenseId
 * @returns {string}
 */
export function spdxLicensePageUrl(licenseId) {
  return `https://spdx.org/licenses/${encodeURIComponent(licenseId)}`;
}

/**
 * Canonical SPDX License List page for a license exception.
 *
 * @param {string} exceptionId
 * @returns {string}
 */
export function spdxLicenseExceptionPageUrl(exceptionId) {
  return `https://spdx.org/licenses/exceptions/${encodeURIComponent(exceptionId)}`;
}
