// @ts-check
/**
 * Shareable-link hash: serializes where the user is (bundled sample, view,
 * selected element) into the URL fragment and back. Only sessions loaded from
 * a bundled sample are linkable, since dropped files can't be re-fetched.
 *
 * @module lib/share
 */

/** @type {Record<string, string>} */
const REQ_KIND_TO_CODE = {
  '': 'all',
  functionalsafety_RequirementVerification: 'ver',
  functionalsafety_EvaluationResult: 'eval',
  functionalsafety_Assumption: 'asm'
};

/** @type {Record<string, string>} */
const REQ_CODE_TO_KIND = {
  all: '',
  ver: 'functionalsafety_RequirementVerification',
  eval: 'functionalsafety_EvaluationResult',
  asm: 'functionalsafety_Assumption'
};

/** @type {Record<string, string>} */
const SC_MODE_TO_CODE = {
  states: 'st',
  processes: 'pr',
  custody: 'cu',
  map: 'mp'
};

/** @type {Record<string, string>} */
const SC_CODE_TO_MODE = {
  st: 'states',
  pr: 'processes',
  cu: 'custody',
  mp: 'map'
};

/**
 * Builds the URL fragment (without the leading '#') for a spot in a sample.
 * Returns '' when there is no sample to anchor the link to.
 *
 * Every optional field is omitted at its default, so the common link stays
 * short and only the settings actually chosen show up in it.
 *
 * @param {{sample?: string|null, view?: string|null, expanded?: string|null,
 *          detail?: string|null, graphSelected?: string|null,
 *          licenseMode?: string|null, compatPanel?: string|null,
 *          compatOutbound?: string|null, compatScope?: string|null,
 *          compatEdges?: string|null, securityScope?: string|null,
 *          securityScopeReach?: string|null, requirementKind?: string|null,
 *          requirementLayout?: string|null, supplyChainMode?: string|null}} spot
 * @returns {string}
 */
export function buildShareHash(spot) {
  if (!spot?.sample) return '';
  const params = new URLSearchParams();
  params.set('s', spot.sample);
  if (spot.view && spot.view !== 'dashboard') params.set('v', spot.view);
  if (spot.expanded) params.set('e', spot.expanded);
  if (spot.detail) params.set('d', spot.detail);
  if (spot.graphSelected) params.set('g', spot.graphSelected);
  // The license compatibility check: what it was pointed at, so a link lands
  // the recipient on the same verdict rather than the default guess.
  if (spot.licenseMode === 'compatibility') {
    params.set('lm', 'c');
    if (spot.compatPanel === 'matrix') params.set('cp', 'm');
    if (spot.compatOutbound) params.set('co', spot.compatOutbound);
    if (spot.compatScope) params.set('cs', spot.compatScope);
    if (spot.compatEdges === 'distributed') params.set('ce', 'd');
  }
  // The Security view's scope: which artifact the findings were narrowed to,
  // and how strictly, so a link reopens the same answer rather than the
  // document-wide list.
  if (spot.view === 'security' && spot.securityScope) {
    params.set('ss', spot.securityScope);
    if (spot.securityScopeReach === 'declared') params.set('sr', 'd');
  }
  // Functional Safety chips and layout. Requirement + unspecified layout stay
  // out of the hash; a verification/test chip or an explicit list/tree does not,
  // so a saved URL can reopen the same kind of card.
  if (spot.view === 'requirements') {
    const kindCode = REQ_KIND_TO_CODE[spot.requirementKind ?? 'Requirement'];
    if (kindCode) params.set('rk', kindCode);
    if (spot.requirementLayout === 'tree') params.set('rl', 't');
    else if (spot.requirementLayout === 'list') params.set('rl', 'l');
  }
  // Supply Chain angle. Timeline is the default and stays out of the hash.
  if (spot.view === 'supplychain') {
    const modeCode = SC_MODE_TO_CODE[spot.supplyChainMode ?? 'timeline'];
    if (modeCode) params.set('svm', modeCode);
  }
  // URLSearchParams encodes ':' and '/' as %3A / %2F. SPDX ids and purls are
  // full of both, so a saved URL looked broken (a wall of percent-escapes)
  // even though it parsed. Those characters are not hash delimiters; leave
  // them readable. '#' '&' '=' stay encoded so the fragment cannot split.
  return params.toString().replace(/%3A/gi, ':').replace(/%2F/gi, '/').replace(/%40/gi, '@');
}

/**
 * Parses a URL fragment produced by buildShareHash. Returns null when the
 * fragment isn't a share link (no sample id).
 *
 * @param {string} hash - location.hash, with or without the leading '#'
 * @returns {{sample: string, view: string, expanded: string|null,
 *            detail: string|null, graphSelected: string|null,
 *            licenseMode: string, compatPanel: string, compatOutbound: string|null,
 *            compatScope: string|null, compatEdges: string,
 *            securityScope: string|null, securityScopeReach: string,
 *            requirementKind: string, requirementLayout: string|null,
 *            supplyChainMode: string|null}|null}
 */
export function parseShareHash(hash) {
  const raw = String(hash || '').replace(/^#/, '');
  if (!raw) return null;
  const params = new URLSearchParams(raw);
  const sample = params.get('s');
  if (!sample) return null;
  const rk = params.get('rk');
  const rl = params.get('rl');
  const svm = params.get('svm');
  return {
    sample,
    view: params.get('v') || 'dashboard',
    expanded: params.get('e') || null,
    detail: params.get('d') || null,
    graphSelected: params.get('g') || null,
    licenseMode: params.get('lm') === 'c' ? 'compatibility' : 'inventory',
    compatPanel: params.get('cp') === 'm' ? 'matrix' : 'check',
    compatOutbound: params.get('co') || null,
    compatScope: params.get('cs') || null,
    compatEdges: params.get('ce') === 'd' ? 'distributed' : 'all',
    securityScope: params.get('ss') || null,
    securityScopeReach: params.get('sr') === 'd' ? 'declared' : 'compiled',
    // Omitted rk is the Requirements chip, the view's default.
    requirementKind: rk == null ? 'Requirement' : (REQ_CODE_TO_KIND[rk] ?? 'Requirement'),
    // null means the link did not pin a layout: keep the document default
    // (tree when there is a decomposition) unless an expanded card forces list.
    requirementLayout: rl === 't' ? 'tree' : rl === 'l' ? 'list' : null,
    // null when omitted so an expanded card can still infer its angle; an
    // explicit svm always wins.
    supplyChainMode: svm ? SC_CODE_TO_MODE[svm] || 'timeline' : null
  };
}
