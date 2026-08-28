// @ts-check
/**
 * Shareable-link hash: serializes where the user is (bundled sample, view,
 * selected element) into the URL fragment and back. Only sessions loaded from
 * a bundled sample are linkable, since dropped files can't be re-fetched.
 *
 * @module lib/share
 */

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
 *          compatEdges?: string|null}} spot
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
  return params.toString();
}

/**
 * Parses a URL fragment produced by buildShareHash. Returns null when the
 * fragment isn't a share link (no sample id).
 *
 * @param {string} hash - location.hash, with or without the leading '#'
 * @returns {{sample: string, view: string, expanded: string|null,
 *            detail: string|null, graphSelected: string|null,
 *            licenseMode: string, compatPanel: string, compatOutbound: string|null,
 *            compatScope: string|null, compatEdges: string}|null}
 */
export function parseShareHash(hash) {
  const raw = String(hash || '').replace(/^#/, '');
  if (!raw) return null;
  const params = new URLSearchParams(raw);
  const sample = params.get('s');
  if (!sample) return null;
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
    compatEdges: params.get('ce') === 'd' ? 'distributed' : 'all'
  };
}
