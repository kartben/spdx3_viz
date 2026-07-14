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
 * @param {{sample?: string|null, view?: string|null, expanded?: string|null,
 *          detail?: string|null, graphSelected?: string|null}} spot
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
  return params.toString();
}

/**
 * Parses a URL fragment produced by buildShareHash. Returns null when the
 * fragment isn't a share link (no sample id).
 *
 * @param {string} hash - location.hash, with or without the leading '#'
 * @returns {{sample: string, view: string, expanded: string|null,
 *            detail: string|null, graphSelected: string|null}|null}
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
    graphSelected: params.get('g') || null
  };
}
