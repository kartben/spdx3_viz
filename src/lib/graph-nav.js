/**
 * Graph sidebar navigation: the trail of nodes walked via the detail panel,
 * the camera-focus easing, and the colours that paint start vs here.
 *
 * Pure (no DOM, no d3) so the hop rules and the pan timing stay testable.
 * The canvas renderer maps trail ids onto render nodes and interpolates the
 * zoom transform; this module only decides *what* the trail is and *how*
 * the camera should move.
 *
 * @module lib/graph-nav
 */

/** Cyan ring on the node where the walk started. */
export const TRAIL_START = '#22d3ee';
/** Violet on intermediate hops. */
export const TRAIL_MID = '#a78bfa';
/** Pink ring on the node currently in focus. */
export const TRAIL_CURRENT = '#f472b6';

const DEFAULT_MAX_TRAIL = 24;

/**
 * Walk the trail one hop. Clicking a node already on the path rewinds to it.
 * Clicking the current node is a no-op. A very long walk keeps the origin and
 * drops the oldest intermediate hops so "where I started" stays visible.
 *
 * @param {string[]|null|undefined} trail
 * @param {string|null|undefined} nextId
 * @param {number} [max]
 * @returns {string[]}
 */
export function advanceNavTrail(trail, nextId, max = DEFAULT_MAX_TRAIL) {
  if (!nextId) return Array.isArray(trail) ? trail.slice() : [];
  const prev = Array.isArray(trail) ? trail : [];
  if (!prev.length) return [nextId];
  if (prev[prev.length - 1] === nextId) return prev.slice();
  const existing = prev.indexOf(nextId);
  if (existing >= 0) return prev.slice(0, existing + 1);
  const next = prev.concat(nextId);
  if (next.length <= max) return next;
  return [next[0], ...next.slice(next.length - (max - 1))];
}

/**
 * Fold a trail of element ids onto render-node ids (clusters share one id),
 * dropping unknowns and collapsing consecutive duplicates.
 *
 * @param {string[]|null|undefined} trail
 * @param {Map<string, string>} renderKeyOf
 * @param {Map<string, unknown>} renderById
 * @returns {string[]}
 */
export function mapTrailToRenderIds(trail, renderKeyOf, renderById) {
  if (!trail?.length) return [];
  const ids = [];
  for (const id of trail) {
    const rid = renderKeyOf.get(id) || (renderById.has(id) ? id : null);
    if (rid && rid !== ids[ids.length - 1]) ids.push(rid);
  }
  return ids;
}

function parseHex(hex) {
  const n = parseInt(hex.slice(1), 16);
  return { r: (n >> 16) & 255, g: (n >> 8) & 255, b: n & 255 };
}

function mixHex(a, b, t) {
  const ca = parseHex(a);
  const cb = parseHex(b);
  const r = Math.round(ca.r + (cb.r - ca.r) * t);
  const g = Math.round(ca.g + (cb.g - ca.g) * t);
  const bl = Math.round(ca.b + (cb.b - ca.b) * t);
  return '#' + ((1 << 24) + (r << 16) + (g << 8) + bl).toString(16).slice(1);
}

/**
 * Colour for hop `i` of an `n`-long trail: cyan at the start, violet in the
 * middle, pink on the current node.
 *
 * @param {number} i
 * @param {number} n
 * @returns {string}
 */
export function trailColorAt(i, n) {
  if (n <= 1 || i >= n - 1) return TRAIL_CURRENT;
  if (i <= 0) return TRAIL_START;
  const t = i / (n - 1);
  if (t < 0.5) return mixHex(TRAIL_START, TRAIL_MID, t * 2);
  return mixHex(TRAIL_MID, TRAIL_CURRENT, (t - 0.5) * 2);
}

/**
 * Quartic ease-in-out: slow start, quick middle, gentle stop. Used as the
 * d3-transition ease so a camera pan accelerates and decelerates.
 *
 * @param {number} t 0..1
 * @returns {number}
 */
export function easeInOutQuart(t) {
  return t < 0.5 ? 8 * t * t * t * t : 1 - Math.pow(-2 * t + 2, 4) / 2;
}

/**
 * Zoom factor that keeps the focused node a readable size without yanking
 * a close-up back out. Tiny nodes (zoomed far out) grow to `targetPx`; huge
 * clusters shrink toward `maxPx`. Otherwise the current zoom is kept so a
 * hop only pans.
 *
 * @param {{currentK: number, nodeR: number, minK: number, maxK: number, minPx?: number, targetPx?: number, maxPx?: number, capK?: number}} opts
 * @returns {number}
 */
export function focusScale({
  currentK,
  nodeR,
  minK,
  maxK,
  minPx = 6,
  targetPx = 14,
  maxPx = 72,
  capK = 1.6
}) {
  const r = Math.max(nodeR || 0.5, 0.5);
  const onScreen = r * currentK;
  let k = currentK;
  if (onScreen < minPx) k = targetPx / r;
  else if (onScreen > maxPx) k = maxPx / r;
  return Math.max(minK, Math.min(maxK, capK, k));
}

/**
 * d3-zoom translate/scale that centres world-space `(x, y)` in a `width`×`height`
 * viewport at scale `k`. Matches `graphFitView`'s transform convention.
 *
 * @param {{width: number, height: number, x: number, y: number, k: number}} opts
 * @returns {{x: number, y: number, k: number}}
 */
export function focusTransform({ width, height, x, y, k }) {
  return { x: width / 2 - k * x, y: height / 2 - k * y, k };
}

/**
 * Pan duration in ms from the current transform to the target, longer for
 * distant hops and zoom changes, clamped so a nearby click is snappy and a
 * cross-graph hop still finishes in about a second.
 *
 * @param {{x?: number, y?: number, k?: number}} from
 * @param {{x?: number, y?: number, k?: number}} to
 * @returns {number}
 */
export function focusPanDuration(from, to) {
  const dx = (to.x ?? 0) - (from.x ?? 0);
  const dy = (to.y ?? 0) - (from.y ?? 0);
  const pan = Math.hypot(dx, dy);
  const fk = from.k || 1;
  const tk = to.k || 1;
  const zoomDelta = Math.abs(Math.log2(tk / fk));
  return Math.max(380, Math.min(980, Math.round(360 + pan * 0.42 + zoomDelta * 240)));
}

/**
 * True when the camera still has a noticeable pan or zoom to do.
 *
 * @param {{x?: number, y?: number, k?: number}} from
 * @param {{x?: number, y?: number, k?: number}} to
 * @param {number} [epsilon]
 * @returns {boolean}
 */
export function focusNeedsMove(from, to, epsilon = 6) {
  const pan = Math.hypot((to.x ?? 0) - (from.x ?? 0), (to.y ?? 0) - (from.y ?? 0));
  const zoomDelta = Math.abs((to.k || 1) - (from.k || 1));
  return pan > epsilon || zoomDelta > 0.02;
}
