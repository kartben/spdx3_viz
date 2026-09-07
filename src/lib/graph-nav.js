/**
 * Graph sidebar navigation: the trail of nodes walked via the detail panel,
 * the camera-focus easing, and the colours that paint start vs here.
 *
 * Pure (no DOM, no d3) so the hop rules and the pan timing stay testable.
 * The canvas renderer maps trail ids onto render nodes and interpolates the
 * zoom transform; this module only decides *what* the trail is and *how*
 * the camera should move. Also the click-vs-drag threshold so a node press
 * does not reheat the force layout.
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
 * Recap of a walk for the toolbar chip card: trail colours, a short sentence
 * that reads the path, and the relationship that connected each hop.
 *
 * @param {string[]|null|undefined} trail
 * @param {(id: string) => {name?: string, typeLabel?: string, el?: unknown}|null|undefined} [resolve]
 * @param {(fromId: string, toId: string) => {label?: string, color?: string}|null|undefined} [relationBetween]
 * @returns {{hops: Array<{id: string, name: string, typeLabel: string, color: string, role: string, viaLabel: string, viaColor: string, last: boolean, el: unknown}>, hopCount: number, summary: string}}
 */
export function trailRecap(trail, resolve = () => null, relationBetween = () => null) {
  const ids = Array.isArray(trail) ? trail.filter(Boolean) : [];
  const n = ids.length;
  const hops = ids.map((id, i) => {
    const info = resolve(id) || {};
    const via = i > 0 ? relationBetween(ids[i - 1], id) || {} : {};
    const role = i === 0 ? 'start' : i === n - 1 ? 'here' : 'hop';
    return {
      id,
      name: recapDisplayName(info.name || id),
      typeLabel: info.typeLabel || '',
      color: trailColorAt(i, n),
      role,
      viaLabel: via.label || '',
      viaColor: via.color || '',
      last: i === n - 1,
      el: info.el ?? null
    };
  });
  let summary = '';
  if (n === 1) summary = `At ${hops[0].name}.`;
  else if (n === 2) summary = `From ${hops[0].name} to ${hops[1].name}.`;
  else if (n === 3) summary = `From ${hops[0].name} via ${hops[1].name} to ${hops[2].name}.`;
  else if (n > 3) summary = `From ${hops[0].name} via ${n - 2} hops to ${hops[n - 1].name}.`;
  return { hops, hopCount: Math.max(0, n - 1), summary };
}

function recapDisplayName(name) {
  return String(name || '')
    .replace(/\s*\(screenshot\)\s*$/i, '')
    .trim();
}

/**
 * The relationship walked from `fromId` to `toId`. Prefers an outgoing edge
 * (the usual sidebar hop); falls back to an incoming edge when the hop was a
 * reverse group such as "Required by".
 *
 * @param {string} fromId
 * @param {string} toId
 * @param {{outgoing?: Array<{to?: string|string[], relationshipType?: string}>, incoming?: Array<{from?: string, relationshipType?: string}>}} [rels]
 * @returns {{type: string, direction: 'out'|'in'}|null}
 */
export function findTrailRelation(fromId, toId, rels = {}) {
  if (!fromId || !toId) return null;
  for (const rel of rels.outgoing || []) {
    const targets = Array.isArray(rel.to) ? rel.to : [rel.to];
    if (targets.includes(toId) && rel.relationshipType) {
      return { type: rel.relationshipType, direction: 'out' };
    }
  }
  for (const rel of rels.incoming || []) {
    if (rel.from === toId && rel.relationshipType) {
      return { type: rel.relationshipType, direction: 'in' };
    }
  }
  return null;
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

/**
 * Camera transform that keeps every trail point in the viewport. Zoom only
 * changes when a hop would clip the walk, or when a single node is too small
 * to read; a short trail at a comfortable zoom just pans.
 *
 * @param {{points: Array<{x?: number, y?: number, r?: number}>, width: number, height: number, minK: number, maxK: number, currentK: number, margin?: number, capK?: number}} opts
 * @returns {{x: number, y: number, k: number}|null}
 */
export function trailFocusTransform({
  points,
  width,
  height,
  minK,
  maxK,
  currentK,
  margin = 0.86,
  capK = 1.6
}) {
  const pts = (points || []).filter((p) => p && p.x != null && p.y != null);
  if (!pts.length) return null;
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const p of pts) {
    const pad = Math.max(p.r || 0, 4) * 1.35 + 18;
    if (p.x - pad < minX) minX = p.x - pad;
    if (p.y - pad < minY) minY = p.y - pad;
    if (p.x + pad > maxX) maxX = p.x + pad;
    if (p.y + pad > maxY) maxY = p.y + pad;
  }
  const bw = Math.max(maxX - minX, 1);
  const bh = Math.max(maxY - minY, 1);
  const cx = (minX + maxX) / 2;
  const cy = (minY + maxY) / 2;
  const fitK = margin * Math.min(width / bw, height / bh);
  const readableK = focusScale({
    currentK,
    nodeR: pts[pts.length - 1].r,
    minK,
    maxK,
    capK
  });
  const k = Math.max(minK, Math.min(readableK, fitK));
  return { x: width / 2 - k * cx, y: height / 2 - k * cy, k };
}

/** Screen pixels the pointer must move before a node press counts as a drag. */
export const NODE_CLICK_PX = 6;

/**
 * True when a pointer movement is large enough to treat as dragging a node
 * rather than a click. d3-drag otherwise reheats the layout on mousedown and
 * swallows the subsequent click.
 *
 * @param {number} dx
 * @param {number} dy
 * @param {number} [thresholdPx]
 * @returns {boolean}
 */
export function isDragGesture(dx, dy, thresholdPx = NODE_CLICK_PX) {
  return dx * dx + dy * dy >= thresholdPx * thresholdPx;
}
