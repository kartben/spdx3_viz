/**
 * Graph layout catalogue and the pure graph maths the force renderer uses to
 * position nodes. Every layout ends up as a d3 force configuration in
 * graph-view.js; the parts that are plain graph algorithms (layer assignment,
 * BFS depth, lane ordering) live here so they stay DOM and d3 free, and testable.
 *
 * Each layout has a distinct job:
 *   - organic:   physics clustering, the open-ended default
 *   - hierarchy: layered top-down DAG following dependency direction
 *   - radial:    concentric rings out from the SBOM root elements
 *   - spotlight: final build artifacts pulled to the centre and enlarged
 *   - lanes:     vertical lanes bucketed by node type
 *
 * @module lib/graph-layout
 */

/**
 * The layouts offered in the graph toolbar's layout picker. `key` selects the
 * force configuration in graph-view.js; `icon` is an ICON_PATHS key; `hint` is
 * the one-line "when to use this" shown in the menu.
 *
 * @constant {Array<{key: string, label: string, short: string, icon: string, hint: string}>}
 */
export const GRAPH_LAYOUTS = [
  {
    key: 'organic',
    label: 'Organic (force)',
    short: 'Organic',
    icon: 'layout_organic',
    hint: 'Physics clustering: nodes repel, links pull them back. Best for open-ended exploration, where dense clusters and hub nodes surface on their own.'
  },
  {
    key: 'hierarchy',
    label: 'Hierarchy',
    short: 'Hierarchy',
    icon: 'layout_hierarchy',
    hint: 'Layers nodes by dependency depth, edges flowing top to bottom. Best for build pipelines and provenance: read what derives from what, sources up top.'
  },
  {
    key: 'radial',
    label: 'Radial',
    short: 'Radial',
    icon: 'layout_radial',
    hint: 'Rings outward from the SBOM root elements. Best for judging centrality: core components sit near the hub, incidental ones on the rim.'
  },
  {
    key: 'spotlight',
    label: 'Spotlight artifacts',
    short: 'Spotlight',
    icon: 'layout_spotlight',
    hint: 'Pulls final build outputs and distribution artifacts to the centre and enlarges them; the inputs that feed them orbit around. Best for "what did this build ship?".'
  },
  {
    key: 'lanes',
    label: 'Type lanes',
    short: 'Lanes',
    icon: 'layout_lanes',
    hint: 'Sorts nodes into vertical lanes by type. Best for inventory: compare at a glance how many packages, files, agents and tools the SBOM carries.'
  }
];

const LAYOUT_BY_KEY = new Map(GRAPH_LAYOUTS.map((l) => [l.key, l]));

/** The default layout key (physics clustering). */
export const DEFAULT_GRAPH_LAYOUT = 'organic';

/**
 * Metadata for a layout key, falling back to the organic default for an unknown
 * key so the toolbar always has a label/icon to show.
 *
 * @param {string} key
 * @returns {{key: string, label: string, short: string, icon: string, hint: string}}
 */
export function graphLayoutMeta(key) {
  return LAYOUT_BY_KEY.get(key) || LAYOUT_BY_KEY.get(DEFAULT_GRAPH_LAYOUT);
}

/**
 * Canonical column order for the "type lanes" layout: producers and build inputs
 * on the left, the artifacts they yield in the middle, and the people, licenses
 * and external references on the right. Types not listed here sort to the end in
 * a stable order, so an unknown/new node type still gets its own lane.
 */
const LANE_TYPE_ORDER = [
  'config',
  'tool',
  'build',
  'package',
  'ai',
  'dataset',
  'file',
  'snippet',
  'hardware',
  'supplychain',
  'requirement',
  'vulnerability',
  'agent',
  'license',
  'external'
];

/**
 * Orders a set/array of node types into stable lane columns: known types follow
 * {@link LANE_TYPE_ORDER}, any others keep their first-seen order after them.
 *
 * @param {Iterable<string>} types
 * @returns {string[]} Ordered, de-duplicated lane types
 */
export function orderLaneTypes(types) {
  const seen = [];
  const set = new Set();
  for (const t of types) {
    if (t != null && !set.has(t)) {
      set.add(t);
      seen.push(t);
    }
  }
  const rank = (t) => {
    const i = LANE_TYPE_ORDER.indexOf(t);
    return i === -1 ? LANE_TYPE_ORDER.length : i;
  };
  return (
    seen
      .map((t, i) => ({ t, i }))
      // Sort by canonical rank, keeping first-seen order within the same rank.
      .sort((a, b) => rank(a.t) - rank(b.t) || a.i - b.i)
      .map((e) => e.t)
  );
}

/**
 * Assigns each node a layer (0-based longest path from a source) for the
 * hierarchy layout. Edges are flow-directed [from, to] pairs; a node with no
 * incoming edge is a source at layer 0, and every other node sits one layer
 * below its deepest predecessor. Cycles (rare in an SBOM DAG) are broken by
 * ignoring the back edge, so the function always terminates.
 *
 * Iterative (Kahn longest-path) so a deep dependency chain can't overflow the
 * call stack.
 *
 * @param {Iterable<string>} nodeIds
 * @param {Array<[string, string]>} edges - flow-directed [from, to] pairs
 * @returns {Map<string, number>} id -> layer
 */
export function computeLayers(nodeIds, edges) {
  const ids = [...nodeIds];
  const idSet = new Set(ids);
  const out = new Map();
  const indeg = new Map();
  const preds = new Map();
  ids.forEach((id) => {
    out.set(id, []);
    indeg.set(id, 0);
    preds.set(id, []);
  });
  edges.forEach(([f, t]) => {
    if (f === t || !idSet.has(f) || !idSet.has(t)) return;
    out.get(f).push(t);
    preds.get(t).push(f);
    indeg.set(t, indeg.get(t) + 1);
  });

  const layer = new Map(ids.map((id) => [id, 0]));
  const rem = new Map(indeg);
  const order = ids.filter((id) => rem.get(id) === 0);
  for (let head = 0; head < order.length; head++) {
    const u = order[head];
    const lu = layer.get(u);
    for (const v of out.get(u)) {
      if (layer.get(v) < lu + 1) layer.set(v, lu + 1);
      rem.set(v, rem.get(v) - 1);
      if (rem.get(v) === 0) order.push(v);
    }
  }
  // Any node still unresolved sits on a cycle Kahn never drained. Relax it a few
  // times against its predecessors so it lands below them rather than at layer 0.
  const stuck = ids.filter((id) => rem.get(id) > 0);
  for (let pass = 0; pass < 4 && stuck.length; pass++) {
    stuck.forEach((id) => {
      let best = layer.get(id);
      for (const p of preds.get(id)) best = Math.max(best, layer.get(p) + 1);
      layer.set(id, best);
    });
  }
  return layer;
}

/**
 * Breadth-first depth of every node from a set of roots, over an undirected
 * adjacency map. Nodes unreachable from any root (or with no root at all) are
 * placed one ring beyond the deepest reached node, so a disconnected fringe
 * still lands on the outer rim rather than the centre.
 *
 * @param {Iterable<string>} nodeIds
 * @param {Map<string, Iterable<string>>} adjacency - id -> neighbour ids
 * @param {Iterable<string>} roots
 * @returns {Map<string, number>} id -> depth
 */
export function bfsDepths(nodeIds, adjacency, roots) {
  const ids = [...nodeIds];
  const idSet = new Set(ids);
  const depth = new Map();
  const queue = [];
  for (const r of roots) {
    if (idSet.has(r) && !depth.has(r)) {
      depth.set(r, 0);
      queue.push(r);
    }
  }
  let head = 0;
  let maxDepth = 0;
  while (head < queue.length) {
    const u = queue[head++];
    const du = depth.get(u);
    if (du > maxDepth) maxDepth = du;
    const neighbours = adjacency.get(u);
    if (!neighbours) continue;
    for (const v of neighbours) {
      if (idSet.has(v) && !depth.has(v)) {
        depth.set(v, du + 1);
        queue.push(v);
      }
    }
  }
  const outer = queue.length ? maxDepth + 1 : 0;
  ids.forEach((id) => {
    if (!depth.has(id)) depth.set(id, outer);
  });
  return depth;
}
