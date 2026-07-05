/**
 * Impact analysis: dependency-graph reachability over the SPDX relationship
 * types that express "A relies on / includes B". Powers the provenance path
 * ("why is this here?") and the blast radius ("what depends on it?") — both a
 * breadth-first walk over a directed edge set that spans the different
 * topologies real SBOMs use (dependsOn, containment, static/dynamic linking).
 *
 * @module lib/impact
 */

/**
 * Relationship types traversed as a directed dependency edge (`from` relies on
 * or includes `to`). Deliberately spans ecosystems: npm/deb use `dependsOn`,
 * OS-image SBOMs use `contains`, Android uses `hasStaticLink`, Maven uses
 * `hasDynamicLink`. Build-lineage edges (hasInput/hasOutput/generates) are
 * intentionally excluded — those describe how an artifact was produced, not
 * what a component depends on.
 * @type {Set<string>}
 */
export const IMPACT_EDGE_TYPES = new Set([
  'dependsOn',
  'contains',
  'hasStaticLink',
  'hasDynamicLink',
  'hasOptionalComponent',
  'hasProvidedDependency',
  'hasPrerequisite',
  'hasDistributionArtifact'
]);

// Optional/provided edges are real but not hard runtime requirements — traversed
// so nothing is missed, but flagged so paths through them can be de-prioritized.
const SOFT_EDGE_TYPES = new Set(['hasOptionalComponent', 'hasProvidedDependency']);

const EDGE_VERB = {
  dependsOn: 'depends on',
  contains: 'contains',
  hasStaticLink: 'statically links',
  hasDynamicLink: 'dynamically links',
  hasOptionalComponent: 'optional component',
  hasProvidedDependency: 'provided dependency',
  hasPrerequisite: 'prerequisite',
  hasDistributionArtifact: 'distributed as'
};

/**
 * Human-readable verb for a dependency edge, used to label each provenance hop.
 *
 * @param {string} rel - relationshipType
 * @returns {string}
 */
export function impactEdgeVerb(rel) {
  return EDGE_VERB[rel] || rel || 'relates to';
}

function pushInto(map, key, value) {
  let arr = map.get(key);
  if (!arr) {
    arr = [];
    map.set(key, arr);
  }
  arr.push(value);
}

/**
 * Builds the directed impact adjacency from the relationship list.
 *
 * @param {Array<Object>} relationships - parsed relationship elements
 * @returns {{childIndex: Map<string, Array<{id: string, rel: string, soft: boolean}>>, parentIndex: Map<string, Array<{id: string, rel: string, soft: boolean}>>}}
 *   childIndex: `from` → the elements it relies on; parentIndex: `to` → the
 *   elements that rely on it.
 */
export function buildImpactAdjacency(relationships) {
  const childIndex = new Map();
  const parentIndex = new Map();
  for (const rel of relationships || []) {
    const type = rel?.relationshipType;
    if (!IMPACT_EDGE_TYPES.has(type)) continue;
    const from = rel.from;
    if (!from) continue;
    const soft = SOFT_EDGE_TYPES.has(type);
    const targets = Array.isArray(rel.to) ? rel.to : [rel.to];
    for (const to of targets) {
      if (!to) continue;
      pushInto(childIndex, from, { id: to, rel: type, soft });
      pushInto(parentIndex, to, { id: from, rel: type, soft });
    }
  }
  return { childIndex, parentIndex };
}

/**
 * @typedef {Object} ProvenanceHop
 * @property {string} id - element spdxId at this hop
 * @property {string|null} rel - the edge type from the previous hop into this one (null for the root)
 * @property {boolean} soft - whether that edge is an optional/provided dependency
 */

/**
 * Shortest provenance path(s) from a document root down to `target`, over the
 * dependency edge set. Answers "why is this here?".
 *
 * @param {string} target - element spdxId
 * @param {{childIndex: Map, parentIndex: Map, roots: Set<string>}} graph
 * @param {{maxPaths?: number}} [opts]
 * @returns {{reachable: boolean, isRoot?: boolean, hops?: number, paths?: ProvenanceHop[][]}}
 *   `paths` are ordered root→target; the first is a shortest, all-required path
 *   when one exists. Empty when the element is a root or unreachable.
 */
export function provenancePaths(target, { childIndex, parentIndex, roots }, opts = {}) {
  if (roots.has(target)) return { reachable: true, isRoot: true, hops: 0, paths: [] };
  const maxPaths = opts.maxPaths ?? 6;

  // Reverse BFS from the target over parent edges; stop at the nearest root.
  const dist = new Map([[target, 0]]);
  const queue = [target];
  let nearestRoot = null;
  let head = 0;
  while (head < queue.length) {
    const node = queue[head++];
    if (roots.has(node)) {
      nearestRoot = node;
      break;
    }
    const d = dist.get(node);
    for (const parent of parentIndex.get(node) || []) {
      if (!dist.has(parent.id)) {
        dist.set(parent.id, d + 1);
        queue.push(parent.id);
      }
    }
  }
  if (nearestRoot === null) return { reachable: false, paths: [] };

  // Reconstruct shortest paths root→target: follow child edges whose distance
  // (to the target) strictly decreases, collecting the edge type at each step.
  const paths = [];
  const walk = (node, acc) => {
    if (paths.length >= maxPaths) return;
    if (node === target) {
      paths.push(acc.slice());
      return;
    }
    const d = dist.get(node);
    for (const child of childIndex.get(node) || []) {
      if (dist.get(child.id) === d - 1) {
        acc.push({ id: child.id, rel: child.rel, soft: child.soft });
        walk(child.id, acc);
        acc.pop();
        if (paths.length >= maxPaths) return;
      }
    }
  };
  walk(nearestRoot, [{ id: nearestRoot, rel: null, soft: false }]);

  // All-required paths first, so the primary path avoids optional edges when it can.
  paths.sort((a, b) => Number(a.some((h) => h.soft)) - Number(b.some((h) => h.soft)));
  return { reachable: true, hops: dist.get(nearestRoot), paths };
}

/**
 * The blast radius of `target`: every element that (transitively) depends on it.
 * Answers "what breaks if this is compromised or removed?".
 *
 * @param {string} target - element spdxId
 * @param {{parentIndex: Map}} graph
 * @param {{cap?: number}} [opts] - visited cap for pathological hubs
 * @returns {{direct: Array<{id: string, soft: boolean}>, total: number, nodes: Set<string>, truncated: boolean}}
 */
export function blastRadius(target, { parentIndex }, opts = {}) {
  const cap = opts.cap ?? 20000;
  const direct = [];
  const directSeen = new Set();
  for (const parent of parentIndex.get(target) || []) {
    if (!directSeen.has(parent.id)) {
      directSeen.add(parent.id);
      direct.push({ id: parent.id, soft: parent.soft });
    }
  }
  const seen = new Set();
  const queue = [target];
  let head = 0;
  let truncated = false;
  while (head < queue.length) {
    const node = queue[head++];
    for (const parent of parentIndex.get(node) || []) {
      if (seen.has(parent.id)) continue;
      if (seen.size >= cap) {
        truncated = true;
        continue;
      }
      seen.add(parent.id);
      queue.push(parent.id);
    }
  }
  seen.delete(target);
  return { direct, total: seen.size, nodes: seen, truncated };
}
