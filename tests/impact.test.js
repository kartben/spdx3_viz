import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildImpactAdjacency,
  provenancePaths,
  blastRadius,
  impactEdgeVerb,
  IMPACT_EDGE_TYPES
} from '../src/lib/impact.js';

// root R contains A and B; A and B both dependsOn L; L dependsOn C.
// R also has an OPTIONAL component P. X<->Y form a dependency cycle with no root.
const rels = [
  { relationshipType: 'contains', from: 'R', to: ['A', 'B'] },
  { relationshipType: 'dependsOn', from: 'A', to: ['L'] },
  { relationshipType: 'dependsOn', from: 'B', to: ['L'] },
  { relationshipType: 'dependsOn', from: 'L', to: ['C'] },
  { relationshipType: 'hasOptionalComponent', from: 'R', to: ['P'] },
  { relationshipType: 'dependsOn', from: 'P', to: ['L'] },
  { relationshipType: 'dependsOn', from: 'X', to: ['Y'] },
  { relationshipType: 'dependsOn', from: 'Y', to: ['X'] },
  // Non-dependency edges must be ignored by the impact adjacency.
  { relationshipType: 'hasConcludedLicense', from: 'A', to: ['lic:mit'] },
  { relationshipType: 'hasOutput', from: 'build', to: ['A'] }
];

const graph = () => {
  const { childIndex, parentIndex } = buildImpactAdjacency(rels);
  return { childIndex, parentIndex, roots: new Set(['R']) };
};

test('buildImpactAdjacency only includes dependency/containment edges', () => {
  const { childIndex, parentIndex } = buildImpactAdjacency(rels);
  assert.deepEqual(
    childIndex.get('R').map((e) => e.id),
    ['A', 'B', 'P']
  );
  // License and build-output edges are excluded.
  assert.equal(childIndex.has('build'), false);
  assert.equal(parentIndex.has('lic:mit'), false);
  // Optional edges are flagged soft.
  assert.equal(childIndex.get('R').find((e) => e.id === 'P').soft, true);
  assert.equal(childIndex.get('R').find((e) => e.id === 'A').soft, false);
});

test('provenancePaths finds shortest root→element paths and prefers required edges', () => {
  const g = graph();
  const prov = provenancePaths('L', g);
  assert.equal(prov.reachable, true);
  assert.equal(prov.hops, 2);
  // Three 2-hop paths reach L: R→A→L, R→B→L, and R⇢P→L (optional).
  assert.equal(prov.paths.length, 3);
  // The primary path must be all-required (no optional hop).
  assert.equal(
    prov.paths[0].some((h) => h.soft),
    false
  );
  // Each path starts at the root and ends at the target.
  for (const path of prov.paths) {
    assert.equal(path[0].id, 'R');
    assert.equal(path[0].rel, null);
    assert.equal(path[path.length - 1].id, 'L');
  }
});

test('provenancePaths flags a root, an optional-only hop, and an unreachable node', () => {
  const g = graph();
  assert.equal(provenancePaths('R', g).isRoot, true);
  // C is deeper: R→A→L→C (3 hops).
  assert.equal(provenancePaths('C', g).hops, 3);
  // The optional hop carries the relationship type and soft flag.
  const pPath = provenancePaths('P', g).paths[0];
  assert.equal(pPath[1].id, 'P');
  assert.equal(pPath[1].rel, 'hasOptionalComponent');
  assert.equal(pPath[1].soft, true);
  // X is in a cycle with no path to a root.
  assert.equal(provenancePaths('X', g).reachable, false);
});

test('blastRadius returns direct + transitive dependents and terminates on cycles', () => {
  const { parentIndex } = buildImpactAdjacency(rels);
  const br = blastRadius('L', { parentIndex });
  // Directly depended on by A, B, and (optionally) P.
  assert.deepEqual(br.direct.map((d) => d.id).sort(), ['A', 'B', 'P']);
  // Transitively, R depends on L (contains A/B) — P has no dependents.
  assert.deepEqual([...br.nodes].sort(), ['A', 'B', 'P', 'R']);
  assert.equal(br.total, 4);
  assert.equal(br.truncated, false);

  // Cyclic X↔Y still terminates.
  const cyc = blastRadius('X', { parentIndex });
  assert.deepEqual([...cyc.nodes].sort(), ['Y']);
});

test('blastRadius honors the visited cap', () => {
  const { parentIndex } = buildImpactAdjacency(rels);
  const capped = blastRadius('L', { parentIndex }, { cap: 1 });
  assert.equal(capped.truncated, true);
  assert.ok(capped.total <= 1);
});

test('impactEdgeVerb and IMPACT_EDGE_TYPES cover the cross-topology edge set', () => {
  assert.equal(impactEdgeVerb('hasStaticLink'), 'statically links');
  assert.equal(impactEdgeVerb('contains'), 'contains');
  assert.ok(IMPACT_EDGE_TYPES.has('dependsOn'));
  assert.ok(IMPACT_EDGE_TYPES.has('hasDynamicLink'));
  // Build-lineage edges are deliberately excluded.
  assert.equal(IMPACT_EDGE_TYPES.has('hasOutput'), false);
  assert.equal(IMPACT_EDGE_TYPES.has('generates'), false);
});
