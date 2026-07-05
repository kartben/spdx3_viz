import assert from 'node:assert/strict';
import test from 'node:test';

import { buildRelationshipIndexes, parseGraph } from '../src/parser/parser.js';
import { computeQualityReport } from '../src/lib/index.js';

const report = (graph) => {
  const parsed = parseGraph(graph);
  const indexes = buildRelationshipIndexes(parsed.relationships);
  return computeQualityReport({ ...parsed, ...indexes });
};

const improvement = (rep, key) => rep.improvements.find((i) => i.key === key);

const mixedGraph = [
  {
    type: 'software_Package',
    spdxId: 'pkg:good',
    name: 'good-lib',
    software_packageVersion: '1.2.3',
    software_packageUrl: 'pkg:npm/good-lib@1.2.3',
    suppliedBy: 'agent:acme',
    software_copyrightText: 'Copyright 2024 Acme',
    verifiedUsing: [{ type: 'Hash', algorithm: 'sha256', hashValue: 'abc123' }]
  },
  { type: 'Person', spdxId: 'agent:acme', name: 'Acme Corp' },
  {
    type: 'simplelicensing_LicenseExpression',
    spdxId: 'lic:mit',
    simplelicensing_licenseExpression: 'MIT'
  },
  {
    type: 'Relationship',
    spdxId: 'rel:license',
    relationshipType: 'hasDeclaredLicense',
    from: 'pkg:good',
    to: ['lic:mit']
  },
  {
    type: 'Relationship',
    spdxId: 'rel:dep',
    relationshipType: 'dependsOn',
    from: 'pkg:good',
    to: ['pkg:other']
  },
  {
    type: 'software_Package',
    spdxId: 'pkg:other',
    name: 'other-lib',
    software_packageVersion: '2.0'
  },
  // Bare package: no version, supplier, identifier, copyright, hash, or
  // relationship of any kind — should surface in every improvement's offenders.
  { type: 'software_Package', spdxId: 'pkg:bare', name: 'bare-lib' }
];

test('computeQualityReport flags a bare package across the improvement offenders', () => {
  const rep = report(mixedGraph);

  assert.deepEqual(
    improvement(rep, 'license').sample.map((o) => o.id),
    ['pkg:other', 'pkg:bare']
  );
  assert.deepEqual(
    improvement(rep, 'supplier').sample.map((o) => o.id),
    ['pkg:other', 'pkg:bare']
  );
  assert.deepEqual(
    improvement(rep, 'version').sample.map((o) => o.id),
    ['pkg:bare']
  );
  assert.deepEqual(
    improvement(rep, 'orphans').sample.map((o) => o.id),
    ['pkg:bare']
  );
  // pkg:good's own relationships (its license + its dependsOn) keep it off the
  // orphan list even though nothing depends on it.
  assert.ok(!improvement(rep, 'orphans').sample.some((o) => o.id === 'pkg:good'));

  const ntia = rep.categories.find((c) => c.key === 'ntia');
  assert.ok(ntia.score > 0 && ntia.score < 100);
  assert.ok(rep.overall.score > 0 && rep.overall.score < 100);
});

test('improvements are ranked by score gain and each gain is non-negative', () => {
  const rep = report(mixedGraph);
  assert.ok(rep.improvements.length > 0);
  for (let i = 1; i < rep.improvements.length; i++) {
    assert.ok(rep.improvements[i - 1].gain >= rep.improvements[i].gain);
  }
  rep.improvements.forEach((im) => {
    assert.ok(im.gain >= 0);
    assert.ok(im.count > 0);
  });
});

test('computeQualityReport gives a fully undocumented package a low grade', () => {
  const rep = report([{ type: 'software_Package', spdxId: 'pkg:bare', name: 'bare-lib' }]);

  assert.ok(rep.overall.score < 50);
  assert.ok(['D', 'F'].includes(rep.overall.grade));
  assert.equal(improvement(rep, 'license').count, 1);
});

test('file-level licensing credits the License category when packages are NoAssertion', () => {
  // A module package that declares NoAssertion, but whose contained file carries
  // a real license — the pattern in the Zephyr SBOM. The License category must
  // not collapse to ~0 just because the package node is unlicensed.
  const graph = [
    { type: 'software_Package', spdxId: 'pkg:mod', name: 'mod' },
    { type: 'software_File', spdxId: 'file:a', name: 'a.c' },
    { type: 'software_File', spdxId: 'file:b', name: 'b.c' },
    {
      type: 'simplelicensing_LicenseExpression',
      spdxId: 'lic:apache',
      simplelicensing_licenseExpression: 'Apache-2.0'
    },
    {
      type: 'Relationship',
      relationshipType: 'contains',
      from: 'pkg:mod',
      to: ['file:a', 'file:b']
    },
    {
      type: 'Relationship',
      relationshipType: 'hasConcludedLicense',
      from: 'file:a',
      to: ['lic:apache']
    },
    {
      type: 'Relationship',
      relationshipType: 'hasConcludedLicense',
      from: 'file:b',
      to: ['lic:apache']
    }
  ];
  const rep = report(graph);
  const license = rep.categories.find((c) => c.key === 'license');
  // Both files are licensed -> file-level license coverage is 100%, so the
  // category (license 60% + copyright 40%) is at least the license weight.
  assert.ok(license.score >= 55, `expected file-level credit, got ${license.score}`);
});

test('computeQualityReport renormalizes category weights when a category has no applicable population', () => {
  const rep = computeQualityReport({
    packages: [],
    files: [],
    licenses: [],
    creators: [{ id: 'agent:x', name: 'X', type: 'Person' }],
    createdDate: '2024-01-01T00:00:00Z',
    externalRefStats: { total: 4, resolved: 3, unresolved: 1 },
    relFromIndex: new Map(),
    relToIndex: new Map()
  });

  assert.deepEqual(
    rep.categories.filter((c) => c.applicable).map((c) => c.key),
    ['ntia', 'structural']
  );
  // ntia = 100 (doc-level author+timestamp only, no packages to check),
  // structural = 75 (3/4 external refs resolved), weighted 0.3/0.1 -> 93.75.
  assert.equal(rep.overall.score, 94);
  // The one unresolved reference is surfaced as a count-only improvement.
  assert.equal(improvement(rep, 'refs').count, 1);
});
