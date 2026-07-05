import assert from 'node:assert/strict';
import test from 'node:test';

import { buildRelationshipIndexes, parseGraph } from '../src/parser/parser.js';
import { computeQualityReport } from '../src/lib/index.js';

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
  // relationship of any kind — should surface in every offender list.
  { type: 'software_Package', spdxId: 'pkg:bare', name: 'bare-lib' }
];

test('computeQualityReport flags a bare package across the offender lists and scores a documented one favorably', () => {
  const parsed = parseGraph(mixedGraph);
  const indexes = buildRelationshipIndexes(parsed.relationships);
  const report = computeQualityReport({ ...parsed, ...indexes });

  const { offenders, supplyChainConcentration } = report.insights;
  assert.deepEqual(
    offenders.missingLicense.sample.map((o) => o.id),
    ['pkg:other', 'pkg:bare']
  );
  assert.deepEqual(
    offenders.missingSupplier.sample.map((o) => o.id),
    ['pkg:other', 'pkg:bare']
  );
  assert.deepEqual(
    offenders.missingVersion.sample.map((o) => o.id),
    ['pkg:bare']
  );
  assert.deepEqual(
    offenders.orphans.sample.map((o) => o.id),
    ['pkg:bare']
  );

  // pkg:good's own relationships (its license + its dependsOn) keep it off the
  // orphan list even though nothing depends on it.
  assert.ok(!offenders.orphans.sample.some((o) => o.id === 'pkg:good'));

  assert.deepEqual(supplyChainConcentration, [
    { id: 'pkg:other', name: 'other-lib', dependents: 1 }
  ]);

  const ntia = report.categories.find((c) => c.key === 'ntia');
  assert.ok(ntia.score > 0 && ntia.score < 100);
  assert.ok(report.overall.score > 0 && report.overall.score < 100);
});

test('computeQualityReport gives a fully undocumented package a low grade', () => {
  const parsed = parseGraph([{ type: 'software_Package', spdxId: 'pkg:bare', name: 'bare-lib' }]);
  const indexes = buildRelationshipIndexes(parsed.relationships);
  const report = computeQualityReport({ ...parsed, ...indexes });

  assert.ok(report.overall.score < 50);
  assert.ok(['D', 'F'].includes(report.overall.grade));
  assert.equal(report.insights.offenders.missingLicense.total, 1);
});

test('computeQualityReport renormalizes category weights when a category has no applicable population', () => {
  const report = computeQualityReport({
    packages: [],
    files: [],
    licenses: [],
    vulnerabilities: [],
    creators: [{ id: 'agent:x', name: 'X', type: 'Person' }],
    createdDate: '2024-01-01T00:00:00Z',
    externalRefStats: { total: 4, resolved: 3, unresolved: 1 },
    relFromIndex: new Map(),
    relToIndex: new Map(),
    dependentIndex: new Map()
  });

  assert.deepEqual(
    report.categories.filter((c) => c.applicable).map((c) => c.key),
    ['ntia', 'structural']
  );
  // ntia = 100 (doc-level author+timestamp only, no packages to check),
  // structural = 75 (3/4 external refs resolved), weighted 0.3/0.1 -> 93.75.
  assert.equal(report.overall.score, 94);
});
