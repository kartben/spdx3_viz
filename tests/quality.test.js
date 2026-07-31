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
  // ntia = 6/7 ≈ 85.7: with no packages the four component elements pass
  // vacuously and author + timestamp pass, but no dependency relationship is
  // asserted. structural = 75 (3/4 external refs resolved). Weighted 0.3/0.1:
  // (85.71*0.3 + 75*0.1) / 0.4 ≈ 83.
  assert.equal(report.overall.score, 83);
});

test('computeQualityReport builds a detailed NTIA report mirroring the reference tool', () => {
  const parsed = parseGraph(mixedGraph);
  const indexes = buildRelationshipIndexes(parsed.relationships);
  const { ntia } = computeQualityReport({ ...parsed, ...indexes });

  const el = Object.fromEntries([...ntia.elements, ...ntia.fsct].map((e) => [e.key, e]));

  assert.equal(ntia.totalComponents, 3);
  assert.equal(ntia.isConformant, false);

  // Component-level coverage.
  assert.equal(el.name.missing.total, 0);
  assert.deepEqual(
    el.version.missing.sample.map((o) => o.id),
    ['pkg:bare']
  );
  assert.deepEqual(
    el.supplier.missing.sample.map((o) => o.id),
    ['pkg:other', 'pkg:bare']
  );
  assert.equal(el.identifier.covered, 1); // only pkg:good has a PURL

  // Document-level: a dependsOn relationship exists, but this fixture has no
  // creator or timestamp.
  assert.equal(el.dependency.present, true);
  assert.equal(el.author.present, false);
  assert.equal(el.timestamp.present, false);

  // CISA FSCT3 extension: only the fully documented package has license +
  // copyright.
  assert.equal(el.concludedLicense.covered, 1);
  assert.equal(el.copyrightText.covered, 1);
});

test('computeQualityReport builds a CISA 2026 minimum-elements report', () => {
  const graph = [
    {
      type: 'SpdxDocument',
      spdxId: 'doc:1',
      name: 'demo',
      creationInfo: 'ci:1',
      profileConformance: ['core', 'software']
    },
    {
      type: 'CreationInfo',
      '@id': 'ci:1',
      created: '2026-07-01T00:00:00Z',
      createdBy: ['agent:author'],
      createdUsing: ['tool:gen'],
      specVersion: '3.0.1'
    },
    { type: 'Organization', spdxId: 'agent:author', name: 'Example Org', creationInfo: 'ci:1' },
    { type: 'Tool', spdxId: 'tool:gen', name: 'Example SBOM Tool 1.2.3', creationInfo: 'ci:1' },
    {
      type: 'software_Sbom',
      spdxId: 'sbom:1',
      name: 'demo-sbom',
      software_sbomType: ['build'],
      creationInfo: 'ci:1',
      rootElement: ['pkg:good']
    },
    {
      type: 'software_Package',
      spdxId: 'pkg:good',
      name: 'good-lib',
      software_packageVersion: '1.2.3',
      software_packageUrl: 'pkg:npm/good-lib@1.2.3',
      suppliedBy: 'agent:author',
      verifiedUsing: [{ type: 'Hash', algorithm: 'sha256', hashValue: 'abc123' }],
      creationInfo: 'ci:1'
    },
    {
      type: 'software_Package',
      spdxId: 'pkg:bare',
      name: 'bare-lib',
      creationInfo: 'ci:1'
    },
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
      to: ['pkg:bare']
    }
  ];

  const parsed = parseGraph(graph);
  const indexes = buildRelationshipIndexes(parsed.relationships);
  const { cisa2026 } = computeQualityReport({ ...parsed, ...indexes });

  assert.equal(cisa2026.isConformant, false);
  assert.ok(cisa2026.referenceUrl.includes('cisa.gov'));
  assert.ok(cisa2026.pdfUrl.endsWith('.pdf'));

  const meta = Object.fromEntries(cisa2026.metadata.map((e) => [e.key, e]));
  assert.equal(meta.author.status, 'pass');
  assert.equal(meta.authorSignature.status, 'warn');
  assert.equal(meta.formatName.status, 'pass');
  assert.equal(meta.formatVersion.status, 'pass');
  assert.equal(meta.generationContext.status, 'pass');
  assert.equal(meta.generationContext.detail, 'build');
  assert.equal(meta.timestamp.status, 'pass');
  assert.equal(meta.toolName.status, 'pass');
  assert.equal(meta.toolVersion.status, 'pass');
  assert.equal(meta.sbomVersion.status, 'na');

  const comp = Object.fromEntries(cisa2026.component.map((e) => [e.key, e]));
  assert.equal(comp.name.missing.total, 0);
  assert.equal(comp.producer.missing.total, 1);
  assert.deepEqual(
    comp.version.missing.sample.map((o) => o.id),
    ['pkg:bare']
  );
  assert.equal(comp.hashValue.missing.total, 1);
  assert.equal(comp.hashAlgorithm.missing.total, 1);
  assert.equal(comp.license.covered, 1);
  assert.equal(comp.dependency.present, true);

  const practices = Object.fromEntries(cisa2026.practices.map((e) => [e.key, e]));
  assert.equal(practices.machineProcessable.status, 'pass');
  assert.equal(practices.coverage.status, 'na');
  assert.equal(practices.explicitUnknowns.status, 'partial');

  assert.equal(
    meta.author.definition,
    'The name of the entity that creates the SBOM data for the target component.'
  );
  assert.equal(
    comp.hashValue.definition,
    'The output generated from applying a cryptographic hash algorithm to an executable component artifact.'
  );
  assert.match(
    practices.explicitUnknowns.definition,
    /explicitly state whether the information is unknown/
  );
});

test('CISA 2026 treats explicit unknown hash and version as covered', () => {
  const report = computeQualityReport({
    packages: [
      {
        type: 'software_Package',
        spdxId: 'pkg:1',
        name: 'lib',
        software_packageVersion: 'NOASSERTION',
        suppliedBy: 'agent:x',
        software_packageUrl: 'pkg:generic/lib@unknown',
        verifiedUsing: [{ type: 'Hash', algorithm: 'sha256', hashValue: 'NOASSERTION' }]
      }
    ],
    files: [],
    licenses: [
      {
        id: 'lic:na',
        label: 'NoAssertion',
        declaredBy: ['pkg:1'],
        concludedBy: []
      }
    ],
    creators: [{ id: 'agent:x', name: 'X', type: 'Organization' }],
    creatorTools: [{ id: 'tool:1', name: 'Tool 9.0', type: 'Tool' }],
    createdDate: '2026-01-01T00:00:00Z',
    specVersion: '3.0.1',
    sbomTypes: ['source'],
    relationships: [{ relationshipType: 'dependsOn', from: 'pkg:1', to: ['pkg:1'] }],
    elementMap: new Map(),
    tools: [],
    builds: [],
    profileConformance: [],
    relFromIndex: new Map(),
    relToIndex: new Map(),
    dependentIndex: new Map()
  });

  const comp = Object.fromEntries(report.cisa2026.component.map((e) => [e.key, e]));
  assert.equal(comp.version.missing.total, 0);
  assert.equal(comp.hashValue.missing.total, 0);
  assert.equal(comp.hashAlgorithm.missing.total, 0);
  assert.equal(comp.license.missing.total, 0);
  assert.equal(report.cisa2026.practices.find((p) => p.key === 'explicitUnknowns').status, 'pass');
});
