import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

import { buildRelationshipIndexes, parseGraph } from '../src/parser/parser.js';
import {
  parseBuildParameters,
  extractLicenseExpressionParts,
  renderLicenseExpression,
  getVulnerabilityId,
  getVexStatusMeta,
  getVexJustificationLabel,
  parseCpe,
  getVulnerabilityLookup,
  getPurlLink,
  getExternalIdentifiers,
  buildShareHash,
  parseShareHash,
  summarizeCveRecord,
  summarizeVulnAssessments,
  cvssSeverityForScore,
  getCvssSeverityMeta,
  getCdxProperties,
  getRelationshipColor,
  getRelationshipGroupLabel
} from '../src/lib/index.js';
import { spdxApp } from '../src/app.js';

const fixtureGraph = [
  { type: 'software_Package', spdxId: 'pkg:kernel', name: 'Kernel' },
  { type: 'build_Build', spdxId: 'build:root', build_buildId: 'root-build' },
  { type: 'build_Build', spdxId: 'build:compile', build_buildId: 'compile-step' },
  { type: 'build_Build', spdxId: 'build:link', build_buildId: 'link-step' },
  { type: 'software_File', spdxId: 'file:src1', name: 'init/main.c' },
  { type: 'software_File', spdxId: 'file:src2', name: 'kernel/sched.c' },
  { type: 'software_File', spdxId: 'file:obj1', name: 'init/main.o' },
  { type: 'software_File', spdxId: 'file:image', name: 'arch/x86/boot/bzImage' },
  { type: 'software_File', spdxId: 'file:dist', name: 'vmlinux' },
  {
    type: 'Relationship',
    spdxId: 'rel:ancestor',
    relationshipType: 'ancestorOf',
    from: 'build:root',
    to: ['build:compile', 'build:link']
  },
  {
    type: 'Relationship',
    spdxId: 'rel:inputs',
    relationshipType: 'hasInput',
    from: 'build:compile',
    to: ['file:src1', 'file:src2', 'missing:generated-header']
  },
  {
    type: 'Relationship',
    spdxId: 'rel:outputs',
    relationshipType: 'hasOutput',
    from: 'build:compile',
    to: ['file:obj1', 'missing:object']
  },
  {
    type: 'Relationship',
    spdxId: 'rel:generates',
    relationshipType: 'generates',
    from: 'build:link',
    to: ['file:image']
  },
  {
    type: 'Relationship',
    spdxId: 'rel:dist',
    relationshipType: 'hasDistributionArtifact',
    from: 'pkg:kernel',
    to: ['file:dist']
  }
];

test('parseGraph keeps all builds and selects an ancestor root as buildInfo', () => {
  const parsed = parseGraph(fixtureGraph);

  assert.equal(parsed.builds.length, 3);
  assert.equal(parsed.buildInfo.spdxId, 'build:root');
  assert.deepEqual(parsed.generatedArtifacts, ['file:obj1', 'missing:object', 'file:image']);
});

test('buildRelationshipIndexes indexes SPDX build relationships and unresolved endpoints', () => {
  const parsed = parseGraph(fixtureGraph);
  const indexes = buildRelationshipIndexes(parsed.relationships);

  assert.deepEqual(indexes.buildStepIndex.get('build:root'), ['build:compile', 'build:link']);
  assert.deepEqual(indexes.parentBuildIndex.get('build:compile'), ['build:root']);

  assert.deepEqual(indexes.buildInputIndex.get('build:compile'), [
    'file:src1',
    'file:src2',
    'missing:generated-header'
  ]);
  assert.deepEqual(indexes.consumedByBuildIndex.get('missing:generated-header'), ['build:compile']);

  assert.deepEqual(indexes.buildOutputIndex.get('build:compile'), ['file:obj1', 'missing:object']);
  assert.deepEqual(indexes.buildOutputIndex.get('build:link'), ['file:image']);
  assert.deepEqual(indexes.producedByBuildIndex.get('file:image'), ['build:link']);
  assert.deepEqual(
    indexes.relToIndex.get('missing:object').map((rel) => rel.spdxId),
    ['rel:outputs']
  );

  assert.deepEqual(indexes.distributionArtifactIndex.get('pkg:kernel'), ['file:dist']);
  assert.deepEqual(indexes.distributedByIndex.get('file:dist'), ['pkg:kernel']);
});

test('parseGraph categorizes SPDX 3.1 SupplyChain actions, processes, and states', () => {
  const graph = JSON.parse(
    readFileSync('public/samples/supply-chain/arborlink-sg1-supply-chain.spdx3.jsonld', 'utf8')
  )['@graph'];
  const parsed = parseGraph(graph);
  const indexes = buildRelationshipIndexes(parsed.relationships);

  assert.equal(parsed.profileConformance.includes('supplyChain'), true);
  assert.equal(parsed.supplyChain.length, 48);
  assert.equal(parsed.supplyChain.filter((el) => el.type.endsWith('Action')).length, 25);
  assert.equal(parsed.supplyChain.filter((el) => el.type.endsWith('Process')).length, 14);
  assert.equal(parsed.supplyChain.filter((el) => el.type === 'supplychain_State').length, 9);
  assert.equal(parsed.presentNodeTypes.includes('supplychain'), true);
  assert.equal(parsed.presentRelTypes.includes('resolved'), true);
  assert.equal(parsed.presentRelTypes.includes('hasResolution'), true);

  const transport = parsed.supplyChain.find((el) => el.type === 'supplychain_TransportAction');
  assert.ok(transport.supplychain_pickupLocation);
  assert.ok(transport.supplychain_dropoffLocation);

  const resolution = parsed.supplyChain.find((el) => el.type === 'supplychain_ResolutionAction');
  assert.deepEqual(
    indexes.relFromIndex.get(resolution.spdxId).map((rel) => rel.relationshipType),
    ['performedBy', 'resolved', 'hasResolution', 'affects', 'hasRequirement', 'hasEvidence']
  );
});

test('SupplyChain sample embeds LicenseRef-Arbor-Proprietary text', async () => {
  const graph = JSON.parse(
    readFileSync('public/samples/supply-chain/arborlink-sg1-supply-chain.spdx3.jsonld', 'utf8')
  )['@graph'];
  const parsed = parseGraph(graph);
  const indexes = buildRelationshipIndexes(parsed.relationships);
  const app = spdxApp();
  Object.assign(app, parsed, indexes);

  const proprietaryLicenseId =
    'https://spdx.org/spdxdocs/arborlink-sg1-2026.07-supply-chain#license/proprietary';
  const proprietaryTextId =
    'https://spdx.org/spdxdocs/arborlink-sg1-2026.07-supply-chain#license/text/arbor-proprietary';
  const proprietaryLicense = app.elementMap.get(proprietaryLicenseId);
  const proprietaryText = app.elementMap.get(proprietaryTextId);

  assert.equal(app.licenseExpressionFor(proprietaryLicenseId), 'LicenseRef-Arbor-Proprietary');
  assert.deepEqual(proprietaryLicense.simplelicensing_customIdToUri, [
    {
      type: 'DictionaryEntry',
      key: 'LicenseRef-Arbor-Proprietary',
      value: proprietaryTextId
    }
  ]);
  assert.equal(proprietaryText.type, 'simplelicensing_SimpleLicensingText');
  assert.match(
    proprietaryText.simplelicensing_licenseText,
    /Arbor Devices Proprietary Firmware License/
  );

  await app.showLicenseText(proprietaryLicenseId);
  assert.equal(app.licenseModalParts.length, 1);
  assert.equal(app.licenseModalParts[0].kind, 'inline');
  assert.equal(app.licenseModalParts[0].loaded, true);
  assert.match(app.licenseModalText(), /Redistribution, reverse engineering, sublicensing/);
});

test('SupplyChain view model exposes lifecycle, custody, and exception structures', () => {
  const graph = JSON.parse(
    readFileSync('public/samples/supply-chain/arborlink-sg1-supply-chain.spdx3.jsonld', 'utf8')
  )['@graph'];
  const parsed = parseGraph(graph);
  const indexes = buildRelationshipIndexes(parsed.relationships);
  const app = spdxApp();
  Object.assign(app, parsed, indexes);

  assert.deepEqual(app.supplyChainCounts, {
    actions: 25,
    processes: 14,
    states: 9,
    transports: 2,
    custody: 2,
    inspections: 1,
    tests: 1,
    exceptions: 1,
    resolutions: 1
  });

  assert.deepEqual(
    app.supplyChainStateTransitions.map((row) => [
      row.action.name,
      row.previous?.name || null,
      row.state?.name || null,
      row.decisionProcess?.name || null
    ]),
    [
      [
        'Mark device firmware provisioned',
        null,
        'Firmware provisioned',
        'Factory provisioning process'
      ],
      [
        'Place SG-1 in out-of-spec quarantine',
        'Firmware provisioned',
        'Out-of-spec quarantine',
        'Quarantine decision process'
      ],
      [
        'Mark SG-1 accepted for deployment',
        'Out-of-spec quarantine',
        'Accepted for deployment',
        'Quarantine decision process'
      ],
      [
        'Mark SG-1 deployed with retirement plan',
        'Accepted for deployment',
        'Deployed',
        'Decommissioning plan process'
      ]
    ]
  );

  assert.deepEqual(
    app.supplyChainActionLanes.map((lane) => [lane.key, lane.items.length]),
    [
      ['create', 6],
      ['move', 6],
      ['verify', 6],
      ['exception', 2],
      ['operate', 12]
    ]
  );
  assert.equal(app.supplyChainTransportLegs.length, 2);
  assert.equal(app.supplyChainTransportLegs[0].route.includes('Austin secure staging'), true);
  assert.equal(app.supplyChainCustodyHandoffs.length, 2);
  assert.equal(app.supplyChainCustodyHandoffs[1].category, 'ownership');
  assert.equal(app.supplyChainTimelineRows.length, 25);

  const transportProcess = parsed.supplyChain.find(
    (el) => el.name === 'Controlled-lane transport process'
  );
  const manufactureProcess = parsed.supplyChain.find(
    (el) => el.name === 'Critical component manufacture process'
  );
  assert.equal(app.supplyChainFamily(transportProcess), 'move');
  assert.equal(app.supplyChainFamily(manufactureProcess), 'create');
  assert.equal(app.supplyChainProcessActions(transportProcess).length, 2);
  assert.equal(
    app
      .supplyChainCardFacts(transportProcess)
      .some((fact) => fact.label === 'Observed actions' && fact.value === '2 execution(s)'),
    true
  );

  const shockExcursion = parsed.supplyChain.find(
    (el) => el.name === 'Shock telemetry exceeds SG-1 shipment threshold'
  );
  assert.equal(app.supplyChainTimeFactLabel(shockExcursion), 'Start time (2 seconds)');

  assert.equal(app.supplyChainCarbonSummary.rows.length, 2);
  assert.equal(app.supplyChainCarbonSummary.totalKg, 228.5);
  assert.deepEqual(
    app.supplyChainCarbonSummary.rows.map((row) => [row.kg, row.distanceKm, row.mode, row.pct]),
    [
      [186.4, 2380, 'road+air+road', 100],
      [42.1, 542, 'road', 23]
    ]
  );

  assert.equal(app.supplyChainExceptionChains.length, 1);
  assert.equal(app.supplyChainExceptionChains[0].resolutions.length, 1);
  assert.equal(
    app.supplyChainExceptionChains[0].resolutions[0].name,
    'Resolve shipment shock excursion'
  );
  assert.equal(app.supplyChainExceptionChains[0].evidenceCount, 4);
});

test('parseBuildParameters groups Zephyr-style build_parameter entries', () => {
  const groups = parseBuildParameters({
    build_parameter: [
      {
        type: 'DictionaryEntry',
        key: 'compile:flags:C',
        value: '-Os -mcpu=cortex-a72 -std=c17'
      },
      {
        type: 'DictionaryEntry',
        key: 'compile:defines:C',
        value: '-DKERNEL -D__ZEPHYR__=1'
      },
      {
        type: 'DictionaryEntry',
        key: 'compiler:c:version',
        value: '14.3.0'
      }
    ]
  });

  assert.deepEqual(
    groups.map((group) => group.key),
    ['compile', 'compiler']
  );
  assert.deepEqual(
    groups[0].entries.map((entry) => entry.label),
    ['flags / C', 'defines / C']
  );
  assert.deepEqual(
    groups[0].entries[0].tokens.map((token) => token.text),
    ['-Os', '-mcpu=cortex-a72', '-std=c17']
  );
  assert.deepEqual(
    groups[0].entries[0].tokens.map((token) => token.kind),
    ['Optimization', 'Machine', 'Language standard']
  );
  assert.deepEqual(
    groups[0].entries[0].tokens.map((token) => token.renderKey),
    ['compile:flags:C:0:0', 'compile:flags:C:0:1', 'compile:flags:C:0:2']
  );
  assert.equal(groups[0].entries[1].tokens[0].className, 'param-token param-token-define');
  assert.equal(groups[1].entries[0].value, '14.3.0');
});

test('parseBuildParameters gives repeated parameter tokens unique render keys', () => {
  const groups = parseBuildParameters({
    build_parameter: [
      {
        type: 'DictionaryEntry',
        key: 'compile:flags:C',
        value: '-imacros generated/autoconf.h -imacros zephyr_stdint.h'
      },
      {
        type: 'DictionaryEntry',
        key: 'compile:flags:C',
        value: '-imacros generated/autoconf.h'
      }
    ]
  });
  const entryKeys = groups[0].entries.map((entry) => entry.renderKey);
  const tokens = groups[0].entries.flatMap((entry) => entry.tokens);
  const renderKeys = tokens.map((token) => token.renderKey);

  assert.equal(new Set(entryKeys).size, entryKeys.length);
  assert.equal(tokens.filter((token) => token.text === '-imacros').length, 3);
  assert.equal(new Set(renderKeys).size, renderKeys.length);
});

test('build parameter token display helpers never render undefined', () => {
  const app = spdxApp();
  const groups = app.buildParameters({
    build_parameter: [
      {
        type: 'DictionaryEntry',
        key: 'compile:flags:C',
        value: '-Os -mcpu=cortex-a72 -imacros generated/autoconf.h -imacros zephyr_stdint.h'
      }
    ]
  });
  const token = groups[0].entries[0].tokens[0];
  const tokenIds = groups[0].entries[0].tokens.map((item) => app.parameterTokenId(item));

  assert.equal(app.parameterTokenText(token), '-Os');
  assert.equal(app.parameterTokenKind(token), 'Optimization');
  assert.equal(app.parameterTokenClass(token), 'param-token param-token-opt');
  assert.equal(app.parameterTokenText('-D__ZEPHYR__=1'), '-D__ZEPHYR__=1');
  assert.equal(new Set(tokenIds).size, tokenIds.length);
  assert.notEqual(app.parameterTokenText(token), 'undefined');
});

const linuxSbomFiles = [
  '/Users/kartben/linux-head-build/out/sbom-source.spdx.json',
  '/Users/kartben/linux-head-build/out/sbom-output.spdx.json',
  '/Users/kartben/linux-head-build/out/sbom-build.spdx.json'
];

const zephyrBuildFile = '/Users/kartben/zephyrproject/zephyr/BUILD_DIR/spdx/build.jsonld';

test(
  'real Linux SBOM smoke test has expected build relationship counts',
  { skip: !linuxSbomFiles.every((file) => existsSync(file)) },
  () => {
    const graph = linuxSbomFiles.flatMap(
      (file) => JSON.parse(readFileSync(file, 'utf8'))['@graph']
    );
    const parsed = parseGraph(graph);
    const indexes = buildRelationshipIndexes(parsed.relationships);

    const relationshipCounts = {};
    const expandedEdgeCounts = {};
    parsed.relationships.forEach((rel) => {
      const targets = Array.isArray(rel.to) ? rel.to : [rel.to];
      relationshipCounts[rel.relationshipType] =
        (relationshipCounts[rel.relationshipType] || 0) + 1;
      expandedEdgeCounts[rel.relationshipType] =
        (expandedEdgeCounts[rel.relationshipType] || 0) + targets.length;
    });

    assert.equal(parsed.builds.length, 989);
    assert.equal(relationshipCounts.hasOutput, 989);
    assert.equal(relationshipCounts.hasInput, 685);
    assert.equal(expandedEdgeCounts.hasInput, 259722);
    assert.equal(relationshipCounts.ancestorOf, 1);
    assert.equal(relationshipCounts.hasDistributionArtifact, 1);
    assert.equal(parsed.buildInfo.spdxId, 'o:3');
    assert.ok(indexes.buildInputIndex.get('b:1025').includes('b:4'));
    assert.ok(indexes.buildOutputIndex.get('b:1025').includes('o:5'));
    assert.ok(parsed.generatedArtifacts.includes('o:5'));
    assert.equal(parsed.elementMap.get('o:5').name, 'arch/x86/boot/bzImage');
  }
);

test(
  'real Zephyr build SBOM smoke test has build parameters',
  { skip: !existsSync(zephyrBuildFile) },
  () => {
    const graph = JSON.parse(readFileSync(zephyrBuildFile, 'utf8'))['@graph'] || [];
    const parsed = parseGraph(graph);
    const parameterCount = parsed.builds.reduce(
      (count, build) =>
        count +
        parseBuildParameters(build).reduce(
          (groupCount, group) => groupCount + group.entries.length,
          0
        ),
      0
    );

    assert.ok(parsed.builds.length > 0);
    assert.ok(parameterCount > 0);
    assert.equal(parsed.buildInfo.spdxId, 'zephyr:builds/default');
    assert.ok(parseBuildParameters(parsed.buildInfo).every((group) => group.key));
  }
);

const vexGraph = [
  { type: 'software_Package', spdxId: 'pkg:busybox', name: 'busybox' },
  {
    type: 'security_Vulnerability',
    spdxId: 'vuln:cve-1',
    externalIdentifier: [
      {
        type: 'ExternalIdentifier',
        externalIdentifierType: 'cve',
        identifier: 'CVE-2023-0001',
        identifierLocator: ['https://www.cve.org/CVERecord?id=CVE-2023-0001']
      }
    ]
  },
  {
    type: 'security_Vulnerability',
    spdxId: 'vuln:cve-2',
    externalIdentifier: [
      { type: 'ExternalIdentifier', externalIdentifierType: 'cve', identifier: 'CVE-2023-0002' }
    ]
  },
  {
    // Orphan: present in the SBOM but not connected to any package by VEX.
    type: 'security_Vulnerability',
    spdxId: 'vuln:orphan',
    externalIdentifier: [
      { type: 'ExternalIdentifier', externalIdentifierType: 'cve', identifier: 'CVE-2023-9999' }
    ]
  },
  {
    type: 'security_VexFixedVulnAssessmentRelationship',
    spdxId: 'vex:fixed-1',
    relationshipType: 'fixedIn',
    from: 'vuln:cve-1',
    to: ['pkg:busybox'],
    security_vexVersion: '1.0.0'
  },
  {
    type: 'security_VexNotAffectedVulnAssessmentRelationship',
    spdxId: 'vex:na-1',
    relationshipType: 'doesNotAffect',
    from: 'vuln:cve-2',
    to: ['pkg:busybox'],
    security_justificationType: 'vulnerableCodeNotPresent',
    security_impactStatement: 'Not built with the affected component.',
    security_vexVersion: '1.0.0'
  },
  {
    type: 'Relationship',
    spdxId: 'rel:assoc',
    relationshipType: 'hasAssociatedVulnerability',
    from: 'pkg:busybox',
    to: ['vuln:cve-1', 'vuln:cve-2']
  }
];

test('parseGraph builds the VEX model from vulnerabilities and assessment relationships', () => {
  const parsed = parseGraph(vexGraph);

  assert.equal(parsed.vulnerabilities.length, 3);
  assert.equal(parsed.vexRelationships.length, 2);

  const byId = Object.fromEntries(parsed.vulnerabilities.map((v) => [v.spdxId, v]));

  // Fixed vulnerability
  const fixed = byId['vuln:cve-1'];
  assert.equal(fixed.name, 'CVE-2023-0001');
  assert.equal(fixed.overallStatus, 'fixed');
  assert.equal(fixed.packageCount, 1);
  assert.deepEqual(fixed.statusCounts, { fixed: 1 });
  assert.ok(fixed.locators.includes('https://www.cve.org/CVERecord?id=CVE-2023-0001'));

  // Not-affected vulnerability carries justification + impact statement
  const na = byId['vuln:cve-2'];
  assert.equal(na.overallStatus, 'not_affected');
  assert.equal(na.assessments[0].justification, 'vulnerableCodeNotPresent');
  assert.equal(na.assessments[0].impactStatement, 'Not built with the affected component.');
  // A CVE with no locator still synthesizes a cve.org link
  assert.ok(na.locators.some((u) => u.includes('CVE-2023-0002')));

  // Orphan vulnerability: no assessments, status is "unknown", never "fixed"
  const orphan = byId['vuln:orphan'];
  assert.equal(orphan.overallStatus, 'unknown');
  assert.equal(orphan.packageCount, 0);
  assert.deepEqual(orphan.assessments, []);

  // Indexes
  assert.equal(parsed.vexByPackage.get('pkg:busybox').length, 2);
  assert.equal(parsed.vexByVuln.get('vuln:cve-1')[0].status, 'fixed');

  // Present-types drive the legend trimming
  assert.ok(parsed.presentNodeTypes.includes('vulnerability'));
  assert.ok(parsed.presentNodeTypes.includes('package'));
  assert.ok(parsed.presentRelTypes.includes('fixedIn'));
  assert.ok(parsed.presentRelTypes.includes('doesNotAffect'));
  assert.ok(parsed.presentRelTypes.includes('hasAssociatedVulnerability'));

  // VEX assessment relationships are NOT mixed into the generic relationships
  assert.ok(!parsed.relationships.some((r) => r.type?.startsWith('security_Vex')));
});

test('parseGraph enriches vulnerabilities with in-SBOM CVSS/EPSS/exploit signals', () => {
  const graph = [
    { type: 'software_Package', spdxId: 'pkg:libx', name: 'libx' },
    {
      type: 'security_Vulnerability',
      spdxId: 'vuln:cve-a',
      externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-2024-1000' }]
    },
    {
      type: 'security_Vulnerability',
      spdxId: 'vuln:cve-b',
      externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-2024-2000' }]
    },
    {
      type: 'security_CvssV3VulnAssessmentRelationship',
      spdxId: 'assess:cvss-a1',
      relationshipType: 'hasAssessmentFor',
      from: 'vuln:cve-a',
      to: ['pkg:libx'],
      security_score: '5.9',
      security_severity: 'medium',
      security_vectorString: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'
    },
    {
      // A second, higher CVSS for the same vuln: the highest score wins.
      type: 'security_CvssV3VulnAssessmentRelationship',
      spdxId: 'assess:cvss-a2',
      relationshipType: 'hasAssessmentFor',
      from: 'vuln:cve-a',
      to: ['pkg:libx'],
      security_score: '9.8',
      security_severity: 'critical',
      security_vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    },
    {
      type: 'security_EpssVulnAssessmentRelationship',
      spdxId: 'assess:epss-a',
      relationshipType: 'hasAssessmentFor',
      from: 'vuln:cve-a',
      to: ['pkg:libx'],
      security_probability: '0.42',
      security_percentile: '0.97'
    },
    {
      type: 'security_ExploitCatalogVulnAssessmentRelationship',
      spdxId: 'assess:kev-a',
      relationshipType: 'hasAssessmentFor',
      from: 'vuln:cve-a',
      to: ['pkg:libx'],
      security_catalogType: 'kev',
      security_exploited: true
    }
  ];

  const parsed = parseGraph(graph);
  const byId = Object.fromEntries(parsed.vulnerabilities.map((v) => [v.spdxId, v]));

  const a = byId['vuln:cve-a'];
  assert.equal(a.severity, 'critical');
  assert.equal(a.severityRank, 5);
  assert.equal(a.cvss.score, 9.8);
  assert.equal(a.cvss.version, '3.1');
  assert.equal(a.epss.probability, 0.42);
  assert.equal(a.kev, true);

  // A vulnerability with no assessment relationships carries no risk signals.
  const b = byId['vuln:cve-b'];
  assert.equal(b.severity, '');
  assert.equal(b.severityRank, 0);
  assert.equal(b.cvss, null);
  assert.equal(b.epss, null);
  assert.equal(b.kev, false);

  // The assessment relationships must not leak into the generic relationships.
  assert.ok(!parsed.relationships.some((r) => r.type?.includes('VulnAssessment')));
});

test('summarizeVulnAssessments normalizes distro synonyms and CVSS-v2 bands', () => {
  // Red Hat-style qualitative synonyms map onto the standard bands.
  assert.equal(
    summarizeVulnAssessments([
      { type: 'security_CvssV3VulnAssessmentRelationship', security_severity: 'moderate' }
    ]).severity,
    'medium'
  );
  assert.equal(
    summarizeVulnAssessments([
      { type: 'security_CvssV3VulnAssessmentRelationship', security_severity: 'important' }
    ]).severity,
    'high'
  );

  // A CVSS v2 assessment with no explicit severity never becomes "critical"
  // (v2 has no Critical band), even for a 9.0+ score.
  const v2 = summarizeVulnAssessments([
    {
      type: 'security_CvssV2VulnAssessmentRelationship',
      security_score: '9.3',
      security_vectorString: 'CVSS:2.0/AV:N/AC:M/Au:N/C:C/I:C/A:C'
    }
  ]);
  assert.equal(v2.severity, 'high');
  assert.equal(cvssSeverityForScore(9.3, '2.0'), 'high');
  assert.equal(cvssSeverityForScore(9.3, '3.1'), 'critical');

  // Null entries in the list are ignored rather than throwing.
  assert.equal(summarizeVulnAssessments([null, undefined]).severity, '');
});

test('VEX assessment elements are excluded from the generic relationship indexes', () => {
  const parsed = parseGraph(vexGraph);
  const indexes = buildRelationshipIndexes(parsed.relationships);
  // The vulnerability id must not appear as a relationship "from" (that would
  // mean a VEX element leaked into the generic relationships array).
  assert.equal(indexes.relFromIndex.has('vuln:cve-1'), false);
});

test('VEX utility helpers resolve status, justification, and vulnerability ids', () => {
  assert.equal(getVexStatusMeta('fixed').label, 'Fixed');
  assert.equal(getVexStatusMeta('not_affected').label, 'Not affected');
  assert.equal(getVexStatusMeta('unknown').label, 'No VEX status');
  assert.equal(getVexJustificationLabel('vulnerableCodeNotPresent'), 'Vulnerable code not present');
  assert.equal(getVexJustificationLabel('somethingNew'), 'somethingNew');
  assert.equal(
    getVulnerabilityId({
      type: 'security_Vulnerability',
      spdxId: 'x/CVE-2020-1',
      externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-2020-1' }]
    }),
    'CVE-2020-1'
  );
});

test('parseCpe handles CPE 2.3 and 2.2, normalizing wildcards', () => {
  assert.deepEqual(parseCpe('cpe:2.3:*:*:glibc:2.39:*:*:*:*:*:*:*'), {
    part: '',
    vendor: '',
    product: 'glibc',
    version: '2.39'
  });
  assert.deepEqual(parseCpe('cpe:2.3:o:linux:linux_kernel:6.6:*:*:*:*:*:*:*'), {
    part: 'o',
    vendor: 'linux',
    product: 'linux_kernel',
    version: '6.6'
  });
  assert.deepEqual(parseCpe('cpe:/a:openssl:openssl:3.0.0'), {
    part: 'a',
    vendor: 'openssl',
    product: 'openssl',
    version: '3.0.0'
  });
  assert.equal(parseCpe('not-a-cpe'), null);
});

test('getVulnerabilityLookup routes wildcard CPEs to a cve.org product search', () => {
  // Yocto-style wildcard part/vendor — NVD would reject this, so use cve.org
  const glibc = getVulnerabilityLookup({
    type: 'cpe23',
    identifier: 'cpe:2.3:*:*:glibc:2.39:*:*:*:*:*:*:*'
  });
  assert.equal(glibc.url, 'https://www.cve.org/CVERecord/SearchResults?query=glibc');

  // Underscores in the product become spaces in the query
  const kernel = getVulnerabilityLookup({
    type: 'cpe23',
    identifier: 'cpe:2.3:o:linux:linux_kernel:6.6:*:*:*:*:*:*:*'
  });
  assert.equal(kernel.url, 'https://www.cve.org/CVERecord/SearchResults?query=linux%20kernel');

  // Non-CPE identifiers are not linked
  assert.equal(getVulnerabilityLookup({ type: 'packageUrl', identifier: 'pkg:deb/glibc' }), null);
});

test('getPurlLink links supported ecosystems to deps.dev', () => {
  assert.equal(
    getPurlLink({ type: 'packageUrl', identifier: 'pkg:npm/%40vue/compiler-sfc@3.4.0' }).url,
    'https://deps.dev/npm/%40vue%2Fcompiler-sfc/3.4.0'
  );
  assert.equal(
    getPurlLink({
      type: 'packageUrl',
      identifier: 'pkg:maven/org.jenkins-ci.main/jenkins-core@2.572'
    }).url,
    'https://deps.dev/maven/org.jenkins-ci.main%3Ajenkins-core/2.572'
  );
  assert.equal(
    getPurlLink({ type: 'packageUrl', identifier: 'pkg:golang/github.com/gorilla/mux@v1.8.1' }).url,
    'https://deps.dev/go/github.com%2Fgorilla%2Fmux/v1.8.1'
  );
  // Qualifiers are stripped, versionless purls link to the package page
  assert.equal(
    getPurlLink({ type: 'packageUrl', identifier: 'pkg:pypi/requests?os=linux' }).url,
    'https://deps.dev/pypi/requests'
  );
  // Ecosystems deps.dev doesn't cover are not linked
  assert.equal(
    getPurlLink({ type: 'packageUrl', identifier: 'pkg:deb/ubuntu/coreutils@9.4' }),
    null
  );
  assert.equal(getPurlLink({ type: 'cpe23', identifier: 'cpe:2.3:a:x:y' }), null);
});

test('share hash round-trips a spot in a sample', () => {
  const spot = {
    sample: 'trivy',
    view: 'security',
    expanded: 'urn:spdx:vuln/CVE-2026-1234',
    detail: null,
    graphSelected: null
  };
  assert.deepEqual(parseShareHash('#' + buildShareHash(spot)), spot);

  // The default view stays out of the hash, and parsing restores it
  const home = buildShareHash({ sample: 'zephyr', view: 'dashboard' });
  assert.equal(home, 's=zephyr');
  assert.equal(parseShareHash(home).view, 'dashboard');

  // Not a share link without a sample id
  assert.equal(buildShareHash({ view: 'graph' }), '');
  assert.equal(parseShareHash(''), null);
  assert.equal(parseShareHash('#v=graph'), null);
});

test('getExternalIdentifiers surfaces the software_packageUrl property as a purl', () => {
  const rows = getExternalIdentifiers({
    software_packageUrl: 'pkg:npm/leftpad@1.0.0'
  });
  assert.deepEqual(rows, [
    { type: 'packageUrl', label: 'PackageURL', identifier: 'pkg:npm/leftpad@1.0.0', isUrl: false }
  ]);
  // ...but not when an ExternalIdentifier purl is already present
  const withEid = getExternalIdentifiers({
    software_packageUrl: 'pkg:npm/leftpad@1.0.0',
    externalIdentifier: [{ externalIdentifierType: 'packageUrl', identifier: 'pkg:npm/leftpad' }]
  });
  assert.equal(withEid.length, 1);
  assert.equal(withEid[0].identifier, 'pkg:npm/leftpad');
});

test('summarizeCveRecord distills a CVE 5.x record', () => {
  const record = {
    cveMetadata: {
      cveId: 'CVE-2023-0001',
      state: 'PUBLISHED',
      datePublished: '2023-01-02T00:00:00Z',
      assignerShortName: 'redhat'
    },
    containers: {
      cna: {
        descriptions: [
          { lang: 'es', value: 'hola' },
          { lang: 'en', value: 'An out-of-bounds read flaw.' }
        ],
        problemTypes: [
          { descriptions: [{ cweId: 'CWE-125', description: 'CWE-125 Out-of-bounds Read' }] }
        ],
        references: [{ url: 'https://example.com/a', name: 'Advisory' }],
        metrics: [{ cvssV3_0: { version: '3.0', baseScore: 5, baseSeverity: 'medium' } }]
      },
      adp: [
        {
          metrics: [
            {
              cvssV3_1: {
                version: '3.1',
                baseScore: 8.1,
                baseSeverity: 'HIGH',
                vectorString: 'CVSS:3.1/AV:N'
              }
            }
          ],
          references: [{ url: 'https://example.com/a' }, { url: 'https://example.com/b' }]
        }
      ]
    }
  };

  const s = summarizeCveRecord(record);
  assert.equal(s.description, 'An out-of-bounds read flaw.');
  // Highest CVSS version wins (3.1 over 3.0), severity uppercased
  assert.deepEqual(s.cvss, {
    version: '3.1',
    score: 8.1,
    severity: 'HIGH',
    vector: 'CVSS:3.1/AV:N'
  });
  assert.deepEqual(s.cwes, ['CWE-125: Out-of-bounds Read']);
  // References de-duplicated by URL across CNA + ADP
  assert.deepEqual(
    s.references.map((r) => r.url),
    ['https://example.com/a', 'https://example.com/b']
  );
  assert.equal(getCvssSeverityMeta(s.cvss.severity).label, 'High');
});

test('summarizeCveRecord tolerates a minimal record with no metrics or CWE', () => {
  const s = summarizeCveRecord({
    cveMetadata: { cveId: 'CVE-1999-0001', state: 'PUBLISHED' },
    containers: { cna: { descriptions: [{ lang: 'en', value: 'Old issue.' }] } }
  });
  assert.equal(s.description, 'Old issue.');
  assert.equal(s.cvss, null);
  assert.deepEqual(s.cwes, []);
  assert.deepEqual(s.references, []);
});

test('extractLicenseExpressionParts parses simple and compound expressions', () => {
  assert.deepEqual(extractLicenseExpressionParts('MIT'), [{ id: 'MIT', kind: 'license' }]);

  assert.deepEqual(extractLicenseExpressionParts('Apache-2.0 OR MIT'), [
    { id: 'Apache-2.0', kind: 'license' },
    { id: 'MIT', kind: 'license' }
  ]);

  assert.deepEqual(extractLicenseExpressionParts('Apache-2.0 AND (Apache-2.0 OR MIT)'), [
    { id: 'Apache-2.0', kind: 'license' },
    { id: 'MIT', kind: 'license' }
  ]);

  assert.deepEqual(extractLicenseExpressionParts('GPL-2.0-only WITH Classpath-exception-2.0'), [
    { id: 'GPL-2.0-only', kind: 'license' },
    {
      id: 'Classpath-exception-2.0',
      kind: 'exception',
      withLicense: 'GPL-2.0-only'
    }
  ]);
});

test('renderLicenseExpression renders SPDX 3 ExpandedLicensing operators', () => {
  // A Syft-style ConjunctiveLicenseSet: listed licenses as http(s) URLs plus a
  // CustomLicense member resolved by its name.
  const graph = [
    {
      type: 'expandedlicensing_ConjunctiveLicenseSet',
      spdxId: 'lic:and',
      expandedlicensing_member: [
        'http://spdx.org/licenses/GPL-2.0-only',
        'https://spdx.org/licenses/BSD-3-Clause',
        'lic:custom'
      ]
    },
    { type: 'expandedlicensing_CustomLicense', spdxId: 'lic:custom', name: 'public-domain' },
    {
      type: 'expandedlicensing_DisjunctiveLicenseSet',
      spdxId: 'lic:or',
      expandedlicensing_member: [
        'http://spdx.org/licenses/MIT',
        'http://spdx.org/licenses/Apache-2.0'
      ]
    },
    // OR nested inside AND must be parenthesised (AND binds tighter than OR).
    {
      type: 'expandedlicensing_ConjunctiveLicenseSet',
      spdxId: 'lic:nested',
      expandedlicensing_member: ['http://spdx.org/licenses/GPL-2.0-only', 'lic:or']
    },
    {
      type: 'expandedlicensing_OrLaterOperator',
      spdxId: 'lic:orlater',
      expandedlicensing_subjectLicense: 'http://spdx.org/licenses/GPL-2.0-only'
    },
    {
      type: 'expandedlicensing_WithAdditionOperator',
      spdxId: 'lic:with',
      expandedlicensing_subjectExtendableLicense: 'http://spdx.org/licenses/GPL-2.0-only',
      expandedlicensing_subjectAddition: 'lic:exc'
    },
    {
      type: 'expandedlicensing_ListedLicenseException',
      spdxId: 'lic:exc',
      name: 'Classpath-exception-2.0'
    }
  ];
  const map = new Map(graph.map((el) => [el.spdxId, el]));

  assert.equal(
    renderLicenseExpression(map.get('lic:and'), map),
    'GPL-2.0-only AND BSD-3-Clause AND public-domain'
  );
  assert.equal(renderLicenseExpression(map.get('lic:or'), map), 'MIT OR Apache-2.0');
  assert.equal(
    renderLicenseExpression(map.get('lic:nested'), map),
    'GPL-2.0-only AND (MIT OR Apache-2.0)'
  );
  assert.equal(renderLicenseExpression(map.get('lic:orlater'), map), 'GPL-2.0-only+');
  assert.equal(
    renderLicenseExpression(map.get('lic:with'), map),
    'GPL-2.0-only WITH Classpath-exception-2.0'
  );

  // Non-operator elements return '' so callers keep their own name handling.
  assert.equal(renderLicenseExpression(map.get('lic:custom'), map), '');
  assert.equal(renderLicenseExpression(undefined, map), '');
});

test('getCdxProperties flattens the SPDX 3 CdxPropertiesExtension', () => {
  const pkg = {
    type: 'software_Package',
    spdxId: 'pkg:pinia',
    extension: [
      {
        type: 'extension_CdxPropertiesExtension',
        extension_cdxProperty: [
          {
            type: 'extension_CdxPropertyEntry',
            extension_cdxPropName: 'scope',
            extension_cdxPropValue: 'required'
          },
          {
            type: 'extension_CdxPropertyEntry',
            extension_cdxPropName: 'group',
            extension_cdxPropValue: ''
          },
          {
            type: 'extension_CdxPropertyEntry',
            extension_cdxPropName: 'tags',
            extension_cdxPropValue: '["framework"]'
          },
          {
            type: 'extension_CdxPropertyEntry',
            extension_cdxPropName: 'properties.cdx:npm:package:development',
            extension_cdxPropValue: 'true'
          },
          {
            type: 'extension_CdxPropertyEntry',
            extension_cdxPropName: 'licenses',
            extension_cdxPropValue: '[{"license":{"id":"MIT"}}]'
          }
        ]
      }
    ]
  };

  const props = getCdxProperties(pkg);
  const byName = new Map(props.map((p) => [p.name, p]));

  // Empty values (group) are dropped.
  assert.equal(byName.has('group'), false);
  assert.equal(props.length, 4);

  // Scalars keep their raw name and string value; no JSON parse.
  assert.equal(byName.get('scope').value, 'required');
  assert.equal(byName.get('scope').json, null);
  assert.equal(byName.has('properties.cdx:npm:package:development'), true);

  // JSON blobs are parsed and pretty-printed.
  const licenses = byName.get('licenses');
  assert.deepEqual(licenses.json, [{ license: { id: 'MIT' } }]);
  assert.equal(licenses.pretty, JSON.stringify([{ license: { id: 'MIT' } }], null, 2));

  // Verbose JSON properties sort after concise scalars.
  assert.equal(props[props.length - 1].name, 'licenses');

  // Elements without the extension yield an empty list.
  assert.deepEqual(getCdxProperties({ type: 'software_Package' }), []);
  assert.deepEqual(getCdxProperties(undefined), []);
});

test('parseGraph supports LifecycleScopedRelationship dynamic-link / optional-component edges', () => {
  const graph = [
    { type: 'software_Package', spdxId: 'pkg:app', name: 'app' },
    { type: 'software_Package', spdxId: 'pkg:lib', name: 'lib' },
    { type: 'software_Package', spdxId: 'pkg:plugin', name: 'plugin' },
    {
      type: 'LifecycleScopedRelationship',
      spdxId: 'rel:dyn',
      relationshipType: 'hasDynamicLink',
      scope: 'runtime',
      from: 'pkg:app',
      to: ['pkg:lib']
    },
    {
      type: 'LifecycleScopedRelationship',
      spdxId: 'rel:opt',
      relationshipType: 'hasOptionalComponent',
      scope: 'runtime',
      from: 'pkg:app',
      to: ['pkg:plugin']
    }
  ];

  const parsed = parseGraph(graph);

  // Lifecycle-scoped relationships are collected like generic relationships…
  assert.equal(parsed.relationships.length, 2);
  // …and surface in the legend's present relationship types.
  assert.ok(parsed.presentRelTypes.includes('hasDynamicLink'));
  assert.ok(parsed.presentRelTypes.includes('hasOptionalComponent'));
  // Both edges are runtime-scoped and none are unscoped, so the scope legend
  // lists just 'runtime' (no synthetic 'unscoped' bucket).
  assert.deepEqual(parsed.presentScopes, ['runtime']);

  // Each type has a distinct, non-default colour and a directional label.
  const dyn = getRelationshipColor('hasDynamicLink');
  const opt = getRelationshipColor('hasOptionalComponent');
  const fallback = getRelationshipColor('nonexistentRel');
  assert.notEqual(dyn, opt);
  assert.notEqual(dyn, fallback);
  assert.notEqual(opt, fallback);
  assert.equal(getRelationshipGroupLabel('hasDynamicLink', 'out'), 'Dynamically links');
  assert.equal(getRelationshipGroupLabel('hasOptionalComponent', 'in'), 'Optional component of');
});

test('parseGraph supports hasVariant relationships (as emitted by the AOSP SBOM)', () => {
  const app = spdxApp();
  const graph = [
    { type: 'software_Package', spdxId: 'pkg:toybox', name: 'toybox' },
    { type: 'software_Package', spdxId: 'pkg:toybox-variant', name: 'toybox' },
    {
      type: 'Relationship',
      spdxId: 'rel:variant',
      relationshipType: 'hasVariant',
      from: 'pkg:toybox',
      to: ['pkg:toybox-variant']
    }
  ];

  const parsed = parseGraph(graph);

  // The plain Relationship is collected and surfaces in the legend's present types.
  assert.equal(parsed.relationships.length, 1);
  assert.ok(parsed.presentRelTypes.includes('hasVariant'));

  // hasVariant has a distinct, non-default colour and directional labels.
  const variant = getRelationshipColor('hasVariant');
  assert.notEqual(variant, getRelationshipColor('nonexistentRel'));
  assert.notEqual(variant, getRelationshipColor('hasStaticLink'));
  assert.equal(getRelationshipGroupLabel('hasVariant', 'out'), 'Variants');
  assert.equal(getRelationshipGroupLabel('hasVariant', 'in'), 'Variant of');

  // It surfaces in the detail panel's relationship groups, both directions.
  const indexes = buildRelationshipIndexes(parsed.relationships);
  app.elementMap = parsed.elementMap;
  app.relFromIndex = indexes.relFromIndex;
  app.relToIndex = indexes.relToIndex;
  const outGroups = app.detailRelGroupsFor({ spdxId: 'pkg:toybox' });
  assert.equal(
    outGroups.find((g) => g.key === 'hasVariant:out')?.items[0].id,
    'pkg:toybox-variant'
  );
  const inGroups = app.detailRelGroupsFor({ spdxId: 'pkg:toybox-variant' });
  assert.equal(inGroups.find((g) => g.key === 'hasVariant:in')?.items[0].id, 'pkg:toybox');
});

test('detailRelGroupsFor surfaces lifecycle-scoped relationships with their scope', () => {
  const app = spdxApp();
  const graph = [
    { type: 'software_Package', spdxId: 'pkg:app', name: 'app' },
    { type: 'software_Package', spdxId: 'pkg:lib', name: 'lib' },
    {
      type: 'LifecycleScopedRelationship',
      spdxId: 'rel:dyn',
      relationshipType: 'hasDynamicLink',
      scope: 'runtime',
      from: 'pkg:app',
      to: ['pkg:lib']
    }
  ];
  const parsed = parseGraph(graph);
  const indexes = buildRelationshipIndexes(parsed.relationships);
  app.elementMap = parsed.elementMap;
  app.relFromIndex = indexes.relFromIndex;
  app.relToIndex = indexes.relToIndex;

  const groups = app.detailRelGroupsFor({ spdxId: 'pkg:app' });
  const dyn = groups.find((g) => g.key === 'hasDynamicLink:out');
  assert.ok(dyn, 'expected a hasDynamicLink:out group');
  assert.equal(dyn.label, 'Dynamically links');
  assert.equal(dyn.items[0].id, 'pkg:lib');
  assert.equal(dyn.items[0].scope, 'runtime');
});

test('detailRelGroupsFor collapses same-file snippet endpoints into one N-ranges row', () => {
  const app = spdxApp();
  const graph = [
    { type: 'Requirement', spdxId: 'req:1', name: 'REQ-1' },
    { type: 'software_File', spdxId: 'file:a', name: 'thread.c' },
    { type: 'software_File', spdxId: 'file:b', name: 'sched.c' },
    {
      type: 'software_Snippet',
      spdxId: 'snip:a2',
      software_snippetFromFile: 'file:a',
      software_lineRange: { beginIntegerRange: 200, endIntegerRange: 210 }
    },
    {
      type: 'software_Snippet',
      spdxId: 'snip:a1',
      software_snippetFromFile: 'file:a',
      software_lineRange: { beginIntegerRange: 10, endIntegerRange: 20 }
    },
    {
      type: 'software_Snippet',
      spdxId: 'snip:b1',
      software_snippetFromFile: 'file:b',
      software_lineRange: { beginIntegerRange: 5, endIntegerRange: 8 }
    },
    {
      type: 'Relationship',
      spdxId: 'rel:1',
      relationshipType: 'implementedBy',
      from: 'req:1',
      to: ['snip:a1', 'snip:a2', 'snip:b1']
    }
  ];
  const parsed = parseGraph(graph);
  const indexes = buildRelationshipIndexes(parsed.relationships);
  app.elementMap = parsed.elementMap;
  app.relFromIndex = indexes.relFromIndex;
  app.relToIndex = indexes.relToIndex;

  const group = app
    .detailRelGroupsFor({ spdxId: 'req:1' })
    .find((g) => g.key === 'implementedBy:out');
  assert.ok(group, 'expected an implementedBy:out group');
  // Two files → two rows (three snippets collapsed), not three snippet rows.
  assert.equal(group.total, 2);
  assert.equal(group.items.length, 2);

  const multi = group.items.find((i) => i.multiRange);
  assert.ok(multi, 'expected a collapsed multi-range row for thread.c');
  assert.match(multi.displayName, /thread\.c › 2 ranges/);
  // Snippet ids ordered by start line so the popup opens at the first range.
  assert.deepEqual(multi.snippetIds, ['snip:a1', 'snip:a2']);

  // The lone snippet for sched.c stays a normal single-snippet row.
  const single = group.items.find((i) => !i.multiRange);
  assert.equal(single.id, 'snip:b1');
  assert.ok(!single.snippetIds);
});

test('_collapseSource keeps ranges with context and folds the gaps between them', () => {
  const app = spdxApp();
  const lines = Array.from({ length: 200 }, (_, i) => ({ lineNum: i + 1, html: `line ${i + 1}` }));
  const ranges = [
    { start: 50, end: 55 },
    { start: 120, end: 122 }
  ];
  const segs = app._collapseSource(lines, ranges, {});

  // Two big stretches are collapsed: 1..(50-context-1) and the middle gap.
  const gaps = segs.filter((s) => s.kind === 'gap');
  assert.equal(gaps.length, 3, 'leading, middle, and trailing gaps');
  // Covered lines are flagged; context lines around them are shown but not covered.
  const code = segs.filter((s) => s.kind === 'code');
  const shown = new Set(code.map((c) => c.lineNum));
  assert.ok(shown.has(50) && shown.has(55), 'first range shown');
  assert.ok(shown.has(44) && shown.has(61), 'context around the first range shown');
  assert.ok(!shown.has(30), 'far-away lines are collapsed away');
  assert.equal(code.find((c) => c.lineNum === 52).covered, true, 'in-range line marked covered');
  assert.equal(
    code.find((c) => c.lineNum === 44).covered,
    false,
    'context line not marked covered'
  );

  // Expanding the middle gap reveals a chunk without disturbing the ranges.
  const middleKey = gaps[1].key;
  const expanded = app._collapseSource(lines, ranges, { [middleKey]: 40 });
  const shownAfter = new Set(expanded.filter((s) => s.kind === 'code').map((c) => c.lineNum));
  assert.ok(shownAfter.size > shown.size, 'expanding a gap reveals more lines');
});

test('_collapseSource shows the whole file when there are no line ranges', () => {
  const app = spdxApp();
  const lines = Array.from({ length: 10 }, (_, i) => ({ lineNum: i + 1, html: '' }));
  const segs = app._collapseSource(lines, [{ start: null, end: null }], {});
  assert.equal(segs.length, 10);
  assert.ok(segs.every((s) => s.kind === 'code'));
});

test('parseGraph reports present lifecycle scopes in lifecycle order with unscoped last', () => {
  const graph = [
    { type: 'software_Package', spdxId: 'pkg:app', name: 'app' },
    { type: 'software_Package', spdxId: 'pkg:lib', name: 'lib' },
    { type: 'software_Package', spdxId: 'pkg:buildtool', name: 'buildtool' },
    // A runtime-scoped edge, a build-scoped edge, and a plain unscoped one.
    {
      type: 'LifecycleScopedRelationship',
      spdxId: 'rel:rt',
      relationshipType: 'dependsOn',
      scope: 'runtime',
      from: 'pkg:app',
      to: ['pkg:lib']
    },
    {
      type: 'LifecycleScopedRelationship',
      spdxId: 'rel:bt',
      relationshipType: 'dependsOn',
      scope: 'build',
      from: 'pkg:app',
      to: ['pkg:buildtool']
    },
    {
      type: 'Relationship',
      spdxId: 'rel:plain',
      relationshipType: 'contains',
      from: 'pkg:app',
      to: ['pkg:lib']
    }
  ];

  const parsed = parseGraph(graph);
  // Ordered per SCOPE_ORDER (build before runtime), 'unscoped' appended because
  // the plain `contains` relationship carries no scope.
  assert.deepEqual(parsed.presentScopes, ['build', 'runtime', 'unscoped']);
});

test('parseGraph reports no scopes when nothing is lifecycle-scoped', () => {
  const graph = [
    { type: 'software_Package', spdxId: 'pkg:app', name: 'app' },
    { type: 'software_Package', spdxId: 'pkg:lib', name: 'lib' },
    {
      type: 'Relationship',
      spdxId: 'rel:plain',
      relationshipType: 'dependsOn',
      from: 'pkg:app',
      to: ['pkg:lib']
    }
  ];

  const parsed = parseGraph(graph);
  // No scoped relationships → empty, which hides the scope legend row entirely.
  assert.deepEqual(parsed.presentScopes, []);
});

test('parseGraph collects SpdxDocument.import ExternalMap entries and resolution stats', () => {
  const graph = [
    // ext:file1 is defined here (so it resolves); ext:file2 is not.
    { type: 'software_File', spdxId: 'ext:file1', name: 'shared.c' },
    {
      type: 'SpdxDocument',
      spdxId: 'doc:build',
      name: 'Build Document',
      import: [
        {
          type: 'ExternalMap',
          externalSpdxId: 'ext:file1',
          locationHint: './zephyr.jsonld'
        },
        {
          type: 'ExternalMap',
          externalSpdxId: 'ext:file2',
          locationHint: './zephyr.jsonld',
          definingArtifact: 'pkg:zephyr',
          verifiedUsing: [{ type: 'Hash', algorithm: 'sha256', hashValue: 'abc123' }]
        }
      ]
    }
  ];

  const parsed = parseGraph(graph);

  assert.equal(parsed.externalMap.size, 2);
  assert.deepEqual(parsed.externalRefStats, { total: 2, resolved: 1, unresolved: 1 });

  const f1 = parsed.externalMap.get('ext:file1');
  assert.equal(f1.locationHint, './zephyr.jsonld');
  assert.deepEqual(f1.importedBy, ['Build Document']);

  const f2 = parsed.externalMap.get('ext:file2');
  assert.equal(f2.definingArtifact, 'pkg:zephyr');
  assert.equal(f2.verifiedUsing[0].hashValue, 'abc123');
});

test('parseGraph merges ExternalMap importers across documents', () => {
  const graph = [
    {
      type: 'SpdxDocument',
      spdxId: 'doc:a',
      name: 'Doc A',
      import: [{ type: 'ExternalMap', externalSpdxId: 'ext:shared', locationHint: './a.jsonld' }]
    },
    {
      type: 'SpdxDocument',
      spdxId: 'doc:b',
      name: 'Doc B',
      // Same id, no location hint here — the first entry's hint must survive.
      import: [{ type: 'ExternalMap', externalSpdxId: 'ext:shared' }]
    }
  ];

  const parsed = parseGraph(graph);
  const entry = parsed.externalMap.get('ext:shared');

  assert.equal(parsed.externalMap.size, 1);
  assert.deepEqual(entry.importedBy, ['Doc A', 'Doc B']);
  assert.equal(entry.locationHint, './a.jsonld');
  assert.deepEqual(parsed.externalRefStats, { total: 1, resolved: 0, unresolved: 1 });
});

test('externalRefFor resolves an element to its ExternalMap import entry', () => {
  const app = spdxApp();
  const graph = [
    { type: 'software_File', spdxId: 'ext:file1', name: 'shared.c' },
    {
      type: 'SpdxDocument',
      spdxId: 'doc:build',
      name: 'Build Document',
      import: [
        { type: 'ExternalMap', externalSpdxId: 'ext:file1', locationHint: './zephyr.jsonld' }
      ]
    }
  ];
  const parsed = parseGraph(graph);
  app.externalMap = parsed.externalMap;

  assert.equal(app.externalRefFor({ spdxId: 'ext:file1' })?.locationHint, './zephyr.jsonld');
  assert.equal(app.externalRefFor({ spdxId: 'ext:absent' }), null);
  assert.equal(app.externalRefFor(null), null);
});
