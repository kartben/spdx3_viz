import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

import { buildRelationshipIndexes, parseGraph } from '../js/parser.js';
import {
  parseBuildParameters,
  extractLicenseExpressionParts,
  getVulnerabilityId,
  getVexStatusMeta,
  getVexJustificationLabel,
  parseCpe,
  getVulnerabilityLookup,
  summarizeCveRecord,
  getCvssSeverityMeta
} from '../js/utils.js';
import { spdxApp } from '../js/app.js';

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

    assert.equal(parsed.builds.length, 19);
    assert.equal(parameterCount, 50);
    assert.equal(parsed.buildInfo.spdxId, 'zephyr:builds/default');
    assert.equal(parseBuildParameters(parsed.buildInfo).length, 3);
    assert.deepEqual(
      parseBuildParameters(parsed.buildInfo).map((group) => group.key),
      ['archiver', 'cmake', 'compiler']
    );
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
