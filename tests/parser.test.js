import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

import { buildRelationshipIndexes, parseGraph } from '../js/parser.js';
import { parseBuildParameters, extractLicenseExpressionParts } from '../js/utils.js';
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
