import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

import { buildRelationshipIndexes, parseGraph } from '../js/parser.js';

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

const linuxSbomFiles = [
  '/Users/kartben/linux-head-build/out/sbom-source.spdx.json',
  '/Users/kartben/linux-head-build/out/sbom-output.spdx.json',
  '/Users/kartben/linux-head-build/out/sbom-build.spdx.json'
];

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
