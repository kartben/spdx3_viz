import assert from 'node:assert/strict';
import test from 'node:test';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

import {
  detectMainArtifactCandidates,
  buildContributionAdjacency,
  contributionSet
} from '../src/lib/main-artifact.js';

// --- Detection -------------------------------------------------------------

test('detectMainArtifactCandidates prefers a terminal executable build output', () => {
  const elements = [
    { spdxId: 'app.elf', type: 'software_File', name: 'app.elf' },
    { spdxId: 'lib.a', type: 'software_File', name: 'libapp.a' },
    { spdxId: 'main.o', type: 'software_File', name: 'main.o' },
    { spdxId: 'readme', type: 'software_File', name: 'README.txt' }
  ];
  const relationships = [
    { relationshipType: 'hasOutput', from: 'build', to: ['app.elf'] },
    { relationshipType: 'hasOutput', from: 'build:lib', to: ['lib.a'] },
    { relationshipType: 'hasInput', from: 'build', to: ['lib.a', 'main.o'] },
    { relationshipType: 'hasStaticLink', from: 'app.elf', to: ['lib.a'] }
  ];
  const { candidates, auto } = detectMainArtifactCandidates({ elements, relationships });
  assert.equal(candidates[0].id, 'app.elf');
  assert.equal(auto, 'app.elf');
  // The archive that is consumed as a build input must not outrank the binary.
  const libRank = candidates.findIndex((c) => c.id === 'lib.a');
  assert.ok(libRank === -1 || libRank > 0);
});

test('detectMainArtifactCandidates credits an application primaryPurpose', () => {
  const elements = [
    {
      spdxId: 'pkg',
      type: 'software_Package',
      name: 'my-app',
      software_primaryPurpose: 'application'
    },
    { spdxId: 'dep', type: 'software_Package', name: 'libc', software_primaryPurpose: 'library' }
  ];
  const { candidates, auto } = detectMainArtifactCandidates({ elements, relationships: [] });
  assert.equal(candidates[0].id, 'pkg');
  assert.equal(auto, 'pkg');
});

test('detectMainArtifactCandidates stays unset when no candidate is confident', () => {
  const elements = [
    { spdxId: 'a', type: 'software_Package', name: 'libfoo', software_primaryPurpose: 'library' },
    { spdxId: 'b', type: 'software_Package', name: 'libbar', software_primaryPurpose: 'library' }
  ];
  const { auto } = detectMainArtifactCandidates({ elements, relationships: [] });
  assert.equal(auto, null);
});

test('detectMainArtifactCandidates ignores non file/package elements', () => {
  const elements = [
    { spdxId: 'agent', type: 'Person', name: 'agent.elf' },
    { spdxId: 'rel', type: 'Relationship', name: 'x' }
  ];
  const { candidates } = detectMainArtifactCandidates({ elements, relationships: [] });
  assert.equal(candidates.length, 0);
});

// --- Contribution reachability --------------------------------------------

test('contributionSet walks build lineage, links, and dependencies', () => {
  // elf is output by a build whose inputs are lib.a + main.o; elf also statically
  // links lib.a; lib.a dependsOn zlib. `other.elf` is an unrelated output.
  const relationships = [
    { relationshipType: 'hasOutput', from: 'build', to: ['elf'] },
    { relationshipType: 'hasInput', from: 'build', to: ['lib.a', 'main.o'] },
    { relationshipType: 'hasStaticLink', from: 'elf', to: ['lib.a'] },
    { relationshipType: 'dependsOn', from: 'lib.a', to: ['zlib'] },
    { relationshipType: 'hasOutput', from: 'build:other', to: ['other.elf'] },
    { relationshipType: 'dependsOn', from: 'other.elf', to: ['unrelated'] }
  ];
  const adj = buildContributionAdjacency(relationships);
  const set = contributionSet('elf', adj);
  assert.ok(set.has('elf'));
  assert.ok(set.has('build'));
  assert.ok(set.has('lib.a'));
  assert.ok(set.has('main.o'));
  assert.ok(set.has('zlib'));
  // Nothing from the unrelated build should be reachable.
  assert.ok(!set.has('other.elf'));
  assert.ok(!set.has('unrelated'));
});

test('contributionSet terminates on cyclic dependency graphs', () => {
  const relationships = [
    { relationshipType: 'dependsOn', from: 'a', to: ['b'] },
    { relationshipType: 'dependsOn', from: 'b', to: ['a'] }
  ];
  const adj = buildContributionAdjacency(relationships);
  const set = contributionSet('a', adj);
  assert.deepEqual([...set].sort(), ['a', 'b']);
});

test('contributionSet returns an empty set without a root', () => {
  const adj = buildContributionAdjacency([]);
  assert.equal(contributionSet(null, adj).size, 0);
});

// --- Bundled-sample sanity -------------------------------------------------
// The visualizer is expected to auto-pick zephyr.elf and bzImage; guard on the
// fixtures existing so the suite still runs without a git-lfs / sample checkout.

function loadModelFromDir(dir, exts) {
  const elements = [];
  const relationships = [];
  const rootElementIds = new Set();
  for (const fn of readdirSync(dir)) {
    if (!exts.some((e) => fn.endsWith(e))) continue;
    const doc = JSON.parse(readFileSync(join(dir, fn), 'utf8'));
    const graph = doc['@graph'] || (Array.isArray(doc) ? doc : []);
    for (const el of graph) {
      elements.push(el);
      if (el.relationshipType) relationships.push(el);
      if (el.rootElement) [].concat(el.rootElement).forEach((r) => rootElementIds.add(r));
    }
  }
  return { elements, relationships, rootElementIds };
}

test(
  'auto-detects zephyr.elf as the main artifact',
  { skip: !existsSync('public/samples/zephyr') },
  () => {
    const model = loadModelFromDir('public/samples/zephyr', ['.jsonld']);
    const { auto } = detectMainArtifactCandidates(model);
    assert.equal(auto, 'zephyr:files/File-zephyr.elf');
  }
);

test(
  'auto-detects the Linux bzImage as the main artifact',
  { skip: !existsSync('public/samples/linux') },
  () => {
    const model = loadModelFromDir('public/samples/linux', ['.json']);
    const { candidates, auto } = detectMainArtifactCandidates(model);
    assert.ok(auto);
    assert.equal(candidates[0].name, 'arch/x86/boot/bzImage');
  }
);
