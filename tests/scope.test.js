import assert from 'node:assert/strict';
import test from 'node:test';

import { buildSecurityScope, vulnInScope } from '../src/lib/scope.js';

// The fixture is the shape that motivated the feature, shrunk to five packages:
// a build declares every module in the manifest as an input, but only some of
// them put a file into the image. `img` is the artifact someone ships.
//
//   img --contains--> img.elf --(produced by)--> build
//   build --hasInput--> used-sources   (has a file, compiled in)
//                       unused-sources (no files, in the manifest only)
//                       app-sources    (has a file)
//   used-deps   --hasVariant--> used-sources     reference-only twin
//   unused-deps --hasVariant--> unused-sources   reference-only twin
const ELEMENTS = new Map(
  [
    ['img', 'software_Package'],
    ['img.elf', 'software_File'],
    ['used-sources', 'software_Package'],
    ['used.c', 'software_File'],
    ['unused-sources', 'software_Package'],
    ['app-sources', 'software_Package'],
    ['main.c', 'software_File'],
    ['used-deps', 'software_Package'],
    ['unused-deps', 'software_Package'],
    ['offgraph-sources', 'software_Package'],
    ['offgraph.c', 'software_File']
  ].map(([id, type]) => [id, { spdxId: id, type }])
);

const IMPACT_CHILDREN = new Map([['img', [{ id: 'img.elf', rel: 'contains' }]]]);

const CONTAINS = new Map([
  ['img', ['img.elf']],
  ['used-sources', ['used.c']],
  ['app-sources', ['main.c']],
  ['unused-sources', []],
  ['offgraph-sources', ['offgraph.c']]
]);

const PRODUCED_BY_BUILD = new Map([['img.elf', ['build']]]);
const BUILD_INPUTS = new Map([
  ['build', ['used-sources', 'unused-sources', 'app-sources', 'used-deps', 'unused-deps']]
]);

const variantRel = (from, to) => ({ from, to: [to], relationshipType: 'hasVariant' });
const REL_FROM = new Map([
  ['used-deps', [variantRel('used-deps', 'used-sources')]],
  ['unused-deps', [variantRel('unused-deps', 'unused-sources')]]
]);
const REL_TO = new Map([
  ['used-sources', [variantRel('used-deps', 'used-sources')]],
  ['unused-sources', [variantRel('unused-deps', 'unused-sources')]]
]);

const scope = (reach) =>
  buildSecurityScope({
    root: 'img',
    reach,
    impactChildIndex: IMPACT_CHILDREN,
    producedByBuildIndex: PRODUCED_BY_BUILD,
    buildInputIndex: BUILD_INPUTS,
    containsIndex: CONTAINS,
    elementMap: ELEMENTS,
    relFromIndex: REL_FROM,
    relToIndex: REL_TO
  });

test('buildSecurityScope', async (t) => {
  await t.test('walks build lineage, not just dependency edges', () => {
    // Nothing "depends on" the sources: they are reachable only by stepping
    // from the artifact back through the build that produced it.
    assert.ok(scope('declared').elements.has('used-sources'));
    assert.ok(scope('declared').elements.has('build'));
  });

  await t.test('declared reach keeps every package the closure names', () => {
    const packages = scope('declared').packages;
    assert.ok(packages.has('used-sources'));
    assert.ok(packages.has('unused-sources'), 'a declared input counts even with no files');
    assert.equal(packages.has('offgraph-sources'), false);
  });

  await t.test('compiled reach drops inputs that contributed no file', () => {
    const packages = scope('compiled').packages;
    assert.ok(packages.has('used-sources'));
    assert.ok(packages.has('app-sources'));
    assert.ok(packages.has('img'), 'the artifact is in its own scope');
    assert.equal(
      packages.has('unused-sources'),
      false,
      'declared by the manifest but never compiled in'
    );
  });

  await t.test('compiled reach keeps a reference-only twin of something that shipped', () => {
    const packages = scope('compiled').packages;
    assert.ok(packages.has('used-deps'), 'its -sources twin put a file in the image');
    assert.equal(packages.has('unused-deps'), false, 'its twin contributed nothing');
  });

  await t.test('reports what the contribution test removed', () => {
    const compiled = scope('compiled');
    // img, used/unused/app-sources, used/unused-deps
    assert.equal(compiled.reachedPackages, 6);
    // img, used-sources, app-sources, used-deps
    assert.equal(compiled.packages.size, 4);
    assert.equal(compiled.reachedPackages - compiled.packages.size, 2);
  });

  await t.test('defaults to compiled for an unknown reach', () => {
    assert.deepEqual(
      [...scope('nonsense').packages].sort(),
      [...scope('compiled').packages].sort()
    );
  });

  await t.test('falls back to reachability when nothing in scope records a file', () => {
    // A container scan or dependency manifest: packages, and nothing below them.
    // The contribution test would answer "nothing is in scope" for every
    // artifact, so it must not be applied at all.
    const fileless = buildSecurityScope({
      root: 'img',
      reach: 'compiled',
      impactChildIndex: IMPACT_CHILDREN,
      producedByBuildIndex: PRODUCED_BY_BUILD,
      buildInputIndex: BUILD_INPUTS,
      containsIndex: new Map(),
      elementMap: ELEMENTS,
      relFromIndex: REL_FROM,
      relToIndex: REL_TO
    });
    assert.equal(fileless.fellBack, true, 'callers can say why the narrowing is off');
    assert.equal(fileless.packages.size, fileless.reachedPackages, 'nothing was removed');
    assert.ok(fileless.packages.size > 0, 'the report is not silently emptied');
  });

  await t.test('a scope that legitimately reaches no package does not claim a fallback', () => {
    const empty = buildSecurityScope({
      root: 'nowhere',
      reach: 'compiled',
      impactChildIndex: new Map(),
      producedByBuildIndex: new Map(),
      buildInputIndex: new Map(),
      containsIndex: new Map(),
      elementMap: new Map(),
      relFromIndex: new Map(),
      relToIndex: new Map()
    });
    assert.equal(empty.fellBack, false);
    assert.equal(empty.reachedPackages, 0);
  });

  await t.test('a normal scope reports no fallback', () => {
    assert.equal(scope('compiled').fellBack, false);
    assert.equal(scope('declared').fellBack, false);
  });

  await t.test('scoping to a package with files puts that package in scope', () => {
    const empty = buildSecurityScope({
      root: 'offgraph-sources',
      reach: 'compiled',
      impactChildIndex: new Map(),
      producedByBuildIndex: new Map(),
      buildInputIndex: new Map(),
      containsIndex: CONTAINS,
      elementMap: ELEMENTS,
      relFromIndex: REL_FROM,
      relToIndex: REL_TO
    });
    // Nothing else is reachable, but the package carries a file of its own, so
    // a finding against it applies to the thing being scoped to.
    assert.deepEqual([...empty.elements], ['offgraph-sources']);
    assert.deepEqual([...empty.packages], ['offgraph-sources']);
  });
});

test('vulnInScope', async (t) => {
  const inScope = new Set(['used-sources', 'used-deps']);

  await t.test('a finding assessed against something in scope applies', () => {
    assert.equal(vulnInScope({ assessments: [{ packageId: 'used-deps' }] }, inScope), true);
  });

  await t.test('a finding assessed only against something out of scope does not', () => {
    assert.equal(vulnInScope({ assessments: [{ packageId: 'unused-deps' }] }, inScope), false);
  });

  await t.test('one in-scope assessment is enough', () => {
    const vuln = { assessments: [{ packageId: 'unused-deps' }, { packageId: 'used-sources' }] };
    assert.equal(vulnInScope(vuln, inScope), true);
  });

  await t.test('online matches count as subjects too', () => {
    const vuln = { assessments: [], online: { matched: [{ spdxId: 'used-sources' }] } };
    assert.equal(vulnInScope(vuln, inScope), true);
  });

  await t.test('a plain hasAssociatedVulnerability link counts as a subject', () => {
    // An SBOM may attach vulnerabilities with no VEX verdict at all; those
    // findings must not become invisible the moment a scope is chosen.
    const vuln = { assessments: [] };
    assert.equal(vulnInScope(vuln, inScope, ['used-sources']), true);
    assert.equal(vulnInScope(vuln, inScope, ['unused-sources']), false);
  });

  await t.test('a finding naming nothing is out of scope', () => {
    assert.equal(vulnInScope({ assessments: [] }, inScope), false);
  });

  await t.test('no scope means everything applies', () => {
    assert.equal(vulnInScope({ assessments: [] }, null), true);
  });
});
