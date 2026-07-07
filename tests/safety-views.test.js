import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { spdxApp } from '../src/app.js';
import { buildRelationshipIndexes, parseGraph } from '../src/parser/parser.js';

function loadSampleApp(samplePath) {
  const json = JSON.parse(readFileSync(samplePath, 'utf8'));
  const parsed = parseGraph(json['@graph'] || json);
  const indexes = buildRelationshipIndexes(parsed.relationships);
  const app = spdxApp();
  Object.assign(app, parsed, indexes);
  return app;
}

test('AEB functional-safety sample builds complete coverage rows', () => {
  const app = loadSampleApp('public/samples/functional-safety/aeb-safety-case.spdx3.jsonld');

  assert.equal(app.safetyCoverageBaseRows.length, 48);
  assert.equal(app.safetyStatusSummary.noImpl, 0);
  assert.equal(app.safetyStatusSummary.noEvidence, 0);
  assert.equal(app.safetyStatusSummary.counts.passed, 46);
  assert.equal(app.safetyStatusSummary.counts.failed, 1);
  assert.equal(app.safetyStatusSummary.counts.inconclusive, 1);

  const row = app.safetyCoverageBaseRows.find((r) => r.uid === 'SG-01');
  assert.ok(row);
  assert.equal(row.implementationCount, 1);
  assert.equal(row.verificationCount, 1);
  assert.equal(row.evidenceCount, 1);
  assert.deepEqual(row.methods, ['assessment']);
  assert.deepEqual(row.evidenceCategories, ['report']);

  const brakeGroup = app.safetyAllocationGroups.find((g) => g.name === 'Brake demand arbitrator');
  assert.equal(brakeGroup?.requirementCount, 10);
});

test('Zephyr safety sample exposes allocation and evidence gaps', () => {
  const app = loadSampleApp('public/samples/zephyr-experimental/safety.jsonld');

  assert.equal(app.safetyCoverageBaseRows.length, 529);
  assert.equal(app.safetyStatusSummary.noImpl, 265);
  assert.equal(app.safetyStatusSummary.noEvidence, 265);
  assert.equal(app.safetyStatusSummary.counts.passed, 322);
  assert.equal(app.safetyStatusSummary.counts.failed, 1);
  assert.equal(app.safetyStatusSummary.counts.inconclusive, 25);
  assert.equal(app.safetyStatusSummary.counts.unverified, 181);

  app.requirementStatusFilter = 'noevidence';
  assert.equal(app.safetyCoverageRows.length, 265);
  assert.ok(app.safetyCoverageRows.every((row) => row.gapKeys.includes('noevidence')));

  const unallocated = app.safetyAllocationGroups.find((g) => g.key === '__unallocated__');
  assert.equal(unallocated?.requirementCount, 241);

  app.requirementStatusFilter = 'noimpl';
  assert.equal(app.safetyCoverageRows.length, 265);
  const unimplemented = app.safetyAllocationGroups.find((g) => g.key === '__unallocated__');
  assert.equal(unimplemented?.requirementCount, 265);

  app.requirementStatusFilter = '';
  assert.ok(app.safetyAllocationGroups.some((g) => g.snippetCount > 0));
  assert.ok(app.safetyAssuranceRoots.length > 0);
  assert.ok(app.safetyAssuranceContext.specifications.length > 0);
});
