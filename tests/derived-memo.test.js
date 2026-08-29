import assert from 'node:assert/strict';
import test from 'node:test';

import { derivedMixin } from '../src/app/derived.js';
import { securityMixin } from '../src/app/security.js';
import { CLASS } from '../src/spdx/model.js';

// The summary getters are whole-collection scans memoized on their source
// array's identity: same array in, same object out; a replaced array (a fresh
// parse, or the merged vuln list changing after an online sync) recomputes.

function makeApp(overrides = {}) {
  const app = {};
  for (const mixin of [derivedMixin, securityMixin]) {
    Object.defineProperties(app, Object.getOwnPropertyDescriptors(mixin));
  }
  return Object.assign(app, overrides);
}

test('securitySummary', async (t) => {
  const vulns = [
    { spdxId: 'v1', overallStatus: 'affected', source: 'sbom', severity: 'high' },
    { spdxId: 'v2', overallStatus: 'fixed', source: 'online' },
    { spdxId: 'v3', overallStatus: 'affected', source: 'both', severity: 'critical' }
  ];
  const app = makeApp({ vulnerabilities: vulns, onlineVulns: [] });

  await t.test('counts statuses and provenance', () => {
    const s = app.securitySummary;
    assert.equal(s.total, 3);
    assert.equal(s.counts.affected, 2);
    assert.equal(s.counts.fixed, 1);
    assert.equal(s.sbomTotal, 2);
    assert.equal(s.onlineTotal, 2);
    assert.equal(s.newOnline, 1);
    assert.equal(s.both, 1);
  });

  await t.test('repeated reads return the same object', () => {
    assert.equal(app.securitySummary, app.securitySummary);
  });

  await t.test('a replaced list recomputes', () => {
    const before = app.securitySummary;
    app.vulnerabilities = [...vulns, { spdxId: 'v4', overallStatus: 'fixed', source: 'sbom' }];
    const after = app.securitySummary;
    assert.notEqual(after, before);
    assert.equal(after.total, 4);
    assert.equal(after.counts.fixed, 2);
  });
});

test('securitySeveritySummary and hasCvssData', async (t) => {
  const vulns = [
    { spdxId: 'v1', severity: 'high' },
    { spdxId: 'v2' },
    { spdxId: 'v3', severity: 'critical' },
    { spdxId: 'v4', severity: 'exotic' }
  ];
  const app = makeApp({ vulnerabilities: vulns, onlineVulns: [] });

  await t.test('counts only the standard bands', () => {
    const s = app.securitySeveritySummary;
    assert.equal(s.scored, 2);
    assert.equal(s.counts.high, 1);
    assert.equal(s.counts.critical, 1);
    assert.equal(app.securitySeveritySummary, s);
  });

  await t.test('hasCvssData memoizes per list identity', () => {
    assert.equal(app.hasCvssData, true);
    app.vulnerabilities = [{ spdxId: 'v1' }];
    assert.equal(app.hasCvssData, false);
  });
});

test('safetyCounts', () => {
  const app = makeApp({
    requirements: [
      { spdxId: 'r1', type: CLASS.Requirement, _level: 'software' },
      { spdxId: 'r2', type: CLASS.Requirement, _level: 'system' },
      { spdxId: 'ver1', type: CLASS.functionalsafety_RequirementVerification },
      { spdxId: 'as1', type: CLASS.functionalsafety_Assumption }
    ],
    requirementLevel: (r) => r._level || ''
  });
  const c = app.safetyCounts;
  assert.equal(c.requirements, 2);
  assert.equal(c.systemRequirements, 1);
  assert.equal(c.verifications, 1);
  assert.equal(c.assumptions, 1);
  assert.equal(app.safetyCounts, c, 'same list, same object');
});

test('safetyStatusSummary', () => {
  const app = makeApp({
    requirements: [
      { spdxId: 'r1', type: CLASS.Requirement, _status: 'passed' },
      { spdxId: 'r2', type: CLASS.Requirement, _status: 'failed' },
      { spdxId: 'r3', type: CLASS.Requirement, _status: 'unverified' }
    ],
    requirementSafetyStatus: (r) => ({ key: r._status })
  });
  const s = app.safetyStatusSummary;
  assert.equal(s.total, 3);
  assert.equal(s.counts.passed, 1);
  assert.equal(s.counts.failed, 1);
  assert.equal(s.passPct, 33);
  assert.equal(s.verifiedPct, 67);
  assert.equal(app.safetyStatusSummary, s, 'same list, same object');
});

test('supplyChainCounts', () => {
  const app = makeApp({
    supplyChain: [
      { spdxId: 's1', type: CLASS.supplychain_TransportAction, _kind: 'action' },
      { spdxId: 's2', type: CLASS.supplychain_CreateProcess, _kind: 'process' },
      { spdxId: 's3', type: CLASS.supplychain_State, _kind: 'state' }
    ],
    supplyChainKind: (el) => el._kind,
    supplyChainExceptionStatus: () => null
  });
  const c = app.supplyChainCounts;
  assert.equal(c.actions, 1);
  assert.equal(c.processes, 1);
  assert.equal(c.states, 1);
  assert.equal(c.transports, 1);
  assert.equal(app.supplyChainCounts, c, 'same list, same object');
});

test('vulnRecord', async (t) => {
  const vulns = [
    { spdxId: 'urn:v1', name: 'CVE-2026-0001' },
    { spdxId: 'online:CVE-2026-0002', name: 'CVE-2026-0002' }
  ];
  const app = makeApp({ vulnerabilities: vulns, onlineVulns: [] });

  await t.test('resolves ids from the merged list', () => {
    assert.equal(app.vulnRecord('urn:v1').name, 'CVE-2026-0001');
    assert.equal(app.vulnRecord('online:CVE-2026-0002').name, 'CVE-2026-0002');
    assert.equal(app.vulnRecord('urn:nope'), null);
  });

  await t.test('the lookup follows a replaced list', () => {
    app.vulnerabilities = [{ spdxId: 'urn:v9', name: 'CVE-2026-0009' }];
    assert.equal(app.vulnRecord('urn:v9').name, 'CVE-2026-0009');
    assert.equal(app.vulnRecord('urn:v1'), null);
  });
});
