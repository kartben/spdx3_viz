import assert from 'node:assert/strict';
import test from 'node:test';

import { computeHeatIndex, HEAT_MODES, heatModeMeta } from '../src/lib/index.js';

const vulns = [
  {
    spdxId: 'vuln:critical',
    severity: 'critical',
    severityRank: 5,
    assessments: [
      { packageId: 'pkg:a', status: 'affected' },
      { packageId: 'pkg:fixed', status: 'fixed' } // resolved -> must not heat
    ]
  },
  {
    spdxId: 'vuln:medium',
    severity: 'medium',
    severityRank: 3,
    assessments: [
      { packageId: 'pkg:a', status: 'under_investigation' }, // lower than critical on pkg:a
      { packageId: 'pkg:b', status: 'under_investigation' }
    ]
  },
  {
    spdxId: 'vuln:unscored',
    severity: '',
    severityRank: 0,
    assessments: [{ packageId: 'pkg:c', status: 'affected' }]
  }
];

test('vuln heat marks only open assessments, keeping the worst severity per element', () => {
  const heat = computeHeatIndex('vuln', { vulnerabilities: vulns });

  assert.deepEqual(new Set(heat.keys()), new Set(['pkg:a', 'pkg:b', 'pkg:c']));
  // pkg:a is hit by critical + medium; the critical intensity/colour wins.
  assert.equal(heat.get('pkg:a').intensity, 1);
  assert.equal(heat.get('pkg:a').color, '#f43f5e');
  // A medium-only element sits between the floor and the top.
  assert.ok(heat.get('pkg:b').intensity > 0.4 && heat.get('pkg:b').intensity < 1);
  // An unscored-but-open vulnerability still reads as warm (floor).
  assert.equal(heat.get('pkg:c').intensity, 0.4);
  // A fixed assessment never appears.
  assert.ok(!heat.has('pkg:fixed'));
});

const requirements = [
  { spdxId: 'req:fail', type: 'Requirement' },
  { spdxId: 'req:incon', type: 'Requirement' },
  { spdxId: 'req:unver', type: 'Requirement' },
  { spdxId: 'req:noimpl', type: 'Requirement' },
  { spdxId: 'req:pass', type: 'Requirement' },
  { spdxId: 'ver:x', type: 'functionalsafety_RequirementVerification' } // not a Requirement
];

const statusByReq = {
  'req:fail': { key: 'failed' },
  'req:incon': { key: 'inconclusive' },
  'req:unver': { key: 'unverified' },
  'req:noimpl': { key: 'verified' },
  'req:pass': { key: 'passed' }
};
const requirementStatus = (r) => (r.type === 'Requirement' ? statusByReq[r.spdxId] : null);
const implementedByCount = (id) => (id === 'req:noimpl' ? 0 : 2);

test('failed heat marks failing (hottest) and inconclusive requirements only', () => {
  const heat = computeHeatIndex('failed', { requirements, requirementStatus });

  assert.deepEqual(new Set(heat.keys()), new Set(['req:fail', 'req:incon']));
  assert.equal(heat.get('req:fail').intensity, 1);
  assert.ok(heat.get('req:incon').intensity < heat.get('req:fail').intensity);
  // Verification elements are never treated as requirements.
  assert.ok(!heat.has('ver:x'));
});

test('unverified heat covers unverified requirements and traceability gaps', () => {
  const heat = computeHeatIndex('unverified', {
    requirements,
    requirementStatus,
    implementedByCount
  });

  assert.deepEqual(new Set(heat.keys()), new Set(['req:unver', 'req:noimpl']));
  // An unverified requirement runs hotter than a mere no-implementation gap.
  assert.ok(heat.get('req:unver').intensity > heat.get('req:noimpl').intensity);
  assert.equal(heat.get('req:noimpl').color, '#fb923c');
});

test('unknown / off mode yields an empty heat map', () => {
  assert.equal(computeHeatIndex('off', { vulnerabilities: vulns }).size, 0);
  assert.equal(computeHeatIndex('nonsense', {}).size, 0);
});

test('every heat mode has renderable metadata', () => {
  for (const mode of HEAT_MODES) {
    const meta = heatModeMeta(mode.key);
    assert.equal(meta.key, mode.key);
    assert.match(meta.color, /^#[0-9a-f]{6}$/i);
    assert.ok(meta.icon && meta.label && meta.short);
  }
  // Unknown keys fall back to a neutral "off" descriptor rather than throwing.
  assert.equal(heatModeMeta('whatever').label, 'Off');
});
