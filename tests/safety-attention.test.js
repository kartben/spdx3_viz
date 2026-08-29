import assert from 'node:assert/strict';
import test from 'node:test';

import { accessorsMixin } from '../src/app/accessors.js';
import { SAFETY_STATUSES } from '../src/config.js';
import { CLASS } from '../src/spdx/model.js';

// A requirement can pass every test that verifies it and still never have its
// implementation executed by those tests. The row has to say so, and the list
// has to put it first, or nothing in the UI ever draws the eye to it.

function makeApp(overrides = {}) {
  const app = {};
  Object.defineProperties(app, Object.getOwnPropertyDescriptors(accessorsMixin));
  return Object.assign(app, overrides);
}

const req = (id, adequacy) => ({
  spdxId: id,
  type: CLASS.Requirement,
  externalIdentifier: adequacy ? [{ identifier: `adequacy:${adequacy}` }] : []
});

function appWith(statusByeId) {
  return makeApp({
    externalIdentifiers: (el) => el.externalIdentifier || [],
    requirementSafetyStatus: (el) => SAFETY_STATUSES[statusByeId[el.spdxId]] || null
  });
}

test('requirementRowStatus overrides a pass that never ran the implementation', () => {
  const app = appWith({ broken: 'passed', partial: 'passed', fine: 'passed' });

  const broken = app.requirementRowStatus(req('broken', 'broken'));
  assert.equal(broken.key, 'broken');
  assert.equal(broken.label, 'Not exercised');
  // the title has to carry both halves, since it is the row's accessible name
  assert.match(broken.title, /^Passed · /);

  assert.equal(app.requirementRowStatus(req('partial', 'partial')).key, 'partial');
  // anything else is left exactly as the verification outcome reported it
  assert.equal(app.requirementRowStatus(req('fine', 'true')), SAFETY_STATUSES.passed);
});

test('an outright test failure still dominates the row', () => {
  const app = appWith({ r: 'failed' });
  assert.equal(app.requirementRowStatus(req('r', 'broken')), SAFETY_STATUSES.failed);
});

test('requirementAttentionRank sorts the misleading states above the honest ones', () => {
  const app = appWith({
    broken: 'passed',
    failed: 'failed',
    partial: 'passed',
    untested: 'unverified',
    noimpl: 'passed',
    healthy: 'passed'
  });
  const rank = (id, adequacy) => app.requirementAttentionRank(req(id, adequacy));

  // a requirement that looks verified but is not comes before a plain failure
  assert.ok(rank('broken', 'broken') < rank('failed', null));
  assert.ok(rank('failed', null) < rank('partial', 'partial'));
  assert.ok(rank('partial', 'partial') < rank('untested', null));
  // nothing verifies it beats "verified, but we cannot see what implements it"
  assert.ok(rank('untested', null) < rank('noimpl', 'no-impl'));
  assert.ok(rank('noimpl', 'no-impl') < rank('healthy', 'true'));
  // a requirement with neither tests nor an implementation ranks as untested:
  // writing a test is the actionable gap, and it is the more urgent of the two
  assert.equal(rank('untested', 'no-impl'), rank('untested', null));
  // non-requirements sort out of the way entirely
  assert.equal(app.requirementAttentionRank({ type: CLASS.functionalsafety_Assumption }), 99);
});
