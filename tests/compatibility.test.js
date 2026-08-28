import assert from 'node:assert/strict';
import test from 'node:test';

import { parseLicenseExpression, extractLicenseExpressionParts } from '../src/lib/licenses.js';
import {
  buildCompatMatrix,
  buildCompatReport,
  checkLicenseExpression,
  isRatedLicense,
  isSameLicense,
  licenseAlternatives,
  licensePairStatus,
  outboundCandidates,
  PROPRIETARY_OUTBOUND,
  ratedLicenses,
  resolveLicenseToken
} from '../src/lib/compatibility.js';
import { DISTRIBUTED_EDGE_TYPES, IMPACT_EDGE_TYPES } from '../src/lib/impact.js';
import { COMPAT_LICENSES, COMPAT_ROWS } from '../src/lib/osadl-matrix.js';

test('the vendored matrix is square and uses only known cell codes', () => {
  assert.equal(COMPAT_ROWS.length, COMPAT_LICENSES.length);
  for (const row of COMPAT_ROWS) {
    assert.equal(row.length, COMPAT_LICENSES.length);
    assert.match(row, /^[SYNUD]+$/);
  }
  // The diagonal is the license against itself, always "Same".
  COMPAT_ROWS.forEach((row, i) => assert.equal(row[i], 'S', `${COMPAT_LICENSES[i]} diagonal`));
});

test('license expressions parse with AND binding tighter than OR', () => {
  assert.deepEqual(parseLicenseExpression('MIT'), { type: 'id', id: 'MIT' });

  // `A OR B AND C` is `A OR (B AND C)`, not `(A OR B) AND C`.
  const tree = parseLicenseExpression('MIT OR GPL-2.0-only AND BSD-3-Clause');
  assert.equal(tree.type, 'compound');
  assert.equal(tree.op, 'OR');
  assert.deepEqual(tree.left, { type: 'id', id: 'MIT' });
  assert.equal(tree.right.op, 'AND');

  assert.equal(parseLicenseExpression('MIT AND'), null);
  assert.equal(parseLicenseExpression('NoAssertion'), null);
  assert.equal(parseLicenseExpression(''), null);
});

test('extractLicenseExpressionParts still collects every distinct part', () => {
  assert.deepEqual(extractLicenseExpressionParts('MIT OR GPL-2.0-only AND MIT'), [
    { id: 'MIT', kind: 'license' },
    { id: 'GPL-2.0-only', kind: 'license' }
  ]);
  assert.deepEqual(extractLicenseExpressionParts('GPL-2.0-only WITH Classpath-exception-2.0'), [
    { id: 'GPL-2.0-only', kind: 'license' },
    { id: 'Classpath-exception-2.0', kind: 'exception', withLicense: 'GPL-2.0-only' }
  ]);
});

test('alternatives expand OR into choices and AND into combinations', () => {
  assert.deepEqual(licenseAlternatives('MIT'), [['MIT']]);
  assert.deepEqual(licenseAlternatives('MIT OR Apache-2.0'), [['MIT'], ['Apache-2.0']]);
  assert.deepEqual(licenseAlternatives('MIT AND Apache-2.0'), [['MIT', 'Apache-2.0']]);
  assert.deepEqual(licenseAlternatives('(MIT OR ISC) AND BSD-3-Clause'), [
    ['MIT', 'BSD-3-Clause'],
    ['ISC', 'BSD-3-Clause']
  ]);
  // A license repeated across both sides of an AND is only listed once.
  assert.deepEqual(licenseAlternatives('MIT AND MIT'), [['MIT']]);
  assert.deepEqual(licenseAlternatives('not a license expression!'), []);
});

test('licensePairStatus reads the matrix in the outbound-to-inbound direction', () => {
  // GPL-3.0-or-later may absorb Apache-2.0, but not the other way round.
  assert.equal(licensePairStatus('GPL-3.0-or-later', 'Apache-2.0'), 'compatible');
  assert.equal(licensePairStatus('Apache-2.0', 'GPL-3.0-or-later'), 'conflict');

  assert.equal(licensePairStatus('MIT', 'MIT'), 'compatible');
  assert.equal(licensePairStatus('AGPL-3.0-only', 'GPL-3.0-only'), 'review');
  assert.equal(licensePairStatus('MIT', 'LicenseRef-something'), 'unrated');
  assert.equal(licensePairStatus('', 'MIT'), 'unrated');
});

test('token resolution falls back only in ways that cannot flatter the result', () => {
  assert.deepEqual(resolveLicenseToken('MIT'), { token: 'MIT', id: 'MIT', exact: true, note: '' });

  // "or later" written with the deprecated + suffix.
  const orLater = resolveLicenseToken('GPL-2.0+');
  assert.equal(orLater.id, 'GPL-2.0-or-later');
  assert.equal(orLater.exact, false);

  // A bare, deprecated id resolves to the stricter -only reading.
  assert.equal(resolveLicenseToken('GPL-2.0').id, 'GPL-2.0-only');

  // An exception the matrix rates is used as-is; one it does not falls back to
  // the bare license, which can only be stricter.
  assert.equal(
    resolveLicenseToken('GPL-2.0-only WITH Classpath-exception-2.0').exact,
    true,
    'the one WITH pair OSADL rates is matched exactly'
  );
  const fallback = resolveLicenseToken('GPL-2.0-only WITH Linux-syscall-note');
  assert.equal(fallback.id, 'GPL-2.0-only');
  assert.equal(fallback.exact, false);
  assert.match(fallback.note, /GPL-2\.0-only alone/);

  assert.equal(resolveLicenseToken('LicenseRef-acme-proprietary').id, '');
  assert.equal(resolveLicenseToken('').id, '');
});

test('an expression is compatible when any one of its alternatives is', () => {
  const check = checkLicenseExpression('GPL-2.0-only OR Apache-2.0', 'Apache-2.0');
  assert.equal(check.status, 'compatible');
  assert.deepEqual(check.alternative, ['Apache-2.0'], 'reports the branch that cleared it');
  assert.equal(check.choice, true);
  assert.deepEqual(check.blockers, []);
});

test('an AND expression is only as good as its worst member', () => {
  const check = checkLicenseExpression('MIT AND GPL-2.0-only', 'Apache-2.0');
  assert.equal(check.status, 'conflict');
  assert.deepEqual(
    check.blockers.map((term) => term.token),
    ['GPL-2.0-only']
  );
});

test('the same license is reported as such, not merely compatible', () => {
  const check = checkLicenseExpression('Apache-2.0', 'Apache-2.0');
  assert.equal(check.status, 'compatible');
  assert.equal(check.sameLicense, true);
  assert.equal(checkLicenseExpression('MIT', 'Apache-2.0').sameLicense, false);
});

test('unparseable and unrated expressions are unrated, never compatible', () => {
  const unparsed = checkLicenseExpression('NoAssertion', 'MIT');
  assert.equal(unparsed.status, 'unrated');
  assert.equal(unparsed.parsed, false);

  const unrated = checkLicenseExpression('LicenseRef-acme', 'MIT');
  assert.equal(unrated.status, 'unrated');
  assert.equal(unrated.parsed, true);
  assert.equal(unrated.terms[0].id, '');
});

test('an unrated member drags a whole conjunction down to unrated', () => {
  const check = checkLicenseExpression('MIT AND LicenseRef-acme', 'MIT');
  assert.equal(check.status, 'unrated');
  assert.deepEqual(
    check.blockers.map((term) => term.token),
    ['LicenseRef-acme']
  );
});

const SUBJECTS = [
  { id: 'l1', expression: 'GPL-2.0-only', elements: ['pkg:a', 'pkg:b'] },
  { id: 'l2', expression: 'MIT', elements: ['pkg:b', 'pkg:c'] },
  { id: 'l3', expression: 'LicenseRef-acme', elements: ['pkg:d'] }
];

test('buildCompatReport counts licenses and elements, and orders worst first', () => {
  const report = buildCompatReport(SUBJECTS, 'Apache-2.0');

  assert.equal(report.findings[0].status, 'conflict', 'conflicts sort to the top');
  assert.equal(report.findings[0].id, 'l1');

  assert.deepEqual(report.totals.conflict, { licenses: 1, elements: 2 });
  assert.deepEqual(report.totals.compatible, { licenses: 1, elements: 2 });
  assert.deepEqual(report.totals.unrated, { licenses: 1, elements: 1 });
  assert.deepEqual(report.totals.review, { licenses: 0, elements: 0 });

  assert.equal(report.licenseCount, 3);
  assert.equal(report.elementCount, 4, 'pkg:b carries two licenses but counts once');
  // pkg:a and pkg:b carry the conflicting license, so only pkg:c and pkg:d are clear.
  assert.equal(report.clearElementCount, 2);
});

test('buildCompatReport keeps the subject fields the UI needs', () => {
  const report = buildCompatReport([{ id: 'l1', expression: 'MIT', label: 'MIT license' }], 'MIT');
  assert.equal(report.findings[0].label, 'MIT license');
  assert.equal(report.findings[0].elementCount, 0);
  assert.equal(buildCompatReport([], 'MIT').licenseCount, 0);
});

test('outboundCandidates ranks by conflicts and matches a direct check', () => {
  const candidates = outboundCandidates(SUBJECTS);
  assert.equal(
    candidates.length,
    COMPAT_LICENSES.length + 1,
    'the proprietary option is ranked too'
  );

  const best = candidates[0];
  assert.equal(best.conflict, 0, 'a license exists that absorbs both GPL-2.0-only and MIT');
  assert.ok(
    candidates.every((candidate, i) => i === 0 || candidate.conflict >= best.conflict),
    'sorted by conflict count'
  );

  // Unrated licenses do not depend on the outbound choice, so every candidate
  // sees the same one.
  assert.ok(candidates.every((candidate) => candidate.unrated === 1));

  // The ranking must agree with checking each subject one at a time.
  for (const candidate of [candidates[0], candidates[40], candidates.at(-1)]) {
    const report = buildCompatReport(SUBJECTS, candidate.id);
    assert.equal(report.totals.conflict.licenses, candidate.conflict, candidate.id);
    assert.equal(report.totals.review.licenses, candidate.review, candidate.id);
    assert.equal(report.totals.compatible.licenses, candidate.compatible, candidate.id);
    assert.equal(
      report.totals.conflict.elements,
      candidate.blockedElements,
      `${candidate.id} blocked elements`
    );
  }
});

test('outboundCandidates honours a limit', () => {
  assert.equal(outboundCandidates(SUBJECTS, { limit: 5 }).length, 5);
  assert.equal(outboundCandidates([]).length, COMPAT_LICENSES.length + 1);
});

test('buildCompatMatrix grids the licenses and finds two-way conflicts', () => {
  const matrix = buildCompatMatrix([
    { id: 'a', expression: 'GPL-2.0-only' },
    { id: 'b', expression: 'Apache-2.0' },
    { id: 'c', expression: 'MIT OR ISC' }
  ]);

  assert.equal(matrix.rows.length, 3);
  assert.equal(matrix.rows[0].cells[0].same, true);
  assert.equal(matrix.rows[0].cells[1].status, 'conflict', 'GPL-2.0-only cannot take Apache-2.0');
  assert.equal(matrix.rows[1].cells[0].status, 'conflict', 'nor the other way round');
  assert.equal(matrix.conflictPairs, 1);

  // A choice expression has no single identifier, so it cannot be gridded.
  assert.equal(matrix.licenses[2].matrixId, '');
  assert.equal(matrix.rows[2].cells[0].status, 'unrated');
  assert.equal(matrix.rows[0].cells[2].status, 'unrated');
});

test('buildCompatMatrix flags approximated identifiers', () => {
  const matrix = buildCompatMatrix([{ id: 'a', expression: 'GPL-2.0+' }]);
  assert.equal(matrix.licenses[0].matrixId, 'GPL-2.0-or-later');
  assert.equal(matrix.licenses[0].approximate, true);
  assert.equal(buildCompatMatrix([]).conflictPairs, 0);
});

test('isRatedLicense answers for the outbound picker', () => {
  assert.equal(isRatedLicense('Apache-2.0'), true);
  assert.equal(isRatedLicense('apache-2.0'), true, 'case is forgiven');
  assert.equal(isRatedLicense(PROPRIETARY_OUTBOUND), true);
  assert.equal(isRatedLicense('LicenseRef-acme'), false);
  assert.equal(isRatedLicense(''), false);
});

test('the proprietary outbound is offered first, ahead of the SPDX ids', () => {
  const all = ratedLicenses();
  assert.equal(all[0], PROPRIETARY_OUTBOUND);
  assert.equal(all.length, COMPAT_LICENSES.length + 1);
  assert.deepEqual(
    all.slice(1),
    [...COMPAT_LICENSES].sort((a, b) => a.localeCompare(b))
  );
});

test('every permissive reference row agrees on what a proprietary work can absorb', () => {
  // The proprietary answer is only derivable because the matrix draws a sharp
  // permissive/copyleft line. If a future revision blurs it this test says so,
  // rather than the UI quietly reporting one row's opinion as fact.
  const references = ['MIT', 'BSD-3-Clause', 'Apache-2.0', 'ISC', '0BSD', 'Zlib', 'BSL-1.0'];
  const accepted = references.map(
    (ref) => new Set(COMPAT_LICENSES.filter((id) => licensePairStatus(ref, id) === 'compatible'))
  );
  for (const set of accepted) {
    assert.equal(set.size, accepted[0].size, 'permissive rows accept the same number of licenses');
    for (const id of accepted[0]) assert.ok(set.has(id), `${id} accepted by every permissive row`);
  }
});

test('proprietary clears permissive licenses and blocks copyleft ones', () => {
  for (const id of ['MIT', 'BSD-3-Clause', 'Apache-2.0', 'ISC', 'Zlib', 'X11', 'Unlicense']) {
    assert.equal(licensePairStatus(PROPRIETARY_OUTBOUND, id), 'compatible', id);
  }
  for (const id of [
    'GPL-2.0-only',
    'GPL-3.0-or-later',
    'AGPL-3.0-only',
    'LGPL-2.1-only',
    'MPL-2.0',
    'EPL-2.0'
  ]) {
    assert.equal(licensePairStatus(PROPRIETARY_OUTBOUND, id), 'conflict', id);
  }
  // Outside the matrix stays outside it: proprietary claims nothing there.
  assert.equal(licensePairStatus(PROPRIETARY_OUTBOUND, 'LicenseRef-acme'), 'unrated');
  // Nothing is ever "the same license" as a proprietary product.
  assert.equal(isSameLicense(PROPRIETARY_OUTBOUND, 'MIT'), false);
});

test('proprietary flows through expressions like any other outbound', () => {
  const choice = checkLicenseExpression('GPL-2.0-only OR MIT', PROPRIETARY_OUTBOUND);
  assert.equal(choice.status, 'compatible');
  assert.deepEqual(choice.alternative, ['MIT'], 'takes the branch that clears it');

  const both = checkLicenseExpression('MIT AND GPL-2.0-only', PROPRIETARY_OUTBOUND);
  assert.equal(both.status, 'conflict');

  const report = buildCompatReport(SUBJECTS, PROPRIETARY_OUTBOUND);
  assert.equal(report.outbound, PROPRIETARY_OUTBOUND);
  assert.deepEqual(
    report.totals.conflict,
    { licenses: 1, elements: 2 },
    'the GPL-2.0-only subject'
  );
  assert.deepEqual(report.totals.compatible, { licenses: 1, elements: 2 }, 'the MIT subject');
  assert.deepEqual(report.totals.unrated, { licenses: 1, elements: 1 });
});

test('the distributed edge set is the shipped subset of the dependency edges', () => {
  for (const type of DISTRIBUTED_EDGE_TYPES) {
    assert.ok(IMPACT_EDGE_TYPES.has(type), `${type} is a dependency edge`);
  }
  // Edges that mean "needed" rather than "shipped inside" must stay out, or the
  // distributed-only scope would pull in components the product never carries.
  for (const type of ['hasOptionalComponent', 'hasProvidedDependency', 'hasPrerequisite']) {
    assert.ok(IMPACT_EDGE_TYPES.has(type), `${type} is still traversed normally`);
    assert.equal(DISTRIBUTED_EDGE_TYPES.has(type), false, `${type} is not distributed`);
  }
  for (const type of ['dependsOn', 'contains', 'hasStaticLink', 'hasDynamicLink']) {
    assert.ok(DISTRIBUTED_EDGE_TYPES.has(type), `${type} ships`);
  }
});
