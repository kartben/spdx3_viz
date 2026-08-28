import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  parseLicenseExpression,
  normalizeSpdxLicenseId,
  licenseExpressionAtomIds
} from '../src/lib/licenses.js';
import {
  parseOsadlMatrix,
  getCompatibility,
  evaluateOutboundAgainst,
  outboundCandidates,
  analyzeSbomLicenses,
  describeCompatibility,
  formatInboundList,
  formatMatrixTimestamp,
  groupConflictsByOutbound,
  isCompatYes,
  shortLicenseLabel,
  COMPAT_STATUS,
  COMPAT_VERDICT,
  andTrees
} from '../src/lib/license-compat.js';

const FIXTURE = parseOsadlMatrix({
  timestamp: '2026-08-20T12:46:00+0000',
  timeformat: '%Y-%m-%dT%H:%M:%S%z',
  MIT: {
    MIT: 'Same',
    'BSD-3-Clause': 'Yes',
    'Apache-2.0': 'Yes',
    'GPL-2.0-only': 'No',
    'GPL-2.0-or-later': 'No',
    'GPL-3.0-only': 'No'
  },
  'BSD-3-Clause': {
    MIT: 'Yes',
    'BSD-3-Clause': 'Same',
    'Apache-2.0': 'Yes',
    'GPL-2.0-only': 'No',
    'GPL-2.0-or-later': 'No',
    'GPL-3.0-only': 'No'
  },
  'Apache-2.0': {
    MIT: 'Yes',
    'BSD-3-Clause': 'Yes',
    'Apache-2.0': 'Same',
    'GPL-2.0-only': 'No',
    'GPL-2.0-or-later': 'No',
    'GPL-3.0-only': 'No'
  },
  'GPL-2.0-only': {
    MIT: 'Yes',
    'BSD-3-Clause': 'Yes',
    'Apache-2.0': 'No',
    'GPL-2.0-only': 'Same',
    'GPL-2.0-or-later': 'Yes',
    'GPL-3.0-only': 'No'
  },
  'GPL-2.0-or-later': {
    MIT: 'Yes',
    'BSD-3-Clause': 'Yes',
    'Apache-2.0': 'No',
    'GPL-2.0-only': 'No',
    'GPL-2.0-or-later': 'Same',
    'GPL-3.0-only': 'No'
  },
  'GPL-3.0-only': {
    MIT: 'Yes',
    'BSD-3-Clause': 'Yes',
    'Apache-2.0': 'Yes',
    'GPL-2.0-only': 'No',
    'GPL-2.0-or-later': 'Yes',
    'GPL-3.0-only': 'Same'
  }
});

describe('normalizeSpdxLicenseId', () => {
  it('maps deprecated GPL-family ids onto the -only / -or-later split', () => {
    assert.equal(normalizeSpdxLicenseId('GPL-2.0'), 'GPL-2.0-only');
    assert.equal(normalizeSpdxLicenseId('GPL-2.0+'), 'GPL-2.0-or-later');
    assert.equal(normalizeSpdxLicenseId('LGPL-2.1'), 'LGPL-2.1-only');
    assert.equal(normalizeSpdxLicenseId('AGPL-3.0+'), 'AGPL-3.0-or-later');
  });

  it('turns a trailing + into -or-later when there is no alias', () => {
    assert.equal(normalizeSpdxLicenseId('Apache-2.0+'), 'Apache-2.0-or-later');
    assert.equal(normalizeSpdxLicenseId('GPL-2.0-only+'), 'GPL-2.0-or-later');
  });

  it('aliases informal BSD names and leaves current ids alone', () => {
    assert.equal(normalizeSpdxLicenseId('BSD'), 'BSD-3-Clause');
    assert.equal(normalizeSpdxLicenseId('MIT'), 'MIT');
    assert.equal(normalizeSpdxLicenseId(''), '');
  });
});

describe('parseLicenseExpression', () => {
  it('binds AND tighter than OR', () => {
    const tree = parseLicenseExpression('MIT OR Apache-2.0 AND GPL-2.0-only');
    assert.equal(tree.type, 'compound');
    assert.equal(tree.op, 'OR');
    assert.equal(tree.left.id, 'MIT');
    assert.equal(tree.right.op, 'AND');
    assert.equal(tree.right.left.id, 'Apache-2.0');
    assert.equal(tree.right.right.id, 'GPL-2.0-only');
  });

  it('parses WITH as a single node', () => {
    const tree = parseLicenseExpression('GPL-2.0-only WITH Classpath-exception-2.0');
    assert.deepEqual(tree, {
      type: 'with',
      licenseId: 'GPL-2.0-only',
      exceptionId: 'Classpath-exception-2.0'
    });
  });

  it('returns null for empty or NoAssertion expressions', () => {
    assert.equal(parseLicenseExpression(''), null);
    assert.equal(parseLicenseExpression('NOASSERTION'), null);
    assert.equal(parseLicenseExpression('MIT AND'), null);
  });

  it('lists unique atoms including WITH pairs', () => {
    const tree = parseLicenseExpression(
      'MIT AND GPL-2.0-only WITH Classpath-exception-2.0 AND MIT'
    );
    assert.deepEqual(licenseExpressionAtomIds(tree), [
      'MIT',
      'GPL-2.0-only WITH Classpath-exception-2.0'
    ]);
  });
});

describe('getCompatibility', () => {
  it('treats the matrix as outbound row, inbound column', () => {
    assert.equal(getCompatibility('GPL-2.0-only', 'MIT', FIXTURE), COMPAT_STATUS.YES);
    assert.equal(getCompatibility('MIT', 'GPL-2.0-only', FIXTURE), COMPAT_STATUS.NO);
    assert.equal(getCompatibility('MIT', 'MIT', FIXTURE), COMPAT_STATUS.SAME);
  });

  it('normalizes deprecated ids before lookup', () => {
    assert.equal(getCompatibility('GPL-2.0', 'MIT', FIXTURE), COMPAT_STATUS.YES);
    assert.equal(getCompatibility('MIT', 'GPL-2.0+', FIXTURE), COMPAT_STATUS.NO);
  });

  it('returns undef when a license is missing from the matrix', () => {
    assert.equal(getCompatibility('MIT', 'LicenseRef-Foo', FIXTURE), COMPAT_STATUS.UNDEF);
    assert.equal(getCompatibility('LicenseRef-Foo', 'MIT', FIXTURE), COMPAT_STATUS.UNDEF);
  });
});

describe('evaluateOutboundAgainst', () => {
  it('requires every AND operand and any OR operand', () => {
    const andTree = parseLicenseExpression('MIT AND GPL-2.0-only');
    const orTree = parseLicenseExpression('MIT OR GPL-2.0-only');
    assert.equal(evaluateOutboundAgainst('MIT', andTree, FIXTURE), COMPAT_STATUS.NO);
    assert.ok(isCompatYes(evaluateOutboundAgainst('GPL-2.0-only', andTree, FIXTURE)));
    assert.ok(isCompatYes(evaluateOutboundAgainst('MIT', orTree, FIXTURE)));
    assert.ok(isCompatYes(evaluateOutboundAgainst('Apache-2.0', orTree, FIXTURE)));
  });

  it('matches flict-style outbound candidates for a copyleft conjunction', () => {
    const tree = parseLicenseExpression('MIT AND BSD-3-Clause AND GPL-2.0-or-later');
    assert.deepEqual(outboundCandidates(tree, FIXTURE), [
      'GPL-2.0-only',
      'GPL-2.0-or-later',
      'GPL-3.0-only'
    ]);
  });

  it('ANDs several trees the way an SBOM of several packages does', () => {
    const tree = andTrees([
      parseLicenseExpression('MIT'),
      parseLicenseExpression('Apache-2.0'),
      parseLicenseExpression('GPL-2.0-only')
    ]);
    // GPLv2 cannot include Apache-2.0, and nothing else in the fixture can
    // include both Apache-2.0 and GPL-2.0-only.
    assert.deepEqual(outboundCandidates(tree, FIXTURE), []);
  });
});

describe('analyzeSbomLicenses', () => {
  it('recommends outbound licenses already in a mixed permissive+copyleft SBOM', () => {
    const licenses = [
      { id: 'https://spdx.org/licenses/MIT', label: 'MIT', userCount: 12 },
      { id: 'https://spdx.org/licenses/GPL-2.0-only', label: 'GPL-2.0-only', userCount: 3 }
    ];
    const report = analyzeSbomLicenses(licenses, new Map(), FIXTURE);
    assert.equal(report.verdict, COMPAT_VERDICT.CONSTRAINED);
    assert.deepEqual(
      report.candidates.map((c) => c.id),
      ['GPL-2.0-only']
    );
    assert.equal(report.sbomCandidates[0].id, 'GPL-2.0-only');
    assert.ok(report.conflicts.some((c) => c.outbound === 'MIT' && c.inbound === 'GPL-2.0-only'));
    assert.deepEqual(
      report.groupedConflicts.map((g) => [g.outbound, g.inbounds]),
      [['MIT', ['GPL-2.0-only']]]
    );
    assert.equal(report.byId[licenses[0].id].kind, 'conflict');
    assert.equal(report.byId[licenses[1].id].kind, 'ok');
    assert.equal(report.showMatrix, true);
  });

  it('treats a single permissive license as combinable', () => {
    const licenses = [{ id: 'https://spdx.org/licenses/MIT', label: 'MIT', userCount: 4 }];
    const report = analyzeSbomLicenses(licenses, new Map(), FIXTURE);
    assert.equal(report.verdict, COMPAT_VERDICT.COMPATIBLE);
    assert.ok(report.candidates.some((c) => c.id === 'MIT' && c.inSbom));
    assert.ok(report.candidates.length > 1);
    assert.equal(report.showMatrix, false);
  });

  it('flags custom LicenseRef ids as unsupported without blocking known licenses', () => {
    const licenses = [
      { id: 'https://spdx.org/licenses/MIT', label: 'MIT', userCount: 2 },
      { id: 'custom', label: 'LicenseRef-Arbor-Proprietary', userCount: 1 }
    ];
    const report = analyzeSbomLicenses(licenses, new Map(), FIXTURE);
    assert.equal(report.verdict, COMPAT_VERDICT.COMPATIBLE);
    assert.equal(report.unsupported[0].id, 'LicenseRef-Arbor-Proprietary');
    assert.equal(report.byId.custom.kind, 'unsupported');
    assert.ok(report.candidates.some((c) => c.id === 'MIT'));
  });

  it('resolves SimpleLicensing expressions through the element map', () => {
    const exprId = 'spdx:expr-1';
    const elementMap = new Map([
      [exprId, { simplelicensing_licenseExpression: 'MIT OR Apache-2.0' }]
    ]);
    const report = analyzeSbomLicenses(
      [{ id: exprId, label: 'MIT OR Apache-2.0', userCount: 1 }],
      elementMap,
      FIXTURE
    );
    assert.equal(report.verdict, COMPAT_VERDICT.COMPATIBLE);
    assert.deepEqual(report.atoms, ['Apache-2.0', 'MIT']);
  });

  it('reports incomplete when every license is outside the matrix', () => {
    const report = analyzeSbomLicenses(
      [{ id: 'x', label: 'LicenseRef-Secret', userCount: 1 }],
      new Map(),
      FIXTURE
    );
    assert.equal(report.verdict, COMPAT_VERDICT.INCOMPLETE);
    assert.equal(report.candidates.length, 0);
  });

  it('groups pairwise conflicts by outbound license', () => {
    assert.deepEqual(
      groupConflictsByOutbound([
        { outbound: 'MIT', inbound: 'GPL-2.0-only' },
        { outbound: 'MIT', inbound: 'GPL-3.0-only' },
        { outbound: 'MIT', inbound: 'GPL-2.0-only' },
        { outbound: 'Apache-2.0', inbound: 'GPL-2.0-only' }
      ]).map((g) => [g.outbound, g.inbounds]),
      [
        ['MIT', ['GPL-2.0-only', 'GPL-3.0-only']],
        ['Apache-2.0', ['GPL-2.0-only']]
      ]
    );
  });

  it('shortens LicenseRef URLs and SPDX license URLs', () => {
    assert.equal(shortLicenseLabel('MIT'), 'MIT');
    assert.equal(shortLicenseLabel('https://spdx.org/licenses/Apache-2.0'), 'Apache-2.0');
    assert.equal(
      shortLicenseLabel('https://example.com/LicenseRef-Arbor-Proprietary'),
      'LicenseRef-Arbor-Proprietary'
    );
  });

  it('summarizes long inbound lists', () => {
    assert.equal(formatInboundList(['A', 'B']), 'A, B');
    assert.equal(formatInboundList(['A', 'B', 'C']), 'A, B, C');
    assert.equal(formatInboundList(['A', 'B', 'C', 'D']), 'A, B, and 2 more');
  });

  it('describes cells in outbound-includes-inbound language', () => {
    assert.match(
      describeCompatibility('GPL-2.0-only', 'MIT', COMPAT_STATUS.YES),
      /GPL-2.0-only can include MIT/
    );
    assert.match(
      describeCompatibility('MIT', 'GPL-2.0-only', COMPAT_STATUS.NO),
      /MIT cannot include GPL-2.0-only/
    );
  });

  it('formats the OSADL timestamp as a date', () => {
    assert.equal(formatMatrixTimestamp('2026-08-20T12:46:00+0000'), '2026-08-20');
    assert.equal(formatMatrixTimestamp(''), '');
  });
});

describe('bundled OSADL matrix', () => {
  const matrix = parseOsadlMatrix(
    JSON.parse(readFileSync(new URL('../src/data/osadl-matrix.json', import.meta.url), 'utf8'))
  );

  it('loads the snapshot with the licenses flict relies on', () => {
    assert.ok(matrix.ids.length >= 100);
    assert.ok(matrix.timestamp.startsWith('20'));
    assert.equal(getCompatibility('GPL-2.0-only', 'MIT', matrix), COMPAT_STATUS.YES);
    assert.equal(getCompatibility('MIT', 'GPL-2.0-only', matrix), COMPAT_STATUS.NO);
    assert.equal(getCompatibility('GPL-3.0-only', 'Apache-2.0', matrix), COMPAT_STATUS.YES);
    assert.equal(getCompatibility('GPL-2.0-only', 'Apache-2.0', matrix), COMPAT_STATUS.NO);
  });

  it('suggests GPL outbound for MIT AND BSD-3-Clause AND GPL-2.0-or-later', () => {
    const tree = parseLicenseExpression('MIT AND BSD-3-Clause AND GPL-2.0-or-later');
    const found = outboundCandidates(tree, matrix);
    assert.ok(found.includes('GPL-2.0-only'));
    assert.ok(found.includes('GPL-3.0-only'));
    assert.ok(!found.includes('MIT'));
  });
});
