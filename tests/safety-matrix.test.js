import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { CLASS, isA } from '../src/spdx/model.js';
import {
  assembleCoverageMatrix,
  availableCoverageKinds,
  buildCoverageMatrices,
  coverageElementUid,
  coverageEvalStatus,
  coverageMatricesToXlsx,
  coverageMatrixToCsv,
  coverageVisibleCells,
  coverageVisibleWindow,
  COVERAGE_LAYOUT,
  EXCEL_DATA_COL_CAP,
  filterCoverageMatrix,
  zipStore
} from '../src/lib/safety-matrix.js';

function unzipStore(bytes) {
  const files = {};
  let offset = 0;
  const u16 = (o) => bytes[o] | (bytes[o + 1] << 8);
  const u32 = (o) =>
    (bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24)) >>> 0;
  while (offset + 30 <= bytes.length) {
    if (u32(offset) !== 0x04034b50) break;
    const nameLen = u16(offset + 26);
    const extraLen = u16(offset + 28);
    const size = u32(offset + 18);
    const nameStart = offset + 30;
    const name = new TextDecoder().decode(bytes.subarray(nameStart, nameStart + nameLen));
    const dataStart = nameStart + nameLen + extraLen;
    files[name] = new TextDecoder().decode(bytes.subarray(dataStart, dataStart + size));
    offset = dataStart + size;
  }
  return files;
}

describe('coverageElementUid', () => {
  it('prefers requirementUID, then a non-meta external identifier', () => {
    assert.equal(coverageElementUid({ requirementUID: { identifier: 'SG-01' } }), 'SG-01');
    assert.equal(
      coverageElementUid({
        externalIdentifier: [{ identifier: 'adequacy:true' }, { identifier: 'VER-SG-01' }]
      }),
      'VER-SG-01'
    );
  });

  it('falls back to a CODE: name prefix', () => {
    assert.equal(coverageElementUid({ name: 'FSR-02: Bound deceleration' }), 'FSR-02');
  });
});

describe('coverageEvalStatus', () => {
  it('normalizes SPDX enum IRIs to pass/fail/inconclusive', () => {
    assert.equal(
      coverageEvalStatus({
        functionalsafety_evaluation: 'spdx:FunctionalSafety/EvaluationResultType/pass'
      }),
      'pass'
    );
    assert.equal(coverageEvalStatus({ functionalsafety_evaluation: 'fail' }), 'fail');
    assert.equal(coverageEvalStatus({ functionalsafety_evaluation: 'maybe' }), '');
    assert.equal(coverageEvalStatus(null), '');
  });
});

describe('assembleCoverageMatrix', () => {
  it('clusters columns by the first row they cover so links sit near the diagonal', () => {
    const matrix = assembleCoverageMatrix({
      kind: 'verification',
      rows: [
        { id: 'r2', uid: 'SG-02', name: 'Two' },
        { id: 'r1', uid: 'SG-01', name: 'One' }
      ],
      cols: [
        { id: 'v2', uid: 'VER-02', name: 'Test 2' },
        { id: 'v1', uid: 'VER-01', name: 'Test 1' }
      ],
      links: [
        { rowId: 'r1', colId: 'v1', status: 'pass' },
        { rowId: 'r2', colId: 'v2', status: 'fail' }
      ]
    });
    assert.deepEqual(
      matrix.rows.map((r) => r.uid),
      ['SG-01', 'SG-02']
    );
    assert.deepEqual(
      matrix.cols.map((c) => c.uid),
      ['VER-01', 'VER-02']
    );
    assert.equal(matrix.cells.get('0:0').status, 'pass');
    assert.equal(matrix.cells.get('1:1').status, 'fail');
    assert.equal(matrix.filled, 2);
    assert.equal(matrix.coveredRows, 2);
    assert.equal(matrix.rows[0].linked, 1);
  });

  it('keeps the more severe status when two links share a cell', () => {
    const matrix = assembleCoverageMatrix({
      kind: 'verification',
      rows: [{ id: 'r', uid: 'R', name: 'R' }],
      cols: [{ id: 'v', uid: 'V', name: 'V' }],
      links: [
        { rowId: 'r', colId: 'v', status: 'pass' },
        { rowId: 'r', colId: 'v', status: 'fail' }
      ]
    });
    assert.equal(matrix.cells.get('0:0').status, 'fail');
    assert.equal(matrix.filled, 1);
  });
});

describe('filterCoverageMatrix', () => {
  const base = assembleCoverageMatrix({
    kind: 'verification',
    rows: [
      { id: 'r1', uid: 'SG-01', name: 'Braking' },
      { id: 'r2', uid: 'SG-02', name: 'Override' },
      { id: 'r3', uid: 'SG-03', name: 'Faults' }
    ],
    cols: [
      { id: 'v1', uid: 'VER-01', name: 'T1' },
      { id: 'v2', uid: 'VER-02', name: 'T2' }
    ],
    links: [
      { rowId: 'r1', colId: 'v1', status: 'pass' },
      { rowId: 'r2', colId: 'v2', status: 'pass' }
    ]
  });

  it('filters rows by search and can keep only gaps', () => {
    const search = filterCoverageMatrix(base, { search: 'over' });
    assert.deepEqual(
      search.rows.map((r) => r.uid),
      ['SG-02']
    );
    assert.equal(search.cells.get('0:1').status, 'pass');

    const gaps = filterCoverageMatrix(base, { gapsOnly: true });
    assert.deepEqual(
      gaps.rows.map((r) => r.uid),
      ['SG-03']
    );
    assert.equal(gaps.filled, 0);
  });

  it('drops columns that no remaining row uses', () => {
    const compact = filterCoverageMatrix(base, { search: 'braking', hideEmptyCols: true });
    assert.equal(compact.cols.length, 1);
    assert.equal(compact.cols[0].uid, 'VER-01');
    assert.equal(compact.cells.get('0:0').status, 'pass');
  });
});

describe('coverageVisibleWindow', () => {
  it('overscans the scrolled viewport in both axes', () => {
    const win = coverageVisibleWindow({
      scrollTop: 280,
      scrollLeft: 260,
      viewH: 140,
      viewW: 130,
      nRows: 100,
      nCols: 80,
      layout: { ...COVERAGE_LAYOUT, overscan: 2 }
    });
    assert.equal(win.startRow, 8); // 280/28 - 2
    assert.equal(win.endRow, 17); // ceil((280+140)/28) + 2
    assert.equal(win.startCol, 8); // 260/26 - 2
    assert.equal(win.endCol, 17);
  });

  it('clamps to the matrix size', () => {
    const win = coverageVisibleWindow({
      scrollTop: 0,
      scrollLeft: 0,
      viewH: 10000,
      viewW: 10000,
      nRows: 3,
      nCols: 4
    });
    assert.equal(win.startRow, 0);
    assert.equal(win.endRow, 3);
    assert.equal(win.endCol, 4);
  });
});

describe('buildCoverageMatrices', () => {
  const req = (id, uid, name) => ({
    spdxId: id,
    type: 'Requirement',
    name: `${uid}: ${name}`,
    requirementUID: { identifier: uid }
  });
  const labels = {
    displayName: (el) => (el.name || '').replace(/^[A-Z0-9-]+:\s+/, '') || el.name,
    uidOf: (el) => coverageElementUid(el),
    evalOf: (vid) =>
      vid === 'ver:1'
        ? { spdxId: 'eval:1', functionalsafety_evaluation: 'pass' }
        : vid === 'ver:2'
          ? { spdxId: 'eval:2', functionalsafety_evaluation: 'fail' }
          : null,
    cleanName: (id) => String(id).split(':').pop()
  };

  it('builds verification, implementation, evidence, and specification matrices', () => {
    const elementMap = new Map([
      ['req:1', req('req:1', 'SG-01', 'Braking')],
      ['req:2', req('req:2', 'SG-02', 'Override')],
      [
        'ver:1',
        {
          spdxId: 'ver:1',
          type: CLASS.functionalsafety_RequirementVerification,
          name: 'VER-SG-01: HIL',
          functionalsafety_verificationMethod: ['test'],
          externalIdentifier: [{ identifier: 'VER-SG-01' }]
        }
      ],
      [
        'ver:2',
        {
          spdxId: 'ver:2',
          type: CLASS.functionalsafety_RequirementVerification,
          name: 'VER-SG-02: Override',
          externalIdentifier: [{ identifier: 'VER-SG-02' }]
        }
      ],
      ['eval:1', { spdxId: 'eval:1', type: CLASS.functionalsafety_EvaluationResult }],
      ['eval:2', { spdxId: 'eval:2', type: CLASS.functionalsafety_EvaluationResult }],
      ['pkg:a', { spdxId: 'pkg:a', type: 'software_Package', name: 'brake-arbitrator' }],
      ['file:e', { spdxId: 'file:e', type: 'software_File', name: 'hil-report.pdf' }],
      ['spec:sys', { spdxId: 'spec:sys', type: 'Specification', name: 'Item definition' }]
    ]);
    const relationships = [
      { relationshipType: 'verifiedBy', from: 'req:1', to: ['ver:1'] },
      { relationshipType: 'verifiedBy', from: 'req:2', to: ['ver:2'] },
      { relationshipType: 'implementedBy', from: 'req:1', to: ['pkg:a'] },
      { relationshipType: 'hasEvidence', from: 'eval:1', to: ['file:e'] },
      { relationshipType: 'hasRequirement', from: 'spec:sys', to: ['req:1', 'req:2'] }
    ];
    const bundle = buildCoverageMatrices(
      {
        requirements: [...elementMap.values()],
        relationships,
        elementMap,
        isA,
        CLASS
      },
      labels
    );

    assert.equal(bundle.verification.cols.length, 2);
    assert.equal(bundle.verification.cells.get('0:0').status, 'pass');
    assert.equal(bundle.verification.cells.get('1:1').status, 'fail');
    assert.equal(bundle.implementation.cols[0].name, 'brake-arbitrator');
    assert.equal(bundle.implementation.filled, 1);
    assert.equal(bundle.evidence.cols[0].name, 'hil-report.pdf');
    assert.equal(bundle.evidence.filled, 1);
    assert.equal(bundle.specification.cols.length, 1);
    assert.equal(bundle.specification.filled, 2);
    assert.deepEqual(
      availableCoverageKinds(bundle).map((k) => k.id),
      ['verification', 'implementation', 'evidence', 'specification']
    );
  });

  it('groups snippet implementations into one file column', () => {
    const file = { spdxId: 'file:a', type: 'software_File', name: 'kernel/thread.c' };
    const snip = {
      spdxId: 's:1',
      type: 'software_Snippet',
      name: 'create @ kernel/thread.c:10-20',
      software_snippetFromFile: 'file:a',
      software_lineRange: { beginIntegerRange: 10, endIntegerRange: 20 }
    };
    const elementMap = new Map([
      ['req:1', req('req:1', 'SG-01', 'Threads')],
      ['file:a', file],
      ['s:1', snip]
    ]);
    const bundle = buildCoverageMatrices(
      {
        requirements: [elementMap.get('req:1')],
        relationships: [{ relationshipType: 'implementedBy', from: 'req:1', to: ['s:1'] }],
        elementMap,
        isA,
        CLASS
      },
      labels
    );
    assert.equal(bundle.implementation.cols.length, 1);
    assert.equal(bundle.implementation.cols[0].uid, 'thread.c');
    assert.equal(bundle.implementation.filled, 1);
  });
});

describe('coverage export', () => {
  const matrix = assembleCoverageMatrix({
    kind: 'verification',
    rows: [
      { id: 'r1', uid: 'SG-01', name: 'Braking, "quoted"' },
      { id: 'r2', uid: 'SG-02', name: 'Override' }
    ],
    cols: [
      { id: 'v1', uid: 'VER-01', name: 'T1' },
      { id: 'v2', uid: 'VER-02', name: 'T2' }
    ],
    links: [{ rowId: 'r1', colId: 'v1', status: 'pass' }]
  });

  it('writes CSV that Excel can open, escaping quotes', () => {
    const csv = coverageMatrixToCsv(matrix);
    assert.match(csv, /^UID,Requirements,VER-01,VER-02\n/);
    assert.match(csv, /"Braking, ""quoted"""/);
    assert.match(csv, /SG-01,.*"Braking, ""quoted""",pass,/);
    assert.match(csv, /SG-02,Override,,/);
  });

  it('builds a real xlsx workbook in pure JS, with coloured cells and several sheets', () => {
    const xlsx = coverageMatricesToXlsx({ verification: matrix });
    assert.ok(xlsx.byteLength > 100);
    // ZIP local-file signature PK\x03\x04
    assert.equal(xlsx[0], 0x50);
    assert.equal(xlsx[1], 0x4b);
    const files = unzipStore(xlsx);
    assert.ok(files['xl/workbook.xml'].includes('name="Summary"'));
    assert.ok(files['xl/workbook.xml'].includes('name="Verification"'));
    assert.ok(files['xl/worksheets/sheet2.xml'].includes('SG-01'));
    assert.ok(files['xl/worksheets/sheet2.xml'].includes('pass'));
    assert.ok(files['xl/worksheets/sheet2.xml'].includes('state="frozen"'));
    assert.ok(files['xl/styles.xml'].includes('FF10B981'));
  });

  it('round-trips zipStore entries', () => {
    const bytes = zipStore([{ name: 'hello.txt', data: new TextEncoder().encode('hi') }]);
    const files = unzipStore(bytes);
    assert.equal(files['hello.txt'], 'hi');
  });
});

describe('coverageVisibleCells', () => {
  it('returns only filled cells inside the window', () => {
    const matrix = assembleCoverageMatrix({
      kind: 'verification',
      rows: [
        { id: 'r1', uid: 'A', name: 'A' },
        { id: 'r2', uid: 'B', name: 'B' },
        { id: 'r3', uid: 'C', name: 'C' }
      ],
      cols: [
        { id: 'c1', uid: '1', name: '1' },
        { id: 'c2', uid: '2', name: '2' },
        { id: 'c3', uid: '3', name: '3' }
      ],
      links: [
        { rowId: 'r1', colId: 'c1', status: 'pass' },
        { rowId: 'r2', colId: 'c2', status: 'fail' },
        { rowId: 'r3', colId: 'c3', status: 'linked' }
      ]
    });
    const cells = coverageVisibleCells(matrix, {
      startRow: 1,
      endRow: 3,
      startCol: 1,
      endCol: 3
    });
    assert.deepEqual(
      cells.map((c) => `${c.r}:${c.c}:${c.status}`),
      ['1:1:fail', '2:2:linked']
    );
  });
});

describe('EXCEL_DATA_COL_CAP', () => {
  it("stays under Excel's 16384-column limit after the two stub columns", () => {
    assert.ok(EXCEL_DATA_COL_CAP <= 16382);
  });
});
