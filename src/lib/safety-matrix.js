/**
 * Functional Safety coverage matrices: Requirements against verifications,
 * implementations, evidence, and specifications. Sparse 2D grids plus CSV /
 * Excel (.xlsx) export, all in pure JS (no spreadsheet library).
 *
 * @module lib/safety-matrix
 */
import { enumValue, isMeaningfulValue } from './format.js';
import { isProducerMetaIdentifier } from './safety.js';
import { groupSnippetsByFile } from './relationships.js';

/** @typedef {{ id: string, uid: string, name: string, subtitle?: string }} CoverageAxisItem */
/** @typedef {{ r: number, c: number, status: string }} CoverageCell */
/** @typedef {{
 *   kind: string,
 *   label: string,
 *   rowNoun: string,
 *   colNoun: string,
 *   rows: Array<CoverageAxisItem & { linked: number }>,
 *   cols: CoverageAxisItem[],
 *   cells: Map<string, CoverageCell>,
 *   rowCells: Array<Map<number, CoverageCell>>, // per row, ascending column
 *   filled: number,
 *   coveredRows: number
 * }} CoverageMatrix */

export const COVERAGE_KINDS = Object.freeze([
  {
    id: 'verification',
    label: 'Verification',
    rowNoun: 'Requirements',
    colNoun: 'Verifications',
    hint: 'Which tests and analyses cover each requirement, and how they evaluated.'
  },
  {
    id: 'implementation',
    label: 'Implementation',
    rowNoun: 'Requirements',
    colNoun: 'Implementations',
    hint: 'Which source files, snippets, or packages implement each requirement.'
  },
  {
    id: 'evidence',
    label: 'Evidence',
    rowNoun: 'Requirements',
    colNoun: 'Evidence',
    hint: 'Which work products back each requirement via evaluation hasEvidence links.'
  },
  {
    id: 'specification',
    label: 'Specifications',
    rowNoun: 'Requirements',
    colNoun: 'Specifications',
    hint: 'Which specifications allocate each requirement.'
  }
]);

export const COVERAGE_KIND_BY_ID = Object.fromEntries(COVERAGE_KINDS.map((k) => [k.id, k]));

/**
 * Cell (and row-status) presentation. `pass`/`fail`/`inconclusive` come from an
 * EvaluationResult; `linked` is a relationship with no evaluation yet; empty
 * cells are the coverage gap and have no key.
 */
export const COVERAGE_CELL = Object.freeze({
  fail: {
    key: 'fail',
    label: 'Failed',
    short: 'fail',
    color: '#f43f5e',
    bgClass: 'bg-rose-500',
    excelRgb: 'FFF43F5E'
  },
  inconclusive: {
    key: 'inconclusive',
    label: 'Inconclusive',
    short: 'inc',
    color: '#f59e0b',
    bgClass: 'bg-amber-500',
    excelRgb: 'FFF59E0B'
  },
  pass: {
    key: 'pass',
    label: 'Passed',
    short: 'pass',
    color: '#10b981',
    bgClass: 'bg-emerald-500',
    excelRgb: 'FF10B981'
  },
  linked: {
    key: 'linked',
    label: 'Linked',
    short: 'link',
    color: '#38bdf8',
    bgClass: 'bg-sky-500',
    excelRgb: 'FF38BDF8'
  }
});

export const COVERAGE_CELL_ORDER = Object.freeze(['fail', 'inconclusive', 'pass', 'linked']);

export const COVERAGE_LAYOUT = Object.freeze({
  rowH: 28,
  colW: 26,
  labelW: 256,
  headH: 120,
  overscan: 6
});

/** Excel worksheet column cap (ISO/IEC 29500). Extra columns are dropped on export. */
export const EXCEL_MAX_COLS = 16384;
/** Leave room for the UID + name stub columns. */
export const EXCEL_DATA_COL_CAP = EXCEL_MAX_COLS - 2;

/** Locators are real identifiers, but they make a terrible 26px column title. */
const LOCATOR_ID_RE = /^(https?:\/\/|pkg:|cpe:\/|gitoid:|swh:1:|mailto:)/i;

function isLocatorIdentifier(value) {
  return LOCATOR_ID_RE.test(String(value || '').trim());
}

function isCompactAxisCode(value) {
  const s = String(value || '').trim();
  return !!s && s.length <= 40 && !/\s/.test(s) && !isLocatorIdentifier(s) && !s.includes('/');
}

/**
 * Controlled identifier for a matrix axis: requirementUID, then a non-meta
 * non-locator externalIdentifier, then a `CODE: rest` name prefix.
 *
 * @param {Object|null|undefined} el
 * @param {(el: Object) => Array<{identifier: string}>} [getIds]
 * @returns {string}
 */
export function coverageElementUid(el, getIds) {
  if (!el) return '';
  const direct =
    el.requirementUID?.identifier ||
    el.functionalsafety_verificationUID?.identifier ||
    el.functionalsafety_assumptionUID?.identifier ||
    el.functionalsafety_evidenceUID?.identifier;
  if (isMeaningfulValue(direct) && !isLocatorIdentifier(direct)) return String(direct).trim();
  const ids = typeof getIds === 'function' ? getIds(el) : el.externalIdentifier || [];
  for (const id of ids || []) {
    const raw = String(id?.identifier || '').trim();
    if (raw && !isProducerMetaIdentifier(raw) && !isLocatorIdentifier(raw)) return raw;
  }
  const m = String(el.name || '').match(/^([A-Za-z][A-Za-z0-9._-]{1,}):/);
  return m ? m[1] : '';
}

/**
 * Short label for a rotated matrix column: a compact FS code when the element
 * has one, otherwise a file basename or the human name. HTTPS SPDX ids and
 * package URLs are never used as the visible title.
 *
 * @param {Object|null|undefined} el
 * @param {{ uidOf?: (el: Object) => string, cleanName?: (id: string) => string,
 *           fallbackId?: string }} [opts]
 * @returns {string}
 */
export function coverageAxisShortLabel(el, opts = {}) {
  const fallbackId = opts.fallbackId || el?.spdxId || '';
  const uid = typeof opts.uidOf === 'function' ? opts.uidOf(el) : coverageElementUid(el);
  if (isCompactAxisCode(uid)) return uid;

  const name = (el?.name || '').trim();
  if (name) {
    const prefixed = name.match(/^([A-Za-z][A-Za-z0-9._-]{1,24}):\s+\S/);
    if (prefixed && isCompactAxisCode(prefixed[1])) return prefixed[1];
    if (name.includes('/') || isLocatorIdentifier(name)) {
      const base = name
        .split(/[\\/#]/)
        .filter(Boolean)
        .pop();
      if (base) return base;
    }
    return name;
  }

  const fromId = String(fallbackId);
  const afterHash = fromId.includes('#') ? fromId.slice(fromId.lastIndexOf('#') + 1) : fromId;
  const tail = afterHash.split('/').filter(Boolean).pop() || '';
  if (isCompactAxisCode(tail)) return tail;
  const cleaned = typeof opts.cleanName === 'function' ? opts.cleanName(fallbackId) : '';
  if (cleaned && !isLocatorIdentifier(cleaned)) return cleaned;
  return tail;
}

/**
 * Evaluation token (`pass` / `fail` / `inconclusive`) or '' when unevaluated.
 *
 * @param {Object|null|undefined} evaluation
 * @returns {string}
 */
export function coverageEvalStatus(evaluation) {
  const raw = enumValue(evaluation?.functionalsafety_evaluation).toLowerCase();
  if (raw === 'pass' || raw === 'fail' || raw === 'inconclusive') return raw;
  return '';
}

function relTargets(rel) {
  if (!rel) return [];
  return Array.isArray(rel.to) ? rel.to.filter(Boolean) : rel.to ? [rel.to] : [];
}

function nameOf(el, fallback) {
  const n = (el?.name || '').trim();
  return n || fallback || '';
}

function compareUid(a, b) {
  return String(a || '').localeCompare(String(b || ''), undefined, { numeric: true });
}

function cellKey(r, c) {
  return `${r}:${c}`;
}

/**
 * Rebuild every row's cell map in ascending column order. Links arrive in
 * relationship order, so a row can otherwise hold column 5 before column 2, and
 * Excel refuses to open a worksheet whose row cells are not left to right.
 *
 * @param {Array<Map<number, CoverageCell>>} rowCells
 * @returns {Array<Map<number, CoverageCell>>}
 */
function orderRowCells(rowCells) {
  return rowCells.map((row) =>
    row.size < 2 ? row : new Map([...row.entries()].sort((a, b) => a[0] - b[0]))
  );
}

/**
 * Assemble a sparse matrix from row/col items and (rowId, colId, status) links.
 * Columns cluster by the first row they cover so related links sit near the
 * diagonal of a typical requirements-traceability matrix.
 *
 * @param {{ kind: string, label: string, rowNoun: string, colNoun: string,
 *           rows: CoverageAxisItem[], cols: CoverageAxisItem[],
 *           links: Array<{ rowId: string, colId: string, status: string }> }} spec
 * @returns {CoverageMatrix}
 */
export function assembleCoverageMatrix(spec) {
  const kindMeta = COVERAGE_KIND_BY_ID[spec.kind] || spec;
  const rowItems = [...(spec.rows || [])].sort(
    (a, b) => compareUid(a.uid, b.uid) || a.name.localeCompare(b.name)
  );
  const rowIndex = new Map(rowItems.map((row, i) => [row.id, i]));

  const firstRow = new Map();
  const links = spec.links || [];
  for (const link of links) {
    const r = rowIndex.get(link.rowId);
    if (r == null) continue;
    const prev = firstRow.get(link.colId);
    if (prev == null || r < prev) firstRow.set(link.colId, r);
  }

  const colItems = [...(spec.cols || [])].sort((a, b) => {
    const fa = firstRow.has(a.id) ? firstRow.get(a.id) : Infinity;
    const fb = firstRow.has(b.id) ? firstRow.get(b.id) : Infinity;
    return fa - fb || compareUid(a.uid, b.uid) || a.name.localeCompare(b.name);
  });
  const colIndex = new Map(colItems.map((col, i) => [col.id, i]));

  /** @type {Map<string, CoverageCell>} */
  const cells = new Map();
  const rowCells = rowItems.map(() => new Map());
  const linked = new Array(rowItems.length).fill(0);

  for (const link of links) {
    const r = rowIndex.get(link.rowId);
    const c = colIndex.get(link.colId);
    if (r == null || c == null) continue;
    const status = COVERAGE_CELL[link.status] ? link.status : 'linked';
    const key = cellKey(r, c);
    const existing = cells.get(key);
    if (existing && rankStatus(existing.status) >= rankStatus(status)) continue;
    const cell = { r, c, status };
    if (!existing) linked[r]++;
    cells.set(key, cell);
    rowCells[r].set(c, cell);
  }

  const rows = rowItems.map((row, i) => ({ ...row, linked: linked[i] }));
  const coveredRows = linked.reduce((n, v) => n + (v > 0 ? 1 : 0), 0);

  return {
    kind: kindMeta.id || spec.kind,
    label: kindMeta.label || spec.label || spec.kind,
    rowNoun: kindMeta.rowNoun || spec.rowNoun || 'Rows',
    colNoun: kindMeta.colNoun || spec.colNoun || 'Columns',
    rows,
    cols: colItems,
    cells,
    rowCells: orderRowCells(rowCells),
    filled: cells.size,
    coveredRows
  };
}

function rankStatus(status) {
  if (status === 'fail') return 4;
  if (status === 'inconclusive') return 3;
  if (status === 'pass') return 2;
  return 1;
}

/**
 * Filter rows (search / gaps) and optionally drop columns that have no remaining
 * filled cell. Indices are rebuilt so callers can treat the result as a matrix.
 *
 * @param {CoverageMatrix} matrix
 * @param {{ search?: string, gapsOnly?: boolean, hideEmptyCols?: boolean }} [opts]
 * @returns {CoverageMatrix}
 */
export function filterCoverageMatrix(matrix, opts = {}) {
  if (!matrix) {
    return assembleCoverageMatrix({
      kind: 'verification',
      rows: [],
      cols: [],
      links: []
    });
  }
  const q = String(opts.search || '')
    .trim()
    .toLowerCase();
  let rows = matrix.rows;
  if (q) {
    rows = rows.filter((row) => {
      const hay = `${row.uid} ${row.name} ${row.subtitle || ''}`.toLowerCase();
      return hay.includes(q);
    });
  }
  if (opts.gapsOnly) rows = rows.filter((row) => row.linked === 0);

  if (rows.length === matrix.rows.length && !opts.hideEmptyCols) return matrix;
  if (rows.length === 0) {
    return {
      ...matrix,
      rows: [],
      cols: opts.hideEmptyCols ? [] : matrix.cols,
      cells: new Map(),
      rowCells: [],
      filled: 0,
      coveredRows: 0
    };
  }

  const rowIndex = new Map(rows.map((row, i) => [row.id, i]));
  /** @type {Map<string, CoverageCell>} */
  const cells = new Map();
  const usedCols = new Set();
  for (const cell of matrix.cells.values()) {
    const row = matrix.rows[cell.r];
    const nr = rowIndex.get(row.id);
    if (nr == null) continue;
    usedCols.add(cell.c);
    const next = { r: nr, c: cell.c, status: cell.status };
    cells.set(cellKey(nr, cell.c), next);
  }

  let cols = matrix.cols;
  if (opts.hideEmptyCols) {
    const colMap = new Map();
    cols = matrix.cols.filter((_, c) => {
      if (!usedCols.has(c)) return false;
      colMap.set(c, colMap.size);
      return true;
    });
    const remapped = new Map();
    for (const cell of cells.values()) {
      const nc = colMap.get(cell.c);
      const next = { r: cell.r, c: nc, status: cell.status };
      remapped.set(cellKey(cell.r, nc), next);
    }
    return finishFiltered(matrix, rows, cols, remapped);
  }

  return finishFiltered(matrix, rows, cols, cells);
}

function finishFiltered(matrix, rows, cols, cells) {
  const rowCells = rows.map(() => new Map());
  let coveredRows = 0;
  for (const cell of cells.values()) {
    rowCells[cell.r].set(cell.c, cell);
  }
  const nextRows = rows.map((row, i) => {
    const linked = rowCells[i].size;
    if (linked) coveredRows++;
    return linked === row.linked ? row : { ...row, linked };
  });
  return {
    ...matrix,
    rows: nextRows,
    cols,
    cells,
    rowCells: orderRowCells(rowCells),
    filled: cells.size,
    coveredRows
  };
}

/**
 * Visible row/col window for a virtualized grid.
 *
 * @param {{ scrollTop: number, scrollLeft: number, viewH: number, viewW: number,
 *           nRows: number, nCols: number, layout?: typeof COVERAGE_LAYOUT }} args
 * @returns {{ startRow: number, endRow: number, startCol: number, endCol: number }}
 */
export function coverageVisibleWindow(args) {
  const layout = args.layout || COVERAGE_LAYOUT;
  const nRows = Math.max(0, args.nRows | 0);
  const nCols = Math.max(0, args.nCols | 0);
  const startRow = Math.max(0, Math.floor((args.scrollTop || 0) / layout.rowH) - layout.overscan);
  const endRow = Math.min(
    nRows,
    Math.ceil(((args.scrollTop || 0) + (args.viewH || 0)) / layout.rowH) + layout.overscan
  );
  const startCol = Math.max(0, Math.floor((args.scrollLeft || 0) / layout.colW) - layout.overscan);
  const endCol = Math.min(
    nCols,
    Math.ceil(((args.scrollLeft || 0) + (args.viewW || 0)) / layout.colW) + layout.overscan
  );
  return {
    startRow,
    endRow: Math.max(startRow, endRow),
    startCol,
    endCol: Math.max(startCol, endCol)
  };
}

/**
 * Filled cells that intersect a visible window.
 *
 * @param {CoverageMatrix} matrix
 * @param {{ startRow: number, endRow: number, startCol: number, endCol: number }} win
 * @returns {CoverageCell[]}
 */
export function coverageVisibleCells(matrix, win) {
  if (!matrix?.rowCells) return [];
  const out = [];
  const startRow = win.startRow | 0;
  const endRow = win.endRow | 0;
  const startCol = win.startCol | 0;
  const endCol = win.endCol | 0;
  for (let r = startRow; r < endRow && r < matrix.rowCells.length; r++) {
    const row = matrix.rowCells[r];
    for (const [c, cell] of row) {
      if (c >= startCol && c < endCol) out.push(cell);
    }
  }
  return out;
}

function emptyBundle() {
  return {
    verification: assembleCoverageMatrix({
      kind: 'verification',
      rows: [],
      cols: [],
      links: []
    }),
    implementation: assembleCoverageMatrix({
      kind: 'implementation',
      rows: [],
      cols: [],
      links: []
    }),
    evidence: assembleCoverageMatrix({ kind: 'evidence', rows: [], cols: [], links: [] }),
    specification: assembleCoverageMatrix({
      kind: 'specification',
      rows: [],
      cols: [],
      links: []
    })
  };
}

/**
 * Build the four coverage matrices from SPDX Functional Safety relationships.
 *
 * @param {{
 *   requirements: Array<Object>,
 *   relationships: Array<Object>,
 *   elementMap: Map<string, Object>,
 *   isA: (type: string|undefined, base: string) => boolean,
 *   CLASS: { Requirement: string, Specification: string, functionalsafety_EvaluationResult: string }
 * }} model
 * @param {{
 *   displayName: (el: Object) => string,
 *   uidOf: (el: Object) => string,
 *   evalOf: (verificationId: string) => Object|null,
 *   cleanName: (id: string) => string
 * }} labels
 * @returns {{ verification: CoverageMatrix, implementation: CoverageMatrix,
 *             evidence: CoverageMatrix, specification: CoverageMatrix }}
 */
export function buildCoverageMatrices(model, labels) {
  const requirements = model?.requirements || [];
  const relationships = model?.relationships || [];
  const elementMap = model?.elementMap || new Map();
  const isA = model?.isA;
  const CLASS = model?.CLASS;
  if (!isA || !CLASS) return emptyBundle();

  const displayName = labels?.displayName || ((el) => nameOf(el, el?.spdxId));
  const uidOf = labels?.uidOf || ((el) => coverageElementUid(el));
  const evalOf = labels?.evalOf || (() => null);
  const cleanName =
    labels?.cleanName ||
    ((id) =>
      String(id || '')
        .split(/[#/]/)
        .pop());
  const colLabel = (el, colId) =>
    coverageAxisShortLabel(el, { uidOf, cleanName, fallbackId: colId });

  const reqs = [];
  const reqIds = new Set();
  for (const r of requirements) {
    if (!r?.spdxId || !isA(r.type, CLASS.Requirement)) continue;
    reqIds.add(r.spdxId);
    reqs.push({
      id: r.spdxId,
      uid: uidOf(r) || cleanName(r.spdxId),
      name: displayName(r) || nameOf(r, cleanName(r.spdxId))
    });
  }

  /** @type {Map<string, { id: string, uid: string, name: string, subtitle?: string }>} */
  const verCols = new Map();
  /** @type {Array<{ rowId: string, colId: string, status: string }>} */
  const verLinks = [];
  /** @type {Map<string, { id: string, uid: string, name: string, targetIds: string[] }>} */
  const implCols = new Map();
  const implLinks = [];
  /** @type {Map<string, { id: string, uid: string, name: string, targetIds: string[] }>} */
  const evidCols = new Map();
  const evidLinks = [];
  /** @type {Map<string, { id: string, uid: string, name: string }>} */
  const specCols = new Map();
  const specLinks = [];

  const evalByVerification = new Map();
  const evidenceByEvaluation = new Map();
  for (const r of requirements) {
    if (r?.type === 'functionalsafety_EvaluationResult' && r.functionalsafety_evaluationBasedOn) {
      evalByVerification.set(r.functionalsafety_evaluationBasedOn, r);
    }
  }
  const resolveEval = (vid) => evalOf(vid) || evalByVerification.get(vid) || null;

  for (const rel of relationships) {
    if (!rel?.relationshipType) continue;
    const tos = relTargets(rel);
    if (rel.relationshipType === 'verifiedBy' && reqIds.has(rel.from)) {
      for (const vid of tos) {
        const el = elementMap.get(vid);
        if (!verCols.has(vid)) {
          const method = Array.isArray(el?.functionalsafety_verificationMethod)
            ? enumValue(el.functionalsafety_verificationMethod[0])
            : enumValue(el?.functionalsafety_verificationMethod);
          verCols.set(vid, {
            id: vid,
            uid: colLabel(el || { spdxId: vid }, vid),
            name: displayName(el || { spdxId: vid, name: cleanName(vid) }) || cleanName(vid),
            subtitle: method || ''
          });
        }
        const evaluation = resolveEval(vid);
        verLinks.push({
          rowId: rel.from,
          colId: vid,
          status: coverageEvalStatus(evaluation) || 'linked'
        });
      }
    } else if (rel.relationshipType === 'implementedBy' && reqIds.has(rel.from)) {
      const targets = tos.map((id) => elementMap.get(id) || { spdxId: id });
      const grouped = groupSnippetsByFile(targets, elementMap);
      for (const file of grouped.files) {
        const colId = file.fileId || file.snippets[0]?.id || file.baseName;
        if (!implCols.has(colId)) {
          implCols.set(colId, {
            id: colId,
            uid: file.baseName || cleanName(colId),
            name: file.fileName || file.baseName || cleanName(colId)
          });
        }
        implLinks.push({ rowId: rel.from, colId, status: 'linked' });
      }
      for (const other of grouped.others) {
        const colId = other.spdxId;
        if (!colId) continue;
        if (!implCols.has(colId)) {
          implCols.set(colId, {
            id: colId,
            uid: colLabel(other, colId),
            name: displayName(other) || nameOf(other, cleanName(colId))
          });
        }
        implLinks.push({ rowId: rel.from, colId, status: 'linked' });
      }
    } else if (rel.relationshipType === 'hasEvidence') {
      const list = evidenceByEvaluation.get(rel.from) || [];
      list.push(...tos);
      evidenceByEvaluation.set(rel.from, list);
    } else if (rel.relationshipType === 'hasRequirement') {
      const fromEl = elementMap.get(rel.from);
      if (!fromEl || !isA(fromEl.type, CLASS.Specification)) continue;
      if (!specCols.has(rel.from)) {
        specCols.set(rel.from, {
          id: rel.from,
          uid: colLabel(fromEl, rel.from),
          name: displayName(fromEl) || nameOf(fromEl, cleanName(rel.from))
        });
      }
      for (const rid of tos) {
        if (!reqIds.has(rid)) continue;
        specLinks.push({ rowId: rid, colId: rel.from, status: 'linked' });
      }
    }
  }

  // Evidence is EvaluationResult --hasEvidence--> artifact, reached from a
  // requirement through verifiedBy. Direct hasEvidence on the requirement is
  // also honoured (some producers skip the evaluation hop).
  const evidSeen = new Set();
  const pushEvidence = (rowId, targetId) => {
    if (!targetId || !reqIds.has(rowId)) return;
    const key = `${rowId}\t${targetId}`;
    if (evidSeen.has(key)) return;
    evidSeen.add(key);
    const el = elementMap.get(targetId) || { spdxId: targetId };
    const grouped = groupSnippetsByFile([el], elementMap, { dedupeRanges: true });
    const addCol = (colId, uid, name) => {
      if (!evidCols.has(colId)) evidCols.set(colId, { id: colId, uid, name });
      evidLinks.push({ rowId, colId, status: 'linked' });
    };
    for (const file of grouped.files) {
      const colId = file.fileId || file.snippets[0]?.id || file.baseName;
      addCol(colId, file.baseName || cleanName(colId), file.fileName || file.baseName || colId);
    }
    for (const other of grouped.others) {
      if (!other.spdxId) continue;
      addCol(
        other.spdxId,
        colLabel(other, other.spdxId),
        displayName(other) || nameOf(other, cleanName(other.spdxId))
      );
    }
  };

  for (const rel of relationships) {
    if (rel?.relationshipType !== 'verifiedBy' || !reqIds.has(rel.from)) continue;
    for (const vid of relTargets(rel)) {
      const evaluation = resolveEval(vid);
      const evidIds = evaluation?.spdxId ? evidenceByEvaluation.get(evaluation.spdxId) || [] : [];
      for (const eid of evidIds) pushEvidence(rel.from, eid);
    }
  }
  for (const rel of relationships) {
    if (rel?.relationshipType !== 'hasEvidence' || !reqIds.has(rel.from)) continue;
    for (const eid of relTargets(rel)) pushEvidence(rel.from, eid);
  }

  return {
    verification: assembleCoverageMatrix({
      kind: 'verification',
      rows: reqs,
      cols: [...verCols.values()],
      links: verLinks
    }),
    implementation: assembleCoverageMatrix({
      kind: 'implementation',
      rows: reqs,
      cols: [...implCols.values()],
      links: implLinks
    }),
    evidence: assembleCoverageMatrix({
      kind: 'evidence',
      rows: reqs,
      cols: [...evidCols.values()],
      links: evidLinks
    }),
    specification: assembleCoverageMatrix({
      kind: 'specification',
      rows: reqs,
      cols: [...specCols.values()],
      links: specLinks
    })
  };
}

/**
 * Kinds that actually have something to plot (at least one column).
 *
 * @param {{ [id: string]: CoverageMatrix }} bundle
 * @returns {typeof COVERAGE_KINDS}
 */
export function availableCoverageKinds(bundle) {
  return COVERAGE_KINDS.filter((k) => (bundle?.[k.id]?.cols.length || 0) > 0);
}

function csvEscape(value) {
  const s = String(value ?? '');
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

/**
 * CSV of one matrix (UID, name, then one column per axis item). Excel opens this
 * directly; the .xlsx export keeps colours and frozen panes on top.
 *
 * @param {CoverageMatrix} matrix
 * @returns {string}
 */
export function coverageMatrixToCsv(matrix) {
  if (!matrix) return '';
  const header = ['UID', matrix.rowNoun || 'Row', ...matrix.cols.map((c) => c.uid || c.name)];
  const lines = [header.map(csvEscape).join(',')];
  for (let r = 0; r < matrix.rows.length; r++) {
    const row = matrix.rows[r];
    const cells = [row.uid, row.name];
    const filled = matrix.rowCells[r] || new Map();
    for (let c = 0; c < matrix.cols.length; c++) {
      const cell = filled.get(c);
      cells.push(cell ? COVERAGE_CELL[cell.status]?.short || cell.status : '');
    }
    lines.push(cells.map(csvEscape).join(','));
  }
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Minimal xlsx writer (Office Open XML, stored ZIP, no compression library)
// ---------------------------------------------------------------------------

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[i] = c >>> 0;
  }
  return t;
})();

function crc32(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function u16(n) {
  const b = new Uint8Array(2);
  b[0] = n & 0xff;
  b[1] = (n >>> 8) & 0xff;
  return b;
}

function u32(n) {
  const b = new Uint8Array(4);
  b[0] = n & 0xff;
  b[1] = (n >>> 8) & 0xff;
  b[2] = (n >>> 16) & 0xff;
  b[3] = (n >>> 24) & 0xff;
  return b;
}

function concatBytes(parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

const encoder = new TextEncoder();

/** 1980-01-01 in DOS date form: day 1, month 1, year 0. A literal 0 encodes
 *  day 0 of month 0, which strict readers reject. */
const DOS_DATE = (1 << 5) | 1;

/**
 * ZIP archive using STORE (no compression). Enough for an xlsx package.
 *
 * @param {Array<{ name: string, data: Uint8Array }>} files
 * @returns {Uint8Array}
 */
export function zipStore(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const file of files) {
    const nameBytes = encoder.encode(file.name);
    const data = file.data;
    const crc = crc32(data);
    const local = concatBytes([
      u32(0x04034b50),
      u16(20),
      u16(0),
      u16(0),
      u16(0),
      u16(DOS_DATE),
      u32(crc),
      u32(data.length),
      u32(data.length),
      u16(nameBytes.length),
      u16(0),
      nameBytes,
      data
    ]);
    locals.push(local);
    const central = concatBytes([
      u32(0x02014b50),
      u16(20),
      u16(20),
      u16(0),
      u16(0),
      u16(0),
      u16(DOS_DATE),
      u32(crc),
      u32(data.length),
      u32(data.length),
      u16(nameBytes.length),
      u16(0),
      u16(0),
      u16(0),
      u16(0),
      u32(0),
      u32(offset),
      nameBytes
    ]);
    centrals.push(central);
    offset += local.length;
  }
  const centralDir = concatBytes(centrals);
  const end = concatBytes([
    u32(0x06054b50),
    u16(0),
    u16(0),
    u16(files.length),
    u16(files.length),
    u32(centralDir.length),
    u32(offset),
    u16(0)
  ]);
  return concatBytes([...locals, centralDir, end]);
}

function xmlText(value) {
  const s = String(value ?? '');
  let out = '';
  for (let i = 0; i < s.length && out.length < 32767; i++) {
    const code = s.charCodeAt(i);
    if (code < 32 && code !== 9 && code !== 10 && code !== 13) continue;
    const ch = s[i];
    if (ch === '&') out += '&amp;';
    else if (ch === '<') out += '&lt;';
    else if (ch === '>') out += '&gt;';
    else out += ch;
  }
  return out;
}

function colRef(n) {
  let s = '';
  let x = n + 1;
  while (x > 0) {
    const r = (x - 1) % 26;
    s = String.fromCharCode(65 + r) + s;
    x = Math.floor((x - 1) / 26);
  }
  return s;
}

const STATUS_STYLE = { fail: 2, inconclusive: 3, pass: 4, linked: 5 };

function inlineCell(ref, text, style) {
  const s = style ? ` s="${style}"` : '';
  return `<c r="${ref}" t="inlineStr"${s}><is><t xml:space="preserve">${xmlText(text)}</t></is></c>`;
}

function worksheetXml(matrix, { truncatedCols = 0 } = {}) {
  const cols = matrix.cols.slice(0, EXCEL_DATA_COL_CAP);
  const truncNote = truncatedCols
    ? ` (${truncatedCols} extra columns omitted: Excel allows ${EXCEL_MAX_COLS})`
    : '';
  const parts = [
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
    '<sheetViews><sheetView workbookViewId="0">',
    '<pane xSplit="2" ySplit="1" topLeftCell="C2" activePane="bottomRight" state="frozen"/>',
    '</sheetView></sheetViews>',
    '<cols>',
    '<col min="1" max="1" width="16" customWidth="1"/>',
    '<col min="2" max="2" width="44" customWidth="1"/>',
    cols.length ? `<col min="3" max="${2 + cols.length}" width="6" customWidth="1"/>` : '',
    '</cols>',
    '<sheetData>'
  ];

  const header = [inlineCell('A1', 'UID', 1), inlineCell('B1', matrix.rowNoun + truncNote, 1)];
  for (let c = 0; c < cols.length; c++) {
    header.push(inlineCell(`${colRef(c + 2)}1`, cols[c].uid || cols[c].name, 1));
  }
  parts.push(`<row r="1">${header.join('')}</row>`);

  for (let r = 0; r < matrix.rows.length; r++) {
    const row = matrix.rows[r];
    const excelRow = r + 2;
    const cells = [inlineCell(`A${excelRow}`, row.uid, 0), inlineCell(`B${excelRow}`, row.name, 0)];
    const filled = matrix.rowCells[r] || new Map();
    for (const [c, cell] of filled) {
      if (c >= cols.length) continue;
      const meta = COVERAGE_CELL[cell.status];
      cells.push(
        inlineCell(
          `${colRef(c + 2)}${excelRow}`,
          meta?.short || cell.status,
          STATUS_STYLE[cell.status] || 5
        )
      );
    }
    parts.push(`<row r="${excelRow}">${cells.join('')}</row>`);
  }
  parts.push('</sheetData></worksheet>');
  return parts.join('');
}

function summarySheetXml(bundle, kinds) {
  const rows = [['Kind', 'Rows', 'Columns', 'Filled cells', 'Rows with a link', 'Coverage']];
  for (const k of kinds) {
    const m = bundle[k.id];
    if (!m) continue;
    const pct = m.rows.length ? Math.round((m.coveredRows / m.rows.length) * 100) : 0;
    rows.push([
      k.label,
      String(m.rows.length),
      String(m.cols.length),
      String(m.filled),
      String(m.coveredRows),
      `${pct}%`
    ]);
  }
  rows.push([]);
  rows.push(['Cell', 'Meaning']);
  for (const key of COVERAGE_CELL_ORDER) {
    const meta = COVERAGE_CELL[key];
    rows.push([meta.short, meta.label]);
  }
  const parts = [
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
    '<cols><col min="1" max="1" width="22" customWidth="1"/><col min="2" max="6" width="18" customWidth="1"/></cols>',
    '<sheetData>'
  ];
  rows.forEach((row, i) => {
    const cells = row.map((text, c) => inlineCell(`${colRef(c)}${i + 1}`, text, i === 0 ? 1 : 0));
    parts.push(`<row r="${i + 1}">${cells.join('')}</row>`);
  });
  parts.push('</sheetData></worksheet>');
  return parts.join('');
}

const STYLES_XML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="2">
    <font><sz val="11"/><name val="Calibri"/></font>
    <font><b/><sz val="11"/><name val="Calibri"/></font>
  </fonts>
  <fills count="6">
    <fill><patternFill patternType="none"/></fill>
    <fill><patternFill patternType="gray125"/></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFF43F5E"/><bgColor indexed="64"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFF59E0B"/><bgColor indexed="64"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FF10B981"/><bgColor indexed="64"/></patternFill></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FF38BDF8"/><bgColor indexed="64"/></patternFill></fill>
  </fills>
  <borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="6">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
    <xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0"/>
    <xf numFmtId="0" fontId="0" fillId="2" borderId="0" xfId="0" applyFill="1"/>
    <xf numFmtId="0" fontId="0" fillId="3" borderId="0" xfId="0" applyFill="1"/>
    <xf numFmtId="0" fontId="0" fillId="4" borderId="0" xfId="0" applyFill="1"/>
    <xf numFmtId="0" fontId="0" fillId="5" borderId="0" xfId="0" applyFill="1"/>
  </cellXfs>
</styleSheet>`;

/**
 * Build a real .xlsx workbook of the coverage matrices (one sheet per kind,
 * plus a Summary sheet). Pure JS: stored ZIP of SpreadsheetML.
 *
 * @param {{ [id: string]: CoverageMatrix }} bundle
 * @param {{ kinds?: typeof COVERAGE_KINDS }} [opts]
 * @returns {Uint8Array}
 */
export function coverageMatricesToXlsx(bundle, opts = {}) {
  const kinds = (opts.kinds || availableCoverageKinds(bundle)).filter((k) => bundle?.[k.id]);
  const sheets = [{ name: 'Summary', xml: summarySheetXml(bundle, kinds) }];
  for (const k of kinds) {
    const matrix = bundle[k.id];
    const truncatedCols = Math.max(0, matrix.cols.length - EXCEL_DATA_COL_CAP);
    sheets.push({
      name: k.label.slice(0, 31),
      xml: worksheetXml(matrix, { truncatedCols })
    });
  }

  const files = [
    {
      name: '[Content_Types].xml',
      data: encoder.encode(
        `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
  ${sheets
    .map(
      (_, i) =>
        `<Override PartName="/xl/worksheets/sheet${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`
    )
    .join('\n  ')}
</Types>`
      )
    },
    {
      name: '_rels/.rels',
      data: encoder.encode(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`)
    },
    {
      name: 'xl/_rels/workbook.xml.rels',
      data: encoder.encode(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  ${sheets
    .map(
      (_, i) =>
        `<Relationship Id="rId${i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i + 1}.xml"/>`
    )
    .join('\n  ')}
  <Relationship Id="rId${sheets.length + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>`)
    },
    {
      name: 'xl/workbook.xml',
      data: encoder.encode(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    ${sheets
      .map((s, i) => `<sheet name="${xmlText(s.name)}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`)
      .join('\n    ')}
  </sheets>
</workbook>`)
    },
    { name: 'xl/styles.xml', data: encoder.encode(STYLES_XML) },
    ...sheets.map((s, i) => ({
      name: `xl/worksheets/sheet${i + 1}.xml`,
      data: encoder.encode(s.xml)
    }))
  ];
  return zipStore(files);
}
