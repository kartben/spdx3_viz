import {
  availableCoverageKinds,
  buildCoverageMatrices,
  coverageElementUid,
  coverageMatricesToXlsx,
  coverageVisibleCells,
  coverageVisibleWindow,
  COVERAGE_CELL,
  COVERAGE_CELL_ORDER,
  COVERAGE_KIND_BY_ID,
  COVERAGE_LAYOUT,
  filterCoverageMatrix
} from '../lib/index.js';
import { CLASS, isA } from '../spdx/model.js';

/* Functional Safety coverage matrices: virtualized 2D grids (requirements ×
   verifications / implementations / evidence / specifications) and a pure-JS
   Excel export of the same workbook. */

let coverageBundleSrcReqs = null;
let coverageBundleSrcRels = null;
let coverageBundleVal = null;
let coverageFilterKey = '';
let coverageFilterSrc = null;
let coverageFilterVal = null;

const DEFAULT_WINDOW = Object.freeze({
  startRow: 0,
  endRow: 40,
  startCol: 0,
  endCol: 40
});

export const coverageMixin = {
  _resetCoverageMemos() {
    coverageBundleSrcReqs = null;
    coverageBundleSrcRels = null;
    coverageBundleVal = null;
    coverageFilterKey = '';
    coverageFilterSrc = null;
    coverageFilterVal = null;
  },

  get coverageLayout() {
    return COVERAGE_LAYOUT;
  },

  get coverageCellMeta() {
    return COVERAGE_CELL;
  },

  get coverageCellOrder() {
    return COVERAGE_CELL_ORDER;
  },

  coverageCellStyle(status) {
    return COVERAGE_CELL[status] || COVERAGE_CELL.linked;
  },

  // The four raw matrices for this document, rebuilt only when the SBOM's
  // requirement or relationship arrays are replaced.
  get coverageBundle() {
    if (
      coverageBundleSrcReqs === this.requirements &&
      coverageBundleSrcRels === this.relationships
    ) {
      return coverageBundleVal;
    }
    coverageBundleVal = buildCoverageMatrices(
      {
        requirements: this.requirements,
        relationships: this.relationships,
        elementMap: this.elementMap,
        isA,
        CLASS
      },
      {
        displayName: (el) => this.requirementDisplayName(el) || this.cleanName(el?.spdxId),
        uidOf: (el) =>
          coverageElementUid(el, (e) => this.externalIdentifiers(e)) || this.cleanName(el?.spdxId),
        cleanName: (id) => this.cleanName(id)
      }
    );
    coverageBundleSrcReqs = this.requirements;
    coverageBundleSrcRels = this.relationships;
    coverageFilterSrc = null;
    return coverageBundleVal;
  },

  get coverageKinds() {
    return availableCoverageKinds(this.coverageBundle);
  },

  get hasCoverageMatrices() {
    return this.coverageKinds.length > 0;
  },

  // Keep the selected kind on a tab that still has columns after a new SBOM
  // loads; otherwise land on the first available matrix.
  get coverageActiveKind() {
    const kinds = this.coverageKinds;
    if (!kinds.length) return 'verification';
    if (kinds.some((k) => k.id === this.coverageKind)) return this.coverageKind;
    return kinds[0].id;
  },

  get coverageKindMeta() {
    return COVERAGE_KIND_BY_ID[this.coverageActiveKind] || COVERAGE_KINDS_FALLBACK;
  },

  get coverageMatrix() {
    const kind = this.coverageActiveKind;
    const raw = this.coverageBundle[kind];
    const key = `${kind}|${this.coverageSearch}|${this.coverageGapsOnly ? 1 : 0}|${this.coverageHideEmptyCols ? 1 : 0}`;
    if (coverageFilterSrc === raw && coverageFilterKey === key) return coverageFilterVal;
    coverageFilterVal = filterCoverageMatrix(raw, {
      search: this.coverageSearch,
      gapsOnly: this.coverageGapsOnly,
      hideEmptyCols: this.coverageHideEmptyCols
    });
    coverageFilterSrc = raw;
    coverageFilterKey = key;
    return coverageFilterVal;
  },

  get coverageSummaryLine() {
    const m = this.coverageMatrix;
    if (!m?.rows.length) return 'No requirements to plot.';
    const pct = m.rows.length ? Math.round((m.coveredRows / m.rows.length) * 100) : 0;
    return `${this.formatCount(m.coveredRows)} of ${this.formatCount(m.rows.length)} ${m.rowNoun.toLowerCase()} linked · ${this.formatCount(m.cols.length)} ${m.colNoun.toLowerCase()} · ${this.formatCount(m.filled)} cells · ${pct}%`;
  },

  get coverageVisibleRows() {
    const m = this.coverageMatrix;
    const win = this.coverageWindow;
    return m.rows.slice(win.startRow, win.endRow).map((row, i) => ({
      ...row,
      index: win.startRow + i
    }));
  },

  get coverageVisibleCols() {
    const m = this.coverageMatrix;
    const win = this.coverageWindow;
    return m.cols.slice(win.startCol, win.endCol).map((col, i) => ({
      ...col,
      index: win.startCol + i
    }));
  },

  get coverageVisibleCells() {
    return coverageVisibleCells(this.coverageMatrix, this.coverageWindow);
  },

  get coverageGridStyle() {
    const m = this.coverageMatrix;
    const L = COVERAGE_LAYOUT;
    return `width:${Math.max(m.cols.length, 1) * L.colW}px;height:${Math.max(m.rows.length, 1) * L.rowH}px;background-size:${L.colW}px ${L.rowH}px`;
  },

  get coverageExplanation() {
    const hover = this.coverageHover;
    if (!hover) return null;
    const m = this.coverageMatrix;
    const row = hover.r != null ? m.rows[hover.r] : null;
    const col = hover.c != null ? m.cols[hover.c] : null;
    if (hover.r != null && hover.c != null) {
      const cell = m.rowCells[hover.r]?.get(hover.c);
      const meta = cell ? COVERAGE_CELL[cell.status] : null;
      return {
        row,
        col,
        cell,
        status: meta?.label || 'Not covered',
        sentence: cell
          ? `${row.uid} is ${meta.label.toLowerCase()} against ${col.uid}.`
          : `${row.uid} has no ${m.colNoun.toLowerCase().replace(/s$/, '')} link to ${col.uid}.`
      };
    }
    if (row) {
      return {
        row,
        col: null,
        cell: null,
        status: row.linked ? `${row.linked} linked` : 'No links',
        sentence: row.linked
          ? `${row.uid} is linked to ${row.linked} ${m.colNoun.toLowerCase()}.`
          : `${row.uid} has no ${m.colNoun.toLowerCase()} links.`
      };
    }
    if (col) {
      let n = 0;
      for (const cell of m.cells.values()) if (cell.c === hover.c) n++;
      return {
        row: null,
        col,
        cell: null,
        status: n ? `${n} requirements` : 'Unused',
        sentence: n
          ? `${col.uid} covers ${n} ${m.rowNoun.toLowerCase()}.`
          : `${col.uid} covers no plotted requirement.`
      };
    }
    return null;
  },

  setCoverageKind(kind) {
    if (kind === this.coverageKind) return;
    this.coverageKind = kind;
    this.coverageHover = null;
    this._resetCoverageScroll();
    this._scheduleNavPush();
  },

  setCoverageHover(hover) {
    const prev = this.coverageHover;
    if (prev?.r === hover?.r && prev?.c === hover?.c) return;
    this.coverageHover = hover;
  },

  coverageCellPosition(cell) {
    const L = COVERAGE_LAYOUT;
    return `left:${cell.c * L.colW}px;top:${cell.r * L.rowH}px;width:${L.colW}px;height:${L.rowH}px`;
  },

  coverageRowPosition(index) {
    const L = COVERAGE_LAYOUT;
    return `top:${index * L.rowH}px;height:${L.rowH}px`;
  },

  coverageColPosition(index) {
    const L = COVERAGE_LAYOUT;
    return `left:${index * L.colW}px;width:${L.colW}px`;
  },

  _coverageCellFromEvent(e) {
    const grid = e.currentTarget;
    if (!grid) return null;
    const rect = grid.getBoundingClientRect();
    const L = COVERAGE_LAYOUT;
    const c = Math.floor((e.clientX - rect.left) / L.colW);
    const r = Math.floor((e.clientY - rect.top) / L.rowH);
    const m = this.coverageMatrix;
    if (r < 0 || c < 0 || r >= m.rows.length || c >= m.cols.length) return null;
    return { r, c };
  },

  onCoverageGridMove(e) {
    this.setCoverageHover(this._coverageCellFromEvent(e));
  },

  onCoverageGridClick(e) {
    const at = this._coverageCellFromEvent(e);
    if (!at) return;
    const cell = this.coverageMatrix.rowCells[at.r]?.get(at.c);
    if (cell) this.openCoverageCell(cell);
    else this.openCoverageRow(this.coverageMatrix.rows[at.r]);
  },

  onCoverageScroll() {
    const body = this.$refs?.coverageBody;
    if (!body) return;
    if (this.$refs.coverageColHead) this.$refs.coverageColHead.scrollLeft = body.scrollLeft;
    if (this.$refs.coverageRowHead) this.$refs.coverageRowHead.scrollTop = body.scrollTop;
    if (this._coverageRaf) return;
    this._coverageRaf = requestAnimationFrame(() => {
      this._coverageRaf = 0;
      this._updateCoverageWindow();
    });
  },

  onCoverageHeaderWheel(e) {
    const body = this.$refs?.coverageBody;
    if (!body) return;
    body.scrollTop += e.deltaY;
    body.scrollLeft += e.deltaX;
    this.onCoverageScroll();
  },

  _updateCoverageWindow() {
    const body = this.$refs?.coverageBody;
    if (!body) return;
    const m = this.coverageMatrix;
    const next = coverageVisibleWindow({
      scrollTop: body.scrollTop,
      scrollLeft: body.scrollLeft,
      viewH: body.clientHeight,
      viewW: body.clientWidth,
      nRows: m.rows.length,
      nCols: m.cols.length
    });
    const prev = this.coverageWindow;
    if (
      prev.startRow === next.startRow &&
      prev.endRow === next.endRow &&
      prev.startCol === next.startCol &&
      prev.endCol === next.endCol
    ) {
      return;
    }
    this.coverageWindow = next;
  },

  _resetCoverageScroll() {
    const body = this.$refs?.coverageBody;
    if (body) {
      body.scrollTop = 0;
      body.scrollLeft = 0;
    }
    if (this.$refs?.coverageColHead) this.$refs.coverageColHead.scrollLeft = 0;
    if (this.$refs?.coverageRowHead) this.$refs.coverageRowHead.scrollTop = 0;
    this.coverageWindow = { ...DEFAULT_WINDOW };
    this.$nextTick?.(() => this._updateCoverageWindow());
  },

  bindCoverageScroll() {
    this._unbindCoverageScroll();
    const body = this.$refs?.coverageBody;
    if (!body || typeof ResizeObserver === 'undefined') {
      this.$nextTick?.(() => this._updateCoverageWindow());
      return;
    }
    this._coverageResizeObserver = new ResizeObserver(() => this._updateCoverageWindow());
    this._coverageResizeObserver.observe(body);
    this._updateCoverageWindow();
  },

  _unbindCoverageScroll() {
    if (this._coverageResizeObserver) {
      this._coverageResizeObserver.disconnect();
      this._coverageResizeObserver = null;
    }
  },

  exportCoverageXlsx() {
    const bundle = this.coverageBundle;
    const kinds = this.coverageKinds;
    if (!kinds.length) return;
    const bytes = coverageMatricesToXlsx(bundle, { kinds });
    const blob = new Blob([bytes], {
      type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const sample = this.loadedSampleId || 'sbom';
    a.download = `${sample}-coverage.xlsx`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    this.toastMsg = 'Downloaded Excel workbook';
    setTimeout(() => {
      if (this.toastMsg === 'Downloaded Excel workbook') this.toastMsg = '';
    }, 2500);
  },

  openCoverageRow(row) {
    if (!row?.id) return;
    this.navigateToRequirement(row.id);
  },

  openCoverageCol(col) {
    if (!col?.id) return;
    this.navigateTo(col.id);
  },

  openCoverageCell(cell) {
    const row = this.coverageMatrix.rows[cell.r];
    if (row?.id) this.navigateToRequirement(row.id);
  }
};

const COVERAGE_KINDS_FALLBACK = COVERAGE_KIND_BY_ID.verification;
