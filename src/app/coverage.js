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

  // Tooltip for a row or column label. The name usually already carries the
  // short label, either as a code prefix ("VER-FSR-01: Confirm...") or as a
  // path tail ("kernel/thread.c" for "thread.c"), so only prepend the UID when
  // it would actually add something.
  coverageAxisTitle(item) {
    const uid = (item?.uid || '').trim();
    const name = (item?.name || '').trim();
    if (!uid || uid === name) return name || uid;
    if (!name) return uid;
    return name.startsWith(uid) || name.endsWith(uid) ? name : `${uid}: ${name}`;
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
        uidOf: (el) => coverageElementUid(el, (e) => this.externalIdentifiers(e)),
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
      // Every gap row is empty by definition, so keeping the columns would draw
      // a grid that cannot hold a single cell.
      hideEmptyCols: this.coverageHideEmptyCols || this.coverageGapsOnly
    });
    coverageFilterSrc = raw;
    coverageFilterKey = key;
    return coverageFilterVal;
  },

  // How many requirements the current matrix leaves unlinked, before any
  // filtering: the number "Gaps only" is about to show.
  get coverageGapCount() {
    const m = this.coverageBundle[this.coverageActiveKind];
    return m ? m.rows.length - m.coveredRows : 0;
  },

  // The count line under the toolbar. Gaps only reports against the whole
  // matrix, because "0 of 238 linked, 0%" says nothing once the rows with a
  // link have been filtered out.
  get coverageSummaryLine() {
    const m = this.coverageMatrix;
    const all = this.coverageBundle[this.coverageActiveKind];
    const noun = (all || m)?.rowNoun.toLowerCase() || 'requirements';
    const colNoun = (all || m)?.colNoun.toLowerCase() || 'columns';
    if (this.coverageGapsOnly && all) {
      const gaps = this.coverageGapCount;
      const shown = m?.rows.length ?? 0;
      const scope = shown === gaps ? '' : ` · ${this.formatCount(shown)} match the filter`;
      return `${this.formatCount(gaps)} of ${this.formatCount(all.rows.length)} ${noun} have no ${singular(colNoun)} link${scope}`;
    }
    if (!m?.rows.length) return `No ${noun} to plot.`;
    const pct = Math.round((m.coveredRows / m.rows.length) * 100);
    return `${this.formatCount(m.coveredRows)} of ${this.formatCount(m.rows.length)} ${noun} linked · ${this.formatCount(m.cols.length)} ${colNoun} · ${this.formatCount(m.filled)} cells · ${pct}%`;
  },

  // What the body area says when there is no grid to draw.
  get coverageEmptyNote() {
    const m = this.coverageMatrix;
    const all = this.coverageBundle[this.coverageActiveKind];
    const colNoun = singular((all || m)?.colNoun.toLowerCase() || 'column');
    if (this.coverageGapsOnly) {
      if (!m?.rows.length) {
        return this.coverageSearch
          ? `No requirement matching the filter is missing a ${colNoun} link.`
          : `No gaps: every requirement has at least one ${colNoun} link.`;
      }
      return `Nothing to plot: these requirements have no ${colNoun} link at all. Click one to open it.`;
    }
    if (!m?.rows.length) return 'No requirements match the current filter.';
    return `None of the requirements shown has a ${colNoun} link.`;
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

  // Label for one plotted cell. A cell carries the coordinates it was built
  // with, and the matrix underneath can be replaced (a new SBOM, a filter)
  // before the grid is re-rendered, so never assume the pair still resolves.
  coverageCellTitle(cell) {
    const m = this.coverageMatrix;
    const row = m.rows[cell.r];
    const col = m.cols[cell.c];
    if (!row || !col) return '';
    return `${row.uid} × ${col.uid}: ${this.coverageCellStyle(cell.status).label}`;
  },

  get coverageExplanation() {
    const hover = this.coverageHover;
    if (!hover) return null;
    const m = this.coverageMatrix;
    const row = hover.r != null ? m.rows[hover.r] : null;
    const col = hover.c != null ? m.cols[hover.c] : null;
    if (hover.r != null && hover.c != null) {
      if (!row || !col) return null;
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

  setSafetyViewMode(mode) {
    const next = mode === 'coverage' ? 'coverage' : 'requirements';
    if (next === this.safetyViewMode) return;
    this.safetyViewMode = next;
    if (next === 'coverage') {
      this.coverageHover = null;
      this.$nextTick?.(() => this.bindCoverageScroll());
    }
    this._scheduleNavPush();
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

  // A rotated column title. It is anchored at its column's bottom-left corner
  // and runs up and to the right, so it needs the length the header band can
  // hold, not the 26px width of the column it names.
  coverageColHeadStyle(index) {
    const L = COVERAGE_LAYOUT;
    return (
      `left:${index * L.colW}px;width:${L.headLabelW}px;line-height:${L.headLineH}px;` +
      `transform:rotate(-${L.headAngle}deg) translateX(6px)`
    );
  },

  // The column-header track runs past the last column by the horizontal reach
  // of a title, and the grid gets the same slack, so scrolling to the end still
  // leaves room to read it.
  get coverageTrackWidth() {
    const L = COVERAGE_LAYOUT;
    return Math.max(this.coverageMatrix.cols.length, 1) * L.colW + L.headTrailW;
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

/** "verifications" -> "verification", for a sentence about a single link. */
function singular(noun) {
  return noun.replace(/s$/, '');
}
