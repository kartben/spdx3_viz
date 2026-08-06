import {
  computeHeatIndex,
  heatModeMeta,
  HEAT_MODES,
  GRAPH_LAYOUTS,
  graphLayoutMeta
} from '../lib/index.js';

/* Force graph: thin bridge between the Alpine component and the D3 renderer in
   graph-view.js, plus selecting a node into the detail panel.

   The renderer (2,000 lines plus its d3 modules) loads on first use, mirroring
   the mermaid and highlight.js patterns, so a session that never opens the
   Graph view never downloads it. The dynamic import resolves from cache after
   the first call, so re-renders stay effectively synchronous. */

export const graphMixin = {
  selectGraphNode(spdxId) {
    // Virtual (online-scan) vulns live outside elementMap; resolve them too so a
    // deep link or restore lands on the real node, not a bare placeholder.
    const el = this.elementMap.get(spdxId) || this.virtualVulnMap?.get(spdxId);
    this.detailElement = el || this.placeholderElement(spdxId);
    this._scheduleNavPush();
  },
  renderGraph() {
    import('../graph/graph-view.js').then(({ renderGraph }) => renderGraph(this));
  },
  updateGraph() {
    this.renderGraph();
  },
  // Search only updates the overlay (match/dim/focus) and redraws — no
  // re-layout. Falls back to a full render if the graph isn't built yet.
  graphSearch() {
    if (this.graphRecomputeSearch) this.graphRecomputeSearch();
    else this.renderGraph();
  },
  clearGraphSearch() {
    this.graphSearchQuery = '';
    this.graphSearch();
  },
  collapseAllClusters() {
    this.expandedClusters = new Set();
    this.graphExpandedCount = 0;
    this.renderGraph();
  },
  // Icon mode is purely visual, so repaint the settled canvas rather than
  // rebuilding the graph and restarting the force simulation.
  toggleGraphIcons() {
    if (this.graphRedraw) this.graphRedraw();
    else this.renderGraph();
  },
  resetGraphZoom() {
    import('../graph/graph-view.js').then(({ resetGraphZoom }) => resetGraphZoom(this));
  },

  // --- Layout picker -----------------------------------------------------

  // The catalogue of layouts (organic / hierarchy / radial / spotlight / lanes)
  // and metadata for the active one, for the toolbar picker and its button.
  get graphLayoutList() {
    return GRAPH_LAYOUTS;
  },
  graphLayoutMeta(key) {
    return graphLayoutMeta(key);
  },
  get currentGraphLayout() {
    return graphLayoutMeta(this.graphLayout);
  },
  toggleLayoutMenu() {
    this.graphLayoutMenuOpen = !this.graphLayoutMenuOpen;
  },
  closeLayoutMenu() {
    this.graphLayoutMenuOpen = false;
  },
  // Switch layout: the forces differ per layout, so rebuild the graph, and
  // re-enable auto-fit since a new layout reframes the whole spread.
  setGraphLayout(key) {
    this.graphLayoutMenuOpen = false;
    if (this.graphLayout === key) return;
    this.graphLayout = key;
    this.graphAutoFit = true;
    this.renderGraph();
  },

  // --- Heatmap overlay ---------------------------------------------------

  // True while a heat mode is selected (drives the toolbar highlight + legend).
  get graphHeatActive() {
    return !!this.graphHeatMode && this.graphHeatMode !== 'off';
  },
  // Do not advertise a control that cannot change the graph. The list is cached
  // after loading so this reactive getter stays cheap even for large SBOMs.
  get graphHeatAvailable() {
    return this.graphHeatModeList.some((m) => m.count > 0);
  },
  get graphHeatCount() {
    return this.graphHeatModeList.find((m) => m.key === this.graphHeatMode)?.count || 0;
  },
  // Whether a lens even applies to the loaded data (the underlying feature is
  // present), independent of whether it currently has any hot elements.
  _heatModeApplicable(mode) {
    if (mode === 'vuln') return this.vulnerabilities.length > 0;
    if (mode === 'failed' || mode === 'unverified') return this.safetyCounts.requirements > 0;
    return false;
  },
  heatModeMeta(key) {
    return heatModeMeta(key);
  },
  // The per-element heat map for the active mode, consumed by the renderer.
  // Callbacks are bound here so the pure lib stays DOM/state-free.
  graphHeatData() {
    return computeHeatIndex(this.graphHeatMode, this._graphHeatInputs());
  },
  _graphHeatInputs() {
    return {
      vulnerabilities: this.vulnerabilities,
      requirements: this.requirements,
      requirementStatus: (r) => this.requirementSafetyStatus(r),
      implementedByCount: (id) => this.implementedByCount(id)
    };
  },
  // Modes applicable to the loaded data, each with its live hot-element count.
  // Recomputed when the picker opens (cheap, and only then) rather than on every
  // reactive tick, since it walks the vulnerability/requirement lists.
  _computeHeatModeList() {
    const inputs = this._graphHeatInputs();
    return HEAT_MODES.filter((m) => this._heatModeApplicable(m.key)).map((m) => ({
      ...m,
      count: computeHeatIndex(m.key, inputs).size
    }));
  },
  toggleHeatMenu() {
    this.graphHeatMenuOpen = !this.graphHeatMenuOpen;
    if (this.graphHeatMenuOpen) this.graphHeatModeList = this._computeHeatModeList();
  },
  closeHeatMenu() {
    this.graphHeatMenuOpen = false;
  },
  // Pick a mode (clicking the active one turns it off). Heat is a pure overlay,
  // so repaint the settled canvas instead of rebuilding + relaying out the graph.
  setGraphHeatMode(mode) {
    if (!this.graphHeatModeList.some((m) => m.key === mode && m.count > 0)) return;
    this.graphHeatMode = this.graphHeatMode === mode ? 'off' : mode;
    this.graphHeatMenuOpen = false;
    this._repaintHeat();
  },
  clearGraphHeat() {
    this.graphHeatMode = 'off';
    this.graphHeatMenuOpen = false;
    this._repaintHeat();
  },
  _repaintHeat() {
    if (this.graphRecomputeHeat) this.graphRecomputeHeat();
    else this.renderGraph();
  },
  // Fresh SBOM: drop a heat selection the new data can't honour (e.g. a
  // requirement lens after loading an SBOM with no requirements) so the overlay
  // never lingers on a signal that no longer exists, and reset the picker. The
  // renderer reads graphHeatMode on its next build, so no repaint is needed here.
  _resetGraphHeat() {
    this.graphHeatMenuOpen = false;
    this.graphHeatModeList = this._computeHeatModeList();
    if (
      this.graphHeatActive &&
      !this.graphHeatModeList.some((m) => m.key === this.graphHeatMode && m.count > 0)
    ) {
      this.graphHeatMode = 'off';
    }
  }
};
