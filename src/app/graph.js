import {
  renderGraph as renderGraphView,
  resetGraphZoom as resetGraphViewZoom
} from '../graph/graph-view.js';

/* Force graph: thin bridge between the Alpine component and the D3 renderer in
   graph-view.js, plus selecting a node into the detail panel. */

export const graphMixin = {
  selectGraphNode(spdxId) {
    const el = this.elementMap.get(spdxId);
    this.detailElement = el || this.placeholderElement(spdxId);
    this._scheduleNavPush();
  },
  renderGraph() {
    renderGraphView(this);
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
    resetGraphViewZoom(this);
  }
};
