import { createState } from './app/state.js';
import { loadingMixin } from './app/loading.js';
import { addFilesMixin } from './app/add-files.js';
import { derivedMixin } from './app/derived.js';
import { accessorsMixin } from './app/accessors.js';
import { navigationMixin } from './app/navigation.js';
import { detailPanelMixin } from './app/detail-panel.js';
import { searchMixin } from './app/search.js';
import { paletteMixin } from './app/palette.js';
import { securityMixin } from './app/security.js';
import { licensesMixin } from './app/licenses.js';
import { graphMixin } from './app/graph.js';
import { rawMixin } from './app/raw.js';
import { changelogMixin } from './app/changelog.js';
import { statisticsMixin } from './app/statistics.js';
import { impactMixin } from './app/impact.js';

/* The spdxApp Alpine component: assembles fresh state with behaviour mixins. */

// Lifecycle wiring, kept here since it reaches across several concerns.
const lifecycleMixin = {
  init() {
    this.$watch('currentView', (v) => {
      if (v === 'graph') this.$nextTick(() => this.renderGraph());
      if (v === 'statistics') this.$nextTick(() => this.renderStatisticsCharts());
      if (v === 'supplychain' && this.supplyChainViewMode === 'states') {
        this.renderSupplyChainStateDiagram();
      }
    });
    // The Supply Chain state machine is drawn with Mermaid, which is imported
    // lazily; (re)render it whenever the States angle becomes visible. The
    // render method retries until its host element is in the DOM.
    this.$watch('supplyChainViewMode', (mode) => {
      if (mode === 'states') this.renderSupplyChainStateDiagram();
    });
    this.$watch('dataLoaded', (loaded) => {
      if (loaded) this._initNavHistory();
    });
    // A null history state is the pre-load landing entry: navigating back to it
    // (browser Back / "previous") returns to the home screen rather than leaving
    // the loaded document stuck on screen.
    window.addEventListener('popstate', (e) => {
      if (e.state) this._applyNavState(e.state);
      else if (this.dataLoaded) this.goHome();
    });
    // ⌘K / Ctrl-K opens the command palette from anywhere (once a document is
    // loaded), including the Graph view where the inline header search is hidden.
    window.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
        if (!this.dataLoaded) return;
        e.preventDefault();
        this.togglePalette();
      }
    });
    this.loadSampleManifest().then(() => this._maybeLoadFromUrl());
  }
};

// Behaviour mixins, layered onto a fresh state object. defineProperties (not
// spread) keeps getters lazy, and getOwnPropertyDescriptors preserves their
// enumerable flag so Alpine's reactivity still sees them.
const mixins = [
  lifecycleMixin,
  loadingMixin,
  addFilesMixin,
  derivedMixin,
  accessorsMixin,
  navigationMixin,
  detailPanelMixin,
  searchMixin,
  paletteMixin,
  securityMixin,
  licensesMixin,
  graphMixin,
  rawMixin,
  changelogMixin,
  statisticsMixin,
  impactMixin
];

export function spdxApp() {
  const app = createState();
  for (const mixin of mixins) {
    Object.defineProperties(app, Object.getOwnPropertyDescriptors(mixin));
  }
  return app;
}
