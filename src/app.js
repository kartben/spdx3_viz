import { createState } from './app/state.js';
import { loadingMixin } from './app/loading.js';
import { derivedMixin } from './app/derived.js';
import { accessorsMixin } from './app/accessors.js';
import { navigationMixin } from './app/navigation.js';
import { searchMixin } from './app/search.js';
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
    });
    this.$watch('dataLoaded', (loaded) => {
      if (loaded) this._initNavHistory();
    });
    window.addEventListener('popstate', (e) => this._applyNavState(e.state));
    this.loadSampleManifest().then(() => this._maybeLoadFromUrl());
  }
};

// Behaviour mixins, layered onto a fresh state object. defineProperties (not
// spread) keeps getters lazy, and getOwnPropertyDescriptors preserves their
// enumerable flag so Alpine's reactivity still sees them.
const mixins = [
  lifecycleMixin,
  loadingMixin,
  derivedMixin,
  accessorsMixin,
  navigationMixin,
  searchMixin,
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
