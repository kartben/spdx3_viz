import { createState } from './app/state.js';
import { loadingMixin } from './app/loading.js';
import { derivedMixin } from './app/derived.js';
import { accessorsMixin } from './app/accessors.js';
import { navigationMixin } from './app/navigation.js';
import { securityMixin } from './app/security.js';
import { licensesMixin } from './app/licenses.js';
import { graphMixin } from './app/graph.js';

/* ==========================================================================
   spdxApp — the Alpine component (x-data="spdxApp()")
   Assembled from focused mixins: fresh reactive state (state.js) plus behaviour
   grouped by concern (loading, derived data, element accessors, navigation,
   security/VEX, licenses, graph). This file just wires them together and hooks
   the component lifecycle.
   ========================================================================== */

// Lifecycle wiring. Kept here rather than in a mixin since it reaches across
// several concerns (loading, navigation, graph).
const lifecycleMixin = {
  init() {
    this.$watch('currentView', (v) => {
      if (v === 'graph') this.$nextTick(() => this.renderGraph());
    });
    this.$watch('dataLoaded', (loaded) => {
      if (loaded) this._initNavHistory();
    });
    window.addEventListener('popstate', (e) => this._applyNavState(e.state));
    this.loadSampleManifest();
  }
};

// Behaviour mixins, layered onto a fresh state object. defineProperties (rather
// than spread) is used so getters stay lazy getters instead of being evaluated
// once at assembly time; getOwnPropertyDescriptors preserves their enumerable
// flag so Alpine's reactivity still sees them.
const mixins = [
  lifecycleMixin,
  loadingMixin,
  derivedMixin,
  accessorsMixin,
  navigationMixin,
  securityMixin,
  licensesMixin,
  graphMixin
];

export function spdxApp() {
  const app = createState();
  for (const mixin of mixins) {
    Object.defineProperties(app, Object.getOwnPropertyDescriptors(mixin));
  }
  return app;
}

if (typeof window !== 'undefined') {
  window.spdxApp = spdxApp;

  document.addEventListener('alpine:init', () => {
    window.Alpine.data('spdxApp', spdxApp);
  });
}
