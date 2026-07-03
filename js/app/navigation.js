/* ==========================================================================
   Navigation, history + chunked view rendering
   Browser back/forward wiring, switching between views, streaming heavy list
   views into the DOM a chunk at a time, expand/collapse of detail cards, and
   the navigateToX drill-downs (with scroll-into-view).
   ========================================================================== */

/* Load-on-scroll list rendering (see renderSlice/_ensureViewRendered).
   Building thousands of cards up front freezes the page (the Kubernetes sample
   has ~28k files), so heavy list views render only an initial page and then
   grow by RENDER_CHUNK as the user scrolls near the bottom — driven by an
   IntersectionObserver on a single sentinel at the foot of the scroll area.
   The whole list is NOT proactively built (no more multi-second "Rendering N
   of M" streaming), but cards still accumulate in the DOM as you scroll, and a
   deep link streams the list just far enough to reveal its target (see
   _streamToNavTarget), so deep links keep working. viewRenderSeq cancels a
   deep-link stream when a newer navigation supersedes it; scrollObserver is the
   shared observer — both kept off the reactive state as pure bookkeeping. */
const INITIAL_RENDER = 200; // cards rendered when a list view first opens
const RENDER_CHUNK = 200; // cards added per scroll step / deep-link stream frame
let viewRenderSeq = 0;
let scrollObserver = null;
// View id -> the filtered list its main x-for renders.
const viewListProps = {
  packages: 'filteredPackages',
  ai: 'filteredAiPackages',
  dataset: 'filteredDatasetPackages',
  files: 'filteredFiles',
  licenses: 'filteredLicenses',
  security: 'filteredVulnerabilities',
  configs: 'filteredConfigs',
  build: 'filteredBuilds'
};
// Nav-target kind -> how to locate its card in the corresponding list, so a
// deep link can grow that list far enough to render the target before scrolling.
const navKindListInfo = {
  package: { view: 'packages', list: 'filteredPackages', idField: 'spdxId' },
  ai: { view: 'ai', list: 'filteredAiPackages', idField: 'spdxId' },
  dataset: { view: 'dataset', list: 'filteredDatasetPackages', idField: 'spdxId' },
  file: { view: 'files', list: 'filteredFiles', idField: 'spdxId' },
  license: { view: 'licenses', list: 'filteredLicenses', idField: 'id' },
  vuln: { view: 'security', list: 'filteredVulnerabilities', idField: 'spdxId' },
  config: { view: 'configs', list: 'filteredConfigs', idField: 'spdxId' },
  build: { view: 'build', list: 'filteredBuilds', idField: 'spdxId' }
};

export const navigationMixin = {
  // Navigation
  // Browser back/forward: every view switch or element drill-down (expanded
  // card / graph detail panel) is captured as one history entry. Pushes are
  // batched via microtask so a single action that touches several of these
  // fields at once (e.g. navigateToPackage, which sets currentView then
  // expandedPkg) still only produces one entry.
  _navSnapshot() {
    return {
      view: this.currentView,
      expandedPkg: this.expandedPkg,
      expandedFile: this.expandedFile,
      expandedConfig: this.expandedConfig,
      expandedBuild: this.expandedBuild,
      expandedLicense: this.expandedLicense,
      expandedVuln: this.expandedVuln,
      detail: this.detailElement?.spdxId || null,
      graphSelected: this.graphSelectedNodeId
    };
  },
  _initNavHistory() {
    const state = this._navSnapshot();
    this._lastNavKey = JSON.stringify(state);
    history.replaceState(state, '');
  },
  _scheduleNavPush() {
    if (!this.dataLoaded || this._navPushQueued) return;
    this._navPushQueued = true;
    queueMicrotask(() => {
      this._navPushQueued = false;
      const state = this._navSnapshot();
      const key = JSON.stringify(state);
      if (key === this._lastNavKey) return;
      this._lastNavKey = key;
      history.pushState(state, '');
    });
  },
  _applyNavState(state) {
    if (!state) return;
    const wasGraphView = this.currentView === 'graph';
    this._lastNavKey = JSON.stringify(state);
    if (state.view in this.mountedViews) this.mountedViews[state.view] = true;
    this.currentView = state.view;
    this._ensureViewRendered(state.view);
    this.sidebarOpen = false;
    this.expandedPkg = state.expandedPkg;
    this.expandedFile = state.expandedFile;
    this.expandedConfig = state.expandedConfig;
    this.expandedBuild = state.expandedBuild;
    this.expandedLicense = state.expandedLicense;
    this.expandedVuln = state.expandedVuln;
    if (this.expandedVuln) this.ensureCveDetails(this.vulnRecord(this.expandedVuln)?.cveId);
    this.detailElement = state.detail
      ? this.elementMap.get(state.detail) || this.placeholderElement(state.detail)
      : null;
    this.graphSelectedNodeId = state.graphSelected || null;
    // Switching into 'graph' triggers a full rebuild (see the currentView
    // $watch in init) which already reads graphSelectedNodeId fresh; only
    // nudge the live canvas here if it was already showing (no rebuild
    // coming) and needs its pinned highlight moved to match.
    if (wasGraphView && state.view === 'graph') this.graphSyncSelection?.(state.graphSelected);
    // Mirror navigateToX's scroll-into-view for whichever list the restored
    // view tracks an expanded card for.
    const expandedNavTarget = {
      packages: ['package', this.expandedPkg],
      ai: ['ai', this.expandedPkg],
      dataset: ['dataset', this.expandedPkg],
      files: ['file', this.expandedFile],
      configs: ['config', this.expandedConfig],
      build: ['build', this.expandedBuild],
      licenses: ['license', this.expandedLicense],
      security: ['vuln', this.expandedVuln]
    }[state.view];
    if (expandedNavTarget?.[1]) this.scrollToNavTarget(...expandedNavTarget);
  },
  switchView(id) {
    // Mark the target view mounted before switching so its content builds on
    // first visit (and stays cached for instant re-switching afterwards).
    if (id in this.mountedViews) this.mountedViews[id] = true;
    this.currentView = id;
    this.detailElement = null;
    this.sidebarOpen = false; // close the mobile drawer after navigating
    this._ensureViewRendered(id);
    this._scheduleNavPush();
  },

  // Every heavy list x-for renders through this. It's a pure clamp to
  // renderLimits[view] — the growth of that limit is driven by the scroll
  // observer (loadMoreForView) and, for deep links, _streamToNavTarget, so
  // there's one source of truth for how much of the list is in the DOM.
  renderSlice(view, list) {
    const limit = this.renderLimits[view];
    return list.length <= limit ? list : list.slice(0, limit);
  },

  // Ensures a view has at least its first page rendered, then makes sure the
  // scroll loader is wired up. Preserves an already-larger limit so returning
  // to a view you'd scrolled through (or deep-linked into) doesn't collapse it
  // back to the first page.
  _ensureViewRendered(view) {
    const listProp = viewListProps[view];
    if (!listProp) return;
    const total = this[listProp].length;
    this.renderLimits[view] = Math.min(
      Math.max(this.renderLimits[view] || 0, INITIAL_RENDER),
      total
    );
    this.viewRender.active = false;
    this.$nextTick(() => this._ensureScrollLoader());
  },

  // Grows the current view's rendered slice by one chunk. Called by the scroll
  // observer as its sentinel nears the viewport; no-ops once the whole list is
  // in the DOM or for non-list views.
  loadMoreForView(view) {
    const listProp = viewListProps[view];
    if (!listProp) return;
    const total = this[listProp].length;
    if (this.renderLimits[view] >= total) return;
    this.renderLimits[view] = Math.min(this.renderLimits[view] + RENDER_CHUNK, total);
  },

  // Lazily creates the shared IntersectionObserver + a single sentinel at the
  // foot of the scroll area (#mainContent). Only the active view contributes
  // height, so one sentinel tracks whichever list is showing; when it nears the
  // viewport we load the next chunk of the current view.
  _ensureScrollLoader() {
    const root = document.getElementById('mainContent');
    if (!root) return;
    if (!scrollObserver) {
      const app = this;
      scrollObserver = new IntersectionObserver(
        (entries) => {
          for (const e of entries) if (e.isIntersecting) app.loadMoreForView(app.currentView);
        },
        // Pre-load before the sentinel is actually on screen so scrolling stays
        // seamless rather than revealing a blank gap then filling it.
        { root, rootMargin: '1000px 0px' }
      );
    }
    if (!root.querySelector(':scope > [data-stream-sentinel]')) {
      const sentinel = document.createElement('div');
      sentinel.setAttribute('data-stream-sentinel', '');
      sentinel.setAttribute('aria-hidden', 'true');
      root.appendChild(sentinel);
      scrollObserver.observe(sentinel);
    }
  },

  // Grows a view's rendered slice up to `targetLimit`, a chunk per frame behind
  // the progress bar. Used only for deep links that land beyond the currently
  // rendered rows (see _streamToNavTarget) — normal browsing never triggers it.
  async _streamTo(view, targetLimit) {
    const listProp = viewListProps[view];
    if (!listProp) return;
    const goal = Math.min(targetLimit, this[listProp].length);
    if (this.renderLimits[view] >= goal) return;
    const token = ++viewRenderSeq;
    while (this.renderLimits[view] < goal) {
      this.renderLimits[view] = Math.min(this.renderLimits[view] + RENDER_CHUNK, goal);
      const active = this.renderLimits[view] < goal;
      Object.assign(this.viewRender, { active, view, done: this.renderLimits[view], total: goal });
      if (!active) break;
      await this.$nextTick();
      await new Promise((resolve) => setTimeout(resolve, 0));
      if (token !== viewRenderSeq || this.currentView !== view) {
        this.viewRender.active = false;
        return;
      }
    }
    this.viewRender.active = false;
  },

  // Reveals a deep-link target: grows its list far enough that the card exists
  // in the DOM (plus a small buffer) so scrollToNavTarget can find and scroll
  // to it. No-ops when the target is already rendered or has no streamed list.
  _streamToNavTarget(kind, id) {
    const info = navKindListInfo[kind];
    if (!info) return;
    const list = this[info.list];
    if (!list) return;
    const idx = list.findIndex((item) => item[info.idField] === id);
    if (idx < 0) return;
    this._streamTo(info.view, idx + 1 + RENDER_CHUNK);
  },

  // Re-renders a view from its first page. Used when its sort order or a filter
  // chip changes: the list content/order changes wholesale, so drop back to the
  // first page and scroll to the top rather than keeping a deep slice of the
  // old ordering mounted.
  restreamView(view) {
    if (!(view in this.renderLimits)) return;
    const total = this[viewListProps[view]]?.length ?? 0;
    this.renderLimits[view] = Math.min(INITIAL_RENDER, total);
    this.$nextTick(() => {
      document.getElementById('mainContent')?.scrollTo({ top: 0 });
      this._ensureScrollLoader();
    });
  },

  // Resets the render cursors after fresh data is applied: drops every view
  // back to zero and re-renders the first page of the one currently shown.
  // Called from parseData.
  _resetStreaming() {
    viewRenderSeq++; // cancel any in-flight deep-link stream of the old data
    this.viewRender.active = false;
    Object.keys(this.renderLimits).forEach((k) => {
      this.renderLimits[k] = 0;
    });
    this._ensureViewRendered(this.currentView);
  },

  closeDetailPanel() {
    this.detailElement = null;
    this._scheduleNavPush();
  },
  togglePkg(id) {
    this.expandedPkg = this.expandedPkg === id ? null : id;
    this._scheduleNavPush();
  },
  toggleFile(id) {
    this.expandedFile = this.expandedFile === id ? null : id;
    this._scheduleNavPush();
  },
  toggleConfig(id) {
    this.expandedConfig = this.expandedConfig === id ? null : id;
    this._scheduleNavPush();
  },
  toggleBuild(id) {
    this.expandedBuild = this.expandedBuild === id ? null : id;
    this._scheduleNavPush();
  },
  toggleLicense(id) {
    this.expandedLicense = this.expandedLicense === id ? null : id;
    this._scheduleNavPush();
  },
  toggleVuln(id) {
    this.expandedVuln = this.expandedVuln === id ? null : id;
    if (this.expandedVuln) this.ensureCveDetails(this.vulnRecord(id)?.cveId);
    this._scheduleNavPush();
  },
  isNavTarget(kind, id) {
    return this.focusedNavKind === kind && this.focusedNavId === id;
  },
  focusNavTarget(kind, id) {
    this.focusedNavKind = kind;
    this.focusedNavId = id;
    if (this.focusedNavTimer) clearTimeout(this.focusedNavTimer);
    this.focusedNavTimer = setTimeout(() => {
      if (this.focusedNavKind === kind && this.focusedNavId === id) {
        this.focusedNavKind = '';
        this.focusedNavId = '';
      }
    }, 1800);
  },
  // Scrolls the list card for (kind, id) into view. With load-on-scroll the
  // card may be beyond the rendered slice, so first grow the list far enough to
  // include it (a no-op when it's already rendered); the retry loop then waits
  // out that stream (viewRender.active) before it appears.
  scrollToNavTarget(kind, id) {
    this._streamToNavTarget(kind, id);
    const seq = ++this._scrollNavSeq;
    const attempt = (retriesLeft) => {
      if (seq !== this._scrollNavSeq) return; // superseded by a newer navigation
      const target = [...document.querySelectorAll(`[data-nav-kind="${kind}"]`)].find(
        (el) => el.dataset.navId === id && el.offsetParent !== null
      );
      if (target) {
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        this.focusNavTarget(kind, id);
      } else if (this.viewRender.active) {
        setTimeout(() => attempt(retriesLeft), 200); // list still streaming — wait
      } else if (retriesLeft > 0) {
        setTimeout(() => attempt(retriesLeft - 1), 200);
      }
    };
    this.$nextTick(() => requestAnimationFrame(() => attempt(2)));
  },
  // The list view (if any) that navigateTo would land an element in, used by
  // the graph detail panel's "View in <list>" link. Returns null for elements
  // with no dedicated list (placeholders / external references / agents).
  // Nav-target kind for a package card, so the shared list template can live in
  // the Packages / AI Models / Datasets tabs and still scroll to the right card.
  pkgNavKind(pkg) {
    if (pkg?.type === 'ai_AIPackage') return 'ai';
    if (pkg?.type === 'dataset_DatasetPackage') return 'dataset';
    return 'package';
  },
  listTargetFor(el) {
    if (!el || el.placeholder) return null;
    switch (el.type) {
      case 'software_Package':
        return { label: 'Packages' };
      case 'ai_AIPackage':
        return { label: 'AI Models' };
      case 'dataset_DatasetPackage':
        return { label: 'Datasets' };
      case 'software_File':
        return el.software_primaryPurpose === 'configuration' || el.spdxId?.includes('build-config')
          ? { label: 'Build Configs' }
          : { label: 'Files' };
      case 'build_Build':
        return { label: 'Builds' };
      case 'Tool':
        return { label: 'Build Tools' };
      case 'simplelicensing_LicenseExpression':
        return { label: 'Licenses' };
      case 'security_Vulnerability':
        return { label: 'Security' };
      default:
        return null;
    }
  },
  navigateTo(spdxId) {
    const el = this.elementMap.get(spdxId);
    if (!el) {
      this.selectGraphNode(spdxId);
      return;
    }
    if (el.type === 'software_Package') {
      this.navigateToPackage(spdxId);
    } else if (el.type === 'ai_AIPackage') {
      this.navigateToAiPackage(spdxId);
    } else if (el.type === 'dataset_DatasetPackage') {
      this.navigateToDataset(spdxId);
    } else if (el.type === 'software_File') {
      // Check if it's a build config
      if (el.software_primaryPurpose === 'configuration' || spdxId?.includes('build-config')) {
        this.navigateToConfig(spdxId);
      } else {
        this.navigateToFile(spdxId);
      }
    } else if (el.type === 'build_Build') {
      this.navigateToBuild(spdxId);
    } else if (el.type === 'Tool') {
      this.navigateToTool(spdxId);
    } else if (el.type === 'simplelicensing_LicenseExpression') {
      this.navigateToLicense(spdxId);
    } else if (el.type === 'security_Vulnerability') {
      this.navigateToVuln(spdxId);
    }
  },
  navigateToPackage(spdxId) {
    this.searchQuery = '';
    this.switchView('packages');
    this.expandedPkg = spdxId;
    this.scrollToNavTarget('package', spdxId);
  },
  navigateToAiPackage(spdxId) {
    this.searchQuery = '';
    this.switchView('ai');
    this.expandedPkg = spdxId;
    this.scrollToNavTarget('ai', spdxId);
  },
  navigateToDataset(spdxId) {
    this.searchQuery = '';
    this.switchView('dataset');
    this.expandedPkg = spdxId;
    this.scrollToNavTarget('dataset', spdxId);
  },
  navigateToConfig(spdxId) {
    this.configSearch = '';
    this.switchView('configs');
    this.expandedConfig = spdxId;
    this.scrollToNavTarget('config', spdxId);
  },
  navigateToFile(spdxId) {
    this.searchQuery = '';
    this.fileTypeFilter = '';
    this.switchView('files');
    this.expandedFile = spdxId;
    this.scrollToNavTarget('file', spdxId);
  },
  navigateToBuild(spdxId) {
    this.buildSearch = '';
    this.switchView('build');
    this.expandedBuild = spdxId;
    this.scrollToNavTarget('build', spdxId);
  },
  navigateToLicense(spdxId) {
    this.licenseSearch = '';
    this.switchView('licenses');
    this.expandedLicense = spdxId;
    this.scrollToNavTarget('license', spdxId);
  },
  navigateToVuln(spdxId) {
    this.securitySearch = '';
    this.securityStatusFilter = '';
    this.switchView('security');
    this.expandedVuln = spdxId;
    this.scrollToNavTarget('vuln', spdxId);
  },
  // Jump to the Security view pre-filtered to a package's vulnerabilities.
  navigateToPackageSecurity(pkgSpdxId) {
    this.securityStatusFilter = '';
    this.securitySearch = this.relTargetDisplayName(pkgSpdxId);
    this.switchView('security');
  },
  navigateToTool(spdxId) {
    // Tools live in the Build Tools grid at the bottom of the build view.
    this.switchView('build');
    this.scrollToNavTarget('tool', spdxId);
  }
};
