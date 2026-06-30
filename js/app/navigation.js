/* ==========================================================================
   Navigation, history + chunked view rendering
   Browser back/forward wiring, switching between views, streaming heavy list
   views into the DOM a chunk at a time, expand/collapse of detail cards, and
   the navigateToX drill-downs (with scroll-into-view).
   ========================================================================== */

/* Chunked list rendering (see renderSlice/_ensureViewRendered). Building
   thousands of cards in one synchronous x-for pass freezes the page for
   seconds on large SBOMs (the Yocto sample has ~3k CVEs), so the heavy list
   views stream in RENDER_CHUNK cards per frame behind a progress bar instead.
   The whole list still ends up in the DOM — no virtualization — so deep links
   to any card keep working. viewRenderSeq cancels a streaming loop when a
   newer one (or freshly parsed data) supersedes it, kept off the reactive
   state since it's pure bookkeeping. */
const RENDER_CHUNK = 200; // max new cards added to the DOM per frame
let viewRenderSeq = 0;
// View id -> the filtered list its main x-for renders, for the streaming loop.
const viewListProps = {
  packages: 'filteredPackages',
  files: 'filteredFiles',
  licenses: 'filteredLicenses',
  security: 'filteredVulnerabilities',
  configs: 'filteredConfigs',
  build: 'filteredBuilds'
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
  // renderLimits[view] — the actual chunk-by-chunk growth of that limit is
  // driven solely by _ensureViewRendered, so there's one source of truth
  // for how much of the list is in the DOM.
  renderSlice(view, list) {
    const limit = this.renderLimits[view];
    return list.length <= limit ? list : list.slice(0, limit);
  },

  // Streams the current view's list into the DOM one chunk per frame,
  // driving the viewRender progress bar. Resumable and safe to call any
  // time: it no-ops when the view is hidden or fully rendered, and a newer
  // call (or freshly parsed data) cancels an in-flight one.
  async _ensureViewRendered(view) {
    const listProp = viewListProps[view];
    if (!listProp || this.currentView !== view) return;
    if (this.renderLimits[view] >= this[listProp].length) return;
    const token = ++viewRenderSeq;
    for (;;) {
      const total = this[listProp].length;
      const done = Math.min(this.renderLimits[view] + RENDER_CHUNK, total);
      this.renderLimits[view] = done;
      Object.assign(this.viewRender, { active: done < total, view, done, total });
      if (done >= total) return;
      // Let Alpine build this chunk, then yield so the page (and the
      // progress bar) stays responsive between chunks. Plain setTimeout,
      // not requestAnimationFrame — rAF callbacks are paused in background/
      // inactive tabs, which would stall the stream indefinitely if the
      // user switches away mid-render.
      await this.$nextTick();
      await new Promise((resolve) => setTimeout(resolve, 0));
      if (token !== viewRenderSeq) return; // superseded — the newer run owns viewRender
      if (this.currentView !== view) {
        // User switched away mid-stream: pause; the next visit resumes.
        this.viewRender.active = false;
        return;
      }
    }
  },

  // Re-streams a view from a fresh first page. Used when its sort order or
  // a filter chip changes: re-sorting swaps/reorders thousands of existing
  // cards, which is as expensive as building them from scratch.
  restreamView(view) {
    if (!(view in this.renderLimits)) return;
    this.renderLimits[view] = Math.min(this.renderLimits[view], RENDER_CHUNK);
    this._ensureViewRendered(view);
  },

  // Resets the streaming cursors after fresh data is applied: cancels any
  // in-flight chunked render, drops every view back to zero rendered cards,
  // and kicks the one currently shown. Called from parseData.
  _resetStreaming() {
    viewRenderSeq++; // cancel any in-flight chunked render of the old data
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
    if (this.expandedFile === id && this.shouldShowFileSource(id)) {
      this.loadFileSource(id);
    }
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
  // Scrolls the list card for (kind, id) into view. The card may not exist
  // yet while its view's list is still streaming in (_ensureViewRendered),
  // so this retries until it appears or the stream settles without it.
  scrollToNavTarget(kind, id) {
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
  navigateTo(spdxId) {
    const el = this.elementMap.get(spdxId);
    if (!el) {
      this.selectGraphNode(spdxId);
      return;
    }
    if (el.type === 'software_Package') {
      this.navigateToPackage(spdxId);
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
    if (this.shouldShowFileSource(spdxId)) {
      this.loadFileSource(spdxId);
    }
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
