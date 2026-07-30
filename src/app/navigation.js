/* Navigation, history, and chunked view rendering: browser back/forward wiring,
   view switching, load-on-scroll list rendering, expand/collapse of detail
   cards, and the navigateToX drill-downs with scroll-into-view. */

import { buildShareHash, copyToClipboard, snippetFileRef } from '../lib/index.js';
import { CLASS, isA } from '../spdx/model.js';
import { NAV_CHEVRON_ICON, NAV_EXPLORE_VIEW_IDS, NAV_INSIGHTS_VIEW_IDS } from '../config.js';

// View id -> the nav-snapshot field holding that view's expanded card, for
// carrying the selection in a share link.
const expandedFieldByView = {
  packages: 'expandedPkg',
  ai: 'expandedPkg',
  dataset: 'expandedPkg',
  files: 'expandedFile',
  hardware: 'expandedHardware',
  supplychain: 'expandedSupplyChain',
  requirements: 'expandedRequirement',
  configs: 'expandedConfig',
  build: 'expandedBuild',
  licenses: 'expandedLicense',
  security: 'expandedVuln',
  agents: 'expandedAgent'
};

/* Load-on-scroll list rendering (see renderSlice/_ensureViewRendered).
   Building every card up front freezes the page, so heavy list views render a
   window [start, end) of their filtered list and grow it in whichever direction
   the user scrolls: nearing the bottom grows `end` (renderLimits), nearing the
   top grows the window upward by lowering `start` (renderStarts). Both edges are
   tracked by IntersectionObservers on a sentinel at each end of the scroll area.
   For normal top-down browsing `start` stays 0, so this behaves exactly like a
   grow-downward list. A deep link instead drops the window straight onto its
   target (see _windowToNavTarget) so opening a package buried deep in the Ansible
   SBOM no longer has to render every row above it; scrolling up from there loads
   the earlier rows a chunk at a time. The observers are kept off the reactive
   state as pure bookkeeping. */
const INITIAL_RENDER = 200; // cards rendered when a list view first opens
const RENDER_CHUNK = 200; // cards added per scroll step toward either end
// In-card "show more" lists (revealLimit/revealMore): rows shown before the
// first reveal, and rows added per reveal click.
const REVEAL_BASE = 50;
const REVEAL_CHUNK = 200;
let scrollObserver = null; // grows the window downward (bottom sentinel)
let prevObserver = null; // grows the window upward (top sentinel)
// View id -> the filtered list its main x-for renders.
const viewListProps = {
  packages: 'filteredPackages',
  ai: 'filteredAiPackages',
  dataset: 'filteredDatasetPackages',
  files: 'filteredFiles',
  hardware: 'filteredHardware',
  supplychain: 'filteredSupplyChain',
  requirements: 'filteredRequirements',
  licenses: 'filteredLicenses',
  security: 'filteredVulnerabilities',
  configs: 'filteredConfigs',
  build: 'filteredBuilds',
  agents: 'filteredAgents',
  remediation: 'filteredRemediations'
};
// Nav-target kind -> how to locate its card in the corresponding list, so a
// deep link can center the render window on the target before scrolling to it.
const navKindListInfo = {
  package: { view: 'packages', list: 'filteredPackages', idField: 'spdxId' },
  ai: { view: 'ai', list: 'filteredAiPackages', idField: 'spdxId' },
  dataset: { view: 'dataset', list: 'filteredDatasetPackages', idField: 'spdxId' },
  file: { view: 'files', list: 'filteredFiles', idField: 'spdxId' },
  hardware: { view: 'hardware', list: 'filteredHardware', idField: 'spdxId' },
  supplychain: { view: 'supplychain', list: 'filteredSupplyChain', idField: 'spdxId' },
  requirement: { view: 'requirements', list: 'filteredRequirements', idField: 'spdxId' },
  license: { view: 'licenses', list: 'filteredLicenses', idField: 'id' },
  vuln: { view: 'security', list: 'filteredVulnerabilities', idField: 'spdxId' },
  config: { view: 'configs', list: 'filteredConfigs', idField: 'spdxId' },
  build: { view: 'build', list: 'filteredBuilds', idField: 'spdxId' },
  agent: { view: 'agents', list: 'filteredAgents', idField: 'spdxId' }
};

export const navigationMixin = {
  navChevronIcon: NAV_CHEVRON_ICON,

  viewById(id) {
    return this.views.find((v) => v.id === id) || null;
  },

  get exploreNavViews() {
    return NAV_EXPLORE_VIEW_IDS.map((id) => this.viewById(id)).filter(Boolean);
  },

  get insightsNavViews() {
    return NAV_INSIGHTS_VIEW_IDS.map((id) => this.viewById(id)).filter(Boolean);
  },

  get visibleNavProfiles() {
    return (this.navProfiles || []).filter((p) => p.viewIds.some((id) => this.isViewAvailable(id)));
  },

  // View ids in a profile that are currently reachable (drives single-row vs
  // collapsible rendering when some siblings are empty).
  availableNavProfileViews(profile) {
    return profile.viewIds.filter((id) => this.isViewAvailable(id));
  },

  isNavProfileCollapsible(profile) {
    return this.availableNavProfileViews(profile).length > 1;
  },

  navProfileForView(viewId) {
    return (this.navProfiles || []).find((p) => p.viewIds.includes(viewId)) || null;
  },

  isNavProfileExpanded(profileId) {
    return !!this.expandedNavProfiles[profileId];
  },

  toggleNavProfile(profileId) {
    this.expandedNavProfiles = {
      ...this.expandedNavProfiles,
      [profileId]: !this.expandedNavProfiles[profileId]
    };
  },

  // Expand the collapsible profile that owns viewId (no-op for single-row profiles
  // or Explore / Insights views). Used by switchView and deep-link restore so a
  // nested leaf is never active while its parent drawer is closed.
  ensureNavProfileExpanded(viewId) {
    const profile = this.navProfileForView(viewId);
    if (!profile || !this.isNavProfileCollapsible(profile)) return;
    if (this.expandedNavProfiles[profile.id]) return;
    this.expandedNavProfiles = { ...this.expandedNavProfiles, [profile.id]: true };
  },

  navProfileCount(profile) {
    let total = 0;
    let any = false;
    for (const id of this.availableNavProfileViews(profile)) {
      const n = this.viewById(id)?.count;
      if (n != null && n !== '') {
        any = true;
        total += Number(n) || 0;
      }
    }
    return any ? total : null;
  },

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
      expandedHardware: this.expandedHardware,
      expandedSupplyChain: this.expandedSupplyChain,
      expandedRequirement: this.expandedRequirement,
      expandedConfig: this.expandedConfig,
      expandedBuild: this.expandedBuild,
      expandedLicense: this.expandedLicense,
      expandedVuln: this.expandedVuln,
      expandedAgent: this.expandedAgent,
      detail: this.detailElement?.spdxId || null,
      graphSelected: this.graphSelectedNodeId
    };
  },
  _initNavHistory() {
    const state = this._navSnapshot();
    this._lastNavKey = JSON.stringify(state);
    // Push (not replace) so the pre-load landing entry survives underneath as
    // the previous history state; browser Back then returns to the home screen
    // (handled by the null-state branch of the popstate listener).
    history.pushState(state, '', this._navUrl(state));
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
      history.pushState(state, '', this._navUrl(state));
    });
  },

  // URL for a history entry. Sample-loaded sessions get a share hash so the
  // address bar is always a link to the current spot; anything else (dropped
  // files can't be re-fetched) gets a hashless URL.
  _navUrl(state) {
    const base = location.pathname + location.search;
    if (!this.loadedSampleId) return base;
    const hash = buildShareHash({
      sample: this.loadedSampleId,
      view: state.view,
      expanded: state[expandedFieldByView[state.view]] || null,
      detail: state.detail,
      graphSelected: state.graphSelected
    });
    return hash ? `${base}#${hash}` : base;
  },

  // Applies a parsed share hash (see lib/share.js) once its sample has parsed.
  _applyDeepLink(link) {
    if (!link) return;
    const view = this.views.some((v) => v.id === link.view) ? link.view : 'dashboard';
    const state = {
      view,
      expandedPkg: null,
      expandedFile: null,
      expandedHardware: null,
      expandedSupplyChain: null,
      expandedRequirement: null,
      expandedConfig: null,
      expandedBuild: null,
      expandedLicense: null,
      expandedVuln: null,
      expandedAgent: null,
      detail: link.detail,
      graphSelected: link.graphSelected
    };
    const field = expandedFieldByView[view];
    if (field && link.expanded) state[field] = link.expanded;
    this._applyNavState(state);
    history.replaceState(state, '', this._navUrl(state));
  },

  // Copies the current share link (the address bar URL) to the clipboard.
  copyShareLink() {
    copyToClipboard(location.href).then(() => {
      this.toastMsg = 'Link copied';
      setTimeout(() => (this.toastMsg = ''), 2000);
    });
  },
  _applyNavState(state) {
    if (!state) return;
    const wasGraphView = this.currentView === 'graph';
    this._lastNavKey = JSON.stringify(state);
    if (state.view in this.mountedViews) this.mountedViews[state.view] = true;
    this.ensureNavProfileExpanded(state.view);
    this.currentView = state.view;
    this._ensureViewRendered(state.view);
    this.sidebarOpen = false;
    this.expandedPkg = state.expandedPkg;
    this.expandedFile = state.expandedFile;
    this.expandedHardware = state.expandedHardware;
    this.expandedSupplyChain = state.expandedSupplyChain;
    this.expandedRequirement = state.expandedRequirement;
    this.expandedConfig = state.expandedConfig;
    this.expandedBuild = state.expandedBuild;
    this.expandedLicense = state.expandedLicense;
    this.expandedVuln = state.expandedVuln;
    this.expandedAgent = state.expandedAgent;
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
      hardware: ['hardware', this.expandedHardware],
      supplychain: ['supplychain', this.expandedSupplyChain],
      requirements: ['requirement', this.expandedRequirement],
      configs: ['config', this.expandedConfig],
      build: ['build', this.expandedBuild],
      licenses: ['license', this.expandedLicense],
      security: ['vuln', this.expandedVuln],
      agents: ['agent', this.expandedAgent]
    }[state.view];
    if (expandedNavTarget?.[1]) this.scrollToNavTarget(...expandedNavTarget);
  },
  switchView(id) {
    // Mark the target view mounted before switching so its content builds on
    // first visit (and stays cached for instant re-switching afterwards).
    if (id in this.mountedViews) this.mountedViews[id] = true;
    this.ensureNavProfileExpanded(id);
    this.currentView = id;
    this.detailElement = null;
    this.sidebarOpen = false; // close the mobile drawer after navigating
    this._ensureViewRendered(id);
    this._scheduleNavPush();
  },

  // Unloads the current document and returns to the landing screen. Clears
  // loadedFiles so the next drop/pick starts fresh, and resets the view. Nav
  // history is gated by dataLoaded, so flipping it false leaves no dangling
  // in-document entries.
  goHome() {
    this.loadedFiles = [];
    this.dataLoaded = false;
    this.loadedSampleId = null;
    this._pendingDeepLink = null;
    history.replaceState(null, '', location.pathname + location.search);
    this.currentView = 'dashboard';
    this.detailElement = null;
    this.expandedPkg = null;
    this.expandedFile = null;
    this.expandedHardware = null;
    this.expandedSupplyChain = null;
    this.expandedRequirement = null;
    this.expandedConfig = null;
    this.expandedBuild = null;
    this.expandedLicense = null;
    this.expandedVuln = null;
    this.expandedAgent = null;
    this.rawActiveFile = 0;
    this.sampleError = '';
    this.sidebarOpen = false;
  },

  // Every heavy list x-for renders through this. It's a pure window into the
  // filtered list: [renderStarts[view], renderLimits[view]). Both edges are the
  // single source of truth for what's in the DOM, grown by the scroll observers
  // (loadMoreForView / loadPrevForView) and, for deep links, _windowToNavTarget.
  renderSlice(view, list) {
    const end = this.renderLimits[view];
    let start = this.renderStarts[view] || 0;
    // Guard against a stale start left over if the list shrank out from under
    // the window (filter/sort changes reset it, but be defensive).
    if (start >= list.length) start = 0;
    return start <= 0 && list.length <= end ? list : list.slice(start, Math.max(start, end));
  },

  // Ensures a view has at least its first page rendered, then makes sure the
  // scroll loaders are wired up. Preserves an already-larger window so returning
  // to a view you'd scrolled through (or deep-linked into) doesn't collapse it
  // back to the first page.
  _ensureViewRendered(view) {
    const listProp = viewListProps[view];
    if (!listProp) return;
    const total = this[listProp].length;
    const start = this.renderStarts[view] || 0;
    this.renderLimits[view] = Math.min(
      Math.max(this.renderLimits[view] || 0, start + INITIAL_RENDER),
      total
    );
    this.$nextTick(() => this._ensureScrollLoader());
  },

  // Grows the current view's window downward by one chunk. Called by the bottom
  // scroll observer as its sentinel nears the viewport; no-ops once the window
  // already reaches the end of the list or for non-list views.
  loadMoreForView(view) {
    const listProp = viewListProps[view];
    if (!listProp) return;
    const total = this[listProp].length;
    if (this.renderLimits[view] >= total) return;
    this.renderLimits[view] = Math.min(this.renderLimits[view] + RENDER_CHUNK, total);
  },

  // Grows the current view's window upward by one chunk (lowers `start`). Called
  // by the top scroll observer when the user scrolls back toward the top of a
  // window that was opened deep in the list. Prepending rows above the viewport
  // would shove the visible content down, so we measure the scroll height before
  // and after and re-pin scrollTop by the delta to hold the view still. The
  // _prevLoading guard keeps it to one chunk per frame so the pin is applied
  // before another chunk can queue.
  loadPrevForView(view) {
    const listProp = viewListProps[view];
    if (!listProp) return;
    if ((this.renderStarts[view] || 0) <= 0 || this._prevLoading) return;
    const root = document.getElementById('mainContent');
    if (!root) return;
    this._prevLoading = true;
    const prevHeight = root.scrollHeight;
    const prevTop = root.scrollTop;
    this.renderStarts[view] = Math.max(0, this.renderStarts[view] - RENDER_CHUNK);
    this.$nextTick(() => {
      requestAnimationFrame(() => {
        root.scrollTop = prevTop + (root.scrollHeight - prevHeight);
        this._prevLoading = false;
      });
    });
  },

  // Lazily creates the two IntersectionObservers and a sentinel at each end of
  // the scroll area (#mainContent). Only the active view contributes height, so
  // one pair of sentinels tracks whichever list is showing; nearing the bottom
  // loads the next chunk, nearing the top loads the previous one.
  _ensureScrollLoader() {
    const root = document.getElementById('mainContent');
    if (!root) return;
    const app = this;
    if (!scrollObserver) {
      scrollObserver = new IntersectionObserver(
        (entries) => {
          for (const e of entries) if (e.isIntersecting) app.loadMoreForView(app.currentView);
        },
        // Pre-load before the sentinel is actually on screen so scrolling stays
        // seamless rather than revealing a blank gap then filling it.
        { root, rootMargin: '1000px 0px' }
      );
    }
    if (!prevObserver) {
      prevObserver = new IntersectionObserver(
        (entries) => {
          for (const e of entries) if (e.isIntersecting) app.loadPrevForView(app.currentView);
        },
        // A tighter margin than the bottom: each upward chunk re-pins scrollTop,
        // which pushes this sentinel back out of range, so a smaller lookahead
        // keeps loading to roughly one chunk per scroll-up gesture.
        { root, rootMargin: '300px 0px' }
      );
    }
    if (!root.querySelector(':scope > [data-stream-sentinel="top"]')) {
      const top = document.createElement('div');
      top.setAttribute('data-stream-sentinel', 'top');
      top.setAttribute('aria-hidden', 'true');
      root.prepend(top);
      prevObserver.observe(top);
    }
    if (!root.querySelector(':scope > [data-stream-sentinel="bottom"]')) {
      const bottom = document.createElement('div');
      bottom.setAttribute('data-stream-sentinel', 'bottom');
      bottom.setAttribute('aria-hidden', 'true');
      root.appendChild(bottom);
      scrollObserver.observe(bottom);
    }
  },

  // Centers a view's window on a deep-link target: renders a chunk on each side
  // of the target index so its card exists in the DOM (and scrolling up/down
  // grows the window from there) without rendering every row above it. No-ops
  // when the target is already inside the current window or has no list.
  _windowToNavTarget(kind, id) {
    const info = navKindListInfo[kind];
    if (!info) return;
    const list = this[info.list];
    if (!list) return;
    const idx = list.findIndex((item) => item[info.idField] === id);
    if (idx < 0) return;
    const view = info.view;
    const start = this.renderStarts[view] || 0;
    const end = this.renderLimits[view] || 0;
    if (idx >= start && idx < end) return; // already rendered
    this.renderStarts[view] = Math.max(0, idx - RENDER_CHUNK);
    this.renderLimits[view] = Math.min(list.length, idx + RENDER_CHUNK + 1);
  },

  // Re-renders a view from its first page. Used when its sort order or a filter
  // chip changes: the list content/order changes wholesale, so drop back to the
  // first page and scroll to the top rather than keeping a deep window of the
  // old ordering mounted.
  restreamView(view) {
    if (!(view in this.renderLimits)) return;
    const total = this[viewListProps[view]]?.length ?? 0;
    this.renderStarts[view] = 0;
    this.renderLimits[view] = Math.min(INITIAL_RENDER, total);
    this.$nextTick(() => {
      document.getElementById('mainContent')?.scrollTo({ top: 0 });
      this._ensureScrollLoader();
    });
  },

  // Resets the render windows after fresh data is applied: drops every view back
  // to zero and re-renders the first page of the one currently shown. Called
  // from parseData.
  _resetStreaming() {
    Object.keys(this.renderLimits).forEach((k) => {
      this.renderLimits[k] = 0;
      this.renderStarts[k] = 0;
    });
    this.listReveal = {}; // drop any expanded in-card "show more" lists
    this._ensureViewRendered(this.currentView);
  },

  // "Show more" for an in-card secondary list (a license's users, a build's
  // generated artifacts, …). These aren't the view's main streamed list, so
  // they render a capped preview and grow a chunk at a time on demand rather
  // than mounting tens of thousands of rows the moment the view opens.
  revealLimit(key) {
    return this.listReveal[key] || REVEAL_BASE;
  },
  revealMore(key) {
    this.listReveal[key] = this.revealLimit(key) + REVEAL_CHUNK;
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
    if (this.expandedFile === id && this.fileSourceIndex.get(id)) {
      this.loadFileSource(id);
    }
  },
  toggleHardware(id) {
    this.expandedHardware = this.expandedHardware === id ? null : id;
    this._scheduleNavPush();
  },
  toggleSupplyChain(id) {
    this.expandedSupplyChain = this.expandedSupplyChain === id ? null : id;
    this._scheduleNavPush();
  },
  toggleRequirement(id) {
    this.expandedRequirement = this.expandedRequirement === id ? null : id;
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
  toggleAgent(id) {
    this.expandedAgent = this.expandedAgent === id ? null : id;
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
  // Scrolls the list card for (kind, id) into view. With load-on-scroll the card
  // may be outside the rendered window, so first center the window on it (a
  // no-op when it's already rendered); the card then mounts on the next tick and
  // the retry loop finds and scrolls to it. The window is re-centered on every
  // attempt (cheap no-op once rendered) so a late reactive re-render that resets
  // the window can't leave the target permanently outside it, and the retry
  // budget is generous because a heavy list view's first render after a deep
  // link can take well over half a second to mount the target card.
  scrollToNavTarget(kind, id) {
    // Center synchronously so the reactive re-render is scheduled before the
    // first attempt (deferred via $nextTick + rAF) runs, letting a fast device
    // find the card on the first try with no artificial delay.
    this._windowToNavTarget(kind, id);
    const seq = ++this._scrollNavSeq;
    const attempt = (retriesLeft) => {
      if (seq !== this._scrollNavSeq) return; // superseded by a newer navigation
      this._windowToNavTarget(kind, id);
      const target = [...document.querySelectorAll(`[data-nav-kind="${kind}"]`)].find(
        (el) => el.dataset.navId === id && el.offsetParent !== null
      );
      if (target) {
        // Offset the landing spot by the visible view's sticky header height so
        // the card isn't scrolled underneath it (block:'start' honours
        // scroll-margin-top). Only one list-sticky is on-screen at a time.
        const stickyH = [...document.querySelectorAll('#mainContent .list-sticky')].find(
          (el) => el.offsetParent !== null
        )?.offsetHeight;
        target.style.scrollMarginTop = stickyH ? `${stickyH + 12}px` : '';
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        this.focusNavTarget(kind, id);
      } else if (retriesLeft > 0) {
        setTimeout(() => attempt(retriesLeft - 1), 100);
      }
    };
    // ~3s of retries at 100ms: stops the instant the card is found, so the only
    // cost of a high ceiling is tolerating a slow first render.
    this.$nextTick(() => requestAnimationFrame(() => attempt(30)));
  },
  // Nav-target kind for a package card, so the shared list template works across
  // the Packages / AI Models / Datasets tabs and still scrolls to the right card.
  pkgNavKind(pkg) {
    if (pkg?.type === 'ai_AIPackage') return 'ai';
    if (pkg?.type === 'dataset_DatasetPackage') return 'dataset';
    return 'package';
  },
  // The list view (if any) that navigateTo would land an element in. Returns
  // null for elements with no dedicated list (placeholders / agents).
  listTargetFor(el) {
    if (!el || el.placeholder) return null;
    // Agents (Person / Organization / SoftwareAgent) resolve by node type rather
    // than an exact class, so they land in the Agents tab regardless of subclass.
    if (this.getNodeType(el) === 'agent') return { label: 'Agents' };
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
      case 'hardware_Hardware':
      case 'hardware_PhysicalHardware':
      case 'hardware_BulkHardware':
      case 'hardware_VirtualHardware':
        return { label: 'Hardware' };
      case 'supplychain_State':
        return { label: 'Supply Chain' };
      case 'Requirement':
      case 'functionalsafety_RequirementVerification':
      case 'functionalsafety_Assumption':
      case 'functionalsafety_EvaluationResult':
        return { label: 'Functional Safety' };
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
    const el = this.elementMap.get(spdxId) || this.virtualVulnMap?.get(spdxId);
    if (!el) {
      this.selectGraphNode(spdxId);
      return;
    }
    // Agents route by node type so every subclass lands in the Agents tab.
    if (this.getNodeType(el) === 'agent') {
      this.navigateToAgent(spdxId);
      return;
    }
    if (this.getNodeType(el) === 'supplychain') {
      this.navigateToSupplyChain(spdxId);
      return;
    }
    // A snippet isn't a page of its own: open it in a popup showing its file's
    // source with the snippet's lines highlighted.
    if (this.getNodeType(el) === 'snippet') {
      this.openSnippet(spdxId);
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
    } else if (
      el.type === 'hardware_Hardware' ||
      el.type === 'hardware_PhysicalHardware' ||
      el.type === 'hardware_BulkHardware' ||
      el.type === 'hardware_VirtualHardware'
    ) {
      this.navigateToHardware(spdxId);
    } else if (
      el.type === 'Requirement' ||
      el.type === 'functionalsafety_RequirementVerification' ||
      el.type === 'functionalsafety_Assumption' ||
      el.type === 'functionalsafety_EvaluationResult'
    ) {
      this.navigateToRequirement(spdxId);
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
    this.packageSearch = '';
    this.switchView('packages');
    this.expandedPkg = spdxId;
    this.scrollToNavTarget('package', spdxId);
  },
  navigateToAiPackage(spdxId) {
    this.packageSearch = '';
    this.switchView('ai');
    this.expandedPkg = spdxId;
    this.scrollToNavTarget('ai', spdxId);
  },
  navigateToDataset(spdxId) {
    this.packageSearch = '';
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
    this.fileSearch = '';
    this.fileTypeFilter = '';
    this.switchView('files');
    this.expandedFile = spdxId;
    if (this.fileSourceIndex.get(spdxId)) {
      this.loadFileSource(spdxId);
    }
    this.scrollToNavTarget('file', spdxId);
  },
  // Open a snippet in a popup: it shows the source of the file the snippet was
  // carved from, with the snippet's lines highlighted and scrolled into view,
  // plus a link to open the full file in the Files view.
  openSnippet(snippetId) {
    this._openSnippetModal([snippetId]);
  },
  // Open several ranges of the same file in one popup, highlighting every range
  // and scrolling to the first. Backs the collapsed "N ranges" relationship row
  // (see snippetRow in accessors.js).
  openSnippetRanges(snippetIds) {
    this._openSnippetModal(Array.isArray(snippetIds) ? snippetIds : [snippetIds]);
  },
  // Shared popup builder for one or more snippets. The ranges are confined to
  // the first snippet's file (a collapsed range row always shares one file),
  // sorted by start line so the highlights and the scroll target read top-down.
  _openSnippetModal(snippetIds) {
    const refs = (snippetIds || [])
      .map((id) => ({ id, ref: snippetFileRef(this.elementMap.get(id), this.elementMap) }))
      .filter((s) => s.ref?.fileId);
    if (!refs.length) return;
    const fileId = refs[0].ref.fileId;
    const first = refs[0].ref;
    const ranges = refs
      .filter((s) => s.ref.fileId === fileId && s.ref.start != null)
      .map((s) => ({ start: s.ref.start, end: s.ref.end ?? s.ref.start }))
      .sort((a, b) => a.start - b.start);
    // Fall back to a single (possibly line-less) range so the header/highlight
    // bindings always have something to read.
    const effective = ranges.length
      ? ranges
      : [{ start: first.start, end: first.end ?? first.start }];
    this.snippetModal = {
      snippetId: refs[0].id,
      fileId,
      fileName: first.fileName,
      baseName: first.baseName,
      name: refs.length === 1 ? first.name : '',
      start: effective[0].start,
      end: effective[0].end,
      ranges: effective,
      rangeCount: ranges.length,
      sourceUrl: this.fileSourceIndex.get(fileId) || '',
      expanded: {} // gap key -> revealed line count (see _collapseSource)
    };
    this.snippetModalOpen = true;
    this.loadFileSource(fileId);
    this._scrollSnippetModal();
  },
  closeSnippetModal() {
    // Keep snippetModal data so the header doesn't flash empty while fading out.
    this.snippetModalOpen = false;
  },
  // From the popup, jump to the full file in the Files view.
  openSnippetFile() {
    const m = this.snippetModal;
    if (!m) return;
    this.closeSnippetModal();
    this.navigateToFile(m.fileId);
  },
  // Retry until the highlighted first line is in the popup DOM (source loads
  // async), then centre it. Sequence guard drops retries from a stale open.
  _scrollSnippetModal() {
    const m = this.snippetModal;
    if (!m || m.start == null) return;
    const seq = ++this._scrollSnippetSeq;
    const attempt = (retriesLeft) => {
      if (seq !== this._scrollSnippetSeq || !this.snippetModalOpen) return;
      const line = document.querySelector(`#snippet-modal-body .sv-line[data-line="${m.start}"]`);
      if (line) {
        line.scrollIntoView({ block: 'center' });
      } else if (retriesLeft > 0) {
        setTimeout(() => attempt(retriesLeft - 1), 120);
      }
    };
    this.$nextTick(() => requestAnimationFrame(() => attempt(30)));
  },

  // Collapses a file's full line list down to just the covered ranges plus a few
  // lines of context, folding the long stretches in between into clickable "N
  // lines hidden" gaps, so a link into a file shows the important code directly
  // instead of the whole file. Returns a flat list of segments the source
  // viewers render: { kind:'code', lineNum, html, covered } | { kind:'gap',
  // key, hidden }. `expanded` maps a gap key to how many extra lines the user
  // has revealed there (see expandSnippetGap); over-revealing simply opens the
  // gap fully. With no line ranges the whole file is shown, nothing collapsed.
  _collapseSource(lines, ranges, expanded) {
    const total = lines.length;
    const valid = (ranges || []).filter((r) => Number.isFinite(r.start));
    if (!valid.length) {
      return lines.map((l) => ({
        kind: 'code',
        lineNum: l.lineNum,
        html: l.html,
        covered: false
      }));
    }
    const CONTEXT = 6; // lines of surrounding code kept around each range
    const MIN_GAP = 4; // shorter stretches aren't worth collapsing
    const clamp = (n) => Math.max(1, Math.min(total, n));
    const isCovered = (n) => valid.some((r) => n >= r.start && n <= (r.end ?? r.start));

    // Each range grows to a context window; overlapping/near windows merge so
    // adjacent ranges read as one block rather than a seam of tiny gaps.
    const windows = [];
    valid
      .map((r) => ({ start: clamp(r.start - CONTEXT), end: clamp((r.end ?? r.start) + CONTEXT) }))
      .sort((a, b) => a.start - b.start)
      .forEach((w) => {
        const last = windows[windows.length - 1];
        if (last && w.start <= last.end + MIN_GAP) last.end = Math.max(last.end, w.end);
        else windows.push({ ...w });
      });
    // Absorb tiny head/tail stretches rather than showing a 1-3 line gap.
    if (windows[0].start - 1 < MIN_GAP) windows[0].start = 1;
    const lastWin = windows[windows.length - 1];
    if (total - lastWin.end < MIN_GAP) lastWin.end = total;

    // Reveal: each gap opens toward the window that follows it (the trailing gap
    // extends the last window's tail), clamped so it never crosses a neighbour.
    const exp = expanded || {};
    windows.forEach((w, i) => {
      const rev = exp[i] || 0;
      if (rev) w.start = Math.max((i > 0 ? windows[i - 1].end : 0) + 1, w.start - rev);
    });
    if (exp[windows.length]) lastWin.end = Math.min(total, lastWin.end + exp[windows.length]);

    const segments = [];
    let cursor = 1;
    windows.forEach((w, i) => {
      if (w.start > cursor) segments.push({ kind: 'gap', key: i, hidden: w.start - cursor });
      for (let n = w.start; n <= w.end; n++) {
        segments.push({
          kind: 'code',
          lineNum: n,
          html: lines[n - 1]?.html ?? '',
          covered: isCovered(n)
        });
      }
      cursor = w.end + 1;
    });
    if (cursor <= total)
      segments.push({ kind: 'gap', key: windows.length, hidden: total - cursor + 1 });
    return segments;
  },

  // Collapsed source segments for the snippet popup (all its ranges) and the
  // detail panel's inline viewer (the one selected snippet). null until the
  // file's source has loaded.
  get snippetModalSegments() {
    const m = this.snippetModal;
    const cache = m && this.fileSourceCache[m.fileId];
    if (!m || !cache?.lines) return null;
    return this._collapseSource(cache.lines, m.ranges || [], m.expanded || {});
  },
  get detailSnippetSegments() {
    const ref = this.detailSnippet;
    const cache = ref && this.fileSourceCache[ref.fileId];
    if (!ref || !cache?.lines) return null;
    return this._collapseSource(
      cache.lines,
      [{ start: ref.start, end: ref.end }],
      this.detailSnippetExpanded
    );
  },
  // Reveal a collapsed gap by a chunk (over-revealing opens it fully).
  expandSnippetGap(key) {
    const m = this.snippetModal;
    if (!m) return;
    m.expanded = { ...(m.expanded || {}), [key]: (m.expanded?.[key] || 0) + 40 };
  },
  expandDetailSnippetGap(key) {
    this.detailSnippetExpanded = {
      ...this.detailSnippetExpanded,
      [key]: (this.detailSnippetExpanded?.[key] || 0) + 40
    };
  },

  // True when the graph-selected element is a snippet, gating the inline source
  // viewer in the detail panel.
  get isSnippetDetail() {
    return this.detailElement?.type === 'software_Snippet';
  },
  // File/line ref for the selected snippet (or null), so the detail panel can
  // render its file's source with the snippet's lines highlighted.
  get detailSnippet() {
    const el = this.detailElement;
    if (!el || el.type !== 'software_Snippet') return null;
    return snippetFileRef(el, this.elementMap);
  },
  // Lazily fetch the source behind the selected snippet and, once per selection,
  // scroll its highlighted lines into view. Driven by x-effect in the panel.
  ensureDetailSnippetSource() {
    const el = this.detailElement;
    const ref = el?.type === 'software_Snippet' ? snippetFileRef(el, this.elementMap) : null;
    if (!ref?.fileId) return;
    this.loadFileSource(ref.fileId);
    if (this._detailSnippetId !== el.spdxId) {
      this._detailSnippetId = el.spdxId;
      this.detailSnippetExpanded = {}; // fresh collapse state per snippet
      this._scrollDetailSnippet(ref.start);
    }
  },
  // From the detail panel, jump to the snippet's file in the Files view.
  openDetailSnippetFile() {
    const ref = this.detailSnippet;
    if (!ref?.fileId) return;
    this.closeDetailPanel();
    this.navigateToFile(ref.fileId);
  },
  // Retry until the highlighted first line is in the panel DOM (source loads
  // async), then centre it vertically without disturbing horizontal scroll.
  _scrollDetailSnippet(start) {
    if (start == null) return;
    const seq = ++this._scrollDetailSnippetSeq;
    const attempt = (retriesLeft) => {
      if (seq !== this._scrollDetailSnippetSeq) return;
      const line = document.querySelector(`#detail-snippet-source .sv-line[data-line="${start}"]`);
      if (line) {
        line.scrollIntoView({ block: 'center', inline: 'nearest' });
      } else if (retriesLeft > 0) {
        setTimeout(() => attempt(retriesLeft - 1), 120);
      }
    };
    this.$nextTick(() => requestAnimationFrame(() => attempt(30)));
  },
  navigateToHardware(spdxId) {
    this.hardwareSearch = '';
    this.switchView('hardware');
    this.expandedHardware = spdxId;
    this.scrollToNavTarget('hardware', spdxId);
  },
  navigateToSupplyChain(spdxId) {
    this.supplyChainSearch = '';
    this.supplyChainFamilyFilter = '';
    this.supplyChainExceptionFilter = '';
    this.switchView('supplychain');

    // Route to the angle that actually shows this element: processes live in the
    // Processes playbook, states (and the StateActions that drive them) in the
    // States machine, and every other action in the Timeline.
    const el = this.elementMap.get(spdxId);
    const kind = this.supplyChainKind(el);
    if (kind === 'process') {
      this.supplyChainViewMode = 'processes';
      this.scrollToNavTarget('supplychain', spdxId);
      return;
    }
    if (kind === 'state') {
      // A State element itself has no card; land on the StateAction that reached
      // it so the stepper card highlights.
      const reachedBy = this.supplyChainStateActions(el)[0];
      this.supplyChainViewMode = 'states';
      const target = reachedBy?.spdxId || spdxId;
      this.scrollToNavTarget('supplychain', target);
      return;
    }
    if (isA(el?.type, CLASS.supplychain_StateAction)) {
      this.supplyChainViewMode = 'states';
      this.expandedSupplyChain = spdxId;
      this.scrollToNavTarget('supplychain', spdxId);
      return;
    }
    this.supplyChainViewMode = 'timeline'; // the expanded card lives in the timeline list
    this.expandedSupplyChain = spdxId;
    this.scrollToNavTarget('supplychain', spdxId);
  },
  navigateToRequirement(spdxId) {
    this.requirementSearch = '';
    // Clear the kind + status filters and drop back to the list layout, else the
    // target may be filtered out of filteredRequirements (or hidden by the
    // decomposition tree) and nothing scrolls into view.
    this.requirementKindFilter = '';
    this.requirementStatusFilter = '';
    this.requirementLayout = 'list';
    this.switchView('requirements');
    this.expandedRequirement = spdxId;
    this.scrollToNavTarget('requirement', spdxId);
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
    this.securitySeverityFilter = '';
    this.switchView('security');
    this.expandedVuln = spdxId;
    this.scrollToNavTarget('vuln', spdxId);
  },
  // Jump to the Security view pre-filtered to a package's vulnerabilities.
  navigateToPackageSecurity(pkgSpdxId) {
    this.securityStatusFilter = '';
    this.securitySeverityFilter = '';
    this.securitySearch = this.relTargetDisplayName(pkgSpdxId);
    this.switchView('security');
  },
  navigateToTool(spdxId) {
    // Tools live in the Build Tools grid at the bottom of the build view.
    this.switchView('build');
    this.scrollToNavTarget('tool', spdxId);
  },
  navigateToAgent(spdxId) {
    this.agentSearch = '';
    this.switchView('agents');
    this.expandedAgent = spdxId;
    this.scrollToNavTarget('agent', spdxId);
  }
};
