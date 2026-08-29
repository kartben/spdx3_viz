import {
  buildDirectoryFacets,
  buildPurposeFacets,
  buildSafetySpecFacets,
  dirPrefix,
  escapeHtml,
  getExternalIdentifiers,
  isMeaningfulValue,
  licenseIndividualToken,
  mergeVulnLists,
  packageGaps,
  packageHasPurpose,
  summarizePackageDescription
} from '../lib/index.js';
import { isA, CLASS } from '../spdx/model.js';
import { SAFETY_ADEQUACY } from '../config.js';

/* Derived data: computed getters over the parsed model — filtered/sorted list
   views, the security summary, and the counts/labels templates read. */

// Memoized filtered-list results, keyed on the inputs that actually affect them
// so unrelated reactive changes don't re-sort the list. Kept off the reactive
// state so it isn't proxied. The files memo matters most: without it the getter
// re-ran a full locale-aware sort on every streamed chunk.
let filteredBuildsCacheKey = null;
let filteredBuildsCacheVal = [];
let filteredVulnsCacheKey = null;
let filteredVulnsCacheVal = [];
let allVulnsCacheKey = null;
let allVulnsCacheVal = [];
let filteredFilesCacheKey = null;
let filteredFilesCacheVal = [];
let fileTypesCacheKey = null;
let fileTypesCacheVal = [];
let fileDirsCacheKey = null;
let fileDirsCacheVal = [];
// Packages / AI models / Datasets share one filter+sort pipeline, and only one
// of the three lists is on screen at a time, so a single memo slot is enough.
let pkgListCacheKey = null;
let pkgListCacheVal = [];
let pkgGroupsSrc = null;
let pkgGroupsVal = { plain: [], ai: [], dataset: [] };
let pkgFacetsCacheKey = null;
let pkgFacetsCacheVal = [];
let pkgSummaryCacheKey = null;
let pkgSummaryCacheVal = null;
let licensedIdsSrc = null;
let licensedIdsVal = new Set();
let filteredHardwareCacheKey = null;
let filteredHardwareCacheVal = [];
let filteredLicensesCacheKey = null;
let filteredLicensesCacheVal = [];
let filteredConfigsCacheKey = null;
let filteredConfigsCacheVal = [];
let filteredAgentsCacheKey = null;
let filteredAgentsCacheVal = [];
let filteredSupplyChainCacheKey = null;
let filteredSupplyChainCacheVal = [];
let filteredReqsCacheKey = null;
let filteredReqsCacheVal = [];
// supplyChainActions feeds most of the other supply-chain getters, so a single
// identity memo on the source list spares the whole cascade a re-filter+sort.
let scActionsSrc = null;
let scActionsVal = [];
// The decomposition graph is a full pass over `relationships` (85k+ on a large
// SBOM) and is read by the tree, its empty state, and collapseAllReqs.
let safetyDecompRelsSrc = null;
let safetyDecompReqsSrc = null;
let safetyDecompVal = { childrenOf: new Map(), roots: [], hasDecomposition: false };
let safetyTreeCacheKey = null;
let safetyTreeCacheVal = [];
// Lowercased "name version identifiers" per package, built on the first search
// keystroke only (an SBOM the user never searches never pays for it).
let pkgSearchIndexSrc = null;
let pkgSearchIndexVal = new Map();
// Whole-collection summary rollups, memoized on their source array's identity.
// Every view header is bound at shell mount (view roots are x-show, only the
// lists are gated by mountedViews), so without a memo each of these full scans
// re-ran for all views at once, several times per render.
let scCountsSrc = null;
let scCountsVal = null;
let safetyCountsSrc = null;
let safetyCountsVal = null;
let safetyStatusSrc = null;
let safetyStatusVal = null;
let safetyAdequacySrc = null;
let safetyAdequacyVal = null;
let safetySpecFacetsRelsSrc = null;
let safetySpecFacetsReqsSrc = null;
let safetySpecFacetsVal = [];
let securitySummarySrc = null;
let securitySummaryVal = null;
let severitySummarySrc = null;
let severitySummaryVal = null;
let hasCvssSrc = null;
let hasCvssVal = false;

// Most-common file extensions to offer as filter chips. A large rootfs SBOM can
// carry thousands of distinct extensions; showing one chip each turns the Files
// header into a wall. We surface the top few by file count instead.
const FILE_TYPE_CHIP_LIMIT = 12;

// Chip value+label for files with no extension (fileExt returns ''). A real
// extension always starts with '.', so this never collides with one, nor with
// the '' that fileTypeFilter uses to mean "no filter / All".
const NO_EXT_LABEL = '(no ext)';

// Most populated directories offered as Files filter facets, and how many
// leading path segments each one groups on (matches the graph's file clusters).
const FILE_DIR_FACET_LIMIT = 12;
const FILE_DIR_FACET_DEPTH = 2;

export const derivedMixin = {
  // Clears the build + vulnerability sort memos. Called when fresh data is
  // applied (see parseData) so the next getter read recomputes from scratch.
  _resetListMemos() {
    filteredBuildsCacheKey = null;
    filteredVulnsCacheKey = null;
    filteredFilesCacheKey = null;
    fileTypesCacheKey = null;
    fileDirsCacheKey = null;
    allVulnsCacheKey = null;
    pkgListCacheKey = null;
    pkgGroupsSrc = null;
    pkgFacetsCacheKey = null;
    pkgSummaryCacheKey = null;
    licensedIdsSrc = null;
    pkgSearchIndexSrc = null;
    pkgSearchIndexVal = new Map();
    filteredHardwareCacheKey = null;
    filteredLicensesCacheKey = null;
    filteredConfigsCacheKey = null;
    filteredAgentsCacheKey = null;
    filteredSupplyChainCacheKey = null;
    filteredReqsCacheKey = null;
    scActionsSrc = null;
    safetyDecompRelsSrc = null;
    safetyDecompReqsSrc = null;
    safetyTreeCacheKey = null;
    scCountsSrc = null;
    safetyCountsSrc = null;
    safetyStatusSrc = null;
    safetyAdequacySrc = null;
    safetySpecFacetsRelsSrc = null;
    safetySpecFacetsReqsSrc = null;
    securitySummarySrc = null;
    severitySummarySrc = null;
    hasCvssSrc = null;
  },

  // SBOM-derived vulnerabilities merged with any OSV online findings. Before a
  // lookup runs (no online data) this is just the SBOM list, so the view is
  // unchanged. After a lookup, entries are tagged source: sbom | online | both.
  // Memoized so the merge runs once per (SBOM, online-result) pair.
  get allVulnerabilities() {
    if (!this.onlineVulns.length) return this.vulnerabilities;
    const key = `${this.vulnerabilities.length}|${this.onlineVulns.length}|${this.onlineSync.ranAt}`;
    if (key === allVulnsCacheKey) return allVulnsCacheVal;
    allVulnsCacheVal = mergeVulnLists(this.vulnerabilities, this.onlineVulns);
    allVulnsCacheKey = key;
    return allVulnsCacheVal;
  },

  get currentViewLabel() {
    return this.views.find((v) => v.id === this.currentView)?.label || '';
  },

  // Compact, type-aware inventory for the overview. Empty kinds are omitted so
  // the same landing page works for software, hardware, AI, build and safety
  // documents without reserving space for irrelevant sections.
  get dashboardInventory() {
    return [
      { view: 'packages', label: 'Packages', count: this.plainPackages.length, type: 'package' },
      { view: 'ai', label: 'AI models', count: this.aiPackages.length, type: 'ai' },
      { view: 'dataset', label: 'Datasets', count: this.datasetPackages.length, type: 'dataset' },
      { view: 'files', label: 'Files', count: this.files.length, type: 'file' },
      { view: 'hardware', label: 'Hardware', count: this.hardware.length, type: 'hardware' },
      {
        view: 'supplychain',
        label: 'Supply chain',
        count: this.supplyChain.length,
        type: 'supplychain'
      },
      {
        view: 'requirements',
        label: 'Safety elements',
        count: this.requirements.length,
        type: 'requirement'
      },
      { view: 'licenses', label: 'Licenses', count: this.licenses.length, type: 'license' },
      {
        view: 'security',
        label: 'Vulnerabilities',
        count: this.vulnerabilities.length,
        type: 'vulnerability'
      },
      { view: 'configs', label: 'Build configs', count: this.buildConfigs.length, type: 'config' },
      {
        view: 'build',
        label: 'Builds & tools',
        count: this.builds.length + this.tools.length,
        type: 'build'
      },
      { view: 'agents', label: 'Agents', count: this.agents.length, type: 'agent' }
    ].filter((item) => item.count > 0);
  },

  // AI models and dataset packages are software_Package subclasses (AI profile)
  // and get their own tabs, so the Packages tab lists only plain packages. The
  // three-way split is one pass over `packages`, memoized on that array so the
  // getters below stay O(1) reads instead of re-filtering per template read.
  _packageGroups() {
    if (pkgGroupsSrc === this.packages) return pkgGroupsVal;
    const plain = [];
    const ai = [];
    const dataset = [];
    for (const p of this.packages) {
      const isAi = isA(p.type, CLASS.ai_AIPackage);
      const isDataset = isA(p.type, CLASS.dataset_DatasetPackage);
      if (isAi) ai.push(p);
      if (isDataset) dataset.push(p);
      if (!isAi && !isDataset) plain.push(p);
    }
    pkgGroupsVal = { plain, ai, dataset };
    pkgGroupsSrc = this.packages;
    return pkgGroupsVal;
  },

  get aiPackages() {
    return this._packageGroups().ai;
  },
  get datasetPackages() {
    return this._packageGroups().dataset;
  },
  get plainPackages() {
    return this._packageGroups().plain;
  },

  // Which of the three package-style tabs is showing. Doubles as the memo key
  // for everything derived from that tab's base list.
  get _packageGroupKey() {
    return this.currentView === 'ai' ? 'ai' : this.currentView === 'dataset' ? 'dataset' : 'plain';
  },

  // The unfiltered list behind the current tab.
  get currentPackageBase() {
    return this._packageGroups()[this._packageGroupKey];
  },

  // Elements carrying a concrete declared/concluded license, from the license
  // index the parser already built. The ExpandedLicensing NoAssertion / None
  // individuals name the absence of a license, so they don't count as one.
  get _licensedElementIds() {
    if (licensedIdsSrc === this.licenses) return licensedIdsVal;
    const ids = new Set();
    for (const lic of this.licenses) {
      if (licenseIndividualToken(lic.id) || !isMeaningfulValue(lic.label)) continue;
      for (const id of lic.declaredBy || []) ids.add(id);
      for (const id of lic.concludedBy || []) ids.add(id);
    }
    licensedIdsVal = ids;
    licensedIdsSrc = this.licenses;
    return ids;
  },

  // Search corpus per package: name, id, version, and every external identifier
  // (PackageURL, CPE, …) so a purl paste finds its package. Built once, lazily.
  get _packageSearchIndex() {
    if (pkgSearchIndexSrc === this.packages) return pkgSearchIndexVal;
    const idx = new Map();
    for (const p of this.packages) {
      const parts = [p.name || '', this.cleanName(p.spdxId), p.software_packageVersion || ''];
      for (const eid of getExternalIdentifiers(p)) parts.push(eid.identifier);
      idx.set(p.spdxId, parts.join(' ').toLowerCase());
    }
    pkgSearchIndexVal = idx;
    pkgSearchIndexSrc = this.packages;
    return idx;
  },

  // Which described-fields a package is missing (no version / license / supplier
  // / identifier). Backs both the rollup summary and the gap filter chips.
  packageGapsFor(pkg) {
    return packageGaps(pkg, this._licensedElementIds.has(pkg?.spdxId));
  },

  // Applies the shared package search box, facet filters and sort control to the
  // current tab's base list. Memoized on the inputs that actually change the
  // result, so scrolling a 100k-package list doesn't re-filter and re-sort it on
  // every reactive read.
  get currentPackageList() {
    if (
      this.currentView !== 'packages' &&
      this.currentView !== 'ai' &&
      this.currentView !== 'dataset'
    ) {
      return [];
    }
    const base = this.currentPackageBase;
    const key = [
      this._packageGroupKey,
      this.packages.length,
      this.licenses.length,
      this.packageSearch,
      this.pkgSort,
      this.pkgPurposeFilter,
      this.pkgGapFilter
    ].join('|');
    if (key === pkgListCacheKey) return pkgListCacheVal;

    let pkgs = base;
    if (this.packageSearch) {
      const q = this.packageSearch.toLowerCase();
      const idx = this._packageSearchIndex;
      pkgs = pkgs.filter((p) => (idx.get(p.spdxId) || '').includes(q));
    }
    if (this.pkgPurposeFilter) {
      pkgs = pkgs.filter((p) => packageHasPurpose(p, this.pkgPurposeFilter));
    }
    if (this.pkgGapFilter) {
      pkgs = pkgs.filter((p) => this.packageGapsFor(p)[this.pkgGapFilter]);
    }

    let sorted;
    if (this.pkgSort === 'deps') {
      sorted = [...pkgs].sort(
        (a, b) => (this.depsOf(b.spdxId)?.length || 0) - (this.depsOf(a.spdxId)?.length || 0)
      );
    } else if (this.pkgSort === 'dependents') {
      sorted = [...pkgs].sort(
        (a, b) =>
          (this.dependentsOf(b.spdxId)?.length || 0) - (this.dependentsOf(a.spdxId)?.length || 0)
      );
    } else {
      sorted = [...pkgs].sort((a, b) =>
        (a.name || this.cleanName(a.spdxId)).localeCompare(b.name || this.cleanName(b.spdxId))
      );
    }

    pkgListCacheKey = key;
    pkgListCacheVal = sorted;
    return sorted;
  },

  // The three tabs render through one template, so their list props all resolve
  // to whichever tab is showing (see viewListProps in navigation.js).
  get filteredPackages() {
    return this.currentPackageList;
  },
  get filteredAiPackages() {
    return this.currentPackageList;
  },
  get filteredDatasetPackages() {
    return this.currentPackageList;
  },

  // Primary-purpose facets for the current tab's base list (library, application,
  // container, …), so the rail counts don't move as filters are applied.
  get packagePurposeFacets() {
    const key = `${this._packageGroupKey}|${this.packages.length}`;
    if (key === pkgFacetsCacheKey) return pkgFacetsCacheVal;
    const facets = buildPurposeFacets(this.currentPackageBase);
    // A rail offering a single bucket filters nothing; hide it instead.
    pkgFacetsCacheVal = facets.length > 1 ? facets : [];
    pkgFacetsCacheKey = key;
    return pkgFacetsCacheVal;
  },

  get hasPackagePurposeFacets() {
    return this.packagePurposeFacets.length > 0;
  },

  // How completely the current tab describes its packages: gap counts per field
  // plus the full/partial/sparse split behind the rollup bar.
  get packageDescriptionSummary() {
    const key = `${this._packageGroupKey}|${this.packages.length}|${this.licenses.length}`;
    if (key === pkgSummaryCacheKey && pkgSummaryCacheVal) return pkgSummaryCacheVal;
    const licensed = this._licensedElementIds;
    pkgSummaryCacheVal = summarizePackageDescription(this.currentPackageBase, (p) =>
      licensed.has(p?.spdxId)
    );
    pkgSummaryCacheKey = key;
    return pkgSummaryCacheVal;
  },

  get packageFiltersActive() {
    return !!(this.packageSearch || this.pkgPurposeFilter || this.pkgGapFilter);
  },

  clearPackageFilters() {
    this.packageSearch = '';
    this.pkgPurposeFilter = '';
    this.pkgGapFilter = '';
    this.restreamView(this.currentView);
  },

  get currentPackageNoun() {
    return this.currentView === 'ai'
      ? 'AI models'
      : this.currentView === 'dataset'
        ? 'datasets'
        : 'packages';
  },

  get filteredFiles() {
    // Memoized on the only inputs that affect the result: the file list, the
    // search box, the type/directory filters, and the sort (see the cache note
    // above).
    const search = this.fileSearch;
    const typeFilter = this.fileTypeFilter;
    const dirFilter = this.fileDirFilter;
    const files = this.files;
    const key = `${files.length}|${search}|${typeFilter}|${dirFilter}|${this.fileSort}`;
    if (key === filteredFilesCacheKey) return filteredFilesCacheVal;

    let fs = files;
    if (search) {
      const q = search.toLowerCase();
      fs = fs.filter((f) => f.name?.toLowerCase().includes(q));
    }
    if (typeFilter === NO_EXT_LABEL) {
      fs = fs.filter((f) => !this.fileExt(f.name));
    } else if (typeFilter) {
      fs = fs.filter((f) => this.fileExt(f.name) === typeFilter);
    }
    if (dirFilter) {
      fs = fs.filter((f) => dirPrefix(f.name, FILE_DIR_FACET_DEPTH) === dirFilter);
    }
    const sorted =
      this.fileSort === 'size'
        ? [...fs].sort(
            (a, b) =>
              (Number(b.software_artifactSize) || 0) - (Number(a.software_artifactSize) || 0)
          )
        : [...fs].sort((a, b) => (a.name || '').localeCompare(b.name || ''));

    filteredFilesCacheKey = key;
    filteredFilesCacheVal = sorted;
    return sorted;
  },

  // Most populated directories in the file list, as filter facets. Computed over
  // the whole file list (not the filtered one) so the counts stay stable while
  // the user narrows down, and memoized because a rootfs SBOM makes this a scan
  // of hundreds of thousands of paths.
  get fileDirFacets() {
    const key = `${this.files.length}`;
    if (key === fileDirsCacheKey) return fileDirsCacheVal;
    const facets = buildDirectoryFacets(this.files, FILE_DIR_FACET_LIMIT, FILE_DIR_FACET_DEPTH);
    // A rail offering a single directory filters nothing; hide it instead.
    fileDirsCacheVal = facets.length > 1 ? facets : [];
    fileDirsCacheKey = key;
    return fileDirsCacheVal;
  },

  get hasFileDirFacets() {
    return this.fileDirFacets.length > 0;
  },

  get fileFiltersActive() {
    return !!(this.fileSearch || this.fileTypeFilter || this.fileDirFilter);
  },

  clearFileFilters() {
    this.fileSearch = '';
    this.fileTypeFilter = '';
    this.fileDirFilter = '';
    this.restreamView('files');
  },

  // Hardware elements filtered by the in-view search box (name, part number,
  // summary) and sorted by name.
  get filteredHardware() {
    const hardware = this.hardware;
    const key = `${hardware.length}|${this.hardwareSearch}`;
    if (key === filteredHardwareCacheKey) return filteredHardwareCacheVal;

    let hw = hardware;
    if (this.hardwareSearch) {
      const q = this.hardwareSearch.toLowerCase();
      hw = hw.filter(
        (h) =>
          (h.name || '').toLowerCase().includes(q) ||
          this.cleanName(h.spdxId).toLowerCase().includes(q) ||
          (h.hardware_partNumber || '').toLowerCase().includes(q) ||
          (h.summary || '').toLowerCase().includes(q)
      );
    }
    filteredHardwareCacheVal = [...hw].sort((a, b) =>
      (a.name || this.cleanName(a.spdxId)).localeCompare(b.name || this.cleanName(b.spdxId))
    );
    filteredHardwareCacheKey = key;
    return filteredHardwareCacheVal;
  },

  get supplyChainCounts() {
    if (scCountsSrc === this.supplyChain) return scCountsVal;
    const c = {
      actions: 0,
      processes: 0,
      states: 0,
      transports: 0,
      custody: 0,
      inspections: 0,
      tests: 0,
      exceptions: 0,
      resolutions: 0
    };
    this.supplyChain.forEach((el) => {
      const kind = this.supplyChainKind(el);
      if (kind === 'action') c.actions++;
      else if (kind === 'process') c.processes++;
      else if (kind === 'state') c.states++;
      if (isA(el.type, CLASS.supplychain_TransportAction)) c.transports++;
      if (isA(el.type, CLASS.supplychain_ResponsibilityChangeAction)) c.custody++;
      if (isA(el.type, CLASS.supplychain_InspectionAction)) c.inspections++;
      if (isA(el.type, CLASS.supplychain_TestAction)) c.tests++;
      const status = this.supplyChainExceptionStatus(el);
      if (status?.key === 'exception') c.exceptions++;
      if (status?.key === 'resolved') c.resolutions++;
    });
    scCountsVal = c;
    scCountsSrc = this.supplyChain;
    return c;
  },

  // Memoized on the source list: nearly every other supply-chain getter reads
  // this one, so without it a single render re-filters and re-sorts the whole
  // supply-chain list once per reader.
  get supplyChainActions() {
    if (scActionsSrc === this.supplyChain) return scActionsVal;
    scActionsVal = this.supplyChain
      .filter((el) => this.supplyChainKind(el) === 'action')
      .sort((a, b) => (a.startTime || '').localeCompare(b.startTime || ''));
    scActionsSrc = this.supplyChain;
    return scActionsVal;
  },

  // Timeline events: the actions that genuinely happen at a point in time.
  // StateActions are excluded here because they are the transitions of the
  // product state machine, which has its own States angle; keeping them out
  // leaves the timeline focused on the substantive supply-chain events.
  get supplyChainEvents() {
    return this.supplyChainActions.filter((el) => !isA(el.type, CLASS.supplychain_StateAction));
  },

  // Action families present among the timeline events, in phase order, each with
  // its count. Drives the timeline's filter chips (replacing the old
  // action/state/process kind chips, which mixed three different concepts).
  get supplyChainEventFamilies() {
    const order = ['create', 'modify', 'move', 'verify', 'exception', 'operate', 'other'];
    const counts = {};
    this.supplyChainEvents.forEach((el) => {
      const family = this.supplyChainFamily(el);
      counts[family] = (counts[family] || 0) + 1;
    });
    return order
      .filter((key) => counts[key])
      .map((key) => ({ key, label: this.supplyChainFamilyLabel(key), n: counts[key] }));
  },

  get supplyChainProcesses() {
    return this.supplyChain
      .filter((el) => this.supplyChainKind(el) === 'process')
      .sort((a, b) =>
        (a.name || this.cleanName(a.spdxId)).localeCompare(b.name || this.cleanName(b.spdxId))
      );
  },

  get supplyChainStates() {
    return this.supplyChain
      .filter((el) => this.supplyChainKind(el) === 'state')
      .sort((a, b) =>
        (a.name || this.cleanName(a.spdxId)).localeCompare(b.name || this.cleanName(b.spdxId))
      );
  },

  get supplyChainStateTransitions() {
    return this.supplyChainActions
      .filter((el) => isA(el.type, CLASS.supplychain_StateAction))
      .map((action, index, list) => ({
        action,
        index,
        previous: index > 0 ? this.elementMap.get(list[index - 1].supplychain_currentState) : null,
        state: this.elementMap.get(action.supplychain_currentState) || null,
        decisionProcess: this.elementMap.get(action.supplychain_decisionProcess) || null,
        status: this.supplyChainExceptionStatus(action)
      }));
  },

  get supplyChainCustodyHandoffs() {
    return this.supplyChainActions
      .filter((el) => isA(el.type, CLASS.supplychain_ResponsibilityChangeAction))
      .map((action) => ({
        action,
        previous: this.elementMap.get(action.supplychain_previous) || null,
        current: this.elementMap.get(action.supplychain_current) || null,
        product: this.elementMap.get(action.supplychain_responsibilityChangedOn) || null,
        category: action.supplychain_responsibilityCategory || '',
        location: this.elementMap.get(action.actionLocation) || null
      }));
  },

  get supplyChainTransportLegs() {
    return this.supplyChainActions
      .filter((el) => isA(el.type, CLASS.supplychain_TransportAction))
      .map((action) => ({
        action,
        pickup: this.elementMap.get(action.supplychain_pickupLocation) || null,
        dropoff: this.elementMap.get(action.supplychain_dropoffLocation) || null,
        route: action.supplychain_transportRoute || ''
      }));
  },

  get supplyChainTimelineRows() {
    const rows = this.filteredSupplyChain.map((item, index) => ({
      item,
      action: item,
      index,
      kind: this.supplyChainKind(item),
      family: this.supplyChainFamily(item),
      phase: this.supplyChainFamilyMeta(item).label,
      status: this.supplyChainExceptionStatus(item),
      duration: this.supplyChainDurationLabel(item),
      route: this.supplyChainRoute(item),
      state: this.supplyChainStateName(item),
      carbonKg: this.supplyChainCarbonKg(item),
      distanceKm: this.supplyChainDistanceKm(item),
      mode: this.supplyChainTransportMode(item),
      evidence: this.supplyChainEvidenceCount(item),
      time: item.startTime || item.endTime || ''
    }));
    // Day dividers and elapsed-time markers add breathing room and temporal
    // orientation to the chronological list. Computed over the filtered set so
    // gaps reflect only the events actually shown.
    let prevDay = null;
    let prevMs = null;
    for (const row of rows) {
      const ms = row.time ? Date.parse(row.time) : NaN;
      const day = Number.isFinite(ms) ? row.time.slice(0, 10) : null;
      row.newDay = Boolean(day) && day !== prevDay;
      row.dayLabel = row.newDay ? this.supplyChainDayHeading(row.time) : '';
      row.gapLabel =
        Number.isFinite(ms) && Number.isFinite(prevMs)
          ? this.supplyChainElapsedLabel(prevMs, ms)
          : '';
      row.stateChanges = [];
      if (Number.isFinite(ms)) {
        prevDay = day;
        prevMs = ms;
      }
    }
    // StateActions are otherwise hidden from the event list (they are the product
    // state machine's transitions), so it's easy to lose track of when the tracked
    // product changes state. Surface each transition inline, attached below the
    // last event that occurred at or before it, so the timeline shows exactly when
    // the product entered a new state.
    for (const step of this.supplyChainLifecycleSteps) {
      if (!rows.length) break;
      const stepMs = step.time ? Date.parse(step.time) : NaN;
      let target = null;
      if (Number.isFinite(stepMs)) {
        for (const row of rows) {
          const rowMs = row.time ? Date.parse(row.time) : NaN;
          if (Number.isFinite(rowMs) && rowMs <= stepMs) target = row;
        }
      }
      (target || rows[0]).stateChanges.push({
        spdxId: step.action.spdxId,
        name: step.name,
        tone: step.tone,
        time: step.time
      });
    }
    return rows;
  },

  get supplyChainCarbonSummary() {
    const rows = this.supplyChainActions
      .map((action) => ({
        action,
        kg: this.supplyChainCarbonKg(action),
        distanceKm: this.supplyChainDistanceKm(action),
        mode: this.supplyChainTransportMode(action),
        route: this.supplyChainRoute(action)
      }))
      .filter((row) => row.kg > 0);
    const totalKg = rows.reduce((total, row) => total + row.kg, 0);
    const maxKg = rows.reduce((max, row) => Math.max(max, row.kg), 0);
    return {
      rows: rows.map((row) => ({
        ...row,
        pct: maxKg ? Math.max(4, Math.round((row.kg / maxKg) * 100)) : 0
      })),
      totalKg,
      maxKg
    };
  },

  get supplyChainExceptionChains() {
    return this.supplyChainActions
      .filter((el) => isA(el.type, CLASS.supplychain_OutOfSpecAction))
      .map((exception) => {
        const seenResolutionIds = new Set();
        const resolutions = this.relationships
          .filter(
            (rel) =>
              (rel.relationshipType === 'resolved' || rel.relationshipType === 'hasResolution') &&
              (Array.isArray(rel.to) ? rel.to : [rel.to]).includes(exception.spdxId)
          )
          .map((rel) => this.elementMap.get(rel.from))
          .filter((resolution) => {
            if (!resolution || seenResolutionIds.has(resolution.spdxId)) return false;
            seenResolutionIds.add(resolution.spdxId);
            return true;
          });
        return {
          exception,
          resolutions,
          evidenceCount:
            this.supplyChainEvidenceCount(exception) +
            resolutions.reduce(
              (total, resolution) => total + this.supplyChainEvidenceCount(resolution),
              0
            )
        };
      });
  },

  get supplyChainActionLanes() {
    const lanes = [
      {
        key: 'create',
        label: 'Create / make',
        color: '#38bdf8',
        items: this.supplyChainActions.filter(
          (el) =>
            isA(el.type, CLASS.supplychain_CreateAction) ||
            isA(el.type, CLASS.supplychain_ManufactureAction) ||
            isA(el.type, CLASS.supplychain_AssemblyAction) ||
            isA(el.type, CLASS.supplychain_HarvestAction) ||
            isA(el.type, CLASS.supplychain_ReproduceAction)
        )
      },
      {
        key: 'move',
        label: 'Move / custody',
        color: '#22d3ee',
        items: this.supplyChainActions.filter(
          (el) =>
            isA(el.type, CLASS.supplychain_TransportAction) ||
            isA(el.type, CLASS.supplychain_StorageAction) ||
            isA(el.type, CLASS.supplychain_ResponsibilityChangeAction) ||
            isA(el.type, CLASS.supplychain_BoundaryCrossingAction)
        )
      },
      {
        key: 'verify',
        label: 'Inspect / test / decide',
        color: '#a78bfa',
        items: this.supplyChainActions.filter(
          (el) =>
            isA(el.type, CLASS.supplychain_InspectionAction) ||
            isA(el.type, CLASS.supplychain_TestAction) ||
            isA(el.type, CLASS.supplychain_StateAction)
        )
      },
      {
        key: 'exception',
        label: 'Exception / resolution',
        color: '#fb7185',
        items: this.supplyChainActions.filter(
          (el) =>
            isA(el.type, CLASS.supplychain_OutOfSpecAction) ||
            isA(el.type, CLASS.supplychain_ResolutionAction)
        )
      },
      {
        key: 'operate',
        label: 'Use / retire',
        color: '#34d399',
        items: this.supplyChainActions.filter(
          (el) =>
            isA(el.type, CLASS.supplychain_UseAction) ||
            isA(el.type, CLASS.supplychain_PlanAction) ||
            isA(el.type, CLASS.supplychain_DestroyAction)
        )
      }
    ];
    return lanes.filter((lane) => lane.items.length);
  },

  // Chain-of-custody relay: the ordered list of parties responsible for the
  // tracked product, each with the transport legs and checkpoints that happened
  // on their watch. Seeds the first holder from the earliest handoff's previous
  // party, then advances at each ResponsibilityChangeAction.
  get supplyChainCustodyJourney() {
    const handoffs = this.supplyChainCustodyHandoffs;
    const actions = this.supplyChainActions;
    if (!handoffs.length || !actions.length) return [];
    const firstTime = actions[0].startTime || actions[0].endTime || '';
    const last = actions[actions.length - 1];
    const lastTime = last.endTime || last.startTime || '';
    const points = [
      { holder: handoffs[0].previous, category: '', gainedVia: null, start: firstTime },
      ...handoffs.map((h) => ({
        holder: h.current,
        category: h.category,
        gainedVia: h,
        start: h.action.endTime || h.action.startTime || ''
      }))
    ];
    return points.map((p, i) => {
      const next = points[i + 1];
      const end = next ? next.gainedVia.action.startTime || next.start : lastTime;
      const inWindow = (a) => {
        const t = a.startTime || a.endTime || '';
        if (!t || t < p.start) return false;
        return next ? t < end : true;
      };
      const windowActions = actions.filter(inWindow);
      const legs = windowActions
        .filter((a) => isA(a.type, CLASS.supplychain_TransportAction))
        .map((a) => ({
          action: a,
          route: this.supplyChainRoute(a),
          mode: this.supplyChainTransportMode(a),
          distanceKm: this.supplyChainDistanceKm(a),
          carbonKg: this.supplyChainCarbonKg(a),
          duration: this.supplyChainDurationLabel(a)
        }));
      const checkpoints = windowActions
        .filter(
          (a) =>
            !isA(a.type, CLASS.supplychain_TransportAction) &&
            !isA(a.type, CLASS.supplychain_StateAction) &&
            !isA(a.type, CLASS.supplychain_ResponsibilityChangeAction) &&
            !isA(a.type, CLASS.supplychain_BoundaryDefinitionAction)
        )
        .map((a) => ({
          action: a,
          family: this.supplyChainFamily(a),
          meta: this.supplyChainFamilyMeta(a),
          status: this.supplyChainExceptionStatus(a)
        }));
      const startMs = Date.parse(p.start);
      const endMs = Date.parse(end);
      return {
        holder: p.holder,
        name: p.holder ? p.holder.name || this.cleanName(p.holder.spdxId) : 'Unassigned',
        summary: p.holder?.summary || '',
        role: i === 0 ? 'origin' : p.category || 'custody',
        gainedVia: p.gainedVia,
        handoffLocation: p.gainedVia
          ? this.supplyChainRefName(p.gainedVia.action.actionLocation)
          : '',
        start: p.start,
        end,
        duration: this.supplyChainElapsedLabel(startMs, endMs),
        legs,
        checkpoints,
        exceptions: checkpoints.filter((c) => c.status?.key === 'exception').length,
        distanceKm: legs.reduce((s, l) => s + (l.distanceKm || 0), 0),
        carbonKg: legs.reduce((s, l) => s + (l.carbonKg || 0), 0),
        index: i
      };
    });
  },

  // Product lifecycle as an ordered set of state transitions (StateActions), each
  // enriched with the state's meaning, when/where it happened, the decision
  // process that drove it, and a tone (positive / exception / neutral) for the
  // stepper node colour.
  get supplyChainLifecycleSteps() {
    return this.supplyChainStateTransitions.map((t) => {
      const name = t.state
        ? t.state.name || this.cleanName(t.state.spdxId)
        : this.supplyChainStateName(t.action) || '—';
      let tone = 'neutral';
      if (/quarantine|out.?of.?spec|reject|fail|hold/i.test(name)) tone = 'exception';
      else if (/accept|pass|deploy|resolv|complete|provision/i.test(name)) tone = 'positive';
      return {
        action: t.action,
        state: t.state,
        name,
        description: t.state?.description || t.state?.summary || '',
        time: t.action.startTime || t.action.endTime || '',
        location: this.supplyChainRefName(t.action.actionLocation),
        decisionProcess: t.decisionProcess
          ? t.decisionProcess.name || this.cleanName(t.decisionProcess.spdxId)
          : '',
        performers: this.supplyChainPerformerNames(t.action),
        evidence: this.supplyChainEvidenceCount(t.action),
        status: t.status,
        tone
      };
    });
  },

  // The product state machine as Mermaid stateDiagram-v2 source. Nodes follow
  // the StateAction trajectory (received -> ... -> deployed), transitions carry
  // their decision process as a label, and exception / positive states get a
  // themed class. Rendered lazily by renderSupplyChainStateDiagram().
  get supplyChainStateMermaid() {
    const steps = this.supplyChainLifecycleSteps;
    if (!steps.length) return '';
    // Not HTML escaping: these characters are what break stateDiagram-v2 label
    // syntax, so they are stripped rather than turned into entities (Mermaid
    // would render an entity literally).
    const mermaidLabel = (value) =>
      String(value || '')
        .replace(/[:<>"\n\r]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
    const lines = [
      'stateDiagram-v2',
      // Every state is explicitly classed: Mermaid's base theme leaves the
      // default state label the same tone as the node fill, which is unreadable
      // on the dark surface, so even neutral states carry an explicit colour.
      'classDef neutral fill:#1e293b,stroke:#475569,color:#e2e8f0',
      'classDef exception fill:#4c0519,stroke:#fb7185,color:#fecdd3',
      'classDef positive fill:#053e30,stroke:#34d399,color:#a7f3d0',
      '[*] --> s0'
    ];
    steps.forEach((step, i) => lines.push(`s${i} : ${mermaidLabel(step.name) || 'State'}`));
    steps.forEach((step, i) => {
      if (i === 0) return;
      const label = mermaidLabel((step.decisionProcess || '').replace(/\s*process$/i, ''));
      lines.push(label ? `s${i - 1} --> s${i} : ${label}` : `s${i - 1} --> s${i}`);
    });
    lines.push(`s${steps.length - 1} --> [*]`);
    steps.forEach((step, i) => {
      const cls =
        step.tone === 'exception' ? 'exception' : step.tone === 'positive' ? 'positive' : 'neutral';
      lines.push(`class s${i} ${cls}`);
    });
    return lines.join('\n');
  },

  // Defined processes (the plans) grouped by lifecycle phase, for the Processes
  // playbook. Each process keeps the actions that executed it so the plan ->
  // doing relationship stays visible.
  get supplyChainProcessGroups() {
    const order = ['create', 'modify', 'move', 'verify', 'operate', 'process', 'other'];
    const groups = new Map();
    this.supplyChainProcesses.forEach((proc) => {
      const key = this.supplyChainFamily(proc);
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(proc);
    });
    return order
      .filter((key) => groups.has(key))
      .map((key) => ({
        key,
        label: this.supplyChainFamilyLabel(key),
        processes: groups.get(key)
      }));
  },

  // Route map geometry: ordered stops (transport pickup/dropoff spine plus any
  // other action locations) projected onto an equirectangular viewBox, with the
  // transport legs as bowed connectors coloured by mode. Falls back to a
  // schematic left-to-right layout when fewer than two stops can be geocoded.
  get supplyChainRouteMap() {
    const legs = this.supplyChainTransportLegs;
    const actions = this.supplyChainActions;
    // Distinct places, keyed by city (so several facilities in one city collapse
    // to a single pin even when their geographicPointLocation coordinates
    // differ), falling back to coordinate or id. The route follows the tracked
    // product's handling, so component-origin (create/manufacture/harvest)
    // locations are left off the route; they belong to the custody and timeline
    // angles.
    const placeKey = (loc) => {
      const c = this.supplyChainGeocode(loc);
      const city = String(loc.city || '')
        .trim()
        .toLowerCase();
      const key = city
        ? `${city}|${String(loc.country || '').toLowerCase()}`
        : c
          ? `${c.lat},${c.lng}`
          : loc.spdxId;
      return { key, coord: c };
    };
    const spdxToKey = new Map();
    const keyInfo = new Map();
    const keyOrder = [];
    const consider = (loc) => {
      if (!loc) return;
      const { key, coord } = placeKey(loc);
      spdxToKey.set(loc.spdxId, key);
      if (!keyInfo.has(key)) {
        keyInfo.set(key, { loc, coord });
        keyOrder.push(key);
      }
    };
    for (const leg of legs) {
      consider(leg.pickup);
      consider(leg.dropoff);
    }
    for (const a of actions) {
      if (this.supplyChainFamily(a) === 'create') continue;
      consider(this.elementMap.get(a.actionLocation));
    }
    if (!keyOrder.length) {
      return { stops: [], connectors: [], projected: false, viewBox: '0 0 1000 460' };
    }
    // Order pins by when the product first reaches each place.
    const timeByKey = new Map();
    for (const a of actions) {
      if (this.supplyChainFamily(a) === 'create') continue;
      const loc = this.elementMap.get(a.actionLocation);
      if (!loc) continue;
      const key = spdxToKey.get(loc.spdxId);
      const t = a.startTime || a.endTime || '';
      if (t && (!timeByKey.has(key) || t < timeByKey.get(key))) timeByKey.set(key, t);
    }
    const geo = keyOrder
      .map((key) => ({ key, ...keyInfo.get(key) }))
      .sort((a, b) => {
        const ta = timeByKey.get(a.key) || '';
        const tb = timeByKey.get(b.key) || '';
        if (ta && tb) return ta.localeCompare(tb);
        if (ta) return -1;
        if (tb) return 1;
        return 0;
      });

    const W = 1000;
    const H = 460;
    const padX = 90;
    const padY = 70;
    const geocoded = geo.filter((g) => g.coord);
    const projected = geocoded.length >= 2;

    let placed;
    if (projected) {
      const lats = geocoded.map((g) => g.coord.lat);
      const lngs = geocoded.map((g) => g.coord.lng);
      let minLat = Math.min(...lats);
      let maxLat = Math.max(...lats);
      let minLng = Math.min(...lngs);
      let maxLng = Math.max(...lngs);
      const latPad = Math.max(0.5, (maxLat - minLat) * 0.14);
      const lngPad = Math.max(0.5, (maxLng - minLng) * 0.14);
      minLat -= latPad;
      maxLat += latPad;
      minLng -= lngPad;
      maxLng += lngPad;
      const project = (c) => ({
        x: padX + ((c.lng - minLng) / (maxLng - minLng)) * (W - 2 * padX),
        y: padY + ((maxLat - c.lat) / (maxLat - minLat)) * (H - 2 * padY)
      });
      placed = geo.map((g, i) =>
        g.coord
          ? { key: g.key, loc: g.loc, ...project(g.coord), geocoded: true }
          : {
              key: g.key,
              loc: g.loc,
              x: padX + (i / Math.max(1, geo.length - 1)) * (W - 2 * padX),
              y: H / 2,
              geocoded: false
            }
      );
    } else {
      placed = geo.map((g, i) => ({
        key: g.key,
        loc: g.loc,
        x: padX + (i / Math.max(1, geo.length - 1)) * (W - 2 * padX),
        y: H / 2 + (i % 2 ? 30 : -30),
        geocoded: false
      }));
    }

    const posByKey = new Map(placed.map((p) => [p.key, p]));
    const stops = placed.map((p, i) => ({
      spdxId: p.loc.spdxId,
      x: Number(p.x.toFixed(1)),
      y: Number(p.y.toFixed(1)),
      order: i + 1,
      geocoded: p.geocoded,
      name: p.loc.name || this.cleanName(p.loc.spdxId),
      place: this.supplyChainPlaceLabel(p.loc),
      role: this.supplyChainStopRole(p.loc)
    }));

    const connectors = legs
      .map((leg) => {
        const a = leg.pickup ? posByKey.get(spdxToKey.get(leg.pickup.spdxId)) : null;
        const b = leg.dropoff ? posByKey.get(spdxToKey.get(leg.dropoff.spdxId)) : null;
        if (!a || !b) return null;
        const mx = (a.x + b.x) / 2;
        const my = (a.y + b.y) / 2;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const len = Math.hypot(dx, dy) || 1;
        const bow = Math.min(90, len * 0.24);
        const cx = mx + (-dy / len) * bow;
        const cy = my + (dx / len) * bow;
        return {
          id: leg.action.spdxId,
          action: leg.action,
          d: `M ${a.x.toFixed(1)} ${a.y.toFixed(1)} Q ${cx.toFixed(1)} ${cy.toFixed(1)} ${b.x.toFixed(1)} ${b.y.toFixed(1)}`,
          labelX: Number(cx.toFixed(1)),
          labelY: Number(cy.toFixed(1)),
          mode: this.supplyChainTransportMode(leg.action),
          color: this.supplyChainModeColor(this.supplyChainTransportMode(leg.action)),
          distanceKm: this.supplyChainDistanceKm(leg.action),
          carbonKg: this.supplyChainCarbonKg(leg.action),
          route: leg.route
        };
      })
      .filter(Boolean);

    return {
      stops,
      connectors,
      projected,
      viewBox: `0 0 ${W} ${H}`,
      totalDistanceKm: connectors.reduce((s, c) => s + (c.distanceKm || 0), 0),
      totalCarbonKg: connectors.reduce((s, c) => s + (c.carbonKg || 0), 0)
    };
  },

  // The route map as a self-contained SVG string for x-html. Kept a string (not
  // inline template markup) because Alpine's <template x-for> is illegal inside
  // <svg> foreign content. Stops/legs carry data-sc-* ids for delegated clicks.
  get supplyChainRouteMapSvg() {
    const map = this.supplyChainRouteMap;
    if (!map.stops.length) return '';
    const km = (v) => `${Math.round(v).toLocaleString()} km`;
    const grid =
      [92, 184, 276, 368].map((y) => `<line x1="0" y1="${y}" x2="1000" y2="${y}"/>`).join('') +
      [200, 400, 600, 800].map((x) => `<line x1="${x}" y1="0" x2="${x}" y2="460"/>`).join('');
    const conns = map.connectors
      .map((c) => {
        const label = this.formatCarbonKg(c.carbonKg) || (c.distanceKm ? km(c.distanceKm) : c.mode);
        return (
          `<path d="${c.d}" fill="none" stroke="${c.color}" stroke-width="2.5" stroke-linecap="round" class="sc-flow" opacity="0.9"/>` +
          `<g class="cursor-pointer" data-sc-action="${escapeHtml(c.action.spdxId)}">` +
          `<rect x="${c.labelX - 36}" y="${c.labelY - 10}" width="72" height="18" rx="9" fill="#0f172a" stroke="#334155"/>` +
          `<text x="${c.labelX}" y="${c.labelY + 3}" text-anchor="middle" font-size="10" font-weight="600" fill="${c.color}">${escapeHtml(label)}</text></g>`
        );
      })
      .join('');
    const stops = map.stops
      .map(
        (s) =>
          `<g class="cursor-pointer" data-sc-loc="${escapeHtml(s.spdxId)}">` +
          `<circle cx="${s.x}" cy="${s.y}" r="12" fill="none" stroke="${s.role.color}" stroke-width="1" opacity="0.4"/>` +
          `<circle cx="${s.x}" cy="${s.y}" r="6.5" fill="${s.role.color}" stroke="#0b1220" stroke-width="2"/>` +
          `<text x="${s.x}" y="${s.y - 16}" text-anchor="middle" font-size="11.5" font-weight="600" fill="#e2e8f0">${escapeHtml(s.place || s.name)}</text>` +
          `<text x="${s.x}" y="${s.y + 23}" text-anchor="middle" font-size="9.5" fill="${s.role.color}">${escapeHtml(`#${s.order} · ${s.role.label}`)}</text></g>`
      )
      .join('');
    return (
      `<svg viewBox="${map.viewBox}" class="w-full block" preserveAspectRatio="xMidYMid meet" style="aspect-ratio:1000/460">` +
      `<rect x="0" y="0" width="1000" height="460" fill="#0b1220"/>` +
      `<g stroke="#152033" stroke-width="1">${grid}</g>${conns}${stops}</svg>`
    );
  },

  get filteredSupplyChain() {
    const events = this.supplyChainEvents;
    const key = `${events.length}|${this.supplyChainFamilyFilter}|${this.supplyChainExceptionFilter}|${this.supplyChainSearch}`;
    if (key === filteredSupplyChainCacheKey) return filteredSupplyChainCacheVal;

    let items = events;
    if (this.supplyChainFamilyFilter) {
      items = items.filter((el) => this.supplyChainFamily(el) === this.supplyChainFamilyFilter);
    }
    if (this.supplyChainExceptionFilter) {
      items = items.filter(
        (el) => this.supplyChainExceptionStatus(el)?.key === this.supplyChainExceptionFilter
      );
    }
    if (this.supplyChainSearch) {
      const q = this.supplyChainSearch.toLowerCase();
      items = items.filter(
        (el) =>
          (el.name || '').toLowerCase().includes(q) ||
          this.cleanName(el.spdxId).toLowerCase().includes(q) ||
          (el.description || '').toLowerCase().includes(q) ||
          (el.summary || '').toLowerCase().includes(q) ||
          (el.supplychain_transportRoute || '').toLowerCase().includes(q) ||
          this.supplyChainTypeLabel(el).toLowerCase().includes(q)
      );
    }
    filteredSupplyChainCacheVal = [...items].sort((a, b) => {
      const at = a.startTime || a.endTime || '';
      const bt = b.startTime || b.endTime || '';
      if (at && !bt) return -1;
      if (!at && bt) return 1;
      if (at && bt) {
        return (
          at.localeCompare(bt) ||
          this.supplyChainTypeLabel(a).localeCompare(this.supplyChainTypeLabel(b))
        );
      }
      return (a.name || this.cleanName(a.spdxId)).localeCompare(b.name || this.cleanName(b.spdxId));
    });
    filteredSupplyChainCacheKey = key;
    return filteredSupplyChainCacheVal;
  },

  // Breakdown of the functional-safety elements by kind, for the tab header
  // summary and to decide which kind-filter chips to show.
  get safetyCounts() {
    if (safetyCountsSrc === this.requirements) return safetyCountsVal;
    const c = { requirements: 0, verifications: 0, assumptions: 0, evaluations: 0 };
    this.requirements.forEach((r) => {
      if (isA(r.type, CLASS.Requirement)) c.requirements++;
      else if (isA(r.type, CLASS.functionalsafety_RequirementVerification)) c.verifications++;
      else if (isA(r.type, CLASS.functionalsafety_Assumption)) c.assumptions++;
      else if (isA(r.type, CLASS.functionalsafety_EvaluationResult)) c.evaluations++;
    });
    safetyCountsVal = c;
    safetyCountsSrc = this.requirements;
    return c;
  },

  // Rollup of every Requirement's overall verification outcome, for the
  // safety-case meter and status-filter chips. `passPct` is the share that fully
  // passed; `verifiedPct` is the share that has any verification link (passed +
  // has-verification + inconclusive + failed).
  get safetyStatusSummary() {
    if (safetyStatusSrc === this.requirements) return safetyStatusVal;
    const counts = { failed: 0, inconclusive: 0, unverified: 0, verified: 0, passed: 0 };
    let total = 0;
    this.requirements.forEach((r) => {
      if (!isA(r.type, CLASS.Requirement)) return;
      // A system requirement is refined into software ones, never verified
      // directly, so counting it here would report a structural fact as a gap.
      // Without the producer's requirement-level identifier nothing is skipped
      // and this behaves exactly as before.
      if (this.requirementLevel(r) === 'system') return;
      total++;
      const status = this.requirementSafetyStatus(r);
      if (status && Object.hasOwn(counts, status.key)) counts[status.key]++;
    });
    const withVerification = total - counts.unverified;
    safetyStatusVal = {
      total,
      counts,
      passPct: total ? Math.round((counts.passed / total) * 100) : 0,
      verifiedPct: total ? Math.round((withVerification / total) * 100) : 0
    };
    safetyStatusSrc = this.requirements;
    return safetyStatusVal;
  },

  // "True traceability" adequacy of every Requirement carrying an adequacy
  // verdict. Empty (`total: 0`) for an SBOM whose producer recorded none, which
  // keeps the whole chip row hidden rather than showing a row of zeroes.
  get safetyAdequacySummary() {
    if (safetyAdequacySrc === this.requirements) return safetyAdequacyVal;
    const counts = {};
    let total = 0;
    this.requirements.forEach((r) => {
      const key = this.requirementAdequacyKey(r);
      if (!key) return;
      counts[key] = (counts[key] || 0) + 1;
      total++;
    });
    const exercised = counts.true || 0;
    safetyAdequacyVal = {
      total,
      counts,
      exercised,
      exercisedPct: total ? Math.round((exercised / total) * 100) : 0
    };
    safetyAdequacySrc = this.requirements;
    return safetyAdequacyVal;
  },

  // Adequacy verdicts that actually occur, gaps-first.
  get safetyAdequacyOrder() {
    const counts = this.safetyAdequacySummary.counts;
    return Object.keys(SAFETY_ADEQUACY)
      .filter((k) => counts[k] > 0)
      .sort((a, b) => SAFETY_ADEQUACY[b].rank - SAFETY_ADEQUACY[a].rank);
  },

  // The meters run healthy-first, the chips gaps-first: the meter's leading edge
  // then lands on the headline percentage, while the chips keep the order of the
  // list they filter.
  get safetyStatusMeterOrder() {
    return [...this.safetyStatusOrder].reverse();
  },

  get safetyAdequacyMeterOrder() {
    return [...this.safetyAdequacyOrder].reverse();
  },

  // Verification statuses that actually occur, gaps-first, so the rollup bar and
  // chips never render empty buckets.
  get safetyStatusOrder() {
    const order = ['failed', 'inconclusive', 'unverified', 'verified', 'passed'];
    const counts = this.safetyStatusSummary.counts;
    return order.filter((s) => counts[s] > 0);
  },

  // Specification facets from Specification --hasRequirement--> Requirement.
  // Empty when the SBOM has no such links (facet UI stays hidden).
  get safetySpecFacets() {
    if (
      safetySpecFacetsRelsSrc === this.relationships &&
      safetySpecFacetsReqsSrc === this.requirements
    ) {
      return safetySpecFacetsVal;
    }
    const reqIds = new Set();
    this.requirements.forEach((r) => {
      if (isA(r.type, CLASS.Requirement)) reqIds.add(r.spdxId);
    });
    safetySpecFacetsVal = buildSafetySpecFacets(
      this.relationships,
      this.elementMap,
      isA,
      CLASS.Specification,
      reqIds
    );
    safetySpecFacetsRelsSrc = this.relationships;
    safetySpecFacetsReqsSrc = this.requirements;
    return safetySpecFacetsVal;
  },

  get hasSafetySpecFacets() {
    return this.safetySpecFacets.length > 0;
  },

  // Requirement ids belonging to the active specification facet (or null = all).
  get safetySpecMemberIds() {
    if (!this.requirementSpecFilter) return null;
    const facet = this.safetySpecFacets.find((f) => f.id === this.requirementSpecFilter);
    return facet ? new Set(facet.requirementIds) : null;
  },

  // Requirement decomposition graph from `tracedToDetail` relationships
  // (higher-level requirement -> more detailed requirements). Requirements never
  // appearing as a child become roots, so isolated requirements still show. Only
  // Requirement-typed endpoints are kept (verifications/assumptions are excluded).
  get safetyDecomposition() {
    if (safetyDecompRelsSrc === this.relationships && safetyDecompReqsSrc === this.requirements) {
      return safetyDecompVal;
    }
    const reqIds = new Set();
    this.requirements.forEach((r) => {
      if (isA(r.type, CLASS.Requirement)) reqIds.add(r.spdxId);
    });
    const childrenOf = new Map();
    const isChild = new Set();
    this.relationships.forEach((rel) => {
      if (rel.relationshipType !== 'tracedToDetail' || !reqIds.has(rel.from)) return;
      const tos = (Array.isArray(rel.to) ? rel.to : [rel.to]).filter((t) => reqIds.has(t));
      if (!tos.length) return;
      const kids = childrenOf.get(rel.from) || [];
      tos.forEach((t) => {
        if (!kids.includes(t)) kids.push(t);
        isChild.add(t);
      });
      childrenOf.set(rel.from, kids);
    });
    const roots = [...reqIds].filter((id) => !isChild.has(id));
    safetyDecompVal = { childrenOf, roots, hasDecomposition: childrenOf.size > 0 };
    safetyDecompRelsSrc = this.relationships;
    safetyDecompReqsSrc = this.requirements;
    return safetyDecompVal;
  },

  get hasSafetyDecomposition() {
    return this.safetyDecomposition.hasDecomposition;
  },

  // Whether a Requirement matches the active status / no-impl / search filters
  // used by both the list and the decomposition tree.
  _requirementMatchesSafetyFilters(r) {
    if (!r || !isA(r.type, CLASS.Requirement)) return false;
    const members = this.safetySpecMemberIds;
    if (members && !members.has(r.spdxId)) return false;
    if (this.requirementStatusFilter) {
      if (this.requirementLevel(r) === 'system') return false;
      if (this.requirementSafetyStatus(r)?.key !== this.requirementStatusFilter) return false;
    }
    if (
      this.requirementAdequacyFilter &&
      this.requirementAdequacyKey(r) !== this.requirementAdequacyFilter
    ) {
      return false;
    }
    if (this.requirementSearch) {
      const q = this.requirementSearch.toLowerCase();
      const hay = [
        r.name,
        this.requirementDisplayName(r),
        this.cleanName(r.spdxId),
        r.requirementStatement,
        r.functionalsafety_assumptionStatement,
        r.summary,
        ...this.externalIdentifiers(r).map((eid) => eid.identifier)
      ]
        .filter(Boolean)
        .join('\n')
        .toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  },

  // Flattened, depth-annotated rows of the decomposition tree honoring
  // collapsedReqs and the active safety filters. Ancestors of matching leaves
  // stay visible so the hierarchy remains readable. Siblings sort by display
  // name; a cycle guard stops a malformed graph looping.
  get safetyTreeRows() {
    const decomposition = this.safetyDecomposition;
    // collapsedReqs is reassigned rather than mutated (see toggleReqCollapse),
    // so its identity is a sound cache key alongside the safety filters.
    const collapsed = this.collapsedReqs;
    const key = `${this.requirements.length}|${this.requirementSearch}|${this.requirementStatusFilter}|${this.requirementAdequacyFilter}|${this.requirementSpecFilter}`;
    if (
      safetyTreeCacheKey &&
      safetyTreeCacheKey.key === key &&
      safetyTreeCacheKey.decomposition === decomposition &&
      safetyTreeCacheKey.collapsed === collapsed
    ) {
      return safetyTreeCacheVal;
    }

    const { childrenOf, roots } = decomposition;
    const nameOf = (id) =>
      this.requirementDisplayName(this.elementMap.get(id)) ||
      this.elementMap.get(id)?.name ||
      this.cleanName(id);
    const sortIds = (ids) =>
      [...ids].sort((a, b) => nameOf(a).localeCompare(nameOf(b), undefined, { numeric: true }));

    const matchCache = new Map();
    const selfMatches = (id) => {
      if (matchCache.has(id)) return matchCache.get(id);
      const el = this.elementMap.get(id);
      const ok = this._requirementMatchesSafetyFilters(el);
      matchCache.set(id, ok);
      return ok;
    };
    const subtreeMatches = (id, ancestry) => {
      if (ancestry.has(id)) return false;
      if (selfMatches(id)) return true;
      const next = new Set(ancestry).add(id);
      return (childrenOf.get(id) || []).some((k) => subtreeMatches(k, next));
    };

    const rows = [];
    const visit = (id, depth, ancestry) => {
      if (ancestry.has(id)) return;
      if (!subtreeMatches(id, ancestry)) return;
      const kids = childrenOf.get(id) || [];
      const visibleKids = sortIds(kids).filter((k) => subtreeMatches(k, new Set(ancestry).add(id)));
      const isCollapsed = !!collapsed[id];
      const el = this.elementMap.get(id);
      rows.push({
        id,
        el,
        depth,
        hasChildren: visibleKids.length > 0,
        childCount: visibleKids.length,
        collapsed: isCollapsed,
        cue: this.requirementQuietCue(el)
      });
      if (visibleKids.length && !isCollapsed) {
        const next = new Set(ancestry).add(id);
        visibleKids.forEach((k) => visit(k, depth + 1, next));
      }
    };
    sortIds(roots).forEach((r) => visit(r, 0, new Set()));

    safetyTreeCacheKey = { key, decomposition, collapsed };
    safetyTreeCacheVal = rows;
    return rows;
  },

  get filteredRequirements() {
    const requirements = this.requirements;
    const key = `${requirements.length}|${this.requirementKindFilter}|${this.requirementStatusFilter}|${this.requirementAdequacyFilter}|${this.requirementSpecFilter}|${this.requirementSearch}|${this.requirementSort}`;
    if (key === filteredReqsCacheKey) return filteredReqsCacheVal;

    let reqs = requirements;
    // Kind filter chips (all / requirements / verifications / assumptions /
    // evaluations) let the folded-in artifacts be browsed on their own.
    if (this.requirementKindFilter) {
      reqs = reqs.filter((r) => r.type === this.requirementKindFilter);
    }
    // Status / spec / search apply to Requirements. Other kinds only respect
    // search (and kind), so kind × outcome stay orthogonal without forcing
    // kind=Requirement when a status chip is clicked.
    const members = this.safetySpecMemberIds;
    if (
      members ||
      this.requirementStatusFilter ||
      this.requirementAdequacyFilter ||
      this.requirementSearch
    ) {
      reqs = reqs.filter((r) => {
        if (isA(r.type, CLASS.Requirement)) return this._requirementMatchesSafetyFilters(r);
        if (this.requirementStatusFilter || this.requirementAdequacyFilter || members) return false;
        if (!this.requirementSearch) return true;
        const q = this.requirementSearch.toLowerCase();
        return (
          (r.name || '').toLowerCase().includes(q) ||
          this.cleanName(r.spdxId).toLowerCase().includes(q) ||
          (r.summary || '').toLowerCase().includes(q) ||
          (r.description || '').toLowerCase().includes(q) ||
          this.externalIdentifiers(r).some((eid) => eid.identifier.toLowerCase().includes(q))
        );
      });
    }
    const rank = (r) => (r.type === CLASS.Requirement ? 0 : 1);
    const label = (r) => this.requirementDisplayName(r) || r.name || this.cleanName(r.spdxId);
    // Requirements first, then worst-first unless the reader asked for A-Z.
    const attention =
      this.requirementSort === 'attention'
        ? (a, b) => this.requirementAttentionRank(a) - this.requirementAttentionRank(b)
        : () => 0;
    filteredReqsCacheVal = [...reqs].sort(
      (a, b) => rank(a) - rank(b) || attention(a, b) || label(a).localeCompare(label(b))
    );
    filteredReqsCacheKey = key;
    return filteredReqsCacheVal;
  },

  get filteredLicenses() {
    const licenses = this.licenses;
    const key = `${licenses.length}|${this.licenseSearch}|${this.licenseSort}`;
    if (key === filteredLicensesCacheKey) return filteredLicensesCacheVal;

    let lics = licenses;
    if (this.licenseSearch) {
      const q = this.licenseSearch.toLowerCase();
      lics = lics.filter(
        (l) => (l.label || '').toLowerCase().includes(q) || (l.id || '').toLowerCase().includes(q)
      );
    }
    filteredLicensesCacheVal =
      this.licenseSort === 'name'
        ? [...lics].sort((a, b) => (a.label || '').localeCompare(b.label || ''))
        : [...lics].sort(
            (a, b) => b.userCount - a.userCount || (a.label || '').localeCompare(b.label || '')
          );
    filteredLicensesCacheKey = key;
    return filteredLicensesCacheVal;
  },

  // Vulnerabilities filtered by the search box + status filter, then sorted.
  // Memoized on those inputs so unrelated reactive changes don't re-sort.
  get filteredVulnerabilities() {
    const search = this.securitySearch;
    const sort = this.securitySort;
    const statusFilter = this.securityStatusFilter;
    const severityFilter = this.securitySeverityFilter;
    const sourceFilter = this.securitySourceFilter;
    const vulns = this.allVulnerabilities;
    const key = `${vulns.length}|${this.onlineVulns.length}|${this.onlineSync.ranAt}|${search}|${sort}|${statusFilter}|${severityFilter}|${sourceFilter}`;
    if (key === filteredVulnsCacheKey) return filteredVulnsCacheVal;

    let list = vulns;
    if (search) {
      const q = search.toLowerCase();
      list = list.filter((v) => {
        if (v.name.toLowerCase().includes(q)) return true;
        return v.assessments.some(
          (a) =>
            this.relTargetDisplayName(a.packageId).toLowerCase().includes(q) ||
            (a.impactStatement || '').toLowerCase().includes(q) ||
            (a.actionStatement || '').toLowerCase().includes(q)
        );
      });
    }
    if (statusFilter) {
      list = list.filter((v) =>
        statusFilter === 'unknown' ? v.overallStatus === 'unknown' : v.statusCounts[statusFilter]
      );
    }
    // Ignore a stale severity filter when the loaded SBOM carries no CVSS data
    // (the severity chips are hidden then, so an invisible filter would just
    // strip the whole list).
    if (severityFilter && this.hasCvssData) {
      list = list.filter((v) => v.severity === severityFilter);
    }
    // Provenance filter: 'sbom' = anything the document already carried
    // (sbom + both); 'online' = anything OSV reported (online + both).
    if (sourceFilter === 'sbom') {
      list = list.filter((v) => v.source !== 'online');
    } else if (sourceFilter === 'online') {
      list = list.filter((v) => v.source === 'online' || v.source === 'both');
    }

    const sev = { affected: 4, under_investigation: 3, not_affected: 2, fixed: 1, unknown: 0 };
    const sorted = [...list];
    if (sort === 'cvss') {
      sorted.sort(
        (a, b) =>
          b.severityRank - a.severityRank ||
          (b.cvss?.score ?? -1) - (a.cvss?.score ?? -1) ||
          b.packageCount - a.packageCount ||
          b.name.localeCompare(a.name, undefined, { numeric: true })
      );
    } else if (sort === 'cve') {
      sorted.sort((a, b) => b.name.localeCompare(a.name, undefined, { numeric: true }));
    } else if (sort === 'packages') {
      sorted.sort((a, b) => b.packageCount - a.packageCount || a.name.localeCompare(b.name));
    } else {
      // severity: most concerning first, then most-affected, then CVE id
      sorted.sort(
        (a, b) =>
          (sev[b.overallStatus] || 0) - (sev[a.overallStatus] || 0) ||
          b.packageCount - a.packageCount ||
          b.name.localeCompare(a.name, undefined, { numeric: true })
      );
    }

    filteredVulnsCacheKey = key;
    filteredVulnsCacheVal = sorted;
    return sorted;
  },

  // Status breakdown across all vulnerabilities, for the dashboard + security
  // header. Counts each vulnerability once by its overall (most severe) status.
  get securitySummary() {
    const all = this.allVulnerabilities;
    if (securitySummarySrc === all) return securitySummaryVal;
    const counts = { fixed: 0, not_affected: 0, affected: 0, under_investigation: 0, unknown: 0 };
    let sbomOnly = 0;
    let onlineOnly = 0;
    let both = 0;
    all.forEach((v) => {
      counts[v.overallStatus] = (counts[v.overallStatus] || 0) + 1;
      if (v.source === 'online') onlineOnly++;
      else if (v.source === 'both') both++;
      else sbomOnly++;
    });
    securitySummaryVal = {
      total: all.length,
      counts,
      // Provenance rollup: sbomTotal = carried by the document, onlineTotal =
      // reported by OSV (both overlap on `both`), newOnline = OSV-only.
      sbomTotal: sbomOnly + both,
      onlineTotal: onlineOnly + both,
      newOnline: onlineOnly,
      both
    };
    securitySummarySrc = all;
    return securitySummaryVal;
  },

  // Ordered list of statuses that actually occur, for rendering summary chips
  // and the status filter without showing empty buckets.
  get securityStatusOrder() {
    const order = ['affected', 'under_investigation', 'not_affected', 'fixed', 'unknown'];
    const counts = this.securitySummary.counts;
    return order.filter((s) => counts[s] > 0);
  },

  // True when at least one vulnerability carries an in-SBOM CVSS severity, so the
  // severity histogram/filter/badges only appear when there's data behind them.
  get hasCvssData() {
    if (hasCvssSrc === this.allVulnerabilities) return hasCvssVal;
    hasCvssSrc = this.allVulnerabilities;
    hasCvssVal = hasCvssSrc.some((v) => v.severity);
    return hasCvssVal;
  },

  // CVSS-severity histogram across all scored vulnerabilities, counted once each
  // by their headline severity. `scored` is the total that carry a CVSS band.
  get securitySeveritySummary() {
    const all = this.allVulnerabilities;
    if (severitySummarySrc === all) return severitySummaryVal;
    const counts = { critical: 0, high: 0, medium: 0, low: 0, none: 0 };
    let scored = 0;
    all.forEach((v) => {
      // Only count the standard bands the chips/bar can render, so `scored`
      // never diverges from what the UI shows.
      if (!Object.hasOwn(counts, v.severity)) return;
      counts[v.severity]++;
      scored++;
    });
    severitySummaryVal = { scored, counts };
    severitySummarySrc = all;
    return severitySummaryVal;
  },

  // Severity bands that actually occur, most-severe first, for the chips and bar.
  get securitySeverityOrder() {
    const order = ['critical', 'high', 'medium', 'low', 'none'];
    const counts = this.securitySeveritySummary.counts;
    return order.filter((s) => counts[s] > 0);
  },

  // The subset of graph legend entries whose type is actually present in the
  // loaded data — so an SBOM without VEX/tools/builds/etc. doesn't show a long
  // legend full of toggles that would draw nothing.
  get visibleGraphFilters() {
    const nodeTypes = new Set(this.presentNodeTypes);
    const relTypes = new Set(this.presentRelTypes);
    // An online scan can add vulnerability nodes + `affects` edges the SBOM alone
    // had none of, so surface those toggles once virtual vulns exist.
    if (this.virtualVexRelationships.length) {
      nodeTypes.add('vulnerability');
      relTypes.add('affects');
    }
    // Inferred vuln -> file edges add a Files-linking toggle (and need the
    // vulnerability node type) that the SBOM's own relationship set never has.
    if (this.affectedFileRelationships.length) {
      nodeTypes.add('vulnerability');
      relTypes.add('affectsFile');
    }
    return this.graphFilters.filter((f) => (f.isRel ? relTypes.has(f.key) : nodeTypes.has(f.key)));
  },

  // Lifecycle-scope legend entries for the scopes actually present in the data
  // (empty when the SBOM has no scoped relationships, which hides the row).
  get visibleScopeFilters() {
    const scopes = new Set(this.presentScopes);
    return this.scopeFilters.filter((f) => scopes.has(f.key));
  },

  get filteredConfigs() {
    const buildConfigs = this.buildConfigs;
    const key = `${buildConfigs.length}|${this.configSearch}`;
    if (key === filteredConfigsCacheKey) return filteredConfigsCacheVal;

    let cfgs = buildConfigs;
    if (this.configSearch) {
      const q = this.configSearch.toLowerCase();
      cfgs = cfgs.filter(
        (c) =>
          (c.name || '').toLowerCase().includes(q) ||
          (c.spdxId || '').toLowerCase().includes(q) ||
          (c.description || '').toLowerCase().includes(q)
      );
    }
    filteredConfigsCacheVal = [...cfgs].sort((a, b) =>
      (a.name || a.spdxId || '').localeCompare(b.name || b.spdxId || '')
    );
    filteredConfigsCacheKey = key;
    return filteredConfigsCacheVal;
  },

  get filteredBuilds() {
    // Read the reactive inputs up front so Alpine tracks them, then short-
    // circuit to the cached result when none of them changed.
    const search = this.buildSearch;
    const sort = this.buildSort;
    const builds = this.builds;
    const key = `${builds.length}|${search}|${sort}`;
    if (key === filteredBuildsCacheKey) return filteredBuildsCacheVal;

    let buildList = builds;
    if (search) {
      const q = search.toLowerCase();
      buildList = buildList.filter((build) => {
        const searchable = [
          build.spdxId,
          build.name,
          build.build_buildId,
          build.build_buildType,
          ...this.buildParameters(build).flatMap((group) =>
            group.entries.flatMap((entry) => [entry.key, entry.value])
          ),
          ...this.buildOutputs(build.spdxId).map((id) => this.relTargetDisplayName(id))
        ]
          .filter(Boolean)
          .join(' ')
          .toLowerCase();
        return searchable.includes(q);
      });
    }

    const sorted = [...buildList];
    if (sort === 'inputs') {
      sorted.sort((a, b) => this.buildInputs(b.spdxId).length - this.buildInputs(a.spdxId).length);
    } else if (sort === 'buildId') {
      sorted.sort((a, b) =>
        (a.build_buildId || a.spdxId || '').localeCompare(b.build_buildId || b.spdxId || '')
      );
    } else {
      sorted.sort((a, b) =>
        this.buildSortName(a).localeCompare(this.buildSortName(b), undefined, {
          numeric: true
        })
      );
    }

    filteredBuildsCacheKey = key;
    filteredBuildsCacheVal = sorted;
    return sorted;
  },

  // The extension filter chips for the Files view: the most common extensions by
  // file count (capped at FILE_TYPE_CHIP_LIMIT), plus whatever is currently
  // selected so its chip always shows. Memoized: counting over hundreds of
  // thousands of files on every render was a real cost on large SBOMs.
  get fileTypes() {
    const key = `${this.files.length}|${this.fileTypeFilter}`;
    if (key === fileTypesCacheKey) return fileTypesCacheVal;
    const counts = new Map();
    for (const f of this.files) {
      const e = this.fileExt(f.name) || NO_EXT_LABEL; // labeled bucket for no-extension files
      counts.set(e, (counts.get(e) || 0) + 1);
    }
    const top = [...counts.keys()]
      .sort((a, b) => counts.get(b) - counts.get(a) || (a < b ? -1 : a > b ? 1 : 0))
      .slice(0, FILE_TYPE_CHIP_LIMIT);
    if (this.fileTypeFilter && !top.includes(this.fileTypeFilter)) top.push(this.fileTypeFilter);
    fileTypesCacheKey = key;
    fileTypesCacheVal = top;
    return top;
  },

  // Agents (Person / Organization / SoftwareAgent) filtered by the in-view search
  // box (name, id, or email) and sorted either by how many elements they're tied
  // to — the most active creators/suppliers first — or by name.
  get filteredAgents() {
    const agents = this.agents;
    const key = `${agents.length}|${this.agentSearch}|${this.agentSort}`;
    if (key === filteredAgentsCacheKey) return filteredAgentsCacheVal;

    let list = agents;
    if (this.agentSearch) {
      const q = this.agentSearch.toLowerCase();
      list = list.filter(
        (a) =>
          (a.name || '').toLowerCase().includes(q) ||
          this.cleanName(a.spdxId).toLowerCase().includes(q) ||
          (this.agentEmail(a) || '').toLowerCase().includes(q)
      );
    }
    filteredAgentsCacheVal =
      this.agentSort === 'name'
        ? [...list].sort((a, b) =>
            (a.name || this.cleanName(a.spdxId)).localeCompare(b.name || this.cleanName(b.spdxId))
          )
        : [...list].sort(
            (a, b) =>
              this.agentLinkCount(b) - this.agentLinkCount(a) ||
              (a.name || this.cleanName(a.spdxId)).localeCompare(b.name || this.cleanName(b.spdxId))
          );
    filteredAgentsCacheKey = key;
    return filteredAgentsCacheVal;
  }
};
