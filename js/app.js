import { createGraphFilters, createViews } from './config.js';
import { computeRelationshipTypeCounts } from './parser.js';
import {
  cleanName as formatSpdxName,
  cleanFileName as formatFileName,
  fileExt as getFileExtension,
  formatDate as formatDisplayDate,
  getRelationshipColor,
  getRelationshipGroupLabel,
  getRelationshipSortOrder,
  getRelationshipTargetDisplayName,
  getElementDisplayName,
  getDetailPromotedFields,
  getNodeType as resolveNodeType,
  getNodeTypeColor,
  getElementBadgeClass,
  parseCompileFlags as parseBuildConfigFlags,
  parseBuildParameters as parseBuildParameterGroups,
  getToolUsageCount,
  getExternalIdentifiers,
  getVulnerabilityLookup,
  getVulnerabilityId,
  getVulnerabilityLocators,
  getVulnerabilityUrl,
  getVexStatusMeta,
  getVexJustificationLabel,
  getCvssSeverityMeta,
  summarizeCveRecord,
  isMeaningfulValue,
  normalizeUrl,
  copyToClipboard,
  extractSpdxLicenseId,
  extractLicenseExpressionParts,
  resolveLicenseExpression,
  spdxLicenseJsonUrl,
  spdxLicenseExceptionJsonUrl,
  spdxLicensePageUrl,
  spdxLicenseExceptionPageUrl
} from './utils.js';
import {
  renderGraph as renderGraphView,
  resetGraphZoom as resetGraphViewZoom
} from './graph-view.js';

/* ==========================================================================
   Parser worker
   A single long-lived worker, kept off the Alpine reactive state so it is
   never proxied. Parsing large SBOMs (JSON.parse + index building) runs here
   so the main thread stays responsive. latestParseReqId lets us ignore stale
   results when the user loads a second SBOM before the first finishes.
   ========================================================================== */
let parserWorker = null;
let parseReqSeq = 0;
let latestParseReqId = 0;

// Memo for the filteredBuilds getter. Sorting ~1k builds (the default sort
// derives a display name per item) is wasted work when it re-runs on unrelated
// reactive changes (e.g. expanding a card). Cached on the inputs that actually
// affect the result; kept off the reactive state so it isn't proxied.
let filteredBuildsCacheKey = null;
let filteredBuildsCacheVal = [];
// Same idea for the security view: sorting/filtering ~3k vulnerabilities is
// wasted work when it re-runs on unrelated reactive changes (e.g. expanding a
// card). Cached on the inputs that actually affect the result.
let filteredVulnsCacheKey = null;
let filteredVulnsCacheVal = [];
const licenseTextCache = new Map(); // licenseId -> { name, text }

function getParserWorker() {
  if (!parserWorker) {
    parserWorker = new Worker(new URL('./parser.worker.js', import.meta.url), { type: 'module' });
  }
  return parserWorker;
}

/* Marks an object so Alpine's (Vue) reactivity leaves it untouched. The parsed
   SBOM is large (the Linux kernel set is ~8k elements / ~3.9k relationships)
   and fully immutable after parsing, so deep-proxying it just adds per-access
   overhead to every render. `__v_skip` is the flag @vue/reactivity checks to
   skip an object; we set it non-enumerable so it never leaks into iteration. */
function markRaw(value) {
  if (
    value &&
    typeof value === 'object' &&
    !Object.prototype.hasOwnProperty.call(value, '__v_skip')
  ) {
    Object.defineProperty(value, '__v_skip', { value: true, configurable: true });
  }
  return value;
}

/* Marks every object-valued property of a payload raw, then returns it.
   Marking the top-level containers (Maps/arrays) is enough: reading them no
   longer returns a proxy, so their elements aren't proxied on access either. */
function markPayloadRaw(payload) {
  Object.keys(payload || {}).forEach((key) => markRaw(payload[key]));
  return payload;
}

export function spdxApp() {
  return {
    // State
    dataLoaded: false,
    loadedFiles: [], // [{name, data}] — one entry per loaded file
    samples: [], // bundled demo sets, loaded from samples/samples.json
    loadingSample: null, // id of the sample currently being fetched
    sampleError: '',
    parsing: false, // true while loading/parsing a freshly loaded SBOM
    parseError: '',
    progress: 0, // 0..1 overall load progress (download → JSON → graph → index)
    progressPhase: '', // human-readable current phase label
    progressEta: null, // estimated seconds remaining, or null when unknown
    currentView: 'dashboard',
    // Views render their (potentially huge) item lists lazily: a view's heavy
    // x-for only builds once the view has been opened. The dashboard is the
    // landing view so it's mounted from the start. This keeps the initial
    // load fast — otherwise Alpine would build every hidden view's DOM (e.g.
    // thousands of file cards) up front, freezing the page right at the end.
    mountedViews: {
      dashboard: true,
      graph: false,
      packages: false,
      files: false,
      licenses: false,
      security: false,
      configs: false,
      build: false
    },
    searchQuery: '',
    sidebarOpen: false, // mobile off-canvas nav drawer (ignored at md+ where the sidebar is static)
    detailElement: null,
    expandedPkg: null,
    expandedFile: null,
    expandedConfig: null,
    expandedBuild: null,
    expandedLicense: null,
    expandedVuln: null,
    _navPushQueued: false, // batches same-tick nav-state changes into one history entry
    _lastNavKey: null, // JSON of the last pushed/replaced nav state, to skip no-op pushes
    focusedNavKind: '',
    focusedNavId: '',
    focusedNavTimer: null,
    configSearch: '',
    buildSearch: '',
    licenseSearch: '',
    securitySearch: '',
    securitySort: 'severity',
    securityStatusFilter: '',
    // CVE id -> { loading, error, data } fetched on demand from cve.org
    cveDetails: {},
    licenseSort: 'usage',
    buildSort: 'output',
    pkgSort: 'name',
    fileTypeFilter: '',
    toastMsg: '',
    licenseModalOpen: false,
    licenseModalExpression: '',
    licenseModalParts: [],
    licenseModalActiveIndex: 0,
    licenseModalRef: '',

    // Parsed data
    elementMap: new Map(),
    packages: [],
    files: [],
    tools: [],
    relationships: [],
    builds: [],
    buildInfo: null,
    agentInfo: null,
    licenses: [],
    vulnerabilities: [], // enriched CVEs with VEX assessments
    vexRelationships: [], // raw VEX assessment relationship elements (for the graph)
    presentNodeTypes: [], // graph node types present in the data (trims the legend)
    presentRelTypes: [], // relationship types present in the data (trims the legend)
    docName: '',
    docNamespace: '',
    specVersion: '',
    createdDate: '',
    dataLicenseLabel: '',
    profileConformance: [],

    // Relationship indexes
    relFromIndex: new Map(),
    relToIndex: new Map(),
    depIndex: new Map(), // spdxId -> [dependsOn targets]
    dependentIndex: new Map(), // spdxId -> [things that depend on it]
    containsIndex: new Map(), // spdxId -> [contained file spdxIds]
    parentIndex: new Map(), // file spdxId -> parent package spdxId
    toolIndex: new Map(), // file spdxId -> [tool spdxIds]
    staticLinkIndex: new Map(), // elf spdxId -> [linked lib spdxIds]
    configuresIndex: new Map(), // config spdxId -> [target spdxIds]
    configuredByIndex: new Map(), // target spdxId -> [config spdxIds]
    buildInputIndex: new Map(), // build spdxId -> [input spdxIds]
    buildOutputIndex: new Map(), // build spdxId -> [output spdxIds]
    producedByBuildIndex: new Map(), // artifact spdxId -> [producer build spdxIds]
    consumedByBuildIndex: new Map(), // input spdxId -> [consumer build spdxIds]
    buildStepIndex: new Map(), // parent/root build spdxId -> [child build spdxIds]
    parentBuildIndex: new Map(), // child build spdxId -> [parent/root build spdxIds]
    distributionArtifactIndex: new Map(), // package spdxId -> [artifact spdxIds]
    distributedByIndex: new Map(), // artifact spdxId -> [package spdxIds]
    licenseUsersIndex: new Map(), // license id -> [{from, kind}]
    vexByVuln: new Map(), // vulnerability spdxId -> [VexAssessment]
    vexByPackage: new Map(), // package spdxId -> [VexAssessment]
    buildConfigs: [], // build configuration elements
    generatedArtifacts: [],

    // Graph state
    graphSim: null,
    graphSvg: null,
    graphCanvasSel: null,
    graphZoom: null,
    graphFilters: createGraphFilters(),
    graphAggregate: false,
    expandedClusters: new Set(), // cluster keys the user has drilled into
    graphNodeCount: 0, // live readout of rendered nodes/edges
    graphEdgeCount: 0,
    graphTruncated: false, // true when the guard rail capped an un-aggregated render
    graphSearchQuery: '', // search box in the graph controls bar
    graphSearchFullText: false, // false = name/id only, true = whole element JSON
    graphSearchMode: 'dim', // 'dim' fades non-matches, 'focus' hides all but neighbours
    graphMatchCount: 0, // live count of matched nodes
    graphRecomputeSearch: null, // set by the graph renderer; updates the overlay only
    graphSelectedNodeId: null, // render-node id pinned by click (keeps hover-style focus)
    graphSyncSelection: null, // set by the graph renderer; re-pins the highlight without a rebuild

    // Views
    views: createViews(),

    get currentViewLabel() {
      return this.views.find((v) => v.id === this.currentView)?.label || '';
    },

    get relTypeCounts() {
      return computeRelationshipTypeCounts(this.relationships);
    },

    get filteredPackages() {
      let pkgs = this.packages;
      if (this.searchQuery) {
        const q = this.searchQuery.toLowerCase();
        pkgs = pkgs.filter(
          (p) =>
            this.cleanName(p.spdxId).toLowerCase().includes(q) || p.name?.toLowerCase().includes(q)
        );
      }
      if (this.pkgSort === 'deps')
        pkgs = [...pkgs].sort(
          (a, b) => (this.depsOf(b.spdxId)?.length || 0) - (this.depsOf(a.spdxId)?.length || 0)
        );
      else if (this.pkgSort === 'dependents')
        pkgs = [...pkgs].sort(
          (a, b) =>
            (this.dependentsOf(b.spdxId)?.length || 0) - (this.dependentsOf(a.spdxId)?.length || 0)
        );
      else
        pkgs = [...pkgs].sort((a, b) =>
          (a.name || this.cleanName(a.spdxId)).localeCompare(b.name || this.cleanName(b.spdxId))
        );
      return pkgs;
    },

    get filteredFiles() {
      let fs = this.files;
      if (this.searchQuery) {
        const q = this.searchQuery.toLowerCase();
        fs = fs.filter((f) => f.name?.toLowerCase().includes(q));
      }
      if (this.fileTypeFilter) {
        fs = fs.filter((f) => this.fileExt(f.name) === this.fileTypeFilter);
      }
      return [...fs].sort((a, b) => (a.name || '').localeCompare(b.name || ''));
    },

    get filteredLicenses() {
      let lics = this.licenses;
      if (this.licenseSearch) {
        const q = this.licenseSearch.toLowerCase();
        lics = lics.filter(
          (l) => (l.label || '').toLowerCase().includes(q) || (l.id || '').toLowerCase().includes(q)
        );
      }
      if (this.licenseSort === 'name') {
        return [...lics].sort((a, b) => (a.label || '').localeCompare(b.label || ''));
      }
      return [...lics].sort(
        (a, b) => b.userCount - a.userCount || (a.label || '').localeCompare(b.label || '')
      );
    },

    // Vulnerabilities filtered by the search box + status filter, then sorted.
    // Memoized on those inputs (see filteredVulnsCache*) so unrelated reactive
    // changes don't re-sort ~3k CVEs.
    get filteredVulnerabilities() {
      const search = this.securitySearch;
      const sort = this.securitySort;
      const statusFilter = this.securityStatusFilter;
      const vulns = this.vulnerabilities;
      const key = `${vulns.length}|${search}|${sort}|${statusFilter}`;
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

      const sev = { affected: 4, under_investigation: 3, not_affected: 2, fixed: 1, unknown: 0 };
      const sorted = [...list];
      if (sort === 'cve') {
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
      const counts = { fixed: 0, not_affected: 0, affected: 0, under_investigation: 0, unknown: 0 };
      this.vulnerabilities.forEach((v) => {
        counts[v.overallStatus] = (counts[v.overallStatus] || 0) + 1;
      });
      return { total: this.vulnerabilities.length, counts };
    },

    // Ordered list of statuses that actually occur, for rendering summary chips
    // and the status filter without showing empty buckets.
    get securityStatusOrder() {
      const order = ['affected', 'under_investigation', 'not_affected', 'fixed', 'unknown'];
      const counts = this.securitySummary.counts;
      return order.filter((s) => counts[s] > 0);
    },

    // The subset of graph legend entries whose type is actually present in the
    // loaded data — so an SBOM without VEX/tools/builds/etc. doesn't show a long
    // legend full of toggles that would draw nothing.
    get visibleGraphFilters() {
      const nodeTypes = new Set(this.presentNodeTypes);
      const relTypes = new Set(this.presentRelTypes);
      return this.graphFilters.filter((f) =>
        f.isRel ? relTypes.has(f.key) : nodeTypes.has(f.key)
      );
    },

    get filteredConfigs() {
      let cfgs = this.buildConfigs;
      if (this.configSearch) {
        const q = this.configSearch.toLowerCase();
        cfgs = cfgs.filter(
          (c) =>
            (c.name || '').toLowerCase().includes(q) ||
            (c.spdxId || '').toLowerCase().includes(q) ||
            (c.description || '').toLowerCase().includes(q)
        );
      }
      return [...cfgs].sort((a, b) =>
        (a.name || a.spdxId || '').localeCompare(b.name || b.spdxId || '')
      );
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
        sorted.sort(
          (a, b) => this.buildInputs(b.spdxId).length - this.buildInputs(a.spdxId).length
        );
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

    get fileTypes() {
      const exts = new Set(this.files.map((f) => this.fileExt(f.name)));
      return [...exts].sort();
    },

    // Init
    init() {
      this.$watch('currentView', (v) => {
        if (v === 'graph') this.$nextTick(() => this.renderGraph());
      });
      this.$watch('dataLoaded', (loaded) => {
        if (loaded) this._initNavHistory();
      });
      window.addEventListener('popstate', (e) => this._applyNavState(e.state));
      this.loadSampleManifest();
    },

    // Bundled demo SBOMs — listed in samples/samples.json, loaded over fetch
    async loadSampleManifest() {
      try {
        const res = await fetch('samples/samples.json');
        if (res.ok) this.samples = await res.json();
      } catch {
        /* demos just won't show if the manifest is missing */
      }
    },
    async loadSample(sample) {
      this.loadingSample = sample.id;
      this.sampleError = '';
      this._beginParseSession(); // show the overlay during download too
      this.progressPhase = 'Downloading…';
      try {
        const loaded = [];
        const total = sample.files.length;
        for (let i = 0; i < sample.files.length; i++) {
          const fname = sample.files[i];
          const res = await fetch(`${sample.dir}/${fname}`);
          if (!res.ok) throw new Error(`${fname} (HTTP ${res.status})`);
          const text = await this._readResponseWithProgress(res, i, total);
          loaded.push({ name: fname, text });
        }
        this.loadedFiles = loaded; // replace — the drop zone starts empty
        this.rebuildFromLoadedFiles(); // existing merge + parse path (session continues)
        this.dataLoaded = true;
      } catch (err) {
        this.parsing = false;
        this.progressEta = null;
        this.sampleError = `Could not load ${sample.name}: ${err.message}`;
      } finally {
        this.loadingSample = null;
      }
    },

    // Streams a fetch response, advancing the download band of the progress bar.
    // Falls back to a plain read when the body/Content-Length isn't available.
    async _readResponseWithProgress(res, fileIndex, totalFiles) {
      const len = Number(res.headers.get('Content-Length'));
      if (!res.body || !len) {
        const text = await res.text();
        this._setProgress('download', (fileIndex + 1) / totalFiles);
        return text;
      }
      const reader = res.body.getReader();
      const chunks = [];
      let received = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        received += value.length;
        this._setProgress('download', (fileIndex + Math.min(1, received / len)) / totalFiles);
      }
      return new Blob(chunks).text();
    },

    // File handling — supports multiple files
    handleFileDrop(e) {
      e.target.closest?.('.drop-zone')?.classList.remove('drag-over');
      const files = [...(e.dataTransfer.files || [])];
      if (files.length) this.readFiles(files);
    },
    handleFileInput(e) {
      const files = [...(e.target.files || [])];
      if (files.length) this.readFiles(files);
      e.target.value = ''; // reset so same file can be re-added
    },
    readFiles(fileList) {
      this._beginParseSession(); // show the overlay during file reads too
      this.progressPhase = 'Reading files…';
      const total = fileList.length;
      const loaded = new Array(total); // preserve input order
      const fileProgress = new Array(total).fill(0);
      let remaining = total;
      fileList.forEach((file, i) => {
        const reader = new FileReader();
        reader.onprogress = (ev) => {
          if (!ev.lengthComputable) return;
          fileProgress[i] = ev.loaded / ev.total;
          const sum = fileProgress.reduce((a, b) => a + b, 0);
          this._setProgress('download', sum / total);
        };
        reader.onload = (ev) => {
          // Store the raw text; JSON.parse happens in the worker so the main
          // thread never blocks on large files.
          loaded[i] = { name: file.name, text: ev.target.result };
          fileProgress[i] = 1;
          remaining--;
          if (remaining === 0) {
            loaded.forEach((f) => this.loadedFiles.push(f));
            this.rebuildFromLoadedFiles(); // session continues into the worker
            this.dataLoaded = true;
          }
        };
        reader.readAsText(file);
      });
    },
    removeFile(index) {
      this.loadedFiles.splice(index, 1);
      if (this.loadedFiles.length === 0) {
        this.dataLoaded = false;
        return;
      }
      this.rebuildFromLoadedFiles();
    },

    // Begins a load/parse session: shows the overlay and resets the progress
    // bar + ETA timer. Callers (loadSample/readFiles) start this before the
    // download phase so the bar covers download + parse; parseData only starts
    // it if a session isn't already running (e.g. removing a file re-parses
    // from cached text with no download).
    _beginParseSession() {
      this.parsing = true;
      this.parseError = '';
      this.progress = 0;
      this.progressPhase = '';
      this.progressEta = null;
      this._progressStart = performance.now();
      this._progressEtaSmoothed = null;
    },

    // Maps a phase + within-phase fraction (0..1) onto the overall bar and
    // updates the ETA from elapsed time vs. overall fraction.
    _setProgress(phase, value) {
      const bands = {
        download: [0, 0.3],
        json: [0.3, 0.5],
        graph: [0.5, 0.78],
        index: [0.78, 0.99]
      };
      const labels = {
        download: 'Downloading…',
        json: 'Reading JSON…',
        graph: 'Building graph…',
        index: 'Indexing relationships…'
      };
      const [lo, hi] = bands[phase] || [0, 1];
      const v = Math.max(0, Math.min(1, value));
      const overall = Math.min(0.99, lo + v * (hi - lo));
      // Progress only moves forward (phases can briefly overlap across files).
      if (overall >= this.progress) this.progress = overall;
      this.progressPhase = labels[phase] || '';

      const elapsed = (performance.now() - (this._progressStart || performance.now())) / 1000;
      if (this.progress > 0.04 && this.progress < 0.985) {
        const eta = (elapsed * (1 - this.progress)) / this.progress;
        // Exponential smoothing so the number doesn't jitter.
        this._progressEtaSmoothed =
          this._progressEtaSmoothed == null ? eta : this._progressEtaSmoothed * 0.6 + eta * 0.4;
        this.progressEta = this._progressEtaSmoothed;
      }
    },

    // Merge all loaded files and re-parse (off the main thread)
    rebuildFromLoadedFiles() {
      this.parseData(this.loadedFiles);
    },

    // Parse the loaded files in the worker, then apply the result.
    // `files` is [{ name, text }]; parsing (JSON.parse + graph + indexes) runs
    // in parser.worker.js so the UI never freezes on large SBOMs.
    parseData(files) {
      const worker = getParserWorker();
      const reqId = ++parseReqSeq;
      latestParseReqId = reqId;
      if (!this.parsing) this._beginParseSession(); // re-parse path (no download)

      worker.onmessage = (event) => {
        const msg = event.data || {};
        if (msg.id !== latestParseReqId) return; // a newer load superseded this one

        if (msg.type === 'progress') {
          this._setProgress(msg.phase, msg.value);
          return;
        }

        // type === 'done'
        this.parsing = false;
        this.progress = 1;
        this.progressEta = null;

        if (!msg.ok) {
          this.parseError = msg.error || 'Failed to parse SBOM';
          console.error('SBOM parse failed:', this.parseError);
          this.toastMsg = 'Error parsing SBOM: ' + this.parseError;
          setTimeout(() => (this.toastMsg = ''), 5000);
          return;
        }

        Object.assign(this, markPayloadRaw(msg.parsed));
        Object.assign(this, markPayloadRaw(msg.indexes));

        this.views.find((v) => v.id === 'packages').count = this.packages.length;
        this.views.find((v) => v.id === 'files').count = this.files.length;
        this.views.find((v) => v.id === 'licenses').count = this.licenses.length;
        this.views.find((v) => v.id === 'security').count = this.vulnerabilities.length;
        this.views.find((v) => v.id === 'configs').count = this.buildConfigs.length;
        this.views.find((v) => v.id === 'build').count = this.builds.length;
        this.expandedClusters = new Set(); // fresh data: start fully collapsed
        this.cveDetails = {}; // drop cached CVE fetches from the previous SBOM
        filteredBuildsCacheKey = null; // invalidate the build sort memo for new data
        filteredVulnsCacheKey = null; // invalidate the vulnerability sort memo for new data

        // Re-render D3 views if currently active (they don't auto-update from
        // Alpine reactivity).
        this.$nextTick(() => {
          if (this.currentView === 'graph') this.renderGraph();
        });
      };

      worker.onerror = (err) => {
        if (latestParseReqId !== reqId) return;
        this.parsing = false;
        this.progressEta = null;
        this.parseError = err.message || 'Worker error';
        console.error('Parser worker error:', this.parseError);
        this.toastMsg = 'Parser worker error: ' + this.parseError;
        setTimeout(() => (this.toastMsg = ''), 5000);
      };

      worker.postMessage({
        id: reqId,
        files: files.map((f) => ({ name: f.name, text: f.text }))
      });
    },

    // Helpers
    cleanName(spdxId) {
      return formatSpdxName(spdxId);
    },
    cleanFileName(spdxId) {
      return formatFileName(spdxId, this.elementMap);
    },
    fileExt(name) {
      return getFileExtension(name);
    },
    formatDate(date) {
      return formatDisplayDate(date);
    },
    depsOf(spdxId) {
      return this.depIndex.get(spdxId) || [];
    },
    dependentsOf(spdxId) {
      return this.dependentIndex.get(spdxId) || [];
    },
    containedFiles(spdxId) {
      return this.containsIndex.get(spdxId) || [];
    },
    parentPackage(spdxId) {
      return this.parentIndex.get(spdxId) || null;
    },
    fileTools(spdxId) {
      return this.toolIndex.get(spdxId) || [];
    },
    buildInputs(spdxId) {
      return this.buildInputIndex.get(spdxId) || [];
    },
    buildOutputs(spdxId) {
      return this.buildOutputIndex.get(spdxId) || [];
    },
    producedByBuilds(spdxId) {
      return this.producedByBuildIndex.get(spdxId) || [];
    },
    consumedByBuilds(spdxId) {
      return this.consumedByBuildIndex.get(spdxId) || [];
    },
    childBuilds(spdxId) {
      return this.buildStepIndex.get(spdxId) || [];
    },
    parentBuilds(spdxId) {
      return this.parentBuildIndex.get(spdxId) || [];
    },
    distributionArtifacts(spdxId) {
      return this.distributionArtifactIndex.get(spdxId) || [];
    },
    distributedBy(spdxId) {
      return this.distributedByIndex.get(spdxId) || [];
    },
    staticLinks(spdxId) {
      return this.staticLinkIndex.get(spdxId) || [];
    },
    configuresTargets(spdxId) {
      return this.configuresIndex.get(spdxId) || [];
    },
    configuredBy(spdxId) {
      return this.configuredByIndex.get(spdxId) || [];
    },
    outgoingRels(spdxId) {
      return this.relFromIndex.get(spdxId) || [];
    },
    incomingRels(spdxId) {
      return this.relToIndex.get(spdxId) || [];
    },

    buildSortName(build) {
      return (
        this.buildOutputs(build.spdxId)
          .map((id) => this.relTargetDisplayName(id))
          .join(' ') ||
        build.build_buildId ||
        build.spdxId ||
        ''
      );
    },

    buildDisplayName(build) {
      const outputs = this.buildOutputs(build.spdxId);
      if (outputs.length) {
        return outputs.map((id) => this.relTargetDisplayName(id)).join(', ');
      }
      return build.name || build.build_buildId || build.spdxId || 'Build';
    },

    formatCount(count) {
      return new Intl.NumberFormat().format(count || 0);
    },

    getBuildConfigFor(targetSpdxId) {
      const configs = this.configuredBy(targetSpdxId);
      if (!configs.length) return null;
      return this.elementMap.get(configs[0].configId);
    },

    parseCompileFlags(config) {
      return parseBuildConfigFlags(config);
    },
    buildParameters(build) {
      return parseBuildParameterGroups(build);
    },
    buildParameterCount(build) {
      return this.buildParameters(build).reduce((count, group) => count + group.entries.length, 0);
    },
    buildParameterPreview(build) {
      return this.buildParameters(build)
        .flatMap((group) => group.entries)
        .slice(0, 3);
    },
    parameterTokenId(token) {
      if (typeof token === 'string') return token;
      return token?.renderKey || token?.id || this.parameterTokenText(token);
    },
    parameterTokenText(token) {
      if (typeof token === 'string') return token;
      return token?.display ?? token?.text ?? token?.value ?? '';
    },
    parameterTokenKind(token) {
      if (typeof token === 'string') return 'Value';
      return token?.kind || 'Value';
    },
    parameterTokenClass(token) {
      if (typeof token === 'string') return 'param-token param-token-value';
      return token?.className || 'param-token param-token-value';
    },
    toolUsageCount(spdxId) {
      return getToolUsageCount(spdxId, this.relationships);
    },
    externalIdentifiers(element) {
      return getExternalIdentifiers(element);
    },
    vulnLookup(eid) {
      return getVulnerabilityLookup(eid);
    },

    // ========== SECURITY / VEX ==========
    vexStatusMeta(status) {
      return getVexStatusMeta(status);
    },
    vexJustificationLabel(type) {
      return getVexJustificationLabel(type);
    },
    vulnId(el) {
      return getVulnerabilityId(el);
    },
    vulnUrl(el) {
      return getVulnerabilityUrl(el);
    },
    vulnLocators(el) {
      return getVulnerabilityLocators(el);
    },
    // VEX assessments for a package (its associated vulnerabilities + statuses).
    vulnsForPackage(spdxId) {
      return this.vexByPackage.get(spdxId) || [];
    },
    // Distinct-status counts for a package's vulnerabilities, ordered by severity.
    packageVulnSummary(spdxId) {
      const assessments = this.vulnsForPackage(spdxId);
      const byStatus = {};
      const seen = new Set(); // de-dupe (vuln, status) so one CVE counts once
      assessments.forEach((a) => {
        const k = a.vulnId + '|' + a.status;
        if (seen.has(k)) return;
        seen.add(k);
        (byStatus[a.status] ||= new Set()).add(a.vulnId);
      });
      const order = ['affected', 'under_investigation', 'not_affected', 'fixed', 'unknown'];
      const total = new Set(assessments.map((a) => a.vulnId)).size;
      return {
        total,
        statuses: order
          .filter((s) => byStatus[s])
          .map((s) => ({ status: s, count: byStatus[s].size, meta: getVexStatusMeta(s) }))
      };
    },
    // The full enriched vulnerability record for a vuln spdxId (or null).
    vulnRecord(spdxId) {
      return this.vulnerabilities.find((v) => v.spdxId === spdxId) || null;
    },
    cvssSeverityMeta(severity) {
      return getCvssSeverityMeta(severity);
    },
    // Reactive fetch-state for a CVE's enriched details ({} until requested).
    cveDetail(cveId) {
      return this.cveDetails[cveId] || null;
    },
    // Lazily fetch a CVE's public record the first time it's viewed (mirrors the
    // on-demand license-text fetch). Cached in this.cveDetails so re-opening a
    // card is instant and we never re-request. Data & terms: the CVE Program's
    // records are free to use and the SBOM already lists these API URLs as the
    // vulnerabilities' identifierLocators.
    ensureCveDetails(cveId) {
      if (!cveId || !/^CVE-\d{4}-\d+$/i.test(cveId)) return;
      if (this.cveDetails[cveId]) return; // cached or already in flight
      this.fetchCveDetails(cveId);
    },
    async fetchCveDetails(cveId) {
      this.cveDetails[cveId] = { loading: true, error: '', data: null };
      try {
        const res = await fetch(`https://cveawg.mitre.org/api/cve/${encodeURIComponent(cveId)}`);
        if (!res.ok) {
          throw new Error(
            res.status === 404 ? 'Not found in the CVE database' : `Request failed (${res.status})`
          );
        }
        const record = await res.json();
        this.cveDetails[cveId] = { loading: false, error: '', data: summarizeCveRecord(record) };
      } catch (err) {
        this.cveDetails[cveId] = {
          loading: false,
          error: err?.message || 'Could not load CVE details',
          data: null
        };
      }
    },
    // Deduplicated, severity-sorted assessments for a vulnerability detail view.
    assessmentsForVuln(spdxId) {
      const list = this.vexByVuln.get(spdxId) || [];
      const sev = { affected: 4, under_investigation: 3, not_affected: 2, fixed: 1, unknown: 0 };
      return [...list].sort(
        (a, b) =>
          (sev[b.status] || 0) - (sev[a.status] || 0) ||
          this.relTargetDisplayName(a.packageId).localeCompare(
            this.relTargetDisplayName(b.packageId)
          )
      );
    },
    isMeaningful(value) {
      return isMeaningfulValue(value);
    },
    downloadUrl(value) {
      return normalizeUrl(value);
    },
    relColor(type) {
      return getRelationshipColor(type);
    },
    relGroupLabel(relType, direction) {
      return getRelationshipGroupLabel(relType, direction);
    },

    // Grouped relationship data for the detail panel
    get detailRelGroups() {
      if (!this.detailElement) return [];
      const id = this.detailElement.spdxId;
      const groups = new Map(); // key → { label, color, items:[] }

      // Vulnerability associations are surfaced in the dedicated security
      // section, not the generic relationship list (a single package can carry
      // thousands of them).
      const skip = (rel) => rel.relationshipType === 'hasAssociatedVulnerability';

      // Outgoing: this element → targets
      (this.relFromIndex.get(id) || []).forEach((rel) => {
        if (skip(rel)) return;
        const key = rel.relationshipType + ':out';
        if (!groups.has(key)) {
          groups.set(key, {
            key,
            label: this.relGroupLabel(rel.relationshipType, 'out'),
            color: this.relColor(rel.relationshipType),
            sortOrder: this.relSortOrder(rel.relationshipType, 'out'),
            items: []
          });
        }
        const targets = Array.isArray(rel.to) ? rel.to : [rel.to];
        targets.forEach((t) => {
          // Avoid duplicate entries
          if (!groups.get(key).items.find((i) => i.id === t)) {
            groups.get(key).items.push({
              id: t,
              displayName: this.relTargetDisplayName(t),
              direction: 'out'
            });
          }
        });
      });

      // Incoming: sources → this element
      (this.relToIndex.get(id) || []).forEach((rel) => {
        if (skip(rel)) return;
        const key = rel.relationshipType + ':in';
        if (!groups.has(key)) {
          groups.set(key, {
            key,
            label: this.relGroupLabel(rel.relationshipType, 'in'),
            color: this.relColor(rel.relationshipType),
            sortOrder: this.relSortOrder(rel.relationshipType, 'in'),
            items: []
          });
        }
        if (!groups.get(key).items.find((i) => i.id === rel.from)) {
          groups.get(key).items.push({
            id: rel.from,
            displayName: this.relTargetDisplayName(rel.from),
            direction: 'in'
          });
        }
      });

      return [...groups.values()].sort((a, b) => a.sortOrder - b.sortOrder);
    },

    // Sort order for relationship groups (most relevant first)
    relSortOrder(type, dir) {
      return getRelationshipSortOrder(type, dir);
    },
    relTargetDisplayName(spdxId) {
      return getRelationshipTargetDisplayName(spdxId, this.elementMap);
    },
    elementDisplayName(element) {
      return getElementDisplayName(element);
    },
    get detailPromotedFields() {
      return getDetailPromotedFields(this.detailElement);
    },
    elementBadgeClass(type) {
      return getElementBadgeClass(type);
    },
    getNodeType(item) {
      return resolveNodeType(item);
    },
    nodeTypeColor(type) {
      return getNodeTypeColor(type);
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
      this._scheduleNavPush();
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
    licenseUsers(id) {
      return this.licenseUsersIndex.get(id) || [];
    },
    licenseLabel(id) {
      const lic = this.licenses.find((l) => l.id === id);
      if (lic) return lic.label;
      const el = this.elementMap.get(id);
      if (el?.simplelicensing_licenseExpression) return el.simplelicensing_licenseExpression;
      if (id.startsWith('https://spdx.org/licenses/')) {
        return id.replace('https://spdx.org/licenses/', '');
      }
      if (id.includes('NoAssertion')) return 'NoAssertion';
      if (el?.name) return el.name;
      return this.cleanName(id);
    },
    elementLicenses(spdxId) {
      const entries = [];
      const seen = new Set();
      for (const rel of this.outgoingRels(spdxId)) {
        if (
          rel.relationshipType !== 'hasConcludedLicense' &&
          rel.relationshipType !== 'hasDeclaredLicense'
        ) {
          continue;
        }
        const kind = rel.relationshipType === 'hasDeclaredLicense' ? 'declared' : 'concluded';
        const targets = Array.isArray(rel.to) ? rel.to : [rel.to];
        for (const id of targets) {
          if (!id) continue;
          const key = `${kind}:${id}`;
          if (seen.has(key)) continue;
          seen.add(key);
          entries.push({ id, kind, label: this.licenseLabel(id) });
        }
      }
      return entries.sort((a, b) => {
        if (a.kind !== b.kind) return a.kind === 'concluded' ? -1 : 1;
        return a.label.localeCompare(b.label);
      });
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
    scrollToNavTarget(kind, id) {
      this.$nextTick(() => {
        requestAnimationFrame(() => {
          const target = [...document.querySelectorAll(`[data-nav-kind="${kind}"]`)].find(
            (el) => el.dataset.navId === id && el.offsetParent !== null
          );
          if (!target) return;
          target.scrollIntoView({ behavior: 'smooth', block: 'start' });
          this.focusNavTarget(kind, id);
        });
      });
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
    },
    spdxLicenseIdFor(licenseRef) {
      return extractSpdxLicenseId(licenseRef, this.elementMap);
    },
    licenseExpressionFor(licenseRef) {
      return resolveLicenseExpression(licenseRef, this.elementMap);
    },
    licenseExpressionParts(licenseRef) {
      return extractLicenseExpressionParts(this.licenseExpressionFor(licenseRef));
    },
    spdxLicensePageUrl(licenseId) {
      return spdxLicensePageUrl(licenseId);
    },
    licenseModalActivePart() {
      return this.licenseModalParts[this.licenseModalActiveIndex] || null;
    },
    licenseModalLoading() {
      return this.licenseModalParts.some((part) => part.loading);
    },
    licenseModalError() {
      const active = this.licenseModalActivePart();
      return active?.error && !active?.text ? active.error : '';
    },
    licenseModalText() {
      return this.licenseModalActivePart()?.text || '';
    },
    canShowLicenseText(licenseRef) {
      return this.licenseExpressionParts(licenseRef).length > 0;
    },
    licenseTextActionLabel(licenseRef) {
      return this.licenseExpressionParts(licenseRef).length > 1
        ? 'View licenses text'
        : 'View license text';
    },
    licenseModalHeadingLabel() {
      return this.licenseModalParts.length > 1 ? 'Licenses text' : 'License text';
    },
    licenseModalMainPageUrl() {
      if (this.licenseModalParts.length !== 1) return '';
      const part = this.licenseModalParts[0];
      if (part.kind === 'license') return spdxLicensePageUrl(part.id);
      if (part.kind === 'exception') return spdxLicenseExceptionPageUrl(part.id);
      return '';
    },
    closeLicenseModal() {
      this.licenseModalOpen = false;
      this.licenseModalParts = [];
      this.licenseModalActiveIndex = 0;
      this.licenseModalExpression = '';
    },
    licensePartCacheKey(part) {
      return `${part.kind}:${part.id}`;
    },
    createLicenseModalPart(part) {
      const label =
        part.kind === 'exception' && part.withLicense
          ? `${part.withLicense} WITH ${part.id}`
          : part.id;
      return {
        id: part.id,
        kind: part.kind,
        withLicense: part.withLicense || '',
        label,
        name: label,
        text: '',
        error: '',
        loading: false,
        loaded: false
      };
    },
    async fetchLicensePartText(part) {
      const cacheKey = this.licensePartCacheKey(part);
      const cached = licenseTextCache.get(cacheKey);
      if (cached) {
        part.name = cached.name;
        part.text = cached.text;
        part.loaded = true;
        part.loading = false;
        part.error = '';
        return;
      }

      part.loading = true;
      part.error = '';

      try {
        const url =
          part.kind === 'exception'
            ? spdxLicenseExceptionJsonUrl(part.id)
            : spdxLicenseJsonUrl(part.id);
        const res = await fetch(url);
        if (!res.ok) throw new Error(`Not found (${res.status})`);
        const data = await res.json();
        const text =
          part.kind === 'exception' ? data.licenseExceptionText || '' : data.licenseText || '';
        if (!text) throw new Error('No license text in response');
        const name = data.name || part.label;
        licenseTextCache.set(cacheKey, { name, text });
        part.name = name;
        part.text = text;
        part.loaded = true;
      } catch (err) {
        part.error = err.message || 'Failed to load license text';
      } finally {
        part.loading = false;
      }
    },
    async selectLicenseModalPart(index) {
      if (index < 0 || index >= this.licenseModalParts.length) return;
      this.licenseModalActiveIndex = index;
      const part = this.licenseModalParts[index];
      if (!part.loaded && !part.loading) {
        await this.fetchLicensePartText(part);
      }
    },
    async showLicenseText(licenseRef) {
      const expression = this.licenseExpressionFor(licenseRef);
      const parsedParts = extractLicenseExpressionParts(expression);

      this.licenseModalOpen = true;
      this.licenseModalRef = licenseRef;
      this.licenseModalExpression = expression;
      this.licenseModalActiveIndex = 0;
      this.licenseModalParts = parsedParts.map((part) => this.createLicenseModalPart(part));

      if (!parsedParts.length) {
        this.licenseModalParts = [
          {
            id: '',
            kind: 'license',
            withLicense: '',
            label: this.licenseLabel(licenseRef),
            name: this.licenseLabel(licenseRef),
            text: '',
            error: 'Could not parse this license expression.',
            loading: false,
            loaded: true
          }
        ];
        return;
      }

      await this.fetchLicensePartText(this.licenseModalParts[0]);
    },
    placeholderElement(spdxId) {
      return {
        type: 'ExternalReference',
        spdxId,
        name: this.cleanName(spdxId),
        placeholder: true
      };
    },
    selectGraphNode(spdxId) {
      const el = this.elementMap.get(spdxId);
      this.detailElement = el || this.placeholderElement(spdxId);
      this._scheduleNavPush();
    },

    copyHash(h) {
      copyToClipboard(h).then(() => {
        this.toastMsg = 'Copied to clipboard';
        setTimeout(() => (this.toastMsg = ''), 2000);
      });
    },

    // ========== FORCE GRAPH ==========
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
      this.renderGraph();
    },
    resetGraphZoom() {
      resetGraphViewZoom(this);
    }
  };
}

if (typeof window !== 'undefined') {
  window.spdxApp = spdxApp;

  document.addEventListener('alpine:init', () => {
    window.Alpine.data('spdxApp', spdxApp);
  });
}
