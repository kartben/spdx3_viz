import { createGraphFilters, createViews } from '../config.js';

/* The Alpine component's initial reactive state. Returned fresh per component
   instance so the Maps/Sets and the graph-filter/view arrays aren't shared
   between (re)mounts. Pure data only — behaviour lives in the method mixins
   that spdxApp() composes on top of this (see app.js). */
export function createState() {
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
    // How many items of each heavy view's filtered list the DOM may show.
    // Grows chunk-by-chunk (see _ensureViewRendered) so opening e.g. a 3k-CVE
    // Security view streams in behind a progress bar instead of freezing.
    renderLimits: {
      packages: 0,
      files: 0,
      licenses: 0,
      security: 0,
      configs: 0,
      build: 0
    },
    viewRender: { active: false, view: '', done: 0, total: 0 }, // streaming progress readout
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
    _scrollNavSeq: 0, // invalidates pending scrollToNavTarget retries
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
    fileSourceCache: {}, // fileId → {loading, windows, error}
    fileSourceIndex: new Map(), // fileId → raw GitHub URL (built in worker)

    // Parsed data
    elementMap: new Map(),
    packages: [],
    files: [],
    snippets: [],
    snippetsByFileIndex: new Map(),
    tools: [],
    relationships: [],
    builds: [],
    buildInfo: null,
    agentInfo: null,
    sboms: [], // software_Sbom elements
    sbomTypes: [], // distinct software_sbomType values (source, build, …)
    creators: [], // document creators (createdBy → SoftwareAgent/Organization/Person)
    creatorTools: [], // tools the documents were created with (createdUsing)
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
    views: createViews()
  };
}
