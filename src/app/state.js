import { createGraphFilters, createScopeFilters, createViews } from '../config.js';
import { APP_VERSION } from '../version.js';
import { CHANGELOG } from '../changelog.js';
import { storedDetailPanelWidth } from './detail-panel.js';

/* The Alpine component's initial reactive state, returned fresh per instance so
   Maps/Sets and arrays aren't shared between mounts. Pure data only. */
export function createState() {
  return {
    // State
    dataLoaded: false,
    loadedFiles: [], // [{name, data}] — one entry per loaded file
    samples: [], // bundled demo sets, loaded from samples/samples.json
    loadingSample: null, // id of the sample currently being fetched
    loadedSampleId: null, // id of the sample the loaded files came from (null once user files mix in); gates shareable URLs
    _pendingDeepLink: null, // parsed share hash to apply once the sample finishes parsing
    sampleError: '',
    parsing: false, // true while loading/parsing a freshly loaded SBOM
    parseError: '',
    progress: 0, // 0..1 overall load progress (download → JSON → graph → index)
    progressPhase: '', // human-readable current phase label
    progressEta: null, // estimated seconds remaining, or null when unknown
    currentView: 'dashboard',
    // Views build their heavy x-for lists lazily, only once opened; the
    // dashboard is the landing view so it's mounted from the start.
    mountedViews: {
      dashboard: true,
      graph: false,
      packages: false,
      ai: false,
      dataset: false,
      files: false,
      hardware: false,
      requirements: false,
      licenses: false,
      security: false,
      configs: false,
      build: false,
      agents: false,
      raw: false,
      impact: false
    },
    // The [start, end) slice of each heavy view's filtered list the DOM shows.
    // renderLimits is the end index, renderStarts the start. Both grow as the
    // user scrolls (down grows end via loadMoreForView, up grows the window
    // above via loadPrevForView) so large lists open instantly and a deep link
    // can drop a window straight onto its target instead of rendering every row
    // above it. See navigation.js (renderSlice / _ensureScrollLoader).
    renderLimits: {
      packages: 0,
      ai: 0,
      dataset: 0,
      files: 0,
      hardware: 0,
      requirements: 0,
      licenses: 0,
      security: 0,
      configs: 0,
      build: 0,
      agents: 0
    },
    // Start index of each view's rendered window; stays 0 for normal top-down
    // browsing and only moves when a deep link centers the window deep in a list.
    renderStarts: {
      packages: 0,
      ai: 0,
      dataset: 0,
      files: 0,
      hardware: 0,
      requirements: 0,
      licenses: 0,
      security: 0,
      configs: 0,
      build: 0,
      agents: 0
    },
    // How many rows of an in-card "show more" list are currently revealed,
    // keyed by an arbitrary list id (e.g. a license's declaredBy list). Absent
    // keys use the base cap; each reveal grows the entry by a chunk. Keeps big
    // secondary lists (a license used by every package, a build's tens of
    // thousands of generated artifacts) from mounting all at once on view open.
    listReveal: {},
    searchQuery: '', // header global-search box (cross-cutting jump-to-anything)
    searchOpen: false, // whether the global-search results dropdown is showing
    searchActiveIndex: 0, // keyboard-highlighted result row in the dropdown
    packageSearch: '', // in-view filter for the Packages / AI / Datasets lists
    fileSearch: '', // in-view filter for the Files list
    hardwareSearch: '', // in-view filter for the Hardware list
    requirementSearch: '', // in-view filter for the Functional Safety list
    requirementKindFilter: '', // '' = all, else an FS element type to show only
    requirementStatusFilter: '', // '' = all, else a verification-status key or 'noimpl'
    requirementLayout: 'list', // Functional Safety tab: 'list' | 'tree' (tracedToDetail decomposition)
    collapsedReqs: {}, // decomposition tree: spdxId -> true for collapsed subtrees
    sidebarOpen: false, // mobile off-canvas nav drawer (ignored at md+ where the sidebar is static)
    detailElement: null,
    detailPanelWidth: storedDetailPanelWidth(), // graph detail panel width (px) at md+, drag-resizable
    expandedPkg: null,
    expandedFile: null,
    expandedHardware: null,
    expandedRequirement: null,
    expandedConfig: null,
    expandedBuild: null,
    expandedLicense: null,
    expandedVuln: null,
    expandedAgent: null,
    _navPushQueued: false, // batches same-tick nav-state changes into one history entry
    _lastNavKey: null, // JSON of the last pushed/replaced nav state, to skip no-op pushes
    focusedNavKind: '',
    focusedNavId: '',
    focusedNavTimer: null,
    _scrollNavSeq: 0, // invalidates pending scrollToNavTarget retries
    // A link into a snippet opens this popup: the file's source with the
    // snippet's lines highlighted. Data is retained while the popup fades out
    // (visibility is driven by snippetModalOpen) so the header doesn't flash.
    // { snippetId, fileId, fileName, baseName, name, start, end, ranges, rangeCount,
    //   sourceUrl, expanded } — `expanded` maps a collapsed-gap key to the number
    //   of extra lines the user has revealed there (see _collapseSource).
    snippetModal: null,
    snippetModalOpen: false,
    _scrollSnippetSeq: 0, // invalidates pending _scrollSnippetModal retries
    // Graph detail panel: the snippet whose source is currently shown inline, so
    // its highlighted lines are only scrolled into view once per selection.
    _detailSnippetId: null,
    // gap key -> revealed line count for the detail panel's inline snippet source
    // (mirrors snippetModal.expanded; reset when the selected snippet changes).
    detailSnippetExpanded: {},
    _scrollDetailSnippetSeq: 0, // invalidates pending _scrollDetailSnippet retries
    configSearch: '',
    buildSearch: '',
    agentSearch: '', // in-view filter for the Agents list
    agentSort: 'links', // Agents list sort: 'links' (most connected) | 'name'
    licenseSearch: '',
    securitySearch: '',
    securitySort: 'severity',
    securityStatusFilter: '',
    securitySeverityFilter: '', // '' = all, else a CVSS severity band (critical…low)
    impactFocus: null, // Impact tab: focused element spdxId, or null for the rankings
    _impactHookOpenId: null, // element id whose inline Impact hook is expanded
    // CVE id -> { loading, error, data } fetched on demand from cve.org
    cveDetails: {},
    licenseSort: 'usage',
    buildSort: 'output',
    pkgSort: 'name',
    fileTypeFilter: '',
    rawActiveFile: 0, // index into loadedFiles of the file shown in the Raw JSON-LD view
    rawPretty: true, // Raw view: true = pretty-printed, false = file as loaded
    toastMsg: '',
    licenseModalOpen: false,
    licenseModalExpression: '',
    licenseModalParts: [],
    licenseModalActiveIndex: 0,
    licenseModalRef: '',
    appVersion: APP_VERSION,
    changelog: CHANGELOG,
    changelogModalOpen: false,
    fileSourceCache: {}, // fileId → {loading, windows, error} for the source viewer
    fileSourceIndex: new Map(), // fileId → raw GitHub URL (built in the parse worker)

    // Parsed data
    elementMap: new Map(),
    packages: [],
    files: [],
    snippets: [],
    snippetsByFileIndex: new Map(), // fileId → snippet[] (sorted by start line)
    tools: [],
    hardware: [], // hardware profile elements (SPDX 3.1)
    requirements: [], // requirements + FunctionalSafety artifacts (SPDX 3.1)
    relationships: [],
    builds: [],
    buildInfo: null,
    agentInfo: null,
    agents: [], // all Agent elements (SoftwareAgent / Organization / Person)
    agentLinkIndex: new Map(), // agent spdxId -> { created, supplied, originated, manufactured }
    sboms: [], // software_Sbom elements
    sbomTypes: [], // distinct software_sbomType values (source, build, …)
    creators: [], // document creators (createdBy → SoftwareAgent/Organization/Person)
    creatorTools: [], // tools the documents were created with (createdUsing)
    licenses: [],
    vulnerabilities: [], // enriched CVEs with VEX assessments
    vexRelationships: [], // raw VEX assessment relationship elements (for the graph)
    presentNodeTypes: [], // graph node types present in the data (trims the legend)
    presentRelTypes: [], // relationship types present in the data (trims the legend)
    presentScopes: [], // lifecycle scopes present in the data (empty hides the scope legend)
    docName: '',
    docNamespace: '',
    specVersion: '',
    createdDate: '',
    dataLicenseLabel: '',
    profileConformance: [],
    externalMap: new Map(), // externalSpdxId -> ExternalMapEntry (SpdxDocument.import)
    externalRefStats: { total: 0, resolved: 0, unresolved: 0 }, // import resolution summary

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
    impactChildIndex: new Map(), // element -> [{id, rel, soft}] it depends on / includes
    impactParentIndex: new Map(), // element -> [{id, rel, soft}] that depend on / include it
    rootElementIds: new Set(), // spdxIds declared as an SBOM/document rootElement
    buildConfigs: [], // build configuration elements
    generatedArtifacts: [],

    // Graph state
    graphSim: null,
    graphSvg: null,
    graphCanvasSel: null,
    graphZoom: null,
    graphFilters: createGraphFilters(),
    // Lifecycle-scope filters (build / runtime / …). All active by default, so
    // the graph is unchanged until the user narrows to a scope.
    scopeFilters: createScopeFilters(),
    graphAggregate: false,
    graphUseIcons: false, // draw nodes as their type's Material icon instead of a plain dot
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
