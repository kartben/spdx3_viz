import { createGraphFilters, createScopeFilters, createViews } from '../config.js';
import { APP_VERSION } from '../version.js';
import { CHANGELOG } from '../changelog.js';
import { storedDetailPanelWidth } from './detail-panel.js';

// Restores the saved NVD source preference ('live' | 'bundle'); defaults to the
// bundled index (no rate limits or CORS, works offline).
function readNvdSource() {
  try {
    return localStorage.getItem('spdx3viz.nvdSource') === 'live' ? 'live' : 'bundle';
  } catch {
    return 'bundle';
  }
}

/* The Alpine component's initial reactive state, returned fresh per instance so
   Maps/Sets and arrays aren't shared between mounts. Pure data only. */
export function createState() {
  return {
    // State
    dataLoaded: false,
    // [{name, text, src?}]: one entry per loaded file. `src` is the sample path
    // a file was fetched from (absent for user files), which is what lets the
    // Add files picker gray out what the document already holds.
    loadedFiles: [],
    samples: [], // bundled demo sets, loaded from samples/samples.json
    loadingSample: null, // id of the sample currently being fetched
    loadedSampleId: null, // id of the sample the loaded files came from (null once user files mix in); gates shareable URLs
    // Files dialog: the staged edits to the loaded set, applied as one batch.
    // addFilesLocal mirrors the File objects held module-side in add-files.js
    // (name/size only, so Alpine never proxies a File).
    addFilesOpen: false,
    addFilesQuery: '',
    addFilesStaged: [], // sample file paths (`${dir}/${name}`) queued to add
    addFilesRemove: [], // uids of loaded files queued for removal
    addFilesLocal: [], // [{name, size}] local files queued to add
    addFilesExpanded: {}, // sample id -> explicitly toggled open/closed
    addFilesError: '', // a failed batch, shown in the dialog it reopens
    _pendingDeepLink: null, // parsed share hash to apply once the sample finishes parsing
    sampleError: '',
    parsing: false, // true while loading/parsing a freshly loaded SBOM
    parseError: '',
    progress: 0, // 0..1 overall load progress (download → JSON → graph → index)
    progressPhase: '', // human-readable current phase label
    progressEta: null, // estimated seconds remaining, or null when unknown
    progressAnimateMs: 150, // progress-bar transition duration; widened so the bar
    // keeps sweeping (on the compositor) through the main thread's synchronous
    // graph/index phases instead of freezing (see _parseOnMainThread)
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
      supplychain: false,
      requirements: false,
      licenses: false,
      security: false,
      configs: false,
      build: false,
      agents: false,
      statistics: false,
      remediation: false,
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
      supplychain: 0,
      requirements: 0,
      licenses: 0,
      security: 0,
      configs: 0,
      build: 0,
      agents: 0,
      remediation: 0
    },
    // Start index of each view's rendered window; stays 0 for normal top-down
    // browsing and only moves when a deep link centers the window deep in a list.
    renderStarts: {
      packages: 0,
      ai: 0,
      dataset: 0,
      files: 0,
      hardware: 0,
      supplychain: 0,
      requirements: 0,
      licenses: 0,
      security: 0,
      configs: 0,
      build: 0,
      agents: 0,
      remediation: 0
    },
    // How many rows of an in-card "show more" list are currently revealed,
    // keyed by an arbitrary list id (e.g. a license's declaredBy list). Absent
    // keys use the base cap; each reveal grows the entry by a chunk. Keeps big
    // secondary lists (a license used by every package, a build's tens of
    // thousands of generated artifacts) from mounting all at once on view open.
    listReveal: {},
    isMac: /Mac|iPhone|iPad|iPod/.test(
      (typeof navigator !== 'undefined' && (navigator.platform || navigator.userAgent)) || ''
    ), // picks the ⌘ vs Ctrl glyph for the palette hint
    paletteOpen: false, // ⌘K / Ctrl-K command palette overlay
    paletteQuery: '', // the palette's search box
    paletteActiveIndex: 0, // keyboard-highlighted palette row
    packageSearch: '', // in-view filter for the Packages / AI / Datasets lists
    fileSearch: '', // in-view filter for the Files list
    hardwareSearch: '', // in-view filter for the Hardware list
    supplyChainSearch: '', // in-view filter for the Supply Chain list
    supplyChainFamilyFilter: '', // '' = all, else a supplyChainFamily key (create, move, …)
    supplyChainExceptionFilter: '', // '' = all, 'exception' | 'resolved'
    supplyChainViewMode: 'timeline', // Supply Chain angle: timeline | states | processes | custody | map
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
    expandedSupplyChain: null,
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
    securitySourceFilter: '', // '' = all, else 'sbom' | 'online' (data provenance)
    remediationCategoryFilter: '', // '' = all, else a remediation sourceCategory key
    remediationSeverityFilter: '', // '' = all, else critical/high/medium/low
    impactSearch: '', // Impact tab picker query
    impactFocus: null, // Impact tab: focused element spdxId, or null for the picker
    _impactHookOpenId: null, // element id whose inline Impact hook is expanded
    // CVE id -> { loading, error, data } fetched on demand from cve.org
    cveDetails: {},
    _affectedFileIndex: null, // memoized basename->File index for affected-file linking
    _affectedFileIndexFor: null, // the `files` array the index was built from
    _affectedFileLinksCache: null, // memoized CVE id -> AffectedFileLink[]
    // Bundled CVE affected-files index (built by scripts/build-cve-affected-index.mjs):
    // a static CVE id -> {f,r,m} map so affected files link offline, no per-CVE fetch.
    cveAffectedBundleUrl: './cve-affected/', // same-origin base URL of index.json
    cveAffectedBundle: null, // Map<cveId, {f?,r?,m?}> once loaded
    cveAffectedBundleStatus: 'idle', // idle | loading | done | absent
    cveAffectedGenerated: '', // bundle build date, shown in the Security UI
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
    supplyChain: [], // supplychain actions, processes, and states (SPDX 3.1)
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
    onlineVulns: [], // OSV/NVD findings merged into the security view (source online/both)
    nvdSource: readNvdSource(), // 'live' = NVD REST API, 'bundle' = hosted static index
    nvdBundleUrl: './nvd-cpe/', // same-origin base URL of the bundled index (manifest.json + parts)
    nvdBundleGenerated: '', // bundled-index build date (from meta.json), shown in the source hint
    // On-demand public-database lookup state: idle | running | done | error.
    // Per-provider progress lets one combined bar span OSV (purl) + NVD (cpe).
    onlineSync: {
      status: 'idle',
      error: '',
      findings: 0,
      ranAt: 0,
      startedAt: 0,
      osv: { active: false, phase: 'query', done: 0, total: 0 },
      nvd: { active: false, done: 0, total: 0 }
    },
    onlineNow: 0, // wall-clock tick (ms) driving the lookup ETA countdown
    // "Virtual" vulnerabilities: graph nodes/edges synthesized from online-only
    // scan findings so they show like SBOM vulns while staying flagged as scan
    // findings (not carried by the SBOM). Kept off elementMap so the element
    // count stays a true SBOM count.
    virtualVulnMap: new Map(), // online:<id> -> synthetic security_Vulnerability element
    virtualVulnElements: [], // the same synthetic elements, as a list (search corpus)
    virtualVexRelationships: [], // synthetic `affects` edges (vuln -> matched component)
    affectedFileRelationships: [], // inferred `affectsFile` edges (vuln -> matched File)
    resolvingAffectedFiles: false, // true while bulk-fetching CVE records for graph linkage
    affectedFilesProgress: { done: 0, total: 0 }, // bulk-resolve progress
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
    graphTransform: null, // last pan/zoom, so a rebuild can restore the user's view
    graphAutoFit: true, // reframe to fit on every rebuild until the user pans/zooms manually

    graphFilters: createGraphFilters(),
    // Lifecycle-scope filters (build / runtime / …). All active by default, so
    // the graph is unchanged until the user narrows to a scope.
    scopeFilters: createScopeFilters(),
    graphAggregate: false,
    graphUseIcons: false, // draw nodes as their type's Material icon instead of a plain dot
    // Layout algorithm: a GRAPH_LAYOUTS key deciding how the force sim positions
    // nodes (organic / hierarchy / radial / spotlight / lanes).
    graphLayout: 'organic',
    graphLayoutMenuOpen: false, // the toolbar layout picker popover
    graphHideOrphans: true, // hide nodes left with no edges once every other filter is applied
    // Heatmap overlay: 'off' or a HEAT_MODES key (vuln / failed / unverified).
    // Blooms a glow over the elements carrying that risk signal without touching
    // the base node/edge draw.
    graphHeatMode: 'off',
    graphHeatMenuOpen: false, // the toolbar heat-mode picker popover
    graphHeatModeList: [], // applicable modes + live counts, refreshed after loading and on menu open
    graphRecomputeHeat: null, // set by the graph renderer; repaints the heat layer without a rebuild
    expandedClusters: new Set(), // cluster keys the user has drilled into
    graphExpandedCount: 0, // reactive mirror of expandedClusters.size (Set mutations aren't tracked)
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

    // Main artifact: the primary build output the SBOM is about (zephyr.elf,
    // bzImage, ...). Detected on load, overridable from a detail card; drives the
    // graph "focus" lens that grays out non-contributing nodes.
    mainArtifactId: null, // selected element spdxId, or null
    mainArtifactCandidates: [], // ranked [{id, name, score, reasons}] for the current SBOM
    mainArtifactAuto: null, // the confidently auto-detected id (for the confirm banner)
    _mainArtifactWasAuto: false, // true when the current selection came from auto-detection
    mainArtifactBannerDismissed: false, // hides the auto-detect confirm banner
    graphFocusMainArtifact: true, // dim nodes/edges outside the artifact's contribution set
    graphRecomputeFocus: null, // set by the graph renderer; repaints the focus overlay without a rebuild

    // Statistics view: relationship repartition scope chip ('all' or a lifecycle scope).
    relationshipScopeFilter: 'all',

    // Views
    views: createViews()
  };
}
