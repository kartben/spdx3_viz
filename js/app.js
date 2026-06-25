import { createGraphFilters, NODE_COLORS, EDGE_COLORS, createViews } from './config.js';
import { computeRelationshipTypeCounts, findBestTreeRoot } from './parser.js';
import {
  cleanName as formatSpdxName,
  cleanFileName as formatFileName,
  fileExt as getFileExtension,
  formatDate as formatDisplayDate,
  getRelationshipColor,
  getRelationshipGroupLabel,
  getRelationshipSortOrder,
  getRelationshipTargetDisplayName,
  getNodeType as resolveNodeType,
  getNodeTypeColor,
  getElementBadgeClass,
  parseCompileFlags as parseBuildConfigFlags,
  parseBuildParameters as parseBuildParameterGroups,
  getToolUsageCount,
  getToolPath,
  copyToClipboard
} from './utils.js';
import {
  renderGraph as renderGraphView,
  resetGraphZoom as resetGraphViewZoom
} from './graph-view.js';
import {
  renderDependencyTree,
  expandAllTree as expandDependencyTree,
  collapseAllTree as collapseDependencyTree
} from './dependency-tree.js';

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

function getParserWorker() {
  if (!parserWorker) {
    parserWorker = new Worker(new URL('./parser.worker.js', import.meta.url), { type: 'module' });
  }
  return parserWorker;
}

export function spdxApp() {
  return {
    // State
    dataLoaded: false,
    loadedFiles: [], // [{name, data}] — one entry per loaded file
    samples: [], // bundled demo sets, loaded from samples/samples.json
    loadingSample: null, // id of the sample currently being fetched
    sampleError: '',
    parsing: false, // true while the parser worker is crunching a freshly loaded SBOM
    parseError: '',
    currentView: 'dashboard',
    searchQuery: '',
    detailElement: null,
    expandedPkg: null,
    expandedFile: null,
    expandedConfig: null,
    expandedBuild: null,
    configSearch: '',
    buildSearch: '',
    buildSort: 'output',
    pkgSort: 'name',
    fileTypeFilter: '',
    toastMsg: '',
    treeRoot: '',
    treeDepth: 5,

    // Parsed data
    elementMap: new Map(),
    packages: [],
    files: [],
    tools: [],
    relationships: [],
    builds: [],
    buildInfo: null,
    agentInfo: null,
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
    buildConfigs: [], // build configuration elements
    generatedArtifacts: [],

    // Graph state
    graphSim: null,
    graphSvg: null,
    graphCanvasSel: null,
    graphZoom: null,
    graphFilters: createGraphFilters(),
    nodeColors: NODE_COLORS,
    edgeColors: EDGE_COLORS,
    graphAggregate: true, // collapse files/builds into hierarchical clusters by default
    expandedClusters: new Set(), // cluster keys the user has drilled into
    graphNodeCount: 0, // live readout of rendered nodes/edges
    graphEdgeCount: 0,
    graphTruncated: false, // true when the guard rail capped an un-aggregated render

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
          this.cleanName(a.spdxId).localeCompare(this.cleanName(b.spdxId))
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
      let buildList = this.builds;
      if (this.buildSearch) {
        const q = this.buildSearch.toLowerCase();
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
      if (this.buildSort === 'inputs') {
        sorted.sort(
          (a, b) => this.buildInputs(b.spdxId).length - this.buildInputs(a.spdxId).length
        );
      } else if (this.buildSort === 'buildId') {
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
      return sorted;
    },

    get fileTypes() {
      const exts = new Set(this.files.map((f) => this.fileExt(f.name)));
      return [...exts].sort();
    },

    get treeRootOptions() {
      return this.packages
        .map((p) => p.spdxId)
        .sort((a, b) => (this.dependentsOf(b)?.length || 0) - (this.dependentsOf(a)?.length || 0))
        .slice(0, 20);
    },

    // Init
    init() {
      this.$watch('currentView', (v) => {
        if (v === 'graph') this.$nextTick(() => this.renderGraph());
        if (v === 'dependencies') this.$nextTick(() => this.renderDepTree());
      });
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
      try {
        const loaded = [];
        for (const fname of sample.files) {
          const res = await fetch(`${sample.dir}/${fname}`);
          if (!res.ok) throw new Error(`${fname} (HTTP ${res.status})`);
          loaded.push({ name: fname, text: await res.text() });
        }
        this.loadedFiles = loaded; // replace — the drop zone starts empty
        this.rebuildFromLoadedFiles(); // existing merge + parse path
        this.dataLoaded = true;
      } catch (err) {
        this.sampleError = `Could not load ${sample.name}: ${err.message}`;
      } finally {
        this.loadingSample = null;
      }
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
      let remaining = fileList.length;
      fileList.forEach((file) => {
        const reader = new FileReader();
        reader.onload = (ev) => {
          // Store the raw text; JSON.parse happens in the worker so the main
          // thread never blocks on large files.
          this.loadedFiles.push({ name: file.name, text: ev.target.result });
          remaining--;
          if (remaining === 0) {
            this.rebuildFromLoadedFiles();
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
      this.parsing = true;
      this.parseError = '';

      worker.onmessage = (event) => {
        const { id, ok, parsed, indexes, error } = event.data || {};
        if (id !== latestParseReqId) return; // a newer load superseded this one
        this.parsing = false;

        if (!ok) {
          this.parseError = error || 'Failed to parse SBOM';
          alert('Error parsing SBOM: ' + this.parseError);
          return;
        }

        Object.assign(this, parsed);
        Object.assign(this, indexes);

        this.views.find((v) => v.id === 'packages').count = this.packages.length;
        this.views.find((v) => v.id === 'files').count = this.files.length;
        this.views.find((v) => v.id === 'configs').count = this.buildConfigs.length;
        this.views.find((v) => v.id === 'build').count = this.builds.length;
        this.treeRoot = findBestTreeRoot(this.packages, this.depIndex);
        this.expandedClusters = new Set(); // fresh data: start fully collapsed

        // Re-render D3 views if currently active (they don't auto-update from
        // Alpine reactivity).
        this.$nextTick(() => {
          if (this.currentView === 'graph') this.renderGraph();
          if (this.currentView === 'dependencies') this.renderDepTree();
        });
      };

      worker.onerror = (err) => {
        if (latestParseReqId !== reqId) return;
        this.parsing = false;
        this.parseError = err.message || 'Worker error';
        alert('Parser worker error: ' + this.parseError);
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
    toolPath(tool) {
      return getToolPath(tool);
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

      // Outgoing: this element → targets
      (this.relFromIndex.get(id) || []).forEach((rel) => {
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
    switchView(id) {
      this.currentView = id;
      this.detailElement = null;
    },
    togglePkg(id) {
      this.expandedPkg = this.expandedPkg === id ? null : id;
    },
    toggleFile(id) {
      this.expandedFile = this.expandedFile === id ? null : id;
    },
    toggleConfig(id) {
      this.expandedConfig = this.expandedConfig === id ? null : id;
    },
    toggleBuild(id) {
      this.expandedBuild = this.expandedBuild === id ? null : id;
    },
    navigateTo(spdxId) {
      const el = this.elementMap.get(spdxId);
      if (!el) {
        this.selectGraphNode(spdxId);
        return;
      }
      if (el.type === 'software_Package') {
        this.switchView('packages');
        this.expandedPkg = spdxId;
        this.$nextTick(() => {
          document
            .querySelector(`[x-text="cleanName(pkg.spdxId)"]`)
            ?.closest('.card')
            ?.scrollIntoView({ behavior: 'smooth', block: 'center' });
        });
      } else if (el.type === 'software_File') {
        // Check if it's a build config
        if (el.software_primaryPurpose === 'configuration' || spdxId?.includes('build-config')) {
          this.navigateToConfig(spdxId);
        } else {
          this.navigateToFile(spdxId);
        }
      } else if (el.type === 'build_Build') {
        this.navigateToBuild(spdxId);
      }
    },
    navigateToConfig(spdxId) {
      this.switchView('configs');
      this.expandedConfig = spdxId;
    },
    navigateToFile(spdxId) {
      this.switchView('files');
      this.expandedFile = spdxId;
    },
    navigateToBuild(spdxId) {
      this.switchView('build');
      this.expandedBuild = spdxId;
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
    collapseAllClusters() {
      this.expandedClusters = new Set();
      this.renderGraph();
    },
    resetGraphZoom() {
      resetGraphViewZoom(this);
    },

    // ========== DEPENDENCY TREE ==========
    renderDepTree() {
      renderDependencyTree(this);
    },
    expandAllTree() {
      expandDependencyTree(this);
    },
    collapseAllTree() {
      collapseDependencyTree(this);
    }
  };
}

if (typeof window !== 'undefined') {
  window.spdxApp = spdxApp;

  document.addEventListener('alpine:init', () => {
    window.Alpine.data('spdxApp', spdxApp);
  });
}
