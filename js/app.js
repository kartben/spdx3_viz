import { createGraphFilters, NODE_COLORS, EDGE_COLORS, createViews } from './config.js';
import {
  parseGraph,
  buildRelationshipIndexes,
  computeRelationshipTypeCounts,
  findBestTreeRoot
} from './parser.js';
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

export function spdxApp() {
  return {
    // State
    dataLoaded: false,
    loadedFiles: [], // [{name, data}] — one entry per loaded file
    currentView: 'dashboard',
    searchQuery: '',
    detailElement: null,
    expandedPkg: null,
    expandedFile: null,
    expandedConfig: null,
    configSearch: '',
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
    buildConfigs: [], // build configuration elements
    generatedArtifacts: [],

    // Graph state
    graphSim: null,
    graphSvg: null,
    graphZoom: null,
    graphFilters: createGraphFilters(),
    nodeColors: NODE_COLORS,
    edgeColors: EDGE_COLORS,

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
          try {
            const data = JSON.parse(ev.target.result);
            this.loadedFiles.push({ name: file.name, data });
          } catch (err) {
            alert('Error parsing ' + file.name + ': ' + err.message);
          }
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

    // Merge all loaded files and re-parse
    rebuildFromLoadedFiles() {
      const mergedGraph = [];
      this.loadedFiles.forEach((f) => {
        const graph = f.data['@graph'] || [];
        graph.forEach((item) => mergedGraph.push(item));
      });
      this.parseData(mergedGraph);
      // Re-render D3 views if currently active (they don't auto-update from Alpine reactivity)
      this.$nextTick(() => {
        if (this.currentView === 'graph') this.renderGraph();
        if (this.currentView === 'dependencies') this.renderDepTree();
      });
    },

    // Data parsing accepts a merged @graph array.
    parseData(graph) {
      const parsed = parseGraph(graph);
      Object.assign(this, parsed);

      const indexes = buildRelationshipIndexes(this.relationships);
      Object.assign(this, indexes);

      this.views.find((v) => v.id === 'packages').count = this.packages.length;
      this.views.find((v) => v.id === 'files').count = this.files.length;
      this.views.find((v) => v.id === 'configs').count = this.buildConfigs.length;
      this.treeRoot = findBestTreeRoot(this.packages, this.depIndex);
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

    getBuildConfigFor(targetSpdxId) {
      const configs = this.configuredBy(targetSpdxId);
      if (!configs.length) return null;
      return this.elementMap.get(configs[0].configId);
    },

    parseCompileFlags(config) {
      return parseBuildConfigFlags(config);
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
    navigateTo(spdxId) {
      const el = this.elementMap.get(spdxId);
      if (!el) return;
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
    selectGraphNode(spdxId) {
      const el = this.elementMap.get(spdxId);
      if (el) this.detailElement = el;
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
