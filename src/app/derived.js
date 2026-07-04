import { computeRelationshipTypeCounts } from '../parser/parser.js';
import { isA, CLASS } from '../spdx/model.js';

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
let filteredFilesCacheKey = null;
let filteredFilesCacheVal = [];

export const derivedMixin = {
  // Clears the build + vulnerability sort memos. Called when fresh data is
  // applied (see parseData) so the next getter read recomputes from scratch.
  _resetListMemos() {
    filteredBuildsCacheKey = null;
    filteredVulnsCacheKey = null;
    filteredFilesCacheKey = null;
  },

  get currentViewLabel() {
    return this.views.find((v) => v.id === this.currentView)?.label || '';
  },

  get relTypeCounts() {
    return computeRelationshipTypeCounts(this.relationships);
  },

  // AI models and dataset packages are software_Package subclasses (AI profile)
  // and get their own tabs, so the Packages tab lists only plain packages. All
  // three read the same search box + sort control (see _filterSortPackages).
  get aiPackages() {
    return this.packages.filter((p) => isA(p.type, CLASS.ai_AIPackage));
  },
  get datasetPackages() {
    return this.packages.filter((p) => isA(p.type, CLASS.dataset_DatasetPackage));
  },
  get plainPackages() {
    return this.packages.filter(
      (p) => !isA(p.type, CLASS.ai_AIPackage) && !isA(p.type, CLASS.dataset_DatasetPackage)
    );
  },

  // Applies the shared package search box + sort control to a base list. Used by
  // the Packages / AI Models / Datasets tabs so they behave identically.
  _filterSortPackages(base) {
    let pkgs = base;
    if (this.packageSearch) {
      const q = this.packageSearch.toLowerCase();
      pkgs = pkgs.filter(
        (p) =>
          this.cleanName(p.spdxId).toLowerCase().includes(q) || p.name?.toLowerCase().includes(q)
      );
    }
    if (this.pkgSort === 'deps')
      return [...pkgs].sort(
        (a, b) => (this.depsOf(b.spdxId)?.length || 0) - (this.depsOf(a.spdxId)?.length || 0)
      );
    if (this.pkgSort === 'dependents')
      return [...pkgs].sort(
        (a, b) =>
          (this.dependentsOf(b.spdxId)?.length || 0) - (this.dependentsOf(a.spdxId)?.length || 0)
      );
    return [...pkgs].sort((a, b) =>
      (a.name || this.cleanName(a.spdxId)).localeCompare(b.name || this.cleanName(b.spdxId))
    );
  },

  get filteredPackages() {
    return this._filterSortPackages(this.plainPackages);
  },

  get filteredAiPackages() {
    return this._filterSortPackages(this.aiPackages);
  },

  get filteredDatasetPackages() {
    return this._filterSortPackages(this.datasetPackages);
  },

  // The package list backing whichever of the three package-style tabs is
  // showing (packages / ai / dataset); [] elsewhere so the shared list template
  // renders nothing when another view is active.
  get currentPackageList() {
    switch (this.currentView) {
      case 'ai':
        return this.filteredAiPackages;
      case 'dataset':
        return this.filteredDatasetPackages;
      case 'packages':
        return this.filteredPackages;
      default:
        return [];
    }
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
    // search box, and the type-filter chip (see the cache note above).
    const search = this.fileSearch;
    const typeFilter = this.fileTypeFilter;
    const files = this.files;
    const key = `${files.length}|${search}|${typeFilter}`;
    if (key === filteredFilesCacheKey) return filteredFilesCacheVal;

    let fs = files;
    if (search) {
      const q = search.toLowerCase();
      fs = fs.filter((f) => f.name?.toLowerCase().includes(q));
    }
    if (typeFilter) {
      fs = fs.filter((f) => this.fileExt(f.name) === typeFilter);
    }
    const sorted = [...fs].sort((a, b) => (a.name || '').localeCompare(b.name || ''));

    filteredFilesCacheKey = key;
    filteredFilesCacheVal = sorted;
    return sorted;
  },

  // Hardware elements filtered by the in-view search box (name, part number,
  // summary) and sorted by name.
  get filteredHardware() {
    let hw = this.hardware;
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
    return [...hw].sort((a, b) =>
      (a.name || this.cleanName(a.spdxId)).localeCompare(b.name || this.cleanName(b.spdxId))
    );
  },

  // Breakdown of the functional-safety elements by kind, for the tab header
  // summary and to decide which kind-filter chips to show.
  get safetyCounts() {
    const c = { requirements: 0, verifications: 0, assumptions: 0, evaluations: 0 };
    this.requirements.forEach((r) => {
      if (isA(r.type, CLASS.Requirement)) c.requirements++;
      else if (isA(r.type, CLASS.functionalsafety_RequirementVerification)) c.verifications++;
      else if (isA(r.type, CLASS.functionalsafety_Assumption)) c.assumptions++;
      else if (isA(r.type, CLASS.functionalsafety_EvaluationResult)) c.evaluations++;
    });
    return c;
  },

  get filteredRequirements() {
    let reqs = this.requirements;
    // Kind filter chips (all / requirements / verifications / assumptions /
    // evaluations) let the folded-in artifacts be browsed on their own.
    if (this.requirementKindFilter) {
      reqs = reqs.filter((r) => r.type === this.requirementKindFilter);
    }
    if (this.requirementSearch) {
      const q = this.requirementSearch.toLowerCase();
      reqs = reqs.filter(
        (r) =>
          (r.name || '').toLowerCase().includes(q) ||
          this.cleanName(r.spdxId).toLowerCase().includes(q) ||
          (r.requirementStatement || '').toLowerCase().includes(q) ||
          (r.functionalsafety_assumptionStatement || '').toLowerCase().includes(q) ||
          (r.summary || '').toLowerCase().includes(q) ||
          this.externalIdentifiers(r).some((eid) => eid.identifier.toLowerCase().includes(q))
      );
    }
    const rank = (r) => (r.type === CLASS.Requirement ? 0 : 1);
    return [...reqs].sort(
      (a, b) =>
        rank(a) - rank(b) ||
        (a.name || this.cleanName(a.spdxId)).localeCompare(b.name || this.cleanName(b.spdxId))
    );
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
  // Memoized on those inputs so unrelated reactive changes don't re-sort.
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
    return this.graphFilters.filter((f) => (f.isRel ? relTypes.has(f.key) : nodeTypes.has(f.key)));
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

  get fileTypes() {
    const exts = new Set(this.files.map((f) => this.fileExt(f.name)));
    return [...exts].sort();
  }
};
