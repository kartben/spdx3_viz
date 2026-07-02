import { computeRelationshipTypeCounts } from '../parser.js';

/* ==========================================================================
   Derived data
   Computed getters over the parsed model: the filtered/sorted list views, the
   security summary, and the small counts/labels the templates read.
   ========================================================================== */

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

export const derivedMixin = {
  // Clears the build + vulnerability sort memos. Called when fresh data is
  // applied (see parseData) so the next getter read recomputes from scratch.
  _resetListMemos() {
    filteredBuildsCacheKey = null;
    filteredVulnsCacheKey = null;
  },

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
