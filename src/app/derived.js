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

  // Rollup of every Requirement's overall verification outcome, for the
  // safety-case status bar and status-filter chips. `noImpl` counts requirements
  // carrying no implementedBy link (a traceability gap), and `verifiedPct` is the
  // share that reached a passing verification.
  get safetyStatusSummary() {
    const counts = { failed: 0, inconclusive: 0, unverified: 0, verified: 0, passed: 0 };
    let total = 0;
    let noImpl = 0;
    this.requirements.forEach((r) => {
      if (!isA(r.type, CLASS.Requirement)) return;
      total++;
      const status = this.requirementSafetyStatus(r);
      if (status && Object.hasOwn(counts, status.key)) counts[status.key]++;
      if (!this.implementedByCount(r.spdxId)) noImpl++;
    });
    return {
      total,
      counts,
      noImpl,
      verifiedPct: total ? Math.round((counts.passed / total) * 100) : 0
    };
  },

  // Verification statuses that actually occur, gaps-first, so the rollup bar and
  // chips never render empty buckets.
  get safetyStatusOrder() {
    const order = ['failed', 'inconclusive', 'unverified', 'verified', 'passed'];
    const counts = this.safetyStatusSummary.counts;
    return order.filter((s) => counts[s] > 0);
  },

  // Requirement decomposition graph from `tracedToDetail` relationships
  // (higher-level requirement -> more detailed requirements). Requirements never
  // appearing as a child become roots, so isolated requirements still show. Only
  // Requirement-typed endpoints are kept (verifications/assumptions are excluded).
  get safetyDecomposition() {
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
    return { childrenOf, roots, hasDecomposition: childrenOf.size > 0 };
  },

  get hasSafetyDecomposition() {
    return this.safetyDecomposition.hasDecomposition;
  },

  // Flattened, depth-annotated rows of the decomposition tree honoring
  // collapsedReqs, so the (recursive) tree renders through a single x-for.
  // Siblings sort by display name; a cycle guard stops a malformed graph looping.
  get safetyTreeRows() {
    const { childrenOf, roots } = this.safetyDecomposition;
    const nameOf = (id) => this.elementMap.get(id)?.name || this.cleanName(id);
    const sortIds = (ids) =>
      [...ids].sort((a, b) => nameOf(a).localeCompare(nameOf(b), undefined, { numeric: true }));
    const rows = [];
    const visit = (id, depth, ancestry) => {
      if (ancestry.has(id)) return;
      const kids = childrenOf.get(id) || [];
      const collapsed = !!this.collapsedReqs[id];
      rows.push({
        id,
        el: this.elementMap.get(id),
        depth,
        hasChildren: kids.length > 0,
        childCount: kids.length,
        collapsed
      });
      if (kids.length && !collapsed) {
        const next = new Set(ancestry).add(id);
        sortIds(kids).forEach((k) => visit(k, depth + 1, next));
      }
    };
    sortIds(roots).forEach((r) => visit(r, 0, new Set()));
    return rows;
  },

  get filteredRequirements() {
    let reqs = this.requirements;
    // Kind filter chips (all / requirements / verifications / assumptions /
    // evaluations) let the folded-in artifacts be browsed on their own.
    if (this.requirementKindFilter) {
      reqs = reqs.filter((r) => r.type === this.requirementKindFilter);
    }
    // Verification-status rollup chips filter Requirements by their outcome, or
    // by the 'noimpl' traceability gap (no implementedBy link).
    if (this.requirementStatusFilter === 'noimpl') {
      reqs = reqs.filter(
        (r) => isA(r.type, CLASS.Requirement) && !this.implementedByCount(r.spdxId)
      );
    } else if (this.requirementStatusFilter) {
      reqs = reqs.filter(
        (r) =>
          isA(r.type, CLASS.Requirement) &&
          this.requirementSafetyStatus(r)?.key === this.requirementStatusFilter
      );
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
    const severityFilter = this.securitySeverityFilter;
    const vulns = this.vulnerabilities;
    const key = `${vulns.length}|${search}|${sort}|${statusFilter}|${severityFilter}`;
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

  // True when at least one vulnerability carries an in-SBOM CVSS severity, so the
  // severity histogram/filter/badges only appear when there's data behind them.
  get hasCvssData() {
    return this.vulnerabilities.some((v) => v.severity);
  },

  // CVSS-severity histogram across all scored vulnerabilities, counted once each
  // by their headline severity. `scored` is the total that carry a CVSS band.
  get securitySeveritySummary() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, none: 0 };
    let scored = 0;
    this.vulnerabilities.forEach((v) => {
      // Only count the standard bands the chips/bar can render, so `scored`
      // never diverges from what the UI shows.
      if (!Object.hasOwn(counts, v.severity)) return;
      counts[v.severity]++;
      scored++;
    });
    return { scored, counts };
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
    return this.graphFilters.filter((f) => (f.isRel ? relTypes.has(f.key) : nodeTypes.has(f.key)));
  },

  // Lifecycle-scope legend entries for the scopes actually present in the data
  // (empty when the SBOM has no scoped relationships, which hides the row).
  get visibleScopeFilters() {
    const scopes = new Set(this.presentScopes);
    return this.scopeFilters.filter((f) => scopes.has(f.key));
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
  },

  // Agents (Person / Organization / SoftwareAgent) filtered by the in-view search
  // box (name, id, or email) and sorted either by how many elements they're tied
  // to — the most active creators/suppliers first — or by name.
  get filteredAgents() {
    let list = this.agents;
    if (this.agentSearch) {
      const q = this.agentSearch.toLowerCase();
      list = list.filter(
        (a) =>
          (a.name || '').toLowerCase().includes(q) ||
          this.cleanName(a.spdxId).toLowerCase().includes(q) ||
          (this.agentEmail(a) || '').toLowerCase().includes(q)
      );
    }
    if (this.agentSort === 'name') {
      return [...list].sort((a, b) =>
        (a.name || this.cleanName(a.spdxId)).localeCompare(b.name || this.cleanName(b.spdxId))
      );
    }
    return [...list].sort(
      (a, b) =>
        this.agentLinkCount(b) - this.agentLinkCount(a) ||
        (a.name || this.cleanName(a.spdxId)).localeCompare(b.name || this.cleanName(b.spdxId))
    );
  }
};
