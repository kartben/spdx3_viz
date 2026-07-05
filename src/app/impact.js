import { provenancePaths, blastRadius, impactEdgeVerb, getCvssSeverityMeta } from '../lib/index.js';

/* Impact analysis: provenance ("why is this here?") and blast radius ("what
   depends on it?") over the parser's dependency adjacency, plus the Impact tab's
   whole-SBOM rankings. Heavy results are memoized off the reactive state and
   invalidated on load via _resetImpactMemos. */

let rankingsCacheKey = null;
let rankingsCacheVal = null;
let riskCacheKey = null;
let riskCacheVal = null;
const blastCache = new Map(); // element spdxId -> blastRadius result

export const impactMixin = {
  _resetImpactMemos() {
    rankingsCacheKey = null;
    riskCacheKey = null;
    blastCache.clear();
  },

  // True when the SBOM carries any dependency/containment structure to trace.
  // Gates the Impact tab and the inline hook so pure-license SBOMs show neither.
  get hasImpactData() {
    return (this.impactChildIndex?.size || 0) > 0 || (this.impactParentIndex?.size || 0) > 0;
  },

  // Graph entry points: declared rootElement ids present in the graph, falling
  // back to dependency-graph nodes that nothing depends on when none are declared.
  get impactRoots() {
    const declared = this.rootElementIds instanceof Set ? this.rootElementIds : new Set();
    const present = new Set();
    declared.forEach((id) => {
      if (this.elementMap.has(id)) present.add(id);
    });
    if (present.size) return present;
    const fallback = new Set();
    this.impactChildIndex.forEach((_, from) => {
      if (!this.impactParentIndex.has(from)) fallback.add(from);
    });
    return fallback;
  },

  _impactGraph() {
    return {
      childIndex: this.impactChildIndex,
      parentIndex: this.impactParentIndex,
      roots: this.impactRoots
    };
  },

  provenanceOf(id) {
    if (!id || !this.hasImpactData) return { reachable: false, paths: [] };
    return provenancePaths(id, this._impactGraph());
  },

  blastRadiusOf(id) {
    if (!id) return { direct: [], total: 0, nodes: new Set(), truncated: false };
    let cached = blastCache.get(id);
    if (!cached) {
      cached = blastRadius(id, { parentIndex: this.impactParentIndex });
      blastCache.set(id, cached);
    }
    return cached;
  },

  impactEdgeVerb(rel) {
    return impactEdgeVerb(rel);
  },

  // Whether to render the inline hook for an element — only for artifacts that
  // participate in the dependency graph (have a dependency, a dependent, or are a root).
  showImpactHook(el) {
    const id = el?.spdxId;
    if (!id || !this.hasImpactData) return false;
    return (
      this.impactParentIndex.has(id) || this.impactChildIndex.has(id) || this.impactRoots.has(id)
    );
  },

  // One-line summary for the collapsed hook: hops-from-root + direct-dependent count.
  impactSummary(el) {
    const id = el?.spdxId;
    if (!id) return null;
    const isRoot = this.impactRoots.has(id);
    const prov = isRoot ? { reachable: true, hops: 0 } : this.provenanceOf(id);
    const br = this.blastRadiusOf(id);
    return {
      isRoot,
      reachable: prov.reachable,
      hops: prov.hops ?? null,
      directCount: br.direct.length,
      total: br.total,
      truncated: br.truncated
    };
  },

  // One-line label for the collapsed hook.
  impactHookLabel(el) {
    const s = this.impactSummary(el);
    if (!s) return '';
    if (s.isRoot) return 'Top-level element';
    if (!s.reachable) return 'Not reachable from root';
    const hops = `${s.hops} hop${s.hops === 1 ? '' : 's'} from root`;
    const deps = s.directCount
      ? `${this.formatCount(s.directCount)} depend${s.directCount === 1 ? 's' : ''} on it`
      : 'nothing depends on it';
    return `${hops} · ${deps}`;
  },

  // Collapsed-by-default open state, keyed by element id so switching elements
  // re-collapses the hook without an explicit reset.
  isImpactHookOpen(el) {
    return !!el && this._impactHookOpenId === el.spdxId;
  },
  toggleImpactHook(el) {
    if (!el) return;
    this._impactHookOpenId = this._impactHookOpenId === el.spdxId ? null : el.spdxId;
  },

  // Per-package worst-CVSS aggregation (worst severity/score + distinct CVE count),
  // since a package commonly carries several vulnerabilities.
  get packageRiskIndex() {
    const key = `${this.vulnerabilities.length}|${this.packages.length}`;
    if (key === riskCacheKey) return riskCacheVal;
    const map = new Map();
    this.vulnerabilities.forEach((v) => {
      const rank = v.severityRank || 0;
      // Normalize a missing score to -1 so a valid CVSS 0.0 still compares correctly.
      const score = v.cvss?.score != null ? parseFloat(v.cvss.score) : -1;
      const seen = new Set();
      v.assessments.forEach((a) => {
        // Only count a package as at-risk when its VEX status says so: a CVE marked
        // fixed / not-affected for a package must not rank it as vulnerable.
        if (a.status !== 'affected' && a.status !== 'under_investigation') return;
        const pid = a.packageId;
        if (!pid || seen.has(pid)) return;
        seen.add(pid);
        let e = map.get(pid);
        if (!e) {
          e = { severity: '', score: null, rank: 0, vulnIds: new Set() };
          map.set(pid, e);
        }
        e.vulnIds.add(v.spdxId);
        const currentScore = e.score != null ? parseFloat(e.score) : -1;
        if (rank > e.rank || (rank === e.rank && score > currentScore)) {
          e.rank = rank;
          e.severity = v.severity;
          e.score = v.cvss?.score ?? null;
        }
      });
    });
    riskCacheKey = key;
    riskCacheVal = map;
    return map;
  },

  // Aggregated risk badge data for a package/element, or null when it has no
  // CVSS-scored vulnerabilities.
  packageRisk(id) {
    const e = id && this.packageRiskIndex.get(id);
    if (!e || !e.severity) return null;
    return {
      severity: e.severity,
      score: e.score,
      vulnCount: e.vulnIds.size,
      meta: getCvssSeverityMeta(e.severity)
    };
  },

  // Impact tab landing rankings: most-depended-upon (by transitive dependents)
  // and vulnerable-by-blast-radius. To stay cheap on huge SBOMs, most-depended-
  // upon is prefiltered by direct-dependent count before computing exact
  // transitive counts for the top candidates only.
  get impactRankings() {
    const key = `${this.impactParentIndex?.size || 0}|${this.vulnerabilities.length}|${this.packages.length}`;
    if (key === rankingsCacheKey) return rankingsCacheVal;

    const CANDIDATES = 40;
    const TOP = 8;
    const candidates = [];
    this.impactParentIndex.forEach((parents, id) => {
      if (this.elementMap.has(id)) {
        candidates.push({ id, direct: new Set(parents.map((p) => p.id)).size });
      }
    });
    candidates.sort((a, b) => b.direct - a.direct);
    const mostDependedUpon = candidates
      .slice(0, CANDIDATES)
      .map((c) => ({ id: c.id, total: this.blastRadiusOf(c.id).total }))
      .filter((c) => c.total > 0)
      .sort((a, b) => b.total - a.total)
      .slice(0, TOP);

    const vulnerable = [];
    this.packageRiskIndex.forEach((e, id) => {
      if (!e.severity) return;
      vulnerable.push({
        id,
        severity: e.severity,
        score: e.score,
        vulnCount: e.vulnIds.size,
        rank: e.rank,
        total: this.blastRadiusOf(id).total
      });
    });
    vulnerable.sort(
      (a, b) =>
        b.total - a.total ||
        b.rank - a.rank ||
        (parseFloat(b.score) || 0) - (parseFloat(a.score) || 0)
    );

    const val = {
      mostDependedUpon,
      maxTotal: mostDependedUpon[0]?.total || 1,
      vulnerable: vulnerable.slice(0, TOP)
    };
    rankingsCacheKey = key;
    rankingsCacheVal = val;
    return val;
  },

  // Impact tab focus (null = the landing rankings).
  get impactFocusElement() {
    return this.impactFocus
      ? this.elementMap.get(this.impactFocus) || this.placeholderElement(this.impactFocus)
      : null;
  },
  focusImpact(id) {
    if (!id) return;
    this.impactFocus = id;
    this.switchView('impact');
  },
  clearImpactFocus() {
    this.impactFocus = null;
  },

  // Provenance hops for the focused element / the hook, resolved to display data.
  impactProvenance(id) {
    const res = this.provenanceOf(id);
    if (!res.reachable || !res.paths?.length) return res;
    const resolve = (path) =>
      path.map((hop) => ({
        id: hop.id,
        name: this.relTargetDisplayName(hop.id),
        version: this.impactVersionOf(hop.id),
        type: this.impactNodeTypeOf(hop.id),
        rel: hop.rel,
        verb: hop.rel ? impactEdgeVerb(hop.rel) : '',
        soft: hop.soft,
        isRoot: this.impactRoots.has(hop.id)
      }));
    return {
      ...res,
      resolvedPaths: res.paths.map(resolve)
    };
  },

  impactNodeTypeOf(id) {
    const el = this.elementMap.get(id);
    return el ? this.getNodeType(el) : 'package';
  },

  // Package version for an impact node, or '' when absent. Surfaced alongside
  // the name so different versions of the same package stay distinguishable
  // (common in large distro SBOMs where one name ships many builds).
  impactVersionOf(id) {
    const ver = this.elementMap.get(id)?.software_packageVersion;
    return this.isMeaningful(ver) ? String(ver) : '';
  },

  // Name with the version appended, for one-line contexts (the sub-graph SVG
  // labels) where a separate muted span isn't practical.
  impactDisplayName(id) {
    const ver = this.impactVersionOf(id);
    const base = this.relTargetDisplayName(id);
    return ver ? `${base} ${ver}` : base;
  },

  // Direct + transitive dependents of the focused element, resolved for the
  // "what depends on it" list (transitive shown separately from direct).
  impactDependents(id) {
    const br = this.blastRadiusOf(id);
    const directIds = br.direct.map((d) => d.id);
    const directSet = new Set(directIds);
    const toEntry = (nid) => ({
      id: nid,
      name: this.relTargetDisplayName(nid),
      version: this.impactVersionOf(nid),
      type: this.impactNodeTypeOf(nid)
    });
    const byName = (a, b) => a.name.localeCompare(b.name);
    const transitive = [...br.nodes].filter((nid) => !directSet.has(nid));
    return {
      total: br.total,
      truncated: br.truncated,
      direct: directIds.map(toEntry).sort(byName),
      transitive: transitive.map(toEntry).sort(byName)
    };
  },

  // Imperatively renders the focused element's dependency sub-graph (the element
  // plus everything that depends on it) into `container` as a layered SVG. Kept
  // small and capped — for a big blast radius the textual list carries the detail.
  renderImpactSubgraph(container) {
    if (!container) return;
    container.innerHTML = '';
    const id = this.impactFocus;
    if (!id || !this.hasImpactData) return;
    const br = this.blastRadiusOf(id);
    const nodeIds = new Set([id, ...br.nodes]);
    const CAP = 160;
    if (nodeIds.size > CAP) {
      container.innerHTML = `<div class="text-xs text-slate-500 italic px-2 py-6 text-center">${br.total.toLocaleString()} dependents — too many to draw here. See the list above.</div>`;
      return;
    }

    const parentIndex = this.impactParentIndex;
    // Layer by BFS distance from the focused element over dependents.
    const dist = new Map([[id, 0]]);
    const queue = [id];
    let head = 0;
    while (head < queue.length) {
      const n = queue[head++];
      for (const p of parentIndex.get(n) || []) {
        if (nodeIds.has(p.id) && !dist.has(p.id)) {
          dist.set(p.id, dist.get(n) + 1);
          queue.push(p.id);
        }
      }
    }
    let maxL = 0;
    dist.forEach((d) => (maxL = Math.max(maxL, d)));
    const byLayer = new Map();
    nodeIds.forEach((nid) => {
      const l = dist.has(nid) ? dist.get(nid) : maxL;
      if (!byLayer.has(l)) byLayer.set(l, []);
      byLayer.get(l).push(nid);
    });

    const W = 900;
    const H = Math.max(
      220,
      Math.min(520, 60 + [...byLayer.values()].reduce((m, c) => Math.max(m, c.length), 0) * 26)
    );
    const PAD = 46;
    const pos = new Map();
    for (let l = 0; l <= maxL; l++) {
      const col = byLayer.get(l) || [];
      // Focus (layer 0) on the right, dependents fanning left.
      const x = PAD + (W - 2 * PAD) * (maxL ? (maxL - l) / maxL : 1);
      col.forEach((nid, i) => {
        const y = PAD + (H - 2 * PAD) * (col.length > 1 ? i / (col.length - 1) : 0.5);
        pos.set(nid, { x, y });
      });
    }

    const svgNS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(svgNS, 'svg');
    svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
    svg.setAttribute('class', 'w-full h-auto');

    // Edges among the impacted set (a depends-on b, both in the set).
    this.impactChildIndex.forEach((children, from) => {
      if (!pos.has(from)) return;
      children.forEach((c) => {
        if (!pos.has(c.id)) return;
        const a = pos.get(from);
        const b = pos.get(c.id);
        const line = document.createElementNS(svgNS, 'line');
        line.setAttribute('x1', a.x);
        line.setAttribute('y1', a.y);
        line.setAttribute('x2', b.x);
        line.setAttribute('y2', b.y);
        line.setAttribute('stroke', 'rgba(253,164,175,0.4)');
        line.setAttribute('stroke-width', '1');
        svg.appendChild(line);
      });
    });

    nodeIds.forEach((nid) => {
      const p = pos.get(nid);
      if (!p) return;
      const isTarget = nid === id;
      const circle = document.createElementNS(svgNS, 'circle');
      circle.setAttribute('cx', p.x);
      circle.setAttribute('cy', p.y);
      circle.setAttribute('r', isTarget ? 7 : 4.5);
      circle.setAttribute('fill', isTarget ? '#818cf8' : '#fda4af');
      if (isTarget) {
        circle.setAttribute('stroke', '#c7d2fe');
        circle.setAttribute('stroke-width', '2');
      }
      svg.appendChild(circle);
      if (isTarget || nodeIds.size <= 60) {
        const text = document.createElementNS(svgNS, 'text');
        text.setAttribute('x', p.x + 9);
        text.setAttribute('y', p.y + 3.5);
        text.setAttribute('fill', isTarget ? '#c7d2fe' : '#cbd5e1');
        text.setAttribute('font-size', isTarget ? '11' : '9.5');
        text.setAttribute('font-family', 'ui-monospace, monospace');
        text.textContent = this.impactDisplayName(nid);
        svg.appendChild(text);
      }
    });

    container.appendChild(svg);
  }
};
