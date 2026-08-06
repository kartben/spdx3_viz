import { SCOPE_META, SCOPE_ORDER } from '../config.js';
import {
  buildRemediationFindings,
  computeQualityReport,
  getRelationshipColor,
  gradeMeta,
  remediationCategoryMeta,
  scoreColor
} from '../lib/index.js';

/* Statistics tab: an SBOM quality score with a category breakdown and
   actionable "worst offender" insights, computed over the already-parsed
   model (see src/lib/quality.js — no extra parsing pass). */

const ALL_SCOPES = 'all';
const ALL_SCOPE_META = { key: ALL_SCOPES, label: 'All scopes', color: '#94a3b8' };
const countFmt = new Intl.NumberFormat();
const remediationCache = {
  key: null,
  value: []
};
// The quality report is derived purely from the parsed data (same inputs as the
// remediation cache), but the dashboard reads it many times per render and it
// costs a full pass over every element. Without this memo a huge SBOM re-ran
// that pass dozens of times on load, freezing the UI for many seconds.
const qualityReportCache = {
  key: null,
  value: null
};

function remediationCacheKey(data) {
  return [
    data.packages,
    data.files,
    data.licenses,
    data.vulnerabilities,
    data.requirements,
    data.relationships,
    data.externalMap,
    data.elementMap,
    data.relFromIndex,
    data.relToIndex,
    data.impactParentIndex
  ];
}

function sameRemediationKey(a, b) {
  return !!a && !!b && a.length === b.length && a.every((v, i) => v === b[i]);
}

function asTargets(to) {
  if (Array.isArray(to)) return to.filter(Boolean);
  return to ? [to] : [];
}

function scopeMeta(key) {
  return (
    SCOPE_META[key] || {
      key,
      label: key ? key[0].toUpperCase() + key.slice(1) : 'Scope',
      color: SCOPE_META.other.color
    }
  );
}

function pctLabel(value) {
  return `${value >= 10 ? value.toFixed(0) : value.toFixed(1)}%`;
}

function relationshipWeight(rel) {
  return asTargets(rel?.to).length || 0;
}

function buildRelationshipRepartition(app) {
  const relFilters = new Map(
    (app.graphFilters || []).filter((f) => f.isRel).map((f) => [f.key, f])
  );
  const typeScopeCounts = new Map();
  const scopeTotals = new Map();
  let allTotal = 0;

  [...(app.relationships || []), ...(app.vexRelationships || [])].forEach((rel) => {
    const type = rel?.relationshipType;
    const filter = relFilters.get(type);
    if (!filter) return;

    const count = relationshipWeight(rel);
    if (!count) return;

    const scope = rel.scope || 'unscoped';
    if (!typeScopeCounts.has(type)) typeScopeCounts.set(type, new Map());
    const scopeMap = typeScopeCounts.get(type);
    scopeMap.set(scope, (scopeMap.get(scope) || 0) + count);
    scopeTotals.set(scope, (scopeTotals.get(scope) || 0) + count);
    allTotal += count;
  });

  const hasLifecycleScopes = SCOPE_ORDER.some(
    (scope) => scope !== 'unscoped' && (scopeTotals.get(scope) || 0) > 0
  );
  const scopeOptions = [{ ...ALL_SCOPE_META, count: allTotal, pct: '100%' }];
  if (hasLifecycleScopes) {
    SCOPE_ORDER.forEach((key) => {
      const count = scopeTotals.get(key) || 0;
      if (!count) return;
      const meta = scopeMeta(key);
      scopeOptions.push({
        ...meta,
        count,
        pct: allTotal ? pctLabel((count / allTotal) * 100) : '0%'
      });
    });
  }

  const requestedScope = app.relationshipScopeFilter || ALL_SCOPES;
  const activeScope = scopeOptions.some((s) => s.key === requestedScope)
    ? requestedScope
    : ALL_SCOPES;
  const activeScopeMeta = activeScope === ALL_SCOPES ? ALL_SCOPE_META : scopeMeta(activeScope);
  const activeTotal = activeScope === ALL_SCOPES ? allTotal : scopeTotals.get(activeScope) || 0;

  const rows = [...typeScopeCounts.entries()]
    .map(([type, scopeMap]) => {
      const filter = relFilters.get(type);
      const typeTotal = [...scopeMap.values()].reduce((sum, count) => sum + count, 0);
      const count = activeScope === ALL_SCOPES ? typeTotal : scopeMap.get(activeScope) || 0;
      if (!count) return null;
      const pct = activeTotal ? (count / activeTotal) * 100 : 0;
      const scopeBreakdown = hasLifecycleScopes
        ? SCOPE_ORDER.flatMap((key) => {
            const scopeCount = scopeMap.get(key) || 0;
            if (!scopeCount) return [];
            const meta = scopeMeta(key);
            return [
              {
                ...meta,
                count: scopeCount,
                pct: typeTotal ? (scopeCount / typeTotal) * 100 : 0
              }
            ];
          })
        : [];

      return {
        type,
        label: filter?.label || type,
        count,
        total: typeTotal,
        pct,
        pctLabel: pctLabel(pct),
        color: filter?.color || getRelationshipColor(type),
        scopeBreakdown
      };
    })
    .filter(Boolean)
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));

  return {
    total: activeTotal,
    allTotal,
    activeScope,
    activeScopeLabel: activeScopeMeta.label,
    activeScopeColor: activeScopeMeta.color,
    scopeOptions,
    hasLifecycleScopes,
    rows
  };
}

export const statisticsMixin = {
  get qualityReport() {
    const key = remediationCacheKey(this);
    if (!sameRemediationKey(qualityReportCache.key, key)) {
      qualityReportCache.key = key;
      qualityReportCache.value = computeQualityReport(this);
    }
    return qualityReportCache.value;
  },
  get remediationFindings() {
    const key = remediationCacheKey(this);
    if (!sameRemediationKey(remediationCache.key, key)) {
      remediationCache.key = key;
      remediationCache.value = buildRemediationFindings(this);
    }
    return remediationCache.value;
  },
  get filteredRemediations() {
    let findings = this.remediationFindings;
    if (this.remediationCategoryFilter) {
      findings = findings.filter(
        (finding) => finding.sourceCategory === this.remediationCategoryFilter
      );
    }
    if (this.remediationSeverityFilter) {
      findings = findings.filter((finding) => finding.severity === this.remediationSeverityFilter);
    }
    return findings;
  },
  get remediationSummary() {
    const findings = this.remediationFindings;
    const counts = { critical: 0, high: 0, medium: 0, low: 0, other: 0 };
    findings.forEach((finding) => {
      const key = counts[finding.severity] == null ? 'other' : finding.severity;
      counts[key] += 1;
    });
    return {
      total: findings.length,
      counts,
      top: findings.slice(0, 8)
    };
  },
  get remediationCategoryOptions() {
    const counts = new Map();
    this.remediationFindings.forEach((finding) => {
      const key = finding.sourceCategory || 'other';
      counts.set(key, (counts.get(key) || 0) + 1);
    });
    return [...counts.entries()]
      .map(([key, count]) => ({ ...remediationCategoryMeta(key), count }))
      .sort((a, b) => a.order - b.order || a.label.localeCompare(b.label));
  },
  get remediationSeverityOptions() {
    const labels = {
      critical: 'Critical',
      high: 'High',
      medium: 'Medium',
      low: 'Low',
      other: 'Other'
    };
    return Object.entries(this.remediationSummary.counts)
      .filter(([, count]) => count > 0)
      .map(([key, count]) => ({ key, label: labels[key] || key, count }));
  },
  get relationshipRepartition() {
    if (!this._relationshipRepartitionCache) {
      this._relationshipRepartitionCache = {
        relationships: null,
        vexRelationships: null,
        scope: null,
        graphFilters: null,
        value: null
      };
    }
    const cache = this._relationshipRepartitionCache;
    if (
      cache.relationships === this.relationships &&
      cache.vexRelationships === this.vexRelationships &&
      cache.scope === this.relationshipScopeFilter &&
      cache.graphFilters === this.graphFilters
    ) {
      return cache.value;
    }

    const value = buildRelationshipRepartition(this);
    this._relationshipRepartitionCache = {
      relationships: this.relationships,
      vexRelationships: this.vexRelationships,
      scope: this.relationshipScopeFilter,
      graphFilters: this.graphFilters,
      value
    };
    return value;
  },
  qualityGradeMeta(grade) {
    return gradeMeta(grade);
  },
  qualityScoreColor(score) {
    return scoreColor(score);
  },
  remediationSeverityClass(severity) {
    return (
      {
        critical: 'bg-rose-500/20 text-rose-200 ring-1 ring-rose-400/40',
        high: 'bg-rose-500/15 text-rose-300 ring-1 ring-rose-500/30',
        medium: 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30',
        low: 'bg-blue-500/15 text-blue-300 ring-1 ring-blue-500/30'
      }[severity] || 'bg-slate-600/20 text-slate-300 ring-1 ring-slate-500/30'
    );
  },
  remediationCategoryMeta(category) {
    return remediationCategoryMeta(category);
  },
  setRemediationCategoryFilter(category) {
    this.remediationCategoryFilter = this.remediationCategoryFilter === category ? '' : category;
    this.restreamView('remediation');
  },
  setRemediationSeverityFilter(severity) {
    this.remediationSeverityFilter = this.remediationSeverityFilter === severity ? '' : severity;
    this.restreamView('remediation');
  },
  // Jump from a Statistics quality gap to the matching Remediation findings so
  // the offending components are enumerated in one place (Remediation) rather
  // than duplicated here. Filters Remediation to the gap's category.
  openRemediation(category = '') {
    this.remediationCategoryFilter = category || '';
    this.remediationSeverityFilter = '';
    this.switchView('remediation');
    this.restreamView('remediation');
  },
  // Conic-gradient ring for the overall-score gauge; a plain CSS circle so the
  // gauge needs no charting dependency.
  qualityRingStyle(score, color) {
    return `background: conic-gradient(${color} ${score * 3.6}deg, #334155 0deg)`;
  },
  setRelationshipScopeFilter(scope) {
    if (!this.relationshipRepartition.scopeOptions.some((s) => s.key === scope)) return;
    this.relationshipScopeFilter = scope;
    this.$nextTick(() => this.renderRelationshipChart());
  },
  scrollToStatsSection(id) {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  },
  renderStatisticsCharts() {
    this.renderRelationshipChart();
  },
  focusGraphRelationship(type, scope = this.relationshipRepartition.activeScope) {
    const relFilter = this.graphFilters.find((f) => f.isRel && f.key === type);
    if (!relFilter) return;

    this.graphFilters.forEach((f) => {
      f.active = f.isRel ? f.key === type : true;
    });

    const scopeKeys = new Set(this.relationshipRepartition.scopeOptions.map((s) => s.key));
    const narrowScope = scope && scope !== ALL_SCOPES && scopeKeys.has(scope);
    this.scopeFilters.forEach((f) => {
      f.active = !narrowScope || f.key === scope;
    });

    this.graphHideOrphans = true;
    this.graphSearchQuery = '';
    this.graphMatchCount = 0;
    this.detailElement = null;
    this.graphSelectedNodeId = null;

    const msg = `Graph focused on ${relFilter.label}${
      narrowScope ? ` · ${scopeMeta(scope).label}` : ''
    }`;
    this.switchView('graph');
    this.toastMsg = msg;
    setTimeout(() => {
      if (this.toastMsg === msg) this.toastMsg = '';
    }, 2400);
  },
  // The chart renderer (and d3 with it) loads on first use, mirroring the
  // mermaid pattern in renderSupplyChainStateDiagram: this mixin is imported at
  // startup, but only opening the Statistics view pays for d3.
  async renderRelationshipChart() {
    if (this.currentView !== 'statistics') return;

    const host = document.getElementById('relationshipRepartitionChart');
    if (!host) return;

    const { renderDonutChart } = await import('./statistics-chart.js');
    const data = this.relationshipRepartition;
    renderDonutChart({
      host,
      rows: data.rows,
      total: data.total,
      centerLabel: data.activeScopeLabel,
      centerColor: data.activeScopeColor,
      ariaLabel: 'Relationship type repartition chart',
      defaultHint: 'graph-visible edges',
      hoverHint: (row) => `${row.pctLabel} of ${data.activeScopeLabel}`,
      titleForRow: (row) =>
        `${row.label}: ${countFmt.format(row.count)} (${row.pctLabel}) - click to focus graph`,
      onClick: (row) => this.focusGraphRelationship(row.type, data.activeScope)
    });
  }
};
