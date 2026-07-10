import {
  getVulnerabilityLookup,
  getVulnerabilityId,
  getVulnerabilityLocators,
  getVulnerabilityUrl,
  getVexStatusMeta,
  getVexJustificationLabel,
  getCvssSeverityMeta,
  summarizeCveRecord,
  collectPurlTargets,
  toOnlineVuln
} from '../lib/index.js';

/* A single long-lived OSV lookup worker, kept off the reactive state so it is
   never proxied. osvReqSeq lets a fresh sync (or a new SBOM) ignore the results
   of an in-flight one. */
let osvWorker = null;
let osvReqSeq = 0;

function getOsvWorker() {
  if (!osvWorker) {
    osvWorker = new Worker(new URL('../parser/osv.worker.js', import.meta.url), { type: 'module' });
  }
  return osvWorker;
}

/* Security / VEX: status and justification labels, per-package and
   per-vulnerability assessment lookups, on-demand fetch of CVE records, and the
   on-demand OSV public-database lookup. */

export const securityMixin = {
  vulnLookup(eid) {
    return getVulnerabilityLookup(eid);
  },
  vexStatusMeta(status) {
    return getVexStatusMeta(status);
  },
  vexJustificationLabel(type) {
    return getVexJustificationLabel(type);
  },
  vulnId(el) {
    return getVulnerabilityId(el);
  },
  vulnUrl(el) {
    return getVulnerabilityUrl(el);
  },
  vulnLocators(el) {
    return getVulnerabilityLocators(el);
  },
  // VEX assessments for a package (its associated vulnerabilities + statuses).
  vulnsForPackage(spdxId) {
    return this.vexByPackage.get(spdxId) || [];
  },
  // Distinct-status counts for a package's vulnerabilities, ordered by severity.
  packageVulnSummary(spdxId) {
    const assessments = this.vulnsForPackage(spdxId);
    const byStatus = {};
    const seen = new Set(); // de-dupe (vuln, status) so one CVE counts once
    assessments.forEach((a) => {
      const k = a.vulnId + '|' + a.status;
      if (seen.has(k)) return;
      seen.add(k);
      (byStatus[a.status] ||= new Set()).add(a.vulnId);
    });
    const order = ['affected', 'under_investigation', 'not_affected', 'fixed', 'unknown'];
    const total = new Set(assessments.map((a) => a.vulnId)).size;
    return {
      total,
      statuses: order
        .filter((s) => byStatus[s])
        .map((s) => ({ status: s, count: byStatus[s].size, meta: getVexStatusMeta(s) }))
    };
  },
  // The full enriched vulnerability record for a vuln spdxId (or null).
  vulnRecord(spdxId) {
    return this.vulnerabilities.find((v) => v.spdxId === spdxId) || null;
  },
  cvssSeverityMeta(severity) {
    return getCvssSeverityMeta(severity);
  },
  // Reactive fetch-state for a CVE's enriched details ({} until requested).
  cveDetail(cveId) {
    return this.cveDetails[cveId] || null;
  },
  // Lazily fetch a CVE's public record the first time it's viewed, cached in
  // this.cveDetails so re-opening a card is instant and we never re-request.
  ensureCveDetails(cveId) {
    if (!cveId || !/^CVE-\d{4}-\d+$/i.test(cveId)) return;
    if (this.cveDetails[cveId]) return; // cached or already in flight
    this.fetchCveDetails(cveId);
  },
  async fetchCveDetails(cveId) {
    this.cveDetails[cveId] = { loading: true, error: '', data: null };
    try {
      const res = await fetch(`https://cveawg.mitre.org/api/cve/${encodeURIComponent(cveId)}`);
      if (!res.ok) {
        throw new Error(
          res.status === 404 ? 'Not found in the CVE database' : `Request failed (${res.status})`
        );
      }
      const record = await res.json();
      this.cveDetails[cveId] = { loading: false, error: '', data: summarizeCveRecord(record) };
    } catch (err) {
      this.cveDetails[cveId] = {
        loading: false,
        error: err?.message || 'Could not load CVE details',
        data: null
      };
    }
  },
  // --- OSV online lookup -------------------------------------------------

  // Components carrying a PackageURL, which OSV can match on. Files can carry a
  // purl too, but packages are the canonical component inventory.
  _osvScanElements() {
    return this.packages;
  },

  // True when the loaded SBOM has at least one purl to look up. Short-circuits on
  // the first purl so it stays cheap even on very large package lists.
  get canSyncOsv() {
    return this._osvScanElements().some((el) => this._purlOfElement(el));
  },

  // Presentation for a vulnerability's provenance badge (only shown once an OSV
  // lookup has run). 'both' means the SBOM listed it and OSV confirmed it.
  vulnSourceMeta(source) {
    switch (source) {
      case 'online':
        return {
          label: 'Online',
          badgeClass: 'bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/30',
          title: 'Found in OSV.dev, not present in the SBOM'
        };
      case 'both':
        return {
          label: 'SBOM + OSV',
          badgeClass: 'bg-violet-500/15 text-violet-300 ring-1 ring-violet-500/30',
          title: 'Carried by the SBOM and also reported by OSV.dev'
        };
      default:
        return {
          label: 'In SBOM',
          badgeClass: 'bg-slate-600/25 text-slate-300 ring-1 ring-slate-500/30',
          title: 'Carried by the SBOM document'
        };
    }
  },

  // True once a lookup has produced (or attempted) online results, which gates
  // the source badges/filters so the view is unchanged until the user syncs.
  get hasOnlineData() {
    return this.onlineVulns.length > 0 || this.osvSync.status === 'done';
  },

  // 0–100 completion for the progress bar across both lookup phases.
  get osvProgress() {
    const s = this.osvSync;
    return s.total ? Math.round((s.done / s.total) * 100) : 0;
  },

  // The purl of an element (scalar property or packageUrl externalIdentifier).
  _purlOfElement(el) {
    if (!el) return '';
    if (el.software_packageUrl) return String(el.software_packageUrl).trim();
    const ids = Array.isArray(el.externalIdentifier)
      ? el.externalIdentifier
      : el.externalIdentifier
        ? [el.externalIdentifier]
        : [];
    const p = ids.find((e) => e && e.externalIdentifierType === 'packageUrl' && e.identifier);
    return p ? String(p.identifier).trim() : '';
  },

  // Kicks off an OSV lookup for every component purl, in a worker, with progress.
  startOsvSync() {
    if (this.osvSync.status === 'running') return;
    const targets = collectPurlTargets(this._osvScanElements());
    if (!targets.length) {
      this.toastMsg = 'No PackageURL (purl) identifiers found to look up online.';
      setTimeout(() => (this.toastMsg = ''), 4000);
      return;
    }
    const reqId = ++osvReqSeq;
    this._osvReqId = reqId;
    this.osvSync = {
      status: 'running',
      phase: 'query',
      done: 0,
      total: targets.length,
      error: '',
      findings: 0,
      queried: targets.length,
      ranAt: 0
    };

    const worker = getOsvWorker();
    worker.onmessage = (event) => {
      const msg = event.data || {};
      if (msg.id !== this._osvReqId) return; // superseded by a newer sync/SBOM

      if (msg.type === 'progress') {
        this.osvSync = { ...this.osvSync, phase: msg.phase, done: msg.done, total: msg.total };
        return;
      }
      // type === 'done'
      if (!msg.ok) {
        if (msg.cancelled) {
          this.osvSync = { ...this.osvSync, status: 'idle' };
          return;
        }
        this.osvSync = { ...this.osvSync, status: 'error', error: msg.error || 'Lookup failed' };
        this.toastMsg = 'Online lookup failed: ' + (msg.error || 'unknown error');
        setTimeout(() => (this.toastMsg = ''), 5000);
        return;
      }
      this._applyOsvFindings(msg.findings || []);
      this.osvSync = {
        ...this.osvSync,
        status: 'done',
        phase: 'done',
        findings: (msg.findings || []).length,
        ranAt: Date.now()
      };
      const secView = this.views.find((v) => v.id === 'security');
      if (secView) secView.count = this.allVulnerabilities.length;
      // Re-stream the list so newly merged findings render, even when the view
      // was mounted empty (an SBOM with no VEX data at all).
      if (this.currentView === 'security') this.restreamView('security');
    };
    worker.postMessage({ id: reqId, type: 'start', targets });
  },

  // Cancels an in-flight lookup, leaving any prior results in place.
  cancelOsvSync() {
    if (this.osvSync.status !== 'running') return;
    if (osvWorker) osvWorker.postMessage({ id: this._osvReqId, type: 'cancel' });
    this.osvSync = { ...this.osvSync, status: 'idle' };
  },

  // Turns worker findings (normalized OSV record + matched element ids) into
  // card-ready online vulnerabilities, resolving element display names locally.
  _applyOsvFindings(findings) {
    this.onlineVulns = findings.map((f) => {
      const matched = (f.elementIds || []).map((id) => {
        const el = this.elementMap.get(id);
        return { spdxId: id, name: el?.name || this.cleanName(id), purl: this._purlOfElement(el) };
      });
      return toOnlineVuln(f, matched);
    });
    this._resetListMemos();
  },

  // Clears online findings + lookup state (a fresh SBOM, or an explicit reset).
  resetOsvSync() {
    if (osvWorker && this.osvSync.status === 'running') {
      osvWorker.postMessage({ id: this._osvReqId, type: 'cancel' });
    }
    osvReqSeq++;
    this._osvReqId = osvReqSeq;
    this.onlineVulns = [];
    this.securitySourceFilter = '';
    this.osvSync = {
      status: 'idle',
      phase: '',
      done: 0,
      total: 0,
      error: '',
      findings: 0,
      queried: 0,
      ranAt: 0
    };
    this._resetListMemos();
  },

  // Deduplicated, severity-sorted assessments for a vulnerability detail view.
  assessmentsForVuln(spdxId) {
    const list = this.vexByVuln.get(spdxId) || [];
    const sev = { affected: 4, under_investigation: 3, not_affected: 2, fixed: 1, unknown: 0 };
    return [...list].sort(
      (a, b) =>
        (sev[b.status] || 0) - (sev[a.status] || 0) ||
        this.relTargetDisplayName(a.packageId).localeCompare(this.relTargetDisplayName(b.packageId))
    );
  }
};
