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
  collectCpeTargets,
  buildOnlineVulns
} from '../lib/index.js';

/* Long-lived lookup workers, kept off the reactive state so they are never
   proxied. One queries OSV by PackageURL, the other NVD by CPE. onlineReqSeq
   lets a fresh sync (or a new SBOM) ignore the results of an in-flight one. */
let osvWorker = null;
let nvdWorker = null;
let onlineReqSeq = 0;
/* Non-reactive accumulator for one lookup run: the raw provider findings and
   which providers are still running. Kept module-side so pushing findings does
   not churn Alpine reactivity. */
let onlineAccum = { reqId: 0, findings: [], pending: new Set() };

function getOsvWorker() {
  if (!osvWorker) {
    osvWorker = new Worker(new URL('../parser/osv.worker.js', import.meta.url), { type: 'module' });
  }
  return osvWorker;
}

function getNvdWorker() {
  if (!nvdWorker) {
    nvdWorker = new Worker(new URL('../parser/nvd.worker.js', import.meta.url), { type: 'module' });
  }
  return nvdWorker;
}

const NVD_KEY_STORAGE = 'spdx3viz.nvdApiKey';

/* Security / VEX: status and justification labels, per-package and
   per-vulnerability assessment lookups, on-demand fetch of CVE records, and the
   on-demand public-database lookup (OSV by PackageURL, NVD by CPE). */

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
  // --- Online public-database lookup (OSV by PURL, NVD by CPE) ------------

  // Components to scan. Packages are the canonical component inventory; both
  // purls (OSV) and CPEs (NVD) are read from them.
  _onlineScanElements() {
    return this.packages;
  },

  // True when the SBOM has at least one purl or CPE to look up. Short-circuits
  // so it stays cheap even on very large package lists.
  get canSyncOnline() {
    return this._onlineScanElements().some(
      (el) => this._purlOfElement(el) || this._cpeOfElement(el)
    );
  },

  // Presentation for a vulnerability's provenance badge (only shown once a
  // lookup has run). 'both' means the SBOM listed it and a public DB confirmed it.
  vulnSourceMeta(source) {
    switch (source) {
      case 'online':
        return {
          label: 'Online',
          badgeClass: 'bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/30',
          title: 'Found in a public database (OSV/NVD), not present in the SBOM'
        };
      case 'both':
        return {
          label: 'SBOM + online',
          badgeClass: 'bg-violet-500/15 text-violet-300 ring-1 ring-violet-500/30',
          title: 'Carried by the SBOM and also reported by a public database'
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
    return this.onlineVulns.length > 0 || this.onlineSync.status === 'done';
  },

  // 0–100 completion across whichever providers are still running. OSV runs a
  // query then a details phase (each half the bar); NVD is a single phase.
  get onlineProgress() {
    const s = this.onlineSync;
    const fr = [];
    if (s.osv.active) {
      const base = s.osv.total ? s.osv.done / s.osv.total : 0;
      fr.push(s.osv.phase === 'details' ? 0.5 + 0.5 * base : 0.5 * base);
    }
    if (s.nvd.active) fr.push(s.nvd.total ? s.nvd.done / s.nvd.total : 0);
    if (!fr.length) return 0;
    return Math.round((fr.reduce((a, b) => a + b, 0) / fr.length) * 100);
  },

  // Human label for the running phase, naming the active providers.
  get onlinePhaseLabel() {
    const s = this.onlineSync;
    const parts = [];
    if (s.osv.active)
      parts.push(s.osv.phase === 'details' ? 'fetching OSV advisories' : 'querying OSV');
    if (s.nvd.active) parts.push('matching NVD by CPE');
    return parts.length ? 'Checking: ' + parts.join(', ') + '…' : 'Checking public databases…';
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

  // The first CPE identifier of an element (cpe22 or cpe23), or ''.
  _cpeOfElement(el) {
    if (!el) return '';
    const ids = Array.isArray(el.externalIdentifier)
      ? el.externalIdentifier
      : el.externalIdentifier
        ? [el.externalIdentifier]
        : [];
    const c = ids.find(
      (e) =>
        e &&
        (e.externalIdentifierType === 'cpe22' || e.externalIdentifierType === 'cpe23') &&
        e.identifier
    );
    return c ? String(c.identifier).trim() : '';
  },

  // Resolves a matched component spdxId to a display record for the card.
  _resolveComponent(id) {
    const el = this.elementMap.get(id);
    return {
      spdxId: id,
      name: el?.name || this.cleanName(id),
      purl: this._purlOfElement(el),
      cpe: this._cpeOfElement(el)
    };
  },

  // Kicks off the public-database lookup: OSV for purls, NVD for CPEs, both in
  // workers, with combined progress.
  startOnlineSync() {
    if (this.onlineSync.status === 'running') return;
    const purlTargets = collectPurlTargets(this._onlineScanElements());
    const cpeTargets = collectCpeTargets(this._onlineScanElements());
    if (!purlTargets.length && !cpeTargets.length) {
      this.toastMsg = 'No PackageURL or CPE identifiers found to look up online.';
      setTimeout(() => (this.toastMsg = ''), 4000);
      return;
    }
    const reqId = ++onlineReqSeq;
    this._onlineReqId = reqId;
    onlineAccum = { reqId, findings: [], pending: new Set() };
    this.onlineSync = {
      status: 'running',
      error: '',
      findings: 0,
      ranAt: 0,
      osv: { active: purlTargets.length > 0, phase: 'query', done: 0, total: purlTargets.length },
      nvd: { active: cpeTargets.length > 0, done: 0, total: cpeTargets.length }
    };

    if (purlTargets.length) {
      onlineAccum.pending.add('OSV');
      const osv = getOsvWorker();
      osv.onmessage = (event) => this._onProviderMessage('OSV', reqId, event.data || {});
      osv.postMessage({ id: reqId, type: 'start', targets: purlTargets });
    }
    if (cpeTargets.length) {
      onlineAccum.pending.add('NVD');
      const nvd = getNvdWorker();
      nvd.onmessage = (event) => this._onProviderMessage('NVD', reqId, event.data || {});
      nvd.postMessage({
        id: reqId,
        type: 'start',
        targets: cpeTargets,
        apiKey: this.nvdApiKey || ''
      });
    }
  },

  // Handles a progress/done message from one provider worker.
  _onProviderMessage(provider, reqId, msg) {
    if (msg.id !== reqId || reqId !== this._onlineReqId) return; // superseded
    const key = provider === 'NVD' ? 'nvd' : 'osv';

    if (msg.type === 'progress') {
      const patch = { done: msg.done, total: msg.total };
      if (provider === 'OSV') patch.phase = msg.phase;
      this.onlineSync = {
        ...this.onlineSync,
        [key]: { ...this.onlineSync[key], ...patch }
      };
      return;
    }
    // type === 'done' for this provider
    this.onlineSync = {
      ...this.onlineSync,
      [key]: { ...this.onlineSync[key], active: false }
    };

    if (!msg.ok && !msg.cancelled) {
      // Record the provider's error but let the other provider finish.
      this.onlineSync = {
        ...this.onlineSync,
        error: `${provider}: ${msg.error || 'lookup failed'}`
      };
    } else if (msg.ok) {
      (msg.findings || []).forEach((f) => onlineAccum.findings.push({ ...f, provider }));
    }

    onlineAccum.pending.delete(provider);
    if (onlineAccum.pending.size === 0) this._finalizeOnline(msg.cancelled);
  },

  // Builds the merged online vulnerability list once every provider has finished.
  _finalizeOnline(cancelled) {
    if (cancelled && !onlineAccum.findings.length) {
      this.onlineSync = { ...this.onlineSync, status: 'idle' };
      return;
    }
    this.onlineVulns = buildOnlineVulns(onlineAccum.findings, (id) => this._resolveComponent(id));
    const hadError = !!this.onlineSync.error;
    this.onlineSync = {
      ...this.onlineSync,
      status: hadError && !this.onlineVulns.length ? 'error' : 'done',
      findings: this.onlineVulns.length,
      ranAt: Date.now()
    };
    this._resetListMemos();
    const secView = this.views.find((v) => v.id === 'security');
    if (secView) secView.count = this.allVulnerabilities.length;
    if (this.currentView === 'security') this.restreamView('security');
    if (hadError) {
      this.toastMsg = 'Some online sources failed: ' + this.onlineSync.error;
      setTimeout(() => (this.toastMsg = ''), 6000);
    }
  },

  // Cancels an in-flight lookup, leaving any prior results in place.
  cancelOnlineSync() {
    if (this.onlineSync.status !== 'running') return;
    if (osvWorker) osvWorker.postMessage({ id: this._onlineReqId, type: 'cancel' });
    if (nvdWorker) nvdWorker.postMessage({ id: this._onlineReqId, type: 'cancel' });
    this.onlineSync = { ...this.onlineSync, status: 'idle' };
  },

  // Persists the optional NVD API key (raises NVD's rate limit) to localStorage.
  setNvdApiKey(value) {
    this.nvdApiKey = String(value || '').trim();
    try {
      if (this.nvdApiKey) localStorage.setItem(NVD_KEY_STORAGE, this.nvdApiKey);
      else localStorage.removeItem(NVD_KEY_STORAGE);
    } catch {
      /* storage may be unavailable (private mode); the key still applies this session */
    }
  },

  // Clears online findings + lookup state (a fresh SBOM, or an explicit reset).
  resetOnlineSync() {
    if (this.onlineSync?.status === 'running') {
      if (osvWorker) osvWorker.postMessage({ id: this._onlineReqId, type: 'cancel' });
      if (nvdWorker) nvdWorker.postMessage({ id: this._onlineReqId, type: 'cancel' });
    }
    onlineReqSeq++;
    this._onlineReqId = onlineReqSeq;
    onlineAccum = { reqId: 0, findings: [], pending: new Set() };
    this.onlineVulns = [];
    this.securitySourceFilter = '';
    this.onlineSync = {
      status: 'idle',
      error: '',
      findings: 0,
      ranAt: 0,
      osv: { active: false, phase: 'query', done: 0, total: 0 },
      nvd: { active: false, done: 0, total: 0 }
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
