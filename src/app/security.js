import {
  getVulnerabilityLookup,
  getVulnerabilityId,
  getVulnerabilityLocators,
  getVulnerabilityUrl,
  getVexStatusMeta,
  getVexJustificationLabel,
  getCvssSeverityMeta,
  summarizeCveRecord,
  buildFileIndex,
  linkAffectedFiles,
  annotateAffectedFiles,
  summarizeAffectedFiles,
  isRuledOutStatus,
  buildAffectedFileRelationships,
  collectPurlTargets,
  collectCpeTargets,
  buildOnlineVulns,
  buildVirtualVulnGraph,
  buildSecurityScope
} from '../lib/index.js';

// Above this many synthesized vuln edges, keep the graph's vulnerability nodes
// opt-in (mirrors the SBOM load path) so a large scan doesn't swamp the canvas.
const VIRTUAL_VEX_AUTO_SHOW_MAX = 200;

// Bulk "Resolve affected files" bounds: cap how many CVE records one run will
// fetch (so a huge advisory list can't hammer cve.org) and how many at once.
const AFFECTED_FILES_RESOLVE_MAX = 300;
const AFFECTED_FILES_RESOLVE_CONCURRENCY = 5;

// Memo for the scope walk. It touches the whole graph, so recomputing it on
// every keystroke in the search box would be felt on a large SBOM.
let scopeKey = null;
let scopeVal = null;

// Scope picker entries are capped: the dropdown is a search box, not a list to
// scroll, and a large SBOM has thousands of candidate packages.
const SCOPE_OPTION_LIMIT = 200;

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

/* vulnRecord's id lookup, memoized on the merged list's identity. The linear
   .find() it replaces ran once per rendered security row and again for every
   affected-file stat inside an expanded card: with thousands of
   vulnerabilities that multiplied into millions of comparisons per render. */
let vulnByIdSrc = null;
let vulnByIdVal = new Map();
/* Ticks `onlineNow` while a lookup runs so the ETA counts down smoothly
   between provider progress messages (NVD without a key is rate-limited to
   one request every ~6s). Cleared as soon as the run settles. */
let etaTimer = null;
function stopEtaTimer() {
  if (etaTimer) {
    clearInterval(etaTimer);
    etaTimer = null;
  }
}

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

/* Security / VEX: status and justification labels, per-package and
   per-vulnerability assessment lookups, on-demand fetch of CVE records, and the
   on-demand public-database lookup (OSV by PackageURL, NVD by CPE). */

export const securityMixin = {
  // Drops the scope walk's memo. Called when fresh data is applied, since the
  // key is only the scope choice: the graph underneath it has changed.
  _resetSecurityScopeMemo() {
    scopeKey = null;
    scopeVal = null;
  },

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
  // The full enriched vulnerability record for a vuln spdxId (or null). Searches
  // the merged list so online-only findings (spdxId `online:…`, absent from the
  // SBOM's own vulnerabilities) resolve too, otherwise expanding an online CVE
  // card would never trigger its cve.org fetch (and its referenced files).
  vulnRecord(spdxId) {
    const list = this.allVulnerabilities;
    if (vulnByIdSrc !== list) {
      vulnByIdVal = new Map(list.map((v) => [v.spdxId, v]));
      vulnByIdSrc = list;
    }
    return vulnByIdVal.get(spdxId) || null;
  },
  cvssSeverityMeta(severity) {
    return getCvssSeverityMeta(severity);
  },
  // Reactive fetch-state for a CVE's enriched details ({} until requested).
  cveDetail(cveId) {
    return this.cveDetails[cveId] || null;
  },
  // A basename->File index over the current document's files, rebuilt only when
  // the files array itself changes (i.e. a new SBOM loads). Backs the "affected
  // files" linking without rescanning every File on each render.
  _fileIndex() {
    if (this._affectedFileIndexFor !== this.files) {
      this._affectedFileIndex = buildFileIndex(this.files);
      this._affectedFileIndexFor = this.files;
      this._affectedFileLinksCache = {}; // a new file set invalidates every resolved link
    }
    return this._affectedFileIndex;
  },
  // A CVE's affected files/functions/modules, preferring the freshly fetched
  // record (what the card also shows) and falling back to the bundled index
  // (scripts/build-cve-affected-index.mjs) so the data is available offline and
  // in bulk without a per-CVE fetch. Returns null when neither source has it.
  affectedFilesFor(cveId) {
    const rec = this.cveDetail(cveId)?.data;
    if (rec) {
      return {
        affectedFiles: rec.affectedFiles || [],
        affectedRoutines: rec.affectedRoutines || [],
        affectedModules: rec.affectedModules || []
      };
    }
    const b = this.cveAffectedBundle?.get(cveId);
    if (b)
      return { affectedFiles: b.f || [], affectedRoutines: b.r || [], affectedModules: b.m || [] };
    return null;
  },
  // Resolves each affected source path a CVE declares to a File in this SBOM
  // (when one matches). Returns [] when neither the record nor the bundle has
  // affected files. Memoized per cveId (both cards call this several times per
  // render); the cache is dropped when the SBOM's files change (see _fileIndex),
  // when a record is fetched, and when the bundle loads, and a no-data CVE is
  // never cached, so a later source still resolves.
  affectedFileLinks(cveId) {
    const files = this.affectedFilesFor(cveId)?.affectedFiles;
    if (!files || !files.length) return [];
    const index = this._fileIndex(); // resolves the cache reset before we read it
    this._affectedFileLinksCache ||= {};
    if (!this._affectedFileLinksCache[cveId]) {
      this._affectedFileLinksCache[cveId] = linkAffectedFiles(files, index);
    }
    return this._affectedFileLinksCache[cveId];
  },
  // How many affected paths resolved to a File in this SBOM (drives the "N in
  // this SBOM" hint next to the affected-files list).
  affectedFileMatchCount(cveId) {
    return this.affectedFileLinks(cveId).filter((l) => l.linked).length;
  },
  // The CVE's affected files, annotated with the package that contains each
  // matched File and the VEX status that package carries for this vulnerability,
  // and ordered actionable-first. cveId keys the affected files; vulnSpdxId keys
  // the VEX lookup (a vuln's assessments live under its spdxId, not its CVE id).
  // Recomputed per call: the join is a handful of O(1) lookups over the already
  // memoized links, and staying uncached keeps it reactive to a later fetch.
  affectedFileDetails(cveId, vulnSpdxId) {
    const links = this.affectedFileLinks(cveId);
    if (!links.length) return links; // [] fast; nothing to annotate
    return annotateAffectedFiles(links, vulnSpdxId, {
      packageOf: (fileId) => {
        const pkgId = this.parentPackage(fileId);
        if (!pkgId) return null;
        const el = this.elementMap.get(pkgId);
        return { spdxId: pkgId, name: el?.name || this.cleanName(pkgId) };
      },
      assessmentsOf: (pkgId) => this.vexByPackage.get(pkgId) || [],
      // When a VEX clears the whole CVE for this SBOM, matched files inherit that
      // clearance so they don't read as an open issue under the "not an issue"
      // banner (their own sub-package rarely carries the product-level VEX).
      overallStatus: this.vulnRecord(vulnSpdxId)?.overallStatus || ''
    });
  },
  // Counts over a CVE's affected files relative to this SBOM (matched, ruled-out
  // by VEX, distinct owning packages). Backs the card subtitle and the
  // affected-files header badges.
  affectedFileStats(cveId, vulnSpdxId) {
    return summarizeAffectedFiles(this.affectedFileDetails(cveId, vulnSpdxId));
  },
  // The collapsed vulnerability card's one-line subtitle: the count of assessed
  // packages plus, once files are resolved, how many of the CVE's referenced
  // files land in this SBOM (noting any a VEX already clears).
  vulnCardSubtitle(vuln) {
    const pkgs = vuln.packageCount;
    const { matched, ruledOut } = this.affectedFileStats(vuln.cveId, vuln.spdxId);
    const parts = [];
    if (pkgs > 0) parts.push(`${this.formatCount(pkgs)} ${pkgs === 1 ? 'package' : 'packages'}`);
    if (matched > 0) {
      const files = `${this.formatCount(matched)} ${matched === 1 ? 'file' : 'files'}`;
      parts.push(ruledOut > 0 ? `${files} (${this.formatCount(ruledOut)} not an issue)` : files);
    }
    return parts.length ? parts.join(' · ') : 'Not linked to a package';
  },
  // The VEX status that clears this vulnerability for the whole SBOM
  // ('not_affected' or 'fixed'), or '' when at least one assessed package is
  // still affected / under investigation, or nothing has assessed it.
  // overallStatus is the most-severe status across assessments, so it only lands
  // on a clearing status when no assessment outranks it. Drives the card's
  // "not an issue" banner and reframes the referenced-files list as reference.
  vulnClearedByVex(vuln) {
    if (!vuln || !vuln.packageCount) return '';
    return isRuledOutStatus(vuln.overallStatus) ? vuln.overallStatus : '';
  },
  // Distinct packages a vulnerability is assessed against, for the card's
  // quick-jump chips. Deduped by spdxId and display-name sorted, so a security
  // card offers a one-click hop to every package it touches without scrolling to
  // the assessments section.
  vulnPackages(spdxId) {
    const seen = new Set();
    const out = [];
    for (const a of this.vexByVuln.get(spdxId) || []) {
      if (!a.packageId || seen.has(a.packageId)) continue;
      seen.add(a.packageId);
      out.push({ spdxId: a.packageId, name: this.relTargetDisplayName(a.packageId) });
    }
    return out.sort((x, y) => x.name.localeCompare(y.name));
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
      // A newly fetched record supersedes the bundle for this CVE, so drop its
      // memoized links and, if it names affected files, refresh the graph edges.
      if (this._affectedFileLinksCache) delete this._affectedFileLinksCache[cveId];
      if (this.cveDetails[cveId].data.affectedFiles.length) this._rebuildAffectedFileLinks();
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

  // 0–1 completion across whichever providers are still running. OSV runs a
  // query then a details phase (each half its share); NVD is a single phase.
  get _onlineFraction() {
    const s = this.onlineSync;
    const fr = [];
    if (s.osv.active) {
      const base = s.osv.total ? s.osv.done / s.osv.total : 0;
      fr.push(s.osv.phase === 'details' ? 0.5 + 0.5 * base : 0.5 * base);
    }
    if (s.nvd.active) fr.push(s.nvd.total ? s.nvd.done / s.nvd.total : 0);
    if (!fr.length) return 0;
    return fr.reduce((a, b) => a + b, 0) / fr.length;
  },

  // 0–100 completion, for the progress bar and its percentage label.
  get onlineProgress() {
    return Math.round(this._onlineFraction * 100);
  },

  // Rough "time left" for the running lookup, projected from how far it has
  // progressed since it started. Empty until there's enough signal to avoid a
  // wildly wrong first guess. onlineNow ticks every second so it counts down
  // smoothly between the (sometimes slow) provider progress messages.
  get onlineEta() {
    const s = this.onlineSync;
    if (s.status !== 'running' || !s.startedAt) return '';
    const frac = this._onlineFraction;
    if (frac <= 0.02) return ''; // too early to project reliably
    const elapsed = (this.onlineNow || Date.now()) - s.startedAt;
    if (elapsed < 1500) return '';
    const remainingMs = (elapsed * (1 - frac)) / frac;
    if (remainingMs <= 0) return '';
    return this.formatEta(remainingMs) + ' left';
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
    const now = Date.now();
    this.onlineSync = {
      status: 'running',
      error: '',
      findings: 0,
      ranAt: 0,
      startedAt: now,
      osv: { active: purlTargets.length > 0, phase: 'query', done: 0, total: purlTargets.length },
      nvd: { active: cpeTargets.length > 0, done: 0, total: cpeTargets.length }
    };
    this.onlineNow = now;
    stopEtaTimer();
    etaTimer = setInterval(() => {
      this.onlineNow = Date.now();
    }, 1000);

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
      // 'bundle' matches a statically-hosted index (no CORS/rate limits); 'live'
      // queries NVD's REST API directly.
      const bundle = this.nvdSource === 'bundle';
      // Resolve to an absolute URL against the page: a relative URL inside a
      // worker would otherwise resolve against the worker script's location.
      const baseUrl = bundle ? new URL(this.nvdBundleUrl, location.href).href : undefined;
      nvd.postMessage({
        id: reqId,
        type: 'start',
        mode: bundle ? 'bundle' : 'live',
        baseUrl,
        targets: cpeTargets
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
      // A partial run (e.g. some NVD products failed) still returns results, but
      // the gap is surfaced rather than hidden.
      if (msg.warning) this.onlineSync = { ...this.onlineSync, error: msg.warning };
    }

    onlineAccum.pending.delete(provider);
    if (onlineAccum.pending.size === 0) this._finalizeOnline(msg.cancelled);
  },

  // Builds the merged online vulnerability list once every provider has finished.
  _finalizeOnline(cancelled) {
    stopEtaTimer();
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
    this._rebuildVirtualVulns();
    this._resetSearchMemos(); // the corpus now includes the scan's virtual vulns
    const secView = this.views.find((v) => v.id === 'security');
    if (secView) secView.count = this.allVulnerabilities.length;
    if (this.currentView === 'security') this.restreamView('security');
    if (hadError) {
      this.toastMsg = 'Online lookup incomplete — ' + this.onlineSync.error;
      setTimeout(() => (this.toastMsg = ''), 6000);
    }
  },

  // Rebuilds the "virtual" vulnerability graph nodes/edges from the current
  // online-only findings: synthetic security_Vulnerability elements plus one
  // `affects` edge per matched component. Kept off elementMap (so the SBOM
  // element count is untouched) and exposed via virtualVulnMap for the graph and
  // detail panel to resolve. On the first run with findings, reveals the graph's
  // vulnerability nodes + `affects` edges the way a freshly loaded SBOM does, so
  // the scan's results are visible without hunting through the legend.
  _rebuildVirtualVulns() {
    const onlineOnly = this.allVulnerabilities.filter((v) => v.source === 'online');
    const { elements, relationships } = buildVirtualVulnGraph(onlineOnly);
    this.virtualVulnElements = elements;
    this.virtualVulnMap = new Map(elements.map((el) => [el.spdxId, el]));
    this.virtualVexRelationships = relationships;

    if (relationships.length && relationships.length < VIRTUAL_VEX_AUTO_SHOW_MAX) {
      // Only ever switch these on: never override a user who turned vuln nodes
      // off, but do surface a scan they explicitly asked for.
      this.graphFilters.forEach((f) => {
        if (f.key === 'vulnerability' || f.key === 'affects') f.active = true;
      });
    }
    // Repaint the canvas if the graph is on screen so the new nodes appear.
    if (this.currentView === 'graph') this.renderGraph();
  },

  // Drops every synthesized virtual-vuln node/edge (a reset, or a fresh SBOM).
  _clearVirtualVulns() {
    this.virtualVulnElements = [];
    this.virtualVulnMap = new Map();
    this.virtualVexRelationships = [];
    this.affectedFileRelationships = [];
    this.affectedFilesProgress = { done: 0, total: 0 };
  },

  // Rebuilds the inferred vulnerability -> file graph edges from every CVE record
  // fetched so far: each affected source path that resolves unambiguously to a
  // File in this SBOM becomes one dashed `affectsFile` edge. Kept off elementMap
  // (both endpoints already exist) and, for a small set, auto-revealed like the
  // virtual VEX edges so the linkage is visible without hunting the legend.
  _rebuildAffectedFileLinks() {
    const index = this._fileIndex();
    if (!index.size) {
      this.affectedFileRelationships = [];
      return;
    }
    const rels = buildAffectedFileRelationships(
      this.allVulnerabilities,
      (v) => this.affectedFilesFor(v.cveId)?.affectedFiles,
      index
    );
    this.affectedFileRelationships = rels;
    if (rels.length && rels.length < VIRTUAL_VEX_AUTO_SHOW_MAX) {
      // Only ever switch these on, never off: surface a link the user's action
      // (viewing a CVE, or Resolve) just produced, without overriding an opt-out.
      this.graphFilters.forEach((f) => {
        if (f.key === 'vulnerability' || f.key === 'affectsFile') f.active = true;
      });
    }
    if (this.currentView === 'graph') this.renderGraph();
  },

  // Whether bulk-resolving affected files can do anything: needs File elements to
  // match against and at least one CVE-identified vulnerability to link.
  get canResolveAffectedFiles() {
    return this._fileIndex().size > 0 && this.allVulnerabilities.some((v) => v.cveId);
  },

  // Loads the bundled CVE affected-files index once (a single static fetch that
  // covers every CVE), parsing it into a cveId -> {f,r,m} map. Marks the source
  // 'absent' if it isn't hosted, so callers fall back to the live cve.org fetch.
  async loadCveAffectedBundle() {
    if (this.cveAffectedBundleStatus === 'loading' || this.cveAffectedBundleStatus === 'done') {
      return;
    }
    this.cveAffectedBundleStatus = 'loading';
    const base = String(this.cveAffectedBundleUrl || './cve-affected/').replace(/\/?$/, '/');
    try {
      const res = await fetch(`${base}index.json`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      this.cveAffectedBundle = new Map(Object.entries(data.cves || {}));
      this.cveAffectedGenerated = data.generated || '';
      this.cveAffectedBundleStatus = 'done';
      this._affectedFileLinksCache = {}; // a new affected-files source invalidates cached links
    } catch {
      this.cveAffectedBundleStatus = 'absent';
    }
  },

  // Links affected files across the whole SBOM. Prefers the bundled index: one
  // fetch links every CVE instantly and offline. Only when the bundle isn't
  // hosted does it fall back to fetching CVE records from cve.org (bounded, so a
  // huge advisory list can't hammer the API).
  async resolveAffectedFilesForGraph() {
    if (this.resolvingAffectedFiles) return;

    // Bundle path: load once, then link everything from it.
    if (this.cveAffectedBundleStatus !== 'absent') {
      if (this.cveAffectedBundleStatus !== 'done') {
        this.resolvingAffectedFiles = true;
        this.affectedFilesProgress = { done: 0, total: 0 }; // indeterminate: single fetch
        try {
          await this.loadCveAffectedBundle();
        } finally {
          this.resolvingAffectedFiles = false;
        }
      }
      if (this.cveAffectedBundleStatus === 'done') {
        this._rebuildAffectedFileLinks();
        const n = this.affectedFileRelationships.length;
        this.toastMsg = n
          ? `Linked ${n} referenced file${n === 1 ? '' : 's'} to this SBOM (bundled index).`
          : 'No referenced files from these CVEs match files in this SBOM.';
        setTimeout(() => (this.toastMsg = ''), 5000);
        return;
      }
    }

    // Fallback: no bundle hosted — fetch records from cve.org (bounded).
    const cveIds = [...new Set(this.allVulnerabilities.map((v) => v.cveId).filter(Boolean))];
    const pending = cveIds.filter((id) => !this.cveDetails[id]);
    const capped = pending.slice(0, AFFECTED_FILES_RESOLVE_MAX);
    if (!capped.length) {
      this._rebuildAffectedFileLinks(); // records already cached; just (re)link
      const n = this.affectedFileRelationships.length;
      this.toastMsg = n
        ? `Linked ${n} referenced file${n === 1 ? '' : 's'} to this SBOM.`
        : 'No referenced files from these CVEs match files in this SBOM.';
      setTimeout(() => (this.toastMsg = ''), 5000);
      return;
    }
    this.resolvingAffectedFiles = true;
    this.affectedFilesProgress = { done: 0, total: capped.length };
    let cursor = 0;
    const worker = async () => {
      while (cursor < capped.length) {
        const id = capped[cursor++];
        await this.fetchCveDetails(id);
        this.affectedFilesProgress = {
          done: this.affectedFilesProgress.done + 1,
          total: capped.length
        };
      }
    };
    try {
      await Promise.all(Array.from({ length: AFFECTED_FILES_RESOLVE_CONCURRENCY }, worker));
    } finally {
      this.resolvingAffectedFiles = false;
      this._rebuildAffectedFileLinks();
      const n = this.affectedFileRelationships.length;
      const truncated = pending.length > capped.length ? ` (first ${capped.length} CVEs)` : '';
      this.toastMsg = n
        ? `Linked ${n} referenced file${n === 1 ? '' : 's'} to this SBOM${truncated}.`
        : `No referenced files matched files in this SBOM${truncated}.`;
      setTimeout(() => (this.toastMsg = ''), 6000);
    }
  },

  // Cancels an in-flight lookup, leaving any prior results in place.
  cancelOnlineSync() {
    if (this.onlineSync.status !== 'running') return;
    stopEtaTimer();
    if (osvWorker) osvWorker.postMessage({ id: this._onlineReqId, type: 'cancel' });
    if (nvdWorker) nvdWorker.postMessage({ id: this._onlineReqId, type: 'cancel' });
    this.onlineSync = { ...this.onlineSync, status: 'idle' };
  },

  // Persists the NVD source choice ('live' | 'bundle') to localStorage.
  setNvdSource(value) {
    this.nvdSource = value === 'bundle' ? 'bundle' : 'live';
    try {
      localStorage.setItem('spdx3viz.nvdSource', this.nvdSource);
    } catch {
      /* storage may be unavailable; the choice still applies this session */
    }
  },

  // Fetches the bundled index's tiny meta.json (once) to learn its build date,
  // shown in the NVD-source hint. Silent if the index isn't deployed (e.g. local
  // dev): the hint just omits the date. Not the multi-MB manifest.
  async ensureNvdBundleMeta() {
    if (this._nvdMetaFetched) return;
    this._nvdMetaFetched = true;
    try {
      const url = new URL('meta.json', new URL(this.nvdBundleUrl, location.href)).href;
      const res = await fetch(url);
      if (!res.ok) return;
      const meta = await res.json();
      if (meta && meta.generated) this.nvdBundleGenerated = String(meta.generated);
    } catch {
      /* index not hosted here, or offline; the hint drops the date */
    }
  },

  // Clears online findings + lookup state (a fresh SBOM, or an explicit reset).
  resetOnlineSync() {
    if (this.onlineSync?.status === 'running') {
      if (osvWorker) osvWorker.postMessage({ id: this._onlineReqId, type: 'cancel' });
      if (nvdWorker) nvdWorker.postMessage({ id: this._onlineReqId, type: 'cancel' });
    }
    stopEtaTimer();
    onlineReqSeq++;
    this._onlineReqId = onlineReqSeq;
    onlineAccum = { reqId: 0, findings: [], pending: new Set() };
    this.onlineVulns = [];
    this._clearVirtualVulns();
    this.securitySourceFilter = '';
    this.onlineSync = {
      status: 'idle',
      error: '',
      findings: 0,
      ranAt: 0,
      startedAt: 0,
      osv: { active: false, phase: 'query', done: 0, total: 0 },
      nvd: { active: false, done: 0, total: 0 }
    };
    this.onlineNow = 0;
    this._resetListMemos();
    this._resetSearchMemos(); // drop the virtual vulns from the search corpus
  },

  // ---- scope ---------------------------------------------------------------

  // The packages a finding has to touch to count, or null when the whole
  // document counts.
  //
  // "Applies to this artifact" is not the same question as "is reachable from
  // it". A Zephyr build declares every module in the manifest as an input, so
  // the dependency closure of zephyr_final names 164 of the sample's 165
  // packages and would filter out nothing. What separates them is whether a
  // component put a file into the image: see lib/security-scope.js.
  get securityScopeElements() {
    const focus = this.securityScope;
    if (!focus) return null;

    const key = `${focus}|${this.securityScopeReach}`;
    if (scopeKey === key && scopeVal) return scopeVal;

    const scope = buildSecurityScope({
      root: focus,
      reach: this.securityScopeReach,
      impactChildIndex: this.impactChildIndex,
      producedByBuildIndex: this.producedByBuildIndex,
      buildInputIndex: this.buildInputIndex,
      containsIndex: this.containsIndex,
      elementMap: this.elementMap,
      relFromIndex: this.relFromIndex,
      relToIndex: this.relToIndex
    });
    scopeKey = key;
    scopeVal = scope;
    return scope;
  },

  // Name for the scope chip in the toolbar.
  get securityScopeLabel() {
    if (!this.securityScope) return 'Whole document';
    return this.relTargetDisplayName(this.securityScope);
  },

  // The same scope as a noun phrase that reads inside a sentence.
  get securityScopeSentence() {
    if (!this.securityScope) return 'this document';
    const name = this.relTargetDisplayName(this.securityScope);
    return this.securityScopeReach === 'compiled'
      ? `what ${name} is built from`
      : `${name} and everything it declares`;
  },

  // How many packages the scope covers, and how many the contribution test
  // dropped. The gap is the point of the whole feature, so the UI states it.
  get securityScopeStats() {
    const scope = this.securityScopeElements;
    if (!scope) return null;
    return {
      packages: scope.packages.size,
      reached: scope.reachedPackages,
      dropped: Math.max(0, scope.reachedPackages - scope.packages.size)
    };
  },

  // Findings hidden by the current scope, for the "N hidden" note.
  get securityScopeHiddenCount() {
    if (!this.securityScope) return 0;
    return Math.max(0, this.allVulnerabilities.length - this.scopedVulnerabilities.length);
  },

  // Scoping needs a graph to walk; on a flat package list every closure is a
  // single node and the control would only ever empty the list.
  get canScopeSecurity() {
    return this.hasImpactData && this.packages.length > 0;
  },

  // Packages offerable as a scope. Build outputs come first: an image or an
  // archive is what someone actually ships, and so what they mean by "does this
  // apply to me". Everything else that pulls something in follows.
  get securityScopeOptions() {
    const query = this.securityScopeSearch.trim().toLowerCase();
    const options = [];
    for (const pkg of this.packages) {
      if (!this.impactChildIndex.has(pkg.spdxId)) continue;
      const label = this.relTargetDisplayName(pkg.spdxId);
      if (query && !label.toLowerCase().includes(query)) continue;
      options.push({
        id: pkg.spdxId,
        label,
        isArtifact: this._isBuiltArtifact(pkg.spdxId),
        deps: this.impactChildIndex.get(pkg.spdxId).length
      });
      if (options.length >= SCOPE_OPTION_LIMIT) break;
    }
    return options.sort(
      (a, b) =>
        Number(b.isArtifact) - Number(a.isArtifact) ||
        b.deps - a.deps ||
        a.label.localeCompare(b.label)
    );
  },

  // Whether a package is something a build produced, and so a candidate for
  // "what do I actually ship?". The build output is usually the binary rather
  // than the package that wraps it (zephyr_final contains zephyr.elf, and it is
  // the elf the Build profile names), so a package counts when it is a build
  // output or holds one.
  _isBuiltArtifact(spdxId) {
    if (this.producedByBuildIndex.has(spdxId)) return true;
    return (this.containsIndex.get(spdxId) || []).some((child) =>
      this.producedByBuildIndex.has(child)
    );
  },

  setSecurityScope(id) {
    this.securityScope = id || '';
    this.securityScopePickerOpen = false;
    this.securityScopeSearch = '';
    this.securityStatusFilter = '';
    this.securitySeverityFilter = '';
    this._resetListMemos?.();
    this.restreamView?.('security');
    this._scheduleNavPush?.();
  },

  setSecurityScopeReach(reach) {
    this.securityScopeReach = reach === 'declared' ? 'declared' : 'compiled';
    this.securityStatusFilter = '';
    this.securitySeverityFilter = '';
    this._resetListMemos?.();
    this.restreamView?.('security');
    this._scheduleNavPush?.();
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
