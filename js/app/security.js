import {
  getVulnerabilityLookup,
  getVulnerabilityId,
  getVulnerabilityLocators,
  getVulnerabilityUrl,
  getVexStatusMeta,
  getVexJustificationLabel,
  getCvssSeverityMeta,
  summarizeCveRecord
} from '../utils.js';

/* ==========================================================================
   Security / VEX
   VEX status/justification labels, per-package and per-vulnerability
   assessment lookups, and the on-demand fetch of enriched CVE records.
   ========================================================================== */

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
  // Lazily fetch a CVE's public record the first time it's viewed (mirrors the
  // on-demand license-text fetch). Cached in this.cveDetails so re-opening a
  // card is instant and we never re-request. Data & terms: the CVE Program's
  // records are free to use and the SBOM already lists these API URLs as the
  // vulnerabilities' identifierLocators.
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
