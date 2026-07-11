/**
 * Security / VEX helpers: vulnerability ids, locators, VEX status/justification
 * metadata, CVSS severity, and CVE record summaries.
 *
 * @module lib/security
 */
import {
  COLORS,
  CVSS_SEVERITIES,
  VEX_STATUSES,
  VEX_STATUS_BY_REL,
  VEX_JUSTIFICATION_LABELS
} from '../config.js';
import { cleanName, isMeaningfulValue } from './format.js';

/**
 * Extracts the display id (preferring a CVE identifier) for a security_Vulnerability.
 *
 * @param {Object} el - The security_Vulnerability element
 * @returns {string} e.g. 'CVE-2023-25584', or the cleaned spdxId tail as a fallback
 */
export function getVulnerabilityId(el) {
  const ids = el?.externalIdentifier;
  if (Array.isArray(ids)) {
    const cve = ids.find(
      (i) => i && /cve/i.test(i.externalIdentifierType || '') && isMeaningfulValue(i.identifier)
    );
    if (cve) return String(cve.identifier).trim();
    const any = ids.find((i) => i && isMeaningfulValue(i.identifier));
    if (any) return String(any.identifier).trim();
  }
  const tail = String(el?.spdxId || '')
    .split('/')
    .pop();
  return tail || cleanName(el?.spdxId);
}

/**
 * Collects followable reference URLs for a vulnerability from its
 * externalIdentifier[].identifierLocator entries, adding a cve.org record link
 * when the id is a CVE and no authoritative link is present.
 *
 * @param {Object} el - The security_Vulnerability element
 * @returns {string[]} De-duplicated http(s) URLs
 */
export function getVulnerabilityLocators(el) {
  const out = [];
  const seen = new Set();
  const push = (url) => {
    if (typeof url === 'string' && /^https?:\/\//i.test(url) && !seen.has(url)) {
      seen.add(url);
      out.push(url);
    }
  };
  (el?.externalIdentifier || []).forEach((eid) => {
    (eid?.identifierLocator || []).forEach(push);
  });
  const cve = getVulnerabilityId(el);
  if (/^CVE-\d{4}-\d+$/i.test(cve) && !out.some((u) => /cve\.org|nvd\.nist\.gov/i.test(u))) {
    push(`https://www.cve.org/CVERecord?id=${cve}`);
  }
  return out;
}

/**
 * Best single "canonical" reference URL for a vulnerability (prefers cve.org /
 * NVD), or '' when none is available.
 *
 * @param {Object} el - The security_Vulnerability element
 * @returns {string}
 */
export function getVulnerabilityUrl(el) {
  const locs = getVulnerabilityLocators(el);
  return locs.find((u) => /cve\.org|nvd\.nist\.gov/i.test(u)) || locs[0] || '';
}

/**
 * Presentation metadata (label, colors, severity) for a normalized VEX status.
 * Falls back to a neutral descriptor for unknown statuses.
 *
 * @param {string} status - 'fixed' | 'not_affected' | 'affected' | 'under_investigation'
 * @returns {{key: string, label: string, color: string, badgeClass: string, dotClass: string, severity: number}}
 */
export function getVexStatusMeta(status) {
  return (
    VEX_STATUSES[status] || {
      key: status || 'unknown',
      label: 'No VEX status',
      color: COLORS.default,
      badgeClass: 'bg-slate-600/20 text-slate-300 ring-1 ring-slate-500/30',
      dotClass: 'bg-slate-500',
      severity: 0
    }
  );
}

/**
 * Maps a VEX assessment relationship's relationshipType to a normalized status key.
 *
 * @param {string} relationshipType - e.g. 'fixedIn'
 * @returns {string|null}
 */
export function vexStatusForRel(relationshipType) {
  return VEX_STATUS_BY_REL[relationshipType] || null;
}

/**
 * Human-readable label for a VexJustificationType value.
 *
 * @param {string} type
 * @returns {string}
 */
export function getVexJustificationLabel(type) {
  if (!type) return '';
  return VEX_JUSTIFICATION_LABELS[type] || type;
}

/**
 * Presentation metadata for a CVSS qualitative severity rating. Accepts either
 * spelling (`HIGH` from a fetched CVE record, or `high` from an in-SBOM CVSS
 * assessment relationship).
 *
 * @param {string} severity - critical | high | medium | low | none
 * @returns {{key: string, label: string, color: string, badgeClass: string, dotClass: string, rank: number}}
 */
export function getCvssSeverityMeta(severity) {
  return (
    CVSS_SEVERITIES[String(severity || '').toLowerCase()] || {
      key: 'unknown',
      label: severity || 'Unknown',
      color: COLORS.default,
      badgeClass: 'bg-slate-600/20 text-slate-300 ring-1 ring-slate-500/30',
      dotClass: 'bg-slate-500',
      rank: 0
    }
  );
}

/**
 * Normalizes a CVSS base score to its qualitative severity band, used as a
 * fallback when an assessment omits an explicit severity. CVSS v2 has no
 * Critical band (Low/Medium/High only), so a v2 score never maps above High.
 *
 * @param {number} score
 * @param {string} [version] - CVSS version (e.g. '2.0', '3.1'); v2 caps at High
 * @returns {string} critical | high | medium | low | none
 */
export function cvssSeverityForScore(score, version = '') {
  if (!Number.isFinite(score)) return '';
  if (score >= 9 && !String(version).startsWith('2')) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'none';
}

/**
 * Distills the non-VEX vulnerability assessment relationships attached to a
 * single vulnerability (CVSS, EPSS, exploit-catalog) into the headline risk
 * signals the UI badges. All of it comes straight from the SBOM — no network.
 *
 * @param {Array<Object>} assessments - security_*VulnAssessmentRelationship elements
 * @returns {{cvss: (Object|null), epss: (Object|null), kev: boolean, severity: string, severityRank: number}}
 */
export function summarizeVulnAssessments(assessments) {
  let cvss = null;
  let epss = null;
  let kev = false;

  (assessments || []).filter(Boolean).forEach((a) => {
    const type = a.type || '';
    if (/Cvss/.test(type)) {
      const score = parseFloat(a.security_score);
      const numeric = Number.isFinite(score) ? score : null;
      const versionMatch = /CVSS:(\d(?:\.\d)?)/i.exec(a.security_vectorString || '');
      const version = versionMatch ? versionMatch[1] : (/CvssV(\d)/i.exec(type)?.[1] ?? '');
      // Map common distro synonyms (Red Hat's moderate/important) onto the
      // standard bands; fall back to the score when the label is unrecognized.
      let severity = String(a.security_severity || '').toLowerCase();
      if (severity === 'moderate') severity = 'medium';
      else if (severity === 'important') severity = 'high';
      if (!CVSS_SEVERITIES[severity]) severity = cvssSeverityForScore(numeric, version);
      const cand = { score: numeric, severity, vector: a.security_vectorString || '', version };
      if (!cvss || (cand.score ?? -1) > (cvss.score ?? -1)) cvss = cand;
    } else if (/Epss/.test(type)) {
      const probability = parseFloat(a.security_probability);
      if (Number.isFinite(probability)) {
        const percentile = parseFloat(a.security_percentile);
        epss = { probability, percentile: Number.isFinite(percentile) ? percentile : null };
      }
    } else if (/ExploitCatalog/.test(type)) {
      if (a.security_exploited === true || String(a.security_catalogType).toLowerCase() === 'kev') {
        kev = true;
      }
    }
  });

  const severity = cvss?.severity || '';
  return { cvss, epss, kev, severity, severityRank: getCvssSeverityMeta(severity).rank };
}

/**
 * @typedef {Object} CveSummary
 * @property {string} id
 * @property {string} state - PUBLISHED | REJECTED | …
 * @property {string} description
 * @property {{version: string, score: number, severity: string, vector: string}|null} cvss
 * @property {string[]} cwes
 * @property {Array<{url: string, name: string, tags: string[]}>} references
 * @property {string} published
 * @property {string} assigner
 * @property {string[]} affectedFiles - source paths from affected[].programFiles
 * @property {string[]} affectedRoutines - function/method names from affected[].programRoutines
 * @property {string[]} affectedModules - component names from affected[].modules
 */

/**
 * Distills a CVE 5.x record (as returned by cveawg.mitre.org / cve.org) into the
 * handful of fields the UI shows. Looks in both the CNA and ADP containers, and
 * picks the highest-version CVSS metric available.
 *
 * @param {Object} record - Parsed CVE JSON record
 * @returns {CveSummary}
 */
export function summarizeCveRecord(record) {
  const meta = record?.cveMetadata || {};
  const cna = record?.containers?.cna || {};
  const adp = Array.isArray(record?.containers?.adp) ? record.containers.adp : [];

  const englishDescription = (container) => {
    const list = container?.descriptions || [];
    const en = list.find((x) => (x.lang || '').toLowerCase().startsWith('en'));
    return (en || list[0])?.value || '';
  };
  let description = englishDescription(cna) || adp.map(englishDescription).find(Boolean) || '';
  if (!description && Array.isArray(cna.rejectedReasons)) {
    description = cna.rejectedReasons.find((r) => r.value)?.value || '';
  }

  // CVSS: collect every baseScore-bearing metric from CNA + ADP, keep the
  // highest CVSS version (v4 > v3.1 > v3.0 > v2).
  const collectMetrics = (container) => {
    const out = [];
    (container?.metrics || []).forEach((m) => {
      Object.entries(m).forEach(([key, value]) => {
        if (/^cvssV/i.test(key) && value && typeof value === 'object' && value.baseScore != null) {
          out.push({
            version: value.version || key.replace(/^cvssV/i, '').replace(/_/g, '.'),
            score: value.baseScore,
            severity: String(value.baseSeverity || '').toUpperCase(),
            vector: value.vectorString || ''
          });
        }
      });
    });
    return out;
  };
  const metrics = [...collectMetrics(cna), ...adp.flatMap(collectMetrics)];
  metrics.sort((a, b) => (parseFloat(b.version) || 0) - (parseFloat(a.version) || 0));
  const cvss = metrics[0] || null;

  // CWE identifiers, de-duplicated, formatted as "CWE-125: Out-of-bounds Read"
  const cwes = [];
  const addCwes = (container) => {
    (container?.problemTypes || []).forEach((pt) => {
      (pt.descriptions || []).forEach((d) => {
        const id = d.cweId || '';
        const text = (d.description || '').trim();
        if (id && !/^n\/?a$/i.test(id)) {
          let label = id;
          const rest = text.replace(new RegExp(`^${id}[:\\s-]*`, 'i'), '').trim();
          if (rest && !/^n\/?a$/i.test(rest)) label = `${id}: ${rest}`;
          if (!cwes.some((c) => c.startsWith(id))) cwes.push(label);
        } else if (/CWE-\d+/i.test(text) && !cwes.includes(text)) {
          cwes.push(text);
        }
      });
    });
  };
  addCwes(cna);
  adp.forEach(addCwes);

  // References (CNA + ADP), de-duplicated by URL.
  const references = [];
  const seen = new Set();
  const addRefs = (container) => {
    (container?.references || []).forEach((r) => {
      const url = r?.url;
      if (typeof url === 'string' && /^https?:\/\//i.test(url) && !seen.has(url)) {
        seen.add(url);
        references.push({ url, name: r.name || '', tags: Array.isArray(r.tags) ? r.tags : [] });
      }
    });
  };
  addRefs(cna);
  adp.forEach(addRefs);

  // Affected source files / functions / modules. These live in the CVE 5.x
  // record's `affected[]` entries (optional, and mostly populated by CNAs like
  // the Linux kernel). They're de-duplicated across CNA + ADP containers and
  // across the per-version `affected` entries, which usually repeat the paths.
  const affectedFiles = [];
  const affectedRoutines = [];
  const affectedModules = [];
  const pushUnique = (list, value) => {
    const v = typeof value === 'string' ? value.trim() : '';
    if (v && !list.includes(v)) list.push(v);
  };
  const addAffected = (container) => {
    (container?.affected || []).forEach((a) => {
      (a?.programFiles || []).forEach((f) => pushUnique(affectedFiles, f));
      (a?.programRoutines || []).forEach((r) =>
        pushUnique(affectedRoutines, typeof r === 'string' ? r : r?.name)
      );
      (a?.modules || []).forEach((m) => pushUnique(affectedModules, m));
    });
  };
  addAffected(cna);
  adp.forEach(addAffected);

  return {
    id: meta.cveId || '',
    state: meta.state || '',
    description,
    cvss,
    cwes,
    references,
    published: meta.datePublished || '',
    assigner: meta.assignerShortName || '',
    affectedFiles,
    affectedRoutines,
    affectedModules
  };
}
