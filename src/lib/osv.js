/**
 * OSV.dev online vulnerability lookup helpers: turning SBOM components into
 * PackageURL queries, normalizing OSV records into the shape the security view
 * already renders, computing a CVSS base score from a vector string, and merging
 * online findings with what the SBOM already carries.
 *
 * Everything here is pure and DOM-free so it can run in a Web Worker and be unit
 * tested directly.
 *
 * @module lib/osv
 */
import { isMeaningfulValue } from './format.js';
import { cvssSeverityForScore, getCvssSeverityMeta } from './security.js';

/** Public OSV API base. */
export const OSV_API = 'https://api.osv.dev';

/**
 * Collects the distinct PackageURL query targets from a set of SBOM elements
 * (packages, files, …). A component can carry its purl either as a
 * `software_packageUrl` scalar or as a `packageUrl` externalIdentifier; both are
 * surfaced. Query targets are de-duplicated by purl so we never ask OSV about
 * the same coordinate twice, while still remembering every element that shares
 * it so a finding can be attributed back to each.
 *
 * @param {Array<Object>} elements - SPDX elements to inspect
 * @returns {Array<{purl: string, elementIds: string[]}>} de-duplicated targets
 */
export function collectPurlTargets(elements) {
  /** @type {Map<string, Set<string>>} */
  const byPurl = new Map();
  const add = (purl, spdxId) => {
    const clean = String(purl || '').trim();
    if (!/^pkg:/i.test(clean)) return;
    if (!byPurl.has(clean)) byPurl.set(clean, new Set());
    if (spdxId) byPurl.get(clean).add(spdxId);
  };
  (elements || []).forEach((el) => {
    if (!el) return;
    add(el.software_packageUrl, el.spdxId);
    const ids = Array.isArray(el.externalIdentifier)
      ? el.externalIdentifier
      : el.externalIdentifier
        ? [el.externalIdentifier]
        : [];
    ids.forEach((eid) => {
      if (eid && eid.externalIdentifierType === 'packageUrl' && isMeaningfulValue(eid.identifier)) {
        add(eid.identifier, el.spdxId);
      }
    });
  });
  return [...byPurl.entries()].map(([purl, ids]) => ({ purl, elementIds: [...ids] }));
}

/**
 * The CVE alias of an OSV record, if it has one. OSV keys records by GHSA / DSA /
 * CVE / … ids and lists cross-references under `aliases`; we prefer a CVE id so a
 * finding lines up with the CVE ids the SBOM uses.
 *
 * @param {Object} osv - Raw OSV vulnerability record
 * @returns {string} e.g. 'CVE-2024-1234', or ''
 */
export function pickCveId(osv) {
  const isCve = (s) => /^CVE-\d{4}-\d+$/i.test(String(s || '').trim());
  if (isCve(osv?.id)) return String(osv.id).trim().toUpperCase();
  const alias = (osv?.aliases || []).find(isCve);
  return alias ? String(alias).trim().toUpperCase() : '';
}

// CVSS metric weights (v3.0 / v3.1 share these).
const V3 = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  PR_U: { N: 0.85, L: 0.62, H: 0.27 },
  PR_C: { N: 0.85, L: 0.68, H: 0.5 },
  CIA: { H: 0.56, L: 0.22, N: 0 }
};
const V2 = {
  AV: { L: 0.395, A: 0.646, N: 1.0 },
  AC: { H: 0.35, M: 0.61, L: 0.71 },
  Au: { M: 0.45, S: 0.56, N: 0.704 },
  CIA: { N: 0, P: 0.275, C: 0.66 }
};

// CVSS v3.1 roundup: smallest one-decimal value >= x, computed with integer math
// to avoid binary-float surprises (matches the spec's reference implementation).
function roundUp1(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

/**
 * Parses a CVSS vector string into its metric map. Tolerates the optional
 * `CVSS:3.1/` prefix (v3/v4) and the bare `AV:.../AC:.../…` form (v2).
 *
 * @param {string} vector
 * @returns {{version: string, metrics: Object<string, string>}}
 */
function parseCvssVector(vector) {
  const raw = String(vector || '').trim();
  let version = '';
  let body = raw;
  const prefix = /^CVSS:(\d(?:\.\d)?)\//i.exec(raw);
  if (prefix) {
    version = prefix[1];
    body = raw.slice(prefix[0].length);
  }
  const metrics = {};
  body.split('/').forEach((part) => {
    const [k, v] = part.split(':');
    if (k && v) metrics[k.trim().toUpperCase()] = v.trim().toUpperCase();
  });
  if (!version) version = '2.0'; // bare vector => CVSS v2
  return { version, metrics };
}

/**
 * Computes a CVSS base score (0–10) from a vector string. Supports CVSS v2 and
 * v3.0/3.1. CVSS v4's scoring is a large lookup table we don't reproduce, so a v4
 * vector returns null (the caller falls back to the record's qualitative rating).
 *
 * @param {string} vector - e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
 * @returns {number|null} base score rounded to one decimal, or null
 */
export function cvssBaseScore(vector) {
  const { version, metrics: m } = parseCvssVector(vector);
  if (version.startsWith('4')) return null;

  if (version.startsWith('3')) {
    const av = V3.AV[m.AV];
    const ac = V3.AC[m.AC];
    const ui = V3.UI[m.UI];
    const scopeChanged = m.S === 'C';
    const pr = (scopeChanged ? V3.PR_C : V3.PR_U)[m.PR];
    const c = V3.CIA[m.C];
    const iN = V3.CIA[m.I];
    const a = V3.CIA[m.A];
    if ([av, ac, ui, pr, c, iN, a].some((v) => v == null)) return null;
    const iscBase = 1 - (1 - c) * (1 - iN) * (1 - a);
    const impact = scopeChanged
      ? 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15)
      : 6.42 * iscBase;
    const exploitability = 8.22 * av * ac * pr * ui;
    if (impact <= 0) return 0;
    const base = scopeChanged
      ? Math.min(1.08 * (impact + exploitability), 10)
      : Math.min(impact + exploitability, 10);
    return roundUp1(base);
  }

  // CVSS v2
  const av = V2.AV[m.AV];
  const ac = V2.AC[m.AC];
  const au = V2.Au[m.AU];
  const c = V2.CIA[m.C];
  const iN = V2.CIA[m.I];
  const a = V2.CIA[m.A];
  if ([av, ac, au, c, iN, a].some((v) => v == null)) return null;
  const impact = 10.41 * (1 - (1 - c) * (1 - iN) * (1 - a));
  const exploitability = 20 * av * ac * au;
  const f = impact === 0 ? 0 : 1.176;
  const base = ((0.6 * impact + 0.4 * exploitability - 1.5) * f) / 1;
  return Math.round(base * 10) / 10;
}

// OSV severity entry types that carry a CVSS vector, richest first.
const CVSS_TYPES = [
  ['CVSS_V4', '4.0'],
  ['CVSS_V3', '3.1'],
  ['CVSS_V2', '2.0']
];

/**
 * Distills the CVSS signal from an OSV record: the best available vector, its
 * numeric base score (when we can compute one), and the qualitative band. Falls
 * back to `database_specific.severity` (GHSA labels like "HIGH") when no vector
 * is present.
 *
 * @param {Object} osv
 * @returns {{score: (number|null), severity: string, vector: string, version: string}|null}
 */
function osvCvss(osv) {
  const severities = Array.isArray(osv?.severity) ? osv.severity : [];
  for (const [type, version] of CVSS_TYPES) {
    const entry = severities.find((s) => s && s.type === type && s.score);
    if (entry) {
      const vector = String(entry.score);
      const detected = /^CVSS:(\d(?:\.\d)?)/i.exec(vector);
      const ver = detected ? detected[1] : version;
      const score = cvssBaseScore(vector);
      const severity = score != null ? cvssSeverityForScore(score, ver) : bandFromLabel(osv) || '';
      return { score, severity, vector, version: ver };
    }
  }
  const band = bandFromLabel(osv);
  return band ? { score: null, severity: band, vector: '', version: '' } : null;
}

// Maps a free-text severity label (GHSA "MODERATE", distro "important", …) onto
// the standard CVSS bands the UI renders.
function bandFromLabel(osv) {
  let label = String(osv?.database_specific?.severity || '').toLowerCase();
  if (!label) return '';
  if (label === 'moderate') label = 'medium';
  else if (label === 'important') label = 'high';
  else if (label === 'critical' || label === 'high' || label === 'medium' || label === 'low') {
    /* already standard */
  } else return '';
  return label;
}

/**
 * @typedef {Object} NormalizedOsvVuln
 * @property {string} osvId - The OSV record id (GHSA-…, CVE-…, DSA-…)
 * @property {string} cveId - CVE alias when present, else ''
 * @property {string} displayId - cveId || osvId
 * @property {string[]} aliases
 * @property {string} summary
 * @property {string} details
 * @property {{score:(number|null),severity:string,vector:string,version:string}|null} cvss
 * @property {string[]} cwes
 * @property {Array<{url:string,type:string}>} references
 * @property {string} published
 * @property {string} modified
 * @property {boolean} withdrawn - true when the advisory has been withdrawn
 */

/**
 * Normalizes a raw OSV vulnerability record into the compact, render-ready shape
 * the security view consumes.
 *
 * @param {Object} osv - Raw OSV record (from /v1/vulns/{id} or /v1/query)
 * @returns {NormalizedOsvVuln}
 */
export function normalizeOsvVuln(osv) {
  const osvId = String(osv?.id || '').trim();
  const cveId = pickCveId(osv);
  const aliases = Array.isArray(osv?.aliases) ? osv.aliases.filter(Boolean) : [];
  const cwes = Array.isArray(osv?.database_specific?.cwe_ids)
    ? osv.database_specific.cwe_ids.filter(Boolean)
    : [];
  const references = (Array.isArray(osv?.references) ? osv.references : [])
    .filter((r) => r && typeof r.url === 'string' && /^https?:\/\//i.test(r.url))
    .map((r) => ({ url: r.url, type: String(r.type || '').toLowerCase() }));
  return {
    osvId,
    cveId,
    displayId: cveId || osvId,
    aliases,
    summary: String(osv?.summary || '').trim(),
    details: String(osv?.details || '').trim(),
    cvss: osvCvss(osv),
    cwes,
    references,
    published: osv?.published || '',
    modified: osv?.modified || '',
    withdrawn: Boolean(osv?.withdrawn)
  };
}

/**
 * Human label for a provider key, used in source tags and the references list.
 * @param {string} provider - 'OSV' | 'NVD'
 * @returns {string}
 */
export function providerLabel(provider) {
  return provider === 'NVD' ? 'NVD' : 'OSV.dev';
}

// Picks the richer of two CVSS objects: a numeric score beats none, then the
// higher score wins.
function betterCvss(a, b) {
  if (!a) return b;
  if (!b) return a;
  const as = a.score == null ? -1 : a.score;
  const bs = b.score == null ? -1 : b.score;
  return bs > as ? b : a;
}

/**
 * @typedef {Object} ProviderFinding
 * @property {string} provider - 'OSV' | 'NVD'
 * @property {string} [osvId]
 * @property {string} cveId
 * @property {string} displayId
 * @property {string} summary
 * @property {string} details
 * @property {{score:(number|null),severity:string,vector:string,version:string}|null} cvss
 * @property {string[]} cwes
 * @property {Array<{url:string,type:string}>} references
 * @property {string} published
 * @property {string[]} elementIds - matched component spdxIds
 */

/**
 * Groups online provider findings (from OSV and/or NVD) by the CVE they
 * describe and builds one card-ready vulnerability per group, combining the
 * providers' data and recording which databases reported it. A single CVE found
 * by both OSV and NVD becomes one entry tagged with both sources.
 *
 * @param {ProviderFinding[]} findings
 * @param {(spdxId: string) => ({spdxId:string,name:string,purl?:string,cpe?:string}|null)} resolve
 * @returns {Object[]} card-ready online vulnerabilities (source: 'online')
 */
export function buildOnlineVulns(findings, resolve) {
  const groups = new Map();
  for (const f of findings || []) {
    if (!f) continue;
    const key = mergeKey({ cveId: f.cveId, name: f.displayId, osvId: f.osvId });
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(f);
  }
  return [...groups.values()].map((fs) => buildOnlineVuln(fs, resolve));
}

const CVE_RE = /^CVE-\d{4}-\d+$/i;

function buildOnlineVuln(fs, resolve) {
  const sources = [...new Set(fs.map((f) => f.provider))];
  const cveId = (fs.find((f) => CVE_RE.test(f.cveId || ''))?.cveId || '').toUpperCase();
  const osvId = fs.find((f) => f.osvId)?.osvId || '';
  const displayId = cveId || osvId || fs[0].displayId || '';

  const elementIds = [...new Set(fs.flatMap((f) => f.elementIds || []))];
  const matched = elementIds.map(resolve).filter(Boolean);

  const cvss = fs.reduce((best, f) => betterCvss(best, f.cvss), null);
  const severity = cvss?.severity || '';

  const cwes = [...new Set(fs.flatMap((f) => f.cwes || []))];
  const summary = fs.map((f) => f.summary).find(Boolean) || '';
  const details = fs.map((f) => f.details).find(Boolean) || '';
  const published = fs.map((f) => f.published).find(Boolean) || '';

  // References de-duplicated by URL, remembering which provider(s) cited each.
  const refMap = new Map();
  fs.forEach((f) => {
    (f.references || []).forEach((r) => {
      if (!r?.url) return;
      if (!refMap.has(r.url)) refMap.set(r.url, { url: r.url, providers: new Set() });
      refMap.get(r.url).providers.add(f.provider);
    });
  });
  const references = [...refMap.values()].map((r) => ({ url: r.url, providers: [...r.providers] }));

  const locators = references.map((r) => r.url);
  if (cveId && !locators.some((u) => /cve\.org|nvd\.nist\.gov/i.test(u))) {
    locators.push(`https://www.cve.org/CVERecord?id=${cveId}`);
  } else if (!cveId && osvId) {
    locators.unshift(`https://osv.dev/vulnerability/${osvId}`);
  }

  return {
    // Synthetic spdxId keeps Alpine's :key stable and distinct from SBOM ids.
    spdxId: `online:${displayId}`,
    el: { summary, description: details },
    name: displayId,
    cveId,
    osvId,
    locators,
    assessments: [],
    statusCounts: {},
    overallStatus: 'unknown',
    packageCount: matched.length,
    cvss,
    epss: null,
    kev: false,
    severity,
    severityRank: getCvssSeverityMeta(severity).rank,
    source: 'online',
    online: { sources, matched, cvss, cwes, references, summary, details, osvId, cveId, published }
  };
}

/**
 * The key a vulnerability merges on: its CVE id when it has one (so an online
 * CVE lines up with the same CVE in the SBOM), otherwise its display id
 * upper-cased (GHSA/DSA online ids, or a non-CVE SBOM vuln name).
 *
 * @param {{cveId?:string,name?:string}} v
 * @returns {string}
 */
function mergeKey(v) {
  const cve = String(v?.cveId || '')
    .trim()
    .toUpperCase();
  if (/^CVE-\d{4}-\d+$/.test(cve)) return cve;
  // Fall back through name/osvId to spdxId so identifier-less entries still get a
  // distinct key and don't all collapse onto '' (which would drop all but one).
  return String(v?.name || v?.osvId || v?.spdxId || '')
    .trim()
    .toUpperCase();
}

/**
 * Builds "virtual" graph elements + edges for online-only vulnerabilities so a
 * scan finding shows on the graph, in search and in the detail panel like an
 * in-SBOM vulnerability, while staying clearly flagged (`virtual: true`) as
 * discovered by a public database rather than carried by the SBOM.
 *
 * Each element mimics a security_Vulnerability (so getNodeType, the vuln detail
 * section and the CVE lookup all treat it identically), and one `affects` VEX
 * edge is synthesized per matched component so the finding connects to the
 * package(s) it hits on the graph.
 *
 * @param {Object[]} onlineOnlyVulns - merged vulnerabilities with source 'online'
 * @returns {{elements: Object[], relationships: Object[]}}
 */
export function buildVirtualVulnGraph(onlineOnlyVulns) {
  const elements = [];
  const relationships = [];
  (onlineOnlyVulns || []).forEach((v) => {
    if (!v || !v.spdxId) return;
    const cveId = v.cveId || '';
    const identifier = cveId || v.osvId || v.name || v.spdxId;
    const locators = Array.isArray(v.locators) ? v.locators : [];
    const online = v.online || {};
    elements.push({
      type: 'security_Vulnerability',
      spdxId: v.spdxId,
      name: v.name || identifier,
      // Not from the SBOM: discovered by an online scan (OSV/NVD). Every consumer
      // reads this flag to mark the node/row/panel as a scan finding.
      virtual: true,
      summary: online.summary || '',
      description: online.details || '',
      externalIdentifier: [
        {
          externalIdentifierType: cveId ? 'cve' : 'securityOther',
          identifier,
          identifierLocator: locators
        }
      ],
      // The card-ready online payload (matched components, CVSS, sources) so the
      // detail panel can list what the scan matched without re-deriving it.
      _online: online
    });
    (online.matched || []).filter(Boolean).forEach((m) => {
      if (!m.spdxId) return;
      relationships.push({
        type: 'security_VexAffectedVulnAssessmentRelationship',
        spdxId: `${v.spdxId}#affects#${m.spdxId}`,
        relationshipType: 'affects',
        from: v.spdxId,
        to: m.spdxId,
        virtual: true
      });
    });
  });
  return { elements, relationships };
}

/**
 * Merges online (OSV) findings into the SBOM-derived vulnerability list. SBOM
 * entries that OSV also reports are tagged `source: 'both'` and carry the online
 * payload under `.online`; online-only findings are appended with
 * `source: 'online'`. SBOM-only entries stay `source: 'sbom'`.
 *
 * @param {Array<Object>} sbomVulns - Enriched SBOM vulnerabilities
 * @param {Array<Object>} onlineVulns - Card-ready online vulns (from toOnlineVuln)
 * @returns {Array<Object>} merged list
 */
export function mergeVulnLists(sbomVulns, onlineVulns) {
  const byKey = new Map();
  const merged = (sbomVulns || []).map((v) => {
    const copy = { ...v, source: 'sbom' };
    byKey.set(mergeKey(copy), copy);
    return copy;
  });
  (onlineVulns || []).forEach((o) => {
    const key = mergeKey(o);
    const existing = byKey.get(key);
    if (existing) {
      existing.source = 'both';
      existing.online = o.online;
      // Adopt an online CVSS only when the SBOM carried none, so the SBOM's own
      // assessment always wins when both exist.
      if (!existing.cvss && o.cvss) {
        existing.cvss = o.cvss;
        existing.severity = o.severity;
        existing.severityRank = o.severityRank;
      }
    } else {
      byKey.set(key, o);
      merged.push(o);
    }
  });
  return merged;
}
