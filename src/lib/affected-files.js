/**
 * Links the "affected files" a CVE record declares (its CVE 5.x
 * `affected[].programFiles` paths) to the actual File elements present in the
 * loaded SPDX document, so the Security view can turn a bare source path into a
 * clickable jump to that file.
 *
 * CVE program-file paths are repo-root-relative (e.g. `net/netfilter/nft_set_rbtree.c`),
 * while an SBOM's File.name is often prefixed with the project directory
 * (`linux/net/...`, `zephyr/lib/...`) or written as `./path`. Matching is
 * therefore path-suffix aware, not just equality, and deliberately conservative:
 * a link is only produced when a path (not merely a basename) lines up
 * unambiguously, so we never point the user at the wrong file.
 *
 * Pure and DOM-free so it can be unit tested and reused outside the app shell.
 *
 * @module lib/affected-files
 */

import { getVexStatusMeta } from './security.js';

/**
 * Normalizes a source path for comparison: backslashes to slashes, drop any
 * leading `./` / `/` segments, collapse repeats. Case is preserved (source
 * trees are case-sensitive).
 *
 * @param {string} p
 * @returns {string}
 */
export function normalizeSourcePath(p) {
  return String(p || '')
    .trim()
    .replace(/\\/g, '/')
    .replace(/\/+/g, '/')
    .replace(/^(?:\.\/)+/, '')
    .replace(/^\/+/, '')
    .replace(/\/+$/, '');
}

/** The last path segment (basename) of a normalized path. */
function basename(norm) {
  const i = norm.lastIndexOf('/');
  return i === -1 ? norm : norm.slice(i + 1);
}

/**
 * Builds a basename→files lookup from the document's File elements. Grouping by
 * basename keeps matching cheap: a CVE path can only match a File that shares
 * its filename, so we compare against that small bucket instead of every file.
 *
 * @param {Array<{spdxId?: string, name?: string}>} files
 * @returns {{byBase: Map<string, Array<{spdxId: string, name: string, norm: string}>>, size: number}}
 */
export function buildFileIndex(files) {
  const byBase = new Map();
  let size = 0;
  for (const f of files || []) {
    const name = f?.name;
    if (!name || !f?.spdxId) continue;
    const norm = normalizeSourcePath(name);
    if (!norm) continue;
    const base = basename(norm);
    if (!byBase.has(base)) byBase.set(base, []);
    byBase.get(base).push({ spdxId: f.spdxId, name, norm });
    size++;
  }
  return { byBase, size };
}

/**
 * @typedef {Object} AffectedFileLink
 * @property {string} path - The CVE-declared path, as written in the record
 * @property {('exact'|'suffix'|'basename'|'none')} strength - How well it matched
 * @property {boolean} linked - True when we're confident enough to link
 * @property {string} spdxId - The matched File's spdxId ('' when not linked)
 * @property {string} name - The matched File's name ('' when not linked)
 * @property {number} candidates - How many files shared the basename
 * @property {boolean} ambiguous - True when several files tied for the best match
 */

// Score a candidate file against a normalized CVE path. Higher is a stronger,
// more path-anchored match; only >= SUFFIX is trustworthy enough to link.
const SCORE = { EXACT: 3, SUFFIX: 2, REVERSE: 2, BASENAME: 1 };

function scoreCandidate(cveNorm, fileNorm) {
  if (fileNorm === cveNorm) return SCORE.EXACT;
  if (fileNorm.endsWith('/' + cveNorm)) return SCORE.SUFFIX; // file has an extra prefix dir
  if (cveNorm.endsWith('/' + fileNorm)) return SCORE.REVERSE; // cve path is the longer of the two
  return SCORE.BASENAME; // only the filename lines up
}

/**
 * Resolves one CVE-declared affected path to a File element in the document.
 *
 * @param {string} cvePath
 * @param {{byBase: Map}} index - from buildFileIndex
 * @returns {AffectedFileLink}
 */
export function matchAffectedFile(cvePath, index) {
  const norm = normalizeSourcePath(cvePath);
  const empty = {
    path: cvePath,
    strength: 'none',
    linked: false,
    spdxId: '',
    name: '',
    candidates: 0,
    ambiguous: false
  };
  if (!norm || !index?.byBase) return empty;

  const cands = index.byBase.get(basename(norm)) || [];
  if (!cands.length) return empty;

  let best = null;
  let bestScore = 0;
  let tiedIds = new Set();
  for (const c of cands) {
    const s = scoreCandidate(norm, c.norm);
    if (s > bestScore) {
      bestScore = s;
      best = c;
      tiedIds = new Set([c.spdxId]);
    } else if (s === bestScore && best) {
      tiedIds.add(c.spdxId);
    }
  }

  const strength =
    bestScore >= SCORE.EXACT ? 'exact' : bestScore >= SCORE.SUFFIX ? 'suffix' : 'basename';
  // Distinct files tied at the top score => we can't pick one safely.
  const ambiguous = tiedIds.size > 1;
  // Only link on a path-anchored match (exact/suffix) that isn't ambiguous.
  const linked = bestScore >= SCORE.SUFFIX && !ambiguous;

  return {
    path: cvePath,
    strength,
    linked,
    spdxId: linked ? best.spdxId : '',
    name: linked ? best.name : '',
    candidates: cands.length,
    ambiguous
  };
}

/**
 * Resolves every affected path for a CVE, de-duplicating by the path text.
 *
 * @param {string[]} paths - CVE `affectedFiles`
 * @param {{byBase: Map}} index - from buildFileIndex
 * @returns {AffectedFileLink[]}
 */
export function linkAffectedFiles(paths, index) {
  const seen = new Set();
  const out = [];
  for (const p of paths || []) {
    const key = normalizeSourcePath(p);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(matchAffectedFile(p, index));
  }
  return out;
}

/**
 * The compact "affected data" row bundled per CVE: whichever of files (f),
 * routines (r), modules (m) the record declares. Returns null when the CVE has
 * none, so the bundle only carries CVEs that actually contribute something.
 * Shared by the build script and (via the shape it produces) the client bundle.
 *
 * @param {{affectedFiles?: string[], affectedRoutines?: string[], affectedModules?: string[]}} summary
 * @returns {{f?: string[], r?: string[], m?: string[]}|null}
 */
export function cveAffectedRow(summary) {
  const f = summary?.affectedFiles || [];
  const r = summary?.affectedRoutines || [];
  const m = summary?.affectedModules || [];
  if (!f.length && !r.length && !m.length) return null;
  const row = {};
  if (f.length) row.f = f;
  if (r.length) row.r = r;
  if (m.length) row.m = m;
  return row;
}

/** A VEX status that clearly clears a component of a vulnerability. */
export function isRuledOutStatus(status) {
  return status === 'not_affected' || status === 'fixed';
}

/**
 * The single effective VEX status a set of assessments expresses for one
 * vulnerability: the most severe wins, so a package carrying both an `affected`
 * and a `not_affected` record is treated as affected (never silently cleared).
 * Returns '' when none of the assessments target the vulnerability.
 *
 * @param {Array<{vulnId?: string, status?: string}>} assessments
 * @param {string} vulnSpdxId
 * @returns {string}
 */
export function effectiveVexStatus(assessments, vulnSpdxId) {
  let best = '';
  let bestRank = -1;
  for (const a of assessments || []) {
    if (!a || a.vulnId !== vulnSpdxId) continue;
    const rank = getVexStatusMeta(a.status).severity;
    if (rank > bestRank) {
      bestRank = rank;
      best = a.status;
    }
  }
  return best;
}

/**
 * @typedef {AffectedFileLink} AnnotatedAffectedFile
 * @property {string} packageId - spdxId of the package that contains the matched File ('' when unlinked/unknown)
 * @property {string} packageName - that package's display name ('')
 * @property {string} vexStatus - the effective VEX status for this vuln ('' when none)
 * @property {boolean} ruledOut - true when that VEX status clears the file (not_affected/fixed)
 * @property {boolean} vexInherited - true when vexStatus came from the whole-CVE clearance
 *   rather than the file's own package (the file's package carries no direct assessment)
 */

/**
 * Joins each resolved affected-file link to the package that contains its
 * matched File and to the VEX status that clears it for this vulnerability, so
 * the UI can flag files a VEX already rules out. Pure: the document lookups are
 * supplied as callbacks. Only linked files (a path that resolved to a File in
 * the document) can carry a package or status.
 *
 * A file's own containing package rarely carries the VEX statement directly: VEX
 * records typically target a top-level product package, while a matched source
 * file belongs to a sub-component (or to no package at all). So when the whole
 * CVE is ruled out for this SBOM (`overallStatus` is not_affected/fixed), a
 * matched file with no direct assessment inherits that clearance rather than
 * reading as "still an issue", which would contradict the card's clearance
 * banner. A file whose own package is directly assessed keeps that status.
 *
 * The result is ordered for display: still-affected matched files first, then
 * matched files a VEX rules out, then paths not present in this SBOM.
 *
 * @param {AffectedFileLink[]} links - from linkAffectedFiles
 * @param {string} vulnSpdxId - the vulnerability the files belong to (keys the VEX lookup)
 * @param {Object} lookups
 * @param {(fileId: string) => ({spdxId: string, name: string}|null)} lookups.packageOf
 *   matched File spdxId -> its containing package, or null
 * @param {(pkgId: string) => Array<{vulnId?: string, status?: string}>} lookups.assessmentsOf
 *   package spdxId -> its VEX assessments
 * @param {string} [lookups.overallStatus] - the vuln's effective VEX status across every
 *   assessed package; when it clears the CVE, matched files inherit the clearance
 * @returns {AnnotatedAffectedFile[]}
 */
export function annotateAffectedFiles(
  links,
  vulnSpdxId,
  { packageOf, assessmentsOf, overallStatus = '' }
) {
  const clearedOverall = isRuledOutStatus(overallStatus);
  const annotated = (links || []).map((link) => {
    const base = {
      ...link,
      packageId: '',
      packageName: '',
      vexStatus: '',
      ruledOut: false,
      vexInherited: false
    };
    // A path not present in this SBOM stays a bare reference, even when the CVE
    // is cleared overall: there is no file here to rule out.
    if (!link.linked) return base;
    const pkg = packageOf(link.spdxId);
    const pkgStatus =
      pkg && pkg.spdxId ? effectiveVexStatus(assessmentsOf(pkg.spdxId), vulnSpdxId) : '';
    // Prefer the file's own package assessment; otherwise inherit the whole-CVE
    // clearance so a matched file never contradicts the card's "not an issue"
    // banner just because the VEX names the product, not this sub-package.
    const vexStatus = pkgStatus || (clearedOverall ? overallStatus : '');
    return {
      ...base,
      packageId: pkg?.spdxId || '',
      packageName: pkg?.name || '',
      vexStatus,
      ruledOut: isRuledOutStatus(vexStatus),
      vexInherited: !pkgStatus && clearedOverall
    };
  });
  // Actionable (matched, still affected) first, ruled-out next, absent last. A
  // stable sort keeps the CVE's declared order within each group.
  const rank = (d) => (!d.linked ? 2 : d.ruledOut ? 1 : 0);
  return annotated.sort((a, b) => rank(a) - rank(b));
}

/**
 * Compact counts over a CVE's annotated affected files, relative to this SBOM:
 * how many paths matched a File, how many of those a VEX rules out, how many
 * remain an open issue (matched minus ruled out), and how many distinct packages
 * own the matched files. Drives the card subtitle and badges.
 *
 * @param {AnnotatedAffectedFile[]} annotated - from annotateAffectedFiles
 * @returns {{matched: number, ruledOut: number, affected: number, packages: number}}
 */
export function summarizeAffectedFiles(annotated) {
  let matched = 0;
  let ruledOut = 0;
  const pkgs = new Set();
  for (const d of annotated || []) {
    if (!d.linked) continue;
    matched++;
    if (d.ruledOut) ruledOut++;
    if (d.packageId) pkgs.add(d.packageId);
  }
  return { matched, ruledOut, affected: matched - ruledOut, packages: pkgs.size };
}

/**
 * Builds synthetic "affects file" graph relationships (vulnerability -> File) from
 * the affected files a vulnerability's fetched CVE record declares, but only for
 * paths that resolve unambiguously to a File in the document. These are marked
 * `virtual` and `inferred` so the graph can draw them distinctly (dashed) and
 * every consumer can tell they were derived by path-matching, not declared by
 * the SBOM.
 *
 * @param {Array<{spdxId?: string}>} vulns - vulnerability records (SBOM + virtual)
 * @param {(v: Object) => (string[]|undefined)} getAffectedFiles - per-vuln affected paths
 *   (typically the fetched CVE record's affectedFiles; undefined until fetched)
 * @param {{byBase: Map}} index - from buildFileIndex
 * @returns {Array<Object>} relationship objects shaped like the app's edges
 */
export function buildAffectedFileRelationships(vulns, getAffectedFiles, index) {
  const rels = [];
  const seen = new Set();
  for (const v of vulns || []) {
    if (!v?.spdxId) continue;
    const files = getAffectedFiles(v);
    if (!files || !files.length) continue;
    for (const link of linkAffectedFiles(files, index)) {
      if (!link.linked) continue;
      const key = v.spdxId + '\0' + link.spdxId;
      if (seen.has(key)) continue;
      seen.add(key);
      rels.push({
        type: 'security_VexAffectedVulnAssessmentRelationship',
        spdxId: `${v.spdxId}#affectsFile#${link.spdxId}`,
        relationshipType: 'affectsFile',
        from: v.spdxId,
        to: link.spdxId,
        virtual: true,
        inferred: true,
        affectedPath: link.path
      });
    }
  }
  return rels;
}
