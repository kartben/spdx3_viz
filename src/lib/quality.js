/**
 * SBOM quality score: a single document-level completeness score, plus a
 * ranked list of the concrete fixes that would raise it the most. Everything is
 * computed from data the parser already produces (no extra parsing pass). The
 * category/metric vocabulary mirrors publicly documented practice in the SBOM
 * tooling space — the NTIA "minimum elements" baseline, and the category
 * breakdown used by tools such as Interlynk's sbomqs and eBay's sbom-scorecard —
 * reimplemented natively against this app's own model rather than any vendored
 * code.
 *
 * Each improvement's "gain" is the number of overall-score points that would be
 * recovered by fully satisfying that one dimension, computed by re-scoring the
 * document with that dimension treated as complete and diffing against the
 * baseline. This makes the "what to fix first" list honest: it is ranked by real
 * score impact, and it naturally accounts for a dimension (e.g. supplier) that
 * feeds more than one category.
 *
 * @module lib/quality
 */
import { isMeaningfulValue, cleanName } from './format.js';
import { getExternalIdentifiers } from './provenance.js';

const OFFENDER_CAP = 10;

function asArray(v) {
  return Array.isArray(v) ? v : v == null || v === '' ? [] : [v];
}

// suppliedBy/originatedBy/etc. carry raw spdxId strings; a NoAssertion sentinel
// can be a bare word or a ref like "SPDXRef-NoAssertion", so both isMeaningfulValue's
// exact-match check and a substring check are needed (same idiom parser.js uses
// for these fields).
function hasMeaningfulRef(value) {
  return asArray(value).some((v) => isMeaningfulValue(v) && !String(v).includes('NoAssertion'));
}

function displayName(el) {
  return el?.name || cleanName(el?.spdxId) || el?.spdxId || 'Unknown';
}

function gradeFor(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 65) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

const GRADE_META = {
  A: { color: '#10b981', badgeClass: 'bg-emerald-500/15 text-emerald-400' },
  B: { color: '#22c55e', badgeClass: 'bg-emerald-500/15 text-emerald-400' },
  C: { color: '#f59e0b', badgeClass: 'bg-amber-500/15 text-amber-400' },
  D: { color: '#f97316', badgeClass: 'bg-orange-500/15 text-orange-400' },
  F: { color: '#ef4444', badgeClass: 'bg-rose-500/15 text-rose-400' }
};

/**
 * Presentation metadata for an overall-score letter grade.
 *
 * @param {string} grade - 'A' | 'B' | 'C' | 'D' | 'F'
 * @returns {{color: string, badgeClass: string}}
 */
export function gradeMeta(grade) {
  return GRADE_META[grade] || GRADE_META.F;
}

/**
 * The grade-scale color for a raw 0-100 score (used to tint category bars and
 * coverage meters, which don't carry their own letter grade).
 *
 * @param {number} score
 * @returns {string} hex color
 */
export function scoreColor(score) {
  return gradeMeta(gradeFor(score)).color;
}

// --- Per-element predicates (the atoms every category and improvement is built
// from) ---
function pkgHasVersion(p) {
  return isMeaningfulValue(p.software_packageVersion);
}
function pkgHasSupplier(p) {
  return (
    hasMeaningfulRef(p.suppliedBy ?? p.software_suppliedBy) ||
    hasMeaningfulRef(p.originatedBy ?? p.software_originatedBy)
  );
}
function pkgHasIdentifier(p) {
  return isMeaningfulValue(p.software_packageUrl) || getExternalIdentifiers(p).length > 0;
}
function pkgHasName(p) {
  return isMeaningfulValue(p.name);
}
function elHasHash(el) {
  return asArray(el.verifiedUsing).some((h) => isMeaningfulValue(h?.hashValue));
}
function elHasCopyright(el) {
  return isMeaningfulValue(el.software_copyrightText);
}
function elIsConnected(el, relFromIndex, relToIndex) {
  return (
    (relFromIndex.get(el.spdxId)?.length || 0) > 0 || (relToIndex.get(el.spdxId)?.length || 0) > 0
  );
}

// A real, resolvable license label — anything that isn't the NoAssertion / None
// sentinel. Substring check because expanded labels look like "NoAssertion" or a
// full expression; the sentinel never appears inside a genuine expression.
function isRealLicenseLabel(label) {
  return !!label && !/noassertion/i.test(label) && !/^none$/i.test(String(label).trim());
}

/**
 * The set of element ids (packages and files) that declare or conclude a real
 * license, read off the parser's `licenses` list.
 *
 * @param {Array<{label: string, declaredBy: string[], concludedBy: string[]}>} licenses
 * @returns {Set<string>}
 */
function buildLicensedIdSet(licenses) {
  const ids = new Set();
  licenses.forEach((lic) => {
    if (!isRealLicenseLabel(lic.label)) return;
    (lic.declaredBy || []).forEach((id) => ids.add(id));
    (lic.concludedBy || []).forEach((id) => ids.add(id));
  });
  return ids;
}

function pct(numerator, denominator) {
  return denominator > 0 ? (numerator / denominator) * 100 : null;
}

// License and copyright are assessed at whichever granularity the document uses:
// a package-licensed SBOM scores on its packages, a file-licensed one (e.g.
// Zephyr, where the package nodes are NoAssertion but the contained files carry
// Apache/MIT) scores on its files. Taking the better of the two credits either
// practice without penalizing an SBOM for not also doing the other.
function betterOf(a, b) {
  if (a == null) return b;
  if (b == null) return a;
  return Math.max(a, b);
}

function weighted(a, b, wa, wb) {
  if (a != null && b != null) return a * wa + b * wb;
  return a ?? b;
}

const CATEGORY_META = [
  {
    key: 'ntia',
    label: 'NTIA Minimum Elements',
    weight: 0.3,
    detail: 'Name, version, supplier, a unique identifier and a relationship, per package'
  },
  {
    key: 'license',
    label: 'License & Copyright',
    weight: 0.25,
    detail: 'Declared/concluded license and copyright coverage, at the package or file level'
  },
  {
    key: 'provenance',
    label: 'Provenance & Identifiers',
    weight: 0.2,
    detail: 'Supplier/originator and PURL/CPE coverage across packages'
  },
  {
    key: 'integrity',
    label: 'Integrity & Verification',
    weight: 0.15,
    detail: 'Packages and files carrying an integrity hash'
  },
  {
    key: 'structural',
    label: 'Structural Health',
    weight: 0.1,
    detail: 'Elements with no relationships, and unresolved external references'
  }
];

// The fixable dimensions surfaced as "improve your score" cards. `pop`/`pred`
// pick out the failing elements (for the count + clickable sample); `key` is the
// lever fed to scoreCategories() to measure the point gain.
const IMPROVEMENT_META = [
  {
    key: 'supplier',
    title: 'Missing supplier',
    hint: 'Declare who supplied or originated each package (suppliedBy / originatedBy).'
  },
  {
    key: 'identifier',
    title: 'Missing a unique identifier',
    hint: 'Add a Package URL, CPE, or other external identifier so each package can be looked up.'
  },
  {
    key: 'license',
    title: 'Missing license information',
    hint: 'Declare or conclude a license for each package (or license its files).'
  },
  {
    key: 'version',
    title: 'Missing a version',
    hint: 'Give each package a version so it can be matched to advisories.'
  },
  {
    key: 'copyright',
    title: 'Missing copyright text',
    hint: 'Record the copyright notice for each package.'
  },
  {
    key: 'hash',
    title: 'Missing an integrity hash',
    hint: 'Attach a checksum (verifiedUsing) so the element can be verified.'
  },
  {
    key: 'orphans',
    title: 'No relationships',
    hint: 'Connect these elements into the dependency graph so their role is defined.'
  }
];

// Which population and predicate each improvement lever draws its offenders from.
// Kept beside IMPROVEMENT_META so the two stay in lock-step.
const IMPROVEMENT_POPULATIONS = {
  supplier: ({ packages }) => ({ pop: packages, pred: pkgHasSupplier }),
  identifier: ({ packages }) => ({ pop: packages, pred: pkgHasIdentifier }),
  license: ({ packages, hasLicense }) => ({ pop: packages, pred: hasLicense }),
  version: ({ packages }) => ({ pop: packages, pred: pkgHasVersion }),
  copyright: ({ packages }) => ({ pop: packages, pred: elHasCopyright }),
  hash: ({ artifacts }) => ({ pop: artifacts, pred: elHasHash }),
  orphans: ({ artifacts, isConnected }) => ({ pop: artifacts, pred: isConnected })
};

/**
 * Computes the document-level quality report: one overall score, the category
 * breakdown behind it, and the ranked list of fixes that would raise it most.
 *
 * @param {Object} data - Duck-typed subset of the app's parsed state:
 *   packages, files, licenses, creators, createdDate, externalRefStats,
 *   relFromIndex, relToIndex.
 * @returns {{
 *   overall: {score: number, grade: string},
 *   categories: Array<{key: string, label: string, score: number, weight: number, applicable: boolean, detail: string}>,
 *   improvements: Array<{key: string, title: string, hint: string, count: number, gain: number, coveragePct: number|null, sample: Array<{id: string, name: string, type: string}>, moreCount: number}>,
 *   counts: {packages: number, files: number, elements: number}
 * }}
 */
export function computeQualityReport(data) {
  const packages = data.packages || [];
  const files = data.files || [];
  const licenses = data.licenses || [];
  const relFromIndex = data.relFromIndex || new Map();
  const relToIndex = data.relToIndex || new Map();
  const artifacts = [...packages, ...files];

  const licensedIds = buildLicensedIdSet(licenses);
  const isConnected = (el) => elIsConnected(el, relFromIndex, relToIndex);
  const hasLicense = (el) => licensedIds.has(el.spdxId);

  const hasAuthor = (data.creators || []).length > 0;
  const hasTimestamp = isMeaningfulValue(data.createdDate);
  const refStats = data.externalRefStats || { total: 0, resolved: 0, unresolved: 0 };
  const refResolvedPct = pct(refStats.resolved, refStats.total);

  const count = (pop, pred) => pop.filter(pred).length;

  // Category scores as a function of which fix dimensions are treated as fully
  // satisfied. Passing an empty set yields the document's real scores; forcing a
  // single dimension is how each improvement's point gain is measured.
  function scoreCategories(forced) {
    const on = (k) => forced.has(k);
    const passes = (pop, pred, key) => (on(key) ? pop.length : count(pop, pred));

    // NTIA: five per-package checks plus the document-level author + timestamp.
    const ntiaChecks = packages.length * 5 + 2;
    const ntiaPasses =
      count(packages, pkgHasName) +
      passes(packages, pkgHasVersion, 'version') +
      passes(packages, pkgHasSupplier, 'supplier') +
      passes(packages, pkgHasIdentifier, 'identifier') +
      passes(packages, isConnected, 'orphans') +
      (hasAuthor ? 1 : 0) +
      (hasTimestamp ? 1 : 0);
    const ntia = ntiaChecks > 0 ? (ntiaPasses / ntiaChecks) * 100 : null;

    // License & copyright — the better of package-level and file-level coverage.
    // The 'license'/'copyright' levers force the package side (the offenders are
    // packages), so a file-licensed SBOM still keeps its file-side credit.
    const pkgLicense = on('license') ? 100 : pct(count(packages, hasLicense), packages.length);
    const fileLicense = pct(count(files, hasLicense), files.length);
    const pkgCopyright = on('copyright')
      ? 100
      : pct(count(packages, elHasCopyright), packages.length);
    const fileCopyright = pct(count(files, elHasCopyright), files.length);
    const license = weighted(
      betterOf(pkgLicense, fileLicense),
      betterOf(pkgCopyright, fileCopyright),
      0.6,
      0.4
    );

    const supplierPct = on('supplier')
      ? 100
      : pct(count(packages, pkgHasSupplier), packages.length);
    const identifierPct = on('identifier')
      ? 100
      : pct(count(packages, pkgHasIdentifier), packages.length);
    const provenance = weighted(supplierPct, identifierPct, 0.5, 0.5);

    const integrity = on('hash') ? 100 : pct(count(artifacts, elHasHash), artifacts.length);

    const orphanPct = on('orphans') ? 100 : pct(count(artifacts, isConnected), artifacts.length);
    const resolvedPct = on('refs') ? 100 : refResolvedPct;
    const structuralParts = [orphanPct, resolvedPct].filter((v) => v != null);
    const structural = structuralParts.length
      ? structuralParts.reduce((a, b) => a + b, 0) / structuralParts.length
      : null;

    return { ntia, license, provenance, integrity, structural };
  }

  function overallOf(scores) {
    const cats = CATEGORY_META.map((c) => ({
      ...c,
      score: scores[c.key],
      applicable: scores[c.key] != null
    }));
    const applicable = cats.filter((c) => c.applicable);
    const weightSum = applicable.reduce((sum, c) => sum + c.weight, 0);
    const overall =
      weightSum > 0 ? applicable.reduce((sum, c) => sum + c.score * c.weight, 0) / weightSum : 0;
    return { cats, overall };
  }

  const baseline = overallOf(scoreCategories(new Set()));
  const overallScore = baseline.overall;

  // How much the overall score would rise if this one dimension were fully fixed.
  const gainFor = (key) =>
    Math.max(0, overallOf(scoreCategories(new Set([key]))).overall - overallScore);

  const improvements = IMPROVEMENT_META.flatMap((meta) => {
    const { pop, pred } = IMPROVEMENT_POPULATIONS[meta.key]({
      packages,
      artifacts,
      hasLicense,
      isConnected
    });
    const failing = pop.filter((el) => !pred(el));
    if (failing.length === 0) return [];
    const sample = failing
      .slice(0, OFFENDER_CAP)
      .map((el) => ({ id: el.spdxId, name: displayName(el), type: el.type }));
    return [
      {
        key: meta.key,
        title: meta.title,
        hint: meta.hint,
        count: failing.length,
        gain: gainFor(meta.key),
        coveragePct: pct(pop.length - failing.length, pop.length),
        sample,
        moreCount: failing.length - sample.length
      }
    ];
  });

  // Unresolved external references have no element to click through to, so they
  // are surfaced as a count-only improvement rather than an offender list.
  if (refStats.unresolved > 0) {
    improvements.push({
      key: 'refs',
      title: 'Unresolved external references',
      hint: 'These reference elements imported from documents this SBOM does not include.',
      count: refStats.unresolved,
      gain: gainFor('refs'),
      coveragePct: pct(refStats.resolved, refStats.total),
      sample: [],
      moreCount: 0
    });
  }

  improvements.sort((a, b) => b.gain - a.gain || b.count - a.count);

  return {
    overall: { score: Math.round(overallScore), grade: gradeFor(overallScore) },
    categories: baseline.cats,
    improvements,
    counts: { packages: packages.length, files: files.length, elements: artifacts.length }
  };
}
