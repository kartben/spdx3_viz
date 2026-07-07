/**
 * SBOM quality score: a document-level completeness score plus actionable
 * "worst offender" insights, computed purely from data the parser already
 * produces (no extra parsing pass). The category/metric vocabulary mirrors
 * publicly documented practice in the SBOM tooling space — the NTIA "minimum
 * elements" baseline, and the category breakdown used by tools such as
 * Interlynk's sbomqs and eBay's sbom-scorecard — reimplemented natively
 * against this app's own model rather than any vendored code.
 *
 * @module lib/quality
 */
import { isMeaningfulValue, cleanName } from './format.js';
import { getExternalIdentifiers } from './provenance.js';
import { RELATIONSHIP_TYPES } from '../config.js';

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
 * The grade-scale color for a raw 0-100 score (used to tint category bars,
 * which don't carry their own letter grade).
 *
 * @param {number} score
 * @returns {string} hex color
 */
export function scoreColor(score) {
  return gradeMeta(gradeFor(score)).color;
}

// Best-effort license-family classification for the copyleft-exposure insight.
// A substring match against the resolved license label, not a full SPDX license
// expression parser — good enough to flag exposure, not to be relied on as legal
// advice (the UI says so explicitly).
const COPYLEFT_PATTERN = /(gpl|mpl-|epl-|cddl|osl-|eupl|sspl)/i;
const PERMISSIVE_PATTERN = /(^|[^a-z])(mit|bsd|apache|isc|zlib|unlicense|cc0|0bsd|python-2)/i;

function classifyLicenseFamily(label) {
  if (!label || /^(noassertion|none)$/i.test(label.trim())) return null;
  if (COPYLEFT_PATTERN.test(label)) return 'copyleft';
  if (PERMISSIVE_PATTERN.test(label)) return 'permissive';
  return 'other';
}

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
function elHasHash(el) {
  return asArray(el.verifiedUsing).some((h) => isMeaningfulValue(h?.hashValue));
}
function elIsConnected(el, relFromIndex, relToIndex) {
  return (
    (relFromIndex.get(el.spdxId)?.length || 0) > 0 || (relToIndex.get(el.spdxId)?.length || 0) > 0
  );
}

/**
 * Maps each license's declaring/concluding elements (from the parser's
 * `licenses` list) onto the subset that are packages, so per-package license
 * coverage and family classification can be read off in O(1).
 *
 * @param {Array<Object>} packages
 * @param {Array<Object>} licenses - {id, label, declaredBy, concludedBy}[]
 * @returns {{coveredPkgIds: Set<string>, familyByPkgId: Map<string,string>}}
 */
function buildPackageLicenseCoverage(packages, licenses) {
  const pkgIds = new Set(packages.map((p) => p.spdxId));
  const coveredPkgIds = new Set();
  const familyByPkgId = new Map();

  licenses.forEach((lic) => {
    const family = classifyLicenseFamily(lic.label);
    const users = new Set([...(lic.declaredBy || []), ...(lic.concludedBy || [])]);
    users.forEach((uid) => {
      if (!pkgIds.has(uid)) return;
      if (family) coveredPkgIds.add(uid);
      // Copyleft dominates when a package carries more than one license.
      if (family === 'copyleft') familyByPkgId.set(uid, 'copyleft');
      else if (family && familyByPkgId.get(uid) !== 'copyleft') familyByPkgId.set(uid, family);
    });
  });

  return { coveredPkgIds, familyByPkgId };
}

function pct(numerator, denominator) {
  return denominator > 0 ? (numerator / denominator) * 100 : null;
}

function offenderList(elements, total) {
  return {
    total,
    sample: elements
      .slice(0, OFFENDER_CAP)
      .map((el) => ({ id: el.spdxId, name: displayName(el), type: el.type }))
  };
}

// A per-component NTIA/FSCT element: coverage plus a (capped) list of the
// components missing it, matching the "nonconformant components" lists the
// reference tool (spdx/ntia-conformance-checker) emits per element.
function componentElement(key, label, missing, total) {
  return {
    key,
    label,
    level: 'component',
    covered: total - missing.length,
    total,
    missing: offenderList(missing, missing.length)
  };
}

/**
 * Computes the document-level quality report.
 *
 * @param {Object} data - Duck-typed subset of the app's parsed state:
 *   packages, files, licenses, vulnerabilities, creators, createdDate,
 *   specVersion, relationships, externalRefStats, relFromIndex, relToIndex,
 *   dependentIndex.
 * @returns {{
 *   overall: {score: number, grade: string},
 *   categories: Array<{key: string, label: string, score: number, weight: number, applicable: boolean, detail: string}>,
 *   ntia: {specVersion: string, totalComponents: number, isConformant: boolean, elements: Array<Object>, fsct: Array<Object>},
 *   insights: Object
 * }}
 */
export function computeQualityReport(data) {
  const packages = data.packages || [];
  const files = data.files || [];
  const licenses = data.licenses || [];
  const relFromIndex = data.relFromIndex || new Map();
  const relToIndex = data.relToIndex || new Map();
  const artifacts = [...packages, ...files];

  const { coveredPkgIds, familyByPkgId } = buildPackageLicenseCoverage(packages, licenses);

  // --- NTIA minimum elements ---
  // Per-component name/version/supplier/identifier coverage, plus three
  // document-level checks: an author, a timestamp, and whether the document
  // asserts any dependency relationship at all. Element definitions and the
  // `ntia` report shape (built below) mirror spdx/ntia-conformance-checker so
  // the CI parity check is 1:1 (see scripts/check-ntia-parity.mjs).
  const missingName = packages.filter((p) => !isMeaningfulValue(p.name));
  const missingVersion = packages.filter((p) => !pkgHasVersion(p));
  const missingSupplier = packages.filter((p) => !pkgHasSupplier(p));
  const missingIdentifier = packages.filter((p) => !pkgHasIdentifier(p));
  const hasAuthor = (data.creators || []).length > 0;
  const hasTimestamp = isMeaningfulValue(data.createdDate);
  const hasDependencyRel = (data.relationships || []).some(
    (r) => r?.relationshipType === RELATIONSHIP_TYPES.DEPENDS_ON
  );

  // --- License & copyright (packages only — file-level licensing is rarely
  // practiced even in well-formed SBOMs, so scoring it would just add noise) ---
  const missingLicense = packages.filter((p) => !coveredPkgIds.has(p.spdxId));
  const missingCopyright = packages.filter((p) => !isMeaningfulValue(p.software_copyrightText));
  const licensePct = pct(coveredPkgIds.size, packages.length);
  const copyrightPct = pct(packages.length - missingCopyright.length, packages.length);

  // --- Provenance & identifiers (packages only) ---
  const withSupplier = packages.filter(pkgHasSupplier).length;
  const withIdentifier = packages.filter(pkgHasIdentifier).length;
  const supplierPct = pct(withSupplier, packages.length);
  const identifierPct = pct(withIdentifier, packages.length);

  // --- Integrity & verification (packages + files) ---
  const missingHash = artifacts.filter((el) => !elHasHash(el));
  const integrityPct = pct(artifacts.length - missingHash.length, artifacts.length);

  // --- Structural health (orphans across packages + files, plus unresolved
  // external refs already computed by the parser) ---
  const orphans = artifacts.filter((el) => !elIsConnected(el, relFromIndex, relToIndex));
  const orphanPct = pct(artifacts.length - orphans.length, artifacts.length);
  const refStats = data.externalRefStats || { total: 0, resolved: 0, unresolved: 0 };
  const resolvedRefPct = refStats.total > 0 ? (refStats.resolved / refStats.total) * 100 : null;
  const structuralParts = [orphanPct, resolvedRefPct].filter((v) => v != null);
  const structuralScore = structuralParts.length
    ? structuralParts.reduce((a, b) => a + b, 0) / structuralParts.length
    : null;

  // --- Detailed NTIA report (the seven minimum elements) plus the CISA FSCT3
  // license/copyright extension. Component-element coverage is vacuously 1 when
  // there are no components, matching the reference tool's "allProvided". ---
  const total = packages.length;
  const rate = (missing) => (total > 0 ? (total - missing.length) / total : 1);
  const ntiaScore =
    ((rate(missingName) +
      rate(missingVersion) +
      rate(missingSupplier) +
      rate(missingIdentifier) +
      (hasDependencyRel ? 1 : 0) +
      (hasAuthor ? 1 : 0) +
      (hasTimestamp ? 1 : 0)) /
      7) *
    100;
  const ntiaConformant =
    missingName.length === 0 &&
    missingVersion.length === 0 &&
    missingSupplier.length === 0 &&
    missingIdentifier.length === 0 &&
    hasDependencyRel &&
    hasAuthor &&
    hasTimestamp;
  const ntia = {
    specVersion: data.specVersion || '',
    totalComponents: total,
    isConformant: ntiaConformant,
    elements: [
      componentElement('name', 'Component name', missingName, total),
      componentElement('version', 'Version of the component', missingVersion, total),
      componentElement('supplier', 'Supplier name', missingSupplier, total),
      componentElement('identifier', 'Unique identifier', missingIdentifier, total),
      {
        key: 'dependency',
        label: 'Dependency relationships',
        level: 'document',
        present: hasDependencyRel
      },
      { key: 'author', label: 'SBOM author', level: 'document', present: hasAuthor },
      { key: 'timestamp', label: 'Timestamp', level: 'document', present: hasTimestamp }
    ],
    fsct: [
      componentElement('concludedLicense', 'Concluded license', missingLicense, total),
      componentElement('copyrightText', 'Copyright text', missingCopyright, total)
    ]
  };

  const categories = [
    {
      key: 'ntia',
      label: 'NTIA Minimum Elements',
      weight: 0.3,
      score: ntiaScore,
      detail: 'Name, version, supplier, a unique identifier and a relationship, per package'
    },
    {
      key: 'license',
      label: 'License & Copyright',
      weight: 0.25,
      score:
        licensePct != null && copyrightPct != null
          ? licensePct * 0.6 + copyrightPct * 0.4
          : (licensePct ?? copyrightPct),
      detail: 'Declared/concluded license and copyright text coverage across packages'
    },
    {
      key: 'provenance',
      label: 'Provenance & Identifiers',
      weight: 0.2,
      score:
        supplierPct != null && identifierPct != null
          ? (supplierPct + identifierPct) / 2
          : (supplierPct ?? identifierPct),
      detail: 'Supplier/originator and PURL/CPE coverage across packages'
    },
    {
      key: 'integrity',
      label: 'Integrity & Verification',
      weight: 0.15,
      score: integrityPct,
      detail: 'Packages and files carrying an integrity hash'
    },
    {
      key: 'structural',
      label: 'Structural Health',
      weight: 0.1,
      score: structuralScore,
      detail: 'Elements with no relationships, and unresolved external references'
    }
  ].map((c) => ({ ...c, applicable: c.score != null }));

  const applicable = categories.filter((c) => c.applicable);
  const weightSum = applicable.reduce((sum, c) => sum + c.weight, 0);
  const overallScore =
    weightSum > 0 ? applicable.reduce((sum, c) => sum + c.score * c.weight, 0) / weightSum : 0;

  // --- Copyleft exposure among packages with a meaningful license ---
  const copyleftExposure = { copyleft: 0, permissive: 0, other: 0 };
  familyByPkgId.forEach((family) => {
    copyleftExposure[family] = (copyleftExposure[family] || 0) + 1;
  });

  // --- Supply-chain concentration: most depended-upon packages ---
  const dependentIndex = data.dependentIndex || new Map();
  const supplyChainConcentration = [...packages]
    .map((p) => ({
      id: p.spdxId,
      name: displayName(p),
      dependents: dependentIndex.get(p.spdxId)?.length || 0
    }))
    .filter((p) => p.dependents > 0)
    .sort((a, b) => b.dependents - a.dependents)
    .slice(0, OFFENDER_CAP);

  // --- Vulnerability triage completeness ---
  const vulnerabilities = data.vulnerabilities || [];
  let vulnerabilityTriage = null;
  if (vulnerabilities.length) {
    const resolved = vulnerabilities.filter(
      (v) => v.overallStatus === 'fixed' || v.overallStatus === 'not_affected'
    ).length;
    const open = vulnerabilities.filter(
      (v) => v.overallStatus === 'affected' || v.overallStatus === 'under_investigation'
    ).length;
    vulnerabilityTriage = {
      total: vulnerabilities.length,
      resolved,
      open,
      unknown: vulnerabilities.length - resolved - open
    };
  }

  return {
    overall: { score: Math.round(overallScore), grade: gradeFor(overallScore) },
    categories,
    ntia,
    insights: {
      packageCount: packages.length,
      fileCount: files.length,
      offenders: {
        missingLicense: offenderList(missingLicense, missingLicense.length),
        missingCopyright: offenderList(missingCopyright, missingCopyright.length),
        missingSupplier: offenderList(missingSupplier, missingSupplier.length),
        missingVersion: offenderList(missingVersion, missingVersion.length),
        missingHash: offenderList(missingHash, missingHash.length),
        orphans: offenderList(orphans, orphans.length)
      },
      copyleftExposure,
      supplyChainConcentration,
      externalRefs: refStats,
      vulnerabilityTriage
    }
  };
}
