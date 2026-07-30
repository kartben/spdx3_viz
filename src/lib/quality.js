/**
 * SBOM quality score: a document-level completeness score plus actionable
 * "worst offender" insights, computed purely from data the parser already
 * produces (no extra parsing pass). The category/metric vocabulary mirrors
 * publicly documented practice in the SBOM tooling space: the NTIA "minimum
 * elements" baseline, the CISA 2026 Minimum Elements update, and the category
 * breakdown used by tools such as Interlynk's sbomqs and eBay's sbom-scorecard,
 * reimplemented natively against this app's own model rather than any vendored
 * code.
 *
 * @module lib/quality
 */
import { isMeaningfulValue, cleanName } from './format.js';
import { getExternalIdentifiers } from './provenance.js';
import { RELATIONSHIP_TYPES } from '../config.js';

const OFFENDER_CAP = 10;

/** @see https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom */
export const CISA_2026_REFERENCE_URL =
  'https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom';
export const CISA_2026_PDF_URL =
  'https://www.cisa.gov/sites/default/files/2026-07/2026_cisa_sbom_minimum_elements_508c.pdf';

const EXPLICIT_UNKNOWN_RE = /^(noassertion|none)$/i;

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

function isExplicitUnknown(value) {
  if (value == null) return false;
  const s = String(value).trim();
  return s !== '' && (EXPLICIT_UNKNOWN_RE.test(s) || s.includes('NoAssertion'));
}

function isBlankField(value) {
  return value == null || String(value).trim() === '';
}

/** Meaningful value or an explicit unknown marker (NOASSERTION / None). */
function hasValueOrUnknown(value) {
  return isMeaningfulValue(value) || isExplicitUnknown(value);
}

function pkgHasVersionOrUnknown(p) {
  return hasValueOrUnknown(p.software_packageVersion);
}

function pkgHashEntries(p) {
  return asArray(p.verifiedUsing).filter((h) => h && typeof h === 'object');
}

/** Package hash present, or explicitly marked unknown. Silent absence fails. */
function pkgHasHashOrUnknown(p) {
  const hashes = pkgHashEntries(p);
  if (!hashes.length) return false;
  return hashes.some((h) => hasValueOrUnknown(h.hashValue));
}

function pkgHasHashAlgorithm(p) {
  const hashes = pkgHashEntries(p);
  if (!hashes.length) return false;
  // Explicit unknown hash: algorithm may also be unknown; treat as covered.
  if (hashes.some((h) => isExplicitUnknown(h.hashValue))) return true;
  return hashes.some((h) => isMeaningfulValue(h.hashValue) && isMeaningfulValue(h.algorithm));
}

/**
 * Per-package license status for CISA Component License: a concrete license
 * ("present"), an explicit unknown ("unknown"), or silent absence ("missing").
 *
 * @param {Array<Object>} packages
 * @param {Array<Object>} licenses
 * @returns {Map<string, 'present'|'unknown'|'missing'>}
 */
function buildPackageLicenseStatus(packages, licenses) {
  const status = new Map(packages.map((p) => [p.spdxId, 'missing']));
  licenses.forEach((lic) => {
    const label = (lic.label || '').trim();
    if (!label) return;
    const kind =
      EXPLICIT_UNKNOWN_RE.test(label) || label.includes('NoAssertion') ? 'unknown' : 'present';
    const users = new Set([...(lic.declaredBy || []), ...(lic.concludedBy || [])]);
    users.forEach((uid) => {
      if (!status.has(uid)) return;
      if (kind === 'present') status.set(uid, 'present');
      else if (status.get(uid) !== 'present') status.set(uid, 'unknown');
    });
  });
  return status;
}

function resolveToolElement(tool, data) {
  if (!tool) return null;
  if (tool.software_packageVersion != null || tool.externalIdentifier) return tool;
  return (
    data.elementMap?.get(tool.id) || (data.tools || []).find((t) => t.spdxId === tool.id) || tool
  );
}

/** True when a creator tool carries a version, versioned PURL, or versioned name. */
function toolHasVersion(tool, data) {
  const el = resolveToolElement(tool, data);
  if (!el) return false;
  if (isMeaningfulValue(el.software_packageVersion) || isMeaningfulValue(el.version)) return true;
  const ids = getExternalIdentifiers(el);
  if (ids.some((id) => id.type === 'packageUrl' && /@[^/@\s]+$/.test(id.identifier))) return true;
  // Common generator spelling: "trivy 0.72.0"
  const name = el.name || tool.name || '';
  return /\b\d+\.\d+(\.\d+)?\b/.test(name);
}

function documentHasAuthorSignature(data) {
  const docs = [];
  if (data.elementMap) {
    for (const el of data.elementMap.values()) {
      if (el?.type === 'SpdxDocument' || el?.type === 'software_Sbom') docs.push(el);
    }
  }
  (data.sboms || []).forEach((s) => docs.push(s));
  const candidates = docs.length ? docs : [...(data.packages || []).slice(0, 1)];
  return candidates.some((el) => {
    if (!el) return false;
    if (isMeaningfulValue(el.signature) || asArray(el.signature).some(isMeaningfulValue))
      return true;
    return asArray(el.verifiedUsing).some((m) => {
      if (!m || typeof m !== 'object') return false;
      const type = String(m.type || '');
      if (/sign/i.test(type)) return true;
      // Hash / content-identifier integrity is not an author signature.
      if (type === 'Hash' || type === 'PackageVerificationCode') return false;
      if (type.includes('ContentIdentifier')) return false;
      return isMeaningfulValue(m.algorithm) && /sign|ed25519|rsa|ecdsa/i.test(String(m.algorithm));
    });
  });
}

/**
 * SBOM Generation Context: prefer software_sbomType, then lifecycle scopes,
 * then build profile / build elements.
 *
 * @param {Object} data
 * @returns {{present: boolean, detail: string}}
 */
function resolveGenerationContext(data) {
  const types = (data.sbomTypes || []).filter(Boolean);
  if (types.length) return { present: true, detail: types.join(', ') };

  const scopes = new Set();
  (data.relationships || []).forEach((r) => {
    if (r?.scope && r.scope !== 'unscoped') scopes.add(r.scope);
  });
  if (scopes.size) return { present: true, detail: [...scopes].join(', ') };

  if ((data.builds || []).length > 0) return { present: true, detail: 'build' };
  if ((data.profileConformance || []).includes('build')) return { present: true, detail: 'build' };
  return { present: false, detail: '' };
}

function documentElement(key, label, present, opts = {}) {
  return {
    key,
    label,
    level: 'document',
    present: !!present,
    status: opts.status || (present ? 'pass' : 'fail'),
    detail: opts.detail || '',
    blocksConformance: opts.blocksConformance !== false
  };
}

function practiceElement(key, label, status, detail = '') {
  return { key, label, level: 'practice', status, detail, present: status === 'pass' };
}

/**
 * CISA 2026 Minimum Elements report (data fields + assessable practices).
 * Author Signature is advisory (warn) and does not block isConformant.
 * SBOM Version has no stable SPDX 3 mapping (na).
 *
 * @param {Object} data
 * @param {{coveredPkgIds: Set<string>, missingName: Object[], missingSupplier: Object[], missingIdentifier: Object[], hasAuthor: boolean, hasTimestamp: boolean, hasDependencyRel: boolean, licenses: Object[]}} ctx
 * @returns {Object}
 */
function buildCisa2026Report(data, ctx) {
  const packages = data.packages || [];
  const total = packages.length;
  const licenseStatus = buildPackageLicenseStatus(packages, ctx.licenses || []);

  const missingVersion = packages.filter((p) => !pkgHasVersionOrUnknown(p));
  const missingProducer = ctx.missingSupplier;
  const missingIdentifier = ctx.missingIdentifier;
  const missingName = ctx.missingName;
  const missingLicense = packages.filter((p) => licenseStatus.get(p.spdxId) === 'missing');
  const missingHash = packages.filter((p) => !pkgHasHashOrUnknown(p));
  const missingHashAlg = packages.filter((p) => !pkgHasHashAlgorithm(p));

  const hasAuthor = ctx.hasAuthor;
  const hasTimestamp = ctx.hasTimestamp;
  const hasDependencyRel = ctx.hasDependencyRel;
  const hasFormatName = true; // this app only loads SPDX / SPDX-compatible JSON-LD
  const hasFormatVersion = isMeaningfulValue(data.specVersion);
  const generation = resolveGenerationContext(data);
  const creatorTools = data.creatorTools || [];
  const hasToolName = creatorTools.some((t) => isMeaningfulValue(t.name));
  const hasToolVersion = creatorTools.some((t) => toolHasVersion(t, data));
  const hasSignature = documentHasAuthorSignature(data);

  const metadata = [
    documentElement('author', 'SBOM Author', hasAuthor),
    documentElement('authorSignature', 'SBOM Author Signature', hasSignature, {
      status: hasSignature ? 'pass' : 'warn',
      detail: hasSignature ? '' : 'Advisory: not required for the Conformant badge yet',
      blocksConformance: false
    }),
    documentElement('formatName', 'SBOM Data Format Name', hasFormatName, {
      detail: 'SPDX'
    }),
    documentElement('formatVersion', 'SBOM Data Format Version', hasFormatVersion, {
      detail: data.specVersion || ''
    }),
    documentElement('generationContext', 'SBOM Generation Context', generation.present, {
      detail: generation.detail
    }),
    documentElement('timestamp', 'SBOM Timestamp', hasTimestamp),
    documentElement('toolName', 'SBOM Tool Name', hasToolName, {
      detail: creatorTools
        .map((t) => t.name)
        .filter(Boolean)
        .slice(0, 3)
        .join(', ')
    }),
    documentElement('toolVersion', 'SBOM Tool Version', hasToolVersion),
    documentElement('sbomVersion', 'SBOM Version', false, {
      status: 'na',
      detail: 'No stable SPDX 3 field mapping yet',
      blocksConformance: false
    })
  ];

  const component = [
    componentElement('name', 'Component Name', missingName, total),
    componentElement('producer', 'Component Producer', missingProducer, total),
    componentElement('version', 'Component Version', missingVersion, total),
    componentElement('identifier', 'Component Identifiers', missingIdentifier, total),
    componentElement('license', 'Component License', missingLicense, total),
    componentElement('hashValue', 'Component Hash Value', missingHash, total),
    componentElement('hashAlgorithm', 'Component Hash Algorithm', missingHashAlg, total),
    documentElement('dependency', 'Component Dependency Relationship', hasDependencyRel)
  ].map((el) => {
    if (el.level === 'document') return el;
    const status =
      el.missing.total === 0 ? 'pass' : el.covered > 0 ? 'partial' : total === 0 ? 'pass' : 'fail';
    return { ...el, status, blocksConformance: true };
  });

  // Silent blanks (empty, not NOASSERTION) on fields that allow unknown.
  const silentVersionGaps = packages.filter((p) => isBlankField(p.software_packageVersion)).length;
  const silentGaps = silentVersionGaps + missingLicense.length + missingHash.length;
  const maxSilentGaps = total * 3;
  const explicitUnknownPractice =
    total === 0 || silentGaps === 0
      ? practiceElement(
          'explicitUnknowns',
          'Explicitly Identifying Unknown Information',
          'pass',
          total === 0 ? '' : 'Gaps use explicit unknown markers'
        )
      : practiceElement(
          'explicitUnknowns',
          'Explicitly Identifying Unknown Information',
          silentGaps < maxSilentGaps ? 'partial' : 'fail',
          `${silentGaps} silent gap${silentGaps === 1 ? '' : 's'} (empty, not NOASSERTION)`
        );

  const practices = [
    practiceElement('machineProcessable', 'Machine-Processable Data', 'pass', 'SPDX JSON-LD'),
    explicitUnknownPractice,
    practiceElement('coverage', 'Coverage', 'na', 'Not assessable from this document alone'),
    practiceElement('frequency', 'Frequency', 'na', 'Not assessable from this document alone'),
    practiceElement(
      'distribution',
      'Distribution and Delivery',
      'na',
      'Not assessable from this document alone'
    ),
    practiceElement(
      'updates',
      'Accommodation of Updates to SBOM Data',
      'na',
      'Not assessable from this document alone'
    )
  ];

  const scored = [...metadata, ...component].filter((el) => el.blocksConformance !== false);
  const isConformant = scored.every((el) => {
    if (el.level === 'document') return el.present;
    return el.missing.total === 0;
  });

  return {
    referenceUrl: CISA_2026_REFERENCE_URL,
    pdfUrl: CISA_2026_PDF_URL,
    specVersion: data.specVersion || '',
    totalComponents: total,
    isConformant,
    metadata,
    component,
    practices
  };
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
 *   cisa2026: Object,
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

  const cisa2026 = buildCisa2026Report(data, {
    coveredPkgIds,
    missingName,
    missingSupplier,
    missingIdentifier,
    hasAuthor,
    hasTimestamp,
    hasDependencyRel,
    licenses
  });

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
    cisa2026,
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
