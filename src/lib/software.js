/**
 * Software profile display helpers: primary-purpose facets, the per-package
 * description gaps the Packages list filters on, and path splitting / directory
 * facets for the Files list.
 *
 * Everything here is a pure function over already-parsed elements, so the views
 * can run one memoized pass over a large SBOM instead of recomputing per
 * rendered row.
 *
 * @module lib/software
 */
import { dirPrefix, enumValue, hasMeaningfulRef, isMeaningfulValue } from './format.js';
import { getExternalIdentifiers } from './provenance.js';

/** Facet key for packages that declare no `software_primaryPurpose`. */
export const NO_PURPOSE_KEY = '(unspecified)';

/** Purpose tokens whose plain title-casing reads wrong. */
const PURPOSE_LABEL_OVERRIDES = {
  bom: 'BOM',
  os: 'OS'
};

/**
 * Human label for a `software_primaryPurpose` value ('operatingSystem' →
 * 'Operating system'). Accepts the bare token, a CURIE, or a full term IRI.
 *
 * @param {*} value
 * @returns {string} Label, or 'Unspecified' when the value is empty
 */
export function primaryPurposeLabel(value) {
  const token = enumValue(value);
  if (!token) return 'Unspecified';
  if (PURPOSE_LABEL_OVERRIDES[token]) return PURPOSE_LABEL_OVERRIDES[token];
  const spaced = token.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase();
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

/**
 * Counts packages per declared primary purpose. Declared purposes come first
 * (most used first); the "unspecified" bucket is always last so it reads as the
 * leftovers rather than as a category.
 *
 * @param {Array<Object>} packages
 * @returns {Array<{key: string, label: string, count: number}>}
 */
export function buildPurposeFacets(packages) {
  const counts = new Map();
  (packages || []).forEach((p) => {
    const key = enumValue(p?.software_primaryPurpose) || NO_PURPOSE_KEY;
    counts.set(key, (counts.get(key) || 0) + 1);
  });
  return [...counts.entries()]
    .map(([key, count]) => ({
      key,
      label: key === NO_PURPOSE_KEY ? 'Unspecified' : primaryPurposeLabel(key),
      count
    }))
    .sort((a, b) => {
      const aLast = a.key === NO_PURPOSE_KEY;
      const bLast = b.key === NO_PURPOSE_KEY;
      if (aLast !== bLast) return aLast ? 1 : -1;
      return b.count - a.count || a.label.localeCompare(b.label);
    });
}

/**
 * True when a package declares the given primary purpose. `NO_PURPOSE_KEY`
 * matches packages that declare none.
 *
 * @param {Object} pkg
 * @param {string} key
 * @returns {boolean}
 */
export function packageHasPurpose(pkg, key) {
  return (enumValue(pkg?.software_primaryPurpose) || NO_PURPOSE_KEY) === key;
}

/**
 * The per-package description gaps the Packages list can filter on, in the order
 * their chips render. These are the component-level fields every SBOM baseline
 * asks for (supplier, version, unique identifier) plus the license, so an empty
 * chip row means the list is fully described.
 *
 * @type {string[]}
 */
export const PACKAGE_GAP_ORDER = ['version', 'license', 'supplier', 'identifier'];

/** Chip labels and tooltips per gap key. */
export const PACKAGE_GAP_META = {
  version: {
    key: 'version',
    label: 'No version',
    title: 'Packages with no software_packageVersion'
  },
  license: {
    key: 'license',
    label: 'No license',
    title: 'Packages with no declared or concluded license'
  },
  supplier: {
    key: 'supplier',
    label: 'No supplier',
    title: 'Packages with no suppliedBy / originatedBy agent'
  },
  identifier: {
    key: 'identifier',
    label: 'No identifier',
    title: 'Packages with no PackageURL, CPE, or other external identifier'
  }
};

/**
 * Which of the described fields a package is missing.
 *
 * @param {Object} pkg
 * @param {boolean} hasLicense - Whether the package carries a meaningful license
 * @returns {{version: boolean, license: boolean, supplier: boolean, identifier: boolean}}
 */
export function packageGaps(pkg, hasLicense) {
  return {
    version: !isMeaningfulValue(pkg?.software_packageVersion),
    license: !hasLicense,
    supplier:
      !hasMeaningfulRef(pkg?.suppliedBy ?? pkg?.software_suppliedBy) &&
      !hasMeaningfulRef(pkg?.originatedBy ?? pkg?.software_originatedBy),
    identifier:
      !isMeaningfulValue(pkg?.software_packageUrl) && getExternalIdentifiers(pkg).length === 0
  };
}

/**
 * How well a package list describes its components: a gap count per field plus
 * a three-way split (no gaps / one or two / three or more) for the rollup bar.
 *
 * @param {Array<Object>} packages
 * @param {(pkg: Object) => boolean} hasLicense - License lookup for one package
 * @returns {{total: number, gapCounts: Object<string, number>,
 *   buckets: {full: number, partial: number, sparse: number}, fullPct: number}}
 */
export function summarizePackageDescription(packages, hasLicense) {
  /** @type {Object<string, number>} */
  const gapCounts = {};
  PACKAGE_GAP_ORDER.forEach((k) => (gapCounts[k] = 0));
  const buckets = { full: 0, partial: 0, sparse: 0 };

  (packages || []).forEach((pkg) => {
    const gaps = packageGaps(pkg, hasLicense(pkg));
    let missing = 0;
    PACKAGE_GAP_ORDER.forEach((k) => {
      if (gaps[k]) {
        gapCounts[k]++;
        missing++;
      }
    });
    if (missing === 0) buckets.full++;
    else if (missing <= 2) buckets.partial++;
    else buckets.sparse++;
  });

  const total = packages?.length || 0;
  return {
    total,
    gapCounts,
    buckets,
    fullPct: total ? Math.round((buckets.full / total) * 100) : 0
  };
}

/** Rollup-bar segments, worst last so the bar reads best-first like a progress bar. */
export const PACKAGE_DESCRIPTION_SEGMENTS = [
  { key: 'full', label: 'Fully described', color: '#10b981' },
  { key: 'partial', label: 'Some gaps', color: '#f59e0b' },
  { key: 'sparse', label: 'Name only', color: '#64748b' }
];

/**
 * Splits a file path into its directory prefix and its base name, so a list row
 * can put the file name first and let the (often much longer) path truncate.
 *
 * @param {string} name - File name, usually a path
 * @returns {{dir: string, base: string}} `dir` keeps its trailing slash; both are
 *   '' / the whole name when there is no directory component
 *
 * @example
 * splitFilePath('usr/lib/libc.so') // { dir: 'usr/lib/', base: 'libc.so' }
 * splitFilePath('Makefile')        // { dir: '', base: 'Makefile' }
 */
export function splitFilePath(name) {
  const s = String(name || '');
  const slash = s.lastIndexOf('/');
  if (slash < 0) return { dir: '', base: s };
  const base = s.slice(slash + 1);
  return base ? { dir: s.slice(0, slash + 1), base } : { dir: '', base: s };
}

/**
 * The most populated directories in a file list, as filter facets. Capped
 * because a rootfs SBOM carries thousands of distinct directories; files with no
 * directory component are left out rather than lumped into a fake bucket.
 *
 * @param {Array<Object>} files
 * @param {number} [limit=12] - How many directories to return
 * @param {number} [depth=2] - Leading path segments each facet groups on
 * @returns {Array<{key: string, label: string, count: number}>}
 */
export function buildDirectoryFacets(files, limit = 12, depth = 2) {
  const counts = new Map();
  (files || []).forEach((f) => {
    const dir = dirPrefix(f?.name, depth);
    if (!dir) return;
    counts.set(dir, (counts.get(dir) || 0) + 1);
  });
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, Math.max(0, limit))
    .map(([key, count]) => ({ key, label: key, count }));
}
