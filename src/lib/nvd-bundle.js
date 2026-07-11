/**
 * Consumes a pre-built, statically-hosted NVD CPE→CVE index (see
 * scripts/build-nvd-index.mjs) so CPE matching can run without calling NVD live:
 * no CORS, no rate limits, offline once fetched. The index is a small
 * `manifest.json` (product → {part, offset, length}) plus a handful of packed
 * `part-*.ndjson` files; the client fetches the manifest once, then Range-fetches
 * only the byte spans for the products in its SBOM.
 *
 * This module is the pure, DOM-free half: the compact row/range format, the
 * version-range match, and the per-target fetch plan. Unit tested; also used by
 * the worker.
 *
 * @module lib/nvd-bundle
 */
import { compareVersions } from './nvd.js';

/** Manifest keys join vendor and product with a space (CPE tokens contain no spaces). */
export function bundleKey(vendor, product) {
  return `${String(vendor || '').toLowerCase()} ${String(product || '').toLowerCase()}`;
}

// Single-char CVSS severity codes used in the packed rows, expanded on read.
const SEV_FROM_CODE = { c: 'critical', h: 'high', m: 'medium', l: 'low', n: 'none' };

/**
 * @typedef {Object} BundleRange
 * @property {string} [x] - exact version (criteria pinned a version)
 * @property {string} [si] - versionStartIncluding
 * @property {string} [se] - versionStartExcluding
 * @property {string} [ei] - versionEndIncluding
 * @property {string} [ee] - versionEndExcluding
 */

/**
 * Whether a component version falls inside a packed range. Mirrors the live
 * matcher's semantics: an exact-version range matches only that version; an
 * unbounded range matches everything; otherwise the bounds decide.
 *
 * @param {string} version
 * @param {BundleRange} r
 * @returns {boolean}
 */
export function bundleRangeApplies(version, r) {
  if (!r) return false;
  if (r.x) return !!version && compareVersions(version, r.x) === 0;
  const hasRange = r.si || r.se || r.ei || r.ee;
  if (!hasRange) return true;
  if (!version) return true;
  if (r.si && compareVersions(version, r.si) < 0) return false;
  if (r.se && compareVersions(version, r.se) <= 0) return false;
  if (r.ei && compareVersions(version, r.ei) > 0) return false;
  if (r.ee && compareVersions(version, r.ee) >= 0) return false;
  return true;
}

/**
 * Expands a packed row into a provider finding, shaped exactly like the live NVD
 * worker's output so both flow through buildOnlineVulns identically.
 *
 * @param {{id:string,sc:(number|null),sv:string,cv:string,cw:number[],pub:string}} row
 * @param {string[]} elementIds
 * @returns {Object}
 */
export function bundleRowToFinding(row, elementIds) {
  const cveId = `CVE-${row.id}`;
  const cvss =
    row.sc != null || row.sv
      ? {
          score: row.sc ?? null,
          severity: SEV_FROM_CODE[row.sv] || '',
          vector: '',
          version: row.cv || ''
        }
      : null;
  return {
    provider: 'NVD',
    cveId,
    displayId: cveId,
    summary: '',
    details: '',
    cvss,
    cwes: (row.cw || []).map((n) => `CWE-${n}`),
    references: [{ url: `https://nvd.nist.gov/vuln/detail/${cveId}`, type: 'nvd' }],
    published: row.pub || '',
    elementIds
  };
}

/**
 * Matches one product's packed rows (its shard) against a target's declared
 * versions, returning a finding per affected CVE.
 *
 * @param {Array<Object>} rows - parsed shard (array of packed rows)
 * @param {{entries: Array<{version:string, elementIds:string[]}>}} target
 * @returns {Object[]} provider findings
 */
export function matchBundleShard(rows, target) {
  const out = [];
  for (const row of rows || []) {
    const affected = new Set();
    for (const entry of target.entries || []) {
      if ((row.r || []).some((rg) => bundleRangeApplies(entry.version, rg))) {
        entry.elementIds.forEach((id) => affected.add(id));
      }
    }
    if (affected.size) out.push(bundleRowToFinding(row, [...affected]));
  }
  return out;
}

/**
 * Builds the fetch plan: for each target that the manifest knows, the part file
 * and byte range holding its shard. Targets absent from the manifest are skipped
 * (no CVEs for that vendor:product).
 *
 * @param {{parts:string[], index:Object<string, [number,number,number]>}} manifest
 * @param {Array<{vendor:string, product:string}>} targets
 * @returns {Array<{target:Object, part:string, offset:number, length:number}>}
 */
export function planBundleFetches(manifest, targets) {
  const index = manifest?.index || {};
  const parts = manifest?.parts || [];
  const plan = [];
  for (const t of targets || []) {
    const loc = index[bundleKey(t.vendor, t.product)];
    if (loc && parts[loc[0]]) {
      plan.push({ target: t, part: parts[loc[0]], offset: loc[1], length: loc[2] });
    }
  }
  return plan;
}
