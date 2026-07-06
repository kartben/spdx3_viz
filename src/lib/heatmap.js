/**
 * Graph heatmap: turns a chosen risk signal into a per-element "heat" value the
 * graph renderer blooms as a glow. Each mode is a different lens over the parsed
 * model (open vulnerabilities, failing verifications, unverified requirements),
 * and every mode reduces to the same shape: a Map from element spdxId to
 * `{ intensity: 0..1, color }`. Only elements that actually carry the signal
 * appear in the map, so the overlay lights up relevant regions and nothing else.
 *
 * The scaling/colour logic lives here (pure, no DOM) so it stays testable; the
 * renderer only folds these values onto its render nodes and paints them.
 *
 * @module lib/heatmap
 */
import { CVSS_SEVERITIES } from '../config.js';

/**
 * The heat lenses offered in the graph toolbar. `key` selects the reduction in
 * {@link computeHeatIndex}; `icon` is an ICON_PATHS key; `color` is the swatch
 * shown in the menu/legend (the per-element colour can be more specific, e.g.
 * a vulnerability's CVSS-severity tint).
 *
 * @constant {Array<{key: string, label: string, short: string, icon: string, color: string, hint: string, emptyHint: string}>}
 */
export const HEAT_MODES = [
  {
    key: 'vuln',
    label: 'Active vulnerabilities',
    short: 'Vulnerabilities',
    icon: 'vulnerability',
    color: '#f43f5e',
    hint: 'Packages and files with an open vulnerability (affected or under investigation), hottest at the highest CVSS severity.',
    emptyHint: 'No open vulnerabilities in this SBOM.'
  },
  {
    key: 'failed',
    label: 'Failing verifications',
    short: 'Failing tests',
    icon: 'requirement_verification',
    color: '#f43f5e',
    hint: 'Requirements whose verification failed (hottest) or came back inconclusive.',
    emptyHint: 'No failing or inconclusive verifications.'
  },
  {
    key: 'unverified',
    label: 'Requirements lacking verification',
    short: 'Unverified reqs',
    icon: 'requirement',
    color: '#f59e0b',
    hint: 'Requirements with no passing verification, or no implementation link to trace at all.',
    emptyHint: 'Every requirement is verified.'
  }
];

const HEAT_MODE_BY_KEY = new Map(HEAT_MODES.map((m) => [m.key, m]));

/**
 * Metadata for a heat mode key (or a neutral descriptor for an unknown key).
 *
 * @param {string} key
 * @returns {{key: string, label: string, short: string, icon: string, color: string, hint: string, emptyHint: string}}
 */
export function heatModeMeta(key) {
  return (
    HEAT_MODE_BY_KEY.get(key) || {
      key: key || 'off',
      label: 'Off',
      short: 'Off',
      icon: 'toggle_heatmap',
      color: '#64748b',
      hint: '',
      emptyHint: ''
    }
  );
}

// A CVSS severity rank (1 none .. 5 critical) mapped onto a heat intensity, with
// a floor so even an unscored-but-open vulnerability still reads as warm.
function intensityForRank(rank) {
  if (!rank) return 0.4;
  return 0.35 + ((rank - 1) / 4) * 0.65;
}

// Open == the VEX status actually says this element is impacted; a CVE marked
// fixed / not-affected for a package must not heat it (mirrors packageRiskIndex).
function isOpenStatus(status) {
  return status === 'affected' || status === 'under_investigation';
}

// Keep the hotter of an existing entry and a candidate, so an element hit by
// several signals glows at its worst.
function upsertHotter(map, id, intensity, color) {
  const prev = map.get(id);
  if (!prev || intensity > prev.intensity) map.set(id, { intensity, color });
}

function vulnHeat(vulnerabilities) {
  const heat = new Map();
  vulnerabilities.forEach((v) => {
    const intensity = intensityForRank(v.severityRank || 0);
    const color = CVSS_SEVERITIES[v.severity]?.color || '#f43f5e';
    (v.assessments || []).forEach((a) => {
      if (!isOpenStatus(a.status) || !a.packageId) return;
      upsertHotter(heat, a.packageId, intensity, color);
    });
  });
  return heat;
}

// Requirements whose verification failed or is inconclusive. `statusOf` returns
// the requirementSafetyStatus object (null for non-Requirement elements), so a
// null result naturally filters out verifications/assumptions/evaluations.
function failedHeat(requirements, statusOf) {
  const heat = new Map();
  if (typeof statusOf !== 'function') return heat;
  requirements.forEach((r) => {
    const status = statusOf(r);
    if (!status) return;
    if (status.key === 'failed') upsertHotter(heat, r.spdxId, 1, '#f43f5e');
    else if (status.key === 'inconclusive') upsertHotter(heat, r.spdxId, 0.55, '#f59e0b');
  });
  return heat;
}

// Requirements lacking verification: an "unverified" outcome (no verification at
// all) or a traceability gap (no implementedBy link). The unverified case runs
// hotter since it's the direct answer to "what still needs verifying".
function unverifiedHeat(requirements, statusOf, implementedByCount) {
  const heat = new Map();
  if (typeof statusOf !== 'function') return heat;
  const countOf = typeof implementedByCount === 'function' ? implementedByCount : () => 1;
  requirements.forEach((r) => {
    const status = statusOf(r);
    if (!status) return; // not a Requirement
    if (status.key === 'unverified') upsertHotter(heat, r.spdxId, 0.8, '#f59e0b');
    else if (!countOf(r.spdxId)) upsertHotter(heat, r.spdxId, 0.55, '#fb923c');
  });
  return heat;
}

/**
 * Reduces the parsed model to a per-element heat map for the given mode.
 *
 * @param {string} mode - 'vuln' | 'failed' | 'unverified' | 'off'
 * @param {Object} data - Duck-typed inputs:
 *   - vulnerabilities: enriched CVE records ({severity, severityRank, assessments:[{packageId,status}]})
 *   - requirements: FunctionalSafety element list
 *   - requirementStatus: (req) => statusObj|null  (requirementSafetyStatus)
 *   - implementedByCount: (spdxId) => number
 * @returns {Map<string, {intensity: number, color: string}>}
 */
export function computeHeatIndex(mode, data = {}) {
  switch (mode) {
    case 'vuln':
      return vulnHeat(data.vulnerabilities || []);
    case 'failed':
      return failedHeat(data.requirements || [], data.requirementStatus);
    case 'unverified':
      return unverifiedHeat(
        data.requirements || [],
        data.requirementStatus,
        data.implementedByCount
      );
    default:
      return new Map();
  }
}
