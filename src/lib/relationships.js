/**
 * Relationship helpers: edge colours, group labels, sort order, and the
 * display names / promoted fields shown for relationship endpoints.
 *
 * @module lib/relationships
 */
import {
  COLORS,
  DETAIL_PROMOTED_FIELDS,
  RELATIONSHIP_LABELS,
  RELATIONSHIP_SORT_ORDER
} from '../config.js';
import { cleanName } from './format.js';
import {
  displayLicenseExpression,
  renderLicenseExpression,
  licenseIndividualLabel
} from './licenses.js';
import { getVulnerabilityId } from './security.js';

// Relationship type -> edge colour. Module-level: getRelationshipColor is called
// once per edge per repaint on the graph, and per row in the detail panel.
const RELATIONSHIP_COLORS = {
  dependsOn: COLORS.package,
  contains: COLORS.file,
  generates: COLORS.build,
  hasInput: COLORS.buildInput,
  hasOutput: COLORS.buildOutput,
  hasDistributionArtifact: COLORS.distribution,
  ancestorOf: COLORS.buildLineage,
  usesTool: COLORS.tool,
  hasStaticLink: COLORS.staticLink,
  hasDynamicLink: COLORS.dynamicLink,
  hasOptionalComponent: COLORS.optionalComponent,
  hasPrerequisite: COLORS.prerequisite,
  hasVariant: COLORS.variant,
  runsOn: COLORS.hardware,
  implementedBy: COLORS.requirement,
  verifiedBy: COLORS.requirement,
  hasRequirement: COLORS.requirement,
  hasEvidence: COLORS.requirement,
  assumes: COLORS.requirement,
  conformsTo: COLORS.requirement,
  evaluationBasedOn: COLORS.requirement,
  tracedToDetail: COLORS.requirement,
  resolved: COLORS.buildOutput,
  hasResolution: COLORS.buildOutput,
  configures: COLORS.config,
  createdBy: COLORS.createdBy,
  suppliedBy: COLORS.createdBy,
  originatedBy: COLORS.createdBy,
  manufacturedBy: COLORS.createdBy,
  performedBy: COLORS.agent,
  hasConcludedLicense: COLORS.license,
  hasDeclaredLicense: COLORS.license,
  trainedOn: COLORS.ai,
  testedOn: COLORS.dataset,
  fixedIn: COLORS.vexFixed,
  doesNotAffect: COLORS.vexNotAffected,
  affects: COLORS.vexAffected,
  underInvestigation: COLORS.vexUnderInvestigation,
  affectsFile: COLORS.vulnerability
};

/**
 * Gets the color for a relationship type
 *
 * @param {string} relType - The relationship type
 * @returns {string} Hex color code
 */
export function getRelationshipColor(relType) {
  return RELATIONSHIP_COLORS[relType] || COLORS.default;
}

/**
 * Gets a human-readable label for a relationship group
 *
 * @param {string} relType - The relationship type
 * @param {string} direction - 'out' (from this element) or 'in' (to this element)
 * @returns {string} Human-readable label
 *
 * @example
 * getRelationshipGroupLabel('dependsOn', 'out') // returns 'Depends on'
 * getRelationshipGroupLabel('dependsOn', 'in') // returns 'Required by'
 */
export function getRelationshipGroupLabel(relType, direction) {
  const key = `${relType}:${direction}`;
  return RELATIONSHIP_LABELS[key] || (direction === 'out' ? relType : `${relType} (from)`);
}

/**
 * Gets the sort order for a relationship group
 * Lower numbers appear first in the detail panel
 *
 * @param {string} relType - The relationship type
 * @param {string} direction - 'out' or 'in'
 * @returns {number} Sort order value
 */
export function getRelationshipSortOrder(relType, direction) {
  const key = `${relType}:${direction}`;
  return RELATIONSHIP_SORT_ORDER[key] || 50;
}

/**
 * Gets the display name for a relationship target
 * Handles license URLs specially, otherwise uses element name or cleaned ID
 *
 * @param {string} spdxId - The target's SPDX ID
 * @param {Map} elementMap - Map of SPDX IDs to elements
 * @returns {string} Display name
 */
export function getRelationshipTargetDisplayName(spdxId, elementMap) {
  if (!spdxId) return '';

  // License URLs: show just the license name
  if (spdxId.startsWith('https://spdx.org/licenses/')) {
    return spdxId.replace('https://spdx.org/licenses/', '');
  }

  // ExpandedLicensing individual licenses (NoAssertionLicense / NoneLicense).
  // These named singletons aren't real elements, so they'd otherwise fall
  // through to cleanName (rendering "expandedlicensing NoAssertionLicense") or
  // the raw-IRI fallback (for the full-term-URL form). Show the human label.
  const individualLicense = licenseIndividualLabel(spdxId);
  if (individualLicense) return individualLicense;

  // Prefer a resolved element's own name/expression before the raw-URL fallback
  // below, since some producers use full http(s) URLs as spdxIds.
  const element = elementMap.get(spdxId);
  if (element?.simplelicensing_licenseExpression) {
    return displayLicenseExpression(element, elementMap);
  }
  const licenseExpr = renderLicenseExpression(element, elementMap);
  if (licenseExpr) return licenseExpr;
  if (element?.type === 'security_Vulnerability') return getVulnerabilityId(element);
  // A snippet reads as a slice of its file, so present the file, not the raw id.
  if (element?.type === 'software_Snippet') return snippetTargetLabel(element, elementMap);
  if (element?.name) return element.name;

  // Unresolved external http(s) reference: show the raw URL.
  if (spdxId.startsWith('http')) return spdxId;
  return cleanName(spdxId);
}

/**
 * Resolves a Snippet to the file it was carved from and its line range, so the
 * UI can make a link into a snippet read (and behave) like a link into the
 * file's source at the right section.
 *
 * @param {Object} element - A software_Snippet element
 * @param {Map} [elementMap] - Map of SPDX IDs to elements
 * @returns {{fileId: string, fileName: string, baseName: string, name: string,
 *   start: (number|null), end: (number|null)}|null}
 */
export function snippetFileRef(element, elementMap) {
  if (!element || element.type !== 'software_Snippet') return null;
  const fileId = element.software_snippetFromFile || '';
  const file = fileId ? elementMap?.get(fileId) : null;
  const fileName = file?.name || (fileId ? cleanName(fileId) : '');
  const baseName = fileName ? fileName.split('/').pop() : '';
  const lr = element.software_lineRange;
  return {
    fileId,
    fileName,
    baseName,
    name: element.name || '',
    start: lr?.beginIntegerRange ?? null,
    end: lr?.endIntegerRange ?? null
  };
}

/** Compact "1-based line span" label for a snippet, e.g. "L289-364" or "L633". */
export function snippetLineLabel(element) {
  const lr = element?.software_lineRange;
  if (!lr || lr.beginIntegerRange == null) return '';
  const { beginIntegerRange: a, endIntegerRange: b } = lr;
  return b != null && b !== a ? `L${a}-${b}` : `L${a}`;
}

/**
 * The interesting bit of a snippet name: the function/symbol when a producer
 * named it "func @ path:lines", otherwise the line span. Drops the path so a
 * file-grouped list can show just the symbol instead of repeating the file.
 *
 * @param {Object} element - A software_Snippet element
 * @returns {string}
 */
export function snippetSymbolLabel(element) {
  const name = (element?.name || '').trim();
  if (name) {
    const at = name.match(/^(.+?)\s+@\s+\S/);
    if (at) {
      const symbol = at[1].trim();
      // A path-like left side is not a symbol (e.g. "kernel/foo.c @ ...").
      if (symbol && !symbol.includes('/')) return symbol;
    }
    // Coverage snippets are often named "path:start-end" with no symbol.
    if (/[/\\].*:\d+(-\d+)?$/.test(name) || /^\S+\.\w+:\d+(-\d+)?$/.test(name)) {
      return snippetLineLabel(element) || name;
    }
    if (!name.includes('/')) return name;
  }
  return snippetLineLabel(element);
}

/** Line numbers only, for a dense coverage chip: "1018" or "1018-1032". */
export function snippetCompactLine(element) {
  const lr = element?.software_lineRange;
  if (!lr || lr.beginIntegerRange == null) return snippetSymbolLabel(element);
  const { beginIntegerRange: a, endIntegerRange: b } = lr;
  return b != null && b !== a ? `${a}-${b}` : String(a);
}

/**
 * File-flavored label for a snippet link: "<file> › <function-or-line-span>",
 * so it reads as "this points at a section of <file>".
 */
export function snippetTargetLabel(element, elementMap) {
  const ref = snippetFileRef(element, elementMap);
  if (!ref) return '';
  const detail = snippetSymbolLabel(element);
  const base = ref.baseName || 'snippet';
  return detail ? `${base} › ${detail}` : base;
}

/**
 * One-line label for several snippets of the same file, listing symbols
 * (or line spans) instead of a vague "N ranges".
 *
 * @param {string} baseName
 * @param {Array<Object>} elements
 * @param {{cap?: number}} [opts]
 * @returns {string}
 */
export function snippetFileGroupLabel(baseName, elements, { cap = 3 } = {}) {
  const base = baseName || 'snippet';
  const labels = (elements || []).map(snippetSymbolLabel).filter(Boolean);
  if (!labels.length) return base;
  if (labels.length === 1) return `${base} › ${labels[0]}`;
  const shown = labels.slice(0, cap);
  const extra = labels.length - shown.length;
  const detail = extra > 0 ? `${shown.join(', ')} +${extra}` : shown.join(', ');
  return `${base} › ${detail}`;
}

/**
 * Group snippet elements by the file they were carved from. Non-snippets (and
 * unresolved ids) are returned separately so a card can render files as rows
 * and everything else as ordinary links.
 *
 * @param {Array<Object>} elements
 * @param {Map} [elementMap]
 * @param {{labelOf?: (el: Object) => string, dedupeRanges?: boolean}} [opts]
 * @returns {{files: Array<{fileId: string, fileName: string, baseName: string,
 *   snippets: Array<{id: string, label: string, start: number|null, end: number|null}>,
 *   snippetIds: string[] }>, others: Array<Object>}}
 */
export function groupSnippetsByFile(elements, elementMap, { labelOf, dedupeRanges } = {}) {
  const label = typeof labelOf === 'function' ? labelOf : snippetSymbolLabel;
  const files = new Map();
  const others = [];
  for (const el of elements || []) {
    if (!el) continue;
    if (el.type !== 'software_Snippet') {
      others.push(el);
      continue;
    }
    const ref = snippetFileRef(el, elementMap);
    const fileKey = ref?.fileId || el.spdxId || '';
    let bucket = files.get(fileKey);
    if (!bucket) {
      bucket = {
        fileId: ref?.fileId || '',
        fileName: ref?.fileName || '',
        baseName: ref?.baseName || 'snippet',
        snippets: [],
        _seen: dedupeRanges ? new Set() : null
      };
      files.set(fileKey, bucket);
    }
    if (bucket._seen) {
      const rangeKey = `${ref?.start ?? ''}:${ref?.end ?? ''}`;
      if (bucket._seen.has(rangeKey)) continue;
      bucket._seen.add(rangeKey);
    }
    bucket.snippets.push({
      id: el.spdxId,
      label: label(el) || 'snippet',
      start: ref?.start ?? null,
      end: ref?.end ?? null
    });
  }
  const out = [];
  for (const bucket of files.values()) {
    bucket.snippets.sort(
      (a, b) => (a.start ?? 0) - (b.start ?? 0) || a.label.localeCompare(b.label)
    );
    bucket.snippetIds = bucket.snippets.map((s) => s.id);
    delete bucket._seen;
    out.push(bucket);
  }
  out.sort((a, b) => (a.baseName || '').localeCompare(b.baseName || ''));
  return { files: out, others };
}

/**
 * Human-readable title for an element in the detail panel header
 *
 * @param {Object} element - The SPDX element
 * @param {Map} [elementMap] - Map of SPDX IDs to elements (resolves custom license ids)
 * @returns {string} Display title
 */
export function getElementDisplayName(element, elementMap) {
  if (!element) return '';
  if (element.simplelicensing_licenseExpression) {
    return displayLicenseExpression(element, elementMap);
  }
  const licenseExpr = renderLicenseExpression(element, elementMap);
  if (licenseExpr) return licenseExpr;
  if (element.type === 'security_Vulnerability') return getVulnerabilityId(element);
  if (element.name) return element.name;
  return cleanName(element.spdxId);
}

/**
 * Promoted fields for the detail panel (see DETAIL_PROMOTED_FIELDS in config)
 *
 * @param {Object} element - The SPDX element
 * @param {Map} [elementMap] - Map of SPDX IDs to elements (resolves custom license ids)
 * @returns {Array<{prop: string, label: string, value: string, variant: string}>}
 */
export function getDetailPromotedFields(element, elementMap) {
  if (!element) return [];

  return DETAIL_PROMOTED_FIELDS.flatMap((spec) => {
    const value = element[spec.prop];
    if (value == null || value === '') return [];
    if (spec.types && !spec.types.includes(element.type)) return [];
    return [
      {
        prop: spec.prop,
        label: spec.label,
        value:
          spec.prop === 'simplelicensing_licenseExpression'
            ? displayLicenseExpression(element, elementMap)
            : String(value),
        variant: spec.variant || 'badge'
      }
    ];
  });
}
