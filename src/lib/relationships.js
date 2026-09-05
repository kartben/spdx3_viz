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
  hasTestCase: COLORS.testCase,
  hasTest: COLORS.testCase,
  hasSpecification: COLORS.specification,
  hasDocumentation: COLORS.documentation,
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
 *   start: (number|null), end: (number|null), byteStart: (number|null),
 *   byteEnd: (number|null), rangeLabel: string}|null}
 */
export function snippetFileRef(element, elementMap) {
  if (!element || element.type !== 'software_Snippet') return null;
  const fileId = element.software_snippetFromFile || '';
  const file = fileId ? elementMap?.get(fileId) : null;
  const fileName = file?.name || (fileId ? cleanName(fileId) : '');
  const baseName = fileName ? fileName.split('/').pop() : '';
  const lr = element.software_lineRange;
  const br = element.software_byteRange;
  return {
    fileId,
    fileName,
    baseName,
    name: element.name || '',
    start: lr?.beginIntegerRange ?? null,
    end: lr?.endIntegerRange ?? null,
    byteStart: br?.beginIntegerRange ?? null,
    byteEnd: br?.endIntegerRange ?? null,
    rangeLabel: snippetRangeLabel(element)
  };
}

/** "start-end" (or a single number) for a PositiveIntegerRange, or empty. */
export function integerRangeLabel(range) {
  if (!range || range.beginIntegerRange == null) return '';
  const { beginIntegerRange: a, endIntegerRange: b } = range;
  return b != null && b !== a ? `${a}-${b}` : String(a);
}

/** Compact "1-based line span" label for a snippet, e.g. "L289-364" or "L633". */
export function snippetLineLabel(element) {
  const span = integerRangeLabel(element?.software_lineRange);
  return span ? `L${span}` : '';
}

/**
 * Maps a 1-based inclusive byte span onto 1-based line numbers in `text`.
 * BASIL snippets record software_byteRange from a character offset; the source
 * viewer highlights lines, so we convert once the file text is in hand.
 *
 * @param {string} text
 * @param {number} begin
 * @param {number} [end]
 * @returns {{start: (number|null), end: (number|null)}}
 */
export function byteRangeToLineRange(text, begin, end) {
  if (text == null || begin == null) return { start: null, end: null };
  const bytes = new TextEncoder().encode(String(text));
  if (!bytes.length) return { start: null, end: null };
  const startByte = Math.max(0, Math.min(bytes.length - 1, begin - 1));
  const endByte = Math.max(startByte, Math.min(bytes.length - 1, (end ?? begin) - 1));
  const lineAt = (byteIdx) => {
    let line = 1;
    for (let i = 0; i < byteIdx; i++) {
      if (bytes[i] === 10) line++;
    }
    return line;
  };
  return { start: lineAt(startByte), end: lineAt(endByte) };
}

/** Line span, or a byte span when the producer recorded only software_byteRange. */
export function snippetRangeLabel(element) {
  const line = snippetLineLabel(element);
  if (line) return line;
  const br = element?.software_byteRange;
  if (!br || br.beginIntegerRange == null) return '';
  const { beginIntegerRange: a, endIntegerRange: b } = br;
  return b != null && b !== a ? `bytes ${a}-${b}` : `byte ${a}`;
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
  return snippetRangeLabel(element);
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
 * Unique 1-based line count across snippet ranges of one file. Overlapping or
 * adjacent spans merge so coverage chips do not double-count the same line.
 *
 * @param {Array<{start?: number|null, end?: number|null}>} snippets
 * @returns {number}
 */
export function snippetGroupLineCount(snippets) {
  const ranges = (snippets || [])
    .map((s) => {
      const start = s?.start;
      if (start == null) return null;
      const end = s.end == null || s.end < start ? start : s.end;
      return { start, end };
    })
    .filter(Boolean)
    .sort((a, b) => a.start - b.start || a.end - b.end);
  if (!ranges.length) return 0;
  let count = 0;
  let lo = ranges[0].start;
  let hi = ranges[0].end;
  for (let i = 1; i < ranges.length; i++) {
    const r = ranges[i];
    if (r.start <= hi + 1) {
      hi = Math.max(hi, r.end);
    } else {
      count += hi - lo + 1;
      lo = r.start;
      hi = r.end;
    }
  }
  return count + (hi - lo + 1);
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
 *   snippetIds: string[], lineCount: number }>, others: Array<Object>}}
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
    bucket.lineCount = snippetGroupLineCount(bucket.snippets);
    delete bucket._seen;
    out.push(bucket);
  }
  out.sort((a, b) => (a.baseName || '').localeCompare(b.baseName || ''));
  return { files: out, others };
}

function relationshipTargets(rel) {
  if (!rel) return [];
  return Array.isArray(rel.to) ? rel.to : rel.to ? [rel.to] : [];
}

/**
 * Snippets that belong on the graph as their own nodes, rather than being
 * redirected onto the file they were carved from.
 *
 * Zephyr-style snippets are leaf targets of implementedBy / hasEvidence: the
 * interesting object is the file, so the graph folds them away. BASIL-style
 * snippets are hubs: an API contains the snippet and the snippet then has
 * requirements, tests, or documentation. Those stay as nodes so the chain
 * LIBRARY → API → Snippet → Requirement remains visible.
 *
 * A snippet is a hub when it is the `from` of any relationship, or the `to` of
 * a `contains` whose `from` is not its software_snippetFromFile (the parent is
 * then a different element, typically the API, not just the source file).
 *
 * @param {Array<{spdxId?: string, software_snippetFromFile?: string}>} snippets
 * @param {Array<{from?: string, to?: string|string[], relationshipType?: string}>} relationships
 * @returns {Set<string>}
 */
export function collectSnippetHubIds(snippets, relationships) {
  const snippetIds = new Set();
  const fromFile = new Map();
  for (const s of snippets || []) {
    if (!s?.spdxId) continue;
    snippetIds.add(s.spdxId);
    fromFile.set(s.spdxId, s.software_snippetFromFile || '');
  }
  if (!snippetIds.size) return new Set();

  const hubs = new Set();
  for (const rel of relationships || []) {
    if (rel.from && snippetIds.has(rel.from)) hubs.add(rel.from);
    if (rel.relationshipType !== 'contains') continue;
    for (const t of relationshipTargets(rel)) {
      if (snippetIds.has(t) && rel.from !== fromFile.get(t)) hubs.add(t);
    }
  }
  return hubs;
}

/**
 * Resolves a graph endpoint that may be a snippet. Leaf snippets redirect to
 * their source file (and carry the snippet name for the "via snippet" hint).
 * Hub snippets, and anything that is not a snippet, pass through unchanged.
 *
 * @param {string} spdxId
 * @param {{snippetIds?: Set<string>|null, hubIds?: Set<string>|null, elementMap?: Map<string, Object>}} ctx
 * @returns {{id: string, snippet: string|null}}
 */
export function resolveGraphSnippetEndpoint(spdxId, { snippetIds, hubIds, elementMap } = {}) {
  if (!spdxId || !snippetIds?.has(spdxId) || hubIds?.has(spdxId)) {
    return { id: spdxId, snippet: null };
  }
  const ref = snippetFileRef(elementMap?.get(spdxId), elementMap);
  if (!ref || !ref.fileId) return { id: spdxId, snippet: null };
  return { id: ref.fileId, snippet: ref.name || cleanName(spdxId) };
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
  if (element.type === 'software_Snippet') {
    return snippetTargetLabel(element, elementMap) || element.name || cleanName(element.spdxId);
  }
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

  const fields = DETAIL_PROMOTED_FIELDS.flatMap((spec) => {
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

  // Snippet ranges are SPDX objects ({beginIntegerRange, endIntegerRange});
  // stringify would print "[object Object]", so format them here. The source
  // file id is resolved to a path so the card shows more than a bare SPDX id.
  if (element.type === 'software_Snippet') {
    const lines = integerRangeLabel(element.software_lineRange);
    if (lines) {
      fields.push({ prop: 'software_lineRange', label: 'Lines', value: lines, variant: 'badge' });
    }
    const bytes = integerRangeLabel(element.software_byteRange);
    if (bytes) {
      fields.push({ prop: 'software_byteRange', label: 'Bytes', value: bytes, variant: 'badge' });
    }
    const fileId = element.software_snippetFromFile;
    if (fileId) {
      const file = elementMap?.get(fileId);
      fields.push({
        prop: 'software_snippetFromFile',
        label: 'From file',
        value: file?.name || cleanName(fileId),
        variant: 'badge'
      });
    }
  }

  return fields;
}
