/**
 * Formatting & small utilities: SPDX id / file-name cleaning, dates, byte
 * sizes, URL normalization, "meaningful value" checks, and clipboard.
 *
 * @module lib/format
 */

/**
 * Cleans an SPDX ID for display by removing prefixes and formatting
 *
 * @param {string} spdxId - The SPDX ID to clean
 * @returns {string} Cleaned, human-readable name
 *
 * @example
 * cleanName('urn:spdx:packages/my-package') // returns 'my package'
 */
export function cleanName(spdxId) {
  if (!spdxId) return '';
  return spdxId
    .replace(/^[^:]+:(packages|files|tools|builds|agents)\//, '')
    .replace(/^File-/, '')
    .replace(/--/g, '/')
    .replace(/__/g, '/')
    .replace(/_/g, ' ');
}

/**
 * Gets the display name for a file element
 * Prefers the element's name property, falls back to cleaned SPDX ID
 *
 * @param {string} spdxId - The file's SPDX ID
 * @param {Map} elementMap - Map of SPDX IDs to elements
 * @returns {string} Display name for the file
 */
export function cleanFileName(spdxId, elementMap) {
  const element = elementMap.get(spdxId);
  if (element?.name) return element.name;
  return cleanName(spdxId);
}

/**
 * Extracts the file extension from a filename
 *
 * @param {string} name - The filename
 * @returns {string} File extension (e.g., '.js', '.c') or empty string
 *
 * @example
 * fileExt('main.c') // returns '.c'
 * fileExt('Makefile') // returns ''
 */
export function fileExt(name) {
  if (!name) return '';
  const match = name.match(/(\.[a-zA-Z0-9]+)$/);
  return match ? match[1] : '';
}

/**
 * Extracts a directory prefix from a path-like file name, used to cluster
 * large flat file sets in the graph.
 *
 * @param {string} name - The file name / path (e.g. 'arch/x86/boot/a20.c')
 * @param {number} [depth=2] - How many leading path segments to keep
 * @returns {string} Directory prefix (e.g. 'arch/x86'), or '' when there is no
 *   directory component (top-level files are left ungrouped)
 *
 * @example
 * dirPrefix('arch/x86/boot/a20.c') // returns 'arch/x86'
 * dirPrefix('Makefile')            // returns ''
 */
export function dirPrefix(name, depth = 2) {
  if (!name) return '';
  const p = name.replace(/^\.?\//, '');
  const slash = p.lastIndexOf('/');
  if (slash < 0) return '';
  return p.slice(0, slash).split('/').filter(Boolean).slice(0, depth).join('/');
}

/**
 * Formats an ISO date string for display
 *
 * @param {string} dateStr - ISO date string
 * @returns {string} Localized date string or original string on error
 *
 * @example
 * formatDate('2024-01-15T10:30:00Z') // returns '1/15/2024, 10:30:00 AM'
 */
export function formatDate(dateStr) {
  if (!dateStr) return '';
  try {
    return new Date(dateStr).toLocaleString();
  } catch {
    return dateStr;
  }
}

/**
 * Reduces an SPDX enumerated (vocab) value to its trailing token so it renders
 * and compares consistently regardless of how the JSON-LD context serialized it.
 *
 * The same enum literal can appear as a bare token (`pass`), a CURIE
 * (`spdx:FunctionalSafety/EvaluationResultType/pass`), or a full term IRI
 * (`https://spdx.org/rdf/3.1/terms/FunctionalSafety/EvaluationResultType/pass`),
 * depending on whether the context's term base is current. All three mean the
 * same value, so we keep only the final path/prefix segment.
 *
 * @param {*} value
 * @returns {string} The trailing token (e.g. 'pass'), or '' when empty.
 *
 * @example
 * enumValue('spdx:FunctionalSafety/EvaluationResultType/pass') // 'pass'
 * enumValue('test') // 'test'
 */
export function enumValue(value) {
  if (value == null) return '';
  const s = String(value).trim();
  if (s === '') return '';
  const seg = s.split(/[/#]/).pop();
  const colon = seg.lastIndexOf(':');
  return colon >= 0 ? seg.slice(colon + 1) : seg;
}

const NO_ASSERTION = /^(noassertion|none)$/i;

/**
 * True when a value carries real information (not empty, not a NOASSERTION/NONE
 * sentinel).
 *
 * @param {*} value
 * @returns {boolean}
 */
export function isMeaningfulValue(value) {
  if (value == null) return false;
  const s = String(value).trim();
  return s !== '' && !NO_ASSERTION.test(s);
}

/**
 * Formats a byte count as a human-readable size using 1000-based (SI) units.
 * Returns '' for anything that isn't a positive, finite number.
 *
 * @param {number} bytes
 * @returns {string}
 */
export function formatByteSize(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let n = bytes;
  let i = 0;
  while (n >= 1000 && i < units.length - 1) {
    n /= 1000;
    i++;
  }
  const rounded = i === 0 ? n : n >= 100 ? Math.round(n) : Math.round(n * 10) / 10;
  return `${rounded} ${units[i]}`;
}

// SPDX Hardware profile QUDT unit tokens used in sample SBOMs. Unknown tokens fall
// back to the raw unitQUDT value.
const QUDT_UNIT_LABELS = {
  MilliM: 'mm',
  M: 'm',
  GM: 'g',
  KiloGM: 'kg'
};

function formatMeasureQuantity(quantity) {
  const n = Number(quantity);
  if (!Number.isFinite(n)) return '';
  return Number.isInteger(n) ? String(n) : String(n);
}

/**
 * Formats an SPDX UnitOfMeasure value (MeasureOfMass, MeasureOfLength, …) for
 * display. Returns '' when quantity is missing or not numeric.
 *
 * @param {{ quantity?: number, unitQUDT?: string } | null | undefined} measure
 * @returns {string}
 */
export function formatQudtMeasure(measure) {
  if (!measure || typeof measure !== 'object') return '';
  const quantity = formatMeasureQuantity(measure.quantity);
  if (!quantity) return '';
  const unit = QUDT_UNIT_LABELS[measure.unitQUDT] || measure.unitQUDT || '';
  return unit ? `${quantity} ${unit}` : quantity;
}

/**
 * Formats a hardware_Dimensions element as "X × Y × Z unit" when all axes share
 * the same QUDT unit, otherwise joins each axis with its own unit label.
 *
 * @param {{ hardware_xAxisLength?: object, hardware_yAxisLength?: object, hardware_zAxisLength?: object } | null | undefined} dims
 * @returns {string}
 */
export function formatHardwareDimensions(dims) {
  if (!dims || typeof dims !== 'object') return '';
  const measures = [
    dims.hardware_xAxisLength,
    dims.hardware_yAxisLength,
    dims.hardware_zAxisLength
  ].filter((m) => m && Number.isFinite(Number(m.quantity)));
  if (!measures.length) return '';
  const unit = measures[0]?.unitQUDT;
  const sameUnit = measures.every((m) => m.unitQUDT === unit);
  if (sameUnit && unit) {
    const nums = measures.map((m) => formatMeasureQuantity(m.quantity)).filter(Boolean);
    const label = QUDT_UNIT_LABELS[unit] || unit;
    return `${nums.join(' × ')} ${label}`;
  }
  return measures.map((m) => formatQudtMeasure(m)).filter(Boolean).join(' × ');
}

/**
 * Normalizes a download/VCS location into a followable http(s) href, stripping a
 * leading `git+`; returns '' for non-web or NOASSERTION locations.
 *
 * @param {string} value
 * @returns {string} An http(s) URL, or '' when not linkable
 */
export function normalizeUrl(value) {
  if (!isMeaningfulValue(value)) return '';
  const stripped = String(value)
    .trim()
    .replace(/^git\+/, '');
  return /^https?:\/\//i.test(stripped) ? stripped : '';
}

/**
 * Extracts displayable external identifiers (PackageURL, CPE, gitoid, …) from a
 * package or tool element.
 *
 * @param {Object} element - The SPDX element
 * @returns {Array<{type: string, label: string, identifier: string, isUrl: boolean}>}
 */

/**
 * Copies text to the clipboard
 *
 * @param {string} text - Text to copy
 * @returns {Promise<void>}
 */
export async function copyToClipboard(text) {
  return navigator.clipboard.writeText(text);
}
