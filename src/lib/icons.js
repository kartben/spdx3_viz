/**
 * Maps an SPDX element (or node type, or app view) to a representative Material
 * Design icon, used app-wide: the graph's optional "icon nodes" mode, the
 * sidebar nav, the detail panel, and every list-view row.
 *
 * The glyphs are Google's Material Design Icons (the `filled` style). Their
 * single-path 24x24 `d` strings live in the generated ./icon-paths.js (built by
 * scripts/gen-node-icons.mjs); here we resolve an element/type/view to a key and
 * either render it on the canvas with `Path2D` (graph) or emit an inline `<svg>`
 * (the DOM UI), tinted by the caller.
 *
 * Everything about "which thing gets which glyph" lives in this one file: the
 * *IconKey helpers pick an ICON_PATHS key from an element's type and its
 * distinguishing fields (a File's fileKind/purpose, an Agent's
 * Person/Organization/SoftwareAgent subclass, a Package's purpose, a
 * FunctionalSafety artifact's class, ...).
 *
 * @module lib/icons
 */
import { isA, CLASS } from '../spdx/model.js';
import { getNodeType } from './nodes.js';
import { ICON_PATHS } from './icon-paths.js';

export { ICON_PATHS };

/** The representative glyph for a whole node type (used by the legend). */
const TYPE_ICON = {
  package: 'package',
  ai: 'ai',
  dataset: 'dataset',
  file: 'file',
  hardware: 'hardware',
  requirement: 'requirement',
  tool: 'tool',
  build: 'build',
  config: 'config',
  agent: 'agent_person',
  license: 'license',
  external: 'external',
  vulnerability: 'vulnerability'
};

// The full SPDX 3 SoftwarePurpose vocabulary (software_primaryPurpose) -> icon
// key. A purpose is a property of the shared SoftwareArtifact base, so a File
// and a Package with the same purpose read the same glyph (an application is an
// application whether shipped as a file or a package). File vs Package only
// decides the *default* when there's no meaningful purpose (see below).
const PURPOSE_ICON = {
  application: 'application',
  archive: 'archive',
  bom: 'requirement',
  configuration: 'config',
  container: 'container',
  data: 'data',
  device: 'hardware',
  deviceDriver: 'hardware',
  diskImage: 'image',
  documentation: 'documentation',
  evidence: 'requirement_verification',
  executable: 'executable',
  file: 'file',
  filesystemImage: 'image',
  firmware: 'hardware',
  framework: 'container',
  install: 'install',
  library: 'library',
  manifest: 'documentation',
  model: 'ai',
  module: 'module',
  operatingSystem: 'operating_system',
  patch: 'patch',
  requirement: 'requirement',
  source: 'source',
  specification: 'documentation',
  test: 'test'
};

function fileIconKey(el) {
  // software_fileKind (SoftwareFileKindType: directory | file); a directory wins
  // over purpose, otherwise the purpose glyph, else the generic file/document.
  if (el?.software_fileKind === 'directory') return 'folder';
  return PURPOSE_ICON[el?.software_primaryPurpose] || 'file';
}

function packageIconKey(el) {
  // Same purpose glyphs as files; only the no-purpose default differs (a box).
  return PURPOSE_ICON[el?.software_primaryPurpose] || 'package';
}

function agentIconKey(el) {
  const t = el?.type;
  if (isA(t, CLASS.Organization)) return 'agent_org';
  if (isA(t, CLASS.SoftwareAgent)) return 'agent_bot';
  return 'agent_person'; // Person or a bare Agent
}

function requirementIconKey(el) {
  const t = el?.type;
  if (isA(t, CLASS.functionalsafety_RequirementVerification)) return 'requirement_verification';
  if (isA(t, CLASS.functionalsafety_Assumption)) return 'assumption';
  if (isA(t, CLASS.functionalsafety_EvaluationResult)) return 'evaluation';
  return 'requirement';
}

/**
 * Picks the icon key for a graph node from its element and node type. Returns
 * `null` for the generic 'other' bucket so the renderer keeps a plain circle.
 *
 * @param {Object} el - The SPDX element backing the node (may be a placeholder)
 * @param {string} nodeType - The node type from getNodeType()
 * @returns {string|null} An ICON_PATHS key, or null to fall back to a circle
 */
export function iconKeyForElement(el, nodeType) {
  switch (nodeType) {
    case 'file':
      return fileIconKey(el);
    case 'package':
      return packageIconKey(el);
    case 'agent':
      return agentIconKey(el);
    case 'requirement':
      return requirementIconKey(el);
    default:
      return TYPE_ICON[nodeType] || null;
  }
}

/** The representative icon key for a node type, for legend swatches. */
export function iconKeyForType(nodeType) {
  return TYPE_ICON[nodeType] || null;
}

/** The icon key for an element, resolving its node type + variant fields. */
export function iconKeyForEl(el) {
  return iconKeyForElement(el, getNodeType(el));
}

/** The Material icon path `d` for a key, or '' if unknown. */
export function getNodeIconPath(iconKey) {
  return (iconKey && ICON_PATHS[iconKey]) || '';
}

/**
 * Inline `<svg>` markup for an icon key, or '' if the key has no glyph. The path
 * data is from our own generated set (never user input), so it's safe to inject
 * with x-html; `fill="currentColor"` lets the caller tint it via CSS `color`.
 *
 * @param {string|null} iconKey
 * @param {string} [className] - classes on the <svg> (sizing/colour)
 * @returns {string}
 */
export function iconSvg(iconKey, className = 'w-4 h-4') {
  const d = getNodeIconPath(iconKey);
  if (!d) return '';
  return `<svg viewBox="0 0 24 24" class="${className}" fill="currentColor" aria-hidden="true"><path d="${d}"/></svg>`;
}

/** Inline `<svg>` for an element's variant-aware icon. */
export function elementIconSvg(el, className) {
  return iconSvg(iconKeyForEl(el), className);
}

/** Inline `<svg>` for a node type's representative icon. */
export function typeIconSvg(nodeType, className) {
  return iconSvg(iconKeyForType(nodeType), className);
}

// Path2D objects are canvas-independent, so cache one per key across renders.
const path2dCache = new Map();

/** A cached Path2D for a key (24x24 space), or null if the key has no glyph. */
export function getNodeIconPath2D(iconKey) {
  if (!iconKey) return null;
  if (path2dCache.has(iconKey)) return path2dCache.get(iconKey);
  const d = ICON_PATHS[iconKey];
  const p = d ? new Path2D(d) : null;
  path2dCache.set(iconKey, p);
  return p;
}
