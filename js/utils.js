/**
 * SPDX 3.0 SBOM Visualizer - Utility Functions
 *
 * Helper functions for data formatting, name cleaning,
 * and common operations used throughout the application.
 *
 * @module utils
 */

import {
  COLORS,
  DETAIL_PROMOTED_FIELDS,
  RELATIONSHIP_LABELS,
  RELATIONSHIP_SORT_ORDER
} from './config.js';

/* ==========================================================================
   Name Cleaning Functions
   Functions to clean and format SPDX IDs for display
   ========================================================================== */

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
 * large flat file sets in the graph (e.g. the Linux kernel's 3k+ files).
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

/* ==========================================================================
   Date Formatting
   Functions to format dates for display
   ========================================================================== */

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

/* ==========================================================================
   Relationship Helpers
   Functions for relationship color coding and labels
   ========================================================================== */

/**
 * Gets the color for a relationship type
 *
 * @param {string} relType - The relationship type
 * @returns {string} Hex color code
 */
export function getRelationshipColor(relType) {
  const colorMap = {
    dependsOn: COLORS.package,
    contains: COLORS.file,
    generates: COLORS.build,
    hasInput: COLORS.buildInput,
    hasOutput: COLORS.buildOutput,
    hasDistributionArtifact: COLORS.distribution,
    ancestorOf: COLORS.buildLineage,
    usesTool: COLORS.tool,
    hasStaticLink: COLORS.staticLink,
    configures: COLORS.config,
    hasConcludedLicense: COLORS.license,
    hasDeclaredLicense: COLORS.license
  };
  return colorMap[relType] || COLORS.default;
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
 * getRelationshipGroupLabel('dependsOn', 'in') // returns 'Depended on by'
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
  if (spdxId.startsWith('http')) {
    return spdxId;
  }

  const element = elementMap.get(spdxId);
  if (element?.simplelicensing_licenseExpression) {
    return element.simplelicensing_licenseExpression;
  }
  if (element?.name) return element.name;
  return cleanName(spdxId);
}

/**
 * Human-readable title for an element in the detail panel header
 *
 * @param {Object} element - The SPDX element
 * @returns {string} Display title
 */
export function getElementDisplayName(element) {
  if (!element) return '';
  if (element.simplelicensing_licenseExpression) {
    return element.simplelicensing_licenseExpression;
  }
  if (element.name) return element.name;
  return cleanName(element.spdxId);
}

/**
 * Promoted fields for the detail panel (see DETAIL_PROMOTED_FIELDS in config)
 *
 * @param {Object} element - The SPDX element
 * @returns {Array<{prop: string, label: string, value: string, variant: string}>}
 */
export function getDetailPromotedFields(element) {
  if (!element) return [];

  return DETAIL_PROMOTED_FIELDS.flatMap((spec) => {
    const value = element[spec.prop];
    if (value == null || value === '') return [];
    if (spec.types && !spec.types.includes(element.type)) return [];
    return [
      {
        prop: spec.prop,
        label: spec.label,
        value: String(value),
        variant: spec.variant || 'badge'
      }
    ];
  });
}

/* ==========================================================================
   Node Type Helpers
   Functions for determining and styling node types
   ========================================================================== */

/**
 * Determines the node type from an element
 *
 * @param {Object} item - The SPDX element
 * @returns {string} Node type ('package', 'file', 'tool', 'build', 'agent', 'config', 'other')
 */
export function getNodeType(item) {
  if (!item || !item.type) return 'other';

  if (item.type === 'ExternalReference') return 'external';
  if (item.type === 'software_Package') return 'package';
  if (item.type === 'software_File') {
    // Check if it's a build config element
    if (item.software_primaryPurpose === 'configuration' || item.spdxId?.includes('build-config')) {
      return 'config';
    }
    return 'file';
  }
  if (item.type === 'Tool') return 'tool';
  if (item.type === 'build_Build') return 'build';
  if (item.type === 'SoftwareAgent') return 'agent';
  if (item.type === 'simplelicensing_LicenseExpression') return 'license';
  return 'other';
}

/**
 * Gets the color for a node type
 *
 * @param {string} nodeType - The node type
 * @returns {string} Hex color code
 */
export function getNodeTypeColor(nodeType) {
  const colorMap = {
    package: COLORS.package,
    file: COLORS.file,
    tool: COLORS.tool,
    build: COLORS.build,
    agent: COLORS.agent,
    config: COLORS.config,
    license: COLORS.license,
    external: COLORS.external
  };
  return colorMap[nodeType] || COLORS.default;
}

/**
 * Gets the CSS class for an element type badge
 *
 * @param {string} type - The element type
 * @returns {string} Tailwind CSS classes
 */
export function getElementBadgeClass(type) {
  const classMap = {
    software_Package: 'bg-blue-500/15 text-blue-400',
    software_File: 'bg-emerald-500/15 text-emerald-400',
    Tool: 'bg-amber-500/15 text-amber-400',
    build_Build: 'bg-purple-500/15 text-purple-400',
    SoftwareAgent: 'bg-red-500/15 text-red-400',
    ExternalReference: 'bg-slate-500/15 text-slate-400',
    simplelicensing_LicenseExpression: 'bg-pink-500/15 text-pink-400'
  };
  return classMap[type] || 'bg-slate-600/15 text-slate-400';
}

/* ==========================================================================
   Build Configuration Helpers
   Functions for parsing build configuration data
   ========================================================================== */

/**
 * Parses compiler flags, defines, and languages from a build configuration
 *
 * @param {Object} config - The build configuration element
 * @returns {{flags: string[], defines: string[], languages: string[]}} Parsed configuration
 *
 * @example
 * const cfg = { description: 'Languages: C, C++; Defines (2): DEBUG, VERSION=1', comment: 'Full compile command fragments: -O2 -Wall' };
 * parseCompileFlags(cfg) // returns { flags: ['-O2', '-Wall'], defines: ['DEBUG', 'VERSION=1'], languages: ['C', 'C++'] }
 */
export function parseCompileFlags(config) {
  if (!config) return { flags: [], defines: [], languages: [] };

  const description = config.description || '';
  const comment = config.comment || '';

  // Extract languages
  const langMatch = description.match(/Languages?:\s*([^;]+)/i);
  const languages = langMatch ? langMatch[1].split(',').map((lang) => lang.trim()) : [];

  // Extract defines from description
  const defMatch = description.match(/Defines\s*\((\d+)\):\s*([^;]+)/i);
  let defines = [];
  if (defMatch) {
    defines = defMatch[2]
      .split(',')
      .map((def) => def.trim())
      .filter((def) => def && !def.includes('...'));
  }

  // Extract flags from comment (full compile command)
  let flags = [];
  if (comment) {
    const flagMatch = comment.match(/Full compile command fragments?:\s*(.+)/i);
    if (flagMatch) {
      flags = flagMatch[1].split(/\s+/).filter((flag) => flag.startsWith('-'));
    }
  }

  return { flags, defines, languages };
}

/**
 * Splits a command-line style parameter value into display tokens.
 * Handles simple quoted strings without trying to be a full shell parser.
 *
 * @param {string} value - Parameter value
 * @returns {Array<string>} Display tokens
 */
export function splitParameterValue(value) {
  if (!value || typeof value !== 'string') return [];
  return (
    value
      .match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g)
      ?.map((token) => token.replace(/^(['"])(.*)\1$/, '$2')) || []
  );
}

/**
 * Assigns display semantics to build parameter tokens.
 *
 * @param {string} token - Parameter token
 * @returns {{kind: string, className: string}} Token display metadata
 */
export function classifyParameterToken(token) {
  if (/^-D/.test(token)) {
    return { kind: 'Define', className: 'param-token param-token-define' };
  }
  if (/^-I/.test(token) || /^-i(macros|system)/.test(token) || /^--sysroot=/.test(token)) {
    return { kind: 'Include path', className: 'param-token param-token-path' };
  }
  if (/^(\/|[A-Za-z]:\\)/.test(token) || /[/\\][^/\\]+/.test(token)) {
    return { kind: 'Path', className: 'param-token param-token-path' };
  }
  if (/^-O/.test(token)) {
    return { kind: 'Optimization', className: 'param-token param-token-opt' };
  }
  if (/^-std=/.test(token)) {
    return { kind: 'Language standard', className: 'param-token param-token-standard' };
  }
  if (/^-g/.test(token)) {
    return { kind: 'Debug', className: 'param-token param-token-debug' };
  }
  if (/^-m/.test(token)) {
    return { kind: 'Machine', className: 'param-token param-token-machine' };
  }
  if (/^-Werror/.test(token)) {
    return { kind: 'Warning as error', className: 'param-token param-token-error' };
  }
  if (/^-W/.test(token)) {
    return { kind: 'Warning', className: 'param-token param-token-warning' };
  }
  if (/^-f/.test(token)) {
    return { kind: 'Code generation', className: 'param-token param-token-feature' };
  }
  if (/^-/.test(token)) {
    return { kind: 'Option', className: 'param-token param-token-option' };
  }
  if (/^[A-Z_][A-Z0-9_]*(=.*)?$/.test(token)) {
    return { kind: 'Symbol', className: 'param-token param-token-symbol' };
  }
  if (/^\d+(\.\d+)*$/.test(token)) {
    return { kind: 'Version', className: 'param-token param-token-version' };
  }
  return { kind: 'Value', className: 'param-token param-token-value' };
}

/**
 * Parses SPDX build parameters into grouped display data.
 *
 * @param {Object} build - The build element
 * @returns {Array<{key: string, label: string, entries: Array<Object>}>} Grouped parameters
 */
export function parseBuildParameters(build) {
  const params = build?.build_parameter || build?.build_parameters || [];
  if (!Array.isArray(params)) return [];

  const groups = new Map();
  params.forEach((param, paramIndex) => {
    if (!param?.key) return;
    const parts = param.key.split(':');
    const groupKey = parts[0] || 'parameter';
    if (!groups.has(groupKey)) {
      groups.set(groupKey, {
        key: groupKey,
        label: groupKey.charAt(0).toUpperCase() + groupKey.slice(1),
        entries: []
      });
    }

    const tokens = splitParameterValue(param.value).map((token, index) => {
      const metadata = classifyParameterToken(token);
      const renderKey = `${param.key}:${paramIndex}:${index}`;
      return {
        id: renderKey,
        renderKey,
        text: token,
        display: token,
        kind: metadata.kind,
        className: metadata.className
      };
    });
    groups.get(groupKey).entries.push({
      id: `${param.key}:${paramIndex}`,
      renderKey: `${param.key}:${paramIndex}`,
      key: param.key,
      label: parts.slice(1).join(' / ') || param.key,
      value: param.value || '',
      tokens
    });
  });

  return [...groups.values()].sort((a, b) => a.label.localeCompare(b.label));
}

/**
 * Counts how many times a tool is referenced in relationships
 *
 * @param {string} toolSpdxId - The tool's SPDX ID
 * @param {Array} relationships - Array of relationship objects
 * @returns {number} Usage count
 */
export function getToolUsageCount(toolSpdxId, relationships) {
  let count = 0;
  relationships.forEach((rel) => {
    if (rel.relationshipType === 'usesTool') {
      const targets = Array.isArray(rel.to) ? rel.to : [rel.to];
      if (targets.includes(toolSpdxId)) count++;
    }
  });
  return count;
}

/**
 * Gets the file path for a tool from its external identifiers
 *
 * @param {Object} tool - The tool element
 * @returns {string} Tool path or empty string
 */
export function getToolPath(tool) {
  if (tool?.externalIdentifier?.length) {
    return tool.externalIdentifier[0].identifier || '';
  }
  return '';
}

/* ==========================================================================
   Provenance / Identifier Helpers
   Surface package & tool metadata (version, download, PackageURL/CPE, …)
   that producers like the Linux kernel and Zephyr emit but is easy to hide.
   ========================================================================== */

// Sentinel values SPDX producers use to mean "no data". Treat them as empty so
// we don't render "NOASSERTION" rows all over the UI.
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

// Human-readable labels for SPDX externalIdentifierType values.
const EXTERNAL_ID_LABELS = {
  packageUrl: 'PackageURL',
  cpe22: 'CPE 2.2',
  cpe23: 'CPE 2.3',
  gitoid: 'gitoid',
  swid: 'SWID',
  swhid: 'SWHID',
  urlScheme: 'URL',
  securityOther: 'Security ref',
  other: 'Reference'
};

/**
 * Normalizes a download/VCS location into an href when it points at the web.
 * Strips a leading `git+` (SPDX VCS URLs like `git+https://…`) so the link is
 * directly followable; returns '' for non-web or NOASSERTION locations.
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
export function getExternalIdentifiers(element) {
  const ids = element?.externalIdentifier;
  if (!Array.isArray(ids)) return [];
  return ids
    .filter((id) => id && isMeaningfulValue(id.identifier))
    .map((id) => {
      const type = id.externalIdentifierType || 'other';
      const identifier = String(id.identifier).trim();
      return {
        type,
        label: EXTERNAL_ID_LABELS[type] || type,
        identifier,
        isUrl: /^https?:\/\//i.test(identifier)
      };
    });
}

/* ==========================================================================
   Clipboard Helper
   Function for copying text to clipboard
   ========================================================================== */

/**
 * Copies text to the clipboard
 *
 * @param {string} text - Text to copy
 * @returns {Promise<void>}
 */
export async function copyToClipboard(text) {
  return navigator.clipboard.writeText(text);
}
