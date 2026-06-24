/**
 * SPDX 3.0 SBOM Visualizer - Utility Functions
 *
 * Helper functions for data formatting, name cleaning,
 * and common operations used throughout the application.
 *
 * @module utils
 */

import { COLORS, RELATIONSHIP_LABELS, RELATIONSHIP_SORT_ORDER } from './config.js';

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
  if (element?.name) return element.name;
  return cleanName(spdxId);
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
    ExternalReference: 'bg-slate-500/15 text-slate-400'
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
