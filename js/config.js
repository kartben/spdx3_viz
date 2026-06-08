/**
 * SPDX 3.0 SBOM Visualizer - Configuration
 *
 * Central configuration file containing constants, color mappings,
 * view definitions, and filter configurations.
 *
 * @module config
 */

/* ==========================================================================
   Type Constants
   String constants for SPDX element types
   ========================================================================== */

/**
 * SPDX element type constants
 * @constant {Object}
 */
export const ELEMENT_TYPES = {
  PACKAGE: 'software_Package',
  FILE: 'software_File',
  TOOL: 'Tool',
  RELATIONSHIP: 'Relationship',
  LIFECYCLE_RELATIONSHIP: 'LifecycleScopedRelationship',
  BUILD: 'build_Build',
  AGENT: 'SoftwareAgent',
  DOCUMENT: 'SpdxDocument'
};

/**
 * Relationship type constants
 * @constant {Object}
 */
export const RELATIONSHIP_TYPES = {
  DEPENDS_ON: 'dependsOn',
  CONTAINS: 'contains',
  GENERATES: 'generates',
  USES_TOOL: 'usesTool',
  HAS_STATIC_LINK: 'hasStaticLink',
  CONFIGURES: 'configures',
  HAS_CONCLUDED_LICENSE: 'hasConcludedLicense',
  HAS_DECLARED_LICENSE: 'hasDeclaredLicense'
};

/* ==========================================================================
   Color Definitions
   Color mappings for nodes, edges, and UI elements
   ========================================================================== */

/**
 * Color palette for different element types
 * @constant {Object}
 */
export const COLORS = {
  package: '#3b82f6',
  file: '#10b981',
  tool: '#f59e0b',
  build: '#8b5cf6',
  agent: '#ef4444',
  config: '#14b8a6',
  license: '#ec4899',
  staticLink: '#06b6d4',
  default: '#6b7280'
};

/**
 * Node color configurations for graph legend
 * @constant {Array<{type: string, label: string, color: string}>}
 */
export const NODE_COLORS = [
  { type: 'package', label: 'Package', color: COLORS.package },
  { type: 'file', label: 'File', color: COLORS.file },
  { type: 'tool', label: 'Tool', color: COLORS.tool },
  { type: 'build', label: 'Build', color: COLORS.build },
  { type: 'config', label: 'Config', color: COLORS.config }
];

/**
 * Edge color configurations for graph legend
 * @constant {Array<{type: string, label: string, color: string}>}
 */
export const EDGE_COLORS = [
  { type: 'dependsOn', label: 'dependsOn', color: COLORS.package },
  { type: 'contains', label: 'contains', color: COLORS.file },
  { type: 'generates', label: 'generates', color: COLORS.build },
  { type: 'usesTool', label: 'usesTool', color: COLORS.tool },
  { type: 'hasStaticLink', label: 'hasStaticLink', color: COLORS.staticLink },
  { type: 'configures', label: 'configures', color: COLORS.config }
];

/**
 * Depth colors for dependency tree visualization
 * @constant {Array<string>}
 */
export const DEPTH_COLORS = [
  '#3b82f6',
  '#8b5cf6',
  '#10b981',
  '#f59e0b',
  '#06b6d4',
  '#ec4899',
  '#ef4444'
];

/* ==========================================================================
   Graph Filters
   Filter configurations for the force-directed graph
   ========================================================================== */

/**
 * Creates the default graph filter configuration
 * @returns {Array<Object>} Array of filter objects
 */
export function createGraphFilters() {
  return [
    // Node type filters
    { key: 'package', label: 'Packages', color: COLORS.package, active: true },
    { key: 'file', label: 'Files', color: COLORS.file, active: true },
    { key: 'tool', label: 'Tools', color: COLORS.tool, active: true },
    { key: 'build', label: 'Build', color: COLORS.build, active: true },
    { key: 'config', label: 'Configs', color: COLORS.config, active: true },
    // Relationship type filters
    { key: 'dependsOn', label: 'dependsOn', color: COLORS.package, active: true, isRel: true },
    { key: 'contains', label: 'contains', color: COLORS.file, active: true, isRel: true },
    { key: 'generates', label: 'generates', color: COLORS.build, active: true, isRel: true },
    { key: 'usesTool', label: 'usesTool', color: COLORS.tool, active: true, isRel: true },
    {
      key: 'hasStaticLink',
      label: 'hasStaticLink',
      color: COLORS.staticLink,
      active: true,
      isRel: true
    },
    { key: 'configures', label: 'configures', color: COLORS.config, active: true, isRel: true }
  ];
}

/* ==========================================================================
   View Definitions
   Navigation view configurations with icons
   ========================================================================== */

/**
 * SVG icon definitions for views
 * @constant {Object}
 */
const VIEW_ICONS = {
  dashboard:
    '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1" stroke-width="2"/><rect x="14" y="3" width="7" height="7" rx="1" stroke-width="2"/><rect x="3" y="14" width="7" height="7" rx="1" stroke-width="2"/><rect x="14" y="14" width="7" height="7" rx="1" stroke-width="2"/></svg>',
  graph:
    '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 10l-2 1m0 0l-2-1m2 1v2.5M20 7l-2 1m2-1l-2-1m2 1v2.5M14 4l-2-1-2 1M4 7l2-1M4 7l2 1M4 7v2.5M12 21l-2-1m2 1l2-1m-2 1v-2.5M6 18l-2-1v-2.5M18 18l2-1v-2.5"/></svg>',
  packages:
    '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/></svg>',
  files:
    '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>',
  configs:
    '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"/></svg>',
  build:
    '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"/></svg>',
  dependencies:
    '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>'
};

/**
 * Creates the view configuration array
 * @returns {Array<Object>} Array of view definition objects
 */
export function createViews() {
  return [
    { id: 'dashboard', label: 'Overview', icon: VIEW_ICONS.dashboard, count: null },
    { id: 'graph', label: 'Graph', icon: VIEW_ICONS.graph, count: null },
    { id: 'packages', label: 'Packages', icon: VIEW_ICONS.packages, count: null },
    { id: 'files', label: 'Files', icon: VIEW_ICONS.files, count: null },
    { id: 'configs', label: 'Build Configs', icon: VIEW_ICONS.configs, count: null },
    { id: 'build', label: 'Build', icon: VIEW_ICONS.build, count: null },
    { id: 'dependencies', label: 'Dependencies', icon: VIEW_ICONS.dependencies, count: null }
  ];
}

/* ==========================================================================
   Tailwind Configuration
   Custom color extensions for Tailwind CSS
   ========================================================================== */

/**
 * Tailwind CSS configuration object
 * @constant {Object}
 */
export const TAILWIND_CONFIG = {
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        spackage: COLORS.package,
        sfile: COLORS.file,
        stool: COLORS.tool,
        sbuild: COLORS.build,
        sagent: COLORS.agent,
        slicense: COLORS.license,
        sconfig: COLORS.config
      }
    }
  }
};

/* ==========================================================================
   Relationship Labels
   Human-readable labels for relationship types
   ========================================================================== */

/**
 * Maps relationship types and directions to human-readable labels
 * @constant {Object}
 */
export const RELATIONSHIP_LABELS = {
  'dependsOn:out': 'Depends on',
  'dependsOn:in': 'Depended on by',
  'contains:out': 'Contains',
  'contains:in': 'Contained in',
  'generates:out': 'Generates',
  'generates:in': 'Generated by',
  'usesTool:out': 'Uses tool',
  'usesTool:in': 'Used as tool by',
  'hasStaticLink:out': 'Statically links',
  'hasStaticLink:in': 'Statically linked by',
  'configures:out': 'Configures',
  'configures:in': 'Configured by',
  'hasConcludedLicense:out': 'Concluded license',
  'hasConcludedLicense:in': 'Licensed (concluded)',
  'hasDeclaredLicense:out': 'Declared license',
  'hasDeclaredLicense:in': 'Licensed (declared)'
};

/**
 * Sort order for relationship groups in the detail panel
 * Lower numbers appear first
 * @constant {Object}
 */
export const RELATIONSHIP_SORT_ORDER = {
  'contains:in': 1,
  'contains:out': 2,
  'configures:in': 3,
  'configures:out': 4,
  'dependsOn:out': 5,
  'dependsOn:in': 6,
  'generates:out': 7,
  'generates:in': 8,
  'hasStaticLink:out': 9,
  'hasStaticLink:in': 10,
  'usesTool:out': 11,
  'usesTool:in': 12,
  'hasConcludedLicense:out': 13,
  'hasDeclaredLicense:out': 14,
  'hasConcludedLicense:in': 15,
  'hasDeclaredLicense:in': 16
};
