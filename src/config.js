/**
 * Constants, color mappings, view definitions, and filter configurations.
 *
 * @module config
 */

// Element categorization by SPDX type is derived from the official class
// hierarchy in src/spdx/ (see bucketOf / isA), not from hand-maintained type
// lists. VEX and relationship types below are semantic vocabularies, not class
// buckets, so they stay here.

/**
 * Security profile VEX assessment relationship element types, keyed by the VEX status they express.
 * @constant {Object}
 */
export const VEX_TYPES = {
  FIXED: 'security_VexFixedVulnAssessmentRelationship',
  NOT_AFFECTED: 'security_VexNotAffectedVulnAssessmentRelationship',
  AFFECTED: 'security_VexAffectedVulnAssessmentRelationship',
  UNDER_INVESTIGATION: 'security_VexUnderInvestigationVulnAssessmentRelationship'
};

/**
 * Relationship type constants
 * @constant {Object}
 */
export const RELATIONSHIP_TYPES = {
  DEPENDS_ON: 'dependsOn',
  CONTAINS: 'contains',
  GENERATES: 'generates',
  HAS_INPUT: 'hasInput',
  HAS_OUTPUT: 'hasOutput',
  HAS_DISTRIBUTION_ARTIFACT: 'hasDistributionArtifact',
  ANCESTOR_OF: 'ancestorOf',
  USES_TOOL: 'usesTool',
  HAS_STATIC_LINK: 'hasStaticLink',
  HAS_DYNAMIC_LINK: 'hasDynamicLink',
  HAS_OPTIONAL_COMPONENT: 'hasOptionalComponent',
  HAS_VARIANT: 'hasVariant',
  CONFIGURES: 'configures',
  HAS_CONCLUDED_LICENSE: 'hasConcludedLicense',
  HAS_DECLARED_LICENSE: 'hasDeclaredLicense',
  // Hardware profile: a software element runs on each `to` Hardware element.
  RUNS_ON: 'runsOn',
  // FunctionalSafety profile relationship types tying a Requirement to what implements,
  // verifies, evidences, and assumes it.
  IMPLEMENTED_BY: 'implementedBy',
  VERIFIED_BY: 'verifiedBy',
  HAS_REQUIREMENT: 'hasRequirement',
  HAS_EVIDENCE: 'hasEvidence',
  ASSUMES: 'assumes',
  CONFORMS_TO: 'conformsTo',
  // Synthesized by the parser from EvaluationResult.evaluationBasedOn so the evaluation ↔
  // verification link appears as a graph edge like any other relationship.
  EVALUATION_BASED_ON: 'evaluationBasedOn',
  // Agent attribution: an Action (build, verification, assessment, …) performedBy an Agent.
  PERFORMED_BY: 'performedBy',
  // Provenance, synthesized by the parser from the Artifact `suppliedBy` /
  // `originatedBy` / `builtBy` agent-valued properties.
  SUPPLIED_BY: 'suppliedBy',
  ORIGINATED_BY: 'originatedBy',
  BUILT_BY: 'builtBy',
  // AI profile relationship types (AI model ↔ training/test dataset).
  TRAINED_ON: 'trainedOn',
  TESTED_ON: 'testedOn',
  // VEX relationship types (Security profile).
  FIXED_IN: 'fixedIn',
  DOES_NOT_AFFECT: 'doesNotAffect',
  AFFECTS: 'affects',
  UNDER_INVESTIGATION: 'underInvestigation'
};

/**
 * Maps a VEX assessment relationship's `relationshipType` to a normalized status key used throughout the UI.
 * @constant {Object}
 */
export const VEX_STATUS_BY_REL = {
  fixedIn: 'fixed',
  doesNotAffect: 'not_affected',
  affects: 'affected',
  underInvestigation: 'under_investigation'
};

/**
 * Presentation metadata for each VEX status. `severity` orders statuses from
 * most to least concerning (used to pick a vulnerability's overall status and to
 * sort the security view).
 * @constant {Object}
 */
export const VEX_STATUSES = {
  affected: {
    key: 'affected',
    label: 'Affected',
    color: '#f43f5e',
    badgeClass: 'bg-rose-500/15 text-rose-300 ring-1 ring-rose-500/30',
    dotClass: 'bg-rose-500',
    severity: 4
  },
  under_investigation: {
    key: 'under_investigation',
    label: 'Under investigation',
    color: '#f59e0b',
    badgeClass: 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30',
    dotClass: 'bg-amber-500',
    severity: 3
  },
  not_affected: {
    key: 'not_affected',
    label: 'Not affected',
    color: '#38bdf8',
    badgeClass: 'bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/30',
    dotClass: 'bg-sky-500',
    severity: 2
  },
  fixed: {
    key: 'fixed',
    label: 'Fixed',
    color: '#10b981',
    badgeClass: 'bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30',
    dotClass: 'bg-emerald-500',
    severity: 1
  }
};

/**
 * Human-readable labels for the VexJustificationType vocabulary (why a component is "not affected").
 * @constant {Object}
 */
export const VEX_JUSTIFICATION_LABELS = {
  componentNotPresent: 'Component not present',
  vulnerableCodeNotPresent: 'Vulnerable code not present',
  vulnerableCodeNotInExecutePath: 'Not in execute path',
  vulnerableCodeCannotBeControlledByAdversary: 'Not adversary-controllable',
  inlineMitigationsAlreadyExist: 'Inline mitigations exist'
};

/**
 * Color palette for different element types
 * @constant {Object}
 */
export const COLORS = {
  package: '#3b82f6',
  // AI profile node types (AI model / dataset).
  ai: '#e879f9',
  dataset: '#22d3ee',
  file: '#10b981',
  // Hardware profile node type + runsOn edges.
  hardware: '#a3e635',
  // FunctionalSafety profile: Requirement node type + its safety relationship edges.
  requirement: '#eab308',
  tool: '#f59e0b',
  build: '#8b5cf6',
  buildInput: '#f97316',
  buildOutput: '#22c55e',
  buildLineage: '#a78bfa',
  agent: '#ef4444',
  config: '#14b8a6',
  license: '#ec4899',
  distribution: '#38bdf8',
  external: '#94a3b8',
  staticLink: '#06b6d4',
  dynamicLink: '#0ea5e9',
  optionalComponent: '#d946ef',
  variant: '#eab308',
  vulnerability: '#f43f5e',
  // VEX edge colors mirror the VEX_STATUSES palette so an edge reads as its status.
  vexFixed: '#10b981',
  vexNotAffected: '#38bdf8',
  vexAffected: '#f43f5e',
  vexUnderInvestigation: '#f59e0b',
  default: '#6b7280'
};

/**
 * Creates the default graph filter configuration
 * @returns {Array<Object>} Array of filter objects
 */
export function createGraphFilters() {
  return [
    // Node type filters
    { key: 'package', label: 'Packages', color: COLORS.package, active: true },
    { key: 'ai', label: 'AI models', color: COLORS.ai, active: true },
    { key: 'dataset', label: 'Datasets', color: COLORS.dataset, active: true },
    { key: 'file', label: 'Files', color: COLORS.file, active: true },
    { key: 'hardware', label: 'Hardware', color: COLORS.hardware, active: true },
    { key: 'requirement', label: 'Requirements', color: COLORS.requirement, active: true },
    { key: 'tool', label: 'Tools', color: COLORS.tool, active: true },
    { key: 'agent', label: 'Agents', color: COLORS.agent, active: true },
    { key: 'build', label: 'Build', color: COLORS.build, active: true },
    { key: 'config', label: 'Configs', color: COLORS.config, active: true },
    { key: 'external', label: 'External', color: COLORS.external, active: true },
    // Vulnerabilities start off to avoid swamping the graph; auto-enabled on load
    // for small VEX sets (see VEX_AUTO_SHOW_MAX), otherwise opted in from the legend.
    {
      key: 'vulnerability',
      label: 'Vulnerabilities',
      color: COLORS.vulnerability,
      active: false
    },
    // Relationship type filters
    { key: 'dependsOn', label: 'dependsOn', color: COLORS.package, active: true, isRel: true },
    { key: 'contains', label: 'contains', color: COLORS.file, active: true, isRel: true },
    { key: 'generates', label: 'generates', color: COLORS.build, active: true, isRel: true },
    { key: 'hasInput', label: 'hasInput', color: COLORS.buildInput, active: true, isRel: true },
    { key: 'hasOutput', label: 'hasOutput', color: COLORS.buildOutput, active: true, isRel: true },
    {
      key: 'hasDistributionArtifact',
      label: 'hasDistributionArtifact',
      color: COLORS.distribution,
      active: true,
      isRel: true
    },
    {
      key: 'ancestorOf',
      label: 'ancestorOf',
      color: COLORS.buildLineage,
      active: true,
      isRel: true
    },
    {
      key: 'usesTool',
      label: 'usesTool',
      color: COLORS.tool,
      active: true,
      isRel: true,
      lineStyle: 'dotted'
    },
    {
      key: 'hasStaticLink',
      label: 'hasStaticLink',
      color: COLORS.staticLink,
      active: true,
      isRel: true
    },
    {
      key: 'hasDynamicLink',
      label: 'hasDynamicLink',
      color: COLORS.dynamicLink,
      active: true,
      isRel: true,
      lineStyle: 'dashed'
    },
    {
      key: 'hasOptionalComponent',
      label: 'hasOptionalComponent',
      color: COLORS.optionalComponent,
      active: true,
      isRel: true,
      lineStyle: 'dashdot'
    },
    { key: 'hasVariant', label: 'hasVariant', color: COLORS.variant, active: true, isRel: true },
    {
      key: 'runsOn',
      label: 'runsOn',
      color: COLORS.hardware,
      active: true,
      isRel: true,
      lineStyle: 'dashed'
    },
    { key: 'configures', label: 'configures', color: COLORS.config, active: true, isRel: true },
    // FunctionalSafety profile relationship edges.
    {
      key: 'implementedBy',
      label: 'implementedBy',
      color: COLORS.requirement,
      active: true,
      isRel: true
    },
    {
      key: 'verifiedBy',
      label: 'verifiedBy',
      color: COLORS.requirement,
      active: true,
      isRel: true,
      lineStyle: 'dashed'
    },
    {
      key: 'hasRequirement',
      label: 'hasRequirement',
      color: COLORS.requirement,
      active: true,
      isRel: true
    },
    {
      key: 'hasEvidence',
      label: 'hasEvidence',
      color: COLORS.requirement,
      active: true,
      isRel: true,
      lineStyle: 'dotted'
    },
    {
      key: 'assumes',
      label: 'assumes',
      color: COLORS.requirement,
      active: true,
      isRel: true,
      lineStyle: 'dashdot'
    },
    {
      key: 'conformsTo',
      label: 'conformsTo',
      color: COLORS.requirement,
      active: true,
      isRel: true,
      lineStyle: 'dashed'
    },
    {
      key: 'evaluationBasedOn',
      label: 'evaluationBasedOn',
      color: COLORS.requirement,
      active: true,
      isRel: true,
      lineStyle: 'dotted'
    },
    // Agent attribution edges (Action/Artifact → Agent). COLORS.agent matches the agent node.
    {
      key: 'performedBy',
      label: 'performedBy',
      color: COLORS.agent,
      active: true,
      isRel: true,
      lineStyle: 'dashed'
    },
    {
      key: 'suppliedBy',
      label: 'suppliedBy',
      color: COLORS.agent,
      active: true,
      isRel: true,
      lineStyle: 'dotted'
    },
    {
      key: 'originatedBy',
      label: 'originatedBy',
      color: COLORS.agent,
      active: true,
      isRel: true,
      lineStyle: 'dotted'
    },
    {
      key: 'builtBy',
      label: 'builtBy',
      color: COLORS.agent,
      active: true,
      isRel: true,
      lineStyle: 'dashdot'
    },
    { key: 'trainedOn', label: 'trainedOn', color: COLORS.ai, active: true, isRel: true },
    {
      key: 'testedOn',
      label: 'testedOn',
      color: COLORS.dataset,
      active: true,
      isRel: true,
      lineStyle: 'dashed'
    },
    // VEX assessment edges (vulnerability → package); start off, auto-enabled on load for small VEX sets.
    { key: 'fixedIn', label: 'fixedIn (VEX)', color: COLORS.vexFixed, active: false, isRel: true },
    {
      key: 'doesNotAffect',
      label: 'doesNotAffect (VEX)',
      color: COLORS.vexNotAffected,
      active: false,
      isRel: true
    },
    {
      key: 'affects',
      label: 'affects (VEX)',
      color: COLORS.vexAffected,
      active: false,
      isRel: true
    },
    {
      key: 'underInvestigation',
      label: 'underInvestigation (VEX)',
      color: COLORS.vexUnderInvestigation,
      active: false,
      isRel: true
    }
  ];
}

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
  ai: '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><rect x="6" y="6" width="12" height="12" rx="2" stroke-width="2"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2"/></svg>',
  dataset:
    '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="8" ry="3" stroke-width="2"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 5v6c0 1.66 3.58 3 8 3s8-1.34 8-3V5M4 11v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6"/></svg>',
  files:
    '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>',
  hardware:
    '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><rect x="7" y="7" width="10" height="10" rx="1" stroke-width="2"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/></svg>',
  requirements:
    '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/></svg>',
  licenses:
    '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>',
  security:
    '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01M12 3l7 4v5c0 4.418-3 8.418-7 9.5C8 20.418 5 16.418 5 12V7l7-4z"/></svg>',
  configs:
    '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"/></svg>',
  build:
    '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"/></svg>',
  raw: '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/></svg>'
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
    { id: 'ai', label: 'AI Models', icon: VIEW_ICONS.ai, count: null },
    { id: 'dataset', label: 'Datasets', icon: VIEW_ICONS.dataset, count: null },
    { id: 'files', label: 'Files', icon: VIEW_ICONS.files, count: null },
    { id: 'hardware', label: 'Hardware', icon: VIEW_ICONS.hardware, count: null },
    { id: 'requirements', label: 'Functional Safety', icon: VIEW_ICONS.requirements, count: null },
    { id: 'licenses', label: 'Licenses', icon: VIEW_ICONS.licenses, count: null },
    { id: 'security', label: 'Security', icon: VIEW_ICONS.security, count: null },
    { id: 'configs', label: 'Build Configs', icon: VIEW_ICONS.configs, count: null },
    { id: 'build', label: 'Build', icon: VIEW_ICONS.build, count: null },
    { id: 'raw', label: 'Raw JSON-LD', icon: VIEW_ICONS.raw, count: null }
  ];
}

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
  'hasInput:out': 'Inputs',
  'hasInput:in': 'Input to builds',
  'hasOutput:out': 'Outputs',
  'hasOutput:in': 'Produced by build',
  'hasDistributionArtifact:out': 'Distribution artifacts',
  'hasDistributionArtifact:in': 'Distributed by',
  'ancestorOf:out': 'Build steps',
  'ancestorOf:in': 'Child build of',
  'usesTool:out': 'Uses tool',
  'usesTool:in': 'Used as tool by',
  'hasStaticLink:out': 'Statically links',
  'hasStaticLink:in': 'Statically linked by',
  'hasDynamicLink:out': 'Dynamically links',
  'hasDynamicLink:in': 'Dynamically linked by',
  'hasOptionalComponent:out': 'Optional components',
  'hasOptionalComponent:in': 'Optional component of',
  'hasVariant:out': 'Variants',
  'hasVariant:in': 'Variant of',
  'configures:out': 'Configures',
  'configures:in': 'Configured by',
  'runsOn:out': 'Runs on',
  'runsOn:in': 'Runs',
  // FunctionalSafety profile.
  'implementedBy:out': 'Implemented by',
  'implementedBy:in': 'Implements',
  'verifiedBy:out': 'Verified by',
  'verifiedBy:in': 'Verifies',
  'hasRequirement:out': 'Has requirement',
  'hasRequirement:in': 'Required by',
  'hasEvidence:out': 'Has evidence',
  'hasEvidence:in': 'Evidence for',
  'assumes:out': 'Assumes',
  'assumes:in': 'Assumed by',
  'conformsTo:out': 'Conforms to',
  'conformsTo:in': 'Conformed to by',
  'evaluationBasedOn:out': 'Based on',
  'evaluationBasedOn:in': 'Evaluated by',
  // Agent attribution.
  'performedBy:out': 'Performed by',
  'performedBy:in': 'Performed',
  'suppliedBy:out': 'Supplied by',
  'suppliedBy:in': 'Supplies',
  'originatedBy:out': 'Originated by',
  'originatedBy:in': 'Originated',
  'builtBy:out': 'Built by',
  'builtBy:in': 'Built',
  'trainedOn:out': 'Trained on',
  'trainedOn:in': 'Training dataset for',
  'testedOn:out': 'Tested on',
  'testedOn:in': 'Test dataset for',
  'hasConcludedLicense:out': 'Concluded license',
  'hasConcludedLicense:in': 'Licensed (concluded)',
  'hasDeclaredLicense:out': 'Declared license',
  'hasDeclaredLicense:in': 'Licensed (declared)'
};

/**
 * Fields shown prominently at the top of the detail panel (before relationships).
 * variant: 'badge' — compact label + pill; 'hero' — large highlighted block
 *
 * @constant {Array<{prop: string, label: string, types?: string[], variant?: string}>}
 */
export const DETAIL_PROMOTED_FIELDS = [
  {
    prop: 'simplelicensing_licenseExpression',
    label: 'License expression',
    types: ['simplelicensing_LicenseExpression'],
    variant: 'hero'
  },
  {
    prop: 'software_primaryPurpose',
    label: 'Purpose',
    types: ['software_File', 'software_Package'],
    variant: 'badge'
  },
  {
    prop: 'software_fileKind',
    label: 'Kind',
    types: ['software_File'],
    variant: 'badge'
  },
  // Hardware profile.
  {
    prop: 'hardware_partNumber',
    label: 'Part number',
    types: [
      'hardware_Hardware',
      'hardware_PhysicalHardware',
      'hardware_BulkHardware',
      'hardware_VirtualHardware'
    ],
    variant: 'badge'
  },
  {
    prop: 'hardware_category',
    label: 'Category',
    types: [
      'hardware_Hardware',
      'hardware_PhysicalHardware',
      'hardware_BulkHardware',
      'hardware_VirtualHardware'
    ],
    variant: 'badge'
  },
  // FunctionalSafety profile: the "shall" statement headlines a Requirement, the assumption statement an Assumption.
  {
    prop: 'requirementStatement',
    label: 'Requirement',
    types: ['Requirement'],
    variant: 'hero'
  },
  {
    prop: 'functionalsafety_assumptionStatement',
    label: 'Assumption',
    types: ['functionalsafety_Assumption'],
    variant: 'hero'
  }
];

/**
 * Sort order for relationship groups in the detail panel
 * Lower numbers appear first
 * @constant {Object}
 */
export const RELATIONSHIP_SORT_ORDER = {
  'contains:in': 1,
  'contains:out': 2,
  'ancestorOf:in': 3,
  'ancestorOf:out': 4,
  'hasInput:out': 5,
  'hasInput:in': 6,
  'hasOutput:in': 7,
  'hasOutput:out': 8,
  'hasDistributionArtifact:out': 9,
  'hasDistributionArtifact:in': 10,
  'configures:in': 11,
  'configures:out': 12,
  'dependsOn:out': 13,
  'dependsOn:in': 14,
  'generates:out': 15,
  'generates:in': 16,
  'hasStaticLink:out': 17,
  'hasStaticLink:in': 18,
  'hasDynamicLink:out': 19,
  'hasDynamicLink:in': 20,
  'hasOptionalComponent:out': 21,
  'hasOptionalComponent:in': 22,
  'hasVariant:out': 23,
  'hasVariant:in': 24,
  'usesTool:out': 25,
  'usesTool:in': 26,
  'runsOn:out': 35,
  'runsOn:in': 36,
  // FunctionalSafety profile: keep a requirement's implementation, verification, evidence and assumptions grouped.
  'implementedBy:out': 37,
  'implementedBy:in': 38,
  'verifiedBy:out': 39,
  'verifiedBy:in': 40,
  'hasRequirement:out': 41,
  'hasRequirement:in': 42,
  'hasEvidence:out': 43,
  'hasEvidence:in': 44,
  'assumes:out': 45,
  'assumes:in': 46,
  'conformsTo:out': 47,
  'conformsTo:in': 48,
  'evaluationBasedOn:out': 49,
  'evaluationBasedOn:in': 50,
  // Agent attribution (kept together, just after the safety group).
  'performedBy:out': 51,
  'performedBy:in': 52,
  'suppliedBy:out': 53,
  'suppliedBy:in': 54,
  'originatedBy:out': 55,
  'originatedBy:in': 56,
  'builtBy:out': 57,
  'builtBy:in': 58,
  'trainedOn:out': 31,
  'trainedOn:in': 32,
  'testedOn:out': 33,
  'testedOn:in': 34,
  'hasConcludedLicense:out': 27,
  'hasDeclaredLicense:out': 28,
  'hasConcludedLicense:in': 29,
  'hasDeclaredLicense:in': 30
};
