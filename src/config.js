/**
 * Constants, color mappings, view definitions, and filter configurations.
 *
 * @module config
 */
import { LUCIDE_NAV_ICONS, NAV_CHEVRON_ICON } from './lib/lucide-nav-icons.js';

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
  HAS_PREREQUISITE: 'hasPrerequisite',
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
  // FunctionalSafety profile: a higher-level Requirement decomposes into more detailed ones.
  TRACED_TO_DETAIL: 'tracedToDetail',
  // Synthesized by the parser from EvaluationResult.evaluationBasedOn so the evaluation ↔
  // verification link appears as a graph edge like any other relationship.
  EVALUATION_BASED_ON: 'evaluationBasedOn',
  // FunctionalSafety profile: names the agent who carried out a verification/evaluation activity.
  PERFORMED_BY: 'performedBy',
  // SupplyChain profile: exception handling / resolution relationships.
  RESOLVED: 'resolved',
  HAS_RESOLUTION: 'hasResolution',
  // AI profile relationship types (AI model ↔ training/test dataset).
  TRAINED_ON: 'trainedOn',
  TESTED_ON: 'testedOn',
  // VEX relationship types (Security profile).
  FIXED_IN: 'fixedIn',
  DOES_NOT_AFFECT: 'doesNotAffect',
  AFFECTS: 'affects',
  UNDER_INVESTIGATION: 'underInvestigation',
  // Synthesized in the graph from each element's CreationInfo.createdBy so the
  // agent (Person / Organization / SoftwareAgent) that created an element shows
  // as an edge (element → agent).
  CREATED_BY: 'createdBy',
  // Synthesized in the graph the same way as createdBy, but read from an
  // Artifact's suppliedBy / originatedBy and a Hardware element's productAgent.
  SUPPLIED_BY: 'suppliedBy',
  ORIGINATED_BY: 'originatedBy',
  MANUFACTURED_BY: 'manufacturedBy'
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
 * FunctionalSafety profile: presentation metadata for a Requirement's overall
 * verification outcome, keyed by the `key` that `requirementSafetyStatus`
 * returns. `rank` orders them gaps-first (a failed verification is the most
 * urgent), matching the order the rollup bar and status-filter chips render in.
 */
export const SAFETY_STATUSES = {
  failed: {
    key: 'failed',
    label: 'Failed',
    color: '#f43f5e',
    badgeClass: 'bg-rose-500/15 text-rose-300 ring-1 ring-rose-500/30',
    dotClass: 'bg-rose-500',
    iconKey: 'status_fail',
    rank: 5
  },
  inconclusive: {
    key: 'inconclusive',
    label: 'Inconclusive',
    color: '#f59e0b',
    badgeClass: 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30',
    dotClass: 'bg-amber-500',
    iconKey: 'status_inconclusive',
    rank: 4
  },
  unverified: {
    key: 'unverified',
    label: 'Not verified',
    color: '#64748b',
    badgeClass: 'bg-slate-600/20 text-slate-300 ring-1 ring-slate-500/30',
    dotClass: 'bg-slate-500',
    iconKey: 'status_unverified',
    rank: 3
  },
  verified: {
    key: 'verified',
    label: 'Has verification',
    color: '#38bdf8',
    badgeClass: 'bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/30',
    dotClass: 'bg-sky-500',
    iconKey: 'status_verified',
    rank: 2
  },
  passed: {
    key: 'passed',
    label: 'Passed',
    color: '#10b981',
    badgeClass: 'bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30',
    dotClass: 'bg-emerald-500',
    iconKey: 'status_pass',
    rank: 1
  }
};

/**
 * FunctionalSafety profile: presentation metadata for a Requirement's
 * "true traceability" adequacy, the verdict a producer records as an
 * `adequacy:<verdict>` external identifier. It answers a different question
 * from SAFETY_STATUSES: not whether the verifying tests passed, but whether
 * they actually executed the code that implements the requirement. `rank`
 * orders them gaps-first, matching the chip row.
 */
export const SAFETY_ADEQUACY = {
  broken: {
    key: 'broken',
    label: 'Not exercised',
    color: '#f43f5e',
    badgeClass: 'bg-rose-500/15 text-rose-300 ring-1 ring-rose-500/30',
    dotClass: 'bg-rose-500',
    iconKey: 'status_fail',
    hint: 'Verified on paper only: other tests reach the implementation, its own never do',
    rank: 7
  },
  partial: {
    key: 'partial',
    label: 'Partly exercised',
    color: '#f59e0b',
    badgeClass: 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30',
    dotClass: 'bg-amber-500',
    iconKey: 'status_inconclusive',
    hint: 'Some implementing symbols are exercised by the verifying tests, others are not',
    rank: 6
  },
  'no-impl': {
    key: 'no-impl',
    label: 'No implementation',
    color: '#fb923c',
    badgeClass: 'bg-orange-500/15 text-orange-300 ring-1 ring-orange-500/30',
    dotClass: 'bg-orange-500',
    iconKey: 'status_unverified',
    hint: 'Nothing in the code claims to implement this requirement',
    rank: 5
  },
  unresolved: {
    key: 'unresolved',
    label: 'Not resolvable',
    color: '#a78bfa',
    badgeClass: 'bg-violet-500/15 text-violet-300 ring-1 ring-violet-500/30',
    dotClass: 'bg-violet-500',
    iconKey: 'status_unverified',
    hint: 'The implementation links point at macros or inlines, which have no body to cover',
    rank: 4
  },
  unattributed: {
    key: 'unattributed',
    label: 'Never reached',
    color: '#64748b',
    badgeClass: 'bg-slate-600/20 text-slate-300 ring-1 ring-slate-500/30',
    dotClass: 'bg-slate-500',
    iconKey: 'status_unverified',
    hint: 'No test in the run reached the implementation (boot-time, inlined away, or configured out)',
    rank: 3
  },
  'no-cov': {
    key: 'no-cov',
    label: 'No coverage data',
    color: '#94a3b8',
    badgeClass: 'bg-slate-600/20 text-slate-300 ring-1 ring-slate-500/30',
    dotClass: 'bg-slate-400',
    iconKey: 'status_unverified',
    hint: 'The verifying tests produced no coverage in this run',
    rank: 2
  },
  true: {
    key: 'true',
    label: 'Exercised',
    color: '#10b981',
    badgeClass: 'bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30',
    dotClass: 'bg-emerald-500',
    iconKey: 'status_pass',
    hint: "Every resolved implementing symbol is exercised by the requirement's own verifying tests",
    rank: 1
  }
};

/**
 * Presentation metadata for each CVSS qualitative severity, sourced directly
 * from the SBOM's own CVSS assessment relationships. `rank` orders them from
 * most to least severe (used to sort/filter the security view and to size the
 * dashboard histogram).
 * @constant {Object}
 */
export const CVSS_SEVERITIES = {
  critical: {
    key: 'critical',
    label: 'Critical',
    color: '#f43f5e',
    badgeClass: 'bg-rose-500/15 text-rose-300 ring-1 ring-rose-500/40',
    dotClass: 'bg-rose-500',
    rank: 5
  },
  high: {
    key: 'high',
    label: 'High',
    color: '#fb923c',
    badgeClass: 'bg-orange-500/15 text-orange-300 ring-1 ring-orange-500/40',
    dotClass: 'bg-orange-500',
    rank: 4
  },
  medium: {
    key: 'medium',
    label: 'Medium',
    color: '#f59e0b',
    badgeClass: 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/40',
    dotClass: 'bg-amber-500',
    rank: 3
  },
  low: {
    key: 'low',
    label: 'Low',
    color: '#38bdf8',
    badgeClass: 'bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/40',
    dotClass: 'bg-sky-500',
    rank: 2
  },
  none: {
    key: 'none',
    label: 'None',
    color: '#64748b',
    badgeClass: 'bg-slate-600/20 text-slate-300 ring-1 ring-slate-500/30',
    dotClass: 'bg-slate-500',
    rank: 1
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
  // A snippet is a slice of a file: a lighter emerald so it reads as file-adjacent.
  snippet: '#34d399',
  // Hardware profile node type + runsOn edges.
  hardware: '#a3e635',
  // SupplyChain profile node type and exception/resolution lifecycle edges.
  supplychain: '#06b6d4',
  // FunctionalSafety profile: Requirement node type + its safety relationship edges.
  requirement: '#eab308',
  tool: '#f59e0b',
  build: '#8b5cf6',
  buildInput: '#f97316',
  buildOutput: '#22c55e',
  buildLineage: '#a78bfa',
  agent: '#4d7c0f',
  // "createdBy" provenance edges tint to the agent colour they point at.
  createdBy: '#4d7c0f',
  config: '#14b8a6',
  license: '#ec4899',
  distribution: '#38bdf8',
  external: '#94a3b8',
  staticLink: '#06b6d4',
  dynamicLink: '#0ea5e9',
  optionalComponent: '#d946ef',
  prerequisite: '#6366f1',
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
 * Presentation metadata for the LifecycleScopeType vocabulary carried by
 * LifecycleScopedRelationship.scope (build / runtime / test / …). The synthetic
 * `unscoped` bucket covers ordinary Relationships that carry no scope. Colours
 * tint the scope chips in the graph legend and the scope badge in the detail
 * panel so the two read the same. `SCOPE_ORDER` is roughly lifecycle order.
 * @constant {Object}
 */
export const SCOPE_META = {
  design: { key: 'design', label: 'Design', color: '#38bdf8' },
  build: { key: 'build', label: 'Build', color: '#f59e0b' },
  development: { key: 'development', label: 'Development', color: '#f472b6' },
  test: { key: 'test', label: 'Test', color: '#a855f7' },
  runtime: { key: 'runtime', label: 'Runtime', color: '#22c55e' },
  other: { key: 'other', label: 'Other', color: '#94a3b8' },
  unscoped: { key: 'unscoped', label: 'Unscoped', color: '#64748b' }
};

/** Order scope chips appear in the legend (roughly design → runtime, unscoped last). */
export const SCOPE_ORDER = [
  'design',
  'build',
  'development',
  'test',
  'runtime',
  'other',
  'unscoped'
];

/**
 * Colour for a lifecycle scope value (falls back to the "other" tint).
 * @param {string} scope - A LifecycleScopeType value, or 'unscoped'
 * @returns {string} Hex color code
 */
export function getScopeColor(scope) {
  return SCOPE_META[scope]?.color || SCOPE_META.other.color;
}

/**
 * Creates the default lifecycle-scope filter configuration (all scopes active).
 * The graph legend trims these to the scopes actually present in the data.
 * @returns {Array<Object>} Array of scope filter objects
 */
export function createScopeFilters() {
  return SCOPE_ORDER.map((key) => ({
    key,
    label: SCOPE_META[key].label,
    color: SCOPE_META[key].color,
    active: true
  }));
}

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
    { key: 'supplychain', label: 'Supply Chain', color: COLORS.supplychain, active: true },
    { key: 'requirement', label: 'Functional Safety', color: COLORS.requirement, active: true },
    { key: 'tool', label: 'Tools', color: COLORS.tool, active: true },
    { key: 'build', label: 'Build', color: COLORS.build, active: true },
    { key: 'config', label: 'Configs', color: COLORS.config, active: true },
    { key: 'agent', label: 'Agents', color: COLORS.agent, active: true },
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
    {
      key: 'hasPrerequisite',
      label: 'hasPrerequisite',
      color: COLORS.prerequisite,
      active: true,
      isRel: true
    },
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
    // Provenance edges synthesized from an element's CreationInfo.createdBy,
    // Artifact.suppliedBy / .originatedBy, and Hardware.productAgent (element →
    // agent). Off by default and dotted so they stay in the background rather
    // than crowding the structural edges above.
    {
      key: 'createdBy',
      label: 'createdBy',
      color: COLORS.createdBy,
      active: false,
      isRel: true,
      lineStyle: 'dotted'
    },
    {
      key: 'suppliedBy',
      label: 'suppliedBy',
      color: COLORS.createdBy,
      active: false,
      isRel: true,
      lineStyle: 'dotted'
    },
    {
      key: 'originatedBy',
      label: 'originatedBy',
      color: COLORS.createdBy,
      active: false,
      isRel: true,
      lineStyle: 'dotted'
    },
    {
      key: 'manufacturedBy',
      label: 'manufacturedBy',
      color: COLORS.createdBy,
      active: false,
      isRel: true,
      lineStyle: 'dotted'
    },
    // FunctionalSafety profile relationship edges. All share the same yellow
    // (they're one profile), so each gets its own dash pattern below,
    // otherwise these relationship types would be indistinguishable on the
    // graph canvas (see dashPatternFor in graph-view.js, which draws these
    // patterns; keep the two in sync).
    {
      key: 'hasRequirement',
      label: 'hasRequirement',
      color: COLORS.requirement,
      active: true,
      isRel: true
    },
    {
      key: 'implementedBy',
      label: 'implementedBy',
      color: COLORS.requirement,
      active: true,
      isRel: true,
      lineStyle: 'dashed'
    },
    {
      key: 'verifiedBy',
      label: 'verifiedBy',
      color: COLORS.requirement,
      active: true,
      isRel: true,
      lineStyle: 'dotted'
    },
    {
      key: 'hasEvidence',
      label: 'hasEvidence',
      color: COLORS.requirement,
      active: true,
      isRel: true,
      lineStyle: 'finedot'
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
      lineStyle: 'longdash'
    },
    {
      key: 'evaluationBasedOn',
      label: 'evaluationBasedOn',
      color: COLORS.requirement,
      active: true,
      isRel: true,
      lineStyle: 'dashdotdot'
    },
    {
      key: 'tracedToDetail',
      label: 'tracedToDetail',
      color: COLORS.requirement,
      active: true,
      isRel: true,
      lineStyle: 'longdashdot'
    },
    // Explicit relationship (not synthesized) naming who carried out a
    // verification/evaluation; tinted the agent colour like the other
    // agent-pointing edges since its target is always an Agent.
    {
      key: 'performedBy',
      label: 'performedBy',
      color: COLORS.agent,
      active: true,
      isRel: true,
      lineStyle: 'dashed'
    },
    {
      key: 'resolved',
      label: 'resolved',
      color: COLORS.buildOutput,
      active: true,
      isRel: true,
      lineStyle: 'longdash'
    },
    {
      key: 'hasResolution',
      label: 'hasResolution',
      color: COLORS.buildOutput,
      active: true,
      isRel: true,
      lineStyle: 'longdashdot'
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
    },
    // Inferred vulnerability -> file edges: a CVE record's affected source files
    // matched to File elements in this SBOM by path. Not declared by the SBOM, so
    // dashed and in the vulnerability colour to read as a derived link. Off by
    // default; auto-enabled for small sets like the VEX edges above.
    {
      key: 'affectsFile',
      label: 'affects file (inferred)',
      color: COLORS.vulnerability,
      active: false,
      isRel: true,
      lineStyle: 'dashed'
    }
  ];
}

/**
 * Lucide stroke <svg> per sidebar view (currentColor, so the nav item tints it).
 * Entity-type Material glyphs stay in ICON_PATHS for lists / graph / detail.
 * @constant {Object<string, string>}
 */
const VIEW_ICONS = {
  dashboard: LUCIDE_NAV_ICONS.dashboard,
  graph: LUCIDE_NAV_ICONS.graph,
  packages: LUCIDE_NAV_ICONS.packages,
  ai: LUCIDE_NAV_ICONS.ai,
  dataset: LUCIDE_NAV_ICONS.dataset,
  files: LUCIDE_NAV_ICONS.files,
  hardware: LUCIDE_NAV_ICONS.hardware,
  supplychain: LUCIDE_NAV_ICONS.supplychain,
  requirements: LUCIDE_NAV_ICONS.requirements,
  coverage: LUCIDE_NAV_ICONS.coverage,
  licenses: LUCIDE_NAV_ICONS.licenses,
  security: LUCIDE_NAV_ICONS.security,
  configs: LUCIDE_NAV_ICONS.configs,
  build: LUCIDE_NAV_ICONS.build,
  agents: LUCIDE_NAV_ICONS.agents,
  statistics: LUCIDE_NAV_ICONS.statistics,
  remediation: LUCIDE_NAV_ICONS.remediation,
  impact: LUCIDE_NAV_ICONS.impact,
  raw: LUCIDE_NAV_ICONS.raw
};

/**
 * Creates the flat view configuration array (palette, counts, switchView).
 * Sidebar grouping lives in {@link createNavProfiles}.
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
    { id: 'supplychain', label: 'Supply Chain', icon: VIEW_ICONS.supplychain, count: null },
    { id: 'requirements', label: 'Requirements', icon: VIEW_ICONS.requirements, count: null },
    { id: 'coverage', label: 'Coverage', icon: VIEW_ICONS.coverage, count: null },
    { id: 'licenses', label: 'Licenses', icon: VIEW_ICONS.licenses, count: null },
    { id: 'security', label: 'Security', icon: VIEW_ICONS.security, count: null },
    { id: 'configs', label: 'Build Configs', icon: VIEW_ICONS.configs, count: null },
    { id: 'build', label: 'Build', icon: VIEW_ICONS.build, count: null },
    { id: 'agents', label: 'Agents', icon: VIEW_ICONS.agents, count: null },
    { id: 'statistics', label: 'Statistics', icon: VIEW_ICONS.statistics, count: null },
    { id: 'remediation', label: 'Remediation', icon: VIEW_ICONS.remediation, count: null },
    { id: 'impact', label: 'Impact', icon: VIEW_ICONS.impact, count: null },
    { id: 'raw', label: 'Raw JSON-LD', icon: VIEW_ICONS.raw, count: null }
  ];
}

/**
 * SPDX-profile-oriented sidebar groups. Multi-view profiles are collapsible;
 * single-view profiles render as one row that jumps to that view. Empty groups
 * stay hidden via isViewAvailable on their children.
 * @returns {Array<{id: string, label: string, icon: string, viewIds: string[]}>}
 */
export function createNavProfiles() {
  return [
    {
      id: 'software',
      label: 'Software',
      icon: LUCIDE_NAV_ICONS.profile_software,
      viewIds: ['packages', 'files']
    },
    {
      id: 'security',
      label: 'Security',
      icon: VIEW_ICONS.security,
      viewIds: ['security']
    },
    {
      id: 'licensing',
      label: 'Licensing',
      icon: VIEW_ICONS.licenses,
      viewIds: ['licenses']
    },
    {
      id: 'build',
      label: 'Build',
      icon: LUCIDE_NAV_ICONS.profile_build,
      viewIds: ['build', 'configs']
    },
    {
      id: 'functional-safety',
      label: 'Functional Safety',
      icon: VIEW_ICONS.requirements,
      viewIds: ['requirements', 'coverage']
    },
    {
      id: 'hardware',
      label: 'Hardware',
      icon: VIEW_ICONS.hardware,
      viewIds: ['hardware']
    },
    {
      id: 'ai-dataset',
      label: 'AI & Dataset',
      icon: LUCIDE_NAV_ICONS.profile_ai,
      viewIds: ['ai', 'dataset']
    },
    {
      id: 'supplychain',
      label: 'Supply Chain',
      icon: VIEW_ICONS.supplychain,
      viewIds: ['supplychain']
    },
    {
      id: 'agents',
      label: 'Agents',
      icon: VIEW_ICONS.agents,
      viewIds: ['agents']
    }
  ];
}

/** View ids always shown under Explore (never gated by isViewAvailable). */
export const NAV_EXPLORE_VIEW_IDS = ['dashboard', 'graph'];

/** View ids pinned in the sticky Insights band. */
export const NAV_INSIGHTS_VIEW_IDS = ['statistics', 'remediation', 'impact', 'raw'];

export { NAV_CHEVRON_ICON };

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
  'dependsOn:in': 'Required by',
  'hasPrerequisite:out': 'Prerequisites',
  'hasPrerequisite:in': 'Prerequisite for',
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
  'tracedToDetail:out': 'Traced to detail',
  'tracedToDetail:in': 'Detail of',
  'evaluationBasedOn:out': 'Based on',
  'evaluationBasedOn:in': 'Evaluated by',
  'trainedOn:out': 'Trained on',
  'trainedOn:in': 'Training dataset for',
  'testedOn:out': 'Tested on',
  'testedOn:in': 'Test dataset for',
  'hasConcludedLicense:out': 'Concluded license',
  'hasConcludedLicense:in': 'Licensed (concluded)',
  'hasDeclaredLicense:out': 'Declared license',
  'hasDeclaredLicense:in': 'Licensed (declared)',
  'createdBy:out': 'Created by',
  'createdBy:in': 'Creator of',
  'suppliedBy:out': 'Supplied by',
  'suppliedBy:in': 'Supplier of',
  'originatedBy:out': 'Originated by',
  'originatedBy:in': 'Originator of',
  'manufacturedBy:out': 'Manufactured by',
  'manufacturedBy:in': 'Manufacturer of',
  'performedBy:out': 'Performed by',
  'performedBy:in': 'Performer of',
  'resolved:out': 'Resolves',
  'resolved:in': 'Resolved by',
  'hasResolution:out': 'Resolution for',
  'hasResolution:in': 'Has resolution'
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
  'hasPrerequisite:out': 14.3,
  'hasPrerequisite:in': 14.6,
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
  'tracedToDetail:out': 42.5,
  'tracedToDetail:in': 42.6,
  'performedBy:out': 51,
  'performedBy:in': 52,
  'resolved:out': 53,
  'resolved:in': 54,
  'hasResolution:out': 55,
  'hasResolution:in': 56,
  'trainedOn:out': 31,
  'trainedOn:in': 32,
  'testedOn:out': 33,
  'testedOn:in': 34,
  'hasConcludedLicense:out': 27,
  'hasDeclaredLicense:out': 28,
  'hasConcludedLicense:in': 29,
  'hasDeclaredLicense:in': 30
};

/**
 * Hosts that serve this app without the license compatibility check.
 *
 * The check renders a verdict on whether licenses may be combined. Served from
 * SPDX's own tools domain that reads as SPDX taking a position on license
 * compatibility, which SPDX deliberately does not do: the specification
 * describes how to record licensing, not how licenses interact. The analysis
 * stays available everywhere else, where it is plainly this tool's own reading
 * of the OSADL matrix.
 *
 * Matched on host alone, so any path under the host is covered. Note that
 * tools.spdx.org reaches the app through an iframe rather than serving it, so
 * in practice isLicenseCompatAvailable's frame check is what covers it.
 * @constant {Set<string>}
 */
export const LICENSE_COMPAT_HIDDEN_HOSTS = new Set(['tools.spdx.org']);

// True when this document is not the top-level one. An opaque parent still
// counts, so a throw is read as "framed" rather than shrugged off.
function isFramed() {
  try {
    return typeof window !== 'undefined' && window.top !== window.self;
  } catch {
    return true;
  }
}

/**
 * Whether the Licenses view offers its compatibility check here.
 *
 * Withheld on the hosts above, and in any frame. tools.spdx.org does not serve
 * the app itself: it embeds the GitHub Pages build cross-origin, with
 * `referrerpolicy="no-referrer"`, so from inside that frame neither the host
 * nor the referrer names the embedder. Rather than guess at the parent, treat
 * being framed as enough on its own. Running inside someone else's page is what
 * makes the verdict look like theirs, which is the impression to avoid, and the
 * check is one click away in a tab of its own.
 *
 * @param {{hostname?: string, framed?: boolean}} [env] - defaults to this document's
 * @returns {boolean}
 */
export function isLicenseCompatAvailable(env = {}) {
  if (env.framed ?? isFramed()) return false;
  const host = env.hostname ?? (typeof location === 'undefined' ? '' : location.hostname || '');
  return !LICENSE_COMPAT_HIDDEN_HOSTS.has(String(host).toLowerCase());
}
