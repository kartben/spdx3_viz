/**
 * Node-type helpers: classifying an SPDX element into a graph node type and
 * mapping that type to colours / badge classes.
 *
 * @module lib/nodes
 */
import { COLORS } from '../config.js';
import { isA, CLASS } from '../spdx/model.js';

// An element's node type is a pure function of its immutable fields, but
// computing it walks the SPDX class hierarchy up to ~20 times (one isA() per
// candidate class). On a large SBOM the graph rebuild calls this once per
// element (hundreds of thousands of times), so memoize on the element object:
// the first call classifies, every later one is a lookup. A WeakMap lets
// discarded placeholder objects be collected. The hierarchy walk itself is
// memoized a second time, by type string, so even the first pass over a fresh
// SBOM does it once per class rather than once per element (see classNodeType).
const NODE_TYPE_CACHE = new WeakMap();

/**
 * Determines the node type from an element
 *
 * @param {Object} item - The SPDX element
 * @returns {string} Node type ('package', 'file', 'tool', 'build', 'agent', 'config', 'other')
 */
export function getNodeType(item) {
  if (!item || !item.type) return 'other';
  const cached = NODE_TYPE_CACHE.get(item);
  if (cached !== undefined) return cached;
  const type = computeNodeType(item);
  NODE_TYPE_CACHE.set(item, type);
  return type;
}

function computeNodeType(item) {
  // Placeholder nodes stand in for references that don't resolve to a loaded
  // element; grouped as one 'external' node type.
  if (item.placeholder || item.type === 'ExternalReference') return 'external';

  const base = classNodeType(item.type);
  // The one node type a class alone can't settle: a File declared as (or named
  // like) build configuration reads as config rather than source.
  if (base === 'file') {
    if (item.software_primaryPurpose === 'configuration' || item.spdxId?.includes('build-config')) {
      return 'config';
    }
  }
  return base;
}

// The class-hierarchy half of the classification, which is the same answer for
// every element sharing a type. Memoized on the type string: an SBOM has a few
// dozen distinct classes but can have a million elements, and the walk below
// asks isA() about ~20 candidate classes each time.
const CLASS_TYPE_CACHE = new Map();

function classNodeType(type) {
  let cached = CLASS_TYPE_CACHE.get(type);
  if (cached === undefined) {
    cached = computeClassNodeType(type);
    CLASS_TYPE_CACHE.set(type, cached);
  }
  return cached;
}

function computeClassNodeType(t) {
  // Classify by the SPDX class hierarchy, most specific first: AI and dataset
  // packages get their own node types before the generic package.
  if (isA(t, CLASS.ai_AIPackage)) return 'ai';
  if (isA(t, CLASS.dataset_DatasetPackage)) return 'dataset';
  if (isA(t, CLASS.software_Package)) return 'package';
  if (isA(t, CLASS.hardware_Hardware)) return 'hardware';
  if (
    isA(t, CLASS.supplychain_State) ||
    isA(t, CLASS.supplychain_CreateAction) ||
    isA(t, CLASS.supplychain_ModifyAction) ||
    isA(t, CLASS.supplychain_UseAction) ||
    isA(t, CLASS.supplychain_BoundaryDefinitionAction) ||
    isA(t, CLASS.supplychain_ResponsibilityChangeAction) ||
    isA(t, CLASS.supplychain_DestroyAction) ||
    isA(t, CLASS.supplychain_CreateProcess) ||
    isA(t, CLASS.supplychain_ModifyProcess) ||
    isA(t, CLASS.supplychain_UseProcess) ||
    isA(t, CLASS.supplychain_BoundaryDefinitionProcess) ||
    isA(t, CLASS.supplychain_ResponsibilityChangeProcess) ||
    isA(t, CLASS.supplychain_DestroyProcess)
  ) {
    return 'supplychain';
  }
  // The Requirement and its FunctionalSafety lifecycle artifacts share one type.
  if (
    isA(t, CLASS.Requirement) ||
    isA(t, CLASS.functionalsafety_RequirementVerification) ||
    isA(t, CLASS.functionalsafety_Assumption) ||
    isA(t, CLASS.functionalsafety_EvaluationResult)
  ) {
    return 'requirement';
  }
  if (isA(t, CLASS.software_File)) return 'file';
  // A snippet is a region of a file; it reads as source, close to its file.
  if (isA(t, CLASS.software_Snippet)) return 'snippet';
  if (isA(t, CLASS.Tool)) return 'tool';
  if (isA(t, CLASS.build_Build)) return 'build';
  // SoftwareAgent / Organization / Person (a bare Agent stays 'other').
  if (isA(t, CLASS.SoftwareAgent) || isA(t, CLASS.Organization) || isA(t, CLASS.Person)) {
    return 'agent';
  }
  if (
    isA(t, CLASS.simplelicensing_LicenseExpression) ||
    isA(t, CLASS.simplelicensing_SimpleLicensingText)
  ) {
    return 'license';
  }
  if (isA(t, CLASS.security_Vulnerability)) return 'vulnerability';
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
    ai: COLORS.ai,
    dataset: COLORS.dataset,
    file: COLORS.file,
    snippet: COLORS.snippet,
    hardware: COLORS.hardware,
    supplychain: COLORS.supplychain,
    requirement: COLORS.requirement,
    tool: COLORS.tool,
    build: COLORS.build,
    agent: COLORS.agent,
    config: COLORS.config,
    license: COLORS.license,
    external: COLORS.external,
    vulnerability: COLORS.vulnerability
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
    software_Snippet: 'bg-emerald-400/15 text-emerald-300',
    hardware_Hardware: 'bg-lime-500/15 text-lime-400',
    hardware_PhysicalHardware: 'bg-lime-500/15 text-lime-400',
    hardware_BulkHardware: 'bg-lime-500/15 text-lime-400',
    hardware_VirtualHardware: 'bg-lime-500/15 text-lime-400',
    supplychain_State: 'bg-cyan-500/15 text-cyan-300',
    supplychain_AssemblyAction: 'bg-cyan-500/15 text-cyan-300',
    supplychain_BoundaryCrossingAction: 'bg-cyan-500/15 text-cyan-300',
    supplychain_BoundaryDefinitionAction: 'bg-cyan-500/15 text-cyan-300',
    supplychain_ChangeAction: 'bg-cyan-500/15 text-cyan-300',
    supplychain_CreateAction: 'bg-cyan-500/15 text-cyan-300',
    supplychain_DestroyAction: 'bg-cyan-500/15 text-cyan-300',
    supplychain_HarvestAction: 'bg-cyan-500/15 text-cyan-300',
    supplychain_InspectionAction: 'bg-cyan-500/15 text-cyan-300',
    supplychain_ManufactureAction: 'bg-cyan-500/15 text-cyan-300',
    supplychain_OutOfSpecAction: 'bg-rose-500/15 text-rose-300',
    supplychain_PlanAction: 'bg-cyan-500/15 text-cyan-300',
    supplychain_ReproduceAction: 'bg-cyan-500/15 text-cyan-300',
    supplychain_ResolutionAction: 'bg-emerald-500/15 text-emerald-300',
    supplychain_ResponsibilityChangeAction: 'bg-cyan-500/15 text-cyan-300',
    supplychain_StateAction: 'bg-cyan-500/15 text-cyan-300',
    supplychain_StorageAction: 'bg-cyan-500/15 text-cyan-300',
    supplychain_TestAction: 'bg-cyan-500/15 text-cyan-300',
    supplychain_TransportAction: 'bg-cyan-500/15 text-cyan-300',
    supplychain_UseAction: 'bg-cyan-500/15 text-cyan-300',
    Requirement: 'bg-yellow-500/15 text-yellow-400',
    functionalsafety_RequirementVerification: 'bg-yellow-500/15 text-yellow-400',
    functionalsafety_Assumption: 'bg-yellow-500/15 text-yellow-400',
    functionalsafety_EvaluationResult: 'bg-yellow-500/15 text-yellow-400',
    Tool: 'bg-amber-500/15 text-amber-400',
    build_Build: 'bg-purple-500/15 text-purple-400',
    SoftwareAgent: 'bg-red-500/15 text-red-400',
    Organization: 'bg-red-500/15 text-red-400',
    Person: 'bg-red-500/15 text-red-400',
    ExternalReference: 'bg-slate-500/15 text-slate-400',
    simplelicensing_LicenseExpression: 'bg-pink-500/15 text-pink-400',
    simplelicensing_SimpleLicensingText: 'bg-pink-500/15 text-pink-400',
    software_Sbom: 'bg-indigo-500/15 text-indigo-400',
    security_Vulnerability: 'bg-rose-500/15 text-rose-400'
  };
  return classMap[type] || 'bg-slate-600/15 text-slate-400';
}
