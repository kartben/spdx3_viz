/**
 * SPDX 3.0 SBOM Visualizer - Data Parser
 *
 * Handles parsing of SPDX JSON-LD data, building element maps,
 * and creating relationship indexes for efficient lookups.
 *
 * @module parser
 */

import { ELEMENT_TYPES, RELATIONSHIP_TYPES, VEX_TYPES } from './config.js';
import {
  displayLicenseExpression,
  renderLicenseExpression,
  getRelationshipColor,
  getVulnerabilityId,
  getVulnerabilityLocators,
  vexStatusForRel
} from './utils.js';

/**
 * Builds a throttled progress reporter. Returns a function to call once per
 * processed item; it invokes `onProgress(fraction)` at most ~50 times so the
 * parser can drive a progress bar without per-iteration overhead. Returns a
 * no-op when no callback is supplied (e.g. tests, or the synchronous path).
 *
 * @param {((fraction: number) => void)|undefined} onProgress
 * @param {number} total - Total number of items that will be processed
 * @returns {() => void}
 */
function makeThrottledReporter(onProgress, total) {
  if (typeof onProgress !== 'function' || !total) return () => {};
  let processed = 0;
  let next = 0;
  const step = Math.max(1, Math.floor(total / 50));
  return () => {
    processed++;
    if (processed >= next) {
      next = processed + step;
      onProgress(processed / total);
    }
  };
}

/* ==========================================================================
   Parser Result Type
   ========================================================================== */

/**
 * @typedef {Object} ParsedData
 * @property {Map<string, Object>} elementMap - Map of SPDX IDs to elements
 * @property {Array<Object>} packages - Package elements
 * @property {Array<Object>} files - File elements (excluding build configs)
 * @property {Array<Object>} tools - Tool elements
 * @property {Array<Object>} relationships - Relationship elements
 * @property {Array<Object>} builds - Build elements
 * @property {Array<Object>} buildConfigs - Build configuration elements
 * @property {Object|null} buildInfo - Build information element
 * @property {Object|null} agentInfo - Agent information element (SoftwareAgent, Organization or Person)
 * @property {Array<Object>} sboms - software_Sbom elements
 * @property {Array<string>} sbomTypes - Distinct software_sbomType values (source, build, …)
 * @property {Array<{id: string, name: string, type: string}>} creators - Document creators (createdBy)
 * @property {Array<{id: string, name: string, type: string}>} creatorTools - Tools the documents were created with (createdUsing)
 * @property {Array<Object>} licenses - Licenses used, with declaring/concluding elements
 * @property {Array<Object>} vulnerabilities - Enriched vulnerabilities (CVEs) with VEX assessments
 * @property {Array<Object>} vexRelationships - Raw VEX assessment relationship elements
 * @property {Map<string, Array>} vexByVuln - Vulnerability spdxId -> [VexAssessment]
 * @property {Map<string, Array>} vexByPackage - Package spdxId -> [VexAssessment]
 * @property {Array<string>} presentNodeTypes - Graph node types present in the data
 * @property {Array<string>} presentRelTypes - Relationship types present in the data
 * @property {string} docName - Document name
 * @property {string} docNamespace - Document namespace
 * @property {string} specVersion - SPDX spec version
 * @property {string} createdDate - Creation date
 * @property {string} dataLicenseLabel - Data license label
 * @property {Array<string>} profileConformance - Profile conformance list
 * @property {Array<string>} generatedArtifacts - Generated artifact IDs
 */

/**
 * @typedef {Object} RelationshipIndexes
 * @property {Map<string, Array>} relFromIndex - Relationships indexed by 'from' field
 * @property {Map<string, Array>} relToIndex - Relationships indexed by 'to' field
 * @property {Map<string, Array>} depIndex - Dependencies (dependsOn targets)
 * @property {Map<string, Array>} dependentIndex - Dependents (things that depend on it)
 * @property {Map<string, Array>} containsIndex - Contains relationships
 * @property {Map<string, string>} parentIndex - Parent package for files
 * @property {Map<string, Array>} toolIndex - Tools used by files
 * @property {Map<string, Array>} staticLinkIndex - Static link relationships
 * @property {Map<string, Array>} configuresIndex - Config to targets mapping
 * @property {Map<string, Array>} configuredByIndex - Target to configs mapping
 * @property {Map<string, Array>} buildInputIndex - Build to input elements mapping
 * @property {Map<string, Array>} buildOutputIndex - Build to output elements mapping
 * @property {Map<string, Array>} producedByBuildIndex - Artifact to producing builds mapping
 * @property {Map<string, Array>} consumedByBuildIndex - Input to consuming builds mapping
 * @property {Map<string, Array>} buildStepIndex - Build to child build steps mapping
 * @property {Map<string, Array>} parentBuildIndex - Build step to parent/root build mapping
 * @property {Map<string, Array>} distributionArtifactIndex - Package to distribution artifacts mapping
 * @property {Map<string, Array>} distributedByIndex - Artifact to distributing packages mapping
 * @property {Map<string, Array>} licenseUsersIndex - License id to [{from, kind}] mapping
 */

/* ==========================================================================
   Main Parser Function
   ========================================================================== */

/**
 * Parses an SPDX JSON-LD graph array and extracts all elements and relationships
 *
 * @param {Array<Object>} graph - The @graph array from SPDX JSON-LD
 * @returns {ParsedData} Parsed data with all elements categorized
 *
 * @example
 * const spdxData = JSON.parse(jsonString);
 * const parsed = parseGraph(spdxData['@graph']);
 */
export function parseGraph(graph, onProgress) {
  if (!Array.isArray(graph)) {
    graph = [];
  }

  // Reports across the two passes below (2 × graph.length items of work).
  const report = makeThrottledReporter(onProgress, graph.length * 2);

  /** @type {Map<string, Object>} */
  const elementMap = new Map();

  /** @type {Array<Object>} */
  const packages = [];

  /** @type {Array<Object>} */
  const files = [];

  /** @type {Array<Object>} */
  const tools = [];

  /** @type {Array<Object>} */
  const relationships = [];

  /** @type {Array<Object>} */
  const builds = [];

  /** @type {Array<Object>} */
  const vulnerabilities = [];

  /** @type {Array<Object>} */
  const vexRelationships = [];

  /** @type {Array<Object>} */
  const sboms = [];

  /** @type {Array<string>} */
  const generatedArtifacts = [];

  /** @type {Object|null} */
  let buildInfo = null;

  /** @type {Object|null} */
  let agentInfo = null;

  /** @type {Object|null} */
  let orgInfo = null; // first Organization/Person, used when no SoftwareAgent exists

  // Document metadata
  let docName = '';
  let docNamespace = '';
  let specVersion = '';
  let createdDate = '';
  let dataLicenseLabel = '';
  const profileConformance = [];

  /** @type {Array<Object>} - Resolved CreationInfo of each SpdxDocument */
  const docCreationInfos = [];

  /** @type {Object|null} - Any CreationInfo seen, as a metadata fallback */
  let anyCreationInfo = null;

  // Track seen IDs to deduplicate
  const seen = new Set();

  // `creationInfo` is either an inline object or a string reference to a
  // standalone CreationInfo element (identified by `@id`, e.g. `_:creationinfo`
  // — the form the Linux kernel and Yocto producers emit).
  const resolveCreationInfo = (el) => {
    const ci = el?.creationInfo;
    if (typeof ci === 'string') return elementMap.get(ci) || null;
    return ci || null;
  };

  // First pass: register all elements in the map
  graph.forEach((item) => {
    report();
    if (item.spdxId) {
      elementMap.set(item.spdxId, item);
    }
    if (item['@id'] && !item.spdxId) {
      elementMap.set(item['@id'], item);
    }
  });

  // Second pass: categorize elements
  graph.forEach((item) => {
    report();
    // Skip duplicate spdxIds
    if (item.spdxId) {
      if (seen.has(item.spdxId)) return;
      seen.add(item.spdxId);
    }

    switch (item.type) {
      case ELEMENT_TYPES.PACKAGE:
        packages.push(item);
        break;

      case ELEMENT_TYPES.FILE:
        files.push(item);
        break;

      case ELEMENT_TYPES.TOOL:
        tools.push(item);
        break;

      case ELEMENT_TYPES.RELATIONSHIP:
      case ELEMENT_TYPES.LIFECYCLE_RELATIONSHIP:
        relationships.push(item);
        break;

      case ELEMENT_TYPES.BUILD:
        builds.push(item);
        break;

      case ELEMENT_TYPES.VULNERABILITY:
        vulnerabilities.push(item);
        break;

      case VEX_TYPES.FIXED:
      case VEX_TYPES.NOT_AFFECTED:
      case VEX_TYPES.AFFECTED:
      case VEX_TYPES.UNDER_INVESTIGATION:
        vexRelationships.push(item);
        break;

      case ELEMENT_TYPES.AGENT:
        agentInfo = agentInfo || item;
        break;

      case ELEMENT_TYPES.ORGANIZATION:
      case ELEMENT_TYPES.PERSON:
        orgInfo = orgInfo || item;
        break;

      case ELEMENT_TYPES.SBOM:
        sboms.push(item);
        break;

      case ELEMENT_TYPES.CREATION_INFO:
        anyCreationInfo = anyCreationInfo || item;
        break;

      case ELEMENT_TYPES.DOCUMENT: {
        // Merge document metadata: accumulate profiles, keep first values
        if (!docName) docName = item.name || '';
        if (!docNamespace) docNamespace = item.namespaceMap?.[0]?.namespace || '';

        const profiles = item.profileConformance || [];
        profiles.forEach((profile) => {
          if (!profileConformance.includes(profile)) {
            profileConformance.push(profile);
          }
        });

        const ci = resolveCreationInfo(item);
        if (ci) docCreationInfos.push(ci);
        if (!createdDate) createdDate = ci?.created || '';
        if (!specVersion) specVersion = ci?.specVersion || '';
        if (!dataLicenseLabel) {
          dataLicenseLabel = item.dataLicense ? item.dataLicense.split('/').pop() : '';
        }
        break;
      }
    }
  });

  // Fallbacks when no SpdxDocument carried the metadata (or its creationInfo
  // could not be resolved): use any CreationInfo present in the graph.
  if (!createdDate) createdDate = anyCreationInfo?.created || '';
  if (!specVersion) specVersion = anyCreationInfo?.specVersion || '';

  // Documents without a name (e.g. the Linux kernel SBOMs): fall back to the
  // name of an SBOM element or of one of the SBOMs' root elements, preferring a
  // root Package (e.g. "Linux Kernel (bzImage)") over a root source-tree File.
  if (!docName) {
    const named = sboms.find((sbom) => sbom.name);
    const roots = sboms
      .flatMap((sbom) => (Array.isArray(sbom.rootElement) ? sbom.rootElement : []))
      .map((id) => elementMap.get(id))
      .filter((el) => el?.name);
    docName =
      named?.name ||
      roots.find((el) => el.type === ELEMENT_TYPES.PACKAGE)?.name ||
      roots[0]?.name ||
      '';
  }

  // SBOM lifecycle types declared by software_Sbom elements (source / build /
  // deployed / …) — surfaced as chips next to the profile conformance list.
  const sbomTypes = [];
  sboms.forEach((sbom) => {
    (sbom.software_sbomType || []).forEach((type) => {
      if (!sbomTypes.includes(type)) sbomTypes.push(type);
    });
  });

  // Who/what produced the documents, resolved from the documents' CreationInfo
  // (falls back to every CreationInfo when documents carry none).
  const { creators, creatorTools } = collectCreators(
    docCreationInfos.length ? docCreationInfos : anyCreationInfo ? [anyCreationInfo] : [],
    elementMap
  );

  // Prefer a SoftwareAgent, but surface an Organization/Person creator
  // (e.g. Yocto's "OpenEmbedded") when that is all the SBOM declares.
  agentInfo = agentInfo || orgInfo;

  // Separate build configs from regular files
  const buildConfigs = files.filter(
    (file) =>
      file.software_primaryPurpose === 'configuration' || file.spdxId?.includes('build-config')
  );

  const regularFiles = files.filter(
    (file) =>
      file.software_primaryPurpose !== 'configuration' && !file.spdxId?.includes('build-config')
  );

  const rootBuildIds = new Set();
  relationships.forEach((rel) => {
    if (
      rel.relationshipType === RELATIONSHIP_TYPES.ANCESTOR_OF &&
      elementMap.get(rel.from)?.type === ELEMENT_TYPES.BUILD
    ) {
      rootBuildIds.add(rel.from);
    }
  });
  buildInfo =
    builds.find((build) => rootBuildIds.has(build.spdxId)) ||
    builds.find(
      (build) => build.build_environment?.length || build.build_configSourceUri?.length
    ) ||
    builds[0] ||
    null;

  // Track generated artifacts
  const pushGeneratedArtifact = (target) => {
    if (target && !generatedArtifacts.includes(target)) {
      generatedArtifacts.push(target);
    }
  };

  relationships.forEach((rel) => {
    if (
      rel.relationshipType === RELATIONSHIP_TYPES.GENERATES ||
      rel.relationshipType === RELATIONSHIP_TYPES.HAS_OUTPUT
    ) {
      const targets = Array.isArray(rel.to) ? rel.to : [rel.to];
      targets.forEach(pushGeneratedArtifact);
    }
  });

  // Collect all licenses used across the SBOM, derived from license
  // relationships so we capture URL-only and NoAssertion targets too.
  const licenses = collectLicenses(relationships, elementMap);

  // Build the VEX model: enriched vulnerabilities + vuln↔package indexes.
  const vex = buildVexModel(vulnerabilities, vexRelationships, elementMap);

  // Which node/relationship types actually occur in this dataset. The graph
  // legend uses these to hide entries for types the SBOM doesn't contain, so it
  // doesn't grow a long list of irrelevant toggles.
  const { presentNodeTypes, presentRelTypes } = computePresentTypes({
    packages,
    regularFiles,
    tools,
    builds,
    buildConfigs,
    vulnerabilities,
    relationships,
    vexRelationships,
    elementMap
  });

  return {
    elementMap,
    packages,
    files: regularFiles,
    tools,
    relationships,
    builds,
    buildConfigs,
    buildInfo,
    agentInfo,
    sboms,
    sbomTypes,
    creators,
    creatorTools,
    licenses,
    vulnerabilities: vex.vulnerabilities,
    vexRelationships,
    vexByVuln: vex.vexByVuln,
    vexByPackage: vex.vexByPackage,
    presentNodeTypes,
    presentRelTypes,
    docName,
    docNamespace,
    specVersion,
    createdDate,
    dataLicenseLabel,
    profileConformance,
    generatedArtifacts
  };
}

/* ==========================================================================
   Creator Collection
   ========================================================================== */

/**
 * Resolves the agents (createdBy) and tools (createdUsing) referenced by the
 * documents' CreationInfo records into displayable {id, name, type} entries.
 *
 * @param {Array<Object>} creationInfos - Resolved CreationInfo objects
 * @param {Map<string, Object>} elementMap
 * @returns {{creators: Array<{id: string, name: string, type: string}>, creatorTools: Array<{id: string, name: string, type: string}>}}
 */
function collectCreators(creationInfos, elementMap) {
  const collect = (prop) => {
    const out = [];
    const seenIds = new Set();
    creationInfos.forEach((ci) => {
      (ci?.[prop] || []).forEach((ref) => {
        if (!ref || seenIds.has(ref)) return;
        seenIds.add(ref);
        const el = elementMap.get(ref);
        out.push({
          id: ref,
          name: el?.name || ref.split('/').pop() || ref,
          type: el?.type || ''
        });
      });
    });
    return out;
  };

  return { creators: collect('createdBy'), creatorTools: collect('createdUsing') };
}

/* ==========================================================================
   VEX Model
   ========================================================================== */

/**
 * @typedef {Object} VexAssessment
 * @property {string} status - Normalized status: fixed | not_affected | affected | under_investigation
 * @property {string} vulnId - spdxId of the security_Vulnerability
 * @property {string} vulnName - Display id of the vulnerability (e.g. a CVE id)
 * @property {string} packageId - spdxId of the assessed package/element
 * @property {string} justification - VexJustificationType (not-affected only)
 * @property {string} impactStatement - Free-text impact statement (not-affected)
 * @property {string} actionStatement - Recommended action (affected)
 * @property {string} statusNotes - Free-text status notes
 * @property {string} vexVersion - security_vexVersion, when present
 * @property {string} spdxId - spdxId of the VEX relationship element
 */

/**
 * @typedef {Object} EnrichedVulnerability
 * @property {Object} el - The raw security_Vulnerability element
 * @property {string} spdxId
 * @property {string} name - Display id (CVE id when available)
 * @property {string} cveId
 * @property {string[]} locators - Reference URLs
 * @property {VexAssessment[]} assessments
 * @property {Object<string, number>} statusCounts - status -> distinct package count
 * @property {string} overallStatus - Most severe status across all assessments
 * @property {number} packageCount - Distinct assessed packages
 */

/**
 * Builds the enriched vulnerability list and the vuln↔package assessment
 * indexes from the raw vulnerabilities and VEX assessment relationships.
 *
 * @param {Array<Object>} vulnerabilities - Raw security_Vulnerability elements
 * @param {Array<Object>} vexRelationships - Raw VEX assessment relationship elements
 * @param {Map<string, Object>} elementMap
 * @returns {{vulnerabilities: EnrichedVulnerability[], vexByVuln: Map<string, VexAssessment[]>, vexByPackage: Map<string, VexAssessment[]>}}
 */
function buildVexModel(vulnerabilities, vexRelationships, elementMap) {
  /** @type {Map<string, VexAssessment[]>} */
  const vexByVuln = new Map();
  /** @type {Map<string, VexAssessment[]>} */
  const vexByPackage = new Map();

  const push = (map, key, value) => {
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(value);
  };

  const vulnNameOf = (vulnId) => {
    const el = elementMap.get(vulnId);
    return el ? getVulnerabilityId(el) : vulnId?.split('/').pop() || vulnId;
  };

  vexRelationships.forEach((rel) => {
    // Prefer the explicit relationshipType; fall back to the element class.
    const status =
      vexStatusForRel(rel.relationshipType) ||
      {
        [VEX_TYPES.FIXED]: 'fixed',
        [VEX_TYPES.NOT_AFFECTED]: 'not_affected',
        [VEX_TYPES.AFFECTED]: 'affected',
        [VEX_TYPES.UNDER_INVESTIGATION]: 'under_investigation'
      }[rel.type];
    if (!status) return;

    const vulnId = rel.from;
    if (!vulnId) return;
    const vulnName = vulnNameOf(vulnId);
    const targets = Array.isArray(rel.to) ? rel.to : [rel.to];
    targets.forEach((packageId) => {
      if (!packageId) return;
      /** @type {VexAssessment} */
      const assessment = {
        status,
        vulnId,
        vulnName,
        packageId,
        justification: rel.security_justificationType || '',
        impactStatement: rel.security_impactStatement || '',
        actionStatement: rel.security_actionStatement || '',
        statusNotes: rel.security_statusNotes || '',
        vexVersion: rel.security_vexVersion || '',
        spdxId: rel.spdxId
      };
      push(vexByVuln, vulnId, assessment);
      push(vexByPackage, packageId, assessment);
    });
  });

  const SEVERITY = { affected: 4, under_investigation: 3, not_affected: 2, fixed: 1 };

  const enriched = vulnerabilities.map((el) => {
    const assessments = vexByVuln.get(el.spdxId) || [];
    const cveId = getVulnerabilityId(el);

    // Count distinct packages per status (a vuln can hit the same package via
    // more than one VEX record; don't double-count).
    const pkgsByStatus = {};
    let overallStatus = null;
    assessments.forEach((a) => {
      (pkgsByStatus[a.status] ||= new Set()).add(a.packageId);
      if (!overallStatus || SEVERITY[a.status] > SEVERITY[overallStatus]) {
        overallStatus = a.status;
      }
    });
    const statusCounts = {};
    Object.keys(pkgsByStatus).forEach((s) => (statusCounts[s] = pkgsByStatus[s].size));
    const packageCount = new Set(assessments.map((a) => a.packageId)).size;

    return {
      el,
      spdxId: el.spdxId,
      name: cveId,
      cveId,
      locators: getVulnerabilityLocators(el),
      assessments,
      statusCounts,
      // A vulnerability with no VEX assessment is "unknown" (present in the SBOM
      // but not connected to a package by a VEX status) — never assume "fixed".
      overallStatus: overallStatus || 'unknown',
      packageCount
    };
  });

  return { vulnerabilities: enriched, vexByVuln, vexByPackage };
}

/**
 * Determines which node and relationship types are actually present in the
 * parsed dataset. Used to trim the graph legend.
 *
 * @returns {{presentNodeTypes: string[], presentRelTypes: string[]}}
 */
function computePresentTypes(data) {
  const nodeTypes = new Set();
  if (data.packages.length) nodeTypes.add('package');
  if (data.regularFiles.length) nodeTypes.add('file');
  if (data.tools.length) nodeTypes.add('tool');
  if (data.builds.length) nodeTypes.add('build');
  if (data.buildConfigs.length) nodeTypes.add('config');
  if (data.vulnerabilities.length) nodeTypes.add('vulnerability');

  const relTypes = new Set();
  data.relationships.forEach((r) => r.relationshipType && relTypes.add(r.relationshipType));
  data.vexRelationships.forEach((r) => r.relationshipType && relTypes.add(r.relationshipType));

  // "External" nodes are placeholders the graph creates for drawn relationship
  // endpoints that resolve to nothing in the element map (and aren't license
  // URLs / NoAssertion). Detect whether any such endpoint exists.
  const isExternal = (id) =>
    id && !data.elementMap.has(id) && !/^https?:\/\//i.test(id) && !id.includes('NoAssertion');
  const hasExternal = data.relationships.some((rel) => {
    if (
      rel.relationshipType === 'hasConcludedLicense' ||
      rel.relationshipType === 'hasDeclaredLicense'
    ) {
      return false;
    }
    const ends = [rel.from, ...(Array.isArray(rel.to) ? rel.to : [rel.to])];
    return ends.some(isExternal);
  });
  if (hasExternal) nodeTypes.add('external');

  return { presentNodeTypes: [...nodeTypes], presentRelTypes: [...relTypes] };
}

/* ==========================================================================
   License Collection
   ========================================================================== */

/**
 * Resolves a human-readable label for a license target id.
 *
 * @param {string} id - License target id (LicenseExpression spdxId, URL, or NoAssertion)
 * @param {Map<string, Object>} elementMap - Map of SPDX IDs to elements
 * @returns {string} Display label
 */
function resolveLicenseLabel(id, elementMap) {
  if (!id) return '';
  const el = elementMap.get(id);
  if (el?.simplelicensing_licenseExpression) {
    return displayLicenseExpression(el, elementMap);
  }
  const expandedExpr = renderLicenseExpression(el, elementMap);
  if (expandedExpr) return expandedExpr;
  const spdxLicenseMatch = id.match(/^https?:\/\/spdx\.org\/licenses\/(.+)$/);
  if (spdxLicenseMatch) {
    return spdxLicenseMatch[1];
  }
  if (id.includes('NoAssertion')) {
    return 'NoAssertion';
  }
  if (el?.name) return el.name;
  return id;
}

/**
 * Builds the list of distinct licenses used, with the elements that declare
 * or conclude each one. Derived from `hasConcludedLicense` /
 * `hasDeclaredLicense` relationships.
 *
 * @param {Array<Object>} relationships - All relationship objects
 * @param {Map<string, Object>} elementMap - Map of SPDX IDs to elements
 * @returns {Array<{id: string, label: string, declaredBy: string[], concludedBy: string[], userCount: number}>}
 */
function collectLicenses(relationships, elementMap) {
  const byId = new Map();

  const ensure = (id) => {
    if (!byId.has(id)) {
      byId.set(id, {
        id,
        label: resolveLicenseLabel(id, elementMap),
        declaredBy: [],
        concludedBy: [],
        userCount: 0
      });
    }
    return byId.get(id);
  };

  const addUser = (bucket, from) => {
    if (from && !bucket.includes(from)) bucket.push(from);
  };

  relationships.forEach((rel) => {
    const isDeclared = rel.relationshipType === RELATIONSHIP_TYPES.HAS_DECLARED_LICENSE;
    const isConcluded = rel.relationshipType === RELATIONSHIP_TYPES.HAS_CONCLUDED_LICENSE;
    if (!isDeclared && !isConcluded) return;

    const targets = Array.isArray(rel.to) ? rel.to : [rel.to];
    targets.forEach((target) => {
      if (!target) return;
      const entry = ensure(target);
      addUser(isDeclared ? entry.declaredBy : entry.concludedBy, rel.from);
    });
  });

  const licenses = [...byId.values()];
  licenses.forEach((lic) => {
    const users = new Set([...lic.declaredBy, ...lic.concludedBy]);
    lic.userCount = users.size;
  });

  // Default sort: most used first, then alphabetical by label.
  licenses.sort((a, b) => b.userCount - a.userCount || a.label.localeCompare(b.label));
  return licenses;
}

/* ==========================================================================
   Relationship Index Builder
   ========================================================================== */

/**
 * Builds relationship indexes for efficient lookups
 *
 * @param {Array<Object>} relationships - Array of relationship objects
 * @returns {RelationshipIndexes} Object containing all relationship indexes
 *
 * @example
 * const indexes = buildRelationshipIndexes(parsedData.relationships);
 * const deps = indexes.depIndex.get(packageId) || [];
 */
export function buildRelationshipIndexes(relationships, onProgress) {
  const report = makeThrottledReporter(onProgress, relationships.length);

  // Initialize all indexes
  const relFromIndex = new Map();
  const relToIndex = new Map();
  const depIndex = new Map();
  const dependentIndex = new Map();
  const containsIndex = new Map();
  const parentIndex = new Map();
  const toolIndex = new Map();
  const staticLinkIndex = new Map();
  const configuresIndex = new Map();
  const configuredByIndex = new Map();
  const buildInputIndex = new Map();
  const buildOutputIndex = new Map();
  const producedByBuildIndex = new Map();
  const consumedByBuildIndex = new Map();
  const buildStepIndex = new Map();
  const parentBuildIndex = new Map();
  const distributionArtifactIndex = new Map();
  const distributedByIndex = new Map();
  const licenseUsersIndex = new Map();

  // Pushes a value into a Map<string, Array> bucket, skipping duplicates.
  // SPDX producers (e.g. Zephyr) may emit the same logical edge more than once
  // as distinct Relationship records. These duplicates would otherwise inflate
  // dependency/dependent counts and, because the UI renders the lists with a
  // keyed x-for, break rendering entirely on duplicate keys.
  const pushUnique = (map, key, value) => {
    if (!map.has(key)) {
      map.set(key, []);
    }
    const bucket = map.get(key);
    if (!bucket.includes(value)) {
      bucket.push(value);
    }
  };

  relationships.forEach((rel) => {
    report();
    const from = rel.from;
    const targets = Array.isArray(rel.to) ? rel.to : [rel.to];

    // Build from index
    if (!relFromIndex.has(from)) {
      relFromIndex.set(from, []);
    }
    relFromIndex.get(from).push(rel);

    // Build to index
    targets.forEach((target) => {
      if (!relToIndex.has(target)) {
        relToIndex.set(target, []);
      }
      relToIndex.get(target).push(rel);
    });

    // Build specific indexes based on relationship type
    switch (rel.relationshipType) {
      case RELATIONSHIP_TYPES.DEPENDS_ON:
        targets.forEach((target) => {
          pushUnique(depIndex, from, target);
          pushUnique(dependentIndex, target, from);
        });
        break;

      case RELATIONSHIP_TYPES.CONTAINS:
        targets.forEach((target) => {
          pushUnique(containsIndex, from, target);
          parentIndex.set(target, from);
        });
        break;

      case RELATIONSHIP_TYPES.USES_TOOL:
        targets.forEach((target) => {
          pushUnique(toolIndex, from, target);
        });
        break;

      case RELATIONSHIP_TYPES.GENERATES:
      case RELATIONSHIP_TYPES.HAS_OUTPUT:
        targets.forEach((target) => {
          pushUnique(buildOutputIndex, from, target);
          pushUnique(producedByBuildIndex, target, from);
        });
        break;

      case RELATIONSHIP_TYPES.HAS_INPUT:
        targets.forEach((target) => {
          pushUnique(buildInputIndex, from, target);
          pushUnique(consumedByBuildIndex, target, from);
        });
        break;

      case RELATIONSHIP_TYPES.HAS_DISTRIBUTION_ARTIFACT:
        targets.forEach((target) => {
          pushUnique(distributionArtifactIndex, from, target);
          pushUnique(distributedByIndex, target, from);
        });
        break;

      case RELATIONSHIP_TYPES.ANCESTOR_OF:
        targets.forEach((target) => {
          pushUnique(buildStepIndex, from, target);
          pushUnique(parentBuildIndex, target, from);
        });
        break;

      case RELATIONSHIP_TYPES.HAS_STATIC_LINK:
        targets.forEach((target) => {
          pushUnique(staticLinkIndex, from, target);
        });
        break;

      case RELATIONSHIP_TYPES.CONFIGURES:
        targets.forEach((target) => {
          pushUnique(configuresIndex, from, target);

          if (!configuredByIndex.has(target)) {
            configuredByIndex.set(target, []);
          }
          const cfgBucket = configuredByIndex.get(target);
          if (!cfgBucket.some((c) => c.configId === from)) {
            cfgBucket.push({
              configId: from,
              scope: rel.scope,
              description: rel.description
            });
          }
        });
        break;

      case RELATIONSHIP_TYPES.HAS_DECLARED_LICENSE:
      case RELATIONSHIP_TYPES.HAS_CONCLUDED_LICENSE: {
        const kind =
          rel.relationshipType === RELATIONSHIP_TYPES.HAS_DECLARED_LICENSE
            ? 'declared'
            : 'concluded';
        targets.forEach((target) => {
          if (!licenseUsersIndex.has(target)) {
            licenseUsersIndex.set(target, []);
          }
          const bucket = licenseUsersIndex.get(target);
          if (!bucket.some((u) => u.from === from && u.kind === kind)) {
            bucket.push({ from, kind });
          }
        });
        break;
      }
    }
  });

  return {
    relFromIndex,
    relToIndex,
    depIndex,
    dependentIndex,
    containsIndex,
    parentIndex,
    toolIndex,
    staticLinkIndex,
    configuresIndex,
    configuredByIndex,
    buildInputIndex,
    buildOutputIndex,
    producedByBuildIndex,
    consumedByBuildIndex,
    buildStepIndex,
    parentBuildIndex,
    distributionArtifactIndex,
    distributedByIndex,
    licenseUsersIndex
  };
}

/* ==========================================================================
   Index Accessor Functions
   Helper functions to safely access indexes
   ========================================================================== */

/**
 * Creates accessor functions for relationship indexes
 * These functions safely return empty arrays when keys don't exist
 *
 * @param {RelationshipIndexes} indexes - The relationship indexes
 * @returns {Object} Object containing accessor functions
 */
export function createIndexAccessors(indexes) {
  return {
    /**
     * Gets dependencies of an element
     * @param {string} spdxId - The element's SPDX ID
     * @returns {Array<string>} Array of dependency SPDX IDs
     */
    depsOf: (spdxId) => indexes.depIndex.get(spdxId) || [],

    /**
     * Gets elements that depend on this element
     * @param {string} spdxId - The element's SPDX ID
     * @returns {Array<string>} Array of dependent SPDX IDs
     */
    dependentsOf: (spdxId) => indexes.dependentIndex.get(spdxId) || [],

    /**
     * Gets files contained in a package
     * @param {string} spdxId - The package's SPDX ID
     * @returns {Array<string>} Array of file SPDX IDs
     */
    containedFiles: (spdxId) => indexes.containsIndex.get(spdxId) || [],

    /**
     * Gets the parent package of a file
     * @param {string} spdxId - The file's SPDX ID
     * @returns {string|null} Parent package SPDX ID or null
     */
    parentPackage: (spdxId) => indexes.parentIndex.get(spdxId) || null,

    /**
     * Gets tools used to build a file
     * @param {string} spdxId - The file's SPDX ID
     * @returns {Array<string>} Array of tool SPDX IDs
     */
    fileTools: (spdxId) => indexes.toolIndex.get(spdxId) || [],

    /**
     * Gets inputs consumed by a build
     * @param {string} spdxId - The build's SPDX ID
     * @returns {Array<string>} Array of input SPDX IDs
     */
    buildInputs: (spdxId) => indexes.buildInputIndex.get(spdxId) || [],

    /**
     * Gets outputs produced by a build
     * @param {string} spdxId - The build's SPDX ID
     * @returns {Array<string>} Array of output SPDX IDs
     */
    buildOutputs: (spdxId) => indexes.buildOutputIndex.get(spdxId) || [],

    /**
     * Gets builds that produced an artifact
     * @param {string} spdxId - The artifact's SPDX ID
     * @returns {Array<string>} Array of build SPDX IDs
     */
    producedByBuilds: (spdxId) => indexes.producedByBuildIndex.get(spdxId) || [],

    /**
     * Gets builds that consumed an input
     * @param {string} spdxId - The input's SPDX ID
     * @returns {Array<string>} Array of build SPDX IDs
     */
    consumedByBuilds: (spdxId) => indexes.consumedByBuildIndex.get(spdxId) || [],

    /**
     * Gets child build steps for a build
     * @param {string} spdxId - The build's SPDX ID
     * @returns {Array<string>} Array of child build SPDX IDs
     */
    childBuilds: (spdxId) => indexes.buildStepIndex.get(spdxId) || [],

    /**
     * Gets parent/root builds for a build step
     * @param {string} spdxId - The build step's SPDX ID
     * @returns {Array<string>} Array of parent build SPDX IDs
     */
    parentBuilds: (spdxId) => indexes.parentBuildIndex.get(spdxId) || [],

    /**
     * Gets distribution artifacts for a package
     * @param {string} spdxId - The package's SPDX ID
     * @returns {Array<string>} Array of artifact SPDX IDs
     */
    distributionArtifacts: (spdxId) => indexes.distributionArtifactIndex.get(spdxId) || [],

    /**
     * Gets statically linked libraries for an element
     * @param {string} spdxId - The element's SPDX ID
     * @returns {Array<string>} Array of linked library SPDX IDs
     */
    staticLinks: (spdxId) => indexes.staticLinkIndex.get(spdxId) || [],

    /**
     * Gets targets configured by a config element
     * @param {string} spdxId - The config's SPDX ID
     * @returns {Array<string>} Array of target SPDX IDs
     */
    configuresTargets: (spdxId) => indexes.configuresIndex.get(spdxId) || [],

    /**
     * Gets configs that configure a target
     * @param {string} spdxId - The target's SPDX ID
     * @returns {Array<{configId: string, scope?: string, description?: string}>}
     */
    configuredBy: (spdxId) => indexes.configuredByIndex.get(spdxId) || [],

    /**
     * Gets outgoing relationships from an element
     * @param {string} spdxId - The element's SPDX ID
     * @returns {Array<Object>} Array of relationship objects
     */
    outgoingRels: (spdxId) => indexes.relFromIndex.get(spdxId) || [],

    /**
     * Gets incoming relationships to an element
     * @param {string} spdxId - The element's SPDX ID
     * @returns {Array<Object>} Array of relationship objects
     */
    incomingRels: (spdxId) => indexes.relToIndex.get(spdxId) || []
  };
}

/* ==========================================================================
   Statistics Functions
   Functions to compute statistics from parsed data
   ========================================================================== */

/**
 * Computes relationship type counts and percentages
 *
 * @param {Array<Object>} relationships - Array of relationship objects
 * @returns {Array<{type: string, count: number, pct: string, color: string}>}
 */
export function computeRelationshipTypeCounts(relationships) {
  const counts = {};

  relationships.forEach((rel) => {
    counts[rel.relationshipType] = (counts[rel.relationshipType] || 0) + 1;
  });

  const total = relationships.length;

  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([type, count]) => ({
      type,
      count,
      pct: total ? ((count / total) * 100).toFixed(1) : '0.0',
      // Single source of truth for edge colours (shared with the graph + detail
      // panel) so every surface agrees on a relationship type's colour.
      color: getRelationshipColor(type)
    }));
}
