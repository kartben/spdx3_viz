/**
 * SPDX 3.0 SBOM Visualizer - Data Parser
 *
 * Handles parsing of SPDX JSON-LD data, building element maps,
 * and creating relationship indexes for efficient lookups.
 *
 * @module parser
 */

import { COLORS, ELEMENT_TYPES, RELATIONSHIP_TYPES } from './config.js';

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
 * @property {Object|null} agentInfo - Agent information element
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

  /** @type {Array<string>} */
  const generatedArtifacts = [];

  /** @type {Object|null} */
  let buildInfo = null;

  /** @type {Object|null} */
  let agentInfo = null;

  // Document metadata
  let docName = '';
  let docNamespace = '';
  let specVersion = '';
  let createdDate = '';
  let dataLicenseLabel = '';
  const profileConformance = [];

  // Track seen IDs to deduplicate
  const seen = new Set();

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

      case ELEMENT_TYPES.AGENT:
        agentInfo = agentInfo || item;
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

        if (!createdDate) createdDate = item.creationInfo?.created || '';
        if (!specVersion) specVersion = item.creationInfo?.specVersion || '';
        if (!dataLicenseLabel) {
          dataLicenseLabel = item.dataLicense ? item.dataLicense.split('/').pop() : '';
        }
        break;
      }
    }
  });

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
    distributedByIndex
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

  const colors = {
    [RELATIONSHIP_TYPES.DEPENDS_ON]: COLORS.package,
    [RELATIONSHIP_TYPES.HAS_CONCLUDED_LICENSE]: COLORS.license,
    [RELATIONSHIP_TYPES.HAS_DECLARED_LICENSE]: COLORS.license,
    [RELATIONSHIP_TYPES.USES_TOOL]: COLORS.tool,
    [RELATIONSHIP_TYPES.HAS_STATIC_LINK]: COLORS.staticLink,
    [RELATIONSHIP_TYPES.GENERATES]: COLORS.build,
    [RELATIONSHIP_TYPES.HAS_INPUT]: COLORS.buildInput,
    [RELATIONSHIP_TYPES.HAS_OUTPUT]: COLORS.buildOutput,
    [RELATIONSHIP_TYPES.HAS_DISTRIBUTION_ARTIFACT]: COLORS.distribution,
    [RELATIONSHIP_TYPES.ANCESTOR_OF]: COLORS.buildLineage,
    [RELATIONSHIP_TYPES.CONTAINS]: COLORS.file,
    [RELATIONSHIP_TYPES.CONFIGURES]: COLORS.config
  };

  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([type, count]) => ({
      type,
      count,
      pct: total ? ((count / total) * 100).toFixed(1) : '0.0',
      color: colors[type] || COLORS.default
    }));
}

/**
 * Finds the best default tree root (package with most dependencies)
 *
 * @param {Array<Object>} packages - Array of package objects
 * @param {Map<string, Array>} depIndex - Dependency index
 * @returns {string} SPDX ID of the best root package
 */
export function findBestTreeRoot(packages, depIndex) {
  if (!packages.length) return '';

  const sorted = [...packages].sort(
    (a, b) => (depIndex.get(b.spdxId)?.length || 0) - (depIndex.get(a.spdxId)?.length || 0)
  );

  return sorted[0].spdxId;
}
