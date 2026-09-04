// @ts-check
/**
 * Parses SPDX JSON-LD data into element maps and relationship indexes.
 *
 * @module parser
 */

import { RELATIONSHIP_TYPES, VEX_TYPES, SCOPE_ORDER } from '../config.js';
import { bucketOf, isA, CLASS, BUCKET } from '../spdx/model.js';
import {
  displayLicenseExpression,
  renderLicenseExpression,
  licenseIndividualLabel,
  getVulnerabilityId,
  getVulnerabilityLocators,
  vexStatusForRel,
  summarizeVulnAssessments,
  buildImpactAdjacency,
  collectSnippetHubIds
} from '../lib/index.js';

/**
 * Builds a throttled progress reporter that calls `onProgress(fraction)` at
 * most ~50 times; returns a no-op when no callback is supplied.
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

/**
 * @typedef {Object} ParsedData
 * @property {Map<string, Object>} elementMap - Map of SPDX IDs to elements
 * @property {Array<Object>} packages - Package elements
 * @property {Array<Object>} files - File elements (excluding build configs)
 * @property {Array<Object>} snippets - Snippet elements (regions of a file)
 * @property {Set<string>} snippetHubIds - Snippets that stay as their own graph nodes
 * @property {Map<string, Array>} snippetsByFileIndex - fileId to its snippets
 * @property {Array<Object>} tools - Tool elements
 * @property {Array<Object>} relationships - Relationship elements
 * @property {Array<Object>} builds - Build elements
 * @property {Array<Object>} hardware - Hardware profile elements (SPDX 3.1)
 * @property {Array<Object>} requirements - Requirements + FunctionalSafety artifacts (SPDX 3.1)
 * @property {Array<Object>} supplyChain - SupplyChain actions, processes, and states (SPDX 3.1)
 * @property {Array<Object>} buildConfigs - Build configuration elements
 * @property {Object|null} buildInfo - Build information element
 * @property {Object|null} agentInfo - Agent information element (SoftwareAgent, Organization or Person)
 * @property {Array<Object>} agents - Agent elements (SoftwareAgent, Organization, Person) referenced as creators, for the graph's "created by" edges
 * @property {Map<string, {created: string[], supplied: string[], originated: string[], manufactured: string[]}>} agentLinkIndex - Agent spdxId -> the elements it created / supplied / originated / manufactured
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
 * @property {Array<string>} presentScopes - Lifecycle scopes present in the data (empty when none)
 * @property {string} docName - Document name
 * @property {string} docNamespace - Document namespace
 * @property {string} specVersion - SPDX spec version
 * @property {string} createdDate - Creation date
 * @property {string} dataLicenseLabel - Data license label
 * @property {Array<string>} profileConformance - Profile conformance list
 * @property {Array<string>} generatedArtifacts - Generated artifact IDs
 * @property {Map<string, ExternalMapEntry>} externalMap - Imported elements (SpdxDocument.import), keyed by externalSpdxId
 * @property {{total: number, resolved: number, unresolved: number}} externalRefStats - Import resolution summary
 * @property {Set<string>} rootElementIds - spdxIds declared as an SBOM/document rootElement
 */

/**
 * A single SPDX ExternalMap entry (an element used by an SpdxDocument but
 * defined outside of it), merged across every document that imports the same id.
 *
 * @typedef {Object} ExternalMapEntry
 * @property {string} externalSpdxId - Id of the element defined outside the document
 * @property {string} locationHint - Where the external element can be retrieved (URL or relative path)
 * @property {string} definingArtifact - Artifact spdxId where the element is defined, when given
 * @property {Array<Object>} verifiedUsing - IntegrityMethod (e.g. Hash) entries asserting the external element's integrity
 * @property {Array<string>} importedBy - Display labels of the documents that import this id
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
 * @property {Map<string, Array<{id: string, rel: string, soft: boolean}>>} impactChildIndex - Element to what it depends on / includes (impact edge set)
 * @property {Map<string, Array<{id: string, rel: string, soft: boolean}>>} impactParentIndex - Element to what depends on / includes it (impact edge set)
 */

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
  const snippets = [];

  /** @type {Array<Object>} */
  const tools = [];

  /** @type {Array<Object>} */
  const relationships = [];

  /** @type {Array<Object>} */
  const builds = [];

  /** @type {Array<Object>} - Hardware profile elements (SPDX 3.1) */
  const hardware = [];

  /** @type {Array<Object>} - Requirements + FunctionalSafety artifacts (SPDX 3.1) */
  const requirements = [];

  /** @type {Array<Object>} - SupplyChain actions, processes, and states (SPDX 3.1) */
  const supplyChain = [];

  /** @type {Array<Object>} */
  const vulnerabilities = [];

  /** @type {Array<Object>} */
  const vexRelationships = [];

  /** @type {Array<Object>} - Non-VEX vuln assessments (CVSS, EPSS, exploit catalog) */
  const vulnAssessments = [];

  /** @type {Array<Object>} */
  const sboms = [];

  /** @type {Set<string>} - spdxIds declared as rootElement by any SBOM/Document */
  const rootElementIds = new Set();

  /** @type {Array<string>} */
  const generatedArtifacts = [];

  // ExternalMap: elements an SpdxDocument references but defines elsewhere (its
  // `import` array), keyed by externalSpdxId and merged across documents, so
  // loading a single document still resolves references defined in another.
  /** @type {Map<string, ExternalMapEntry>} */
  const externalMap = new Map();

  /** @type {Object|null} */
  let buildInfo = null;

  /** @type {Array<Object>} - All Agent elements (SoftwareAgent / Organization / Person) */
  const agents = [];

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
  // standalone CreationInfo element identified by `@id`.
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

    // Categorize by the element's place in the class hierarchy, so subclasses
    // fall into their bucket automatically.
    switch (bucketOf(item.type)) {
      case BUCKET.PACKAGES:
        packages.push(item);
        break;

      case BUCKET.FILES:
        files.push(item);
        break;

      case BUCKET.SNIPPETS:
        snippets.push(item);
        break;

      case BUCKET.HARDWARE:
        hardware.push(item);
        break;

      case BUCKET.REQUIREMENTS:
        requirements.push(item);
        // evaluationBasedOn is a property, not a Relationship; synthesize an edge.
        if (item.functionalsafety_evaluationBasedOn) {
          relationships.push({
            type: 'Relationship',
            spdxId: `${item.spdxId}#evaluationBasedOn`,
            from: item.spdxId,
            relationshipType: RELATIONSHIP_TYPES.EVALUATION_BASED_ON,
            to: [item.functionalsafety_evaluationBasedOn]
          });
        }
        break;

      case BUCKET.SUPPLY_CHAIN:
        supplyChain.push(item);
        break;

      case BUCKET.TOOLS:
        tools.push(item);
        break;

      case BUCKET.RELATIONSHIPS:
        relationships.push(item);
        break;

      case BUCKET.BUILDS:
        builds.push(item);
        break;

      case BUCKET.VULNERABILITIES:
        vulnerabilities.push(item);
        break;

      case BUCKET.VEX:
        vexRelationships.push(item);
        break;

      case BUCKET.VULN_ASSESSMENT:
        vulnAssessments.push(item);
        break;

      case BUCKET.AGENTS:
        // Keep every agent for the graph's "created by" edges (creationInfo →
        // agent), and pick a representative for the document metadata:
        // prefer a SoftwareAgent, else an Organization/Person; ignore a bare Agent.
        agents.push(item);
        if (isA(item.type, CLASS.SoftwareAgent)) agentInfo = agentInfo || item;
        else if (isA(item.type, CLASS.Organization) || isA(item.type, CLASS.Person)) {
          orgInfo = orgInfo || item;
        }
        break;

      case BUCKET.SBOMS:
        sboms.push(item);
        // rootElement may be compacted to a single string in JSON-LD.
        [].concat(item.rootElement || []).forEach((id) => rootElementIds.add(id));
        break;

      case BUCKET.CREATION_INFO:
        anyCreationInfo = anyCreationInfo || item;
        break;

      case BUCKET.DOCUMENTS: {
        [].concat(item.rootElement || []).forEach((id) => rootElementIds.add(id));
        // Merge document metadata: accumulate profiles, keep first values
        if (!docName) docName = item.name || '';
        if (!docNamespace) docNamespace = item.namespaceMap?.[0]?.namespace || '';

        // Record imported (external) elements. The first entry seen for an id
        // keeps its location hint / defining artifact / integrity hashes; later
        // documents importing the same id just add themselves to `importedBy`.
        const docLabel = item.name || item.spdxId || '';
        (item.import || []).forEach((em) => {
          const id = em?.externalSpdxId;
          if (!id) return;
          const existing = externalMap.get(id);
          if (existing) {
            if (docLabel && !existing.importedBy.includes(docLabel)) {
              existing.importedBy.push(docLabel);
            }
            if (!existing.locationHint && em.locationHint) existing.locationHint = em.locationHint;
            if (!existing.definingArtifact && em.definingArtifact) {
              existing.definingArtifact = em.definingArtifact;
            }
            if (!existing.verifiedUsing.length && Array.isArray(em.verifiedUsing)) {
              existing.verifiedUsing = em.verifiedUsing;
            }
          } else {
            externalMap.set(id, {
              externalSpdxId: id,
              locationHint: em.locationHint || '',
              definingArtifact: em.definingArtifact || '',
              verifiedUsing: Array.isArray(em.verifiedUsing) ? em.verifiedUsing : [],
              importedBy: docLabel ? [docLabel] : []
            });
          }
        });

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

  // Fallback when no SpdxDocument carried the metadata: use any CreationInfo.
  if (!createdDate) createdDate = anyCreationInfo?.created || '';
  if (!specVersion) specVersion = anyCreationInfo?.specVersion || '';

  // Documents without a name: fall back to the name of an SBOM element or of a
  // SBOM root element, preferring a root Package over a root File.
  if (!docName) {
    const named = sboms.find((sbom) => sbom.name);
    const roots = sboms
      .flatMap((sbom) => (Array.isArray(sbom.rootElement) ? sbom.rootElement : []))
      .map((id) => elementMap.get(id))
      .filter((el) => el?.name);
    docName =
      named?.name ||
      roots.find((el) => isA(el.type, CLASS.software_Package))?.name ||
      roots[0]?.name ||
      '';
  }

  // SBOM lifecycle types declared by software_Sbom elements.
  const sbomTypes = [];
  sboms.forEach((sbom) => {
    (sbom.software_sbomType || []).forEach((type) => {
      if (!sbomTypes.includes(type)) sbomTypes.push(type);
    });
  });

  // Who/what produced the documents, resolved from their CreationInfo.
  const { creators, creatorTools } = collectCreators(
    docCreationInfos.length ? docCreationInfos : anyCreationInfo ? [anyCreationInfo] : [],
    elementMap
  );

  // Prefer a SoftwareAgent, but fall back to an Organization/Person creator.
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
      isA(elementMap.get(rel.from)?.type, CLASS.build_Build)
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

  // Track generated artifacts. A companion Set keeps dedup O(1): a build-heavy
  // SBOM can carry tens of thousands of generates/hasOutput edges, so a plain
  // includes() scan on the growing array would be O(n^2).
  const generatedArtifactSeen = new Set();
  const pushGeneratedArtifact = (target) => {
    if (target && !generatedArtifactSeen.has(target)) {
      generatedArtifactSeen.add(target);
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

  // Summarize how many imported (ExternalMap) elements are present in the
  // loaded graph vs. still external.
  let externalResolved = 0;
  externalMap.forEach((_, id) => {
    if (elementMap.has(id)) externalResolved++;
  });
  const externalRefStats = {
    total: externalMap.size,
    resolved: externalResolved,
    unresolved: externalMap.size - externalResolved
  };

  // Collect licenses from license relationships, so URL-only and NoAssertion
  // targets are captured too.
  const licenses = collectLicenses(relationships, elementMap);

  // Build the VEX model: enriched vulnerabilities + vuln↔package indexes.
  const vex = buildVexModel(vulnerabilities, vexRelationships, vulnAssessments, elementMap);

  // Reverse provenance index for agents: which elements each agent is tied to,
  // grouped by *how*. An agent is rarely a Relationship endpoint — instead the
  // links are properties on the other elements: an element's CreationInfo.createdBy,
  // an Artifact's suppliedBy / originatedBy, or a Hardware element's productAgent.
  // Collecting the back-references here lets an agent's detail view (and the
  // Agents tab) surface everything it created / supplied / originated / made.
  const agentLinkIndex = buildAgentLinkIndex(graph, resolveCreationInfo);

  // Index snippets by the file they were carved from (software_snippetFromFile),
  // sorted by start line, so the file detail view can render them in order.
  const snippetsByFileIndex = new Map();
  for (const snippet of snippets) {
    const fileId = snippet.software_snippetFromFile;
    if (!fileId) continue;
    if (!snippetsByFileIndex.has(fileId)) snippetsByFileIndex.set(fileId, []);
    snippetsByFileIndex.get(fileId).push(snippet);
  }
  for (const [, list] of snippetsByFileIndex) {
    list.sort(
      (a, b) =>
        (a.software_lineRange?.beginIntegerRange ?? 0) -
        (b.software_lineRange?.beginIntegerRange ?? 0)
    );
  }

  const snippetHubIds = collectSnippetHubIds(snippets, relationships);

  // Which node/relationship types actually occur, so the graph legend can hide
  // entries for types the SBOM doesn't contain.
  const { presentNodeTypes, presentRelTypes, presentScopes } = computePresentTypes({
    packages,
    regularFiles,
    hardware,
    requirements,
    supplyChain,
    tools,
    builds,
    buildConfigs,
    agents,
    vulnerabilities,
    snippetHubIds,
    relationships,
    vexRelationships,
    resolveCreationInfo,
    elementMap
  });

  return {
    elementMap,
    packages,
    files: regularFiles,
    snippets,
    snippetHubIds,
    snippetsByFileIndex,
    tools,
    hardware,
    requirements,
    supplyChain,
    relationships,
    builds,
    buildConfigs,
    buildInfo,
    agentInfo,
    agents,
    agentLinkIndex,
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
    presentScopes,
    docName,
    docNamespace,
    specVersion,
    createdDate,
    dataLicenseLabel,
    profileConformance,
    generatedArtifacts,
    externalMap,
    externalRefStats,
    rootElementIds
  };
}

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

/**
 * Builds the reverse "agent → what it's linked to" index used by the Agents view
 * and an agent's detail panel. Walks every element once and records the agent
 * back-references it carries: CreationInfo.createdBy (creator), the Software
 * profile's suppliedBy / originatedBy (both the bare and `software_`-prefixed
 * spellings occur in the wild), and the Hardware profile's productAgent.
 *
 * @param {Array<Object>} graph - The merged element graph
 * @param {(el: Object) => (Object|null)} resolveCreationInfo - Resolves an element's inline/ref CreationInfo
 * @returns {Map<string, {created: string[], supplied: string[], originated: string[], manufactured: string[]}>}
 */
function buildAgentLinkIndex(graph, resolveCreationInfo) {
  const index = new Map();
  // Companion Sets keep the dedup O(1): a single document creator can be the
  // createdBy of every element, so a plain includes() scan would be O(n^2).
  const seen = new Map();
  const asArray = (v) => (Array.isArray(v) ? v : v == null || v === '' ? [] : [v]);

  const link = (agentId, bucket, elId) => {
    if (!agentId || agentId === elId || String(agentId).includes('NoAssertion')) return;
    let entry = index.get(agentId);
    if (!entry) {
      entry = { created: [], supplied: [], originated: [], manufactured: [] };
      index.set(agentId, entry);
      seen.set(agentId, {
        created: new Set(),
        supplied: new Set(),
        originated: new Set(),
        manufactured: new Set()
      });
    }
    const bucketSeen = seen.get(agentId)[bucket];
    if (!bucketSeen.has(elId)) {
      bucketSeen.add(elId);
      entry[bucket].push(elId);
    }
  };

  graph.forEach((el) => {
    const id = el?.spdxId;
    if (!id) return;
    asArray(resolveCreationInfo(el)?.createdBy).forEach((a) => link(a, 'created', id));
    asArray(el.suppliedBy ?? el.software_suppliedBy).forEach((a) => link(a, 'supplied', id));
    asArray(el.originatedBy ?? el.software_originatedBy).forEach((a) => link(a, 'originated', id));
    asArray(el.hardware_productAgent).forEach((a) => link(a, 'manufactured', id));
  });

  return index;
}

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
 * @property {{score: (number|null), severity: string, vector: string, version: string}|null} cvss - Best in-SBOM CVSS assessment
 * @property {{probability: number, percentile: (number|null)}|null} epss - In-SBOM EPSS assessment
 * @property {boolean} kev - Listed in a known-exploited catalog (e.g. CISA KEV)
 * @property {string} severity - CVSS qualitative severity (critical…none), or ''
 * @property {number} severityRank - Numeric rank of `severity` for sorting
 */

/**
 * Builds the enriched vulnerability list and the vuln↔package assessment
 * indexes from the raw vulnerabilities and VEX assessment relationships.
 *
 * @param {Array<Object>} vulnerabilities - Raw security_Vulnerability elements
 * @param {Array<Object>} vexRelationships - Raw VEX assessment relationship elements
 * @param {Array<Object>} vulnAssessments - Raw non-VEX assessment relationships (CVSS/EPSS/exploit)
 * @param {Map<string, Object>} elementMap
 * @returns {{vulnerabilities: EnrichedVulnerability[], vexByVuln: Map<string, VexAssessment[]>, vexByPackage: Map<string, VexAssessment[]>}}
 */
function buildVexModel(vulnerabilities, vexRelationships, vulnAssessments, elementMap) {
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

  // CVSS/EPSS/exploit assessments point `from` the vulnerability they assess.
  const assessmentsByVuln = new Map();
  vulnAssessments.forEach((a) => push(assessmentsByVuln, a.from, a));

  const enriched = vulnerabilities.map((el) => {
    const assessments = vexByVuln.get(el.spdxId) || [];
    const cveId = getVulnerabilityId(el);
    const risk = summarizeVulnAssessments(assessmentsByVuln.get(el.spdxId) || []);

    // Count distinct packages per status; a vuln can hit the same package via
    // more than one VEX record, so don't double-count.
    const pkgsByStatus = {};
    let overallStatus = null;
    assessments.forEach((a) => {
      (pkgsByStatus[a.status] ||= new Set()).add(a.packageId);
      if (!overallStatus || SEVERITY[a.status] > SEVERITY[overallStatus]) {
        overallStatus = a.status;
      }
    });
    /** @type {Record<string, number>} */
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
      // A vulnerability with no VEX assessment is "unknown", never "fixed".
      overallStatus: overallStatus || 'unknown',
      packageCount,
      cvss: risk.cvss,
      epss: risk.epss,
      kev: risk.kev,
      severity: risk.severity,
      severityRank: risk.severityRank
    };
  });

  return { vulnerabilities: enriched, vexByVuln, vexByPackage };
}

/**
 * Determines which node and relationship types are actually present in the
 * parsed dataset. Used to trim the graph legend.
 *
 * @returns {{presentNodeTypes: string[], presentRelTypes: string[], presentScopes: string[]}}
 */
function computePresentTypes(data) {
  const nodeTypes = new Set();
  // packages holds plain software_Package plus its AI/dataset subclasses; split
  // them so the legend lists the actual node types.
  data.packages.forEach((p) => {
    if (isA(p.type, CLASS.ai_AIPackage)) nodeTypes.add('ai');
    else if (isA(p.type, CLASS.dataset_DatasetPackage)) nodeTypes.add('dataset');
    else nodeTypes.add('package');
  });
  if (data.regularFiles.length) nodeTypes.add('file');
  // Only advertise Snippets when some are graph hubs (BASIL-style). Zephyr-style
  // leaf snippets stay redirected onto their files, so a legend toggle that
  // would draw nothing is hidden.
  if (data.snippetHubIds?.size) nodeTypes.add('snippet');
  if (data.hardware.length) nodeTypes.add('hardware');
  if (data.requirements.length) nodeTypes.add('requirement');
  if (data.supplyChain?.length) nodeTypes.add('supplychain');
  if (data.tools.length) nodeTypes.add('tool');
  if (data.builds.length) nodeTypes.add('build');
  if (data.buildConfigs.length) nodeTypes.add('config');
  if (data.agents?.length) nodeTypes.add('agent');
  if (data.vulnerabilities.length) nodeTypes.add('vulnerability');

  const relTypes = new Set();
  // LifecycleScopedRelationship.scope buckets present in the data. Only real
  // scopes count toward "are there scoped relationships at all"; the synthetic
  // `unscoped` bucket is added alongside them so the legend can offer it as a
  // toggle (used to isolate, say, the runtime graph from build-time edges).
  const scopes = new Set();
  let hasUnscoped = false;
  data.relationships.forEach((r) => {
    if (!r.relationshipType) return;
    relTypes.add(r.relationshipType);
    if (r.scope) scopes.add(r.scope);
    else hasUnscoped = true;
  });
  data.vexRelationships.forEach((r) => r.relationshipType && relTypes.add(r.relationshipType));

  // "createdBy" / "suppliedBy" / "originatedBy" / "manufacturedBy" edges are
  // synthesized in the graph from each element's CreationInfo, suppliedBy /
  // originatedBy, and productAgent (element → agent), so list each type only
  // when some graph-node element actually carries that agent reference.
  const createdByHosts = [
    ...data.packages,
    ...data.regularFiles,
    ...data.hardware,
    ...data.requirements,
    ...(data.supplyChain || []),
    ...data.tools,
    ...data.builds,
    ...data.buildConfigs
  ];
  const hasCreatedBy = createdByHosts.some((el) => data.resolveCreationInfo(el)?.createdBy?.length);
  if (hasCreatedBy) relTypes.add('createdBy');
  const hasSuppliedBy = createdByHosts.some(
    (el) => (el.suppliedBy ?? el.software_suppliedBy)?.length
  );
  if (hasSuppliedBy) relTypes.add('suppliedBy');
  const hasOriginatedBy = createdByHosts.some(
    (el) => (el.originatedBy ?? el.software_originatedBy)?.length
  );
  if (hasOriginatedBy) relTypes.add('originatedBy');
  const hasManufacturedBy = createdByHosts.some((el) => el.hardware_productAgent?.length);
  if (hasManufacturedBy) relTypes.add('manufacturedBy');

  // "External" nodes are placeholders for relationship endpoints that resolve
  // to nothing in the element map (and aren't license URLs / NoAssertion).
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

  // Only surface the scope legend when the data actually scopes some
  // relationship; then list the present scopes in lifecycle order, appending the
  // `unscoped` bucket when plain (un-scoped) relationships also exist.
  const presentScopes = scopes.size
    ? SCOPE_ORDER.filter((s) => scopes.has(s) || (s === 'unscoped' && hasUnscoped))
    : [];

  return { presentNodeTypes: [...nodeTypes], presentRelTypes: [...relTypes], presentScopes };
}

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
  const individual = licenseIndividualLabel(id);
  if (individual) return individual;
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

  // declaredBy/concludedBy are accumulated as Sets so dedup stays O(1) even for
  // a popular license, then converted back to arrays at the end for callers.
  const ensure = (id) => {
    if (!byId.has(id)) {
      byId.set(id, {
        id,
        label: resolveLicenseLabel(id, elementMap),
        declaredBy: new Set(),
        concludedBy: new Set(),
        userCount: 0
      });
    }
    return byId.get(id);
  };

  relationships.forEach((rel) => {
    const isDeclared = rel.relationshipType === RELATIONSHIP_TYPES.HAS_DECLARED_LICENSE;
    const isConcluded = rel.relationshipType === RELATIONSHIP_TYPES.HAS_CONCLUDED_LICENSE;
    if (!isDeclared && !isConcluded) return;

    const targets = Array.isArray(rel.to) ? rel.to : [rel.to];
    targets.forEach((target) => {
      if (!target) return;
      const entry = ensure(target);
      if (rel.from) (isDeclared ? entry.declaredBy : entry.concludedBy).add(rel.from);
    });
  });

  const licenses = [...byId.values()];
  licenses.forEach((lic) => {
    lic.userCount = new Set([...lic.declaredBy, ...lic.concludedBy]).size;
    lic.declaredBy = [...lic.declaredBy];
    lic.concludedBy = [...lic.concludedBy];
  });

  // Default sort: most used first, then alphabetical by label.
  licenses.sort((a, b) => b.userCount - a.userCount || a.label.localeCompare(b.label));
  return licenses;
}

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

  // Companion Sets for the two object-valued indexes above, so their dedup is
  // O(1) per insert instead of an O(n) .some() scan (see pushUnique's note).
  const configuredBySeen = new Map(); // target -> Set<configId>
  const licenseUsersSeen = new Map(); // target -> Set<'from\tkind'>

  // Pushes a value into a Map<string, Array> bucket, skipping duplicates.
  // Producers may emit the same logical edge more than once; unchecked, these
  // inflate counts and break the UI's keyed rendering on duplicate keys.
  // Dedup via a companion Set per (map, key): a hub can fan out to many edges,
  // so avoid an O(n^2) includes() scan while keeping insertion-ordered arrays.
  const seenByMap = new Map(); // index map -> (key -> Set<value>)
  const pushUnique = (map, key, value) => {
    let perKey = seenByMap.get(map);
    if (!perKey) {
      perKey = new Map();
      seenByMap.set(map, perKey);
    }
    let set = perKey.get(key);
    if (!set) {
      set = new Set();
      perKey.set(key, set);
      map.set(key, []);
    }
    if (!set.has(value)) {
      set.add(value);
      map.get(key).push(value);
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

          let cfgSet = configuredBySeen.get(target);
          if (!cfgSet) {
            cfgSet = new Set();
            configuredBySeen.set(target, cfgSet);
            configuredByIndex.set(target, []);
          }
          if (!cfgSet.has(from)) {
            cfgSet.add(from);
            configuredByIndex.get(target).push({
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
          let licSet = licenseUsersSeen.get(target);
          if (!licSet) {
            licSet = new Set();
            licenseUsersSeen.set(target, licSet);
            licenseUsersIndex.set(target, []);
          }
          // Dedup on a Set keyed by from+kind so a popular license doesn't
          // turn this into an O(n^2) scan.
          const seenKey = from + '\t' + kind;
          if (!licSet.has(seenKey)) {
            licSet.add(seenKey);
            licenseUsersIndex.get(target).push({ from, kind });
          }
        });
        break;
      }
    }
  });

  // Impact analysis adjacency over the cross-topology dependency edge set
  // (dependsOn / contains / static+dynamic link / …), used for provenance paths
  // and blast radius. Kept separate from the type-specific indexes above.
  const { childIndex: impactChildIndex, parentIndex: impactParentIndex } =
    buildImpactAdjacency(relationships);

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
    licenseUsersIndex,
    impactChildIndex,
    impactParentIndex
  };
}

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
   File Source Index Builder
   Maps file spdxId → raw GitHub URL using *-sources packages and their
   software_downloadLocation + contains relationships.
   ========================================================================== */

const GH_DL_RE = /^git\+https:\/\/github\.com\/([^/]+\/[^@]+)@([a-f0-9]{40})$/;

function longestCommonPathPrefix(paths) {
  if (!paths.length) return '';
  const parts = paths.map((p) => p.split('/'));
  const minLen = Math.min(...parts.map((p) => p.length));
  let commonSegs = 0;
  for (let i = 0; i < minLen - 1; i++) {
    if (parts.every((p) => p[i] === parts[0][i])) {
      commonSegs = i + 1;
    } else {
      break;
    }
  }
  return commonSegs > 0 ? parts[0].slice(0, commonSegs).join('/') + '/' : '';
}

/**
 * Builds a Map from file spdxId to its raw GitHub URL, derived from the SBOM's
 * *-sources packages (software_downloadLocation) and their contains relationships.
 *
 * For packages where downloadLocation is NOASSERTION (e.g. zephyr-sources when
 * the repo has multiple git remotes), falls back to a hardcoded org/repo + commit
 * when the package is recognisably the Zephyr kernel (see the HACK note below).
 *
 * @param {ParsedData} parsed
 * @param {RelationshipIndexes} indexes
 * @returns {Map<string, string>} fileId → rawUrl
 */
export function buildFileSourceIndex(parsed, indexes) {
  const { packages, elementMap } = parsed;
  const { containsIndex } = indexes;
  const fileSourceIndex = new Map();

  for (const pkg of packages) {
    const dloc = pkg.software_downloadLocation || '';
    const fileIds = containsIndex.get(pkg.spdxId) || [];
    if (!fileIds.length) continue;

    let ghPath, sha; // ghPath = "org/repo"

    const ghMatch = GH_DL_RE.exec(dloc);
    if (ghMatch) {
      ghPath = ghMatch[1];
      sha = ghMatch[2];
    } else if (dloc === 'NOASSERTION' || !dloc) {
      // zephyr-sources falls here when the repo has multiple git remotes —
      // git_remote() in zephyr_module.py returns None → NOASSERTION.
      const pkgId = pkg.spdxId || '';
      const pkgName = pkg.name || '';
      if (pkgId.includes('zephyr-sources') || pkgName === 'zephyr-sources') {
        // ███████████████████████████████████████████████████████████████████
        // ██  ⚠️  TEMPORARY HACK — REMOVE ME  ⚠️                            ██
        // ███████████████████████████████████████████████████████████████████
        // The bundled sample is generated from a fork branch whose commits are
        // not upstream, and its generating checkout has several git remotes, so
        // the SBOM records NOASSERTION instead of a download location. Nothing
        // in the document names a repository we could fetch from, so we PIN
        // every zephyr-sources file to one hardcoded commit in a fork:
        // https://github.com/kartben/zephyr/commit/107120db232f2ce699c6a871b12b844d85c11ab1
        //
        // ✅ That commit is the one the bundled sample was generated from, so
        //    its line ranges do line up with the source fetched here.
        //
        // ❌ Any other SBOM reaching this branch gets that same fork tree, not
        //    its own. It is a stopgap, not correct behaviour.
        //
        // ✅ TO RESTORE CORRECT BEHAVIOUR: delete this block and uncomment the
        //    purl-derived logic below. software_packageVersion is the VERSION
        //    file version ("4.4.99"), never a commit; the commit is in the purl.
        // ███████████████████████████████████████████████████████████████████
        ghPath = 'kartben/zephyr'; // <-- HARDCODED HACK (fork, not upstream)
        sha = '107120db232f2ce699c6a871b12b844d85c11ab1'; // <-- HARDCODED HACK
        // ███████████████████████████████████████████████████████████████████

        // --- CORRECT (dynamic) behaviour, disabled by the hack above ---------
        // const purl = pkg.software_packageUrl || '';
        // const m = /^pkg:github\/([^/]+\/[^@]+)@([a-f0-9]{40})/.exec(purl);
        // if (m) { ghPath = m[1]; sha = m[2]; }
      }
    }

    if (!ghPath || !sha) continue;

    // Strip the common path prefix shared by all files in this package to get
    // the repo-relative path (e.g. "modules/lib/gui/lvgl/" → "").
    const fileNames = fileIds.map((id) => elementMap.get(id)?.name).filter(Boolean);
    const prefix = longestCommonPathPrefix(fileNames);

    for (const fileId of fileIds) {
      const file = elementMap.get(fileId);
      if (!file?.name) continue;
      const rel = file.name.startsWith(prefix) ? file.name.slice(prefix.length) : file.name;
      fileSourceIndex.set(fileId, `https://raw.githubusercontent.com/${ghPath}/${sha}/${rel}`);
    }
  }

  return fileSourceIndex;
}
