// @ts-check
/**
 * SPDX class-hierarchy helpers over the generated model, plus the element
 * categorization rules the parser uses. Keeps type knowledge in one place,
 * derived from the official SPDX model rather than hand-maintained lists.
 *
 * @module spdx/model
 */
import { CLASS_PARENT } from './hierarchy.js';

/** @typedef {import('./hierarchy.js').SpdxClass} SpdxClass */

/**
 * SPDX class names by their exact official spelling (`CLASS.software_Package`).
 * Typed so a bad name is a compile error, and Proxy-backed so an unchecked
 * caller with a bad name throws rather than silently never matching.
 *
 * @type {{ readonly [K in SpdxClass]: K }}
 */
export const CLASS = /** @type {any} */ (
  new Proxy(
    {},
    {
      get(_target, name) {
        if (typeof name !== 'string') return undefined;
        if (!Object.hasOwn(CLASS_PARENT, name)) {
          throw new Error(`Unknown SPDX class: "${name}" is not in the generated hierarchy`);
        }
        return name;
      }
    }
  )
);

/** The categories parseGraph sorts elements into. */
export const BUCKET = Object.freeze({
  PACKAGES: 'packages',
  FILES: 'files',
  HARDWARE: 'hardware',
  REQUIREMENTS: 'requirements',
  TOOLS: 'tools',
  RELATIONSHIPS: 'relationships',
  BUILDS: 'builds',
  VULNERABILITIES: 'vulnerabilities',
  VEX: 'vex',
  VULN_ASSESSMENT: 'vulnAssessment', // non-VEX assessments, not surfaced
  AGENTS: 'agents',
  SBOMS: 'sboms',
  DOCUMENTS: 'documents',
  CREATION_INFO: 'creationInfo'
});

/** @typedef {(typeof BUCKET)[keyof typeof BUCKET]} Bucket */

/**
 * Returns the ancestry chain [type, superclass, …] up to a root.
 *
 * @param {string} [type]
 * @returns {string[]}
 */
export function ancestors(type) {
  /** @type {string[]} */
  const chain = [];
  const seen = new Set();
  let t = type;
  while (t && !seen.has(t)) {
    chain.push(t);
    seen.add(t);
    t = CLASS_PARENT[t];
  }
  return chain;
}

/**
 * True when `type` is `base` or a subclass of it.
 *
 * @param {string|undefined} type
 * @param {SpdxClass} base
 * @returns {boolean}
 */
export function isA(type, base) {
  const seen = new Set();
  let t = type;
  while (t && !seen.has(t)) {
    if (t === base) return true;
    seen.add(t);
    t = CLASS_PARENT[t];
  }
  return false;
}

// Ordered most-specific first: the first rule whose class is in an element's
// ancestry wins (so VEX beats the generic Relationship base below).
/** @type {Array<[SpdxClass, Bucket]>} */
const BUCKET_RULES = [
  [CLASS.software_File, BUCKET.FILES],
  [CLASS.software_Package, BUCKET.PACKAGES], // incl. ai_AIPackage, dataset_DatasetPackage
  [CLASS.hardware_Hardware, BUCKET.HARDWARE],
  [CLASS.security_Vulnerability, BUCKET.VULNERABILITIES],
  [CLASS.security_VexVulnAssessmentRelationship, BUCKET.VEX], // before Relationship
  // Non-VEX vuln assessments (CVSS, EPSS, …) aren't surfaced; catch the base so
  // they don't fall into the generic Relationship bucket.
  [CLASS.security_VulnAssessmentRelationship, BUCKET.VULN_ASSESSMENT],
  [CLASS.build_Build, BUCKET.BUILDS],
  [CLASS.Tool, BUCKET.TOOLS],
  [CLASS.software_Sbom, BUCKET.SBOMS],
  [CLASS.SpdxDocument, BUCKET.DOCUMENTS],
  [CLASS.CreationInfo, BUCKET.CREATION_INFO],
  [CLASS.Agent, BUCKET.AGENTS], // SoftwareAgent / Organization / Person
  // Requirement plus its lifecycle artifacts (which are Elements, not
  // Requirements) read as one group.
  [CLASS.Requirement, BUCKET.REQUIREMENTS],
  [CLASS.functionalsafety_RequirementVerification, BUCKET.REQUIREMENTS],
  [CLASS.functionalsafety_EvaluationResult, BUCKET.REQUIREMENTS],
  [CLASS.functionalsafety_Assumption, BUCKET.REQUIREMENTS],
  [CLASS.Relationship, BUCKET.RELATIONSHIPS] // generic, after the specific buckets
];

/**
 * Categorizes an element type into a parser bucket, or null if uncategorized.
 *
 * @param {string} type
 * @returns {Bucket|null}
 */
export function bucketOf(type) {
  const chain = new Set(ancestors(type));
  for (const [base, bucket] of BUCKET_RULES) if (chain.has(base)) return bucket;
  return null;
}
