/**
 * Relationship helpers: edge colours, group labels, sort order, and the
 * display names / promoted fields shown for relationship endpoints.
 *
 * @module lib/relationships
 */
import {
  COLORS,
  DETAIL_PROMOTED_FIELDS,
  RELATIONSHIP_LABELS,
  RELATIONSHIP_SORT_ORDER
} from '../config.js';
import { cleanName } from './format.js';
import { displayLicenseExpression, renderLicenseExpression } from './licenses.js';
import { getVulnerabilityId } from './security.js';

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
    hasDynamicLink: COLORS.dynamicLink,
    hasOptionalComponent: COLORS.optionalComponent,
    hasVariant: COLORS.variant,
    runsOn: COLORS.hardware,
    implementedBy: COLORS.requirement,
    verifiedBy: COLORS.requirement,
    hasRequirement: COLORS.requirement,
    hasEvidence: COLORS.requirement,
    assumes: COLORS.requirement,
    conformsTo: COLORS.requirement,
    evaluationBasedOn: COLORS.requirement,
    configures: COLORS.config,
    hasConcludedLicense: COLORS.license,
    hasDeclaredLicense: COLORS.license,
    trainedOn: COLORS.ai,
    testedOn: COLORS.dataset,
    fixedIn: COLORS.vexFixed,
    doesNotAffect: COLORS.vexNotAffected,
    affects: COLORS.vexAffected,
    underInvestigation: COLORS.vexUnderInvestigation
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

  // Prefer a resolved element's own name/expression before the raw-URL fallback
  // below, since some producers use full http(s) URLs as spdxIds.
  const element = elementMap.get(spdxId);
  if (element?.simplelicensing_licenseExpression) {
    return displayLicenseExpression(element, elementMap);
  }
  const licenseExpr = renderLicenseExpression(element, elementMap);
  if (licenseExpr) return licenseExpr;
  if (element?.type === 'security_Vulnerability') return getVulnerabilityId(element);
  if (element?.name) return element.name;

  // Unresolved external http(s) reference: show the raw URL.
  if (spdxId.startsWith('http')) return spdxId;
  return cleanName(spdxId);
}

/**
 * Human-readable title for an element in the detail panel header
 *
 * @param {Object} element - The SPDX element
 * @param {Map} [elementMap] - Map of SPDX IDs to elements (resolves custom license ids)
 * @returns {string} Display title
 */
export function getElementDisplayName(element, elementMap) {
  if (!element) return '';
  if (element.simplelicensing_licenseExpression) {
    return displayLicenseExpression(element, elementMap);
  }
  const licenseExpr = renderLicenseExpression(element, elementMap);
  if (licenseExpr) return licenseExpr;
  if (element.type === 'security_Vulnerability') return getVulnerabilityId(element);
  if (element.name) return element.name;
  return cleanName(element.spdxId);
}

/**
 * Promoted fields for the detail panel (see DETAIL_PROMOTED_FIELDS in config)
 *
 * @param {Object} element - The SPDX element
 * @param {Map} [elementMap] - Map of SPDX IDs to elements (resolves custom license ids)
 * @returns {Array<{prop: string, label: string, value: string, variant: string}>}
 */
export function getDetailPromotedFields(element, elementMap) {
  if (!element) return [];

  return DETAIL_PROMOTED_FIELDS.flatMap((spec) => {
    const value = element[spec.prop];
    if (value == null || value === '') return [];
    if (spec.types && !spec.types.includes(element.type)) return [];
    return [
      {
        prop: spec.prop,
        label: spec.label,
        value:
          spec.prop === 'simplelicensing_licenseExpression'
            ? displayLicenseExpression(element, elementMap)
            : String(value),
        variant: spec.variant || 'badge'
      }
    ];
  });
}
