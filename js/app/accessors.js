import {
  cleanName as formatSpdxName,
  cleanFileName as formatFileName,
  fileExt as getFileExtension,
  formatDate as formatDisplayDate,
  getRelationshipColor,
  getRelationshipGroupLabel,
  getRelationshipSortOrder,
  getRelationshipTargetDisplayName,
  getElementDisplayName,
  getDetailPromotedFields,
  getNodeType as resolveNodeType,
  getNodeTypeColor,
  getElementBadgeClass,
  parseCompileFlags as parseBuildConfigFlags,
  parseBuildParameters as parseBuildParameterGroups,
  getToolUsageCount,
  getExternalIdentifiers,
  getCdxProperties,
  isMeaningfulValue,
  normalizeUrl,
  copyToClipboard
} from '../utils.js';

/* ==========================================================================
   Element accessors + display helpers
   Thin lookups into the relationship indexes, name/date formatting, build
   parameter helpers, and the relationship-group data the detail panel renders.
   Most are one-liners exposing a util or index to the templates as this.*().
   ========================================================================== */

export const accessorsMixin = {
  cleanName(spdxId) {
    return formatSpdxName(spdxId);
  },
  cleanFileName(spdxId) {
    return formatFileName(spdxId, this.elementMap);
  },
  fileExt(name) {
    return getFileExtension(name);
  },
  formatDate(date) {
    return formatDisplayDate(date);
  },
  depsOf(spdxId) {
    return this.depIndex.get(spdxId) || [];
  },
  dependentsOf(spdxId) {
    return this.dependentIndex.get(spdxId) || [];
  },
  containedFiles(spdxId) {
    return this.containsIndex.get(spdxId) || [];
  },
  parentPackage(spdxId) {
    return this.parentIndex.get(spdxId) || null;
  },
  fileTools(spdxId) {
    return this.toolIndex.get(spdxId) || [];
  },
  buildInputs(spdxId) {
    return this.buildInputIndex.get(spdxId) || [];
  },
  buildOutputs(spdxId) {
    return this.buildOutputIndex.get(spdxId) || [];
  },
  producedByBuilds(spdxId) {
    return this.producedByBuildIndex.get(spdxId) || [];
  },
  consumedByBuilds(spdxId) {
    return this.consumedByBuildIndex.get(spdxId) || [];
  },
  childBuilds(spdxId) {
    return this.buildStepIndex.get(spdxId) || [];
  },
  parentBuilds(spdxId) {
    return this.parentBuildIndex.get(spdxId) || [];
  },
  distributionArtifacts(spdxId) {
    return this.distributionArtifactIndex.get(spdxId) || [];
  },
  distributedBy(spdxId) {
    return this.distributedByIndex.get(spdxId) || [];
  },
  staticLinks(spdxId) {
    return this.staticLinkIndex.get(spdxId) || [];
  },
  configuresTargets(spdxId) {
    return this.configuresIndex.get(spdxId) || [];
  },
  configuredBy(spdxId) {
    return this.configuredByIndex.get(spdxId) || [];
  },
  outgoingRels(spdxId) {
    return this.relFromIndex.get(spdxId) || [];
  },
  incomingRels(spdxId) {
    return this.relToIndex.get(spdxId) || [];
  },

  buildSortName(build) {
    return (
      this.buildOutputs(build.spdxId)
        .map((id) => this.relTargetDisplayName(id))
        .join(' ') ||
      build.build_buildId ||
      build.spdxId ||
      ''
    );
  },

  buildDisplayName(build) {
    const outputs = this.buildOutputs(build.spdxId);
    if (outputs.length) {
      return outputs.map((id) => this.relTargetDisplayName(id)).join(', ');
    }
    return build.name || build.build_buildId || build.spdxId || 'Build';
  },

  formatCount(count) {
    return new Intl.NumberFormat().format(count || 0);
  },

  getBuildConfigFor(targetSpdxId) {
    const configs = this.configuredBy(targetSpdxId);
    if (!configs.length) return null;
    return this.elementMap.get(configs[0].configId);
  },

  parseCompileFlags(config) {
    return parseBuildConfigFlags(config);
  },
  buildParameters(build) {
    return parseBuildParameterGroups(build);
  },
  buildParameterCount(build) {
    return this.buildParameters(build).reduce((count, group) => count + group.entries.length, 0);
  },
  buildParameterPreview(build) {
    return this.buildParameters(build)
      .flatMap((group) => group.entries)
      .slice(0, 3);
  },
  parameterTokenId(token) {
    if (typeof token === 'string') return token;
    return token?.renderKey || token?.id || this.parameterTokenText(token);
  },
  parameterTokenText(token) {
    if (typeof token === 'string') return token;
    return token?.display ?? token?.text ?? token?.value ?? '';
  },
  parameterTokenKind(token) {
    if (typeof token === 'string') return 'Value';
    return token?.kind || 'Value';
  },
  parameterTokenClass(token) {
    if (typeof token === 'string') return 'param-token param-token-value';
    return token?.className || 'param-token param-token-value';
  },
  toolUsageCount(spdxId) {
    return getToolUsageCount(spdxId, this.relationships);
  },
  externalIdentifiers(element) {
    return getExternalIdentifiers(element);
  },
  cdxProperties(element) {
    return getCdxProperties(element);
  },
  isMeaningful(value) {
    return isMeaningfulValue(value);
  },
  downloadUrl(value) {
    return normalizeUrl(value);
  },
  relColor(type) {
    return getRelationshipColor(type);
  },
  relGroupLabel(relType, direction) {
    return getRelationshipGroupLabel(relType, direction);
  },

  // Grouped relationship data for the detail panel. Parameterized on the
  // element so both the graph detail panel (this.detailElement) and the
  // expanded package card (its pkg) render the same grouped relationships.
  detailRelGroupsFor(element) {
    if (!element) return [];
    const id = element.spdxId;
    const groups = new Map(); // key → { label, color, items:[] }

    // Vulnerability associations are surfaced in the dedicated security
    // section, not the generic relationship list (a single package can carry
    // thousands of them).
    const skip = (rel) => rel.relationshipType === 'hasAssociatedVulnerability';

    // Outgoing: this element → targets
    (this.relFromIndex.get(id) || []).forEach((rel) => {
      if (skip(rel)) return;
      const key = rel.relationshipType + ':out';
      if (!groups.has(key)) {
        groups.set(key, {
          key,
          label: this.relGroupLabel(rel.relationshipType, 'out'),
          color: this.relColor(rel.relationshipType),
          sortOrder: this.relSortOrder(rel.relationshipType, 'out'),
          items: []
        });
      }
      const targets = Array.isArray(rel.to) ? rel.to : [rel.to];
      targets.forEach((t) => {
        // Avoid duplicate entries
        if (!groups.get(key).items.find((i) => i.id === t)) {
          groups.get(key).items.push({
            id: t,
            displayName: this.relTargetDisplayName(t),
            direction: 'out',
            // LifecycleScopedRelationship scope (build / runtime / test / …)
            scope: rel.scope || ''
          });
        }
      });
    });

    // Incoming: sources → this element
    (this.relToIndex.get(id) || []).forEach((rel) => {
      if (skip(rel)) return;
      const key = rel.relationshipType + ':in';
      if (!groups.has(key)) {
        groups.set(key, {
          key,
          label: this.relGroupLabel(rel.relationshipType, 'in'),
          color: this.relColor(rel.relationshipType),
          sortOrder: this.relSortOrder(rel.relationshipType, 'in'),
          items: []
        });
      }
      if (!groups.get(key).items.find((i) => i.id === rel.from)) {
        groups.get(key).items.push({
          id: rel.from,
          displayName: this.relTargetDisplayName(rel.from),
          direction: 'in',
          scope: rel.scope || ''
        });
      }
    });

    return [...groups.values()].sort((a, b) => a.sortOrder - b.sortOrder);
  },

  // Grouped relationships for the currently graph-selected element.
  get detailRelGroups() {
    return this.detailRelGroupsFor(this.detailElement);
  },

  // Sort order for relationship groups (most relevant first)
  relSortOrder(type, dir) {
    return getRelationshipSortOrder(type, dir);
  },
  relTargetDisplayName(spdxId) {
    return getRelationshipTargetDisplayName(spdxId, this.elementMap);
  },
  elementDisplayName(element) {
    return getElementDisplayName(element, this.elementMap);
  },
  detailPromotedFieldsFor(element) {
    return getDetailPromotedFields(element, this.elementMap);
  },
  get detailPromotedFields() {
    return this.detailPromotedFieldsFor(this.detailElement);
  },
  elementBadgeClass(type) {
    return getElementBadgeClass(type);
  },
  getNodeType(item) {
    return resolveNodeType(item);
  },
  nodeTypeColor(type) {
    return getNodeTypeColor(type);
  },

  placeholderElement(spdxId) {
    return {
      type: 'ExternalReference',
      spdxId,
      name: this.cleanName(spdxId),
      placeholder: true
    };
  },

  copyHash(h) {
    copyToClipboard(h).then(() => {
      this.toastMsg = 'Copied to clipboard';
      setTimeout(() => (this.toastMsg = ''), 2000);
    });
  }
};
