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
  formatByteSize,
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
  // The SPDX 3.0 ExternalMap entry for an element, when a loaded SpdxDocument
  // imports it (i.e. references it but defines it elsewhere). Returns the merged
  // entry {locationHint, definingArtifact, verifiedUsing, importedBy} or null.
  // Works for both unresolved placeholders and resolved cross-document elements.
  externalRefFor(element) {
    if (!element?.spdxId) return null;
    return this.externalMap?.get(element.spdxId) || null;
  },
  relColor(type) {
    return getRelationshipColor(type);
  },
  // CSS background for a graph edge-legend swatch, mirroring the line style the
  // edge is drawn with (solid / dotted / dashed / dash-dot) so the legend reads
  // the same as the graph.
  relEdgeSwatchStyle(filter) {
    const c = filter.color;
    switch (filter.lineStyle) {
      case 'dotted':
        return `background-image: repeating-linear-gradient(to right, ${c} 0 2px, transparent 2px 4px)`;
      case 'dashed':
        return `background-image: repeating-linear-gradient(to right, ${c} 0 5px, transparent 5px 8px)`;
      case 'dashdot':
        return `background-image: repeating-linear-gradient(to right, ${c} 0 5px, transparent 5px 7px, ${c} 7px 8px, transparent 8px 10px)`;
      default:
        return `background:${c}`;
    }
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

  // Flattened AI-profile / Dataset-profile fields for an element (ai_AIPackage
  // or dataset_DatasetPackage), as {label, kind, value} descriptors the detail
  // panel and expanded package card render with a single data-driven template.
  // kind ∈ 'badge' | 'text' | 'longtext' | 'chips' | 'list' | 'dict'.
  profileFields(el) {
    if (!el) return [];
    const out = [];
    const push = (label, kind, value) => {
      if (kind === 'chips' || kind === 'list' || kind === 'dict') {
        if (Array.isArray(value) && value.length) out.push({ label, kind, value });
      } else if (kind === 'bytes') {
        if (Number.isFinite(value) && value > 0) {
          out.push({ label, kind: 'badge', value: formatByteSize(value) });
        }
      } else if (isMeaningfulValue(value)) {
        out.push({ label, kind, value });
      }
    };

    // AI profile (ai_AIPackage; dataset_DatasetPackage inherits these too)
    push('Type of model', 'chips', el.ai_typeOfModel);
    push('Domain', 'chips', el.ai_domain);
    push('Autonomy', 'badge', el.ai_autonomyType);
    push('Safety risk assessment', 'badge', el.ai_safetyRiskAssessment);
    push('Sensitive personal information', 'badge', el.ai_sensitivePersonalInformation);
    push('Standards compliance', 'chips', el.ai_standardCompliance);
    push('Model explainability', 'chips', el.ai_modelExplainability);
    push('Energy consumption', 'text', el.ai_energyConsumption);
    push('Limitations', 'longtext', el.ai_limitation);
    push('About the application', 'longtext', el.ai_informationAboutApplication);
    push('About training', 'longtext', el.ai_informationAboutTraining);
    push('Data preprocessing', 'list', el.ai_modelDataPreprocessing);
    push('Hyperparameters', 'dict', el.ai_hyperparameter);
    push('Metrics', 'dict', el.ai_metric);
    push('Metric decision thresholds', 'dict', el.ai_metricDecisionThreshold);

    // Dataset profile (dataset_DatasetPackage)
    push('Dataset type', 'chips', el.dataset_datasetType);
    push('Intended use', 'text', el.dataset_intendedUse);
    push('Availability', 'badge', el.dataset_datasetAvailability);
    push('Confidentiality', 'badge', el.dataset_confidentialityLevel);
    push('Sensitive personal information', 'badge', el.dataset_hasSensitivePersonalInformation);
    push('Dataset size', 'bytes', el.dataset_datasetSize);
    push('Anonymization methods', 'chips', el.dataset_anonymizationMethodUsed);
    push('Known biases', 'list', el.dataset_knownBias);
    push('Data collection process', 'longtext', el.dataset_dataCollectionProcess);
    push('Data preprocessing', 'list', el.dataset_dataPreprocessing);
    push('Dataset noise', 'longtext', el.dataset_datasetNoise);
    push('Dataset update mechanism', 'text', el.dataset_datasetUpdateMechanism);
    push('Sensors', 'dict', el.dataset_sensor);

    return out;
  },

  // Human-readable size of a software artifact (File or Package), from the
  // SPDX Software profile's software_artifactSize (bytes). Returns '' when the
  // element carries no meaningful size, so templates can gate on truthiness.
  artifactSize(el) {
    return formatByteSize(Number(el?.software_artifactSize));
  },

  // Hardware profile (SPDX 3.1): the manufacturer/producer of a hardware
  // element, resolved from its hardware_productAgent reference (→ Organization /
  // Person / SoftwareAgent). Returns { id, name } or null.
  hardwareManufacturer(el) {
    const id = el?.hardware_productAgent;
    // Skip missing and NoAssertion sentinels (e.g. Core/NoAssertionElement) so a
    // "no manufacturer stated" hardware element doesn't render a bare URL.
    if (!id || id.includes('NoAssertion')) return null;
    const agent = this.elementMap.get(id);
    return { id, name: agent?.name || this.cleanName(id) };
  },

  // Spec-sheet fields for a hardware element beyond the headline part number /
  // category (which the detail panel promotes as badges). Returned as
  // {label, value, mono} descriptors so the card and detail panel render the
  // same set with one template.
  hardwareSpecs(el) {
    if (!el) return [];
    const out = [];
    const push = (label, value, mono = false) => {
      if (isMeaningfulValue(value)) out.push({ label, value: String(value), mono });
    };
    push('Serial number', el.hardware_serialNumber, true);
    push('Batch number', el.hardware_batchNumber, true);
    push('Release date', el.hardware_releaseDate && this.formatDate(el.hardware_releaseDate));
    push('Mass', el.hardware_mass);
    push('Bulk quantity', el.hardware_bulkQuantity);
    push('Additional information', el.hardware_additionalInformation);
    return out;
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
