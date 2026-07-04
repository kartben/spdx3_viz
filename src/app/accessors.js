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
  elementIconSvg as elementIconMarkup,
  typeIconSvg as typeIconMarkup,
  parseCompileFlags as parseBuildConfigFlags,
  parseBuildParameters as parseBuildParameterGroups,
  getToolUsageCount,
  getExternalIdentifiers,
  getCdxProperties,
  isMeaningfulValue,
  formatByteSize,
  normalizeUrl,
  copyToClipboard
} from '../lib/index.js';
import { COLORS } from '../config.js';

/* Element accessors and display helpers: thin lookups into the relationship
   indexes, name/date formatting, and the relationship-group data the detail
   panel renders. Most expose a util or index to templates as this.*(). */

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
  // The ExternalMap entry for an element imported by a loaded SpdxDocument
  // (referenced here but defined elsewhere), or null. Merged entry:
  // {locationHint, definingArtifact, verifiedUsing, importedBy}.
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
      case 'finedot':
        return `background-image: repeating-linear-gradient(to right, ${c} 0 1.5px, transparent 1.5px 3px)`;
      case 'dashed':
        return `background-image: repeating-linear-gradient(to right, ${c} 0 5px, transparent 5px 8px)`;
      case 'longdash':
        return `background-image: repeating-linear-gradient(to right, ${c} 0 8px, transparent 8px 12px)`;
      case 'dashdot':
        return `background-image: repeating-linear-gradient(to right, ${c} 0 5px, transparent 5px 7px, ${c} 7px 8px, transparent 8px 10px)`;
      case 'dashdotdot':
        return `background-image: repeating-linear-gradient(to right, ${c} 0 5px, transparent 5px 7px, ${c} 7px 8px, transparent 8px 9px, ${c} 9px 10px, transparent 10px 12px)`;
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
    // section, not the generic relationship list.
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

  // True for Agent elements (Person / Organization / SoftwareAgent, or a bare
  // Agent) — the ones the Agents tab lists and gives a provenance-focused view.
  isAgent(el) {
    return this.getNodeType(el) === 'agent';
  },

  // Human-readable kind of an agent, used as the card/detail subtitle.
  agentTypeLabel(el) {
    switch (el?.type) {
      case 'Organization':
        return 'Organization';
      case 'Person':
        return 'Person';
      case 'SoftwareAgent':
        return 'Software agent';
      default:
        return 'Agent';
    }
  },

  // First email address carried by an agent's externalIdentifier list, or '' —
  // so templates can gate a mailto link on truthiness.
  agentEmail(el) {
    const ids = el?.externalIdentifier;
    if (!Array.isArray(ids)) return '';
    const email = ids.find((id) => id?.externalIdentifierType === 'email' && id?.identifier);
    return email?.identifier?.replace(/^mailto:/i, '') || '';
  },

  // How many elements an agent is tied to across all provenance roles, for the
  // list-card badge and the "most connected" sort.
  agentLinkCount(el) {
    const e = el && this.agentLinkIndex.get(el.spdxId);
    if (!e) return 0;
    return e.created.length + e.supplied.length + e.originated.length + e.manufactured.length;
  },

  // The provenance links an agent has, shaped like detailRelGroups so the detail
  // panel and the Agents-view card render them with the same template. Each group
  // is capped so a document-wide creator (createdBy on every element) can't mount
  // thousands of rows; the surplus is reported via hiddenCount.
  agentLinkGroups(el) {
    const entry = el && this.agentLinkIndex.get(el.spdxId);
    if (!entry) return [];
    const CAP = 50;
    const defs = [
      { bucket: 'created', label: 'Created', color: COLORS.createdBy },
      { bucket: 'manufactured', label: 'Manufacturer of', color: COLORS.hardware },
      { bucket: 'supplied', label: 'Supplier of', color: COLORS.distribution },
      { bucket: 'originated', label: 'Originator of', color: COLORS.package }
    ];
    const groups = [];
    for (const d of defs) {
      const ids = entry[d.bucket] || [];
      if (!ids.length) continue;
      groups.push({
        key: d.bucket,
        label: d.label,
        color: d.color,
        total: ids.length,
        hiddenCount: Math.max(0, ids.length - CAP),
        items: ids.slice(0, CAP).map((id) => ({ id, displayName: this.relTargetDisplayName(id) }))
      });
    }
    return groups;
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
  // Inline Material-icon <svg> for the DOM UI (sidebar, detail panel, list rows,
  // graph legend). fill=currentColor, so callers tint via CSS/Tailwind colour.
  elementIcon(el, className) {
    return elementIconMarkup(el, className);
  },
  nodeTypeIconSvg(nodeType, className = 'w-3.5 h-3.5') {
    return typeIconMarkup(nodeType, className);
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

  // FunctionalSafety profile (SPDX 3.1): spec-sheet fields for a requirement or a
  // safety artifact (verification / assumption / evaluation) beyond the headline
  // statement (which the detail panel promotes as a hero). Returned as
  // {label, value, mono} descriptors so the card and detail panel render the same
  // set with one template. Array-valued fields (rationale, verificationMethod, …)
  // are joined for display.
  safetyFields(el) {
    if (!el) return [];
    const out = [];
    const join = (v) => (Array.isArray(v) ? v.filter(isMeaningfulValue).join(', ') : v);
    const push = (label, value, mono = false) => {
      const v = join(value);
      if (isMeaningfulValue(v)) out.push({ label, value: String(v), mono });
    };
    // Requirement (Core)
    push('Lifecycle stage', el.devLifecycleStage);
    // RequirementVerification (functionalsafety)
    push('Verification method', el.functionalsafety_verificationMethod);
    push('Precondition', el.functionalsafety_verificationPrecondition);
    push('Postcondition', el.functionalsafety_verificationPostcondition);
    // EvaluationResult (functionalsafety): the pass/fail is rendered as a badge via
    // evaluationResultMeta; here we resolve the verification it was based on.
    if (el.functionalsafety_evaluationBasedOn) {
      const v = this.elementMap.get(el.functionalsafety_evaluationBasedOn);
      push('Based on', v?.name || this.cleanName(el.functionalsafety_evaluationBasedOn));
    }
    // Shared: the reasoning behind the requirement / verification / evaluation
    push('Rationale', el.rationale || el.functionalsafety_rationale);
    return out;
  },

  // The verifications a requirement is linked to via `verifiedBy`, each paired
  // with its EvaluationResult (resolved through the evaluation's
  // evaluationBasedOn back-reference) — the data behind a requirement's
  // pass/fail status and its inline verification breakdown.
  requirementVerifications(el) {
    if (!el) return [];
    const out = [];
    (this.outgoingRels(el.spdxId) || []).forEach((rel) => {
      if (rel.relationshipType !== 'verifiedBy') return;
      (Array.isArray(rel.to) ? rel.to : [rel.to]).forEach((vid) => {
        const verification = this.elementMap.get(vid);
        if (verification) out.push({ id: vid, verification, evaluation: this.evaluationFor(vid) });
      });
    });
    return out;
  },

  // The EvaluationResult whose evaluationBasedOn points at a given verification.
  evaluationFor(verificationId) {
    return (
      this.requirements.find(
        (r) =>
          r.type === 'functionalsafety_EvaluationResult' &&
          r.functionalsafety_evaluationBasedOn === verificationId
      ) || null
    );
  },

  // Overall functional-safety status of a Requirement, walking
  // Requirement --verifiedBy--> RequirementVerification <--evaluationBasedOn-- EvaluationResult.
  // A single failed evaluation dominates; otherwise all-pass wins, then
  // inconclusive, then verified-but-not-yet-evaluated, else unverified.
  requirementSafetyStatus(el) {
    if (!el || el.type !== 'Requirement') return null;
    const vers = this.requirementVerifications(el);
    if (!vers.length) {
      return {
        key: 'unverified',
        label: 'Unverified',
        badgeClass: 'bg-slate-600/20 text-slate-400'
      };
    }
    const evals = vers.map((v) =>
      String(v.evaluation?.functionalsafety_evaluation || '').toLowerCase()
    );
    if (evals.includes('fail')) {
      return {
        key: 'failed',
        label: 'Verification failed',
        badgeClass: 'bg-rose-500/15 text-rose-400'
      };
    }
    const decided = evals.filter(Boolean);
    if (decided.length && decided.every((e) => e === 'pass')) {
      return {
        key: 'passed',
        label: 'Verified · pass',
        badgeClass: 'bg-emerald-500/15 text-emerald-400'
      };
    }
    if (evals.includes('inconclusive')) {
      return {
        key: 'inconclusive',
        label: 'Inconclusive',
        badgeClass: 'bg-amber-500/15 text-amber-400'
      };
    }
    return { key: 'verified', label: 'Verified', badgeClass: 'bg-sky-500/15 text-sky-400' };
  },

  // Friendly kind label for a functional-safety element, for the card/detail
  // type badge (Requirement / Verification / Assumption / Evaluation).
  safetyArtifactKind(el) {
    switch (el?.type) {
      case 'Requirement':
        return 'Requirement';
      case 'functionalsafety_RequirementVerification':
        return 'Verification';
      case 'functionalsafety_Assumption':
        return 'Assumption';
      case 'functionalsafety_EvaluationResult':
        return 'Evaluation';
      default:
        return '';
    }
  },

  // Number of elements a requirement is implemented by (distinct `to` targets of
  // its outgoing `implementedBy` relationships) — the headline traceability
  // count shown on a requirement card.
  implementedByCount(spdxId) {
    const targets = new Set();
    (this.outgoingRels(spdxId) || []).forEach((rel) => {
      if (rel.relationshipType !== 'implementedBy') return;
      (Array.isArray(rel.to) ? rel.to : [rel.to]).forEach((t) => t && targets.add(t));
    });
    return targets.size;
  },

  // Presentation for a FunctionalSafety EvaluationResult's pass/fail/inconclusive
  // outcome, so it can render as a status badge. Returns null for elements that
  // carry no evaluation result.
  evaluationResultMeta(el) {
    const v = el?.functionalsafety_evaluation;
    if (!isMeaningfulValue(v)) return null;
    const key = String(v).toLowerCase();
    const map = {
      pass: { label: 'Pass', badgeClass: 'bg-emerald-500/15 text-emerald-400' },
      fail: { label: 'Fail', badgeClass: 'bg-rose-500/15 text-rose-400' },
      inconclusive: { label: 'Inconclusive', badgeClass: 'bg-amber-500/15 text-amber-400' }
    };
    return map[key] || { label: String(v), badgeClass: 'bg-slate-600/20 text-slate-300' };
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
