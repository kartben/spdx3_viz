/**
 * Remediation finding builder: converts parsed SPDX app/model data into a flat,
 * deterministic list of actionable remediation findings. The module is pure and
 * contains no Alpine state logic so it can be tested independently.
 *
 * @module lib/remediation
 */
import { enumValue, cleanName } from './format.js';
import { computeQualityReport } from './quality.js';
import { getCvssSeverityMeta, getVexStatusMeta } from './security.js';
import { blastRadius, buildImpactAdjacency } from './impact.js';

export const REMEDIATION_CATEGORY_META = {
  ntia: { key: 'ntia', label: 'NTIA data', order: 10 },
  cisa: { key: 'cisa', label: 'CISA 2026', order: 15 },
  license: { key: 'license', label: 'License & copyright', order: 20 },
  provenance: { key: 'provenance', label: 'Provenance', order: 30 },
  integrity: { key: 'integrity', label: 'Integrity', order: 40 },
  structural: { key: 'structural', label: 'Structure', order: 50 },
  vulnerability: { key: 'vulnerability', label: 'Security', order: 60 },
  'functional-safety': { key: 'functional-safety', label: 'Functional safety', order: 70 },
  traceability: { key: 'traceability', label: 'Traceability', order: 80 }
};

export function remediationCategoryMeta(category) {
  return (
    REMEDIATION_CATEGORY_META[category] || {
      key: category || '',
      label: category ? category.replace(/-/g, ' ') : 'Other',
      order: 999
    }
  );
}

const QUALITY_KIND_META = {
  'missing-name': {
    severity: 'medium',
    score: 55,
    title: 'Package names are missing',
    summary: 'Add component names so inventory, search, and downstream reports can identify them.',
    recommendedAction: 'Populate name for the affected packages.',
    sourceCategory: 'ntia',
    affectedLabel: 'packages',
    evidence: 'The NTIA component-name element is missing on affected packages.'
  },
  'missing-license': {
    severity: 'medium',
    score: 50,
    title: 'Package licenses are missing',
    summary: 'Add a declared or concluded license so downstream users can review obligations.',
    recommendedAction:
      'Attach hasDeclaredLicense or hasConcludedLicense to a concrete SPDX license expression.',
    sourceCategory: 'license',
    affectedLabel: 'packages',
    evidence: 'No declared or concluded license was found for affected packages.'
  },
  'missing-copyright': {
    severity: 'low',
    score: 35,
    title: 'Copyright text is missing',
    summary:
      'Add package copyright text where the SBOM needs FSCT-style license and copyright coverage.',
    recommendedAction:
      'Populate software_copyrightText with a meaningful copyright statement or NOASSERTION.',
    sourceCategory: 'license',
    affectedLabel: 'packages',
    evidence: 'The package copyright-text field is empty on affected packages.'
  },
  'missing-supplier': {
    severity: 'medium',
    score: 45,
    title: 'Supplier or originator is missing',
    summary: 'Record who supplied or originated this component to improve provenance.',
    recommendedAction: 'Populate suppliedBy or originatedBy with a meaningful agent reference.',
    sourceCategory: 'provenance',
    affectedLabel: 'packages',
    evidence: 'No meaningful suppliedBy or originatedBy agent reference was found.'
  },
  'missing-version': {
    severity: 'medium',
    score: 40,
    title: 'Package versions are missing',
    summary: 'Add the component version so inventory and vulnerability matching are precise.',
    recommendedAction: 'Populate software_packageVersion with the released package version.',
    sourceCategory: 'ntia',
    affectedLabel: 'packages',
    evidence: 'The NTIA component-version element is missing on affected packages.'
  },
  'missing-identifier': {
    severity: 'medium',
    score: 45,
    title: 'Package identifiers are missing',
    summary: 'Add a PURL, CPE, or other external identifier for reliable matching.',
    recommendedAction:
      'Populate software_packageUrl or externalIdentifier with an ecosystem identifier.',
    sourceCategory: 'provenance',
    affectedLabel: 'packages',
    evidence: 'No package URL or external identifier was found.'
  },
  'missing-hash': {
    severity: 'low',
    score: 30,
    title: 'Integrity hashes are missing',
    summary: 'Add an integrity hash so the artifact can be verified against tampering.',
    recommendedAction:
      'Populate verifiedUsing with at least one hash value for this package or file.',
    sourceCategory: 'integrity',
    affectedLabel: 'artifacts',
    evidence: 'No verifiedUsing hash value was found on affected packages or files.'
  },
  'orphan-component': {
    severity: 'low',
    score: 25,
    title: 'Artifacts have no relationships',
    summary: 'Connect this artifact to the SBOM graph so consumers understand why it is present.',
    recommendedAction:
      'Add an appropriate dependency, containment, generated-by, or descriptive relationship.',
    sourceCategory: 'structural',
    affectedLabel: 'artifacts',
    evidence: 'Affected packages or files have neither incoming nor outgoing relationships.'
  }
};

const DOCUMENT_KIND_META = {
  dependency: {
    kind: 'document-missing-dependency-relationship',
    severity: 'medium',
    score: 45,
    title: 'Dependency relationships are missing',
    summary:
      'The document does not assert a dependsOn relationship, so the NTIA dependency element is absent.',
    recommendedAction:
      'Add dependsOn relationships for package dependencies, or document why dependency data is unavailable.',
    sourceCategory: 'structural',
    evidence: 'No SPDX dependsOn relationship was found in the loaded graph.'
  },
  author: {
    kind: 'document-missing-author',
    severity: 'medium',
    score: 40,
    title: 'SBOM author is missing',
    summary: 'Record the person, organization, or tool that created the SBOM.',
    recommendedAction: 'Attach CreationInfo.createdBy to the SpdxDocument.',
    sourceCategory: 'provenance',
    evidence: 'The document has no resolved creator.'
  },
  timestamp: {
    kind: 'document-missing-timestamp',
    severity: 'low',
    score: 25,
    title: 'SBOM timestamp is missing',
    summary: 'Record when the SBOM was created so consumers can judge freshness.',
    recommendedAction: 'Populate CreationInfo.created with the SBOM creation timestamp.',
    sourceCategory: 'ntia',
    evidence: 'No document creation timestamp was found.'
  }
};

const CISA_DOCUMENT_KIND_META = {
  authorSignature: {
    kind: 'document-missing-author-signature',
    severity: 'low',
    score: 20,
    title: 'SBOM author signature is missing',
    summary: 'Add a digital signature attributable to the SBOM author (advisory).',
    recommendedAction:
      'Sign the SBOM with an approved signature algorithm and attach the signature.',
    sourceCategory: 'cisa',
    evidence: 'No SBOM author signature was found on the document.'
  },
  generationContext: {
    kind: 'document-missing-generation-context',
    severity: 'medium',
    score: 35,
    title: 'SBOM generation context is missing',
    summary: 'Record the lifecycle phase when this SBOM was generated (for example build).',
    recommendedAction: 'Set software_sbomType or emit lifecycle-scoped relationships.',
    sourceCategory: 'cisa',
    evidence: 'No SBOM generation context (sbomType, lifecycle scope, or build profile) was found.'
  },
  toolName: {
    kind: 'document-missing-tool-name',
    severity: 'medium',
    score: 35,
    title: 'SBOM tool name is missing',
    summary: 'Record the tool used to generate or amend this SBOM.',
    recommendedAction: 'Populate CreationInfo.createdUsing with a named Tool.',
    sourceCategory: 'cisa',
    evidence: 'No SBOM generation tool name was found.'
  },
  toolVersion: {
    kind: 'document-missing-tool-version',
    severity: 'medium',
    score: 35,
    title: 'SBOM tool version is missing',
    summary: 'Record the version of the SBOM generation tool.',
    recommendedAction: 'Add a tool version, versioned PURL, or versioned tool name.',
    sourceCategory: 'cisa',
    evidence: 'The SBOM generation tool has no version identifier.'
  },
  formatVersion: {
    kind: 'document-missing-format-version',
    severity: 'medium',
    score: 40,
    title: 'SBOM data format version is missing',
    summary: 'Record the SPDX (or CycloneDX) format version used.',
    recommendedAction: 'Populate CreationInfo.specVersion.',
    sourceCategory: 'cisa',
    evidence: 'No SBOM data format version was found.'
  }
};

const SAFETY_GAP_META = {
  'functional-safety-unverified': {
    severity: 'medium',
    score: 55,
    title: 'Requirements are unverified',
    summary: 'Requirements lack completed functional-safety verification results.',
    sourceView: 'requirements',
    sourceCategory: 'functional-safety',
    evidence:
      'No passing, failing, or inconclusive evaluation result was linked to affected requirements.',
    recommendedAction:
      'Link RequirementVerification and EvaluationResult evidence for affected requirements.',
    affectedLabel: 'requirements'
  },
  'requirement-no-implementation': {
    severity: 'medium',
    score: 50,
    title: 'Requirements have no implementation trace',
    summary: 'Requirements are not linked to an implementing artifact.',
    sourceView: 'requirements',
    sourceCategory: 'traceability',
    evidence: 'No implementedBy relationship was found for affected requirements.',
    recommendedAction:
      'Add implementedBy links from affected requirements to source files, snippets, packages, or design artifacts.',
    affectedLabel: 'requirements'
  }
};

const AFFECTED_SAMPLE_CAP = 10;

function asArray(value) {
  return Array.isArray(value) ? value : value == null || value === '' ? [] : [value];
}

function displayName(el) {
  return el?.name || cleanName(el?.spdxId || el?.id) || el?.spdxId || el?.id || 'Unknown';
}

function elementType(el) {
  return el?.type || '';
}

function byId(data, id) {
  return data.elementMap?.get(id) || null;
}

function makeFinding(kind, el, props = {}) {
  // Offenders resolved off a raw sample (not in elementMap) carry `id` but no
  // `spdxId`; fall back to it so distinct offenders keep distinct finding ids.
  const elementId = el?.spdxId || el?.id || props.elementId || '';
  return {
    id: props.id || `${kind}:${elementId || 'document'}`,
    kind,
    severity: props.severity || 'low',
    score: props.score ?? 0,
    title: props.title || kind,
    summary: props.summary || '',
    elementId,
    elementName: props.elementName || (el ? displayName(el) : ''),
    elementType: props.elementType || (el ? elementType(el) : ''),
    sourceView: props.sourceView || '',
    sourceCategory: props.sourceCategory || '',
    evidence: props.evidence || [],
    recommendedAction: props.recommendedAction || '',
    relatedIds: props.relatedIds || [],
    affectedCount: props.affectedCount || 0,
    affectedLabel: props.affectedLabel || 'items',
    affectedSamples: props.affectedSamples || []
  };
}

function sampleItem(item, data) {
  const el = byId(data, item.id) || item;
  return {
    id: item.id || el?.spdxId || '',
    name: item.name || displayName(el),
    type: item.type || elementType(el)
  };
}

function addQualityGroup(out, kind, list, data) {
  if (!list?.total) return;
  const meta = QUALITY_KIND_META[kind];
  if (!meta) return;
  const affectedSamples = (list.sample || []).map((item) => sampleItem(item, data));
  out.push(
    makeFinding(kind, null, {
      ...meta,
      id: kind,
      sourceView: 'statistics',
      evidence: meta.evidence ? [meta.evidence] : [],
      affectedCount: list.total,
      affectedSamples
    })
  );
}

function elementOffenderList(elements) {
  return {
    total: elements.length,
    sample: elements
      .slice(0, AFFECTED_SAMPLE_CAP)
      .map((el) => ({ id: el.spdxId, name: displayName(el), type: el.type }))
  };
}

function addElementGroup(out, kind, elements, data, meta) {
  if (!elements.length || !meta) return;
  const affectedSamples = elementOffenderList(elements).sample.map((item) =>
    sampleItem(item, data)
  );
  out.push(
    makeFinding(kind, null, {
      ...meta,
      id: kind,
      evidence: meta.evidence ? [meta.evidence] : [],
      affectedCount: elements.length,
      affectedSamples
    })
  );
}

function elementsByKey(elements) {
  return Object.fromEntries((elements || []).map((el) => [el.key, el]));
}

function documentElement(data) {
  for (const el of data.elementMap?.values?.() || []) {
    if (el?.type === 'SpdxDocument') return el;
  }
  return null;
}

function addDocumentQualityFindings(out, data, report) {
  const docEl = documentElement(data);
  const docName = docEl ? displayName(docEl) : data.docName || 'SPDX document';
  (report.ntia?.elements || [])
    .filter((el) => el.level === 'document' && !el.present)
    .forEach((el) => {
      const meta = DOCUMENT_KIND_META[el.key];
      if (!meta) return;
      out.push(
        makeFinding(meta.kind, docEl, {
          ...meta,
          id: meta.kind,
          sourceView: 'statistics',
          elementId: docEl?.spdxId || '',
          elementName: docName,
          elementType: docEl?.type || 'SpdxDocument',
          evidence: meta.evidence ? [meta.evidence] : []
        })
      );
    });

  const cisaItems = [...(report.cisa2026?.metadata || []), ...(report.cisa2026?.component || [])];
  cisaItems
    .filter((el) => el.level === 'document' && el.status !== 'pass' && el.status !== 'na')
    .forEach((el) => {
      const meta = CISA_DOCUMENT_KIND_META[el.key];
      if (!meta) return;
      // Skip NTIA overlaps already emitted (author, timestamp, dependency).
      if (DOCUMENT_KIND_META[el.key]) return;
      out.push(
        makeFinding(meta.kind, docEl, {
          ...meta,
          id: meta.kind,
          sourceView: 'statistics',
          elementId: docEl?.spdxId || '',
          elementName: docName,
          elementType: docEl?.type || 'SpdxDocument',
          evidence: meta.evidence ? [meta.evidence] : []
        })
      );
    });
}

function addQualityFindings(out, data) {
  const report = computeQualityReport(data);
  const ntia = elementsByKey(report.ntia?.elements);
  const fsct = elementsByKey(report.ntia?.fsct);
  const cisaComp = elementsByKey(report.cisa2026?.component);
  const offenderMap = {
    'missing-name': ntia.name?.missing,
    'missing-license':
      cisaComp.license?.missing ||
      fsct.concludedLicense?.missing ||
      report.insights.offenders.missingLicense,
    'missing-copyright': fsct.copyrightText?.missing || report.insights.offenders.missingCopyright,
    'missing-supplier':
      cisaComp.producer?.missing ||
      ntia.supplier?.missing ||
      report.insights.offenders.missingSupplier,
    'missing-version':
      cisaComp.version?.missing ||
      ntia.version?.missing ||
      report.insights.offenders.missingVersion,
    'missing-identifier': cisaComp.identifier?.missing || ntia.identifier?.missing,
    'missing-hash': report.insights.offenders.missingHash,
    'orphan-component': report.insights.offenders.orphans
  };

  Object.entries(offenderMap).forEach(([kind, list]) => addQualityGroup(out, kind, list, data));
  addDocumentQualityFindings(out, data, report);
}

function addExternalReferenceFindings(out, data) {
  (data.externalMap || new Map()).forEach((entry, id) => {
    if (data.elementMap?.has(id)) return;
    out.push(
      makeFinding('unresolved-external-reference', null, {
        severity: 'medium',
        score: 45,
        title: 'External reference is unresolved',
        summary: 'An imported SPDX element was referenced but is not present in the parsed graph.',
        elementId: id,
        elementName: id,
        elementType: 'ExternalMap',
        sourceView: 'quality',
        sourceCategory: 'structural',
        evidence: [
          entry.locationHint
            ? `locationHint: ${entry.locationHint}`
            : 'No resolved element in elementMap.'
        ],
        recommendedAction:
          'Load or merge the referenced external SPDX document, or remove the stale import.',
        relatedIds: asArray(entry.definingArtifact)
      })
    );
  });
}

// Scores are on a 0-100 scale so a finding sorts against every other kind. Used
// for vulnerabilities that carry no CVSS score, so the fallback tracks the
// severity band rather than the raw VEX status.
const FALLBACK_SEVERITY_SCORE = { critical: 95, high: 75, medium: 50, low: 25 };

function vulnerabilityFallbackSeverity(status) {
  if (status === 'affected') return 'medium';
  if (status === 'under_investigation') return 'medium';
  return 'low';
}

function addVulnerabilityFindings(out, data) {
  const impactGraph = {
    parentIndex:
      data.impactParentIndex || buildImpactAdjacency(data.relationships || []).parentIndex
  };
  (data.vulnerabilities || []).forEach((vuln) => {
    if (!['affected', 'under_investigation'].includes(vuln.overallStatus)) return;
    const statusMeta = getVexStatusMeta(vuln.overallStatus);
    const cvssMeta = getCvssSeverityMeta(vuln.severity);
    const kind =
      vuln.overallStatus === 'affected'
        ? 'affected-vulnerability'
        : 'vulnerability-under-investigation';
    const severity =
      cvssMeta.key !== 'unknown' && cvssMeta.key !== 'none'
        ? cvssMeta.key
        : vulnerabilityFallbackSeverity(vuln.overallStatus);
    // CVSS is a 0-10 scale; multiply so vulnerabilities sort against the 0-100
    // scores every other finding kind uses (a CVSS 9.1 must outrank a data gap).
    const score =
      vuln.cvss?.score != null
        ? Math.round(vuln.cvss.score * 10)
        : (FALLBACK_SEVERITY_SCORE[severity] ?? 40);
    const relatedIds = [
      ...new Set((vuln.assessments || []).map((a) => a.packageId).filter(Boolean))
    ];
    const blast = relatedIds.map((id) => [id, blastRadius(id, impactGraph, { cap: 1000 }).total]);
    const affectedSamples = relatedIds.map((id) => sampleItem({ id }, data));
    out.push(
      makeFinding(kind, vuln.el || null, {
        severity,
        score,
        title: `${vuln.name} is ${statusMeta.label.toLowerCase()}`,
        summary: 'A vulnerability has an open VEX status for one or more packages.',
        elementId: vuln.spdxId,
        elementName: vuln.name,
        elementType: 'security_Vulnerability',
        sourceView: 'security',
        sourceCategory: 'vulnerability',
        evidence: [
          `VEX status: ${statusMeta.label}`,
          vuln.cvss?.score != null ? `CVSS: ${vuln.cvss.score}` : 'No CVSS score in this SBOM.',
          ...blast.map(([id, total]) => `${id} blast radius: ${total}`)
        ].filter(Boolean),
        recommendedAction:
          'Triage the affected packages, add fix/not-affected VEX justification, or update the component.',
        relatedIds,
        affectedCount: relatedIds.length,
        affectedLabel: 'packages',
        affectedSamples
      })
    );
  });
}

function requirementVerifications(req, data, evaluationMap) {
  return (data.relFromIndex?.get(req.spdxId) || [])
    .filter((rel) => rel.relationshipType === 'verifiedBy')
    .flatMap((rel) => asArray(rel.to))
    .map((id) => ({ id, verification: byId(data, id), evaluation: evaluationMap.get(id) || null }));
}

// verificationId -> its EvaluationResult, built once so requirement lookups are
// O(1) instead of a linear scan of data.requirements per verification.
function buildEvaluationMap(data) {
  const map = new Map();
  (data.requirements || []).forEach((r) => {
    const basedOn = r.functionalsafety_evaluationBasedOn;
    if (r.type === 'functionalsafety_EvaluationResult' && basedOn && !map.has(basedOn)) {
      map.set(basedOn, r);
    }
  });
  return map;
}

function implementedByIds(req, data) {
  return [
    ...new Set(
      (data.relFromIndex?.get(req.spdxId) || [])
        .filter((rel) => rel.relationshipType === 'implementedBy')
        .flatMap((rel) => asArray(rel.to))
        .filter(Boolean)
    )
  ];
}

function addFunctionalSafetyFindings(out, data) {
  const unverified = [];
  const noImplementation = [];
  const evaluationMap = buildEvaluationMap(data);
  (data.requirements || [])
    .filter((req) => req.type === 'Requirement')
    .forEach((req) => {
      const vers = requirementVerifications(req, data, evaluationMap);
      const evaluations = vers.map((v) =>
        enumValue(v.evaluation?.functionalsafety_evaluation).toLowerCase()
      );
      if (evaluations.includes('fail')) {
        out.push(
          makeFinding('functional-safety-failed', req, {
            severity: 'high',
            score: 80,
            title: 'Requirement verification failed',
            summary: 'At least one verification for this requirement has a failing evaluation.',
            sourceView: 'requirements',
            sourceCategory: 'functional-safety',
            evidence: evaluations.map((e, i) => `${vers[i].id}: ${e || 'not evaluated'}`),
            recommendedAction:
              'Fix the implementation or update the requirement and rerun verification.',
            relatedIds: vers.map((v) => v.id)
          })
        );
      } else if (!vers.length || evaluations.every((e) => !e)) {
        unverified.push(req);
      }

      const implementations = implementedByIds(req, data);
      if (!implementations.length) {
        noImplementation.push(req);
      }
    });
  addElementGroup(
    out,
    'functional-safety-unverified',
    unverified,
    data,
    SAFETY_GAP_META['functional-safety-unverified']
  );
  addElementGroup(
    out,
    'requirement-no-implementation',
    noImplementation,
    data,
    SAFETY_GAP_META['requirement-no-implementation']
  );
}

/**
 * Builds remediation findings from parsed SPDX app/model data.
 *
 * @param {Object} data - Parsed data plus relationship indexes used by the app.
 * @returns {Array<Object>} Flat, deterministic remediation findings.
 */
export function buildRemediationFindings(data = {}) {
  const findings = [];
  addQualityFindings(findings, data);
  addExternalReferenceFindings(findings, data);
  addVulnerabilityFindings(findings, data);
  addFunctionalSafetyFindings(findings, data);
  return findings.sort(
    (a, b) => b.score - a.score || a.kind.localeCompare(b.kind) || a.id.localeCompare(b.id)
  );
}
