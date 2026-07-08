import assert from 'node:assert/strict';
import test from 'node:test';

import { buildRelationshipIndexes, parseGraph } from '../src/parser/parser.js';
import { buildRemediationFindings } from '../src/lib/remediation.js';

function parsed(graph) {
  const data = parseGraph(graph);
  return { ...data, ...buildRelationshipIndexes(data.relationships) };
}

test('buildRemediationFindings emits grouped quality and unresolved external reference findings', () => {
  const data = parsed([
    {
      type: 'software_Package',
      spdxId: 'pkg:bare',
      name: 'bare-lib'
    },
    {
      type: 'simplelicensing_LicenseExpression',
      spdxId: 'lic:complex',
      simplelicensing_licenseExpression: 'MIT OR Apache-2.0'
    },
    {
      type: 'Relationship',
      spdxId: 'rel:license',
      relationshipType: 'hasDeclaredLicense',
      from: 'pkg:bare',
      to: ['lic:complex']
    },
    {
      type: 'SpdxDocument',
      spdxId: 'doc:a',
      name: 'Doc A',
      import: [
        { type: 'ExternalMap', externalSpdxId: 'ext:missing', locationHint: './missing.jsonld' }
      ]
    }
  ]);

  const findings = buildRemediationFindings(data);
  const kinds = new Set(findings.map((f) => f.kind));

  assert.ok(kinds.has('missing-supplier'));
  assert.ok(kinds.has('missing-version'));
  assert.ok(kinds.has('missing-identifier'));
  assert.ok(kinds.has('missing-hash'));
  assert.ok(kinds.has('missing-copyright'));
  assert.ok(kinds.has('unresolved-external-reference'));
  assert.ok(!kinds.has('license-expression-review'));

  const version = findings.find((f) => f.kind === 'missing-version');
  assert.equal(version.affectedCount, 1);
  assert.deepEqual(
    version.affectedSamples.map((sample) => sample.id),
    ['pkg:bare']
  );
  assert.equal(
    version.evidence[0],
    'The NTIA component-version element is missing on affected packages.'
  );

  const unresolved = findings.find((f) => f.kind === 'unresolved-external-reference');
  assert.equal(unresolved.elementId, 'ext:missing');
  assert.equal(unresolved.sourceCategory, 'structural');
});

test('buildRemediationFindings emits vulnerability and functional-safety findings', () => {
  const data = parsed([
    { type: 'software_Package', spdxId: 'pkg:a', name: 'package-a' },
    {
      type: 'security_Vulnerability',
      spdxId: 'vuln:1',
      externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-2026-0001' }]
    },
    {
      type: 'security_VexAffectedVulnAssessmentRelationship',
      spdxId: 'vex:affected',
      relationshipType: 'affects',
      from: 'vuln:1',
      to: ['pkg:a']
    },
    {
      type: 'security_CvssV3VulnAssessmentRelationship',
      spdxId: 'cvss:1',
      relationshipType: 'hasAssessmentFor',
      from: 'vuln:1',
      to: ['pkg:a'],
      security_score: '9.1',
      security_severity: 'critical'
    },
    { type: 'Requirement', spdxId: 'req:failed', name: 'Failed requirement' },
    { type: 'Requirement', spdxId: 'req:unverified', name: 'Unverified requirement' },
    {
      type: 'functionalsafety_RequirementVerification',
      spdxId: 'ver:failed',
      name: 'Failure verification'
    },
    {
      type: 'functionalsafety_EvaluationResult',
      spdxId: 'eval:failed',
      functionalsafety_evaluationBasedOn: 'ver:failed',
      functionalsafety_evaluation: 'fail'
    },
    {
      type: 'Relationship',
      spdxId: 'rel:verified',
      relationshipType: 'verifiedBy',
      from: 'req:failed',
      to: ['ver:failed']
    }
  ]);

  const findings = buildRemediationFindings(data);
  const byKind = Object.fromEntries(findings.map((f) => [f.kind, f]));

  assert.equal(byKind['affected-vulnerability'].elementName, 'CVE-2026-0001');
  assert.equal(byKind['affected-vulnerability'].severity, 'critical');
  assert.equal(byKind['functional-safety-failed'].elementId, 'req:failed');
  assert.equal(byKind['functional-safety-unverified'].affectedCount, 1);
  assert.deepEqual(
    byKind['functional-safety-unverified'].affectedSamples.map((sample) => sample.id),
    ['req:unverified']
  );
  assert.equal(byKind['requirement-no-implementation'].sourceCategory, 'traceability');
  assert.equal(byKind['requirement-no-implementation'].affectedCount, 2);
});

test('buildRemediationFindings maps VEX-only affected vulnerabilities to severity buckets', () => {
  const data = parsed([
    { type: 'software_Package', spdxId: 'pkg:a', name: 'package-a' },
    {
      type: 'security_Vulnerability',
      spdxId: 'vuln:1',
      externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-2026-0002' }]
    },
    {
      type: 'security_VexAffectedVulnAssessmentRelationship',
      spdxId: 'vex:affected',
      relationshipType: 'affects',
      from: 'vuln:1',
      to: ['pkg:a']
    }
  ]);

  const finding = buildRemediationFindings(data).find((f) => f.kind === 'affected-vulnerability');

  // An "affected" VEX status with no CVSS score is a medium data gap, not a high.
  assert.equal(finding.severity, 'medium');
  assert.equal(finding.score, 50);
  assert.equal(finding.affectedCount, 1);
  assert.deepEqual(
    finding.affectedSamples.map((sample) => sample.id),
    ['pkg:a']
  );
});

test('buildRemediationFindings scores CVSS vulnerabilities above data-quality gaps', () => {
  const data = parsed([
    { type: 'software_Package', spdxId: 'pkg:a', name: 'package-a' },
    {
      type: 'security_Vulnerability',
      spdxId: 'vuln:1',
      externalIdentifier: [{ externalIdentifierType: 'cve', identifier: 'CVE-2026-0003' }]
    },
    {
      type: 'security_VexAffectedVulnAssessmentRelationship',
      spdxId: 'vex:affected',
      relationshipType: 'affects',
      from: 'vuln:1',
      to: ['pkg:a']
    },
    {
      type: 'security_CvssV3VulnAssessmentRelationship',
      spdxId: 'cvss:1',
      relationshipType: 'hasAssessmentFor',
      from: 'vuln:1',
      to: ['pkg:a'],
      security_score: '9.1',
      security_severity: 'critical'
    }
  ]);

  const findings = buildRemediationFindings(data);
  const vuln = findings.find((f) => f.kind === 'affected-vulnerability');

  // CVSS is 0-10 but findings sort on a 0-100 scale, so a 9.1 must map to ~91.
  assert.equal(vuln.severity, 'critical');
  assert.equal(vuln.score, 91);

  // ...and therefore outrank the package's missing-version quality gap.
  const vulnIndex = findings.findIndex((f) => f.kind === 'affected-vulnerability');
  const gapIndex = findings.findIndex((f) => f.kind === 'missing-version');
  assert.ok(gapIndex >= 0, 'expected a missing-version quality gap');
  assert.ok(vulnIndex < gapIndex, 'CVSS vulnerability should sort above the data gap');
});

import { createViews } from '../src/config.js';

test('remediation is a dedicated navigation view before Impact', () => {
  const views = createViews();
  const remediation = views.findIndex((view) => view.id === 'remediation');
  const impact = views.findIndex((view) => view.id === 'impact');

  assert.ok(remediation >= 0);
  assert.ok(impact >= 0);
  assert.ok(remediation < impact);
});
