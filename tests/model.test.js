import assert from 'node:assert/strict';
import test from 'node:test';

import { CLASS, BUCKET, isA, ancestors, bucketOf } from '../src/spdx/model.js';

// CLASS echoes back the exact official class name, validated against the
// generated hierarchy — so a typo or an upstream rename throws here instead of
// silently never matching in the parser.
test('CLASS resolves official class names and rejects unknown ones', () => {
  assert.equal(CLASS.software_Package, 'software_Package');
  assert.equal(CLASS.ai_AIPackage, 'ai_AIPackage');
  assert.equal(CLASS.SoftwareAgent, 'SoftwareAgent');
  assert.equal(CLASS.functionalsafety_Assumption, 'functionalsafety_Assumption');
  assert.throws(() => CLASS.software_Packge, /Unknown SPDX class/); // typo
  assert.throws(() => CLASS.NotAClass, /Unknown SPDX class/);
});

test('isA walks the class hierarchy', () => {
  assert.equal(isA(CLASS.ai_AIPackage, CLASS.software_Package), true);
  assert.equal(isA(CLASS.dataset_DatasetPackage, CLASS.software_Package), true);
  assert.equal(isA(CLASS.software_File, CLASS.software_Package), false);
  assert.equal(isA(CLASS.security_VexVulnAssessmentRelationship, CLASS.Relationship), true);
  assert.equal(isA('not_a_spdx_type', CLASS.software_Package), false);
  assert.equal(ancestors(CLASS.software_Package).at(-1), 'Element');
});

test('bucketOf categorizes by hierarchy, most-specific rule first', () => {
  assert.equal(bucketOf(CLASS.ai_AIPackage), BUCKET.PACKAGES);
  assert.equal(bucketOf(CLASS.software_File), BUCKET.FILES);
  assert.equal(bucketOf('hardware_PhysicalHardware'), BUCKET.HARDWARE);
  // VEX beats the generic Relationship bucket; non-VEX assessments are separate.
  assert.equal(bucketOf('security_VexFixedVulnAssessmentRelationship'), BUCKET.VEX);
  assert.equal(bucketOf('security_CvssV3VulnAssessmentRelationship'), BUCKET.VULN_ASSESSMENT);
  assert.equal(bucketOf(CLASS.Relationship), BUCKET.RELATIONSHIPS);
  // FunctionalSafety artifacts group with Requirement despite subclassing Element.
  assert.equal(bucketOf(CLASS.functionalsafety_EvaluationResult), BUCKET.REQUIREMENTS);
  assert.equal(bucketOf('DictionaryEntry'), null);
});
