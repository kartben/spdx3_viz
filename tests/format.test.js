import assert from 'node:assert/strict';
import test from 'node:test';

import { enumValue } from '../src/lib/index.js';

test('enumValue keeps a bare vocab token unchanged', () => {
  assert.equal(enumValue('pass'), 'pass');
  assert.equal(enumValue('test'), 'test');
});

test('enumValue reduces a CURIE-serialized enum to its token', () => {
  // The form emitted when the JSON-LD context resolves the term base as a prefix.
  assert.equal(enumValue('spdx:FunctionalSafety/EvaluationResultType/pass'), 'pass');
  assert.equal(enumValue('spdx:FunctionalSafety/VerificationType/test'), 'test');
  assert.equal(enumValue('spdx:Core/PresenceType/yes'), 'yes');
});

test('enumValue reduces a full term IRI to its token', () => {
  assert.equal(
    enumValue('https://spdx.org/rdf/3.1/terms/FunctionalSafety/EvaluationResultType/fail'),
    'fail'
  );
  assert.equal(
    enumValue('https://spdx.org/rdf/3/terms/FunctionalSafety/EvaluationResultType/inconclusive'),
    'inconclusive'
  );
});

test('enumValue handles a fragment-delimited IRI and a plain prefix', () => {
  assert.equal(enumValue('urn:example#pass'), 'pass');
  assert.equal(enumValue('spdx:test'), 'test');
});

test('enumValue returns empty string for empty/nullish input', () => {
  assert.equal(enumValue(''), '');
  assert.equal(enumValue('   '), '');
  assert.equal(enumValue(null), '');
  assert.equal(enumValue(undefined), '');
});
