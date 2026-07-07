import assert from 'node:assert/strict';
import test from 'node:test';

import { enumValue, formatHardwareDimensions, formatQudtMeasure } from '../src/lib/index.js';

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

test('formatQudtMeasure renders mass and length measures', () => {
  assert.equal(formatQudtMeasure({ type: 'MeasureOfMass', quantity: 5, unitQUDT: 'GM' }), '5 g');
  assert.equal(
    formatQudtMeasure({ type: 'MeasureOfMass', quantity: 0.84, unitQUDT: 'KiloGM' }),
    '0.84 kg'
  );
  assert.equal(
    formatQudtMeasure({ type: 'MeasureOfLength', quantity: 210, unitQUDT: 'MilliM' }),
    '210 mm'
  );
});

test('formatQudtMeasure returns empty string for invalid input', () => {
  assert.equal(formatQudtMeasure(null), '');
  assert.equal(formatQudtMeasure({ unitQUDT: 'GM' }), '');
  assert.equal(formatQudtMeasure({ quantity: 'n/a', unitQUDT: 'GM' }), '');
});

test('formatHardwareDimensions joins axes with a shared unit label', () => {
  assert.equal(
    formatHardwareDimensions({
      hardware_xAxisLength: { quantity: 210, unitQUDT: 'MilliM' },
      hardware_yAxisLength: { quantity: 297, unitQUDT: 'MilliM' },
      hardware_zAxisLength: { quantity: 0.1, unitQUDT: 'MilliM' }
    }),
    '210 × 297 × 0.1 mm'
  );
});
