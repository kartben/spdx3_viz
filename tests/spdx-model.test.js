import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ELEMENT_TYPES,
  VEX_TYPES,
  RELATIONSHIP_TYPES,
  VEX_STATUS_BY_REL,
  VEX_JUSTIFICATION_LABELS,
  DETAIL_PROMOTED_FIELDS,
  createGraphFilters,
  getRelationshipColor
} from '../js/config.js';
import {
  CLASSES,
  PROPERTIES,
  VOCABULARIES,
  isSubclassOf,
  isKnownClass,
  isKnownProperty
} from '../js/spdx-model.js';

/**
 * These tests keep the hand-curated SPDX constants in config.js honest against
 * the model generated from the official SPDX SHACL/OWL definitions
 * (js/generated/, produced by `npm run gen:model`). If a constant is misspelled
 * or drifts from the spec, the matching assertion fails with the offender named.
 */

const relationshipVocab = new Set(VOCABULARIES.RelationshipType);
const vexJustificationVocab = new Set(VOCABULARIES.security_VexJustificationType);

test('every ELEMENT_TYPES value is a class in the SPDX model', () => {
  for (const [name, value] of Object.entries(ELEMENT_TYPES)) {
    assert.ok(isKnownClass(value), `ELEMENT_TYPES.${name} = "${value}" is not an SPDX class`);
  }
});

test('every VEX_TYPES value is a class in the SPDX model', () => {
  for (const [name, value] of Object.entries(VEX_TYPES)) {
    assert.ok(isKnownClass(value), `VEX_TYPES.${name} = "${value}" is not an SPDX class`);
  }
});

test('every RELATIONSHIP_TYPES value is a RelationshipType vocabulary member', () => {
  for (const [name, value] of Object.entries(RELATIONSHIP_TYPES)) {
    assert.ok(
      relationshipVocab.has(value),
      `RELATIONSHIP_TYPES.${name} = "${value}" is not an SPDX RelationshipType`
    );
  }
});

test('every VEX_STATUS_BY_REL key is a RelationshipType vocabulary member', () => {
  for (const key of Object.keys(VEX_STATUS_BY_REL)) {
    assert.ok(
      relationshipVocab.has(key),
      `VEX_STATUS_BY_REL key "${key}" is not an SPDX RelationshipType`
    );
  }
});

test('every VEX_JUSTIFICATION_LABELS key is a VexJustificationType member', () => {
  for (const key of Object.keys(VEX_JUSTIFICATION_LABELS)) {
    assert.ok(
      vexJustificationVocab.has(key),
      `VEX_JUSTIFICATION_LABELS key "${key}" is not an SPDX VexJustificationType`
    );
  }
});

test('DETAIL_PROMOTED_FIELDS reference real SPDX properties and classes', () => {
  for (const field of DETAIL_PROMOTED_FIELDS) {
    assert.ok(
      isKnownProperty(field.prop),
      `promoted field prop "${field.prop}" is not an SPDX property`
    );
    for (const type of field.types || []) {
      assert.ok(isKnownClass(type), `promoted field type "${type}" is not an SPDX class`);
    }
  }
});

test('isSubclassOf follows the model class hierarchy', () => {
  // AI and dataset packages must resolve to software_Package (this is what lets
  // the parser categorize them as packages without a hardcoded list).
  assert.ok(isSubclassOf(ELEMENT_TYPES.AI_PACKAGE, ELEMENT_TYPES.PACKAGE));
  assert.ok(isSubclassOf(ELEMENT_TYPES.DATASET_PACKAGE, ELEMENT_TYPES.PACKAGE));
  // In the 3.0.1 model AI and dataset packages are siblings (both direct
  // subclasses of software_Package), not parent/child of each other.
  assert.ok(!isSubclassOf(ELEMENT_TYPES.DATASET_PACKAGE, ELEMENT_TYPES.AI_PACKAGE));

  // Identity holds; unrelated / unknown types do not.
  assert.ok(isSubclassOf(ELEMENT_TYPES.PACKAGE, ELEMENT_TYPES.PACKAGE));
  assert.ok(!isSubclassOf(ELEMENT_TYPES.FILE, ELEMENT_TYPES.PACKAGE));
  assert.ok(!isSubclassOf('not_a_real_type', ELEMENT_TYPES.PACKAGE));
  assert.ok(!isSubclassOf(undefined, ELEMENT_TYPES.PACKAGE));
});

test('generated model exposes the expected shape', () => {
  assert.ok(CLASSES.size > 0 && PROPERTIES.size > 0);
  assert.ok(Array.isArray(VOCABULARIES.RelationshipType));
  assert.ok(relationshipVocab.has('contains') && relationshipVocab.has('dependsOn'));
});

test('graph filters cover every model relationship type, and only real ones', () => {
  const relKeys = new Set(
    createGraphFilters()
      .filter((f) => f.isRel)
      .map((f) => f.key)
  );
  // Every model-defined relationship type gets a filter (so it is drawn and
  // shows a legend chip when present in the data).
  for (const relType of VOCABULARIES.RelationshipType) {
    assert.ok(relKeys.has(relType), `graph filters are missing relationship type "${relType}"`);
  }
  // Conversely, no filter references a type the model doesn't define.
  for (const key of relKeys) {
    assert.ok(
      relationshipVocab.has(key),
      `graph filter rel key "${key}" is not an SPDX RelationshipType`
    );
  }
});

test('getRelationshipColor gives uncurated types a stable, distinct color', () => {
  // A valid but uncurated type must not collapse to one generic default color.
  assert.equal(getRelationshipColor('patchedBy'), getRelationshipColor('patchedBy')); // stable
  assert.notEqual(getRelationshipColor('patchedBy'), getRelationshipColor('amendedBy')); // distinct
  assert.match(getRelationshipColor('patchedBy'), /^hsl\(/); // derived, not the gray default
});
