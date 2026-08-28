import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  requirementDisplayName,
  specificationFacetLabel,
  buildSafetySpecFacets,
  isProducerMetaIdentifier,
  producerMetaValue
} from '../src/lib/safety.js';
import { isA, CLASS } from '../src/spdx/model.js';

describe('requirementDisplayName', () => {
  it('strips an embedded requirementUID prefix', () => {
    const el = {
      name: 'SG-01: Prevent unintended emergency braking',
      requirementUID: { identifier: 'SG-01' }
    };
    assert.equal(requirementDisplayName(el), 'Prevent unintended emergency braking');
  });

  it('strips a matching external identifier prefix', () => {
    const el = { name: 'ZEP-SRS-1-1: Creating threads' };
    const name = requirementDisplayName(el, () => [{ identifier: 'ZEP-SRS-1-1' }]);
    assert.equal(name, 'Creating threads');
  });

  it('keeps the full name when the prefix is not a known UID', () => {
    assert.equal(
      requirementDisplayName({ name: 'Note: something else' }, () => []),
      'Note: something else'
    );
  });
});

describe('specificationFacetLabel', () => {
  it('prefers the human part after a CODE: prefix', () => {
    assert.equal(specificationFacetLabel({ name: 'DESIGN-SEMAPHORES: Semaphores' }), 'Semaphores');
  });
});

describe('isProducerMetaIdentifier', () => {
  it('detects StrictDoc-style meta prefixes', () => {
    assert.equal(isProducerMetaIdentifier('adequacy:no-impl'), true);
    assert.equal(isProducerMetaIdentifier('status:Draft'), true);
    assert.equal(isProducerMetaIdentifier('evidence:passing'), true);
    assert.equal(isProducerMetaIdentifier('component:Threads'), true);
    assert.equal(isProducerMetaIdentifier('requirement-level:system'), true);
    assert.equal(isProducerMetaIdentifier('ZEP-SRS-1-1'), false);
  });
});

describe('producerMetaValue', () => {
  const el = {
    externalIdentifier: [
      { identifier: 'ZEP-SRS-1-1' },
      { identifier: 'adequacy:broken' },
      { identifier: 'evidence:passing' }
    ]
  };

  it('reads the value of a prefixed producer identifier', () => {
    assert.equal(producerMetaValue(el, 'adequacy'), 'broken');
    assert.equal(producerMetaValue(el, 'evidence'), 'passing');
  });

  it('returns an empty string when the element carries none', () => {
    assert.equal(producerMetaValue(el, 'component'), '');
    assert.equal(producerMetaValue(null, 'adequacy'), '');
  });

  it('reads through a supplied accessor', () => {
    assert.equal(
      producerMetaValue({}, 'adequacy', () => [{ identifier: 'adequacy:true' }]),
      'true'
    );
  });
});

describe('buildSafetySpecFacets', () => {
  it('groups requirements under Specification hasRequirement edges', () => {
    const elementMap = new Map([
      ['spec:sem', { spdxId: 'spec:sem', type: 'Specification', name: 'DESIGN-SEM: Semaphores' }],
      ['spec:other', { spdxId: 'spec:other', type: 'Specification', name: 'Other' }],
      ['req:1', { spdxId: 'req:1', type: 'Requirement', name: 'R1' }],
      ['req:2', { spdxId: 'req:2', type: 'Requirement', name: 'R2' }]
    ]);
    const relationships = [
      {
        relationshipType: 'hasRequirement',
        from: 'spec:sem',
        to: ['req:1', 'req:2']
      },
      {
        relationshipType: 'hasRequirement',
        from: 'spec:other',
        to: ['req:1']
      },
      {
        relationshipType: 'verifiedBy',
        from: 'req:1',
        to: ['ver:1']
      }
    ];
    const facets = buildSafetySpecFacets(
      relationships,
      elementMap,
      isA,
      CLASS.Specification,
      new Set(['req:1', 'req:2'])
    );
    assert.equal(facets.length, 2);
    assert.equal(facets[0].id, 'spec:sem');
    assert.equal(facets[0].label, 'Semaphores');
    assert.equal(facets[0].count, 2);
    assert.equal(facets[1].count, 1);
  });

  it('returns an empty list when no Specification hasRequirement links exist', () => {
    const facets = buildSafetySpecFacets(
      [{ relationshipType: 'verifiedBy', from: 'r', to: ['v'] }],
      new Map(),
      isA,
      CLASS.Specification,
      new Set()
    );
    assert.deepEqual(facets, []);
  });
});
