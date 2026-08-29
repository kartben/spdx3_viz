import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  requirementDisplayName,
  specificationFacetLabel,
  buildSafetySpecFacets,
  isProducerMetaIdentifier,
  producerMetaValue
} from '../src/lib/safety.js';
import {
  snippetSymbolLabel,
  snippetCompactLine,
  snippetTargetLabel,
  snippetFileGroupLabel,
  snippetGroupLineCount,
  groupSnippetsByFile
} from '../src/lib/relationships.js';
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

describe('snippet labels', () => {
  it('extracts the function from a producer "func @ path:lines" name', () => {
    const el = {
      type: 'software_Snippet',
      name: 'z_impl_k_thread_create @ kernel/thread.c:1018-1032',
      software_lineRange: { beginIntegerRange: 1018, endIntegerRange: 1032 }
    };
    assert.equal(snippetSymbolLabel(el), 'z_impl_k_thread_create');
    assert.equal(snippetCompactLine(el), '1018-1032');
  });

  it('falls back to the line span for coverage-style path:lines names', () => {
    const el = {
      type: 'software_Snippet',
      name: 'kernel/thread.c:1018-1018',
      software_lineRange: { beginIntegerRange: 1018, endIntegerRange: 1018 }
    };
    assert.equal(snippetSymbolLabel(el), 'L1018');
    assert.equal(snippetCompactLine(el), '1018');
  });

  it('labels a snippet as file › symbol, without repeating the path', () => {
    const el = {
      type: 'software_Snippet',
      name: 'z_impl_k_thread_create @ kernel/thread.c:1018-1032',
      software_snippetFromFile: 'file:a',
      software_lineRange: { beginIntegerRange: 1018, endIntegerRange: 1032 }
    };
    const map = new Map([['file:a', { type: 'software_File', name: 'kernel/thread.c' }]]);
    assert.equal(snippetTargetLabel(el, map), 'thread.c › z_impl_k_thread_create');
  });

  it('lists several symbols of one file instead of "N ranges"', () => {
    const a = {
      name: 'z_impl_k_thread_create @ kernel/thread.c:1018-1032',
      software_lineRange: { beginIntegerRange: 1018, endIntegerRange: 1032 }
    };
    const b = {
      name: 'z_vrfy_k_thread_create @ kernel/thread.c:1051-1112',
      software_lineRange: { beginIntegerRange: 1051, endIntegerRange: 1112 }
    };
    assert.equal(
      snippetFileGroupLabel('thread.c', [a, b]),
      'thread.c › z_impl_k_thread_create, z_vrfy_k_thread_create'
    );
  });
});

describe('groupSnippetsByFile', () => {
  const fileA = { type: 'software_File', spdxId: 'file:a', name: 'kernel/thread.c' };
  const fileB = { type: 'software_File', spdxId: 'file:b', name: 'kernel/sched.c' };
  const map = new Map([
    ['file:a', fileA],
    ['file:b', fileB]
  ]);

  it('groups snippets of the same file and keeps non-snippets aside', () => {
    const snippets = [
      {
        type: 'software_Snippet',
        spdxId: 's2',
        name: 'beta @ kernel/thread.c:20-30',
        software_snippetFromFile: 'file:a',
        software_lineRange: { beginIntegerRange: 20, endIntegerRange: 30 }
      },
      {
        type: 'software_Snippet',
        spdxId: 's1',
        name: 'alpha @ kernel/thread.c:1-5',
        software_snippetFromFile: 'file:a',
        software_lineRange: { beginIntegerRange: 1, endIntegerRange: 5 }
      },
      {
        type: 'software_Snippet',
        spdxId: 's3',
        software_snippetFromFile: 'file:b',
        software_lineRange: { beginIntegerRange: 8, endIntegerRange: 9 }
      },
      { type: 'software_Package', spdxId: 'pkg:1', name: 'lib' }
    ];
    const grouped = groupSnippetsByFile(snippets, map);
    assert.equal(grouped.files.length, 2);
    const thread = grouped.files.find((f) => f.baseName === 'thread.c');
    assert.deepEqual(
      thread.snippets.map((s) => s.label),
      ['alpha', 'beta']
    );
    assert.deepEqual(thread.snippetIds, ['s1', 's2']);
    // alpha 1-5 (5) + beta 20-30 (11), no overlap.
    assert.equal(thread.lineCount, 16);
    assert.equal(grouped.others.length, 1);
    assert.equal(grouped.others[0].spdxId, 'pkg:1');
  });

  it('counts unique lines across overlapping ranges', () => {
    assert.equal(
      snippetGroupLineCount([
        { start: 10, end: 20 },
        { start: 15, end: 25 },
        { start: 40, end: 40 }
      ]),
      17
    );
  });

  it('dedupes identical coverage ranges of one file', () => {
    const snippets = [
      {
        type: 'software_Snippet',
        spdxId: 'c1',
        name: 'kernel/thread.c:1018-1018',
        software_snippetFromFile: 'file:a',
        software_lineRange: { beginIntegerRange: 1018, endIntegerRange: 1018 }
      },
      {
        type: 'software_Snippet',
        spdxId: 'c2',
        name: 'kernel/thread.c:1018-1018',
        software_snippetFromFile: 'file:a',
        software_lineRange: { beginIntegerRange: 1018, endIntegerRange: 1018 }
      },
      {
        type: 'software_Snippet',
        spdxId: 'c3',
        name: 'kernel/thread.c:1024-1024',
        software_snippetFromFile: 'file:a',
        software_lineRange: { beginIntegerRange: 1024, endIntegerRange: 1024 }
      }
    ];
    const grouped = groupSnippetsByFile(snippets, map, { dedupeRanges: true });
    assert.equal(grouped.files.length, 1);
    assert.deepEqual(
      grouped.files[0].snippets.map((s) => s.label),
      ['L1018', 'L1024']
    );
  });
});
