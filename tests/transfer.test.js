import test from 'node:test';
import assert from 'node:assert/strict';

import { chunkEntries, decodeRefs, encodeRefs } from '../src/parser/transfer.js';

// A miniature of the parsed model's shape: element objects held by elementMap
// and referenced again from collections and indexes.
function model() {
  const a = { spdxId: 'a', type: 'Package', name: 'pkg-a' };
  const b = { spdxId: 'b', type: 'File', name: 'file-b' };
  const rel = { spdxId: 'r', type: 'Relationship', from: 'a', to: ['b'] };
  const elementMap = new Map([
    ['a', a],
    ['b', b],
    ['r', rel]
  ]);
  return {
    elementMap,
    a,
    b,
    rel,
    parsed: {
      packages: [a],
      files: [b],
      relationships: [rel],
      licenses: [{ id: 'MIT' }], // not an element: travels as itself
      docName: 'demo',
      rootElementIds: new Set(['a'])
    },
    indexes: { relFromIndex: new Map([['a', [rel]]]) }
  };
}

test('encodeRefs replaces elements with markers and leaves everything else', () => {
  const m = model();
  const encoded = encodeRefs(m.parsed, m.elementMap);

  assert.equal(typeof encoded.packages[0], 'string');
  assert.equal(typeof encoded.files[0], 'string');
  assert.equal(typeof encoded.relationships[0], 'string');
  assert.deepEqual(encoded.licenses, [{ id: 'MIT' }]);
  assert.equal(encoded.docName, 'demo');
  assert.equal(encoded.rootElementIds instanceof Set, true);

  // The original is untouched — the worker still needs it to encode the indexes.
  assert.equal(m.parsed.packages[0], m.a);
});

test('an object that merely looks like an element is not treated as one', () => {
  const m = model();
  // Same id, different object: not the one elementMap holds, so it is data.
  const impostor = { spdxId: 'a', type: 'Package', name: 'not-the-real-a' };
  const encoded = encodeRefs({ items: [impostor] }, m.elementMap);
  assert.equal(typeof encoded.items[0], 'object');
  assert.equal(encoded.items[0].name, 'not-the-real-a');
});

test('decodeRefs restores the identity the model relies on', () => {
  const m = model();
  const encoded = encodeRefs(m.parsed, m.elementMap);
  const encodedIndexes = encodeRefs(m.indexes, m.elementMap);

  // Simulate the boundary: the elements travel separately, as chunks.
  const rebuilt = new Map();
  for (const chunk of chunkEntries(m.elementMap, 2)) {
    for (const [id, el] of structuredClone(chunk)) rebuilt.set(id, el);
  }

  const parsed = decodeRefs(structuredClone(encoded), rebuilt);
  const indexes = decodeRefs(structuredClone(encodedIndexes), rebuilt);

  assert.equal(parsed.packages[0], rebuilt.get('a'), 'packages share with elementMap');
  assert.equal(parsed.files[0], rebuilt.get('b'), 'files share with elementMap');
  assert.equal(parsed.relationships[0], rebuilt.get('r'), 'relationships share');
  assert.equal(indexes.relFromIndex.get('a')[0], rebuilt.get('r'), 'indexes share');

  // Values survive the round trip.
  assert.equal(parsed.packages[0].name, 'pkg-a');
  assert.deepEqual(parsed.licenses, [{ id: 'MIT' }]);
  assert.equal(parsed.docName, 'demo');
  assert.deepEqual([...parsed.rootElementIds], ['a']);
});

test('chunkEntries splits a Map without losing or duplicating entries', () => {
  const map = new Map(Array.from({ length: 10 }, (_, i) => [String(i), { spdxId: String(i) }]));

  for (const size of [1, 3, 10, 25]) {
    const chunks = [...chunkEntries(map, size)];
    assert.equal(chunks.length, Math.ceil(10 / size), `chunk count at size ${size}`);
    assert.ok(
      chunks.every((c) => c.length <= size),
      `no chunk exceeds ${size}`
    );
    assert.deepEqual(
      chunks.flat().map(([k]) => k),
      [...map.keys()],
      `entries preserved in order at size ${size}`
    );
  }

  assert.deepEqual([...chunkEntries(new Map(), 100)], [], 'an empty map yields no chunks');
});
