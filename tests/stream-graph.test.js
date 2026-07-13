import assert from 'node:assert/strict';
import test from 'node:test';

import { forEachGraphItem } from '../src/parser/stream-graph.js';

// Collect every @graph item from a JSON string, reading it back through Blob so
// the code path matches the browser (Blob.stream + TextDecoder).
async function collect(json, chunkSize) {
  const blob = chunkSize ? new ChunkyBlob(json, chunkSize) : new Blob([json]);
  const items = [];
  let lastProgress = 0;
  await forEachGraphItem(
    blob,
    (it) => items.push(it),
    (n) => {
      assert.ok(n >= lastProgress, 'progress is monotonic');
      lastProgress = n;
    }
  );
  return items;
}

// A Blob whose stream yields tiny fixed-size chunks, to exercise splits at every
// possible boundary (mid-string, mid-element, mid-key). Only the surface
// forEachGraphItem touches (size + stream) is implemented.
class ChunkyBlob {
  constructor(text, chunkSize) {
    this.bytes = new TextEncoder().encode(text);
    this.size = this.bytes.length;
    this._chunk = chunkSize;
  }
  stream() {
    const { bytes, _chunk } = this;
    let i = 0;
    return new ReadableStream({
      pull(controller) {
        if (i >= bytes.length) {
          controller.close();
          return;
        }
        controller.enqueue(bytes.slice(i, i + _chunk));
        i += _chunk;
      }
    });
  }
}

test('extracts @graph items from a normal document', async () => {
  const doc = {
    '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
    '@graph': [
      { spdxId: 'a', type: 'software_Package' },
      { spdxId: 'b', type: 'software_File', name: 'x.c' }
    ]
  };
  const items = await collect(JSON.stringify(doc));
  assert.equal(items.length, 2);
  assert.equal(items[0].spdxId, 'a');
  assert.equal(items[1].name, 'x.c');
});

test('handles a bare top-level array', async () => {
  const items = await collect(JSON.stringify([{ spdxId: 'a' }, { spdxId: 'b' }, { spdxId: 'c' }]));
  assert.deepEqual(
    items.map((i) => i.spdxId),
    ['a', 'b', 'c']
  );
});

test('is robust to tiny chunk boundaries', async () => {
  const doc = {
    '@context': ['x', 'y'],
    '@graph': [
      { spdxId: 'a', s: 'has } and ] and " escaped \\" braces {[' },
      { spdxId: 'b', nested: { deep: [1, 2, { k: '@graph' }] } },
      { spdxId: 'c', s: 'comma, and : colon' }
    ]
  };
  const json = JSON.stringify(doc);
  for (const chunk of [1, 2, 3, 5, 7, 13, 64]) {
    const items = await collect(json, chunk);
    assert.equal(items.length, 3, `chunk=${chunk}`);
    assert.equal(items[0].s, 'has } and ] and " escaped \\" braces {[', `chunk=${chunk}`);
    assert.equal(items[1].nested.deep[2].k, '@graph', `chunk=${chunk}`);
    assert.equal(items[2].s, 'comma, and : colon', `chunk=${chunk}`);
  }
});

test('decodes multi-byte UTF-8 split across chunk boundaries', async () => {
  // Names/values with accents, CJK, and emoji encode to 2-4 bytes; tiny byte
  // chunks split them mid-character, which the streaming decoder must stitch
  // back together (and flush at the end).
  const doc = {
    '@graph': [
      { spdxId: 'a', name: 'Benjamin Cabé' },
      { spdxId: 'b', name: '零之执行者 — 🚀🛰️' }
    ]
  };
  const json = JSON.stringify(doc);
  for (const chunk of [1, 2, 3, 5]) {
    const items = await collect(json, chunk);
    assert.equal(items.length, 2, `chunk=${chunk}`);
    assert.equal(items[0].name, 'Benjamin Cabé', `chunk=${chunk}`);
    assert.equal(items[1].name, '零之执行者 — 🚀🛰️', `chunk=${chunk}`);
  }
});

test('does not false-match @graph appearing as a value before the key', async () => {
  const doc = {
    note: '@graph',
    '@graph': [{ spdxId: 'real' }]
  };
  const items = await collect(JSON.stringify(doc), 3);
  assert.equal(items.length, 1);
  assert.equal(items[0].spdxId, 'real');
});

test('missing @graph yields no items', async () => {
  const items = await collect(JSON.stringify({ '@context': 'x', creationInfo: {} }));
  assert.equal(items.length, 0);
});

test('empty @graph yields no items', async () => {
  const items = await collect(JSON.stringify({ '@graph': [] }));
  assert.equal(items.length, 0);
});

test('surfaces a malformed element with context', async () => {
  // A truncated element (missing closing brace never balances) simply never
  // emits; a syntactically broken but balanced element throws on parse.
  const bad = '{"@graph":[{"a":1 "b":2}]}'; // missing comma
  await assert.rejects(() => collect(bad), /graph item:/);
});
