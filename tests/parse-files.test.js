import assert from 'node:assert/strict';
import test from 'node:test';

import { parseFiles } from '../src/parser/parse-files.js';

// A file's @graph as the worker receives it, either shape.
function doc(items) {
  return JSON.stringify({ '@graph': items });
}

const PKG = {
  spdxId: 'urn:pkg-a',
  type: 'software_Package',
  name: 'pkg-a'
};
const FILE = {
  spdxId: 'urn:file-a',
  type: 'software_File',
  name: 'src/a.c'
};
const REL = {
  spdxId: 'urn:rel-1',
  type: 'Relationship',
  relationshipType: 'contains',
  from: 'urn:pkg-a',
  to: ['urn:file-a']
};

const noop = () => {};

test('parse-files', async (t) => {
  await t.test('parses a file given as text', async () => {
    const { parsed } = await parseFiles([{ name: 'a.json', text: doc([PKG, FILE, REL]) }], noop);
    assert.equal(parsed.packages.length, 1);
    assert.equal(parsed.files.length, 1);
    assert.equal(parsed.relationships.length, 1);
  });

  // Files big enough that decoding them on the main thread would stall the UI
  // are handed over as a Blob instead; below the streaming threshold they take
  // the same JSON.parse path, just read here rather than by the caller.
  await t.test('parses a file given as a blob, identically to its text', async () => {
    const json = doc([PKG, FILE, REL]);
    const fromText = await parseFiles([{ name: 'a.json', text: json }], noop);
    const fromBlob = await parseFiles([{ name: 'a.json', blob: new Blob([json]) }], noop);
    assert.deepEqual(
      fromBlob.parsed.packages.map((p) => p.spdxId),
      fromText.parsed.packages.map((p) => p.spdxId)
    );
    assert.deepEqual(
      fromBlob.parsed.files.map((f) => f.spdxId),
      fromText.parsed.files.map((f) => f.spdxId)
    );
    assert.equal(fromBlob.parsed.relationships.length, fromText.parsed.relationships.length);
  });

  await t.test('merges text and blob files into one graph', async () => {
    const { parsed } = await parseFiles(
      [
        { name: 'a.json', text: doc([PKG]) },
        { name: 'b.json', blob: new Blob([doc([FILE, REL])]) }
      ],
      noop
    );
    assert.equal(parsed.packages.length, 1);
    assert.equal(parsed.files.length, 1);
    assert.equal(parsed.relationships.length, 1);
    // The cross-file relationship resolves: b.json's edge finds a.json's package.
    assert.ok(parsed.elementMap.get('urn:pkg-a'));
  });

  await t.test('accepts a bare top-level array in a blob', async () => {
    const { parsed } = await parseFiles(
      [{ name: 'a.json', blob: new Blob([JSON.stringify([PKG])]) }],
      noop
    );
    assert.equal(parsed.packages.length, 1);
  });

  await t.test('names the offending file when a blob holds bad JSON', async () => {
    await assert.rejects(
      () => parseFiles([{ name: 'broken.json', blob: new Blob(['{ not json']) }], noop),
      /broken\.json/
    );
  });

  await t.test('reports progress across both file shapes', async () => {
    const seen = [];
    await parseFiles(
      [
        { name: 'a.json', text: doc([PKG]) },
        { name: 'b.json', blob: new Blob([doc([FILE])]) }
      ],
      (phase, value) => {
        if (phase === 'json') seen.push(value);
      }
    );
    assert.ok(seen.length >= 2, 'each file advances the json phase');
    assert.equal(seen[seen.length - 1], 1, 'the json phase ends at 1');
    for (let i = 1; i < seen.length; i++) {
      assert.ok(seen[i] >= seen[i - 1], 'json progress is monotonic');
    }
  });
});
