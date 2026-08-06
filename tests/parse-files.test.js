import assert from 'node:assert/strict';
import test from 'node:test';

import { describeJsonError, parseFiles } from '../src/parser/parse-files.js';

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

test('describeJsonError', async (t) => {
  await t.test('adds line/column when the message only has a position', () => {
    const source = '{"a": 1,\n "b": oops}';
    const pos = source.indexOf('oops');
    const err = new Error(`Unexpected token o in JSON at position ${pos}`);
    const out = describeJsonError(err, source);
    assert.match(out, /line 2 column 7/);
    assert.match(out, /near: .*"b": oops/);
  });

  await t.test('does not repeat line/column the engine already included', () => {
    const err = new Error(`Expected property name or '}' in JSON at position 2 (line 1 column 3)`);
    const out = describeJsonError(err, '{ not json');
    assert.equal(out.match(/line 1 column 3/g).length, 1);
    assert.match(out, /near: \{ not json/);
  });

  await t.test('passes through messages without a position', () => {
    const err = new Error('Unexpected end of JSON input');
    assert.equal(describeJsonError(err, ''), 'Unexpected end of JSON input');
  });

  await t.test('collapses whitespace in the excerpt', () => {
    const source = `{\n  "a": [\n    1,\n    2,\n  ]\n}`;
    const pos = source.lastIndexOf(']');
    const err = new Error(`Unexpected token ] in JSON at position ${pos}`);
    const out = describeJsonError(err, source);
    assert.match(out, /near: \{ "a": \[ 1, 2, \] \}/);
  });
});

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

  // Wrong-format files must fail loudly. Every shape below used to parse into
  // an empty model, dropping the user into an app with every view at zero.
  await t.test('rejects a CycloneDX BOM, naming file and format', async () => {
    const bom = JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5', components: [] });
    await assert.rejects(
      () => parseFiles([{ name: 'bom.json', text: bom }], noop),
      /bom\.json.*CycloneDX/
    );
  });

  await t.test('rejects an SPDX 2.x document, naming its version', async () => {
    const spdx2 = JSON.stringify({ spdxVersion: 'SPDX-2.3', SPDXID: 'SPDXRef-DOCUMENT' });
    await assert.rejects(
      () => parseFiles([{ name: 'old.json', text: spdx2 }], noop),
      /old\.json.*SPDX-2\.3/
    );
  });

  await t.test('rejects JSON with no @graph array', async () => {
    const lockfile = JSON.stringify({ name: 'my-app', lockfileVersion: 3, packages: {} });
    await assert.rejects(
      () => parseFiles([{ name: 'package-lock.json', text: lockfile }], noop),
      /package-lock\.json.*@graph/
    );
  });

  await t.test('rejects a blob-backed wrong-format file the same way', async () => {
    const bom = JSON.stringify({ bomFormat: 'CycloneDX', components: [] });
    await assert.rejects(
      () => parseFiles([{ name: 'bom.json', blob: new Blob([bom]) }], noop),
      /CycloneDX/
    );
  });

  await t.test('rejects when the merged graph has no elements', async () => {
    await assert.rejects(
      () => parseFiles([{ name: 'empty.json', text: doc([]) }], noop),
      /No SPDX elements found in empty\.json/
    );
  });

  await t.test('one wrong-format file fails the load even next to a valid one', async () => {
    const bom = JSON.stringify({ bomFormat: 'CycloneDX', components: [] });
    await assert.rejects(
      () =>
        parseFiles(
          [
            { name: 'a.json', text: doc([PKG]) },
            { name: 'bom.json', text: bom }
          ],
          noop
        ),
      /bom\.json.*CycloneDX/
    );
  });

  // JSON syntax errors point at where in the source the problem is.
  await t.test('malformed JSON errors include a source excerpt', async () => {
    await assert.rejects(
      () => parseFiles([{ name: 'broken.json', text: '{ not json' }], noop),
      /broken\.json.*near: \{ not json/
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
