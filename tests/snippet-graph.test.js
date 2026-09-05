import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildFileSourceIndex,
  buildRelationshipIndexes,
  parseGraph
} from '../src/parser/parser.js';
import {
  byteRangeToLineRange,
  collectSnippetHubIds,
  fileHttpSourceUrl,
  getDetailPromotedFields,
  normalizeSourceFetchUrl,
  resolveGraphSnippetEndpoint,
  snippetFileRef,
  snippetTargetLabel
} from '../src/lib/index.js';
import { createGraphFilters } from '../src/config.js';
import { spdxApp } from '../src/app.js';

const zephyrLeaf = {
  type: 'software_Snippet',
  spdxId: 'snip:thread',
  name: 'z_impl_k_thread_create @ kernel/thread.c:1018-1032',
  software_snippetFromFile: 'file:thread',
  software_lineRange: { beginIntegerRange: 1018, endIntegerRange: 1032 }
};

const basilHub = {
  type: 'software_Snippet',
  spdxId: 'snip:api-1',
  name: 'https://example.com/spec.md',
  software_snippetFromFile: 'file:spec',
  software_byteRange: { beginIntegerRange: 40, endIntegerRange: 68 }
};

const basilContainedOnly = {
  type: 'software_Snippet',
  spdxId: 'snip:api-2',
  name: 'https://example.com/spec.md',
  software_snippetFromFile: 'file:spec',
  software_byteRange: { beginIntegerRange: 90, endIntegerRange: 110 }
};

test('collectSnippetHubIds treats Zephyr implementedBy targets as leaves', () => {
  const hubs = collectSnippetHubIds(
    [zephyrLeaf],
    [
      {
        from: 'req:srs',
        relationshipType: 'implementedBy',
        to: ['snip:thread']
      }
    ]
  );
  assert.equal(hubs.size, 0);
});

test('collectSnippetHubIds marks a snippet that has outgoing work items as a hub', () => {
  const hubs = collectSnippetHubIds(
    [basilHub],
    [
      { from: 'file:api', relationshipType: 'contains', to: ['snip:api-1'] },
      { from: 'snip:api-1', relationshipType: 'hasRequirement', to: ['file:req'] }
    ]
  );
  assert.deepEqual([...hubs], ['snip:api-1']);
});

test('collectSnippetHubIds marks a contains target whose parent is not snippetFromFile', () => {
  const hubs = collectSnippetHubIds(
    [basilContainedOnly],
    [{ from: 'file:api', relationshipType: 'contains', to: ['snip:api-2'] }]
  );
  assert.ok(hubs.has('snip:api-2'));
});

test('collectSnippetHubIds does not treat file-contains-own-snippet as a hub', () => {
  const hubs = collectSnippetHubIds(
    [zephyrLeaf],
    [{ from: 'file:thread', relationshipType: 'contains', to: ['snip:thread'] }]
  );
  assert.equal(hubs.size, 0);
});

test('resolveGraphSnippetEndpoint redirects leaves and keeps hubs', () => {
  const elementMap = new Map([
    [zephyrLeaf.spdxId, zephyrLeaf],
    [basilHub.spdxId, basilHub],
    ['file:thread', { type: 'software_File', name: 'kernel/thread.c' }],
    ['file:spec', { type: 'software_File', name: 'spec.md' }]
  ]);
  const snippetIds = new Set([zephyrLeaf.spdxId, basilHub.spdxId]);
  const hubIds = new Set([basilHub.spdxId]);

  const leaf = resolveGraphSnippetEndpoint(zephyrLeaf.spdxId, {
    snippetIds,
    hubIds,
    elementMap
  });
  assert.equal(leaf.id, 'file:thread');
  assert.ok(leaf.snippet);

  const hub = resolveGraphSnippetEndpoint(basilHub.spdxId, {
    snippetIds,
    hubIds,
    elementMap
  });
  assert.equal(hub.id, basilHub.spdxId);
  assert.equal(hub.snippet, null);

  const plain = resolveGraphSnippetEndpoint('file:api', { snippetIds, hubIds, elementMap });
  assert.equal(plain.id, 'file:api');
  assert.equal(plain.snippet, null);
});

test('parseGraph advertises snippet nodes only when hubs are present', () => {
  const zephyr = parseGraph([
    { type: 'software_File', spdxId: 'file:thread', name: 'kernel/thread.c' },
    zephyrLeaf,
    { type: 'Requirement', spdxId: 'req:srs', name: 'Create thread' },
    {
      type: 'Relationship',
      spdxId: 'rel:impl',
      relationshipType: 'implementedBy',
      from: 'req:srs',
      to: ['snip:thread']
    }
  ]);
  assert.equal(zephyr.snippets.length, 1);
  assert.equal(zephyr.snippetHubIds.size, 0);
  assert.ok(!zephyr.presentNodeTypes.includes('snippet'));

  const basil = parseGraph([
    { type: 'software_File', spdxId: 'file:api', name: 'API' },
    { type: 'software_File', spdxId: 'file:spec', name: 'spec.md' },
    {
      type: 'software_File',
      spdxId: 'file:req',
      name: 'SW req',
      software_primaryPurpose: 'requirement'
    },
    basilHub,
    {
      type: 'Relationship',
      spdxId: 'rel:contains',
      relationshipType: 'contains',
      from: 'file:api',
      to: ['snip:api-1']
    },
    {
      type: 'Relationship',
      spdxId: 'rel:req',
      relationshipType: 'hasRequirement',
      from: 'snip:api-1',
      to: ['file:req']
    }
  ]);
  assert.ok(basil.snippetHubIds.has('snip:api-1'));
  assert.ok(basil.presentNodeTypes.includes('snippet'));
  assert.ok(basil.presentRelTypes.includes('hasRequirement'));
  assert.equal(snippetTargetLabel(basilHub, basil.elementMap), 'spec.md › bytes 40-68');
});

test('graph legend includes a Snippets toggle when hub snippets are present', () => {
  const parsed = parseGraph([
    { type: 'software_File', spdxId: 'file:api', name: 'API' },
    { type: 'software_File', spdxId: 'file:spec', name: 'spec.md' },
    basilHub,
    {
      type: 'Relationship',
      relationshipType: 'contains',
      from: 'file:api',
      to: ['snip:api-1']
    },
    {
      type: 'Relationship',
      relationshipType: 'hasRequirement',
      from: 'snip:api-1',
      to: ['file:req']
    }
  ]);

  const app = spdxApp();
  app.presentNodeTypes = parsed.presentNodeTypes;
  app.presentRelTypes = parsed.presentRelTypes;
  const keys = app.visibleGraphFilters.map((f) => f.key);
  assert.ok(keys.includes('snippet'));
  assert.ok(createGraphFilters().some((f) => f.key === 'snippet' && !f.isRel));
});

test('detailRelGroupsFor lists hub snippets individually instead of folding them', () => {
  const parsed = parseGraph([
    { type: 'software_File', spdxId: 'file:api', name: 'API' },
    { type: 'software_File', spdxId: 'file:spec', name: 'spec.md' },
    basilHub,
    basilContainedOnly,
    {
      type: 'Relationship',
      relationshipType: 'contains',
      from: 'file:api',
      to: ['snip:api-1', 'snip:api-2']
    },
    {
      type: 'Relationship',
      relationshipType: 'hasRequirement',
      from: 'snip:api-1',
      to: ['file:req']
    }
  ]);
  const app = spdxApp();
  app.elementMap = parsed.elementMap;
  app.snippetHubIds = parsed.snippetHubIds;
  const rel = buildRelationshipIndexes(parsed.relationships);
  app.relFromIndex = rel.relFromIndex;
  app.relToIndex = rel.relToIndex;

  const group = app
    .detailRelGroupsFor({ spdxId: 'file:api' })
    .find((g) => g.key === 'contains:out');
  assert.equal(group.total, 2);
  assert.ok(group.items.every((i) => !i.multiRange));
  assert.deepEqual(group.items.map((i) => i.id).sort(), ['snip:api-1', 'snip:api-2']);
});

test('snippetFileRef exposes line, byte, and a display range label', () => {
  const map = new Map([['file:spec', { type: 'software_File', name: 'spec.md' }]]);
  const bytes = snippetFileRef(basilHub, map);
  assert.equal(bytes.byteStart, 40);
  assert.equal(bytes.byteEnd, 68);
  assert.equal(bytes.start, null);
  assert.equal(bytes.rangeLabel, 'bytes 40-68');

  const lines = snippetFileRef(zephyrLeaf, new Map());
  assert.equal(lines.start, 1018);
  assert.equal(lines.end, 1032);
  assert.equal(lines.rangeLabel, 'L1018-1032');
});

test('getDetailPromotedFields lists snippet ranges and the source file', () => {
  const map = new Map([
    ['file:spec', { type: 'software_File', name: 'docs/spec.md' }],
    ['file:thread', { type: 'software_File', name: 'kernel/thread.c' }]
  ]);

  const basilFields = getDetailPromotedFields(basilHub, map);
  assert.deepEqual(
    basilFields.map((f) => [f.label, f.value]),
    [
      ['Bytes', '40-68'],
      ['From file', 'docs/spec.md']
    ]
  );

  const both = getDetailPromotedFields(
    {
      ...zephyrLeaf,
      software_byteRange: { beginIntegerRange: 200, endIntegerRange: 400 },
      software_primaryPurpose: 'source'
    },
    map
  );
  assert.deepEqual(
    both.map((f) => [f.label, f.value]),
    [
      ['Purpose', 'source'],
      ['Lines', '1018-1032'],
      ['Bytes', '200-400'],
      ['From file', 'kernel/thread.c']
    ]
  );
});

test('normalizeSourceFetchUrl rewrites GitHub blob and raw pages', () => {
  assert.equal(
    normalizeSourceFetchUrl('https://github.com/elisa-tech/BASIL/blob/main/README.md'),
    'https://raw.githubusercontent.com/elisa-tech/BASIL/main/README.md'
  );
  assert.equal(
    normalizeSourceFetchUrl('https://github.com/elisa-tech/BASIL/raw/main/README.md'),
    'https://raw.githubusercontent.com/elisa-tech/BASIL/main/README.md'
  );
  assert.equal(
    fileHttpSourceUrl({
      name: 'https://raw.githubusercontent.com/elisa-tech/BASIL/main/README.md'
    }),
    'https://raw.githubusercontent.com/elisa-tech/BASIL/main/README.md'
  );
});

test('byteRangeToLineRange maps 1-based bytes onto lines', () => {
  const text = 'one\ntwo\nthree\n';
  assert.deepEqual(byteRangeToLineRange(text, 1, 3), { start: 1, end: 1 });
  assert.deepEqual(byteRangeToLineRange(text, 5, 7), { start: 2, end: 2 });
  assert.deepEqual(byteRangeToLineRange(text, 1, 10), { start: 1, end: 3 });
});

test('buildFileSourceIndex uses an http(s) File name when no sources package exists', () => {
  const parsed = parseGraph([
    {
      type: 'software_File',
      spdxId: 'file:spec',
      name: 'https://raw.githubusercontent.com/elisa-tech/BASIL/main/README.md',
      software_primaryPurpose: 'specification'
    },
    basilHub
  ]);
  const indexes = buildRelationshipIndexes(parsed.relationships);
  const src = buildFileSourceIndex(parsed, indexes);
  assert.equal(
    src.get('file:spec'),
    'https://raw.githubusercontent.com/elisa-tech/BASIL/main/README.md'
  );
});
