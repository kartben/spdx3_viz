import assert from 'node:assert/strict';
import test from 'node:test';

import { collectSnippetHubIds, resolveGraphSnippetEndpoint } from '../src/lib/index.js';

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
