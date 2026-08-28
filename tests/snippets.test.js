import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  getRelationshipGroupLabel,
  snippetFileRef,
  snippetLineLabel,
  snippetShortName,
  snippetTargetLabel
} from '../src/lib/relationships.js';
import { accessorsMixin } from '../src/app/accessors.js';
import { BUILD_SNIPPET_CLAIM } from '../src/config.js';
import { buildFileSourceIndex } from '../src/parser/parser.js';

// An SBOM produced with `west spdx --analyze-elf=snippets` names each snippet
// after the routine it covers, qualified by the file it was written in.
const FILE_ID = 'zephyr:files/File-cache-utils.c';
const HEADER_ID = 'zephyr:files/File-cache-utils.h';

const elementMap = new Map([
  [FILE_ID, { spdxId: FILE_ID, name: 'components/spi_flash/cache_utils.c' }],
  [HEADER_ID, { spdxId: HEADER_ID, name: 'components/spi_flash/include/cache_utils.h' }]
]);

const routine = {
  type: 'software_Snippet',
  spdxId: 'zephyr:snippets/1',
  name: 'spi_flash_restore_cache@components/spi_flash/cache_utils.c',
  software_snippetFromFile: FILE_ID,
  software_lineRange: { beginIntegerRange: 112, endIntegerRange: 118 }
};

const lineRange = {
  type: 'software_Snippet',
  spdxId: 'zephyr:snippets/2',
  name: 'components/spi_flash/cache_utils.c:112-114',
  software_snippetFromFile: FILE_ID,
  software_lineRange: { beginIntegerRange: 112, endIntegerRange: 114 }
};

describe('snippetShortName', () => {
  it('drops the file half of a routine snippet name', () => {
    assert.equal(snippetShortName(routine), 'spi_flash_restore_cache');
  });

  it('leaves a name with no file qualifier alone', () => {
    assert.equal(snippetShortName(lineRange), 'components/spi_flash/cache_utils.c:112-114');
  });

  it('is empty for an unnamed or missing snippet', () => {
    assert.equal(snippetShortName({ type: 'software_Snippet' }), '');
    assert.equal(snippetShortName(null), '');
  });

  it('keeps a leading @ rather than returning nothing', () => {
    assert.equal(snippetShortName({ name: '@odd' }), '@odd');
  });
});

describe('snippetTargetLabel', () => {
  it('reads as file then routine, without repeating the path', () => {
    assert.equal(
      snippetTargetLabel(routine, elementMap),
      'cache_utils.c › spi_flash_restore_cache'
    );
  });

  it('falls back to the line span when a snippet has no name', () => {
    const unnamed = { ...routine, name: '' };
    assert.equal(snippetTargetLabel(unnamed, elementMap), 'cache_utils.c › L112-118');
  });

  it('ignores anything that is not a snippet', () => {
    assert.equal(snippetTargetLabel({ type: 'software_File' }, elementMap), '');
  });
});

describe('snippetFileRef', () => {
  it('resolves the file a routine was carved from', () => {
    const ref = snippetFileRef(routine, elementMap);
    assert.equal(ref.fileId, FILE_ID);
    assert.equal(ref.baseName, 'cache_utils.c');
    assert.equal(ref.start, 112);
    assert.equal(ref.end, 118);
  });
});

describe('snippetLineLabel', () => {
  it('collapses a single-line range', () => {
    assert.equal(snippetLineLabel({ software_lineRange: { beginIntegerRange: 39 } }), 'L39');
  });

  it('is empty without line information', () => {
    assert.equal(snippetLineLabel({}), '');
  });
});

describe('hasSpecification labels', () => {
  // The header prototype that announces a routine, and the file that implements
  // it: read the pair as declares/implements rather than the raw type name.
  it('reads as declares/implements in both directions', () => {
    assert.equal(getRelationshipGroupLabel('hasSpecification', 'out'), 'Declared in');
    assert.equal(getRelationshipGroupLabel('hasSpecification', 'in'), 'Declares');
  });

  it('still falls back to the raw type for anything unmapped', () => {
    assert.equal(getRelationshipGroupLabel('somethingNew', 'out'), 'somethingNew');
  });
});

// A file several producers have carved snippets out of: the build says what
// reached the image (and, with --analyze-elf=snippet-lines, the ranges each
// routine is made of), a requirement says what implements it, a test run says
// what it executed. Those describe different builds -- sometimes different
// revisions of the file -- so they must not be merged or nested together.
function snippetGraph() {
  const FILE = 'f:thread.c';
  const el = (id, name, a, b) => ({
    spdxId: id,
    type: 'software_Snippet',
    name,
    software_snippetFromFile: FILE,
    software_lineRange: { beginIntegerRange: a, endIntegerRange: b }
  });
  const snippets = [
    el('s:routine', 'k_is_in_isr@kernel/thread.c', 73, 76),
    el('s:range1', 'kernel/thread.c:73-74', 73, 74),
    el('s:range2', 'kernel/thread.c:76-76', 76, 76),
    el('s:impl', 'k_is_in_isr @ kernel/thread.c:73-76', 73, 76),
    el('s:cov', 'kernel/thread.c:75-75', 75, 75),
    el('s:loose', 'kernel/thread.c:90-92', 90, 92)
  ];
  // A prototype in a header, and a macro range the routine pulled in from it.
  const HEADER = 'f:thread.h';
  const decl = el('s:decl', 'k_is_in_isr@kernel/thread.h', 12, 12);
  const macro = el('s:macro', 'kernel/thread.h:40-41', 40, 41);
  decl.software_snippetFromFile = HEADER;
  macro.software_snippetFromFile = HEADER;
  const elementMap = new Map([...snippets, decl, macro].map((s) => [s.spdxId, s]));
  elementMap.set(FILE, { spdxId: FILE, type: 'software_File', name: 'kernel/thread.c' });
  elementMap.set(HEADER, { spdxId: HEADER, type: 'software_File', name: 'kernel/thread.h' });
  const relationships = [
    { relationshipType: 'hasInput', from: 'b:build', to: ['s:routine'] },
    { relationshipType: 'contains', from: 's:routine', to: ['s:range1', 's:range2'] },
    { relationshipType: 'implementedBy', from: 'r:req', to: ['s:impl'] },
    { relationshipType: 'hasEvidence', from: 'e:eval', to: ['s:cov'] },
    { relationshipType: 'hasSpecification', from: 's:routine', to: ['s:decl'] },
    { relationshipType: 'contains', from: 's:routine', to: ['s:macro'] }
  ];
  return Object.assign(Object.create(accessorsMixin), {
    elementMap,
    relationships,
    snippetsByFileIndex: new Map([
      [FILE, snippets],
      [HEADER, [decl, macro]]
    ]),
    FILE,
    HEADER
  });
}

describe('fileSnippetOverlays', () => {
  it("groups a file's snippets by what claims them", () => {
    const app = snippetGraph();
    const labels = app.fileSnippetOverlays(app.FILE).map((o) => `${o.label} (${o.total})`);
    // Named by the same table the detail panel uses for an inbound
    // relationship, so a group means exactly what its relationship means.
    assert.deepEqual(labels, [
      'Input to builds (1)',
      'Implements (1)',
      'Evidence for (1)',
      'Other snippets (1)'
    ]);
  });

  it('nests contained ranges under their routine instead of listing them', () => {
    const app = snippetGraph();
    const image = app.fileSnippetOverlays(app.FILE)[0];
    assert.equal(image.rows.length, 1);
    assert.deepEqual(
      image.rows[0].children.map((c) => c.label),
      ['L73-74', 'L76']
    );
  });

  it('opens the build overlay and leaves the rest shut', () => {
    const app = snippetGraph();
    const [image, ...rest] = app.fileSnippetOverlays(app.FILE);
    assert.equal(image.key, BUILD_SNIPPET_CLAIM);
    assert.equal(image.openByDefault, true);
    assert.deepEqual(
      rest.map((o) => o.openByDefault),
      [false, false, false]
    );
  });

  it('keeps overlapping snippets from different producers apart', () => {
    // s:routine and s:impl cover the same lines of the same file, but come from
    // different builds; neither may absorb the other.
    const app = snippetGraph();
    const overlays = app.fileSnippetOverlays(app.FILE);
    const ids = overlays.flatMap((o) => o.rows.map((r) => r.id));
    assert.ok(ids.includes('s:routine') && ids.includes('s:impl'));
    assert.equal(new Set(ids).size, ids.length, 'a snippet appears in one overlay only');
  });

  it('has no overlays for a file nothing was carved from', () => {
    const app = snippetGraph();
    assert.deepEqual(app.fileSnippetOverlays('f:unknown'), []);
  });

  it('groups by a relationship it has never been told about', () => {
    const app = snippetGraph();
    app.relationships.push({ relationshipType: 'coordinatedBy', from: 'x:who', to: ['s:loose'] });
    const labels = app.fileSnippetOverlays(app.FILE).map((o) => o.label);
    assert.ok(!labels.includes('Other snippets'));
    assert.ok(labels.some((l) => /coordinated/i.test(l)));
  });
});

describe('fileSnippetOverlays: snippets nothing directly claims', () => {
  it('places a header prototype with the declarations, not with the leftovers', () => {
    const app = snippetGraph();
    const overlays = app.fileSnippetOverlays(app.HEADER);
    const decl = overlays.find((o) => o.rows.some((r) => r.id === 's:decl'));
    assert.equal(decl.label, 'Declares');
  });

  it('gives a range the provenance of the routine it is part of', () => {
    // The macro text lives in the header, but it reached the image through the
    // routine that expanded it, so that is what claims it.
    const app = snippetGraph();
    const overlays = app.fileSnippetOverlays(app.HEADER);
    const macro = overlays.find((o) => o.rows.some((r) => r.id === 's:macro'));
    assert.equal(macro.label, 'Input to builds');
  });

  it('names the routine a detached range came from', () => {
    const app = snippetGraph();
    const row = app
      .fileSnippetOverlays(app.HEADER)
      .flatMap((o) => o.rows)
      .find((r) => r.id === 's:macro');
    assert.equal(row.label, 'k_is_in_isr › L40-41');
  });

  it('still has a home for a snippet no chain of claims reaches', () => {
    const app = snippetGraph();
    const overlays = app.fileSnippetOverlays(app.FILE);
    const other = overlays.find((o) => o.key === 'other');
    assert.deepEqual(
      other.rows.map((r) => r.id),
      ['s:loose']
    );
  });
});

// Where a snippet's source can be fetched from, so its line ranges are drawn
// against the revision they were measured on.
function sourceGraph(pkg) {
  const files = [
    { spdxId: 'f:a', type: 'software_File', name: 'zephyr/include/zephyr/drivers/i2c.h' },
    { spdxId: 'f:b', type: 'software_File', name: 'zephyr/kernel/thread.c' }
  ];
  const elementMap = new Map(files.map((f) => [f.spdxId, f]));
  elementMap.set(pkg.spdxId, pkg);
  return [
    { packages: [pkg], elementMap },
    { containsIndex: new Map([[pkg.spdxId, ['f:a', 'f:b']]]) }
  ];
}

const SHA = '563a6fdf8e4ad2c7c97df74657fbbc4803266ffc';

describe('buildFileSourceIndex', () => {
  it('uses the download location when there is one', () => {
    const [parsed, idx] = sourceGraph({
      spdxId: 'p:z',
      name: 'zephyr-sources',
      software_downloadLocation: `git+https://github.com/zephyrproject-rtos/zephyr@${SHA}`
    });
    const src = buildFileSourceIndex(parsed, idx);
    assert.match(src.get('f:a'), new RegExp(`zephyrproject-rtos/zephyr/${SHA}/`));
  });

  it('falls back to the purl, which is where a commit may be the only record', () => {
    const [parsed, idx] = sourceGraph({
      spdxId: 'p:z',
      name: 'zephyr-sources',
      software_downloadLocation: 'NOASSERTION',
      software_packageVersion: '4.4.99',
      externalIdentifier: [
        {
          externalIdentifierType: 'packageUrl',
          identifier: `pkg:github/zephyrproject-rtos/zephyr@${SHA}`
        }
      ]
    });
    const src = buildFileSourceIndex(parsed, idx);
    assert.match(src.get('f:b'), new RegExp(`zephyrproject-rtos/zephyr/${SHA}/`));
  });

  it("reads through west's unconfirmed-revision suffix", () => {
    const [parsed, idx] = sourceGraph({
      spdxId: 'p:z',
      name: 'zephyr-sources',
      externalIdentifier: [
        {
          externalIdentifierType: 'packageUrl',
          identifier: `pkg:github/zephyrproject-rtos/zephyr@${SHA}-off`
        }
      ]
    });
    assert.match(buildFileSourceIndex(parsed, idx).get('f:a'), new RegExp(`/${SHA}/`));
  });

  it('resolves nothing rather than guessing a revision', () => {
    // Drawing real line ranges against the wrong revision of a file reads as a
    // bug in the SBOM; showing no source at all is the honest answer.
    const [parsed, idx] = sourceGraph({
      spdxId: 'p:z',
      name: 'zephyr-sources',
      software_downloadLocation: 'NOASSERTION',
      software_packageVersion: '4.4.99'
    });
    assert.equal(buildFileSourceIndex(parsed, idx).size, 0);
  });

  it('ignores a purl whose version is not a commit', () => {
    const [parsed, idx] = sourceGraph({
      spdxId: 'p:z',
      name: 'zephyr-sources',
      externalIdentifier: [
        {
          externalIdentifierType: 'packageUrl',
          identifier: 'pkg:github/zephyrproject-rtos/zephyr@v4.3.0'
        }
      ]
    });
    assert.equal(buildFileSourceIndex(parsed, idx).size, 0);
  });
});
