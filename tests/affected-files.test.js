import assert from 'node:assert/strict';
import test from 'node:test';

import {
  summarizeCveRecord,
  normalizeSourcePath,
  buildFileIndex,
  matchAffectedFile,
  linkAffectedFiles,
  buildAffectedFileRelationships,
  cveAffectedRow,
  isRuledOutStatus,
  effectiveVexStatus,
  annotateAffectedFiles,
  summarizeAffectedFiles
} from '../src/lib/index.js';

// A trimmed but structurally real CVE 5.x record, shaped like the Linux kernel
// CNA's output: per-version `affected` entries that repeat programFiles /
// programRoutines, plus an ADP container that adds another file.
const KERNEL_RECORD = {
  cveMetadata: { cveId: 'CVE-2024-26581', state: 'PUBLISHED', assignerShortName: 'Linux' },
  containers: {
    cna: {
      affected: [
        {
          product: 'Linux',
          programFiles: ['net/netfilter/nft_set_rbtree.c'],
          programRoutines: [{ name: 'nft_rbtree_gc' }, { name: 'nft_rbtree_gc_elem' }],
          versions: [{ version: '6.7', status: 'affected' }]
        },
        {
          product: 'Linux',
          programFiles: ['net/netfilter/nft_set_rbtree.c'], // repeated across versions
          programRoutines: [{ name: 'nft_rbtree_gc' }],
          versions: [{ version: '6.6', status: 'affected' }]
        }
      ],
      descriptions: [{ lang: 'en', value: 'netfilter: nft_set_rbtree fix.' }]
    },
    adp: [
      {
        affected: [{ programFiles: ['include/net/netfilter/nf_tables.h'], modules: ['netfilter'] }]
      }
    ]
  }
};

test('summarizeCveRecord extracts and de-dupes affected files/functions/modules', () => {
  const s = summarizeCveRecord(KERNEL_RECORD);
  assert.deepEqual(s.affectedFiles, [
    'net/netfilter/nft_set_rbtree.c',
    'include/net/netfilter/nf_tables.h'
  ]);
  assert.deepEqual(s.affectedRoutines, ['nft_rbtree_gc', 'nft_rbtree_gc_elem']);
  assert.deepEqual(s.affectedModules, ['netfilter']);
});

test('summarizeCveRecord tolerates string program routines and missing fields', () => {
  const s = summarizeCveRecord({
    cveMetadata: { cveId: 'CVE-0000-0000' },
    containers: { cna: { affected: [{ programRoutines: ['do_thing', { name: 'do_other' }] }] } }
  });
  assert.deepEqual(s.affectedFiles, []);
  assert.deepEqual(s.affectedRoutines, ['do_thing', 'do_other']);
  assert.deepEqual(s.affectedModules, []);
});

test('summarizeCveRecord yields empty arrays when no affected data is present', () => {
  const s = summarizeCveRecord({ cveMetadata: { cveId: 'CVE-1-1' }, containers: { cna: {} } });
  assert.deepEqual(s.affectedFiles, []);
  assert.deepEqual(s.affectedRoutines, []);
  assert.deepEqual(s.affectedModules, []);
});

test('normalizeSourcePath strips ./ and leading slashes, normalizes separators', () => {
  assert.equal(normalizeSourcePath('./net/x.c'), 'net/x.c');
  assert.equal(normalizeSourcePath('/net//x.c'), 'net/x.c');
  assert.equal(normalizeSourcePath('net\\netfilter\\x.c'), 'net/netfilter/x.c');
  assert.equal(normalizeSourcePath('net/x.c/'), 'net/x.c');
});

// A File set shaped like a real source-inclusive SBOM: repo-root-relative
// names, some project-dir-prefixed, and a couple of colliding basenames.
const FILES = [
  { spdxId: 'F1', name: 'net/netfilter/nft_set_rbtree.c' }, // exact
  { spdxId: 'F2', name: 'linux/fs/ext4/mballoc.c' }, // project-prefixed (suffix)
  { spdxId: 'F3', name: 'drivers/gpu/main.c' }, // basename collision
  { spdxId: 'F4', name: 'drivers/net/main.c' } // basename collision
];

test('matchAffectedFile links exact and project-prefixed (suffix) paths', () => {
  const idx = buildFileIndex(FILES);

  const exact = matchAffectedFile('net/netfilter/nft_set_rbtree.c', idx);
  assert.equal(exact.linked, true);
  assert.equal(exact.spdxId, 'F1');
  assert.equal(exact.strength, 'exact');

  const suffix = matchAffectedFile('fs/ext4/mballoc.c', idx);
  assert.equal(suffix.linked, true);
  assert.equal(suffix.spdxId, 'F2');
  assert.equal(suffix.strength, 'suffix');
});

test('matchAffectedFile does not link a basename-only or ambiguous match', () => {
  const idx = buildFileIndex(FILES);

  // Only the filename `main.c` matches, and two files share it: ambiguous.
  const ambiguous = matchAffectedFile('kernel/main.c', idx);
  assert.equal(ambiguous.linked, false);
  assert.equal(ambiguous.candidates, 2);
  assert.equal(ambiguous.ambiguous, true);

  // A path with no matching basename at all.
  const none = matchAffectedFile('mm/slab.c', idx);
  assert.equal(none.linked, false);
  assert.equal(none.strength, 'none');
  assert.equal(none.candidates, 0);
});

test('matchAffectedFile leaves a lone basename match unlinked (too weak)', () => {
  // One file named foo.c, but at a totally different path than the CVE claims.
  const idx = buildFileIndex([{ spdxId: 'X', name: 'a/b/foo.c' }]);
  const m = matchAffectedFile('c/d/foo.c', idx);
  assert.equal(m.linked, false);
  assert.equal(m.strength, 'basename');
  assert.equal(m.candidates, 1);
});

test('linkAffectedFiles resolves a list and de-dupes by normalized path', () => {
  const idx = buildFileIndex(FILES);
  const links = linkAffectedFiles(
    ['./net/netfilter/nft_set_rbtree.c', 'net/netfilter/nft_set_rbtree.c', 'mm/slab.c'],
    idx
  );
  assert.equal(links.length, 2); // the first two normalize to the same path
  assert.equal(links[0].spdxId, 'F1');
  assert.equal(links[1].linked, false);
});

test('buildAffectedFileRelationships emits inferred vuln -> file edges for linked paths only', () => {
  const idx = buildFileIndex(FILES);
  const vulns = [
    { spdxId: 'V1', cveId: 'CVE-1' }, // record has one linkable + one bogus path
    { spdxId: 'V2', cveId: 'CVE-2' }, // record has only a bogus path -> no edge
    { spdxId: 'V3', cveId: 'CVE-3' } // no record fetched yet -> no edge
  ];
  const byCve = {
    'CVE-1': ['net/netfilter/nft_set_rbtree.c', 'mm/slab.c'],
    'CVE-2': ['mm/slab.c']
  };
  const rels = buildAffectedFileRelationships(vulns, (v) => byCve[v.cveId], idx);
  assert.equal(rels.length, 1);
  assert.equal(rels[0].from, 'V1');
  assert.equal(rels[0].to, 'F1');
  assert.equal(rels[0].relationshipType, 'affectsFile');
  assert.equal(rels[0].virtual, true);
  assert.equal(rels[0].inferred, true);
});

test('cveAffectedRow keeps only non-empty fields and returns null when empty', () => {
  assert.deepEqual(
    cveAffectedRow({ affectedFiles: ['a.c'], affectedRoutines: [], affectedModules: ['m'] }),
    { f: ['a.c'], m: ['m'] }
  );
  assert.equal(
    cveAffectedRow({ affectedFiles: [], affectedRoutines: [], affectedModules: [] }),
    null
  );
  assert.equal(cveAffectedRow({}), null);
});

test('isRuledOutStatus recognizes only the clearing statuses', () => {
  assert.equal(isRuledOutStatus('not_affected'), true);
  assert.equal(isRuledOutStatus('fixed'), true);
  assert.equal(isRuledOutStatus('affected'), false);
  assert.equal(isRuledOutStatus('under_investigation'), false);
  assert.equal(isRuledOutStatus(''), false);
});

test('effectiveVexStatus picks the most severe status for the target vuln only', () => {
  // affected outranks not_affected: a contradicting pair is never cleared.
  assert.equal(
    effectiveVexStatus(
      [
        { vulnId: 'V', status: 'not_affected' },
        { vulnId: 'V', status: 'affected' }
      ],
      'V'
    ),
    'affected'
  );
  // not_affected (2) outranks fixed (1).
  assert.equal(
    effectiveVexStatus(
      [
        { vulnId: 'V', status: 'fixed' },
        { vulnId: 'V', status: 'not_affected' }
      ],
      'V'
    ),
    'not_affected'
  );
  // Assessments for a different vuln are ignored.
  assert.equal(effectiveVexStatus([{ vulnId: 'OTHER', status: 'affected' }], 'V'), '');
  assert.equal(effectiveVexStatus([], 'V'), '');
});

test('annotateAffectedFiles joins package + VEX status and orders actionable-first', () => {
  const idx = buildFileIndex(FILES);
  const links = linkAffectedFiles(
    ['net/netfilter/nft_set_rbtree.c', 'fs/ext4/mballoc.c', 'mm/slab.c'],
    idx
  );
  const packageOf = (id) =>
    ({
      F1: { spdxId: 'PKG_KERNEL', name: 'kernel' },
      F2: { spdxId: 'PKG_EXT4', name: 'ext4' }
    })[id] || null;
  const assessmentsOf = (pkgId) =>
    ({
      PKG_KERNEL: [{ vulnId: 'V', status: 'fixed' }], // ruled out
      PKG_EXT4: [{ vulnId: 'V', status: 'affected' }] // still affected
    })[pkgId] || [];

  const out = annotateAffectedFiles(links, 'V', { packageOf, assessmentsOf });

  // Active matched file first, ruled-out matched file next, absent path last.
  assert.deepEqual(
    out.map((d) => d.path),
    ['fs/ext4/mballoc.c', 'net/netfilter/nft_set_rbtree.c', 'mm/slab.c']
  );
  assert.deepEqual(
    out.map((d) => [d.linked, d.packageName, d.vexStatus, d.ruledOut]),
    [
      [true, 'ext4', 'affected', false],
      [true, 'kernel', 'fixed', true],
      [false, '', '', false]
    ]
  );
});

test('annotateAffectedFiles leaves a matched file without a known package unannotated', () => {
  const idx = buildFileIndex(FILES);
  const links = linkAffectedFiles(['net/netfilter/nft_set_rbtree.c'], idx);
  const out = annotateAffectedFiles(links, 'V', {
    packageOf: () => null, // no containing package resolvable
    assessmentsOf: () => [{ vulnId: 'V', status: 'not_affected' }]
  });
  assert.equal(out.length, 1);
  assert.equal(out[0].linked, true);
  assert.equal(out[0].packageId, '');
  assert.equal(out[0].vexStatus, '');
  assert.equal(out[0].ruledOut, false);
});

test('summarizeAffectedFiles counts matched, ruled-out, and distinct packages', () => {
  const annotated = [
    { linked: true, packageId: 'A', ruledOut: false },
    { linked: true, packageId: 'A', ruledOut: true }, // same package, ruled out
    { linked: true, packageId: 'B', ruledOut: true },
    { linked: false, packageId: '', ruledOut: false } // absent path, ignored
  ];
  assert.deepEqual(summarizeAffectedFiles(annotated), { matched: 3, ruledOut: 2, packages: 2 });
  assert.deepEqual(summarizeAffectedFiles([]), { matched: 0, ruledOut: 0, packages: 0 });
});

test('buildAffectedFileRelationships de-dupes a vuln->file pair reached by two paths', () => {
  const idx = buildFileIndex([{ spdxId: 'F', name: 'a/b/c/thing.c' }]);
  // Both the full path and its suffix resolve to the same File F.
  const rels = buildAffectedFileRelationships(
    [{ spdxId: 'V', cveId: 'X' }],
    () => ['a/b/c/thing.c', 'c/thing.c'],
    idx
  );
  assert.equal(rels.length, 1);
  assert.equal(rels[0].to, 'F');
});
