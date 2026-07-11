import assert from 'node:assert/strict';
import test from 'node:test';

import {
  bundleKey,
  bundleRangeApplies,
  bundleRowToFinding,
  matchBundleShard,
  planBundleFetches
} from '../src/lib/index.js';

test('bundleKey lowercases and space-joins', () => {
  assert.equal(bundleKey('Zlib', 'ZLib'), 'zlib zlib');
});

test('bundleRangeApplies handles exact, unbounded, and ranged', () => {
  assert.equal(bundleRangeApplies('1.2.11', { x: '1.2.11' }), true);
  assert.equal(bundleRangeApplies('1.2.12', { x: '1.2.11' }), false);
  assert.equal(bundleRangeApplies('9.9.9', {}), true); // unbounded
  const r = { si: '1.2.0', ee: '1.2.12' };
  assert.equal(bundleRangeApplies('1.2.11', r), true);
  assert.equal(bundleRangeApplies('1.2.12', r), false);
  assert.equal(bundleRangeApplies('1.1.0', r), false);
});

test('bundleRowToFinding expands the compact row to a live-shaped finding', () => {
  const f = bundleRowToFinding(
    { id: '2022-37434', sc: 9.8, sv: 'c', cv: '3.1', cw: [787], pub: '2022-08-05' },
    ['pkg-a']
  );
  assert.equal(f.provider, 'NVD');
  assert.equal(f.cveId, 'CVE-2022-37434');
  assert.equal(f.cvss.score, 9.8);
  assert.equal(f.cvss.severity, 'critical');
  assert.deepEqual(f.cwes, ['CWE-787']);
  assert.equal(f.references[0].url, 'https://nvd.nist.gov/vuln/detail/CVE-2022-37434');
  assert.deepEqual(f.elementIds, ['pkg-a']);
});

test('matchBundleShard filters by version and returns findings', () => {
  const rows = [
    {
      id: '2022-37434',
      sc: 9.8,
      sv: 'c',
      cv: '3.1',
      cw: [787],
      pub: '2022-08-05',
      r: [{ si: '1.2.0', ei: '1.2.12' }]
    },
    {
      id: '2018-25032',
      sc: 7.5,
      sv: 'h',
      cv: '3.1',
      cw: [787],
      pub: '2022-03-25',
      r: [{ x: '9.9.9' }]
    }
  ];
  const target = {
    vendor: 'zlib',
    product: 'zlib',
    entries: [
      { version: '1.2.11', elementIds: ['a'] },
      { version: '1.3.1', elementIds: ['b'] }
    ]
  };
  const findings = matchBundleShard(rows, target);
  assert.equal(findings.length, 1, 'only the in-range CVE matches; the pinned 9.9.9 does not');
  assert.equal(findings[0].cveId, 'CVE-2022-37434');
  assert.deepEqual(findings[0].elementIds.sort(), ['a']);
});

test('planBundleFetches resolves manifest locations and skips unknown products', () => {
  const manifest = {
    parts: ['part-000.ndjson', 'part-001.ndjson'],
    index: {
      'zlib zlib': [0, 100, 42],
      'openssl openssl': [1, 5, 88]
    }
  };
  const plan = planBundleFetches(manifest, [
    { vendor: 'zlib', product: 'zlib' },
    { vendor: 'openssl', product: 'openssl' },
    { vendor: 'nope', product: 'nope' }
  ]);
  assert.equal(plan.length, 2);
  assert.deepEqual(plan[0], {
    target: { vendor: 'zlib', product: 'zlib' },
    part: 'part-000.ndjson',
    offset: 100,
    length: 42
  });
  assert.equal(plan[1].part, 'part-001.ndjson');
});
