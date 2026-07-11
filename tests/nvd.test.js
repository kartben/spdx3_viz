import assert from 'node:assert/strict';
import test from 'node:test';

import {
  collectCpeTargets,
  cpeMatchString,
  compareVersions,
  cpeMatchApplies,
  normalizeNvdCve,
  matchNvdCveToComponents
} from '../src/lib/index.js';

test('collectCpeTargets dedupes by vendor:product and keeps versions + elements', () => {
  const targets = collectCpeTargets([
    {
      spdxId: 'a',
      externalIdentifier: [
        { externalIdentifierType: 'cpe23', identifier: 'cpe:2.3:a:zlib:zlib:1.2.11:*:*:*:*:*:*:*' }
      ]
    },
    {
      spdxId: 'b',
      externalIdentifier: [
        { externalIdentifierType: 'cpe22', identifier: 'cpe:/a:zlib:zlib:1.3.1' }
      ]
    },
    {
      spdxId: 'c',
      externalIdentifier: [
        { externalIdentifierType: 'cpe23', identifier: 'cpe:2.3:a:zlib:zlib:1.2.11:*:*:*:*:*:*:*' }
      ]
    }
  ]);
  assert.equal(targets.length, 1);
  const t = targets[0];
  assert.equal(t.product, 'zlib');
  const v1211 = t.entries.find((e) => e.version === '1.2.11');
  assert.deepEqual(v1211.elementIds.sort(), ['a', 'c']);
  assert.ok(t.entries.some((e) => e.version === '1.3.1'));
});

test('cpeMatchString builds a wildcard virtualMatchString', () => {
  assert.equal(
    cpeMatchString('Apache Software', 'HTTP Server'),
    'cpe:2.3:*:apache_software:http_server:*:*:*:*:*:*:*:*'
  );
});

test('compareVersions is numeric-aware', () => {
  assert.equal(compareVersions('1.2.10', '1.2.9'), 1);
  assert.equal(compareVersions('1.2', '1.2.1'), -1);
  assert.equal(compareVersions('2.0.0', '2.0.0'), 0);
});

test('cpeMatchApplies handles exact, unbounded, and ranged criteria', () => {
  // Exact pinned version.
  assert.equal(
    cpeMatchApplies('1.2.11', {
      criteria: 'cpe:2.3:a:zlib:zlib:1.2.11:*:*:*:*:*:*:*',
      vulnerable: true
    }),
    true
  );
  assert.equal(
    cpeMatchApplies('1.2.12', {
      criteria: 'cpe:2.3:a:zlib:zlib:1.2.11:*:*:*:*:*:*:*',
      vulnerable: true
    }),
    false
  );
  // Wildcard, no range: all versions affected.
  assert.equal(
    cpeMatchApplies('9.9.9', { criteria: 'cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*', vulnerable: true }),
    true
  );
  // Range: [1.2.0, 1.2.12) affected.
  const ranged = {
    criteria: 'cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*',
    vulnerable: true,
    versionStartIncluding: '1.2.0',
    versionEndExcluding: '1.2.12'
  };
  assert.equal(cpeMatchApplies('1.2.11', ranged), true);
  assert.equal(cpeMatchApplies('1.2.12', ranged), false);
  assert.equal(cpeMatchApplies('1.1.0', ranged), false);
  // A non-vulnerable entry never applies.
  assert.equal(cpeMatchApplies('1.2.11', { ...ranged, vulnerable: false }), false);
});

const NVD_RECORD = {
  cve: {
    id: 'CVE-2022-37434',
    descriptions: [{ lang: 'en', value: 'Heap overflow in zlib inflate' }],
    metrics: {
      cvssMetricV31: [
        {
          cvssData: {
            baseScore: 9.8,
            baseSeverity: 'CRITICAL',
            vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            version: '3.1'
          }
        }
      ]
    },
    weaknesses: [{ description: [{ value: 'CWE-787' }] }],
    references: [{ url: 'https://nvd.nist.gov/vuln/detail/CVE-2022-37434', tags: ['Patch'] }],
    published: '2022-08-05T07:15:00.000',
    configurations: [
      {
        nodes: [
          {
            cpeMatch: [
              {
                vulnerable: true,
                criteria: 'cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*',
                versionStartIncluding: '1.2.0',
                versionEndIncluding: '1.2.12'
              }
            ]
          }
        ]
      }
    ]
  }
};

test('normalizeNvdCve distills id, cvss, cwes, refs, and cpe matches', () => {
  const n = normalizeNvdCve(NVD_RECORD);
  assert.equal(n.cveId, 'CVE-2022-37434');
  assert.equal(n.cvss.score, 9.8);
  assert.equal(n.cvss.severity, 'critical');
  assert.deepEqual(n.cwes, ['CWE-787']);
  assert.equal(n.references.length, 1);
  assert.equal(n.cpeMatches.length, 1);
});

test('matchNvdCveToComponents filters by the declared versions', () => {
  const n = normalizeNvdCve(NVD_RECORD);
  const target = {
    vendor: 'zlib',
    product: 'zlib',
    entries: [
      { version: '1.2.11', elementIds: ['pkg-a'] }, // in range -> affected
      { version: '1.3.1', elementIds: ['pkg-b'] } // above range -> not affected
    ]
  };
  assert.deepEqual(matchNvdCveToComponents(n, target), ['pkg-a']);

  // A different product must not match even if fetched together.
  const other = {
    vendor: 'openssl',
    product: 'openssl',
    entries: [{ version: '1.2.11', elementIds: ['x'] }]
  };
  assert.deepEqual(matchNvdCveToComponents(n, other), []);
});
