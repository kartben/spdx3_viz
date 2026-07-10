import assert from 'node:assert/strict';
import test from 'node:test';

import {
  collectPurlTargets,
  pickCveId,
  cvssBaseScore,
  normalizeOsvVuln,
  toOnlineVuln,
  mergeVulnLists
} from '../src/lib/index.js';

test('collectPurlTargets de-duplicates by purl and remembers every element', () => {
  const targets = collectPurlTargets([
    { spdxId: 'a', software_packageUrl: 'pkg:deb/ubuntu/apt@3.2.0?arch=amd64' },
    {
      spdxId: 'b',
      externalIdentifier: [
        { externalIdentifierType: 'packageUrl', identifier: 'pkg:deb/ubuntu/apt@3.2.0?arch=amd64' }
      ]
    },
    { spdxId: 'c', software_packageUrl: 'not-a-purl' },
    {
      spdxId: 'd',
      externalIdentifier: {
        externalIdentifierType: 'packageUrl',
        identifier: 'pkg:npm/left-pad@1.0.0'
      }
    }
  ]);
  assert.equal(targets.length, 2);
  const apt = targets.find((t) => t.purl.startsWith('pkg:deb'));
  assert.deepEqual(apt.elementIds.sort(), ['a', 'b']);
  assert.ok(targets.some((t) => t.purl === 'pkg:npm/left-pad@1.0.0'));
});

test('pickCveId prefers a CVE alias, tolerating a GHSA primary id', () => {
  assert.equal(pickCveId({ id: 'GHSA-xxxx', aliases: ['CVE-2024-1234'] }), 'CVE-2024-1234');
  assert.equal(pickCveId({ id: 'CVE-2020-0001' }), 'CVE-2020-0001');
  assert.equal(pickCveId({ id: 'GHSA-yyyy', aliases: ['GHSA-zzzz'] }), '');
});

test('cvssBaseScore computes known v3.1 vectors', () => {
  assert.equal(cvssBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvssBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'), 7.5);
  // Scope-changed raises the ceiling above the same unchanged vector (7.5 -> 9.6).
  assert.equal(cvssBaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H'), 9.6);
});

test('cvssBaseScore handles a bare v2 vector and returns null for v4', () => {
  assert.equal(cvssBaseScore('AV:N/AC:L/Au:N/C:C/I:C/A:C'), 10);
  assert.equal(
    cvssBaseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'),
    null
  );
});

test('normalizeOsvVuln distills id, cvss, cwes, and references', () => {
  const n = normalizeOsvVuln({
    id: 'GHSA-abcd',
    aliases: ['CVE-2024-9999'],
    summary: 'Bad thing',
    details: 'Longer text',
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    database_specific: { cwe_ids: ['CWE-79'] },
    references: [
      { type: 'WEB', url: 'https://example.com/a' },
      { type: 'FIX', url: 'not-a-url' }
    ],
    published: '2024-01-01T00:00:00Z'
  });
  assert.equal(n.displayId, 'CVE-2024-9999');
  assert.equal(n.cvss.score, 9.8);
  assert.equal(n.cvss.severity, 'critical');
  assert.deepEqual(n.cwes, ['CWE-79']);
  assert.equal(n.references.length, 1);
});

test('normalizeOsvVuln falls back to a database_specific severity label', () => {
  const n = normalizeOsvVuln({
    id: 'GHSA-only',
    database_specific: { severity: 'MODERATE' }
  });
  assert.equal(n.cvss.score, null);
  assert.equal(n.cvss.severity, 'medium');
});

test('mergeVulnLists tags SBOM/both/online and keeps the SBOM CVSS', () => {
  const sbom = [
    {
      spdxId: 's1',
      name: 'CVE-2024-1111',
      cveId: 'CVE-2024-1111',
      cvss: { score: 8.1, severity: 'high' },
      severity: 'high'
    },
    { spdxId: 's2', name: 'CVE-2024-2222', cveId: 'CVE-2024-2222', cvss: null, severity: '' }
  ];
  const online = [
    toOnlineVuln(
      normalizeOsvVuln({
        id: 'CVE-2024-1111',
        severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' }]
      }),
      [{ spdxId: 'p1', name: 'curl', purl: 'pkg:deb/curl' }]
    ),
    toOnlineVuln(
      normalizeOsvVuln({
        id: 'GHSA-new',
        aliases: ['CVE-2024-3333'],
        severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }]
      }),
      [{ spdxId: 'p2', name: 'left-pad', purl: 'pkg:npm/left-pad' }]
    )
  ];
  const merged = mergeVulnLists(sbom, online);
  const m1 = merged.find((v) => v.cveId === 'CVE-2024-1111');
  assert.equal(m1.source, 'both');
  assert.equal(m1.cvss.score, 8.1, 'SBOM CVSS wins over online');
  assert.ok(m1.online, 'online payload attached');

  // s2 had no CVSS: the online value should fill it in and flip severity.
  const online2 = [
    toOnlineVuln(
      normalizeOsvVuln({
        id: 'CVE-2024-2222',
        severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }]
      }),
      [{ spdxId: 'p3', name: 'x', purl: 'pkg:npm/x' }]
    )
  ];
  const merged2 = mergeVulnLists(sbom, online2);
  const m2 = merged2.find((v) => v.cveId === 'CVE-2024-2222');
  assert.equal(m2.source, 'both');
  assert.equal(m2.cvss.score, 9.8, 'online CVSS fills an empty SBOM one');

  const onlineOnly = merged.find((v) => v.cveId === 'CVE-2024-3333');
  assert.equal(onlineOnly.source, 'online');
  assert.equal(onlineOnly.packageCount, 1);
  assert.equal(onlineOnly.overallStatus, 'unknown');
});
