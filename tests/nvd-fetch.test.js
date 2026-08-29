import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test, { mock } from 'node:test';
import { gzipSync, gunzipSync } from 'node:zlib';

import { defaultFeedYears, fetchNvdPages } from '../scripts/nvd-fetch.mjs';

function gzipJson(obj) {
  return gzipSync(Buffer.from(JSON.stringify(obj)));
}

function sha256(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

function metaFor(uncompressed) {
  return `sha256:${sha256(uncompressed).toUpperCase()}\n`;
}

function feedPayload(ids) {
  return {
    totalResults: ids.length,
    vulnerabilities: ids.map((id) => ({ cve: { id } }))
  };
}

function mockFetch(handler) {
  mock.method(globalThis, 'fetch', async (input) => handler(String(input)));
}

test.afterEach(() => mock.restoreAll());

test('defaultFeedYears runs 2002 through the current UTC year', () => {
  const years = defaultFeedYears(new Date('2026-08-29T00:00:00Z'));
  assert.equal(years[0], 2002);
  assert.equal(years.at(-1), 2026);
  assert.equal(years.length, 2026 - 2002 + 1);
});

test('fetchNvdPages reads yearly gzip feeds and invokes onVuln', async () => {
  const payload = feedPayload(['CVE-2024-1', 'CVE-2024-2']);
  const gz = gzipJson(payload);
  const uncompressed = gunzipSync(gz);
  mockFetch((url) => {
    if (url.endsWith('nvdcve-2.0-2024.meta')) {
      return new Response(metaFor(uncompressed), { status: 200 });
    }
    if (url.endsWith('nvdcve-2.0-2024.json.gz')) return new Response(gz, { status: 200 });
    return new Response('missing', { status: 404 });
  });
  const ids = [];
  const info = await fetchNvdPages({ source: 'feeds', feedYears: [2024], cacheDir: '' }, (w) =>
    ids.push(w.cve.id)
  );
  assert.deepEqual(ids, ['CVE-2024-1', 'CVE-2024-2']);
  assert.equal(info.fetched, 2);
  assert.equal(info.total, 2);
  assert.equal(info.source, 'feeds');
  assert.equal(info.sampled, false);
});

test('fetchNvdPages sample-pages stops before later years', async () => {
  const requested = [];
  const first = feedPayload(Array.from({ length: 2500 }, (_, i) => `CVE-2024-${i}`));
  const firstGz = gzipJson(first);
  mockFetch((url) => {
    requested.push(url);
    if (url.includes('2024') && url.endsWith('.json.gz'))
      return new Response(firstGz, { status: 200 });
    if (url.endsWith('.meta')) return new Response('', { status: 404 });
    return new Response('missing', { status: 404 });
  });
  const ids = [];
  const info = await fetchNvdPages(
    { source: 'feeds', feedYears: [2024, 2025], samplePages: 1, cacheDir: '' },
    (w) => ids.push(w.cve.id)
  );
  assert.equal(ids.length, 2000);
  assert.equal(info.sampled, true);
  assert.equal(
    requested.some((u) => u.includes('2025.json.gz')),
    false
  );
});

test('fetchNvdPages caches gzip feeds and reuses them when sha256 matches', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'nvd-feed-'));
  const payload = feedPayload(['CVE-2024-9']);
  const gz = gzipJson(payload);
  const uncompressed = gunzipSync(gz);
  let gzHits = 0;
  mockFetch((url) => {
    if (url.endsWith('.meta')) return new Response(metaFor(uncompressed), { status: 200 });
    if (url.endsWith('.json.gz')) {
      gzHits++;
      return new Response(gz, { status: 200 });
    }
    return new Response('missing', { status: 404 });
  });
  try {
    await fetchNvdPages({ source: 'feeds', feedYears: [2024], cacheDir: dir }, () => {});
    await fetchNvdPages({ source: 'feeds', feedYears: [2024], cacheDir: dir }, () => {});
    assert.equal(gzHits, 1);
    assert.ok(readFileSync(join(dir, 'nvdcve-2.0-2024.json.gz')).length > 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('fetchNvdPages throws when a past-year feed is missing', async () => {
  mockFetch(() => new Response('missing', { status: 404 }));
  await assert.rejects(
    () => fetchNvdPages({ source: 'feeds', feedYears: [2024], cacheDir: '' }, () => {}),
    /NVD request failed \(404\)/
  );
});

test('fetchNvdPages still pages the REST API when source=api', async () => {
  mockFetch((url) => {
    assert.match(url, /startIndex=0/);
    return Response.json({
      totalResults: 2,
      vulnerabilities: [{ cve: { id: 'CVE-1999-1' } }, { cve: { id: 'CVE-1999-2' } }]
    });
  });
  const ids = [];
  const info = await fetchNvdPages({ source: 'api', cacheDir: '' }, (w) => ids.push(w.cve.id));
  assert.deepEqual(ids, ['CVE-1999-1', 'CVE-1999-2']);
  assert.equal(info.source, 'api');
  assert.equal(info.pages, 1);
});
