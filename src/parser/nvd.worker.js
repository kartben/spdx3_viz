/**
 * Queries the NVD (National Vulnerability Database) 2.0 REST API for CVEs
 * affecting the SBOM's components by CPE, off the main thread. NVD is the
 * authoritative source for CPE-based matching, which OSV does not do.
 *
 * NVD is queried once per vendor:product (via `virtualMatchString`, which
 * returns every CVE referencing that product across versions); the returned
 * CVEs are then filtered locally to the versions actually present. NVD rate
 * limits requests (5 / 30s without an API key, 50 / 30s with one), so requests
 * are throttled and an optional key can be supplied.
 *
 * Protocol:
 *   main → worker: { id, type: 'start', targets: CpeTarget[], apiKey?: string }
 *                  { id, type: 'cancel' }
 *   worker → main: { id, type: 'progress', phase: 'query', done, total }
 *                  { id, type: 'done', ok: true, findings, queried }
 *                  { id, type: 'done', ok: false, error, cancelled? }
 *
 * @module parser/nvd.worker
 */
import { NVD_API, cpeMatchString, normalizeNvdCve, matchNvdCveToComponents } from '../lib/nvd.js';
import { planBundleFetches, matchBundleShard } from '../lib/nvd-bundle.js';

const PAGE_SIZE = 2000; // NVD max resultsPerPage
const MAX_RETRIES = 4;
const BUNDLE_CONCURRENCY = 8; // parallel Range fetches against the bundled index

let job = null; // { id, cancelled, controllers:Set<AbortController>, lastRequest, minInterval }

self.onmessage = (event) => {
  const msg = event.data || {};
  if (msg.type === 'cancel') {
    if (job) {
      job.cancelled = true;
      job.controllers.forEach((c) => c.abort());
    }
    return;
  }
  if (msg.type === 'start') {
    if (msg.mode === 'bundle') runBundleJob(msg);
    else runJob(msg);
  }
};

// Merges an NVD finding into the by-CVE accumulator, unioning affected elements.
function addFinding(byCve, f) {
  const existing = byCve.get(f.cveId);
  if (existing) {
    existing.elementIds = [...new Set([...existing.elementIds, ...f.elementIds])];
  } else {
    byCve.set(f.cveId, f);
  }
}

// Runs `worker` over `items` with at most `size` in flight.
async function pool(items, size, worker) {
  let cursor = 0;
  const runners = Array.from({ length: Math.min(size, items.length) }, async () => {
    while (cursor < items.length) await worker(items[cursor++]);
  });
  await Promise.all(runners);
}

// --- Bundled index mode: match against a statically-hosted index (no live NVD).
async function runBundleJob({ id, baseUrl, targets }) {
  job = { id, cancelled: false, controllers: new Set() };
  const post = (m) => self.postMessage({ id, ...m });
  const list = Array.isArray(targets) ? targets : [];
  const base = String(baseUrl || './nvd-cpe/').replace(/\/?$/, '/');

  try {
    // Manifest first: one small fetch that maps product -> {part, byte range}.
    let manifest;
    try {
      const controller = new AbortController();
      job.controllers.add(controller);
      const res = await fetch(`${base}manifest.json`, { signal: controller.signal });
      job.controllers.delete(controller);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      manifest = await res.json();
    } catch (err) {
      throw new Error(
        `Could not load the bundled NVD index (${(err && err.message) || 'fetch failed'}). ` +
          `Check that it is published at ${base}manifest.json.`
      );
    }

    const plan = planBundleFetches(manifest, list);
    const total = plan.length;
    const byCve = new Map();
    let done = 0;
    let failed = 0;
    post({ type: 'progress', phase: 'bundle', done: 0, total });

    await pool(plan, BUNDLE_CONCURRENCY, async (item) => {
      if (job.cancelled) return;
      let rows;
      try {
        const text = await rangeFetch(`${base}${item.part}`, item.offset, item.length);
        rows = JSON.parse(text);
      } catch {
        failed++;
        done++;
        post({ type: 'progress', phase: 'bundle', done, total });
        return;
      }
      matchBundleShard(rows, item.target).forEach((f) => addFinding(byCve, f));
      done++;
      post({ type: 'progress', phase: 'bundle', done, total });
    });

    if (job.cancelled)
      return post({ type: 'done', ok: false, cancelled: true, error: 'Cancelled' });
    const warning = failed
      ? `Bundled NVD: ${failed} shard${failed === 1 ? '' : 's'} could not be read`
      : '';
    post({ type: 'done', ok: true, findings: [...byCve.values()], queried: total, warning });
  } catch (err) {
    post({ type: 'done', ok: false, error: (err && err.message) || String(err) });
  } finally {
    job = null;
  }
}

// Fetches a byte range of a part file. Handles servers that honor Range (206,
// body is exactly the range) and those that ignore it (200, slice locally).
async function rangeFetch(url, offset, length) {
  const controller = new AbortController();
  job?.controllers.add(controller);
  try {
    const res = await fetch(url, {
      headers: { Range: `bytes=${offset}-${offset + length - 1}` },
      signal: controller.signal
    });
    if (!res.ok && res.status !== 206) throw new Error(`shard fetch failed (${res.status})`);
    const bytes = new Uint8Array(await res.arrayBuffer());
    const slice = res.status === 206 ? bytes : bytes.subarray(offset, offset + length);
    return new TextDecoder().decode(slice);
  } finally {
    job?.controllers.delete(controller);
  }
}

async function runJob({ id, targets, apiKey }) {
  job = {
    id,
    cancelled: false,
    controllers: new Set(),
    lastRequest: 0,
    // Space requests under NVD's published limits with headroom.
    minInterval: apiKey ? 700 : 6500,
    apiKey: apiKey || ''
  };
  const post = (m) => self.postMessage({ id, ...m });
  const list = Array.isArray(targets) ? targets : [];
  const total = list.length;

  try {
    const byCve = new Map(); // cveId -> finding (elementIds unioned across products)
    let failed = 0; // products that could not be checked (reported, not hidden)
    const failedNames = [];
    for (let i = 0; i < list.length; i++) {
      if (job.cancelled)
        return post({ type: 'done', ok: false, cancelled: true, error: 'Cancelled' });
      const target = list[i];
      let cves;
      try {
        cves = await fetchProductCves(target);
      } catch (err) {
        // A hard failure on the very first product is almost always CORS or an
        // unreachable API, not a per-product issue: fail the whole run.
        if (i === 0) {
          throw new Error(
            (err && err.message) ||
              'NVD request failed. The browser may be blocked from calling NVD directly (CORS), or NVD is unreachable.'
          );
        }
        // Later products: keep going so one flaky product doesn't sink the whole
        // scan, but count and report the gap so the result isn't silently partial.
        failed++;
        if (failedNames.length < 3) failedNames.push(`${target.vendor}:${target.product}`);
        cves = [];
      }
      cves.forEach((cve) => {
        const affected = matchNvdCveToComponents(cve, target);
        if (!affected.length) return;
        const existing = byCve.get(cve.cveId);
        if (existing) {
          const ids = new Set([...existing.elementIds, ...affected]);
          existing.elementIds = [...ids];
        } else {
          byCve.set(cve.cveId, {
            provider: 'NVD',
            cveId: cve.cveId,
            displayId: cve.cveId,
            summary: cve.summary,
            details: '',
            cvss: cve.cvss,
            cwes: cve.cwes,
            references: cve.references,
            published: cve.published,
            elementIds: affected
          });
        }
      });
      post({ type: 'progress', phase: 'query', done: i + 1, total });
    }

    if (job.cancelled)
      return post({ type: 'done', ok: false, cancelled: true, error: 'Cancelled' });
    const warning = failed
      ? `NVD: ${failed} product${failed === 1 ? '' : 's'} could not be checked` +
        (failedNames.length
          ? ` (${failedNames.join(', ')}${failed > failedNames.length ? ', …' : ''})`
          : '')
      : '';
    post({ type: 'done', ok: true, findings: [...byCve.values()], queried: total, warning });
  } catch (err) {
    post({ type: 'done', ok: false, error: (err && err.message) || String(err) });
  } finally {
    job = null;
  }
}

// Fetches (and paginates) every CVE NVD lists for a vendor:product, normalized.
async function fetchProductCves(target) {
  const out = [];
  const match = cpeMatchString(target.vendor, target.product);
  let startIndex = 0;
  let totalResults = Infinity;
  while (startIndex < totalResults) {
    if (job?.cancelled) return out;
    const url =
      `${NVD_API}?virtualMatchString=${encodeURIComponent(match)}` +
      `&resultsPerPage=${PAGE_SIZE}&startIndex=${startIndex}`;
    const data = await nvdFetch(url);
    totalResults = Number.isFinite(data.totalResults) ? data.totalResults : 0;
    const page = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
    page.forEach((w) => out.push(normalizeNvdCve(w)));
    if (!page.length) break;
    startIndex += page.length;
  }
  return out;
}

// Fetches an NVD URL with throttling (to respect rate limits). Retries only on
// transient failures (network errors, and NVD's 403/429/5xx rate-limit signals)
// with exponential backoff; fails fast on other 4xx so an invalid query doesn't
// burn 60s of retries. Aborts promptly when cancelled.
async function nvdFetch(url) {
  let lastErr;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    if (job?.cancelled) throw new Error('Cancelled');
    await throttle();
    const controller = new AbortController();
    job?.controllers.add(controller);
    let res = null;
    try {
      res = await fetch(url, {
        headers: job?.apiKey ? { apiKey: job.apiKey } : undefined,
        signal: controller.signal
      });
    } catch (err) {
      if (job?.cancelled) throw err;
      lastErr = err; // network error: retry
    } finally {
      job?.controllers.delete(controller);
    }
    if (res) {
      if (res.ok) return await res.json();
      // NVD signals rate limiting with 403 or 429; those plus 5xx are transient.
      if (res.status === 403 || res.status === 429 || res.status >= 500) {
        lastErr = new Error(`NVD rate-limited or unavailable (${res.status})`);
      } else {
        const err = new Error(`NVD request failed (${res.status})`);
        err.status = res.status;
        throw err; // non-transient 4xx: fail fast
      }
    }
    // Backoff on top of the base throttle: 4s, 8s, 16s, 32s.
    await sleep(4000 * 2 ** attempt);
  }
  throw lastErr || new Error('NVD request failed');
}

// Ensures at least `minInterval` ms between requests across the whole job.
async function throttle() {
  if (!job) return;
  const now = Date.now();
  const wait = job.lastRequest + job.minInterval - now;
  if (wait > 0) await sleep(wait);
  job.lastRequest = Date.now();
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
