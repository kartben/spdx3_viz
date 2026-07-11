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

const PAGE_SIZE = 2000; // NVD max resultsPerPage
const MAX_RETRIES = 4;

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
  if (msg.type === 'start') runJob(msg);
};

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
    for (let i = 0; i < list.length; i++) {
      if (job.cancelled)
        return post({ type: 'done', ok: false, cancelled: true, error: 'Cancelled' });
      const target = list[i];
      let cves;
      try {
        cves = await fetchProductCves(target);
      } catch (err) {
        // A hard failure on the very first product is almost always CORS or an
        // unreachable API, not a per-product issue: surface it rather than
        // grinding through every (throttled) product only to fail each time.
        if (i === 0) {
          throw new Error(
            (err && err.message) ||
              'NVD request failed. The browser may be blocked from calling NVD directly (CORS), or NVD is unreachable.'
          );
        }
        cves = []; // later products: skip and keep going
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
    post({ type: 'done', ok: true, findings: [...byCve.values()], queried: total });
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

// Fetches an NVD URL with throttling (to respect rate limits) and retry/backoff
// on 403/429/5xx. Aborts promptly when cancelled.
async function nvdFetch(url) {
  let lastErr;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    if (job?.cancelled) throw new Error('Cancelled');
    await throttle();
    const controller = new AbortController();
    job?.controllers.add(controller);
    try {
      const res = await fetch(url, {
        headers: job?.apiKey ? { apiKey: job.apiKey } : undefined,
        signal: controller.signal
      });
      // NVD signals rate limiting with 403 or 429; both are worth retrying.
      if (res.status === 403 || res.status === 429 || res.status >= 500) {
        lastErr = new Error(`NVD rate-limited or unavailable (${res.status})`);
      } else if (!res.ok) {
        throw new Error(`NVD request failed (${res.status})`);
      } else {
        return await res.json();
      }
    } catch (err) {
      if (job?.cancelled) throw err;
      lastErr = err;
    } finally {
      job?.controllers.delete(controller);
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
