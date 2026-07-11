/**
 * Queries the public OSV.dev database for vulnerabilities affecting the SBOM's
 * components, off the main thread so the UI stays responsive and a progress bar
 * can animate. Matching is by PackageURL, which OSV supports natively across
 * ecosystems (deb, npm, pypi, golang, maven, …).
 *
 * Two phases:
 *   1. querybatch — one request per (up to) BATCH purls, returning only the ids
 *      of matching advisories.
 *   2. details    — fetch each distinct advisory once (GET /v1/vulns/{id}) and
 *      normalize it down to the fields the security view renders.
 *
 * Protocol:
 *   main → worker: { id, type: 'start', targets: [{ purl, elementIds }] }
 *                  { id, type: 'cancel' }
 *   worker → main: { id, type: 'progress', phase: 'query'|'details', done, total }
 *                  { id, type: 'done', ok: true, findings, queried }
 *                  { id, type: 'done', ok: false, error, cancelled? }
 *
 * A finding is a normalized OSV record plus the purls / element spdxIds it
 * matched, so the main thread can attribute it back to components by name.
 *
 * @module parser/osv.worker
 */
import { OSV_API, normalizeOsvVuln } from '../lib/osv.js';

const BATCH = 500; // purls per querybatch request (OSV allows up to 1000)
const DETAIL_CONCURRENCY = 8; // parallel /v1/vulns/{id} fetches
const MAX_RETRIES = 3;

let job = null; // { id, cancelled, controllers:Set<AbortController> }

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

async function runJob({ id, targets }) {
  job = { id, cancelled: false, controllers: new Set() };
  const post = (m) => self.postMessage({ id, ...m });
  const list = Array.isArray(targets) ? targets : [];

  try {
    // Phase 1 — querybatch. Follow OSV's per-query next_page_token so a purl with
    // many advisories isn't truncated.
    const total = list.length;
    let queue = list.map((t, i) => ({ purl: t.purl, i }));
    const idToTargets = new Map(); // osvId -> Set<targetIndex>
    const firstPageDone = new Set();

    while (queue.length) {
      if (job.cancelled)
        return post({ type: 'done', ok: false, cancelled: true, error: 'Cancelled' });
      const chunk = queue.slice(0, BATCH);
      queue = queue.slice(BATCH);
      const body = {
        queries: chunk.map((q) =>
          q.pageToken
            ? { package: { purl: q.purl }, page_token: q.pageToken }
            : { package: { purl: q.purl } }
        )
      };
      const res = await osvFetch('/v1/querybatch', body);
      (res.results || []).forEach((r, idx) => {
        const q = chunk[idx];
        if (!q) return;
        (r.vulns || []).forEach((v) => {
          if (!v || !v.id) return;
          if (!idToTargets.has(v.id)) idToTargets.set(v.id, new Set());
          idToTargets.get(v.id).add(q.i);
        });
        if (r.next_page_token) queue.push({ purl: q.purl, i: q.i, pageToken: r.next_page_token });
        if (!q.pageToken) firstPageDone.add(q.i);
      });
      post({ type: 'progress', phase: 'query', done: firstPageDone.size, total });
    }

    // Phase 2 — fetch and normalize each distinct advisory exactly once.
    const ids = [...idToTargets.keys()];
    const findings = [];
    let done = 0;
    await pool(ids, DETAIL_CONCURRENCY, async (osvId) => {
      if (job.cancelled) return;
      let raw;
      try {
        raw = await osvFetch(`/v1/vulns/${encodeURIComponent(osvId)}`, null);
      } catch (err) {
        // A withdrawn/removed advisory 404s: skip just that id. Any other error
        // (network, server) propagates so we fail loudly rather than silently
        // returning an incomplete vulnerability list.
        if (err && err.status === 404) raw = null;
        else throw err;
      }
      done++;
      post({ type: 'progress', phase: 'details', done, total: ids.length });
      if (!raw) return;
      const indices = [...idToTargets.get(osvId)];
      const purls = [...new Set(indices.map((i) => list[i]?.purl).filter(Boolean))];
      const elementIds = [...new Set(indices.flatMap((i) => list[i]?.elementIds || []))];
      const normalized = normalizeOsvVuln(raw);
      if (normalized.withdrawn) return; // don't surface withdrawn advisories
      findings.push({ ...normalized, purls, elementIds });
    });

    if (job.cancelled)
      return post({ type: 'done', ok: false, cancelled: true, error: 'Cancelled' });
    post({ type: 'done', ok: true, findings, queried: total });
  } catch (err) {
    post({ type: 'done', ok: false, error: (err && err.message) || String(err) });
  } finally {
    job = null;
  }
}

// Runs `worker` over `items` with at most `size` in flight at once.
async function pool(items, size, worker) {
  let cursor = 0;
  const runners = Array.from({ length: Math.min(size, items.length) }, async () => {
    while (cursor < items.length) {
      const item = items[cursor++];
      await worker(item);
    }
  });
  await Promise.all(runners);
}

// Fetches an OSV endpoint (POST when `body` is given, else GET). Retries only on
// transient failures (network errors, 429, 5xx) with exponential backoff; fails
// fast on other 4xx, attaching the status so the caller can special-case 404.
// Aborts promptly when the job is cancelled.
async function osvFetch(path, body) {
  const url = `${OSV_API}${path}`;
  let lastErr;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    if (job?.cancelled) throw new Error('Cancelled');
    const controller = new AbortController();
    job?.controllers.add(controller);
    let res = null;
    try {
      res = await fetch(url, {
        method: body ? 'POST' : 'GET',
        headers: body ? { 'Content-Type': 'application/json' } : undefined,
        body: body ? JSON.stringify(body) : undefined,
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
      if (res.status === 429 || res.status >= 500) {
        lastErr = new Error(`OSV request failed (${res.status})`); // transient: retry
      } else {
        const err = new Error(`OSV request failed (${res.status})`);
        err.status = res.status;
        throw err; // non-transient 4xx: fail fast
      }
    }
    // Backoff: 400ms, 800ms, 1600ms.
    await sleep(400 * 2 ** attempt);
  }
  throw lastErr || new Error('OSV request failed');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
