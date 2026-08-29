/**
 * Shared NVD 2.0 corpus loader. Streams each CVE to a callback so memory stays
 * bounded on the full corpus. Used by the index generator.
 *
 * Default source is the yearly JSON 2.0 gzip feeds (no API key, no per-page
 * rate limit). `--source api` pages the REST API instead; without an API key
 * that takes ~1h+ from GitHub-hosted runners and often hits the job timeout.
 *
 * @module scripts/nvd-fetch
 */
import { createHash } from 'node:crypto';
import { mkdirSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';

const NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const NVD_FEED = 'https://nvd.nist.gov/feeds/json/cve/2.0';
const PAGE_SIZE = 2000;
const FEED_FIRST_YEAR = 2002;
const UA = 'spdx3-viz nvd-index (https://github.com/kartben/spdx3_viz)';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Pages or downloads the NVD CVE corpus, invoking `onVuln` for each
 * `{cve:{...}}` wrapper.
 *
 * @param {{
 *   apiKey?: string,
 *   cacheDir?: string,
 *   samplePages?: number,
 *   source?: 'feeds' | 'api',
 *   feedYears?: number[],
 *   feedBase?: string
 * }} opts
 * @param {(wrapper: Object) => void} onVuln
 * @returns {Promise<{fetched:number, total:number, pages:number, sampled:boolean, source:string}>}
 */
export async function fetchNvdPages(opts, onVuln) {
  const source = opts?.source === 'api' ? 'api' : 'feeds';
  return source === 'api' ? fetchFromApi(opts, onVuln) : fetchFromFeeds(opts, onVuln);
}

export function defaultFeedYears(now = new Date()) {
  const last = now.getUTCFullYear();
  const years = [];
  for (let y = FEED_FIRST_YEAR; y <= last; y++) years.push(y);
  return years;
}

async function fetchFromFeeds(opts, onVuln) {
  const { cacheDir = '', samplePages = 0, feedBase = NVD_FEED } = opts || {};
  const years =
    Array.isArray(opts?.feedYears) && opts.feedYears.length ? opts.feedYears : defaultFeedYears();
  if (cacheDir) mkdirSync(cacheDir, { recursive: true });
  const limit = samplePages > 0 ? samplePages * PAGE_SIZE : Infinity;

  let fetched = 0;
  let total = 0;
  let pages = 0;
  for (const year of years) {
    const data = await getYearFeed(year, {
      cacheDir,
      feedBase,
      // The current calendar year's feed may not exist yet in early January.
      required: year < new Date().getUTCFullYear()
    });
    if (!data) continue;
    const vulns = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
    total += Number.isFinite(data.totalResults) ? data.totalResults : vulns.length;
    pages++;
    for (const v of vulns) {
      if (fetched >= limit) break;
      onVuln(v);
      fetched++;
    }
    process.stderr.write(
      `\rfetched ${fetched.toLocaleString()} CVEs (${pages} year feed${pages === 1 ? '' : 's'})…`
    );
    if (fetched >= limit) break;
  }
  process.stderr.write('\n');
  return {
    fetched,
    total: samplePages ? fetched : total,
    pages,
    sampled: !!samplePages && fetched >= limit,
    source: 'feeds'
  };
}

async function getYearFeed(year, { cacheDir, feedBase, required }) {
  const name = `nvdcve-2.0-${year}`;
  const gzUrl = `${feedBase}/${name}.json.gz`;
  const metaUrl = `${feedBase}/${name}.meta`;
  const cacheGz = cacheDir ? join(cacheDir, `${name}.json.gz`) : '';

  const expectedSha = await readFeedSha(metaUrl);
  if (cacheGz && expectedSha && existsSync(cacheGz)) {
    const raw = decodeFeed(readFileSync(cacheGz));
    if (sha256hex(raw) === expectedSha) return JSON.parse(raw.toString('utf8'));
  }

  let gz = await fetchBuffer(gzUrl, { acceptMissing: !required });
  if (!gz) return null;
  let raw = decodeFeed(gz);
  if (expectedSha && sha256hex(raw) !== expectedSha) {
    gz = await fetchBuffer(gzUrl, { acceptMissing: !required });
    if (!gz) return null;
    raw = decodeFeed(gz);
    if (sha256hex(raw) !== expectedSha) throw new Error(`${name} sha256 mismatch`);
  }
  if (cacheGz) writeFileSync(cacheGz, gz);
  return JSON.parse(raw.toString('utf8'));
}

async function readFeedSha(metaUrl) {
  try {
    const text = await fetchText(metaUrl, { acceptMissing: true });
    if (!text) return '';
    const match = text.match(/sha256\s*:\s*([0-9a-f]+)/i);
    return match ? match[1].toLowerCase() : '';
  } catch {
    return '';
  }
}

async function fetchFromApi(opts, onVuln) {
  const { apiKey = '', cacheDir = '', samplePages = 0 } = opts || {};
  if (cacheDir) mkdirSync(cacheDir, { recursive: true });
  const minInterval = apiKey ? 700 : 6500;
  let last = 0;
  const throttle = async () => {
    const wait = last + minInterval - Date.now();
    if (wait > 0) await sleep(wait);
    last = Date.now();
  };
  const getPage = async (startIndex) => {
    const cacheFile = cacheDir ? join(cacheDir, `page-${startIndex}.json`) : '';
    if (cacheFile && existsSync(cacheFile)) return JSON.parse(readFileSync(cacheFile, 'utf8'));
    const url = `${NVD_API}?resultsPerPage=${PAGE_SIZE}&startIndex=${startIndex}`;
    for (let attempt = 0; ; attempt++) {
      await throttle();
      let res;
      try {
        res = await fetch(url, { headers: headers(apiKey) });
      } catch (err) {
        if (attempt >= 5) throw err;
        await sleep(4000 * 2 ** attempt);
        continue;
      }
      if (res.ok) {
        const data = await res.json();
        if (cacheFile) writeFileSync(cacheFile, JSON.stringify(data));
        return data;
      }
      if ((res.status === 403 || res.status === 429 || res.status >= 500) && attempt < 5) {
        await sleep(4000 * 2 ** attempt);
        continue;
      }
      throw new Error(`NVD request failed (${res.status}) at startIndex=${startIndex}`);
    }
  };

  let startIndex = 0;
  let total = Infinity;
  let fetched = 0;
  let pages = 0;
  while (startIndex < total) {
    const data = await getPage(startIndex);
    total = Number.isFinite(data.totalResults) ? data.totalResults : 0;
    const vulns = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
    for (const v of vulns) onVuln(v);
    fetched += vulns.length;
    startIndex += vulns.length || PAGE_SIZE;
    pages++;
    process.stderr.write(`\rfetched ${fetched}/${total} CVEs (${pages} pages)…`);
    if (!vulns.length) break;
    if (samplePages && pages >= samplePages) break;
  }
  process.stderr.write('\n');
  return {
    fetched,
    total,
    pages,
    sampled: !!samplePages && pages >= samplePages,
    source: 'api'
  };
}

function headers(apiKey) {
  const h = { 'User-Agent': UA };
  if (apiKey) h.apiKey = apiKey;
  return h;
}

function decodeFeed(buf) {
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) return gunzipSync(buf);
  return buf;
}

function sha256hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

async function fetchText(url, { acceptMissing = false } = {}) {
  const buf = await fetchBuffer(url, { acceptMissing });
  return buf ? buf.toString('utf8') : '';
}

async function fetchBuffer(url, { acceptMissing = false } = {}) {
  for (let attempt = 0; ; attempt++) {
    let res;
    try {
      res = await fetch(url, { headers: headers(), signal: AbortSignal.timeout(120_000) });
    } catch (err) {
      if (attempt >= 5) throw err;
      await sleep(4000 * 2 ** attempt);
      continue;
    }
    if (res.status === 404 && acceptMissing) return null;
    if (res.ok) return Buffer.from(await res.arrayBuffer());
    if ((res.status === 403 || res.status === 429 || res.status >= 500) && attempt < 5) {
      await sleep(4000 * 2 ** attempt);
      continue;
    }
    throw new Error(`NVD request failed (${res.status}) for ${url}`);
  }
}
