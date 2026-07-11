/**
 * Shared NVD 2.0 API pager: cached, throttled, retried. Streams each CVE to a
 * callback so memory stays bounded on the full corpus. Used by the index
 * generator (and can be reused by other tooling).
 *
 * @module scripts/nvd-fetch
 */
import { mkdirSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const PAGE_SIZE = 2000;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Pages the NVD CVE feed, invoking `onVuln` for each `{cve:{...}}` wrapper.
 *
 * @param {{apiKey?:string, cacheDir?:string, samplePages?:number}} opts
 * @param {(wrapper: Object) => void} onVuln
 * @returns {Promise<{fetched:number, total:number, pages:number, sampled:boolean}>}
 */
export async function fetchNvdPages(opts, onVuln) {
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
        res = await fetch(url, { headers: apiKey ? { apiKey } : undefined });
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
  return { fetched, total, pages, sampled: !!samplePages && pages >= samplePages };
}
