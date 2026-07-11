/**
 * Builds the statically-servable NVD CPE→CVE index the app can match against
 * without calling NVD live (no CORS, no rate limits, offline). It downloads NVD,
 * distills each CVE to the fields the matcher needs (via the shipped
 * `normalizeNvdCve`), groups by vendor:product, and writes a packed artifact:
 *
 *   <out>/manifest.json          - { schema, generated, parts, index: {"v p":[part,off,len]} }
 *   <out>/part-000.ndjson ...    - concatenated per-product shards (one JSON array each)
 *
 * The client fetches manifest.json once, then HTTP Range-fetches only the byte
 * spans for the products in its SBOM. Descriptions are omitted to keep it small.
 *
 * Usage:
 *   NVD_API_KEY=xxxx node --max-old-space-size=8192 scripts/build-nvd-index.mjs --out public/nvd-cpe
 *
 * Options:
 *   --out <dir>         Output directory (required).
 *   --api-key <key>     NVD API key (or NVD_API_KEY env); ~8x faster.
 *   --cache-dir <dir>   Cache raw API pages (default .nvd-cache).
 *   --sample-pages <n>  Only fetch N pages (2000 CVEs each) — for a quick/test build.
 *   --part-mb <n>       Target part-file size in MB (default 40; keep < 100 for Pages).
 *   --generated <date>  Override the manifest `generated` stamp (default: today, UTC).
 *
 * @module scripts/build-nvd-index
 */
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';

import { normalizeNvdCve } from '../src/lib/nvd.js';
import { parseCpe } from '../src/lib/provenance.js';
import { bundleKey } from '../src/lib/nvd-bundle.js';
import { fetchNvdPages } from './nvd-fetch.mjs';

const SEV_CODE = { critical: 'c', high: 'h', medium: 'm', low: 'l', none: 'n' };

function parseArgs(argv) {
  const args = { cacheDir: '.nvd-cache', samplePages: 0, partMb: 40, out: '', generated: '' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--out') args.out = argv[++i];
    else if (a === '--api-key') args.apiKey = argv[++i];
    else if (a === '--cache-dir') args.cacheDir = argv[++i];
    else if (a === '--sample-pages') args.samplePages = Number(argv[++i]);
    else if (a === '--part-mb') args.partMb = Number(argv[++i]);
    else if (a === '--generated') args.generated = argv[++i];
  }
  args.apiKey = args.apiKey || process.env.NVD_API_KEY || '';
  return args;
}

function compactRange(cm) {
  const p = parseCpe(cm.criteria);
  const exact = p?.version || '';
  const r = {};
  if (exact) r.x = exact;
  if (cm.versionStartIncluding) r.si = cm.versionStartIncluding;
  if (cm.versionStartExcluding) r.se = cm.versionStartExcluding;
  if (cm.versionEndIncluding) r.ei = cm.versionEndIncluding;
  if (cm.versionEndExcluding) r.ee = cm.versionEndExcluding;
  return r;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.out) throw new Error('missing --out <dir>');

  // productKey -> Map<cveId, row>
  const index = new Map();
  let cves = 0;

  const onVuln = (wrapper) => {
    cves++;
    const n = normalizeNvdCve(wrapper);
    if (!n.cveId) return;
    const byProduct = new Map();
    for (const cm of n.cpeMatches) {
      if (cm.vulnerable === false) continue;
      const p = parseCpe(cm.criteria);
      if (!p || !p.vendor || !p.product) continue;
      const key = bundleKey(p.vendor, p.product);
      if (!byProduct.has(key)) byProduct.set(key, []);
      byProduct.get(key).push(compactRange(cm));
    }
    if (!byProduct.size) return;
    const row = {
      id: n.cveId.replace(/^CVE-/, ''),
      sc: n.cvss?.score ?? null,
      sv: SEV_CODE[n.cvss?.severity] || '',
      cv: n.cvss?.version || '',
      cw: (n.cwes || []).map((c) => Number(String(c).replace(/^CWE-/i, '')) || 0).filter(Boolean),
      pub: (n.published || '').slice(0, 10)
    };
    for (const [key, ranges] of byProduct) {
      if (!index.has(key)) index.set(key, new Map());
      index.get(key).set(n.cveId, { ...row, r: ranges });
    }
  };

  const info = await fetchNvdPages(args, onVuln);

  // --- write packed parts + manifest -------------------------------------
  const out = args.out;
  if (existsSync(out)) rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });

  const partMax = Math.max(1, args.partMb) * 1000 * 1000;
  const NL = Buffer.from('\n');
  const parts = [];
  const manifestIndex = {};
  let partIdx = 0;
  let partChunks = [];
  let partLen = 0;

  const flushPart = () => {
    if (!partChunks.length) return;
    const name = `part-${String(partIdx).padStart(3, '0')}.ndjson`;
    writeFileSync(join(out, name), Buffer.concat(partChunks));
    parts.push(name);
    partIdx++;
    partChunks = [];
    partLen = 0;
  };

  // Deterministic product order so rebuilds diff cleanly.
  for (const key of [...index.keys()].sort()) {
    const rows = [...index.get(key).values()];
    const buf = Buffer.from(JSON.stringify(rows));
    if (partLen && partLen + buf.length > partMax) flushPart();
    const offset = partLen;
    partChunks.push(buf, NL);
    partLen += buf.length + NL.length;
    manifestIndex[key] = [partIdx, offset, buf.length];
  }
  flushPart();

  const manifest = {
    schema: 1,
    source: 'NVD 2.0',
    // NVD Terms of Use (https://nvd.nist.gov/developers/terms-of-use): the NVD
    // must be credited as the source, and consumers must not imply endorsement.
    notice:
      'This data is derived from the U.S. National Vulnerability Database (NVD, ' +
      'https://nvd.nist.gov). This product uses data from the NVD API but is not ' +
      'endorsed or certified by the NVD. CVE is a registered trademark of MITRE.',
    generated: args.generated || new Date().toISOString().slice(0, 10),
    totalCves: cves,
    products: index.size,
    parts,
    index: manifestIndex
  };
  writeFileSync(join(out, 'manifest.json'), JSON.stringify(manifest));

  // Tiny sidecar with everything but the (multi-MB) index, so the app can show
  // the snapshot's build date without downloading the full manifest.
  const { index: _omit, ...meta } = manifest;
  writeFileSync(join(out, 'meta.json'), JSON.stringify(meta));

  const manifestBytes = Buffer.byteLength(JSON.stringify(manifest));
  process.stderr.write(
    `\nWrote ${index.size.toLocaleString()} products across ${parts.length} part(s) to ${out}` +
      `${info.sampled ? ' (SAMPLE)' : ''}\n` +
      `  manifest.json: ${(manifestBytes / 1e6).toFixed(1)} MB\n`
  );
}

main().catch((err) => {
  console.error('\nbuild failed:', err.message);
  process.exitCode = 1;
});
