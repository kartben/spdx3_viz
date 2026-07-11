# Bundled NVD CPE index

The Security view can match components against NVD by CPE in two ways:

- **Live API** – queries `services.nvd.nist.gov` directly from the browser. Always
  current, but subject to NVD's rate limits and to browser CORS.
- **Bundled index** – matches against a pre-built, statically-hosted snapshot of
  NVD's CPE→CVE data. No rate limits, no CORS, works offline. This document
  covers building and hosting that snapshot.

Both use the same matching logic, so they return the same findings; the bundle
only changes _delivery_ (speed/offline), not coverage.

## What the artifact is

`scripts/build-nvd-index.mjs` downloads NVD, distills each CVE to the fields the
matcher needs, groups by `vendor:product`, and writes:

- `manifest.json` – `{ schema, notice, generated, products, parts, index }`, where
  `index` maps `"vendor product"` → `[partIndex, byteOffset, byteLength]`.
- `meta.json` – the same fields **minus** `index`, so the app can show the
  snapshot's build date in the source hint without downloading the full manifest.
- `part-000.ndjson`, `part-001.ndjson`, … – packed per-product shards.

The client fetches `manifest.json` once, then HTTP **Range**-fetches only the byte
spans for the products in its SBOM. Descriptions are omitted to keep it small.

Approximate full-corpus size (measured): ~120k products, **~118 MB uncompressed /
~9 MB gzip / ~6 MB brotli**, across a handful of part files.

## Building it

```bash
# Full corpus (set an NVD API key to run ~8x faster):
NVD_API_KEY=xxxx node --max-old-space-size=8192 scripts/build-nvd-index.mjs --out public/nvd-cpe

# Quick test build (first 5 pages ≈ 10k CVEs):
node scripts/build-nvd-index.mjs --out /tmp/nvd-cpe --sample-pages 5
```

The **Build NVD bundled index** GitHub workflow
(`.github/workflows/build-nvd-index.yml`) does this weekly (and on demand) and
publishes the files as assets on a rolling `nvd-index` pre-release. Set an
`NVD_API_KEY` repository secret to speed it up.

## Hosting it

The app's **Bundled index** source has a configurable base URL (default
`./nvd-cpe/`). Point it at wherever the files are served. Options:

1. **Same-origin (recommended, no CORS):** copy the generated files into the Pages
   deploy under `/nvd-cpe/` and leave the base URL at `./nvd-cpe/`. Generate them
   in the deploy job (don't commit ~118 MB to git).
2. **Release assets:** the workflow uploads to the `nvd-index` release; set the
   base URL to that release's asset download path. (Range works; confirm CORS on
   your first real fetch.)
3. **jsDelivr from a branch/tag** (guarantees CORS + Range) if you commit the
   files to a dedicated branch — at the cost of git size.

The host must support HTTP **Range** requests for efficient per-product fetches;
if a host ignores Range, the worker falls back to fetching the whole part and
slicing locally (correct, just less efficient).

## Attribution — NVD Terms of Use

This data is derived from the U.S. National Vulnerability Database (NVD,
<https://nvd.nist.gov>). Per the
[NVD Terms of Use](https://nvd.nist.gov/developers/terms-of-use):

> This product uses data from the NVD API but is not endorsed or certified by the
> NVD.

CVE is a registered trademark of MITRE. The app surfaces this notice in the
Security view (NVD options) and on each NVD-sourced finding, and the generated
`manifest.json` carries it in its `notice` field. Keep that attribution intact
when redistributing the index.
