/**
 * Generates src/lib/osadl-matrix.js from OSADL's published compatibility
 * matrix. The matrix is vendored rather than fetched at runtime because
 * osadl.org serves it without CORS headers, so a browser cannot read it, and
 * because license compatibility should still work on an offline build.
 *
 * The upstream JSON is ~275 KB of repeated "Yes"/"No" strings; this rewrites it
 * as one character per cell (~16 KB, 1.7 KB gzipped).
 *
 * Run `node scripts/gen-osadl-matrix.mjs` to refresh it.
 */
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { format, resolveConfig } from 'prettier';

const SOURCE_URL = 'https://www.osadl.org/fileadmin/checklists/matrix.json';

// Upstream verdict -> the single character stored per cell. Kept in sync with
// COMPAT_CODES in src/lib/osadl-matrix.js.
const CODE = {
  Same: 'S',
  Yes: 'Y',
  No: 'N',
  Unknown: 'U',
  'Check dependency': 'D'
};

const here = dirname(fileURLToPath(import.meta.url));
const outPath = resolve(here, '../src/lib/osadl-matrix.js');

const res = await fetch(SOURCE_URL);
if (!res.ok) throw new Error(`${SOURCE_URL} responded ${res.status}`);
const raw = await res.json();

const timestamp = typeof raw.timestamp === 'string' ? raw.timestamp : '';
if (!timestamp) throw new Error('Upstream matrix has no timestamp');

const licenses = Object.keys(raw).filter((key) => key !== 'timeformat' && key !== 'timestamp');
if (licenses.length < 100) throw new Error(`Only ${licenses.length} licenses parsed; refusing`);

const rows = licenses.map((outbound) =>
  licenses
    .map((inbound) => {
      const verdict = raw[outbound]?.[inbound];
      const code = CODE[verdict];
      if (!code) throw new Error(`Unknown verdict "${verdict}" at ${outbound} / ${inbound}`);
      return code;
    })
    .join('')
);

const source = `/**
 * OSADL's FOSS license compatibility matrix, vendored.
 *
 * GENERATED FILE: run \`node scripts/gen-osadl-matrix.mjs\` to refresh.
 * Source: ${SOURCE_URL}
 *
 * ROWS[i][j] is the verdict for taking license COMPAT_LICENSES[j] (inbound,
 * the component) into a work distributed under COMPAT_LICENSES[i] (outbound).
 * The relation is directional: rows and columns are not interchangeable.
 *
 * @module lib/osadl-matrix
 */

/** ISO timestamp of the upstream matrix this file was generated from. */
export const COMPAT_MATRIX_DATE = ${JSON.stringify(timestamp)};

/** Where the matrix comes from, for attribution in the UI. */
export const COMPAT_MATRIX_URL = 'https://www.osadl.org/html/CompatMatrix.html';

/** Cell codes, in the order they rank from worst to best outcome. */
export const COMPAT_CODES = ${JSON.stringify(CODE, null, 2)
  .split('\n')
  .map((line, i) => (i === 0 ? line : `  ${line}`))
  .join('\n')};

/** SPDX identifiers covered by the matrix, in row/column order. */
export const COMPAT_LICENSES = ${JSON.stringify(licenses, null, 2)
  .split('\n')
  .map((line, i) => (i === 0 ? line : `  ${line}`))
  .join('\n')};

/** One string per outbound license; character j is the verdict for inbound j. */
export const COMPAT_ROWS = ${JSON.stringify(rows, null, 2)
  .split('\n')
  .map((line, i) => (i === 0 ? line : `  ${line}`))
  .join('\n')};
`;

const prettierConfig = (await resolveConfig(outPath)) || {};
writeFileSync(outPath, await format(source, { ...prettierConfig, filepath: outPath }));

console.log(
  `Wrote ${outPath}: ${licenses.length} licenses, matrix dated ${timestamp.slice(0, 10)}.`
);
