/**
 * Installs a freshly generated Zephyr SBOM as the bundled "zephyr" sample.
 * Run by .github/workflows/zephyr-sbom.yml after `west spdx`:
 *
 *   node scripts/update-zephyr-sample.mjs --spdx-dir build/spdx --zephyr-sha <commit>
 *
 * Replaces the .jsonld files in public/samples/zephyr/ with the ones in
 * --spdx-dir, then updates the sample's entry in public/samples/samples.json
 * (file list, total size, and a description naming the Zephyr commit).
 */
import { copyFileSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { format, resolveConfig } from 'prettier';

const here = dirname(fileURLToPath(import.meta.url));
const samplesDir = resolve(here, '../public/samples');
const sampleDir = join(samplesDir, 'zephyr');
const manifestPath = join(samplesDir, 'samples.json');

// Load order shown in the sample picker; documents west spdx adds later are
// appended after these, alphabetically.
const PREFERRED_ORDER = ['app.jsonld', 'modules-deps.jsonld', 'zephyr.jsonld', 'build.jsonld'];

const { values } = parseArgs({
  options: {
    'spdx-dir': { type: 'string' },
    'zephyr-sha': { type: 'string' }
  }
});
const spdxDir = values['spdx-dir'];
const sha = values['zephyr-sha'] || '';
if (!spdxDir || !/^[0-9a-f]{40}$/.test(sha)) {
  console.error('usage: update-zephyr-sample.mjs --spdx-dir <dir> --zephyr-sha <40-hex commit>');
  process.exit(1);
}

const generated = readdirSync(spdxDir).filter((f) => f.endsWith('.jsonld'));
const missing = PREFERRED_ORDER.filter((f) => !generated.includes(f));
if (missing.length) {
  console.error(`west spdx did not produce: ${missing.join(', ')}`);
  process.exit(1);
}
const files = [...PREFERRED_ORDER, ...generated.filter((f) => !PREFERRED_ORDER.includes(f)).sort()];

for (const f of readdirSync(sampleDir)) {
  if (f.endsWith('.jsonld')) rmSync(join(sampleDir, f));
}
let size = 0;
for (const f of files) {
  copyFileSync(join(spdxDir, f), join(sampleDir, f));
  size += statSync(join(sampleDir, f)).size;
}

const commitUrl = `https://github.com/zephyrproject-rtos/zephyr/commit/${sha}`;
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
const entry = manifest.find((s) => s.id === 'zephyr');
if (!entry) {
  console.error('No "zephyr" entry in samples.json');
  process.exit(1);
}
entry.description =
  'LVGL demos on M5Stack CoreS3, rebuilt weekly from Zephyr <code>main</code> ' +
  `(<a href="${commitUrl}" target="_blank" rel="noopener" onclick="event.stopPropagation()">` +
  `<code>${sha.slice(0, 7)}</code></a>).`;
entry.files = files;
entry.size = size;

const config = (await resolveConfig(manifestPath)) || {};
writeFileSync(
  manifestPath,
  await format(JSON.stringify(manifest), { ...config, filepath: manifestPath })
);

console.log(`Installed ${files.length} documents (${size} bytes) from Zephyr ${sha}`);
