/**
 * NTIA parity check: runs the reference tool, spdx/ntia-conformance-checker,
 * against the bundled sample SBOMs and asserts this app's native NTIA scoring
 * (src/lib/quality.js) agrees with it.
 *
 * The reference tool is Python, so it can't run in the browser. Instead CI runs
 * it against the samples to produce one `<id>.ref.json` per sample (via
 * `sbomcheck <file> --output json`), and this script parses the same samples
 * with the app's own pipeline and compares, element by element.
 *
 * Two classes of facts are compared:
 *
 *   - ALIGNED facts share a definition between the two tools (component name,
 *     version, and the document-level author / timestamp / spec-version checks).
 *     A mismatch here is a real regression and fails the check.
 *
 *   - DIVERGENT facts are ones where this app deliberately uses a stricter or
 *     more meaningful definition than the reference tool's experimental SPDX 3.0
 *     support (see DIVERGENCES for the specifics). They are printed side by side
 *     for transparency but do not fail the check.
 *
 * Usage:
 *   node scripts/check-ntia-parity.mjs --list       # print "<id>\t<path>" lines
 *                                                     # so CI can loop + run sbomcheck
 *   node scripts/check-ntia-parity.mjs <ref-dir>     # compare against
 *                                                     # <ref-dir>/<id>.ref.json
 *
 * Only single-document SPDX 3.0 samples are in scope: the reference tool
 * supports one SBOM per document and rejects SPDX 3.1.
 *
 * @module scripts/check-ntia-parity
 */
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

import { parseGraph, buildRelationshipIndexes } from '../src/parser/parser.js';
import { computeQualityReport } from '../src/lib/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SAMPLES_DIR = resolve(HERE, '../public/samples');

// Single-document SPDX 3.0 samples the reference tool can consume directly.
// Each `file` is relative to public/samples/.
const PARITY_SAMPLES = [
  { id: 'docker', file: 'docker/ubuntu-24.04-linux-amd64.spdx3.jsonld' },
  { id: 'trivy', file: 'trivy/trivy-ubuntu-26-bom.spdx3.json' },
  { id: 'windows', file: 'windows/windows-11.spdx3.json' },
  { id: 'kubernetes', file: 'kubernetes/kubernetes_1_35_3_spdx.jsonld' },
  { id: 'vuejs', file: 'vuejs/vuej-demo-sbom.spdx3.jsonld' },
  { id: 'ai', file: 'ai/simplehtr-example.spdx3.json' }
];

// Elements this app scores differently from the reference tool, and why. These
// are reported but never gated: the app's definition is intentionally the more
// useful one for a viewer.
const DIVERGENCES = {
  totalNumberComponents:
    'reference counts every SPDX object in the graph; this app counts packages',
  'componentIdentifiers.missing':
    'reference treats the mandatory SPDX ID as the identifier (so always present); this app requires a PURL/CPE/external identifier',
  'componentSuppliers.missing':
    'reference checks suppliedBy only; this app also accepts originatedBy',
  dependencyRelationshipsProvided:
    'reference checks the BOM rootElement structure (see their issue #392); this app checks for a dependsOn relationship',
  'componentConcludedLicenses.missing':
    'reference and app resolve SPDX 3.0 concluded licenses differently',
  'componentCopyrightTexts.missing':
    'reference and app resolve SPDX 3.0 copyright text differently',
  isNtiaConformant: 'composite verdict, derived from the diverging elements above'
};

const ALIGNED_KEYS = [
  'componentNames.missing',
  'componentVersions.missing',
  'authorNameProvided',
  'timestampProvided',
  'specVersionProvided'
];
const DIVERGENT_KEYS = Object.keys(DIVERGENCES);

function loadReport(sampleFile) {
  const graph = JSON.parse(readFileSync(join(SAMPLES_DIR, sampleFile), 'utf8'))['@graph'] || [];
  const parsed = parseGraph(graph);
  const indexes = buildRelationshipIndexes(parsed.relationships);
  return computeQualityReport({ ...parsed, ...indexes });
}

// Flatten our ntia report into the reference tool's vocabulary so a single loop
// can diff the two.
function ourFacts(report) {
  const byKey = Object.fromEntries(
    [...report.ntia.elements, ...report.ntia.fsct].map((el) => [el.key, el])
  );
  const missing = (key) => byKey[key].missing.total;
  return {
    isNtiaConformant: report.ntia.isConformant,
    totalNumberComponents: report.ntia.totalComponents,
    authorNameProvided: byKey.author.present,
    timestampProvided: byKey.timestamp.present,
    dependencyRelationshipsProvided: byKey.dependency.present,
    specVersionProvided: !!report.ntia.specVersion,
    'componentNames.missing': missing('name'),
    'componentVersions.missing': missing('version'),
    'componentIdentifiers.missing': missing('identifier'),
    'componentSuppliers.missing': missing('supplier'),
    'componentConcludedLicenses.missing': missing('concludedLicense'),
    'componentCopyrightTexts.missing': missing('copyrightText')
  };
}

function refFacts(ref) {
  const missing = (refKey) => (ref[refKey]?.nonconformantComponents || []).length;
  return {
    isNtiaConformant: !!(ref.isNtiaConformant ?? ref.isConformant),
    totalNumberComponents: ref.totalNumberComponents,
    authorNameProvided: !!ref.authorNameProvided,
    timestampProvided: !!ref.timestampProvided,
    dependencyRelationshipsProvided: !!ref.dependencyRelationshipsProvided,
    specVersionProvided: !!ref.specVersionProvided,
    'componentNames.missing': missing('componentNames'),
    'componentVersions.missing': missing('componentVersions'),
    'componentIdentifiers.missing': missing('componentIdentifiers'),
    'componentSuppliers.missing': missing('componentSuppliers'),
    'componentConcludedLicenses.missing': missing('componentConcludedLicenses'),
    'componentCopyrightTexts.missing': missing('componentCopyrightTexts')
  };
}

function compareSample(id, sampleFile, refDir) {
  const refPath = join(refDir, `${id}.ref.json`);
  if (!existsSync(refPath)) {
    return { id, skipped: true, reason: `no reference JSON at ${refPath}` };
  }
  const ref = JSON.parse(readFileSync(refPath, 'utf8'));
  if (ref.parsingError && ref.parsingError.length) {
    return { id, skipped: true, reason: 'reference tool reported a parsing error' };
  }
  const ours = ourFacts(loadReport(sampleFile));
  const theirs = refFacts(ref);
  const alignedMismatches = ALIGNED_KEYS.filter((k) => ours[k] !== theirs[k]).map((k) => ({
    key: k,
    ours: ours[k],
    ref: theirs[k]
  }));
  const divergences = DIVERGENT_KEYS.map((k) => ({
    key: k,
    ours: ours[k],
    ref: theirs[k],
    same: ours[k] === theirs[k]
  }));
  return { id, alignedMismatches, divergences };
}

function main() {
  const args = process.argv.slice(2);

  if (args[0] === '--list') {
    for (const s of PARITY_SAMPLES) process.stdout.write(`${s.id}\t${s.file}\n`);
    return;
  }

  const refDir = args[0];
  if (!refDir) {
    console.error('usage: node scripts/check-ntia-parity.mjs <ref-dir> | --list');
    process.exit(2);
  }

  let failed = 0;
  let compared = 0;
  for (const { id, file } of PARITY_SAMPLES) {
    const result = compareSample(id, file, refDir);
    if (result.skipped) {
      console.log(`– ${id}: skipped (${result.reason})`);
      continue;
    }
    compared++;
    if (result.alignedMismatches.length === 0) {
      console.log(`✓ ${id}: aligned NTIA elements match the reference tool`);
    } else {
      failed++;
      console.log(`✗ ${id}: ${result.alignedMismatches.length} aligned mismatch(es)`);
      for (const m of result.alignedMismatches) {
        console.log(`    ${m.key}: ours=${m.ours} reference=${m.ref}`);
      }
    }
    const divergedHere = result.divergences.filter((d) => !d.same);
    if (divergedHere.length) {
      console.log(`    (intentional divergences: ${divergedHere.map((d) => d.key).join(', ')})`);
    }
  }

  console.log('');
  console.log('Intentional divergences from the reference tool (not gated):');
  for (const [key, reason] of Object.entries(DIVERGENCES)) {
    console.log(`  • ${key}: ${reason}`);
  }

  console.log(`\n${compared} sample(s) compared, ${failed} with aligned mismatches.`);
  if (compared === 0) {
    console.error('No reference JSON found: did the reference tool run?');
    process.exit(1);
  }
  if (failed > 0) process.exit(1);
}

main();
