/**
 * Turns an lcov.info file (produced by `npm run test:coverage`) into a compact
 * Markdown coverage report, printed to stdout. CI pipes this into the GitHub
 * Actions job summary so the coverage report shows up on the run's page.
 * Run `node scripts/coverage-summary.mjs [path/to/lcov.info]`.
 */
import { readFileSync } from 'node:fs';
import { relative, resolve } from 'node:path';

const lcovPath = resolve(process.argv[2] ?? 'coverage/lcov.info');
const root = process.cwd();

/**
 * Parses lcov into one record per source file, summing the found/hit counters
 * for lines (LF/LH), functions (FNF/FNH) and branches (BRF/BRH).
 */
function parseLcov(text) {
  const files = [];
  let current = null;
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (line.startsWith('SF:')) {
      current = {
        file: line.slice(3),
        lf: 0,
        lh: 0,
        fnf: 0,
        fnh: 0,
        brf: 0,
        brh: 0
      };
    } else if (!current) {
      continue;
    } else if (line.startsWith('LF:')) current.lf = Number(line.slice(3));
    else if (line.startsWith('LH:')) current.lh = Number(line.slice(3));
    else if (line.startsWith('FNF:')) current.fnf = Number(line.slice(4));
    else if (line.startsWith('FNH:')) current.fnh = Number(line.slice(4));
    else if (line.startsWith('BRF:')) current.brf = Number(line.slice(4));
    else if (line.startsWith('BRH:')) current.brh = Number(line.slice(4));
    else if (line === 'end_of_record') {
      files.push(current);
      current = null;
    }
  }
  return files;
}

const pct = (hit, found) => (found === 0 ? 100 : (hit / found) * 100);
const fmt = (value) => `${value.toFixed(2)}%`;

function badge(value) {
  const icon = value >= 90 ? '🟢' : value >= 75 ? '🟡' : '🔴';
  return `${icon} ${fmt(value)}`;
}

const files = parseLcov(readFileSync(lcovPath, 'utf8'));

const totals = files.reduce(
  (acc, f) => {
    acc.lf += f.lf;
    acc.lh += f.lh;
    acc.fnf += f.fnf;
    acc.fnh += f.fnh;
    acc.brf += f.brf;
    acc.brh += f.brh;
    return acc;
  },
  { lf: 0, lh: 0, fnf: 0, fnh: 0, brf: 0, brh: 0 }
);

const lines = pct(totals.lh, totals.lf);
const funcs = pct(totals.fnh, totals.fnf);
const branches = pct(totals.brh, totals.brf);

const out = [];
out.push('## Test coverage');
out.push('');
out.push('| Scope | Lines | Functions | Branches |');
out.push('| --- | --- | --- | --- |');
out.push(`| **All files** | ${badge(lines)} | ${badge(funcs)} | ${badge(branches)} |`);
out.push('');
out.push('<details><summary>Per-file coverage</summary>');
out.push('');
out.push('| File | Lines | Functions | Branches |');
out.push('| --- | --- | --- | --- |');
for (const f of files.sort((a, b) => pct(a.lh, a.lf) - pct(b.lh, b.lf))) {
  const name = relative(root, resolve(root, f.file));
  out.push(
    `| \`${name}\` | ${fmt(pct(f.lh, f.lf))} | ${fmt(pct(f.fnh, f.fnf))} | ${fmt(pct(f.brh, f.brf))} |`
  );
}
out.push('');
out.push('</details>');

process.stdout.write(out.join('\n') + '\n');
