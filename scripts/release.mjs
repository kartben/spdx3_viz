/**
 * Release automation for spdx3-viz.
 *
 * Drives a release entirely from data already in the repo: package.json holds
 * the in-development version as `X.Y.Z-dev`, and CHANGELOG.md collects notes
 * under a `## Unreleased` heading. Releasing means turning that dev version
 * into a real one, dating the changelog, tagging, then reopening a fresh dev
 * cycle. This script only edits files and prints values; committing, tagging
 * and pushing are left to the caller (the release workflow or a human).
 *
 * Subcommands:
 *
 *   node scripts/release.mjs resolve <spec>
 *       Print the release version and next dev version for <spec> without
 *       touching any files. <spec> is one of: auto | patch | minor | major |
 *       an explicit X.Y.Z. With --github-output, also append them to the file
 *       named by $GITHUB_OUTPUT (release=, dev=, tag=).
 *
 *   node scripts/release.mjs prepare <spec> [--date YYYY-MM-DD]
 *       Cut the release: set package.json / package-lock.json to the release
 *       version, rename `## Unreleased` to `## [X.Y.Z] - <date>`, and
 *       regenerate src/changelog.js. This is the commit that gets tagged.
 *
 *   node scripts/release.mjs bump-dev [--next X.Y.Z-dev]
 *       Reopen development after a release: bump package.json /
 *       package-lock.json to the next `-dev` version, add a fresh empty
 *       `## Unreleased` heading, and regenerate src/changelog.js.
 *
 *   node scripts/release.mjs notes [version]
 *       Print the changelog bullets for <version> (default: the newest dated
 *       release) to stdout, for use as GitHub release notes.
 *
 * Global flags: --dry-run prints intended changes without writing files.
 */
import { readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const paths = {
  pkg: resolve(root, 'package.json'),
  lock: resolve(root, 'package-lock.json'),
  changelog: resolve(root, 'CHANGELOG.md'),
  genChangelog: resolve(here, 'gen-changelog.mjs')
};

const SEMVER_RE = /^(\d+)\.(\d+)\.(\d+)(?:-(.+))?$/;
// Matches the project's own version field in package.json / package-lock.json.
// Anchoring on the immediately-preceding `"name": "spdx3-viz"` keeps us from
// touching the many dependency version fields in the lockfile.
const PROJECT_VERSION_RE = /("name":\s*"spdx3-viz",\s*"version":\s*")([^"]+)(")/g;
const DATED_HEADING_RE = /^##\s+\[(\d+\.\d+\.\d+)\]\s*-\s*(\d{4}-\d{2}-\d{2})\s*$/;

function fail(message) {
  console.error(`release: ${message}`);
  process.exit(1);
}

function parseSemver(version) {
  const m = SEMVER_RE.exec(version.trim());
  if (!m) fail(`cannot parse version "${version}"`);
  return { major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] || '' };
}

const base = ({ major, minor, patch }) => `${major}.${minor}.${patch}`;

function readPkgVersion() {
  const m = PROJECT_VERSION_RE.exec(readFileSync(paths.pkg, 'utf8'));
  PROJECT_VERSION_RE.lastIndex = 0;
  if (!m) fail('could not find the project version in package.json');
  return m[2];
}

/** The newest `## [X.Y.Z] - date` version in the changelog, or null. */
function lastReleasedVersion() {
  for (const line of readFileSync(paths.changelog, 'utf8').split('\n')) {
    const m = DATED_HEADING_RE.exec(line);
    if (m) return m[1];
  }
  return null;
}

/**
 * Resolve a spec into { release, dev, tag }. `release` is what we tag now;
 * `dev` is the next in-development version we reopen afterwards.
 */
function resolveVersions(spec) {
  const current = parseSemver(readPkgVersion());
  let release;
  if (SEMVER_RE.test(spec) && !parseSemver(spec).pre) {
    release = base(parseSemver(spec));
  } else if (spec === 'auto' || spec === '' || spec === undefined) {
    // Ship whatever the current -dev version is heading toward.
    release = base(current);
  } else if (['patch', 'minor', 'major'].includes(spec)) {
    // Bump relative to the last real release so the level is meaningful even
    // when the dev version already anticipates a patch.
    const prev = parseSemver(lastReleasedVersion() || base(current));
    const bumped =
      spec === 'major'
        ? { major: prev.major + 1, minor: 0, patch: 0 }
        : spec === 'minor'
          ? { major: prev.major, minor: prev.minor + 1, patch: 0 }
          : { major: prev.major, minor: prev.minor, patch: prev.patch + 1 };
    release = base(bumped);
  } else {
    fail(`unknown version spec "${spec}" (use auto|patch|minor|major|X.Y.Z)`);
  }
  const r = parseSemver(release);
  const dev = `${r.major}.${r.minor}.${r.patch + 1}-dev`;
  return { release, dev, tag: `v${release}` };
}

function setProjectVersion(file, version) {
  const text = readFileSync(file, 'utf8');
  let replaced = 0;
  const next = text.replace(PROJECT_VERSION_RE, (_all, a, _old, c) => {
    replaced++;
    return `${a}${version}${c}`;
  });
  if (!replaced) fail(`no project version field found in ${file}`);
  return next;
}

function regenChangelog() {
  execFileSync('node', [paths.genChangelog], { stdio: 'inherit' });
}

/** Return the lines of the section under `## <heading match>` up to the next `## `. */
function sectionBody(markdown, matchHeading) {
  const lines = markdown.split('\n');
  const start = lines.findIndex((l) => l.startsWith('## ') && matchHeading(l));
  if (start === -1) return null;
  const body = [];
  for (let i = start + 1; i < lines.length; i++) {
    if (lines[i].startsWith('## ')) break;
    body.push(lines[i]);
  }
  return body;
}

// --- Subcommands ------------------------------------------------------------

function cmdResolve(spec, flags) {
  const v = resolveVersions(spec);
  console.log(`release=${v.release}`);
  console.log(`dev=${v.dev}`);
  console.log(`tag=${v.tag}`);
  if (flags.githubOutput && process.env.GITHUB_OUTPUT) {
    appendFileSync(process.env.GITHUB_OUTPUT, `release=${v.release}\ndev=${v.dev}\ntag=${v.tag}\n`);
  }
  return v;
}

function cmdPrepare(spec, flags) {
  const { release, tag } = resolveVersions(spec);
  const date = flags.date || isoDate();

  const changelog = readFileSync(paths.changelog, 'utf8');
  const body = sectionBody(changelog, (l) => l.trim() === '## Unreleased');
  if (body === null) fail('no "## Unreleased" section in CHANGELOG.md');
  const hasItems = body.some((l) => l.trim().startsWith('- '));
  if (!hasItems && !flags.allowEmpty) {
    fail('the Unreleased section is empty; add notes or pass --allow-empty');
  }
  const nextChangelog = changelog.replace(/^##\s+Unreleased[ \t]*$/m, `## [${release}] - ${date}`);

  const nextPkg = setProjectVersion(paths.pkg, release);
  const nextLock = setProjectVersion(paths.lock, release);

  if (flags.dryRun) {
    console.log(`[dry-run] would release ${release} (${tag}) dated ${date}`);
    return;
  }
  writeFileSync(paths.pkg, nextPkg);
  writeFileSync(paths.lock, nextLock);
  writeFileSync(paths.changelog, nextChangelog);
  regenChangelog();
  console.log(`Prepared release ${release} (${tag}) dated ${date}`);
}

function cmdBumpDev(flags) {
  const current = parseSemver(readPkgVersion());
  const dev = flags.next || `${current.major}.${current.minor}.${current.patch + 1}-dev`;
  parseSemver(dev); // validate

  const changelog = readFileSync(paths.changelog, 'utf8');
  if (/^##\s+Unreleased\s*$/m.test(changelog)) {
    fail('CHANGELOG.md already has an "## Unreleased" section');
  }
  // Insert a fresh, empty Unreleased heading just above the newest release.
  const nextChangelog = changelog.replace(/^(##\s+\[)/m, `## Unreleased\n\n$1`);

  const nextPkg = setProjectVersion(paths.pkg, dev);
  const nextLock = setProjectVersion(paths.lock, dev);

  if (flags.dryRun) {
    console.log(`[dry-run] would reopen development at ${dev}`);
    return;
  }
  writeFileSync(paths.pkg, nextPkg);
  writeFileSync(paths.lock, nextLock);
  writeFileSync(paths.changelog, nextChangelog);
  regenChangelog();
  console.log(`Reopened development at ${dev}`);
}

function cmdNotes(version) {
  const changelog = readFileSync(paths.changelog, 'utf8');
  const match = version
    ? (l) => {
        const m = DATED_HEADING_RE.exec(l);
        return m && m[1] === version.replace(/^v/, '');
      }
    : (l) => DATED_HEADING_RE.test(l);
  const body = sectionBody(changelog, match);
  if (body === null) fail(`no changelog section found for "${version || 'latest'}"`);
  console.log(body.join('\n').trim());
}

function isoDate() {
  // Prefer an explicit override so CI runs are reproducible; otherwise today.
  if (process.env.RELEASE_DATE) return process.env.RELEASE_DATE;
  return new Date().toISOString().slice(0, 10);
}

// --- CLI --------------------------------------------------------------------

function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dry-run') flags.dryRun = true;
    else if (a === '--github-output') flags.githubOutput = true;
    else if (a === '--allow-empty') flags.allowEmpty = true;
    else if (a === '--date') flags.date = argv[++i];
    else if (a === '--next') flags.next = argv[++i];
    else positional.push(a);
  }
  return { positional, flags };
}

const { positional, flags } = parseArgs(process.argv.slice(2));
const [command, arg] = positional;

switch (command) {
  case 'resolve':
    cmdResolve(arg ?? 'auto', flags);
    break;
  case 'prepare':
    cmdPrepare(arg ?? 'auto', flags);
    break;
  case 'bump-dev':
    cmdBumpDev(flags);
    break;
  case 'notes':
    cmdNotes(arg);
    break;
  default:
    fail(`unknown command "${command ?? ''}" (use resolve|prepare|bump-dev|notes)`);
}
