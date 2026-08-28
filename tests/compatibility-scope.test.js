import assert from 'node:assert/strict';
import test from 'node:test';

import { compatibilityMixin } from '../src/app/compatibility.js';

// The scope walk decides which licenses the compatibility report is even about,
// so it is worth pinning down away from the UI: a package's dependency closure,
// and the narrower "only what actually ships" walk over it.

// app  --dependsOn-->        lib-gpl   (GPL-2.0-only)
//      --hasStaticLink-->    lib-mit   (MIT)
//      --hasPrerequisite-->  toolchain (GPL-3.0-only)   not shipped
//      --hasOptionalComponent--> plugin (AGPL-3.0-only) may not ship
// lib-gpl --dependsOn--> lib-isc (ISC)
// unrelated (Apache-2.0) sits outside the graph entirely.
const CHILDREN = new Map([
  [
    'app',
    [
      { id: 'lib-gpl', rel: 'dependsOn', soft: false },
      { id: 'lib-mit', rel: 'hasStaticLink', soft: false },
      { id: 'toolchain', rel: 'hasPrerequisite', soft: false },
      { id: 'plugin', rel: 'hasOptionalComponent', soft: true }
    ]
  ],
  ['lib-gpl', [{ id: 'lib-isc', rel: 'dependsOn', soft: false }]]
]);

const LICENSES = [
  { id: 'lic:gpl2', label: 'GPL-2.0-only', declaredBy: ['lib-gpl'], concludedBy: [] },
  { id: 'lic:mit', label: 'MIT', declaredBy: ['lib-mit'], concludedBy: [] },
  { id: 'lic:isc', label: 'ISC', declaredBy: ['lib-isc'], concludedBy: [] },
  { id: 'lic:gpl3', label: 'GPL-3.0-only', declaredBy: ['toolchain'], concludedBy: [] },
  { id: 'lic:agpl', label: 'AGPL-3.0-only', declaredBy: ['plugin'], concludedBy: [] },
  { id: 'lic:apache', label: 'Apache-2.0', declaredBy: ['unrelated'], concludedBy: [] },
  {
    id: 'expandedlicensing_NoAssertionLicense',
    label: 'No assertion',
    declaredBy: ['app'],
    concludedBy: []
  }
];

function makeApp(overrides = {}) {
  const app = {};
  Object.defineProperties(app, Object.getOwnPropertyDescriptors(compatibilityMixin));
  Object.assign(app, {
    licenses: LICENSES,
    packages: [{ spdxId: 'app' }],
    impactChildIndex: CHILDREN,
    producedByBuildIndex: new Map(),
    buildInputIndex: new Map(),
    impactRoots: new Set(['app']),
    hasImpactData: true,
    compatScope: '',
    compatEdgeFilter: 'all',
    compatOutbound: '',
    compatStatusFilter: '',
    compatMatrixAll: false,
    listReveal: {},
    // The license elements are plain SPDX ids here, so the expression is the label.
    licenseExpressionFor: (id) => LICENSES.find((lic) => lic.id === id)?.label || '',
    relTargetDisplayName: (id) => id,
    elementLicenses: () => [],
    _scheduleNavPush: () => {}, // the setters push a history entry; not under test here
    rootElementIds: new Set(['app']),
    ...overrides
  });
  // The memos live at module scope, so a fresh app has to clear the last one's.
  app._resetCompatMemos();
  return app;
}

const labels = (app) => app.compatSubjects.subjects.map((subject) => subject.label).sort();

test('whole document scope checks every license, with no graph walk', () => {
  const app = makeApp();
  assert.equal(app.compatScopeElements, null, 'nothing is filtered out');
  assert.deepEqual(labels(app), [
    'AGPL-3.0-only',
    'Apache-2.0',
    'GPL-2.0-only',
    'GPL-3.0-only',
    'ISC',
    'MIT'
  ]);
  // The NoAssertion individual is a coverage gap, not a finding.
  assert.equal(app.compatUnassertedCount, 1);
  assert.equal(app.compatScopeLabel, 'Whole document');
  assert.match(app.compatHeadline, /in this document/);
});

test('a package scope is its dependency closure, transitively', () => {
  const app = makeApp({ compatScope: 'app' });
  assert.deepEqual(
    [...app.compatScopeElements].sort(),
    ['app', 'lib-gpl', 'lib-isc', 'lib-mit', 'plugin', 'toolchain'],
    'reaches lib-isc through lib-gpl, and excludes the unrelated element'
  );
  assert.deepEqual(labels(app), ['AGPL-3.0-only', 'GPL-2.0-only', 'GPL-3.0-only', 'ISC', 'MIT']);
  assert.equal(app.compatScopeLabel, 'app');
  assert.equal(app.compatScopeSentence, 'app and its dependencies');
});

test('distributed-only drops what is needed but never shipped', () => {
  const app = makeApp({ compatScope: 'app', compatEdgeFilter: 'distributed' });
  assert.deepEqual(
    [...app.compatScopeElements].sort(),
    ['app', 'lib-gpl', 'lib-isc', 'lib-mit'],
    'the prerequisite toolchain and the optional plugin are not part of the product'
  );
  assert.deepEqual(labels(app), ['GPL-2.0-only', 'ISC', 'MIT']);
});

test('distributed-only at document scope walks from the graph roots', () => {
  const app = makeApp({ compatEdgeFilter: 'distributed' });
  assert.deepEqual([...app.compatScopeElements].sort(), ['app', 'lib-gpl', 'lib-isc', 'lib-mit']);
  // Apache-2.0 is on an element nothing reaches, so it is not something we ship.
  assert.deepEqual(labels(app), ['GPL-2.0-only', 'ISC', 'MIT']);
  assert.equal(app.compatScopeLabel, 'What this document ships');
  // The chip label does not read inside a sentence; the headline uses a noun phrase.
  assert.equal(app.compatScopeSentence, 'what this document ships');
});

test('the filter is only offered where there is a graph to walk', () => {
  assert.equal(makeApp().canFilterCompatEdges, true);
  assert.equal(makeApp({ hasImpactData: false }).canFilterCompatEdges, false);
  assert.equal(
    makeApp({ impactRoots: new Set() }).canFilterCompatEdges,
    false,
    'no roots and no package scope leaves nothing to walk from'
  );
  assert.equal(makeApp({ impactRoots: new Set(), compatScope: 'app' }).canFilterCompatEdges, true);
});

test('narrowing the scope changes the report and its candidates', () => {
  const wide = makeApp({ compatOutbound: 'MIT', compatOutboundTouched: true });
  assert.equal(wide.compatReport.totals.conflict.licenses, 3, 'GPL-2.0/3.0 and Apache-2.0');

  const shipped = makeApp({
    compatScope: 'app',
    compatEdgeFilter: 'distributed',
    compatOutbound: 'MIT',
    compatOutboundTouched: true
  });
  assert.equal(shipped.compatReport.totals.conflict.licenses, 1, 'only GPL-2.0-only remains');
  assert.equal(shipped.compatReport.totals.compatible.licenses, 2, 'MIT and ISC');
  assert.ok(
    shipped.compatCandidates.some(
      (candidate) => candidate.id === 'GPL-2.0-only' && candidate.conflict === 0
    ),
    'GPL-2.0-only absorbs MIT and ISC, so it clears the shipped set'
  );
});

test('the proprietary option reads as a product, not a license', () => {
  const app = makeApp({
    compatScope: 'app',
    compatEdgeFilter: 'distributed',
    compatOutbound: 'Proprietary',
    compatOutboundTouched: true
  });
  assert.equal(app.compatIsProprietary, true);
  assert.match(app.compatHeadline, /cannot go into a closed-source product/);

  const blocked = app.compatReport.findings[0];
  assert.equal(blocked.label, 'GPL-2.0-only');
  assert.match(app.compatFindingReason(blocked), /cannot go into a closed-source product/);
  // The claim must not be attributed to a matrix row that does not exist.
  assert.equal(
    app.compatFindingRule(blocked),
    'OSADL: no permissive outbound license accepts GPL-2.0-only'
  );
});

test('an element with a real license is not counted as a coverage gap', () => {
  const app = makeApp({
    licenses: [
      { id: 'lic:mit', label: 'MIT', declaredBy: ['app'], concludedBy: [] },
      {
        id: 'expandedlicensing_NoAssertionLicense',
        label: 'No assertion',
        declaredBy: ['app', 'other'],
        concludedBy: []
      }
    ]
  });
  assert.equal(app.compatUnassertedCount, 1, 'only `other` is wholly unasserted');
  assert.deepEqual(app.compatUnassertedIds, ['other']);
});

test('a scope whose elements name no license explains itself', () => {
  // `built` heads a binary tree; the licensed source tree is parallel to it and
  // unreachable, which is how Zephyr's west-spdx output is shaped.
  const app = makeApp({
    compatScope: 'built',
    packages: [{ spdxId: 'built' }],
    impactChildIndex: new Map([['built', [{ id: 'obj', rel: 'contains', soft: false }]]]),
    licenses: [
      {
        id: 'expandedlicensing_NoAssertionLicense',
        label: 'No assertion',
        declaredBy: ['built', 'obj'],
        concludedBy: []
      },
      { id: 'lic:mit', label: 'MIT', declaredBy: ['sources'], concludedBy: [] }
    ]
  });

  assert.equal(app.compatScopeSize, 2);
  assert.equal(app.compatReport.licenseCount, 0, 'the MIT source tree is out of scope');
  assert.equal(app.compatScopeHasNoLicenses, true);
  assert.equal(app.compatUnassertedCount, 2);
  // The old message was a bare "No licenses to check in this scope", which read
  // as a failure rather than the finding it is.
  assert.match(app.compatHeadline, /Nothing to check/);
  assert.match(app.compatHeadline, /2 elements/);
  assert.match(app.compatHeadline, /declare no license/);
});

test('an empty scope is distinguished from one with no licenses', () => {
  const app = makeApp({ compatScope: 'nothing-here', impactChildIndex: new Map() });
  assert.equal(app.compatScopeSize, 1, 'the focus itself is always in scope');
  const bare = makeApp({ compatScope: 'nothing-here', impactChildIndex: new Map(), licenses: [] });
  assert.equal(bare.compatScopeHasNoLicenses, false, 'nothing in the document to begin with');
  assert.match(bare.compatHeadline, /Nothing to check/);
});

test('the scope follows build lineage back to the sources that went in', () => {
  // Zephyr's SBOM shape: the binary tree never points at the licensed sources.
  // The only link is the Build profile, artifact <- build -> input.
  const app = makeApp({
    compatScope: 'final',
    packages: [{ spdxId: 'final' }],
    impactChildIndex: new Map([['final', [{ id: 'lib.a', rel: 'contains', soft: false }]]]),
    producedByBuildIndex: new Map([['lib.a', ['build:lib']]]),
    buildInputIndex: new Map([['build:lib', ['src.c']]]),
    licenses: [
      { id: 'lic:mit', label: 'MIT', declaredBy: ['src.c'], concludedBy: [] },
      {
        id: 'expandedlicensing_NoAssertionLicense',
        label: 'No assertion',
        declaredBy: ['final', 'lib.a'],
        concludedBy: []
      }
    ]
  });

  assert.deepEqual(
    [...app.compatScopeElements].sort(),
    ['build:lib', 'final', 'lib.a', 'src.c'],
    'steps artifact -> producing build -> build inputs'
  );
  assert.deepEqual(labels(app), ['MIT'], 'the source license is in scope, not just NoAssertion');
  assert.equal(app.compatScopeHasNoLicenses, false);
});

test('build lineage is followed with the distributed-only filter too', () => {
  // A source compiled into a shipped binary travels inside it, so its license
  // applies whichever edge set the dependency walk uses.
  const app = makeApp({
    compatScope: 'final',
    compatEdgeFilter: 'distributed',
    packages: [{ spdxId: 'final' }],
    impactChildIndex: new Map([
      [
        'final',
        [
          { id: 'lib.a', rel: 'contains', soft: false },
          { id: 'toolchain', rel: 'hasPrerequisite', soft: false }
        ]
      ]
    ]),
    producedByBuildIndex: new Map([['lib.a', ['build:lib']]]),
    buildInputIndex: new Map([['build:lib', ['src.c']]]),
    licenses: [
      { id: 'lic:mit', label: 'MIT', declaredBy: ['src.c'], concludedBy: [] },
      { id: 'lic:gpl3', label: 'GPL-3.0-only', declaredBy: ['toolchain'], concludedBy: [] }
    ]
  });

  assert.deepEqual([...app.compatScopeElements].sort(), ['build:lib', 'final', 'lib.a', 'src.c']);
  assert.deepEqual(labels(app), ['MIT'], 'the prerequisite toolchain is still not shipped');
});

test('the candidate rail only offers licenses that beat the current one', () => {
  const subjects = {
    licenses: [
      { id: 'lic:gpl2', label: 'GPL-2.0-only', declaredBy: ['a'], concludedBy: [] },
      { id: 'lic:mit', label: 'MIT', declaredBy: ['b'], concludedBy: [] }
    ],
    impactChildIndex: new Map(),
    impactRoots: new Set()
  };

  // A poor pick: MIT cannot absorb GPL-2.0-only, so better options exist.
  const poor = makeApp({ ...subjects, compatOutbound: 'MIT', compatOutboundTouched: true });
  assert.equal(poor.compatReport.totals.conflict.licenses, 1);
  assert.ok(poor.compatBetterCandidates.length > 0);
  assert.ok(
    poor.compatBetterCandidates.every((candidate) => candidate.conflict === 0),
    'every suggestion improves on the one conflict MIT has'
  );
  assert.ok(
    !poor.compatBetterCandidates.some((candidate) => candidate.id === 'MIT'),
    'the current pick is never offered as an improvement'
  );

  // A pick that already clears everything has nothing better to offer, so the
  // rail stays hidden rather than listing alphabetically-first alternatives.
  const good = makeApp({
    ...subjects,
    compatOutbound: 'GPL-2.0-only',
    compatOutboundTouched: true
  });
  assert.equal(good.compatReport.totals.conflict.licenses, 0);
  assert.deepEqual(good.compatBetterCandidates, []);
});

test('fewer licenses needing review counts as better at equal conflicts', () => {
  const app = makeApp({
    licenses: [{ id: 'lic:lgpl', label: 'LGPL-2.1-only', declaredBy: ['a'], concludedBy: [] }],
    impactChildIndex: new Map(),
    impactRoots: new Set(),
    compatOutbound: 'AGPL-3.0-only',
    compatOutboundTouched: true
  });
  // AGPL-3.0-only takes LGPL-2.1-only only depending on how it is used.
  assert.equal(app.compatReport.totals.conflict.licenses, 0);
  assert.equal(app.compatReport.totals.review.licenses, 1);
  assert.ok(
    app.compatBetterCandidates.every(
      (candidate) => candidate.conflict === 0 && candidate.review === 0
    ),
    'suggestions resolve the review rather than trading it for a conflict'
  );
  assert.ok(app.compatBetterCandidates.length > 0);
});
