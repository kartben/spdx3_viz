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
