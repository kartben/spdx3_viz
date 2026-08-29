import assert from 'node:assert/strict';
import test from 'node:test';

import { loadingMixin } from '../src/app/loading.js';
import { navigationMixin } from '../src/app/navigation.js';
import { CLASS } from '../src/spdx/model.js';

// Enough of the Alpine app for navigateTo / deep-link restore to run without
// a DOM or a full parse. Scroll and history are recorded, not executed.

if (typeof globalThis.history === 'undefined') {
  globalThis.history = { replaceState() {}, pushState() {} };
}
if (typeof globalThis.location === 'undefined') {
  globalThis.location = { pathname: '/', search: '', hash: '', href: 'http://localhost/' };
}

function makeApp(overrides = {}) {
  const elements = new Map(overrides.elements || []);
  const app = {
    isViewAvailable: () => true,
    currentView: 'dashboard',
    views: [{ id: 'dashboard' }, { id: 'requirements' }, { id: 'supplychain' }, { id: 'packages' }],
    mountedViews: { dashboard: true, requirements: false, supplychain: false, packages: false },
    expandedNavProfiles: {},
    navProfiles: [{ id: 'functional-safety', viewIds: ['requirements'] }],
    elementMap: elements,
    requirementSearch: 'stale',
    requirementKindFilter: 'Requirement',
    requirementStatusFilter: 'failed',
    requirementAdequacyFilter: 'unexercised',
    requirementSpecFilter: 'spec:1',
    requirementLayout: 'tree',
    supplyChainViewMode: 'timeline',
    expandedPkg: null,
    expandedFile: null,
    expandedHardware: null,
    expandedSupplyChain: null,
    expandedRequirement: null,
    expandedConfig: null,
    expandedBuild: null,
    expandedLicense: null,
    expandedVuln: null,
    expandedAgent: null,
    detailElement: null,
    graphSelectedNodeId: null,
    licenseViewMode: 'inventory',
    licenseCompatAvailable: false,
    sidebarOpen: false,
    renderLimits: { requirements: 0, supplychain: 0, packages: 0 },
    renderStarts: { requirements: 0, supplychain: 0, packages: 0 },
    filteredRequirements: [],
    filteredSupplyChain: [],
    dataLoaded: true,
    loadedSampleId: 'functional-safety',
    samples: [
      { id: 'functional-safety', files: [] },
      { id: 'paper-plane', files: [] }
    ],
    loadingSample: null,
    _loadCalls: [],
    _navPushQueued: false,
    _lastNavKey: null,
    _lastWrittenHash: '',
    _scrollCalls: [],
    $nextTick(fn) {
      fn();
    },
    supplyChainKind(el) {
      if (!el) return '';
      if (String(el.type || '').includes('Process')) return 'process';
      if (el.type === CLASS.supplychain_State || el.type === 'supplychain_State') return 'state';
      return 'action';
    },
    ...overrides
  };
  Object.defineProperties(app, Object.getOwnPropertyDescriptors(loadingMixin));
  Object.defineProperties(app, Object.getOwnPropertyDescriptors(navigationMixin));
  // Mixin methods talk to the DOM; keep these tests on the nav state only.
  app._ensureViewRendered = () => {};
  app._ensureScrollLoader = () => {};
  app.scrollToNavTarget = (kind, id) => {
    app._scrollCalls.push([kind, id]);
  };
  app.loadSample = (sample) => {
    app._loadCalls.push(sample.id);
  };
  return app;
}

test('navigateToRequirement opens the kind chip that owns the card', () => {
  const app = makeApp({
    elements: [
      ['req:1', { spdxId: 'req:1', type: 'Requirement' }],
      ['ver:1', { spdxId: 'ver:1', type: 'functionalsafety_RequirementVerification' }]
    ]
  });

  app.navigateToRequirement('ver:1');
  assert.equal(app.currentView, 'requirements');
  assert.equal(app.requirementKindFilter, 'functionalsafety_RequirementVerification');
  assert.equal(app.requirementLayout, 'list');
  assert.equal(app.requirementStatusFilter, '');
  assert.equal(app.requirementSearch, '');
  assert.equal(app.expandedRequirement, 'ver:1');
  assert.deepEqual(app._scrollCalls, [['requirement', 'ver:1']]);

  app.navigateToRequirement('req:1');
  assert.equal(app.requirementKindFilter, 'Requirement');
  assert.equal(app.expandedRequirement, 'req:1');
});

test('a deep link to a verification is not swallowed by the Requirements chip', () => {
  const app = makeApp({
    elements: [['ver:1', { spdxId: 'ver:1', type: 'functionalsafety_RequirementVerification' }]]
  });
  const replace = [];
  const hist = globalThis.history;
  const prevReplace = hist.replaceState.bind(hist);
  hist.replaceState = (state, title, url) => {
    replace.push({ state, url });
  };
  try {
    app._applyDeepLink({
      sample: 'functional-safety',
      view: 'requirements',
      expanded: 'ver:1',
      detail: null,
      graphSelected: null,
      licenseMode: 'inventory',
      requirementKind: 'Requirement',
      requirementLayout: null,
      supplyChainMode: null
    });
  } finally {
    hist.replaceState = prevReplace;
  }

  assert.equal(app.currentView, 'requirements');
  assert.equal(app.requirementKindFilter, 'functionalsafety_RequirementVerification');
  assert.equal(app.requirementLayout, 'list');
  assert.equal(app.expandedRequirement, 'ver:1');
  assert.deepEqual(app._scrollCalls, [['requirement', 'ver:1']]);
  assert.equal(replace.length, 1);
});

test('a deep link to the Verifications chip restores it without an expanded card', () => {
  const app = makeApp();
  const hist = globalThis.history;
  const prevReplace = hist.replaceState.bind(hist);
  hist.replaceState = () => {};
  try {
    app._applyDeepLink({
      sample: 'functional-safety',
      view: 'requirements',
      expanded: null,
      detail: null,
      graphSelected: null,
      licenseMode: 'inventory',
      requirementKind: 'functionalsafety_RequirementVerification',
      requirementLayout: 'list',
      supplyChainMode: null
    });
  } finally {
    hist.replaceState = prevReplace;
  }

  assert.equal(app.requirementKindFilter, 'functionalsafety_RequirementVerification');
  assert.equal(app.requirementLayout, 'list');
  assert.equal(app.expandedRequirement, null);
  assert.deepEqual(app._scrollCalls, []);
});

test('a deep link to a Supply Chain map restores that angle', () => {
  const app = makeApp();
  const hist = globalThis.history;
  const prevReplace = hist.replaceState.bind(hist);
  hist.replaceState = () => {};
  try {
    app._applyDeepLink({
      sample: 'paper-plane',
      view: 'supplychain',
      expanded: null,
      detail: null,
      graphSelected: null,
      licenseMode: 'inventory',
      requirementKind: 'Requirement',
      requirementLayout: null,
      supplyChainMode: 'map'
    });
  } finally {
    hist.replaceState = prevReplace;
  }

  assert.equal(app.currentView, 'supplychain');
  assert.equal(app.supplyChainViewMode, 'map');
});

test('an older Supply Chain link infers the angle from the expanded element', () => {
  const app = makeApp({
    elements: [['proc:1', { spdxId: 'proc:1', type: 'supplychain_CreateProcess' }]]
  });
  const hist = globalThis.history;
  const prevReplace = hist.replaceState.bind(hist);
  hist.replaceState = () => {};
  try {
    app._applyDeepLink({
      sample: 'paper-plane',
      view: 'supplychain',
      expanded: 'proc:1',
      detail: null,
      graphSelected: null,
      licenseMode: 'inventory',
      requirementKind: 'Requirement',
      requirementLayout: null,
      supplyChainMode: null
    });
  } finally {
    hist.replaceState = prevReplace;
  }

  assert.equal(app.supplyChainViewMode, 'processes');
  assert.equal(app.expandedSupplyChain, 'proc:1');
});

test('pasting a same-sample share hash restores the spot without reloading', () => {
  const app = makeApp({ dataLoaded: true, loadedSampleId: 'functional-safety' });
  const hist = globalThis.history;
  const prevReplace = hist.replaceState.bind(hist);
  hist.replaceState = () => {};
  const prevHash = globalThis.location.hash;
  globalThis.location.hash = '#s=functional-safety&v=requirements&rk=ver&rl=l';
  try {
    app._followShareHash();
  } finally {
    hist.replaceState = prevReplace;
    globalThis.location.hash = prevHash;
  }
  assert.equal(app.currentView, 'requirements');
  assert.equal(app.requirementKindFilter, 'functionalsafety_RequirementVerification');
  assert.equal(app.requirementLayout, 'list');
  assert.deepEqual(app._loadCalls, []);
});

test('a typed share URL is not treated as Back-to-home', () => {
  const app = makeApp({ dataLoaded: true, loadedSampleId: 'functional-safety' });
  let wentHome = false;
  app.goHome = () => {
    wentHome = true;
  };
  const prevHash = globalThis.location.hash;
  globalThis.location.hash = '#s=paper-plane&v=supplychain&svm=mp';
  try {
    app._onPopState({ state: null });
  } finally {
    globalThis.location.hash = prevHash;
  }
  assert.equal(wentHome, false);
  assert.deepEqual(app._loadCalls, ['paper-plane']);
});

test('Back to the landing entry with no hash goes home', () => {
  const app = makeApp({ dataLoaded: true });
  let wentHome = false;
  app.goHome = () => {
    wentHome = true;
  };
  const prevHash = globalThis.location.hash;
  globalThis.location.hash = '';
  try {
    app._onPopState({ state: null });
  } finally {
    globalThis.location.hash = prevHash;
  }
  assert.equal(wentHome, true);
  assert.deepEqual(app._loadCalls, []);
});

test('pasting a share hash on the landing page loads that sample', () => {
  const app = makeApp({ dataLoaded: false, loadedSampleId: null });
  const prevHash = globalThis.location.hash;
  globalThis.location.hash = '#s=paper-plane&v=supplychain&svm=mp';
  try {
    app._followShareHash();
  } finally {
    globalThis.location.hash = prevHash;
  }
  assert.deepEqual(app._loadCalls, ['paper-plane']);
  assert.equal(app._pendingDeepLink.view, 'supplychain');
  assert.equal(app._pendingDeepLink.supplyChainMode, 'map');
});
