import assert from 'node:assert/strict';
import test from 'node:test';

import { buildShareHash, parseShareHash } from '../src/lib/share.js';

test('a share hash needs a sample to anchor to', () => {
  assert.equal(buildShareHash({ view: 'licenses' }), '');
  assert.equal(buildShareHash(null), '');
  assert.equal(parseShareHash(''), null);
  assert.equal(parseShareHash('#v=licenses'), null, 'no sample id is not a share link');
});

test('defaults are left out so the common link stays short', () => {
  assert.equal(buildShareHash({ sample: 'zephyr' }), 's=zephyr');
  assert.equal(buildShareHash({ sample: 'zephyr', view: 'dashboard' }), 's=zephyr');
  assert.equal(buildShareHash({ sample: 'zephyr', view: 'licenses' }), 's=zephyr&v=licenses');
  // Inventory is the Licenses view's default mode, so it adds nothing.
  assert.equal(
    buildShareHash({ sample: 'zephyr', view: 'licenses', licenseMode: 'inventory' }),
    's=zephyr&v=licenses'
  );
});

test('the compatibility settings survive a round trip', () => {
  const spot = {
    sample: 'zephyr',
    view: 'licenses',
    licenseMode: 'compatibility',
    compatPanel: 'matrix',
    compatOutbound: 'GPL-3.0-or-later',
    compatScope: 'zephyr:packages/zephyr-final',
    compatEdges: 'distributed'
  };
  const hash = buildShareHash(spot);
  assert.equal(
    hash,
    's=zephyr&v=licenses&lm=c&cp=m&co=GPL-3.0-or-later&cs=zephyr%3Apackages%2Fzephyr-final&ce=d'
  );

  const parsed = parseShareHash(`#${hash}`);
  assert.equal(parsed.sample, 'zephyr');
  assert.equal(parsed.view, 'licenses');
  assert.equal(parsed.licenseMode, 'compatibility');
  assert.equal(parsed.compatPanel, 'matrix');
  assert.equal(parsed.compatOutbound, 'GPL-3.0-or-later');
  assert.equal(parsed.compatScope, 'zephyr:packages/zephyr-final');
  assert.equal(parsed.compatEdges, 'distributed');
});

test('compatibility settings are dropped unless that tab is the one being shared', () => {
  const hash = buildShareHash({
    sample: 'zephyr',
    view: 'packages',
    licenseMode: 'inventory',
    compatOutbound: 'MIT',
    compatScope: 'pkg:a',
    compatEdges: 'distributed'
  });
  assert.equal(hash, 's=zephyr&v=packages');
});

test('a link with no compatibility settings parses to the defaults', () => {
  const parsed = parseShareHash('s=zephyr&v=licenses');
  assert.equal(parsed.licenseMode, 'inventory');
  assert.equal(parsed.compatPanel, 'check');
  assert.equal(parsed.compatOutbound, null);
  assert.equal(parsed.compatScope, null);
  assert.equal(parsed.compatEdges, 'all');
});

test('the older link fields still round trip', () => {
  const hash = buildShareHash({
    sample: 'linux',
    view: 'graph',
    expanded: 'pkg:a',
    detail: 'pkg:b',
    graphSelected: 'pkg:c'
  });
  const parsed = parseShareHash(hash);
  assert.equal(parsed.expanded, 'pkg:a');
  assert.equal(parsed.detail, 'pkg:b');
  assert.equal(parsed.graphSelected, 'pkg:c');
});

test('Functional Safety kind and layout survive a round trip', () => {
  const hash = buildShareHash({
    sample: 'functional-safety',
    view: 'requirements',
    expanded: 'ver:brake-test',
    requirementKind: 'functionalsafety_RequirementVerification',
    requirementLayout: 'list'
  });
  assert.equal(hash, 's=functional-safety&v=requirements&e=ver%3Abrake-test&rk=ver&rl=l');
  const parsed = parseShareHash(`#${hash}`);
  assert.equal(parsed.requirementKind, 'functionalsafety_RequirementVerification');
  assert.equal(parsed.requirementLayout, 'list');
  assert.equal(parsed.expanded, 'ver:brake-test');
});

test('the Requirements chip and an unpinned layout stay out of the hash', () => {
  const hash = buildShareHash({
    sample: 'functional-safety',
    view: 'requirements',
    requirementKind: 'Requirement'
  });
  assert.equal(hash, 's=functional-safety&v=requirements');
  const parsed = parseShareHash(hash);
  assert.equal(parsed.requirementKind, 'Requirement');
  assert.equal(parsed.requirementLayout, null);
});

test('All / tree / evaluations encode as short codes', () => {
  const all = parseShareHash(
    buildShareHash({
      sample: 'functional-safety',
      view: 'requirements',
      requirementKind: '',
      requirementLayout: 'tree'
    })
  );
  assert.equal(all.requirementKind, '');
  assert.equal(all.requirementLayout, 'tree');

  const evals = parseShareHash(
    buildShareHash({
      sample: 'functional-safety',
      view: 'requirements',
      requirementKind: 'functionalsafety_EvaluationResult'
    })
  );
  assert.equal(evals.requirementKind, 'functionalsafety_EvaluationResult');
});

test('Supply Chain angles survive a round trip and timeline stays omitted', () => {
  const map = buildShareHash({
    sample: 'paper-plane',
    view: 'supplychain',
    supplyChainMode: 'map'
  });
  assert.equal(map, 's=paper-plane&v=supplychain&svm=mp');
  assert.equal(parseShareHash(map).supplyChainMode, 'map');

  const timeline = buildShareHash({
    sample: 'paper-plane',
    view: 'supplychain',
    supplyChainMode: 'timeline'
  });
  assert.equal(timeline, 's=paper-plane&v=supplychain');
  assert.equal(parseShareHash(timeline).supplyChainMode, null);
});

test('older Functional Safety and Supply Chain links still parse', () => {
  const fs = parseShareHash('s=functional-safety&v=requirements&e=req:sg-01');
  assert.equal(fs.requirementKind, 'Requirement');
  assert.equal(fs.requirementLayout, null);
  assert.equal(fs.expanded, 'req:sg-01');

  const sc = parseShareHash('s=paper-plane&v=supplychain&e=act:fold');
  assert.equal(sc.supplyChainMode, null);
  assert.equal(sc.expanded, 'act:fold');
});
