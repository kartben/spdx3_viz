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
