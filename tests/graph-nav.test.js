import assert from 'node:assert/strict';
import test from 'node:test';

import { graphMixin } from '../src/app/graph.js';
import {
  TRAIL_CURRENT,
  TRAIL_START,
  advanceNavTrail,
  easeInOutQuart,
  focusNeedsMove,
  focusPanDuration,
  focusScale,
  focusTransform,
  mapTrailToRenderIds,
  trailColorAt
} from '../src/lib/index.js';

test('advanceNavTrail starts, appends, and rewinds', () => {
  assert.deepEqual(advanceNavTrail([], 'a'), ['a']);
  assert.deepEqual(advanceNavTrail(['a'], 'b'), ['a', 'b']);
  assert.deepEqual(advanceNavTrail(['a', 'b'], 'c'), ['a', 'b', 'c']);
  assert.deepEqual(advanceNavTrail(['a', 'b', 'c'], 'b'), ['a', 'b']);
  assert.deepEqual(advanceNavTrail(['a', 'b', 'c'], 'a'), ['a']);
  assert.deepEqual(advanceNavTrail(['a', 'b'], 'b'), ['a', 'b']);
});

test('advanceNavTrail keeps the origin when the walk is capped', () => {
  const long = advanceNavTrail(['start', 'a', 'b'], 'c', 3);
  assert.deepEqual(long, ['start', 'b', 'c']);
  assert.equal(advanceNavTrail(null, 'x')[0], 'x');
  assert.deepEqual(advanceNavTrail(['a'], null), ['a']);
});

test('mapTrailToRenderIds folds members into clusters and skips gaps', () => {
  const renderKeyOf = new Map([
    ['file:1', 'pkg:root'],
    ['file:2', 'pkg:root'],
    ['pkg:leaf', 'pkg:leaf']
  ]);
  const renderById = new Map([
    ['pkg:root', {}],
    ['pkg:leaf', {}]
  ]);
  assert.deepEqual(
    mapTrailToRenderIds(['file:1', 'file:2', 'pkg:leaf', 'ghost'], renderKeyOf, renderById),
    ['pkg:root', 'pkg:leaf']
  );
  assert.deepEqual(mapTrailToRenderIds([], renderKeyOf, renderById), []);
});

test('trailColorAt is cyan at the start and pink on the current hop', () => {
  assert.equal(trailColorAt(0, 1), TRAIL_CURRENT);
  assert.equal(trailColorAt(0, 4), TRAIL_START);
  assert.equal(trailColorAt(3, 4), TRAIL_CURRENT);
  assert.match(trailColorAt(1, 4), /^#[0-9a-f]{6}$/);
  assert.notEqual(trailColorAt(1, 4), TRAIL_START);
  assert.notEqual(trailColorAt(1, 4), TRAIL_CURRENT);
});

test('easeInOutQuart starts and ends still, and is symmetric', () => {
  assert.equal(easeInOutQuart(0), 0);
  assert.equal(easeInOutQuart(1), 1);
  assert.equal(easeInOutQuart(0.5), 0.5);
  assert.ok(easeInOutQuart(0.1) < 0.1, 'slow start (acceleration)');
  assert.ok(easeInOutQuart(0.9) > 0.9, 'slow stop (deceleration)');
  assert.ok(Math.abs(easeInOutQuart(0.25) + easeInOutQuart(0.75) - 1) < 1e-12);
});

test('focusTransform centres a world point in the viewport', () => {
  const t = focusTransform({ width: 800, height: 600, x: 100, y: 50, k: 2 });
  assert.equal(t.k, 2);
  assert.equal(t.x, 800 / 2 - 2 * 100);
  assert.equal(t.y, 600 / 2 - 2 * 50);
});

test('focusScale keeps a readable node without yanking a close-up', () => {
  assert.equal(focusScale({ currentK: 1, nodeR: 8, minK: 0.02, maxK: 8 }), 1);
  const zoomedOut = focusScale({ currentK: 0.05, nodeR: 8, minK: 0.02, maxK: 8 });
  assert.ok(zoomedOut > 0.05, 'tiny on-screen nodes zoom in');
  assert.ok(zoomedOut <= 1.6, 'focused zoom is capped');
  const huge = focusScale({ currentK: 4, nodeR: 40, minK: 0.02, maxK: 8 });
  assert.ok(huge < 4, 'oversized clusters ease back');
});

test('focusPanDuration grows with distance and stays clamped', () => {
  const short = focusPanDuration({ x: 0, y: 0, k: 1 }, { x: 10, y: 0, k: 1 });
  const long = focusPanDuration({ x: 0, y: 0, k: 1 }, { x: 900, y: 600, k: 1 });
  assert.ok(short >= 380);
  assert.ok(long > short);
  assert.ok(long <= 980);
  assert.equal(focusNeedsMove({ x: 0, y: 0, k: 1 }, { x: 1, y: 0, k: 1 }), false);
  assert.equal(focusNeedsMove({ x: 0, y: 0, k: 1 }, { x: 40, y: 0, k: 1 }), true);
});

test('selectGraphNode on the graph pins, trails, and asks the camera to follow', () => {
  const focused = [];
  const app = {
    currentView: 'graph',
    elementMap: new Map([
      ['a', { spdxId: 'a' }],
      ['b', { spdxId: 'b' }]
    ]),
    virtualVulnMap: new Map(),
    graphNavTrail: ['a'],
    graphSelectedNodeId: 'a',
    detailElement: { spdxId: 'a' },
    graphFocusNode(id) {
      focused.push(id);
    },
    _scheduleNavPush() {
      app.pushed = true;
    },
    placeholderElement(id) {
      return { spdxId: id, placeholder: true };
    }
  };

  graphMixin.selectGraphNode.call(app, 'b');
  assert.equal(app.detailElement.spdxId, 'b');
  assert.deepEqual(app.graphNavTrail, ['a', 'b']);
  assert.deepEqual(focused, ['b']);
  assert.equal(app.pushed, true);
});

test('selectGraphNode seeds the trail from the open detail element', () => {
  const app = {
    currentView: 'graph',
    elementMap: new Map([['b', { spdxId: 'b' }]]),
    virtualVulnMap: new Map(),
    graphNavTrail: [],
    graphSelectedNodeId: 'a',
    detailElement: { spdxId: 'a' },
    graphFocusNode() {},
    _scheduleNavPush() {}
  };
  graphMixin.selectGraphNode.call(app, 'b');
  assert.deepEqual(app.graphNavTrail, ['a', 'b']);
});

test('graphTrailMark returns the hop colour, or null when the id is not on the path', () => {
  const app = { graphNavTrail: ['a', 'b', 'c'] };
  assert.equal(graphMixin.graphTrailMark.call(app, 'a'), TRAIL_START);
  assert.equal(graphMixin.graphTrailMark.call(app, 'c'), TRAIL_CURRENT);
  assert.equal(graphMixin.graphTrailMark.call(app, 'ghost'), null);
  assert.equal(graphMixin.graphTrailMark.call({ graphNavTrail: [] }, 'a'), null);
});

test('selectGraphNode off the graph only updates the detail panel', () => {
  const focused = [];
  const app = {
    currentView: 'packages',
    elementMap: new Map([['b', { spdxId: 'b' }]]),
    virtualVulnMap: new Map(),
    graphNavTrail: [],
    graphSelectedNodeId: null,
    detailElement: { spdxId: 'a' },
    graphFocusNode(id) {
      focused.push(id);
    },
    _scheduleNavPush() {}
  };

  graphMixin.selectGraphNode.call(app, 'b');
  assert.equal(app.detailElement.spdxId, 'b');
  assert.deepEqual(app.graphNavTrail, []);
  assert.deepEqual(focused, []);
});
