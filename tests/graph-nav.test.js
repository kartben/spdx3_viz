import assert from 'node:assert/strict';
import test from 'node:test';

import { graphMixin } from '../src/app/graph.js';
import {
  TRAIL_CURRENT,
  TRAIL_START,
  NODE_CLICK_PX,
  advanceNavTrail,
  easeInOutQuart,
  focusNeedsMove,
  focusPanDuration,
  focusScale,
  focusTransform,
  isDragGesture,
  mapTrailToRenderIds,
  trailColorAt,
  trailFocusTransform,
  trailRecap
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
  assert.equal(trailColorAt(0, 3), TRAIL_START);
  assert.equal(trailColorAt(2, 3), TRAIL_CURRENT);
  assert.notEqual(trailColorAt(1, 3), TRAIL_START);
  assert.notEqual(trailColorAt(1, 3), TRAIL_CURRENT);
});

test('trailRecap reads the walk with start/here roles and colours', () => {
  assert.deepEqual(trailRecap([]).hops, []);
  assert.equal(trailRecap([]).summary, '');

  const two = trailRecap(['a', 'b'], (id) => ({
    name: id === 'a' ? 'Origin' : 'Here',
    typeLabel: 'Thing'
  }));
  assert.equal(two.hopCount, 1);
  assert.equal(two.summary, 'From Origin to Here.');
  assert.equal(two.hops[0].roleLabel, 'Started');
  assert.equal(two.hops[0].color, TRAIL_START);
  assert.equal(two.hops[1].roleLabel, 'Now');
  assert.equal(two.hops[1].color, TRAIL_CURRENT);
  assert.equal(two.hops[1].last, true);

  const three = trailRecap(['a', 'b', 'c'], (id) => ({ name: id.toUpperCase() }));
  assert.equal(three.summary, 'From A via B to C.');
  assert.equal(three.hops[1].roleLabel, 'Then');
  assert.equal(three.hops[1].last, false);

  const four = trailRecap(['a', 'b', 'c', 'd'], (id) => ({ name: id }));
  assert.equal(four.summary, 'From a via 2 hops to d.');
});

test('graphTrailRecap uses element names and SPDX type labels', () => {
  const app = {
    graphNavTrail: ['a', 'b'],
    elementMap: new Map([
      ['a', { spdxId: 'a', type: 'Requirement', name: 'GLIDE-REQ-01 distance' }],
      ['b', { spdxId: 'b', type: 'supplychain_PlanAction', name: 'Plan the folding run' }]
    ]),
    virtualVulnMap: new Map(),
    elementDisplayName(el) {
      return el.name;
    },
    cleanName(id) {
      return id;
    },
    placeholderElement(id) {
      return { spdxId: id, type: 'ExternalReference', name: id, placeholder: true };
    }
  };
  const recap = Reflect.get(graphMixin, 'graphTrailRecap', app);
  assert.equal(recap.summary, 'From GLIDE-REQ-01 distance to Plan the folding run.');
  assert.equal(recap.hops[0].typeLabel, 'Requirement');
  assert.equal(recap.hops[1].typeLabel, 'Plan Action');
  assert.equal(recap.hops[0].color, TRAIL_START);
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

test('trailFocusTransform frames every hop so the walk stays on screen', () => {
  const viewport = { width: 800, height: 600, minK: 0.02, maxK: 8, currentK: 1 };
  assert.equal(trailFocusTransform({ ...viewport, points: [] }), null);

  const one = trailFocusTransform({
    ...viewport,
    points: [{ x: 100, y: 50, r: 8 }]
  });
  const centred = focusTransform({
    width: 800,
    height: 600,
    x: 100,
    y: 50,
    k: focusScale({ currentK: 1, nodeR: 8, minK: 0.02, maxK: 8 })
  });
  assert.deepEqual(one, centred);

  const nearby = trailFocusTransform({
    ...viewport,
    points: [
      { x: 0, y: 0, r: 8 },
      { x: 40, y: 0, r: 8 }
    ]
  });
  assert.equal(nearby.k, 1, 'a short trail keeps the current zoom');

  const far = trailFocusTransform({
    ...viewport,
    points: [
      { x: 0, y: 0, r: 8 },
      { x: 2000, y: 0, r: 8 }
    ]
  });
  const sx = (t, x) => t.k * x + t.x;
  const sy = (t, y) => t.k * y + t.y;
  assert.ok(sx(far, 0) >= -1, 'origin stays in the viewport');
  assert.ok(sx(far, 2000) <= 800 + 1, 'current hop stays in the viewport');
  assert.ok(far.k < 1, 'a long walk zooms out');

  const tall = trailFocusTransform({
    ...viewport,
    points: [
      { x: 0, y: 0, r: 8 },
      { x: 80, y: 1800, r: 8 },
      { x: 1200, y: 900, r: 8 }
    ]
  });
  for (const p of [
    { x: 0, y: 0 },
    { x: 80, y: 1800 },
    { x: 1200, y: 900 }
  ]) {
    assert.ok(sx(tall, p.x) >= -1 && sx(tall, p.x) <= 801, `x of (${p.x},${p.y}) stays in view`);
    assert.ok(sy(tall, p.y) >= -1 && sy(tall, p.y) <= 601, `y of (${p.x},${p.y}) stays in view`);
  }
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

test('isDragGesture ignores click jitter and trips after a real move', () => {
  assert.equal(isDragGesture(0, 0), false);
  assert.equal(isDragGesture(3, 3), false);
  assert.equal(isDragGesture(NODE_CLICK_PX, 0), true);
  assert.equal(isDragGesture(5, 5), true);
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

test('clearGraphTrail drops the walk and keeps the current node selected', () => {
  const hovered = [];
  let redraws = 0;
  const app = {
    graphNavTrail: ['a', 'b', 'c'],
    graphSelectedNodeId: 'c',
    graphPreviewNodeId: 'b',
    detailElement: { spdxId: 'c' },
    graphHoverNode(id) {
      hovered.push(id);
    },
    graphRedraw() {
      redraws++;
    }
  };
  graphMixin.clearGraphTrail.call(app);
  assert.deepEqual(app.graphNavTrail, []);
  assert.equal(app.graphSelectedNodeId, 'c');
  assert.equal(app.detailElement.spdxId, 'c');
  assert.equal(app.graphPreviewNodeId, null);
  assert.deepEqual(hovered, [null]);
  assert.equal(redraws, 1);

  graphMixin.clearGraphTrail.call(app);
  assert.equal(redraws, 1, 'a second clear is a no-op');
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

test('previewGraphNode on the graph asks the renderer to hover the target', () => {
  const hovered = [];
  const app = {
    currentView: 'graph',
    graphPreviewNodeId: null,
    graphHoverNode(id) {
      hovered.push(id);
    }
  };
  graphMixin.previewGraphNode.call(app, 'b');
  assert.equal(app.graphPreviewNodeId, 'b');
  graphMixin.clearGraphPreview.call(app);
  assert.equal(app.graphPreviewNodeId, null);
  assert.deepEqual(hovered, ['b', null]);
});

test('previewGraphNode off the graph is a no-op', () => {
  const hovered = [];
  const app = {
    currentView: 'packages',
    graphPreviewNodeId: null,
    graphHoverNode(id) {
      hovered.push(id);
    }
  };
  graphMixin.previewGraphNode.call(app, 'b');
  assert.equal(app.graphPreviewNodeId, null);
  assert.deepEqual(hovered, []);
});
