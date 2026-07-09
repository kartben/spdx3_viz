import assert from 'node:assert/strict';
import test from 'node:test';

import {
  GRAPH_LAYOUTS,
  graphLayoutMeta,
  DEFAULT_GRAPH_LAYOUT,
  computeLayers,
  bfsDepths,
  orderLaneTypes
} from '../src/lib/index.js';

test('every layout has the fields the toolbar renders', () => {
  assert.ok(GRAPH_LAYOUTS.length >= 5);
  for (const l of GRAPH_LAYOUTS) {
    assert.ok(l.key && l.label && l.short && l.icon && l.hint, `layout ${l.key} is complete`);
    assert.match(l.icon, /^layout_/, 'icon is a layout_* key');
  }
  const keys = GRAPH_LAYOUTS.map((l) => l.key);
  assert.equal(new Set(keys).size, keys.length, 'layout keys are unique');
  assert.ok(keys.includes(DEFAULT_GRAPH_LAYOUT), 'the default is a real layout');
});

test('graphLayoutMeta falls back to the default for an unknown key', () => {
  assert.equal(graphLayoutMeta('hierarchy').key, 'hierarchy');
  assert.equal(graphLayoutMeta('nope').key, DEFAULT_GRAPH_LAYOUT);
  assert.equal(graphLayoutMeta(undefined).key, DEFAULT_GRAPH_LAYOUT);
});

test('computeLayers gives each node its longest path from a source', () => {
  // a -> b -> d, a -> c -> d, plus a direct a -> d. d is deepest via a-b-d / a-c-d.
  const layers = computeLayers(
    ['a', 'b', 'c', 'd'],
    [
      ['a', 'b'],
      ['a', 'c'],
      ['b', 'd'],
      ['c', 'd'],
      ['a', 'd']
    ]
  );
  assert.equal(layers.get('a'), 0);
  assert.equal(layers.get('b'), 1);
  assert.equal(layers.get('c'), 1);
  // Longest path wins over the shortcut edge, so d is a layer below b/c, not below a.
  assert.equal(layers.get('d'), 2);
});

test('computeLayers terminates on a cycle and keeps nodes below their sources', () => {
  // src -> x -> y -> x (x,y form a cycle fed by src).
  const layers = computeLayers(
    ['src', 'x', 'y'],
    [
      ['src', 'x'],
      ['x', 'y'],
      ['y', 'x']
    ]
  );
  assert.equal(layers.get('src'), 0);
  assert.ok(layers.get('x') >= 1, 'cycle node sits below its source');
  assert.ok(layers.get('y') >= 1);
});

test('computeLayers ignores dangling and self edges', () => {
  const layers = computeLayers(
    ['a', 'b'],
    [
      ['a', 'a'], // self loop
      ['a', 'b'],
      ['a', 'ghost'] // endpoint not in the node set
    ]
  );
  assert.equal(layers.get('a'), 0);
  assert.equal(layers.get('b'), 1);
});

test('bfsDepths measures undirected distance from the roots', () => {
  const adjacency = new Map([
    ['root', new Set(['a', 'b'])],
    ['a', new Set(['root', 'c'])],
    ['b', new Set(['root'])],
    ['c', new Set(['a'])]
  ]);
  const depth = bfsDepths(['root', 'a', 'b', 'c'], adjacency, ['root']);
  assert.equal(depth.get('root'), 0);
  assert.equal(depth.get('a'), 1);
  assert.equal(depth.get('b'), 1);
  assert.equal(depth.get('c'), 2);
});

test('bfsDepths pushes unreachable nodes to the outer ring', () => {
  const adjacency = new Map([
    ['root', new Set(['a'])],
    ['a', new Set(['root'])],
    ['island', new Set()]
  ]);
  const depth = bfsDepths(['root', 'a', 'island'], adjacency, ['root']);
  assert.equal(depth.get('root'), 0);
  assert.equal(depth.get('a'), 1);
  // Deepest reached is 1, so the disconnected island lands one ring beyond it.
  assert.equal(depth.get('island'), 2);
});

test('orderLaneTypes sorts known types canonically and keeps unknowns stable', () => {
  const ordered = orderLaneTypes(['agent', 'file', 'build', 'file', 'package']);
  // build < package < file in the canonical lane order; the duplicate file collapses.
  assert.deepEqual(ordered, ['build', 'package', 'file', 'agent']);

  // Unknown types keep their first-seen order after all known ones.
  const withUnknown = orderLaneTypes(['zeta', 'file', 'omega']);
  assert.deepEqual(withUnknown, ['file', 'zeta', 'omega']);
});
