import assert from 'node:assert/strict';
import test from 'node:test';

import { graphMixin } from '../src/app/graph.js';

const heatAvailable = Object.getOwnPropertyDescriptor(graphMixin, 'graphHeatAvailable').get;
const heatCount = Object.getOwnPropertyDescriptor(graphMixin, 'graphHeatCount').get;

test('heatmap control is available only when a lens has results', () => {
  assert.equal(heatAvailable.call({ graphHeatModeList: [{ key: 'vuln', count: 0 }] }), false);
  assert.equal(
    heatAvailable.call({
      graphHeatModeList: [
        { key: 'failed', count: 0 },
        { key: 'unverified', count: 2 }
      ]
    }),
    true
  );
});

test('active heat count follows the selected lens', () => {
  const context = {
    graphHeatMode: 'failed',
    graphHeatModeList: [
      { key: 'failed', count: 3 },
      { key: 'unverified', count: 7 }
    ]
  };

  assert.equal(heatCount.call(context), 3);
});

test('fresh data clears a selected lens that has no results', () => {
  const context = {
    graphHeatMode: 'vuln',
    graphHeatMenuOpen: true,
    graphHeatModeList: [],
    get graphHeatActive() {
      return this.graphHeatMode !== 'off';
    },
    _computeHeatModeList: () => [{ key: 'vuln', count: 0 }]
  };

  graphMixin._resetGraphHeat.call(context);

  assert.equal(context.graphHeatMode, 'off');
  assert.equal(context.graphHeatMenuOpen, false);
  assert.deepEqual(context.graphHeatModeList, [{ key: 'vuln', count: 0 }]);
});
