import assert from 'node:assert/strict';
import test from 'node:test';

import { loadingMixin } from '../src/app/loading.js';

// A minimal stand-in for the Alpine component: the mixin's methods only touch
// plain state, so prototyping them onto a bare object exercises the real code.
function harness(overrides = {}) {
  return Object.assign(Object.create(loadingMixin), {
    dataLoaded: false,
    loadedFiles: [],
    loadedSampleId: null,
    parseError: '',
    toastMsg: '',
    ...overrides
  });
}

test('_onParseError', async (t) => {
  await t.test('a failed first load returns to the landing screen', () => {
    const app = harness({
      loadedFiles: [{ name: 'broken.json', text: '{' }],
      loadedSampleId: 'zephyr'
    });
    app._onParseError('broken.json: bad JSON');
    assert.equal(app.dataLoaded, false, 'the app shell must not mount');
    assert.equal(app.parseError, 'broken.json: bad JSON', 'the landing screen shows the error');
    assert.deepEqual(app.loadedFiles, [], 'the failed files are dropped so a retry starts clean');
    assert.equal(app.loadedSampleId, null);
    assert.equal(app.toastMsg, '', 'no transient toast on the landing path');
  });

  await t.test('a failed re-parse keeps the open document and toasts', (t2) => {
    t2.mock.timers.enable({ apis: ['setTimeout'] });
    const files = [
      { name: 'good.json', text: '{}' },
      { name: 'added.json', text: '{' }
    ];
    const app = harness({ dataLoaded: true, loadedFiles: files });
    app._onParseError('added.json: bad JSON');
    assert.equal(app.dataLoaded, true, 'the already-open document stays on screen');
    assert.equal(app.loadedFiles, files, 'the loaded set is untouched');
    assert.match(app.toastMsg, /added\.json/);
    t2.mock.timers.tick(5000);
    assert.equal(app.toastMsg, '', 'the toast clears itself');
  });

  await t.test('a missing message still produces a visible error', () => {
    const app = harness();
    app._onParseError(undefined);
    assert.equal(app.parseError, 'Failed to parse SBOM');
  });
});
