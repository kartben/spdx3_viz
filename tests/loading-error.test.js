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

test('cancelParse', async (t) => {
  await t.test('a canceled first load returns to the landing screen', () => {
    const app = harness({
      parsing: true,
      progressEta: 12,
      loadingSample: 'yocto6',
      loadedFiles: [{ name: 'huge.json' }],
      loadedSampleId: 'yocto6'
    });
    app.cancelParse();
    assert.equal(app.parsing, false, 'the overlay closes');
    assert.equal(app.loadingSample, null);
    assert.equal(app.progressEta, null);
    assert.deepEqual(app.loadedFiles, [], 'the canceled files are dropped');
    assert.equal(app.loadedSampleId, null);
    assert.equal(app.dataLoaded, false, 'back on the landing screen');
  });

  await t.test('canceling a re-parse keeps the open document', () => {
    const files = [{ name: 'good.json' }];
    const app = harness({ parsing: true, dataLoaded: true, loadedFiles: files });
    app.cancelParse();
    assert.equal(app.parsing, false);
    assert.equal(app.dataLoaded, true, 'the already-open document stays');
    assert.equal(app.loadedFiles, files, 'the loaded set is untouched');
  });
});

test('_fileSetLabel', async (t) => {
  const app = harness();

  await t.test('names the files and their total size', () => {
    const label = app._fileSetLabel([
      { name: 'a.json', size: 1500 },
      { name: 'b.json', size: 500 }
    ]);
    assert.equal(label, 'a.json, b.json · 2 KB');
  });

  await t.test('elides long file lists past the second name', () => {
    const label = app._fileSetLabel([
      { name: 'a.json', size: 1000 },
      { name: 'b.json', size: 1000 },
      { name: 'c.json', size: 1000 },
      { name: 'd.json', size: 1000 }
    ]);
    assert.equal(label, 'a.json, b.json +2 more · 4 KB');
  });

  await t.test('omits the size when none is known', () => {
    assert.equal(app._fileSetLabel([{ name: 'a.json' }]), 'a.json');
  });
});
