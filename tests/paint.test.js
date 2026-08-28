import assert from 'node:assert/strict';
import test from 'node:test';

import { nextPaint } from '../src/app/paint.js';

// Stands in for a browser that never paints (a hidden tab), the case the
// fallback timer exists for. Restored by each test that installs it.
function withRaf(impl, fn) {
  const had = 'requestAnimationFrame' in globalThis;
  const prev = globalThis.requestAnimationFrame;
  globalThis.requestAnimationFrame = impl;
  return fn().finally(() => {
    if (had) globalThis.requestAnimationFrame = prev;
    else delete globalThis.requestAnimationFrame;
  });
}

test('resolves after two animation frames when the page paints', async () => {
  let frames = 0;
  await withRaf(
    (cb) => {
      frames++;
      setTimeout(() => cb(0), 0);
      return frames;
    },
    async () => {
      await nextPaint(5000);
      assert.equal(frames, 2, 'one frame is not enough: it runs before the commit');
    }
  );
});

test('resolves on its own when frames never come (hidden tab)', async () => {
  await withRaf(
    () => 1, // callback dropped, as in a tab the browser never paints
    async () => {
      const started = Date.now();
      await nextPaint(20);
      assert.ok(Date.now() - started >= 15, 'should wait for the fallback, not resolve instantly');
    }
  );
});

test('resolves once, even when both the frame and the timer fire', async () => {
  let resolutions = 0;
  await withRaf(
    (cb) => {
      setTimeout(() => cb(0), 30); // frames arrive after the fallback has fired
      return 1;
    },
    async () => {
      await nextPaint(1).then(() => resolutions++);
      await new Promise((resolve) => setTimeout(resolve, 80));
      assert.equal(resolutions, 1);
    }
  );
});
