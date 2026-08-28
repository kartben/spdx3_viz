/* Waiting for a painted frame.
 *
 * Two nested animation frames guarantee the browser has committed and painted,
 * so whatever was just put on screen (the load overlay, its progress bar) is
 * actually visible before the next synchronous block takes the main thread for
 * seconds. A single frame is not enough: the callback runs before the commit,
 * so the work can start with the update still unpainted.
 *
 * A hidden tab never runs animation frames at all, so a timer resolves the wait
 * instead of leaving the work behind it stalled until the tab is looked at
 * again. Nothing has to paint in a tab nobody is watching.
 *
 * @module app/paint
 */

// Long enough that a visible tab always paints first (two frames is ~32 ms at
// 60 Hz, less on faster displays), short enough that a hidden tab barely waits.
const HIDDEN_FALLBACK_MS = 100;

/** @returns {Promise<void>} resolved once a frame has painted (or the tab is hidden) */
export function nextPaint(fallbackMs = HIDDEN_FALLBACK_MS) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve();
    };
    const timer = setTimeout(finish, fallbackMs);
    requestAnimationFrame(() => requestAnimationFrame(finish));
  });
}
