/* Resizable graph detail panel: drag its left edge to set the width, persisted
   in localStorage so it survives reloads. Only meaningful at md+ where the panel
   is a static flex column; on mobile it's a full-width slide-over overlay. */

const STORAGE_KEY = 'spdx3viz.detailPanelWidth';
const DEFAULT_WIDTH = 384; // matches the previous fixed md:w-96 (24rem)
const MIN_WIDTH = 320;

// Initial width for state.js: a persisted value if one is stored and sane,
// otherwise the default. Guards against localStorage being unavailable.
export function storedDetailPanelWidth() {
  try {
    const v = parseInt(localStorage.getItem(STORAGE_KEY), 10);
    if (Number.isFinite(v) && v >= MIN_WIDTH) return v;
  } catch {
    /* localStorage blocked (private mode, etc.) — fall back to the default */
  }
  return DEFAULT_WIDTH;
}

export const detailPanelMixin = {
  // Drag handler wired to the panel's left-edge grip (@pointerdown). Tracks the
  // pointer against the panel's fixed right edge, clamps, and persists on release.
  startDetailResize(event) {
    event.preventDefault();
    const panel = this.$refs.detailPanel;
    if (!panel) return;
    const rightEdge = panel.getBoundingClientRect().right;
    const maxWidth = Math.min(Math.round(window.innerWidth * 0.8), 900);

    const onMove = (e) => {
      this.detailPanelWidth = Math.max(
        MIN_WIDTH,
        Math.min(maxWidth, Math.round(rightEdge - e.clientX))
      );
    };
    const onUp = () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      document.body.classList.remove('detail-resizing');
      try {
        localStorage.setItem(STORAGE_KEY, String(this.detailPanelWidth));
      } catch {
        /* ignore persistence failures */
      }
    };

    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    document.body.classList.add('detail-resizing');
  }
};
