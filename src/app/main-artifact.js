import {
  detectMainArtifactCandidates,
  buildContributionAdjacency,
  contributionSet
} from '../lib/main-artifact.js';

/* Main artifact: the one build output an SBOM is really about (zephyr.elf,
   bzImage, ...). Detected on load, overridable from any element's detail card,
   and used to gray out everything that didn't contribute to it. Selection is
   remembered per document in localStorage and travels in the share link. */

const STORAGE_KEY = 'spdx3viz.mainArtifact';

// Memoized contribution set, keyed per component instance so several app mounts
// on one page never collide, and off the reactive state so it isn't proxied.
const contribCache = new WeakMap();

// Reads the per-document selection map { [docKey]: spdxId }. A stored '' means
// the user explicitly cleared it, so we don't re-apply auto-detection on reload.
function readStoredMap() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const parsed = raw ? JSON.parse(raw) : null;
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function writeStoredMap(map) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(map));
  } catch {
    /* localStorage blocked (private mode, etc.) — selection just won't persist */
  }
}

export const mainArtifactMixin = {
  // Stable key for the loaded document, so a remembered selection is scoped to
  // the SBOM it was made in.
  get _mainArtifactDocKey() {
    return this.docNamespace || this.loadedSampleId || this.docName || '';
  },

  // The selected element (or a placeholder if it isn't in the map), or null.
  get mainArtifactElement() {
    if (!this.mainArtifactId) return null;
    return this.elementMap.get(this.mainArtifactId) || null;
  },

  get mainArtifactName() {
    const el = this.mainArtifactElement;
    return el ? this.elementDisplayName(el) : '';
  },

  get hasMainArtifact() {
    return !!this.mainArtifactId;
  },

  // Every element that contributed to producing/composing the main artifact,
  // including it. Empty when nothing is selected. Memoized on the selection and
  // relationship-set size (the latter changes only across loads).
  get mainArtifactContributionSet() {
    if (!this.mainArtifactId) return new Set();
    const key = `${this.mainArtifactId}|${this.relationships.length}`;
    const cached = contribCache.get(this);
    if (cached && cached.key === key) return cached.val;
    const adj = buildContributionAdjacency(this.relationships);
    const val = contributionSet(this.mainArtifactId, adj);
    contribCache.set(this, { key, val });
    return val;
  },

  // Whether an element is a plausible main-artifact pick (so its detail card
  // promotes the action). The current selection always qualifies.
  isMainArtifactCandidate(el) {
    const id = el?.spdxId;
    if (!id) return false;
    if (id === this.mainArtifactId) return true;
    return this.mainArtifactCandidates.some((c) => c.id === id);
  },

  isMainArtifact(el) {
    return !!el?.spdxId && el.spdxId === this.mainArtifactId;
  },

  // Files and packages can stand in as the main artifact; other element kinds
  // (agents, licenses, relationships, ...) can't, so their card hides the control.
  mainArtifactEligible(el) {
    const t = String(el?.type || '');
    return t.includes('File') || t.includes('Package');
  },

  // One-line "why we think so" for the auto-detected pick, shown in the banner
  // and (for candidates) the detail card.
  mainArtifactReason(id) {
    const c = this.mainArtifactCandidates.find((x) => x.id === id);
    return c?.reasons?.[0] || '';
  },

  // Recomputes candidates for freshly loaded data and applies the effective
  // selection: an explicit per-document choice (incl. an explicit clear) wins,
  // otherwise the confident auto-detected artifact, otherwise nothing.
  _resetMainArtifact() {
    contribCache.delete(this);
    this.mainArtifactBannerDismissed = false;

    const { candidates, auto } = detectMainArtifactCandidates({
      elements: [...this.elementMap.values()],
      relationships: this.relationships,
      rootElementIds: this.rootElementIds
    });
    this.mainArtifactCandidates = candidates;
    this.mainArtifactAuto = auto;

    const stored = readStoredMap()[this._mainArtifactDocKey];
    let effective = null;
    if (stored !== undefined) {
      // '' = explicitly cleared; a real id = explicit pick (only if still present).
      effective = stored && this.elementMap.has(stored) ? stored : null;
    } else if (auto && this.elementMap.has(auto)) {
      effective = auto;
      this._mainArtifactWasAuto = true;
    }
    this.mainArtifactId = effective;
  },

  // Persists the choice (or an explicit clear) for the current document.
  _persistMainArtifact() {
    const key = this._mainArtifactDocKey;
    if (!key) return;
    const map = readStoredMap();
    map[key] = this.mainArtifactId || '';
    writeStoredMap(map);
  },

  setMainArtifact(id) {
    if (!id) return;
    this.mainArtifactId = id;
    this.mainArtifactBannerDismissed = true;
    this._mainArtifactWasAuto = false;
    contribCache.delete(this);
    this._persistMainArtifact();
    this._afterMainArtifactChange();
  },

  clearMainArtifact() {
    this.mainArtifactId = null;
    contribCache.delete(this);
    this._persistMainArtifact();
    this._afterMainArtifactChange();
  },

  toggleMainArtifact(el) {
    const id = el?.spdxId;
    if (!id) return;
    if (id === this.mainArtifactId) this.clearMainArtifact();
    else this.setMainArtifact(id);
  },

  dismissMainArtifactBanner() {
    this.mainArtifactBannerDismissed = true;
  },

  // Whether to show the "we picked X" confirm banner: only for the auto pick,
  // until the user dismisses it or overrides the selection.
  get showMainArtifactBanner() {
    return (
      !!this.mainArtifactId &&
      this._mainArtifactWasAuto &&
      !this.mainArtifactBannerDismissed &&
      this.currentView === 'graph'
    );
  },

  // Repaint the graph's focus overlay (no rebuild) and record a history entry so
  // the selection round-trips into the share link.
  _afterMainArtifactChange() {
    if (this.currentView === 'graph') this.focusMainArtifact?.();
    this._scheduleNavPush?.();
  }
};
