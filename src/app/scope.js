/**
 * The scope picker, shared by every view that narrows a document-wide answer to
 * one part of the graph.
 *
 * Licensing and Security ask the same question of different data ("which
 * packages does this really cover?") and had grown two copies of the same
 * dropdown. The walk itself lives in lib/scope.js; this is the thin controller
 * the shared widget in views/partials/scope-picker.html binds to, so a view
 * opts in by naming its state fields here instead of duplicating markup.
 *
 * Each view keeps its own state fields rather than moving to a shared bag: they
 * are already reactive, already in the share link under their own parameters,
 * and a rename would churn both without making the widget any more reusable.
 */

/**
 * @typedef {Object} ScopeViewConfig
 * @property {string} focusField - state field holding the scoped element id
 * @property {string} openField - state field holding the dropdown's open flag
 * @property {string} searchField - state field holding the filter text
 * @property {string} setter - method name applying a new scope
 * @property {string} labelGetter - getter naming the current scope
 * @property {string} optionsGetter - getter listing offerable scopes
 * @property {string} availableGetter - getter gating the whole control
 * @property {string} help - one line explaining what scoping does here
 * @property {string} allLabel - label for the "no scope" entry
 * @property {{border: string, active: string, hint: string}} accent - Tailwind
 *   classes, written out in full so the scanner sees them
 */

/** @type {Record<string, ScopeViewConfig>} */
const SCOPE_VIEWS = {
  licenses: {
    focusField: 'compatScope',
    openField: 'compatScopePickerOpen',
    searchField: 'compatScopeSearch',
    setter: 'setCompatScope',
    labelGetter: 'compatScopeLabel',
    optionsGetter: 'compatScopeOptions',
    availableGetter: 'canScopeCompat',
    help: 'Narrow to one package and everything it pulls in, which is the unit a compatibility check is really about.',
    allLabel: 'Whole document',
    accent: {
      border: 'border-pink-500',
      active: 'bg-pink-500/15 text-pink-300',
      hint: 'focus:border-pink-500'
    }
  },
  security: {
    focusField: 'securityScope',
    openField: 'securityScopePickerOpen',
    searchField: 'securityScopeSearch',
    setter: 'setSecurityScope',
    labelGetter: 'securityScopeLabel',
    optionsGetter: 'securityScopeOptions',
    availableGetter: 'canScopeSecurity',
    help: 'Narrow to one artifact and show only the findings against components it is really built from. Build outputs are listed first.',
    allLabel: 'Whole document',
    accent: {
      border: 'border-rose-500',
      active: 'bg-rose-500/15 text-rose-300',
      hint: 'focus:border-rose-500'
    }
  }
};

export const scopeMixin = {
  /**
   * The descriptor for a scoped view, or null when the key names none. The
   * widget renders nothing on null, so a view that has not opted in cannot
   * accidentally show an inert control.
   * @param {string} key
   * @returns {ScopeViewConfig|null}
   */
  scopeConfig(key) {
    return SCOPE_VIEWS[key] || null;
  },

  /** Whether this view can offer scoping at all. */
  canScope(key) {
    const cfg = SCOPE_VIEWS[key];
    return !!cfg && !!this[cfg.availableGetter];
  },

  /** The currently scoped element id, or '' for the whole document. */
  scopeFocus(key) {
    const cfg = SCOPE_VIEWS[key];
    return cfg ? this[cfg.focusField] || '' : '';
  },

  /** Human-readable name of the current scope. */
  scopeLabel(key) {
    const cfg = SCOPE_VIEWS[key];
    return cfg ? this[cfg.labelGetter] : '';
  },

  /** The scopes this view offers, already filtered by the search box. */
  scopeOptions(key) {
    const cfg = SCOPE_VIEWS[key];
    return cfg ? this[cfg.optionsGetter] : [];
  },

  scopePickerOpen(key) {
    const cfg = SCOPE_VIEWS[key];
    return cfg ? !!this[cfg.openField] : false;
  },

  toggleScopePicker(key) {
    const cfg = SCOPE_VIEWS[key];
    if (cfg) this[cfg.openField] = !this[cfg.openField];
  },

  closeScopePicker(key) {
    const cfg = SCOPE_VIEWS[key];
    if (cfg) this[cfg.openField] = false;
  },

  scopeSearch(key) {
    const cfg = SCOPE_VIEWS[key];
    return cfg ? this[cfg.searchField] : '';
  },

  setScopeSearch(key, value) {
    const cfg = SCOPE_VIEWS[key];
    if (cfg) this[cfg.searchField] = value;
  },

  /** Applies a scope, delegating to the view's own setter so its side effects
   *  (clearing dependent filters, pushing history) still run. */
  setScope(key, id) {
    const cfg = SCOPE_VIEWS[key];
    if (cfg) this[cfg.setter](id);
  }
};
