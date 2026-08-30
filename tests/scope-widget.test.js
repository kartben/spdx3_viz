import assert from 'node:assert/strict';
import test from 'node:test';

import { scopeMixin } from '../src/app/scope.js';

// The shared picker in views/partials/scope-picker.html reaches its view's
// state only through these accessors, so they are the widget's contract: a view
// opts in by naming its fields in SCOPE_VIEWS, and the markup stays one copy.

function makeApp(overrides = {}) {
  return Object.assign(
    Object.create(scopeMixin),
    {
      // licensing
      compatScope: '',
      compatScopePickerOpen: false,
      compatScopeSearch: '',
      canScopeCompat: true,
      compatScopeLabel: 'Whole document',
      compatScopeOptions: [{ id: 'pkg:a', label: 'a', deps: 2 }],
      setCompatScope(id) {
        this.compatScope = id;
        this.compatSetterCalls = (this.compatSetterCalls || 0) + 1;
      },
      // security
      securityScope: '',
      securityScopePickerOpen: false,
      securityScopeSearch: '',
      canScopeSecurity: true,
      securityScopeLabel: 'Whole document',
      securityScopeOptions: [{ id: 'pkg:img', label: 'img', deps: 9, isArtifact: true }],
      setSecurityScope(id) {
        this.securityScope = id;
        this.securitySetterCalls = (this.securitySetterCalls || 0) + 1;
      }
    },
    overrides
  );
}

test('the shared scope widget reads each view through its own fields', async (t) => {
  await t.test('an unknown key renders nothing rather than an inert control', () => {
    const app = makeApp();
    assert.equal(app.scopeConfig('nope'), null);
    assert.equal(app.canScope('nope'), false);
    assert.deepEqual(app.scopeOptions('nope'), []);
    assert.equal(app.scopeFocus('nope'), '');
  });

  await t.test('availability comes from the view, not the widget', () => {
    assert.equal(makeApp().canScope('licenses'), true);
    assert.equal(makeApp({ canScopeCompat: false }).canScope('licenses'), false);
    assert.equal(makeApp({ canScopeSecurity: false }).canScope('security'), false);
  });

  await t.test('each key reads its own state', () => {
    const app = makeApp({ compatScope: 'pkg:a', securityScope: 'pkg:img' });
    assert.equal(app.scopeFocus('licenses'), 'pkg:a');
    assert.equal(app.scopeFocus('security'), 'pkg:img');
    assert.equal(app.scopeOptions('licenses')[0].id, 'pkg:a');
    assert.equal(app.scopeOptions('security')[0].id, 'pkg:img');
  });

  await t.test('the dropdown toggles per view, independently', () => {
    const app = makeApp();
    app.toggleScopePicker('security');
    assert.equal(app.scopePickerOpen('security'), true);
    assert.equal(app.scopePickerOpen('licenses'), false, 'the other view is untouched');
    app.closeScopePicker('security');
    assert.equal(app.scopePickerOpen('security'), false);
  });

  await t.test('the search box writes back to the view that owns it', () => {
    const app = makeApp();
    app.setScopeSearch('licenses', 'lvgl');
    assert.equal(app.compatScopeSearch, 'lvgl');
    assert.equal(app.scopeSearch('licenses'), 'lvgl');
    assert.equal(app.scopeSearch('security'), '');
  });

  await t.test('choosing a scope delegates to the view, keeping its side effects', () => {
    const app = makeApp();
    app.setScope('security', 'pkg:img');
    assert.equal(app.securityScope, 'pkg:img');
    assert.equal(app.securitySetterCalls, 1, 'went through setSecurityScope, not a direct write');
    assert.equal(app.compatSetterCalls, undefined);
  });

  await t.test('each view brings its own wording and accent', () => {
    const licenses = scopeMixin.scopeConfig('licenses');
    const security = scopeMixin.scopeConfig('security');
    assert.notEqual(licenses.help, security.help);
    assert.notEqual(licenses.accent.active, security.accent.active);
    // Written out in full so Tailwind's scanner sees them.
    for (const cfg of [licenses, security]) {
      for (const cls of Object.values(cfg.accent)) {
        assert.doesNotMatch(cls, /\$\{|\+/, 'accent classes must be literals');
      }
    }
  });
});
