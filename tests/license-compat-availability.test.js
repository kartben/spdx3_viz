import assert from 'node:assert/strict';
import test from 'node:test';

import { isLicenseCompatAvailable, LICENSE_COMPAT_HIDDEN_HOSTS } from '../src/config.js';
import { compatibilityMixin } from '../src/app/compatibility.js';
import { navigationMixin } from '../src/app/navigation.js';

test('the compatibility check is withheld on SPDX own tools domain', () => {
  assert.equal(isLicenseCompatAvailable({ hostname: 'tools.spdx.org', framed: false }), false);
  assert.equal(
    isLicenseCompatAvailable({ hostname: 'TOOLS.SPDX.ORG', framed: false }),
    false,
    'host case is irrelevant'
  );
  assert.ok(LICENSE_COMPAT_HIDDEN_HOSTS.has('tools.spdx.org'));
});

test('it is withheld in any frame, whatever the host', () => {
  // tools.spdx.org does not serve the app, it embeds the GitHub Pages build
  // cross-origin with referrerpolicy="no-referrer". Inside that frame the host
  // is kartben.github.io and the referrer is empty, so the host check alone
  // never fired and the panel showed on the SPDX site.
  assert.equal(isLicenseCompatAvailable({ hostname: 'kartben.github.io', framed: true }), false);
  assert.equal(isLicenseCompatAvailable({ hostname: 'localhost', framed: true }), false);
  assert.equal(isLicenseCompatAvailable({ hostname: 'tools.spdx.org', framed: true }), false);
});

test('it stays available everywhere else, unframed', () => {
  for (const hostname of [
    'kartben.github.io',
    'localhost',
    '127.0.0.1',
    '',
    'spdx.org',
    // Neither a suffix nor a prefix of the blocked host counts as a match.
    'tools.spdx.org.example.com',
    'nottools.spdx.org'
  ]) {
    assert.equal(isLicenseCompatAvailable({ hostname, framed: false }), true, hostname);
  }
});

test('outside a browser it reads as unframed rather than throwing', () => {
  // Node has no window or location; the defaults have to survive that, since
  // this module is imported by tests and by the parse worker.
  assert.equal(isLicenseCompatAvailable(), true);
  assert.equal(isLicenseCompatAvailable({}), true);
});

function makeApp(overrides = {}) {
  const app = {};
  for (const mixin of [compatibilityMixin, navigationMixin]) {
    Object.defineProperties(app, Object.getOwnPropertyDescriptors(mixin));
  }
  return Object.assign(
    app,
    {
      licenseCompatAvailable: true,
      currentView: 'licenses',
      licenseViewMode: 'compatibility',
      compatPanel: 'matrix',
      compatScope: 'pkg:a',
      compatEdgeFilter: 'distributed',
      // A rated id, so compatOutboundLicense resolves without a license list.
      compatOutbound: 'MIT',
      compatOutboundTouched: false,
      compatStatusFilter: '',
      _scheduleNavPush: () => {}
    },
    overrides
  );
}

test('the mode cannot be entered where the check is withheld', () => {
  const app = makeApp({ licenseCompatAvailable: false, licenseViewMode: 'inventory' });
  app.setLicenseViewMode('compatibility');
  assert.equal(app.licenseViewMode, 'inventory', 'the tab does not open');
});

test('a withheld check is never described in a share link', () => {
  assert.deepEqual(makeApp()._compatNavState(), {
    licenseMode: 'compatibility',
    compatPanel: 'matrix',
    compatOutbound: 'MIT',
    compatScope: 'pkg:a',
    compatEdges: 'distributed'
  });

  // Nothing about the tab leaks into the URL on a host that withholds it, so a
  // link copied there is the same link as before the feature existed.
  assert.deepEqual(makeApp({ licenseCompatAvailable: false })._compatNavState(), {
    licenseMode: 'inventory'
  });
});

test('a link into the tab lands on the inventory where it is withheld', () => {
  const link = {
    licenseMode: 'compatibility',
    compatPanel: 'matrix',
    compatOutbound: 'GPL-3.0-or-later',
    compatScope: 'pkg:b',
    compatEdges: 'distributed'
  };

  const open = makeApp({ licenseViewMode: 'inventory' });
  open._applyCompatNavState(link);
  assert.equal(open.licenseViewMode, 'compatibility');
  assert.equal(open.compatOutbound, 'GPL-3.0-or-later');

  const withheld = makeApp({ licenseCompatAvailable: false, licenseViewMode: 'inventory' });
  withheld._applyCompatNavState(link);
  assert.equal(withheld.licenseViewMode, 'inventory', 'the tab is not restored');
  assert.equal(withheld.compatOutbound, 'MIT', 'and the link does not change what it points at');
});
