import assert from 'node:assert/strict';
import test from 'node:test';

import { productVariants, vendorVariants, aliasFor } from '../scripts/cpe-normalize.mjs';

test('productVariants strips lib prefix and trailing soname/version', () => {
  const curl = productVariants('libcurl4');
  assert.ok(curl.includes('curl'), 'libcurl4 -> curl');
  const expat = productVariants('libexpat1');
  assert.ok(expat.includes('expat'), 'libexpat1 -> expat');
});

test('productVariants leaves clean names usable and unifies separators', () => {
  assert.ok(productVariants('zlib').includes('zlib'));
  const http = productVariants('http_server');
  assert.ok(http.includes('http-server'));
  assert.ok(http.includes('httpserver'));
});

test('productVariants surfaces a curated alias when present', () => {
  assert.ok(productVariants('libpam0g').includes('linux_pam'));
  assert.ok(productVariants('libssl3').includes('openssl'));
});

test('vendorVariants mirrors productVariants; aliasFor reads the seed map', () => {
  assert.deepEqual(vendorVariants('libcurl4'), productVariants('libcurl4'));
  assert.equal(aliasFor('libpam0g'), 'linux_pam');
  assert.equal(aliasFor('zlib1g'), 'zlib');
  assert.equal(aliasFor('totally-unknown-thing'), null);
});
