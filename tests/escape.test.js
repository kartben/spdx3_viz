import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { escapeAttr, escapeHtml } from '../src/lib/escape.js';

describe('escapeHtml', () => {
  it('escapes every character that is special in markup', () => {
    assert.equal(escapeHtml('&'), '&amp;');
    assert.equal(escapeHtml('<'), '&lt;');
    assert.equal(escapeHtml('>'), '&gt;');
    assert.equal(escapeHtml('"'), '&quot;');
    assert.equal(escapeHtml("'"), '&#39;');
  });

  it('escapes the ampersand once, not twice', () => {
    assert.equal(escapeHtml('&lt;'), '&amp;lt;');
    assert.equal(escapeHtml('a & b < c'), 'a &amp; b &lt; c');
  });

  it('leaves ordinary text alone', () => {
    assert.equal(escapeHtml('zephyr-sources'), 'zephyr-sources');
    assert.equal(escapeHtml('Apache-2.0 OR MIT'), 'Apache-2.0 OR MIT');
    assert.equal(escapeHtml(''), '');
  });

  it('neutralises a script tag smuggled through an element name', () => {
    assert.equal(escapeHtml('<script>alert(1)</script>'), '&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('neutralises an attribute breakout, in either quote style', () => {
    assert.equal(escapeHtml('" onerror="alert(1)'), '&quot; onerror=&quot;alert(1)');
    assert.equal(escapeHtml("' onerror='alert(1)"), '&#39; onerror=&#39;alert(1)');
  });

  it('returns an empty string for null and undefined rather than their names', () => {
    assert.equal(escapeHtml(null), '');
    assert.equal(escapeHtml(undefined), '');
  });

  it('coerces non-string values', () => {
    assert.equal(escapeHtml(0), '0');
    assert.equal(escapeHtml(42), '42');
    assert.equal(escapeHtml(false), 'false');
    assert.equal(escapeHtml(['a', 'b']), 'a,b');
  });

  it('escapes every occurrence, not just the first', () => {
    assert.equal(escapeHtml('<<<'), '&lt;&lt;&lt;');
    assert.equal(escapeHtml('a&b&c'), 'a&amp;b&amp;c');
  });

  it('preserves characters that are not special, including non-ASCII', () => {
    assert.equal(escapeHtml('café / 日本語 /  '), 'café / 日本語 /  ');
    assert.equal(escapeHtml('line\nbreak\ttab'), 'line\nbreak\ttab');
  });
});

describe('escapeAttr', () => {
  it('is the same function, so no call site can pick a weaker escape', () => {
    assert.equal(escapeAttr, escapeHtml);
  });

  it('covers both quote characters', () => {
    assert.equal(escapeAttr('a"b\'c'), 'a&quot;b&#39;c');
  });
});
