import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createViews,
  createNavProfiles,
  NAV_EXPLORE_VIEW_IDS,
  NAV_INSIGHTS_VIEW_IDS
} from '../src/config.js';

test('createNavProfiles covers every non-explore, non-insights view exactly once', () => {
  const views = createViews();
  const reserved = new Set([...NAV_EXPLORE_VIEW_IDS, ...NAV_INSIGHTS_VIEW_IDS]);
  const profileViews = createNavProfiles().flatMap((p) => p.viewIds);
  const expected = views.map((v) => v.id).filter((id) => !reserved.has(id));

  assert.deepEqual([...profileViews].sort(), [...expected].sort());
  assert.equal(new Set(profileViews).size, profileViews.length, 'no duplicate view ids');
});

test('collapsible profiles are the multi-view groups', () => {
  const multi = createNavProfiles().filter((p) => p.viewIds.length > 1);
  assert.deepEqual(multi.map((p) => p.id).sort(), ['ai-dataset', 'build', 'software']);
});

test('sidebar view icons are Lucide stroke SVGs', () => {
  for (const v of createViews()) {
    assert.match(v.icon, /stroke="currentColor"/);
    assert.match(v.icon, /fill="none"/);
  }
});
