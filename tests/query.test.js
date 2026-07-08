import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseQuery,
  serializeQuery,
  compileQuery,
  buildQuerySchema,
  resolveTypeClass,
  friendlyTypeLabel,
  globToRegExp,
  hasConditions
} from '../src/lib/index.js';

// --- A tiny in-memory model + ctx, mirroring the parser's index shapes. ------

const elements = [
  { spdxId: 'p1', type: 'software_Package', name: 'openssl', software_packageVersion: '3.0.1' },
  { spdxId: 'p2', type: 'software_Package', name: 'zlib', software_packageVersion: '1.2' },
  { spdxId: 'f1', type: 'software_File', name: 'main.c' },
  { spdxId: 'f2', type: 'software_File', name: 'util.h' },
  { spdxId: 'v1', type: 'security_Vulnerability', name: 'CVE-2024-0001' }
];
const elementMap = new Map(elements.map((e) => [e.spdxId, e]));

const rels = [
  { relationshipType: 'dependsOn', from: 'p1', to: ['p2'] },
  { relationshipType: 'contains', from: 'p1', to: ['f1', 'f2'] },
  { relationshipType: 'affects', from: 'v1', to: ['p1'] }
];
const relFromIndex = new Map();
const relToIndex = new Map();
const push = (map, key, val) => {
  if (!map.has(key)) map.set(key, []);
  map.get(key).push(val);
};
for (const r of rels) {
  push(relFromIndex, r.from, r);
  for (const t of Array.isArray(r.to) ? r.to : [r.to]) push(relToIndex, t, r);
}
const ctx = {
  elementMap,
  relFrom: (id) => relFromIndex.get(id) || [],
  relTo: (id) => relToIndex.get(id) || []
};

function run(text) {
  const { ast, error } = parseQuery(text);
  assert.equal(error, null, `parse error for "${text}": ${error}`);
  const pred = compileQuery(ast);
  return elements.filter((e) => pred(e, ctx)).map((e) => e.spdxId);
}

// --- Type conditions --------------------------------------------------------

test('type alias resolves to a canonical class and matches subclasses', () => {
  assert.equal(resolveTypeClass('Package'), 'software_Package');
  assert.equal(resolveTypeClass('package'), 'software_Package');
  assert.equal(resolveTypeClass('security_Vulnerability'), 'security_Vulnerability');
  assert.deepEqual(run('type:Package'), ['p1', 'p2']);
  assert.deepEqual(run('type:File'), ['f1', 'f2']);
});

test('a superclass type matches every subclass', () => {
  // Artifact is a superclass of Package, File and Vulnerability in the model.
  assert.deepEqual(run('type:Artifact'), ['p1', 'p2', 'f1', 'f2', 'v1']);
});

// --- Property comparators ---------------------------------------------------

test('contains (default) is a case-insensitive substring', () => {
  assert.deepEqual(run('type:Package name:SSL'), ['p1']);
});

test('exact match with = and has: existence', () => {
  assert.deepEqual(run('name=zlib'), ['p2']);
  assert.deepEqual(run('has:software_packageVersion'), ['p1', 'p2']);
  assert.deepEqual(run('software_packageVersion:?'), ['p1', 'p2']);
});

test('glob wildcards anchor the whole value', () => {
  assert.deepEqual(run('name:*.c'), ['f1']);
  assert.deepEqual(run('name:*.h'), ['f2']);
  assert.deepEqual(run('name:util.?'), ['f2']);
});

test('regex matching', () => {
  assert.deepEqual(run('name~/^open/'), ['p1']);
  assert.deepEqual(run('name~cve'), ['v1']); // case-insensitive by default
});

test('numeric comparators coerce values', () => {
  assert.deepEqual(run('software_packageVersion:>=2.0'), ['p1']);
  assert.deepEqual(run('software_packageVersion:<2'), ['p2']);
});

// --- Boolean structure ------------------------------------------------------

test('implicit AND, explicit OR, grouping and NOT', () => {
  assert.deepEqual(run('type:File (name:*.c OR name:*.h)'), ['f1', 'f2']);
  assert.deepEqual(run('type:File AND name:*.c'), ['f1']);
  assert.deepEqual(run('type:Package NOT ->dependsOn'), ['p2']);
  assert.deepEqual(run('NOT type:Package NOT type:File'), ['v1']);
});

// --- Relationship traversal -------------------------------------------------

test('relationship existence in both directions', () => {
  assert.deepEqual(run('->dependsOn'), ['p1']);
  assert.deepEqual(run('<-dependsOn'), ['p2']);
  assert.deepEqual(run('->affects'), ['v1']);
});

test('relationship with a nested target condition', () => {
  // Packages targeted by an incoming affects edge from a Vulnerability.
  assert.deepEqual(run('<-affects.type:Vulnerability'), ['p1']);
  // Outgoing affects to a Vulnerability: none (affects points at the package).
  assert.deepEqual(run('->affects.type:Vulnerability'), []);
});

// --- Parse errors -----------------------------------------------------------

test('malformed queries report an error instead of throwing', () => {
  assert.equal(parseQuery('(type:Package').error !== null, true);
  assert.equal(parseQuery('name~/(/').error !== null, true); // invalid regex
  assert.equal(parseQuery('type:Package OR').error !== null, true);
});

test('empty input is a cleared query, not an error', () => {
  assert.deepEqual(parseQuery(''), { ast: null, error: null });
  assert.deepEqual(parseQuery('   '), { ast: null, error: null });
});

// --- Serialize round-trip ---------------------------------------------------

test('serialize -> parse is stable', () => {
  const queries = [
    'type:Package name:ssl',
    'type:File (name:*.c OR name:*.h)',
    'type:Package NOT ->dependsOn',
    '<-affects.type:Vulnerability',
    'has:software_packageVersion software_packageVersion:>=2.0',
    'name~/^open/'
  ];
  for (const q of queries) {
    const once = serializeQuery(parseQuery(q).ast);
    const twice = serializeQuery(parseQuery(once).ast);
    assert.equal(twice, once, `not stable: "${q}" -> "${once}" -> "${twice}"`);
  }
});

// --- hasConditions ----------------------------------------------------------

test('hasConditions detects whether a tree is a real query', () => {
  assert.equal(hasConditions(parseQuery('').ast), false);
  assert.equal(hasConditions(parseQuery('type:Package').ast), true);
  assert.equal(hasConditions({ op: 'and', not: false, children: [] }), false);
});

// --- Schema extraction ------------------------------------------------------

test('buildQuerySchema summarizes types, fields, values and relTypes', () => {
  const schema = buildQuerySchema(elements, { relTypes: ['dependsOn', 'contains', 'contains'] });
  const pkg = schema.types.find((t) => t.cls === 'software_Package');
  assert.equal(pkg.count, 2);
  assert.equal(pkg.label, 'Package');
  const nameField = schema.fields.find((f) => f.field === 'name');
  assert.ok(nameField, 'name field present');
  assert.ok(nameField.values.some((v) => v.value === 'openssl'));
  assert.deepEqual(schema.relTypes, ['contains', 'dependsOn']); // deduped + sorted
});

test('helpers', () => {
  assert.equal(friendlyTypeLabel('software_Package'), 'Package');
  assert.equal(friendlyTypeLabel('hardware_PhysicalHardware'), 'Physical Hardware');
  assert.equal(globToRegExp('*.c').test('main.c'), true);
  assert.equal(globToRegExp('*.c').test('main.h'), false);
});
