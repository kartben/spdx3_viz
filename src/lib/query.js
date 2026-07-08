/**
 * SPDX element query engine: a small, dependency-free query language over the
 * already-parsed in-memory model (elementMap + relationship indexes). Both the
 * visual builder and the text box in the Graph view's query panel share this
 * one AST, one text (de)serializer, one evaluator, and one schema extractor.
 *
 * The AST is plain JSON so the visual builder can hold it directly as reactive
 * Alpine state. Nothing here touches the DOM or Alpine; the app-side mixin wires
 * `compileQuery` to the graph overlay and the results list.
 *
 * AST node shapes:
 *   Group: { op: 'and'|'or', not: boolean, children: Node[] }
 *   Type:  { kind: 'type', cls: string, not: boolean }
 *   Prop:  { kind: 'prop', field: string, cmp: Comparator, value?: string, not: boolean }
 *   Rel:   { kind: 'rel', dir: 'out'|'in', relType: string, not: boolean, target?: LeafNode|null }
 *
 * @module lib/query
 */
import { isA } from '../spdx/model.js';
import { CLASS_PARENT } from '../spdx/hierarchy.js';
import { enumValue } from './format.js';

/**
 * Friendly type aliases -> canonical SPDX class. Lets a query say `type:Package`
 * (matching software_Package and every subclass) without knowing the exact
 * class name. Any real SPDX class name is also accepted directly.
 */
export const TYPE_ALIASES = Object.freeze({
  Package: 'software_Package',
  File: 'software_File',
  Snippet: 'software_Snippet',
  Sbom: 'software_Sbom',
  AIPackage: 'ai_AIPackage',
  Dataset: 'dataset_DatasetPackage',
  Hardware: 'hardware_Hardware',
  Requirement: 'Requirement',
  Vulnerability: 'security_Vulnerability',
  Vex: 'security_VexVulnAssessmentRelationship',
  Agent: 'Agent',
  Person: 'Person',
  Organization: 'Organization',
  SoftwareAgent: 'SoftwareAgent',
  Tool: 'Tool',
  Build: 'build_Build',
  Relationship: 'Relationship',
  Annotation: 'Annotation',
  Artifact: 'Artifact',
  Element: 'Element'
});

/** Case-insensitive alias lookup index, built once. */
const ALIAS_BY_LOWER = new Map(Object.keys(TYPE_ALIASES).map((k) => [k.toLowerCase(), k]));

/**
 * Comparators available to a property condition, with the metadata the visual
 * builder's dropdown needs (label, and whether a value input is required).
 */
export const COMPARATORS = Object.freeze([
  { key: 'contains', label: 'contains', needsValue: true },
  { key: 'eq', label: 'is', needsValue: true },
  { key: 'glob', label: 'matches (wildcard)', needsValue: true },
  { key: 'regex', label: 'matches (regex)', needsValue: true },
  { key: 'exists', label: 'exists', needsValue: false },
  { key: 'gt', label: '>', needsValue: true },
  { key: 'gte', label: '>=', needsValue: true },
  { key: 'lt', label: '<', needsValue: true },
  { key: 'lte', label: '<=', needsValue: true }
]);

// --- AST factories (used by the visual builder) ---------------------------

/** A fresh empty group. */
export function newGroup(op = 'and') {
  return { op, not: false, children: [] };
}
/** A fresh type condition. */
export function newTypeCond(cls = 'Package') {
  return { kind: 'type', cls, not: false };
}
/** A fresh property condition. */
export function newPropCond(field = 'name', cmp = 'contains', value = '') {
  return { kind: 'prop', field, cmp, value, not: false };
}
/** A fresh relationship condition. */
export function newRelCond(dir = 'out', relType = 'dependsOn') {
  return { kind: 'rel', dir, relType, not: false, target: null };
}

/** True when a node (or its subtree) carries at least one leaf condition. */
export function hasConditions(node) {
  if (!node) return false;
  if (node.kind) return true;
  return (node.children || []).some(hasConditions);
}

// --- Type resolution -------------------------------------------------------

/**
 * Resolves a type token (alias or raw class) to a canonical SPDX class name.
 * Unknown tokens pass through unchanged so `isA` simply never matches.
 * @param {string} token
 * @returns {string}
 */
export function resolveTypeClass(token) {
  if (!token) return '';
  if (Object.hasOwn(TYPE_ALIASES, token)) return TYPE_ALIASES[token];
  const alias = ALIAS_BY_LOWER.get(token.toLowerCase());
  if (alias) return TYPE_ALIASES[alias];
  return token;
}

/** Short, human label for an SPDX class ("software_Package" -> "Package"). */
export function friendlyTypeLabel(cls) {
  return String(cls || '')
    .replace(/^[a-z][a-z0-9]*_/, '')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2');
}

// --- Wildcard / regex helpers ---------------------------------------------

/** Compiles a glob (`*`, `?`) into an anchored, case-insensitive RegExp. */
export function globToRegExp(glob) {
  const body = String(glob)
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(`^${body}$`, 'i');
}

/** Compiles a user regex (bare or `/.../`) case-insensitively, or null if invalid. */
function safeRegExp(src) {
  let body = String(src);
  const m = /^\/(.*)\/([a-z]*)$/i.exec(body);
  let flags = 'i';
  if (m) {
    body = m[1];
    flags = m[2].includes('i') ? m[2] : m[2] + 'i';
  }
  try {
    return new RegExp(body, flags);
  } catch {
    return null;
  }
}

// --- Evaluator -------------------------------------------------------------

/** Coerces a property value to a comparable string, or null for objects. */
function asStr(v) {
  if (v === null || v === undefined) return null;
  if (typeof v === 'object') return null;
  return String(v);
}

/** The list of scalar values a field holds on an element (arrays flattened). */
function propValues(el, field) {
  const v = el ? el[field] : undefined;
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

/** Builds a per-value tester for a property comparator. */
function propTester(cmp, value) {
  const needle = value == null ? '' : String(value);
  switch (cmp) {
    case 'exists':
      return (v) => v !== '' && v !== null && v !== undefined;
    case 'eq': {
      const lc = needle.toLowerCase();
      return (v) => {
        const s = asStr(v);
        return s != null && s.toLowerCase() === lc;
      };
    }
    case 'contains': {
      const lc = needle.toLowerCase();
      return (v) => {
        const s = asStr(v);
        return s != null && s.toLowerCase().includes(lc);
      };
    }
    case 'glob': {
      const re = globToRegExp(needle);
      return (v) => {
        const s = asStr(v);
        return s != null && re.test(s);
      };
    }
    case 'regex': {
      const re = safeRegExp(needle);
      if (!re) return () => false;
      return (v) => {
        const s = asStr(v);
        return s != null && re.test(s);
      };
    }
    case 'gt':
    case 'gte':
    case 'lt':
    case 'lte': {
      const n = Number.parseFloat(needle);
      if (!Number.isFinite(n)) return () => false;
      return (v) => {
        const s = asStr(v);
        if (s == null) return false;
        const x = Number.parseFloat(s);
        if (!Number.isFinite(x)) return false;
        if (cmp === 'gt') return x > n;
        if (cmp === 'gte') return x >= n;
        if (cmp === 'lt') return x < n;
        return x <= n;
      };
    }
    default:
      return () => false;
  }
}

/** Gathers the endpoint ids a relationship condition points at from an element. */
function relEndpoints(el, dir, relType, ctx) {
  const id = el && el.spdxId;
  if (!id) return [];
  const rels = dir === 'in' ? ctx.relTo(id) : ctx.relFrom(id);
  const out = [];
  for (const rel of rels) {
    if (relType && rel.relationshipType !== relType) continue;
    if (dir === 'in') {
      if (rel.from) out.push(rel.from);
    } else {
      const t = rel.to;
      if (Array.isArray(t)) out.push(...t);
      else if (t) out.push(t);
    }
  }
  return out;
}

/** Compiles one AST node into `(el, ctx) => boolean`. */
function compileNode(node) {
  if (!node) return () => true;

  // Group.
  if (!node.kind) {
    const kids = (node.children || []).map(compileNode);
    const isOr = node.op === 'or';
    let base;
    if (!kids.length)
      base = () => true; // vacuous group matches everything
    else if (isOr) base = (el, ctx) => kids.some((k) => k(el, ctx));
    else base = (el, ctx) => kids.every((k) => k(el, ctx));
    return node.not ? (el, ctx) => !base(el, ctx) : base;
  }

  if (node.kind === 'type') {
    const cls = resolveTypeClass(node.cls);
    const base = (el) => !!el && isA(el.type, /** @type {any} */ (cls));
    return node.not ? (el) => !base(el) : base;
  }

  if (node.kind === 'prop') {
    const test = propTester(node.cmp, node.value);
    const field = node.field;
    const base = (el) => propValues(el, field).some(test);
    return node.not ? (el) => !base(el) : base;
  }

  if (node.kind === 'rel') {
    const dir = node.dir === 'in' ? 'in' : 'out';
    const relType = node.relType || '';
    const targetPred = node.target ? compileNode(node.target) : null;
    const base = (el, ctx) => {
      const ids = relEndpoints(el, dir, relType, ctx);
      if (!ids.length) return false;
      if (!targetPred) return true;
      for (const tid of ids) {
        const tel = ctx.elementMap.get(tid);
        if (tel && targetPred(tel, ctx)) return true;
      }
      return false;
    };
    return node.not ? (el, ctx) => !base(el, ctx) : base;
  }

  return () => true;
}

/**
 * Compiles an AST into a predicate `(element, ctx) => boolean`.
 * `ctx` = { elementMap: Map, relFrom(id)=>rel[], relTo(id)=>rel[] }.
 * The predicate is null-safe (a missing element never matches a positive
 * condition).
 *
 * @param {Object|null} ast
 * @returns {(el: any, ctx: any) => boolean}
 */
export function compileQuery(ast) {
  return compileNode(ast);
}

// --- Text tokenizer --------------------------------------------------------

const KEYWORDS = new Set(['AND', 'OR', 'NOT']);

/**
 * Splits query text into tokens: parentheses, AND/OR/NOT keywords, and terms.
 * A term is a maximal run of non-space, non-paren characters; a double-quoted
 * run (which may contain spaces and parens) counts as part of the current term.
 * @param {string} text
 * @returns {Array<{t:string, v?:string}>}
 */
function tokenize(text) {
  const tokens = [];
  const s = text;
  let i = 0;
  const n = s.length;
  while (i < n) {
    const c = s[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') {
      i++;
      continue;
    }
    if (c === '(') {
      tokens.push({ t: '(' });
      i++;
      continue;
    }
    if (c === ')') {
      tokens.push({ t: ')' });
      i++;
      continue;
    }
    // Read a term (with quoted segments) up to whitespace or an unquoted paren.
    let raw = '';
    while (i < n) {
      const ch = s[i];
      if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') break;
      if (ch === '(' || ch === ')') break;
      if (ch === '"') {
        i++;
        while (i < n && s[i] !== '"') {
          raw += s[i];
          i++;
        }
        i++; // closing quote (or end of string)
        continue;
      }
      raw += ch;
      i++;
    }
    const upper = raw.toUpperCase();
    if (KEYWORDS.has(upper)) tokens.push({ t: upper });
    else tokens.push({ t: 'term', v: raw });
  }
  return tokens;
}

// --- Term classification ---------------------------------------------------

class ParseError extends Error {}

/** Classifies a single term string into a leaf AST node. */
function classifyTerm(raw) {
  const term = raw.trim();
  if (!term) throw new ParseError('Empty condition');

  // Relationship term: ->rel[.<target>] or <-rel[.<target>]
  if (term.startsWith('->') || term.startsWith('<-')) {
    const dir = term[0] === '<' ? 'in' : 'out';
    const rest = term.slice(2);
    if (!rest) throw new ParseError('Relationship needs a type, e.g. ->dependsOn');
    const dot = rest.indexOf('.');
    const relType = dot === -1 ? rest : rest.slice(0, dot);
    const node = { kind: 'rel', dir, relType, not: false, target: null };
    if (dot !== -1) {
      const targetRaw = rest.slice(dot + 1);
      if (targetRaw) node.target = classifyTerm(targetRaw);
    }
    return node;
  }

  // has:field -> existence.
  if (/^has:/i.test(term)) {
    const field = term.slice(4).trim();
    if (!field) throw new ParseError('has: needs a field name');
    return { kind: 'prop', field, cmp: 'exists', value: '', not: false };
  }

  // field~/regex/ or field~regex. Store the bare pattern (no delimiters) so
  // serialize -> parse round-trips without re-wrapping the slashes.
  const tilde = term.indexOf('~');
  if (tilde > 0) {
    const field = term.slice(0, tilde);
    const src = term.slice(tilde + 1);
    const delim = /^\/(.*)\/[a-z]*$/i.exec(src);
    const body = delim ? delim[1] : src;
    if (!safeRegExp(body)) throw new ParseError(`Invalid regular expression: ${src}`);
    return { kind: 'prop', field, cmp: 'regex', value: body, not: false };
  }

  // field!=value -> negated exact.
  const neq = term.indexOf('!=');
  if (neq > 0) {
    const field = term.slice(0, neq);
    const value = term.slice(neq + 2);
    if (field.toLowerCase() === 'type') return { kind: 'type', cls: value, not: true };
    return { kind: 'prop', field, cmp: 'eq', value, not: true };
  }

  // field=value -> exact.
  const eq = term.indexOf('=');
  const colon = term.indexOf(':');
  if (eq > 0 && (colon === -1 || eq < colon)) {
    const field = term.slice(0, eq);
    const value = term.slice(eq + 1);
    if (field.toLowerCase() === 'type') return { kind: 'type', cls: value, not: false };
    return { kind: 'prop', field, cmp: 'eq', value, not: false };
  }

  // field:value family.
  if (colon > 0) {
    const field = term.slice(0, colon);
    const value = term.slice(colon + 1);
    if (field.toLowerCase() === 'type') {
      if (!value) throw new ParseError('type: needs a value, e.g. type:Package');
      return { kind: 'type', cls: value, not: false };
    }
    if (value === '?' || value === '')
      return { kind: 'prop', field, cmp: 'exists', value: '', not: false };
    const numOp = /^(>=|<=|>|<)(.*)$/.exec(value);
    if (numOp) {
      const cmp = { '>': 'gt', '>=': 'gte', '<': 'lt', '<=': 'lte' }[numOp[1]];
      return { kind: 'prop', field, cmp, value: numOp[2], not: false };
    }
    if (value.includes('*') || value.includes('?')) {
      return { kind: 'prop', field, cmp: 'glob', value, not: false };
    }
    return { kind: 'prop', field, cmp: 'contains', value, not: false };
  }

  // Bare word -> shorthand for name contains.
  return { kind: 'prop', field: 'name', cmp: 'contains', value: term, not: false };
}

// --- Recursive-descent parser ----------------------------------------------

function parseTokens(tokens) {
  let pos = 0;
  const peek = () => tokens[pos];
  const next = () => tokens[pos++];

  function parseExpr() {
    return parseOr();
  }

  function parseOr() {
    const children = [parseAnd()];
    while (peek() && peek().t === 'OR') {
      next();
      children.push(parseAnd());
    }
    if (children.length === 1) return children[0];
    return { op: 'or', not: false, children };
  }

  function parseAnd() {
    const children = [parseUnary()];
    while (peek()) {
      const tk = peek();
      if (tk.t === 'OR' || tk.t === ')') break;
      if (tk.t === 'AND') next(); // explicit AND
      // else implicit AND between adjacent primaries
      if (!peek() || peek().t === 'OR' || peek().t === ')') break;
      children.push(parseUnary());
    }
    if (children.length === 1) return children[0];
    return { op: 'and', not: false, children };
  }

  function parseUnary() {
    if (peek() && peek().t === 'NOT') {
      next();
      const inner = parseUnary();
      if (inner.kind) return { ...inner, not: !inner.not };
      return { op: inner.op, not: !inner.not, children: inner.children };
    }
    return parsePrimary();
  }

  function parsePrimary() {
    const tk = peek();
    if (!tk) throw new ParseError('Unexpected end of query');
    if (tk.t === '(') {
      next();
      const inner = parseExpr();
      const close = next();
      if (!close || close.t !== ')') throw new ParseError('Missing closing )');
      // Normalize a bare leaf/group inside parens to a group so `not` has a home.
      return inner.kind ? { op: 'and', not: false, children: [inner] } : inner;
    }
    if (tk.t === ')') throw new ParseError('Unexpected )');
    if (tk.t === 'AND' || tk.t === 'OR') throw new ParseError(`Unexpected ${tk.t}`);
    next();
    return classifyTerm(tk.v);
  }

  const ast = parseExpr();
  if (pos < tokens.length) throw new ParseError('Unexpected trailing input');
  return ast;
}

/**
 * Parses query text into a normalized root group AST.
 * Returns `{ ast: null, error: null }` for empty input, `{ ast, error: null }`
 * on success, or `{ ast: null, error: string }` on a parse error.
 *
 * @param {string} text
 * @returns {{ast: Object|null, error: string|null}}
 */
export function parseQuery(text) {
  const trimmed = (text || '').trim();
  if (!trimmed) return { ast: null, error: null };
  try {
    const tokens = tokenize(trimmed);
    if (!tokens.length) return { ast: null, error: null };
    let ast = parseTokens(tokens);
    if (ast.kind) ast = { op: 'and', not: false, children: [ast] };
    return { ast, error: null };
  } catch (err) {
    return { ast: null, error: err instanceof Error ? err.message : String(err) };
  }
}

// --- Serializer ------------------------------------------------------------

function quoteIfNeeded(value) {
  const s = String(value == null ? '' : value);
  return /[\s()"]/.test(s) ? `"${s.replace(/"/g, '')}"` : s;
}

function serializeProp(node) {
  const f = node.field;
  const v = quoteIfNeeded(node.value);
  switch (node.cmp) {
    case 'exists':
      return `has:${f}`;
    case 'eq':
      return `${f}=${v}`;
    case 'contains':
      return `${f}:${v}`;
    case 'glob':
      return `${f}:${v}`;
    case 'regex':
      return `${f}~/${node.value}/`;
    case 'gt':
      return `${f}:>${v}`;
    case 'gte':
      return `${f}:>=${v}`;
    case 'lt':
      return `${f}:<${v}`;
    case 'lte':
      return `${f}:<=${v}`;
    default:
      return `${f}:${v}`;
  }
}

function serializeLeaf(node) {
  let s;
  if (node.kind === 'type') s = `type:${quoteIfNeeded(node.cls)}`;
  else if (node.kind === 'rel') {
    const arrow = node.dir === 'in' ? '<-' : '->';
    s = arrow + node.relType + (node.target ? '.' + serializeLeaf(node.target) : '');
  } else s = serializeProp(node);
  return node.not ? `NOT ${s}` : s;
}

function serializeGroup(node, top) {
  const op = node.op === 'or' ? ' OR ' : ' AND ';
  const inner = (node.children || []).map(serializeChild).join(op);
  if (node.not) return `NOT (${inner})`;
  if (!top && (node.children || []).length > 1) return `(${inner})`;
  return inner;
}

function serializeChild(child) {
  return child.kind ? serializeLeaf(child) : serializeGroup(child, false);
}

/**
 * Serializes an AST back to query text. Round-trips through `parseQuery` to the
 * same semantics (text form is normalized, not byte-identical).
 *
 * @param {Object|null} ast
 * @returns {string}
 */
export function serializeQuery(ast) {
  if (!ast) return '';
  if (ast.kind) return serializeLeaf(ast);
  return serializeGroup(ast, true);
}

// --- Schema extraction (for autocomplete + builder dropdowns) ---------------

const SKIP_FIELDS = new Set(['type']);
const SAMPLE_CAP = 200;

function inferKind(samples) {
  let n = 0;
  let allNum = true;
  let allDate = true;
  for (const v of samples) {
    if (typeof v === 'object') continue;
    const s = String(v);
    n++;
    if (!/^-?\d+(?:\.\d+)?$/.test(s)) allNum = false;
    if (!/^\d{4}-\d{2}-\d{2}/.test(s)) allDate = false;
    if (!allNum && !allDate) break;
  }
  if (!n) return 'string';
  if (allNum) return 'number';
  if (allDate) return 'date';
  return 'string';
}

/**
 * Scans a set of elements into the query schema that drives autocomplete and
 * the visual builder's dropdowns: present types (with counts), property fields
 * (with an inferred kind and sampled distinct values), and relationship types.
 * Cheap enough to run once per parse (memoize on the caller side).
 *
 * @param {Iterable<any>} elements
 * @param {{relTypes?: string[], maxValues?: number}} [opts]
 * @returns {{types: Array, fields: Array, valuesByField: Object, relTypes: string[]}}
 */
export function buildQuerySchema(elements, { relTypes = [], maxValues = 25 } = {}) {
  const typeCounts = new Map();
  const fields = new Map(); // field -> { field, count, values:Set, samples:[] }

  for (const el of elements) {
    if (!el || typeof el !== 'object') continue;
    if (el.type) typeCounts.set(el.type, (typeCounts.get(el.type) || 0) + 1);
    for (const key of Object.keys(el)) {
      if (SKIP_FIELDS.has(key) || key.startsWith('_') || key.startsWith('@')) continue;
      const raw = el[key];
      if (raw === undefined || raw === null || raw === '') continue;
      let f = fields.get(key);
      if (!f) {
        f = { field: key, count: 0, values: new Set(), samples: [] };
        fields.set(key, f);
      }
      f.count++;
      const vals = Array.isArray(raw) ? raw : [raw];
      for (const v of vals) {
        if (typeof v === 'object') continue;
        if (f.values.size < maxValues) f.values.add(v);
        if (f.samples.length < SAMPLE_CAP) f.samples.push(v);
      }
    }
  }

  const fieldList = [...fields.values()]
    .map((f) => ({
      field: f.field,
      count: f.count,
      kind: inferKind(f.samples),
      enumLike: f.values.size > 0 && f.values.size <= 12,
      values: [...f.values].slice(0, maxValues).map((v) => ({
        value: String(v),
        label: enumValue(String(v))
      }))
    }))
    .sort((a, b) => b.count - a.count);

  const types = [...typeCounts.entries()]
    .map(([cls, count]) => ({ cls, count, label: friendlyTypeLabel(cls) }))
    .sort((a, b) => b.count - a.count);

  return {
    types,
    fields: fieldList,
    valuesByField: Object.fromEntries(fieldList.map((f) => [f.field, f.values])),
    relTypes: [...new Set(relTypes.filter(Boolean))].sort()
  };
}

/** Convenience: is a token a known SPDX class or alias? (used for hints). */
export function isKnownType(token) {
  if (!token) return false;
  if (Object.hasOwn(TYPE_ALIASES, token)) return true;
  if (ALIAS_BY_LOWER.has(token.toLowerCase())) return true;
  return Object.hasOwn(CLASS_PARENT, token);
}
