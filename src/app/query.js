import {
  parseQuery,
  serializeQuery,
  compileQuery,
  buildQuerySchema,
  hasConditions,
  friendlyTypeLabel,
  TYPE_ALIASES,
  COMPARATORS,
  newGroup,
  newTypeCond,
  newPropCond,
  newRelCond
} from '../lib/index.js';
import { RELATIONSHIP_TYPES } from '../config.js';

/* Structured query panel for the Graph view. A query is one AST (src/lib/query.js)
   edited either visually (a Sparnatural-style builder) or as text (a compact DSL
   with autocomplete). Both compile to one predicate that drives the graph's
   existing dim/focus overlay (via app.graphQueryPredicate + graphSearch) and a
   results list. The visual builder edits up to two levels of grouping; deeper
   queries stay text-only. */

// Memo for the query schema (types/fields/values/relTypes), rebuilt only when
// the loaded data changes. Kept off reactive state like search.js's corpus.
let schemaKey = null;
let schemaVal = null;

// Cap on materialized result rows so a query matching an entire large SBOM
// never mounts tens of thousands of rows; the surplus is reported as a count.
const RESULT_CAP = 500;

export const queryMixin = {
  // --- Schema (autocomplete + builder dropdowns) --------------------------

  get querySchema() {
    const key = `${this.elementMap.size}:${this.presentRelTypes.length}`;
    if (key === schemaKey && schemaVal) return schemaVal;
    schemaVal = buildQuerySchema(this.elementMap.values(), {
      relTypes: [...(this.presentRelTypes || []), ...Object.values(RELATIONSHIP_TYPES)]
    });
    schemaKey = key;
    return schemaVal;
  },

  // Comparator metadata for the builder's comparator <select>.
  get queryComparators() {
    return COMPARATORS;
  },
  comparatorNeedsValue(cmp) {
    return COMPARATORS.find((c) => c.key === cmp)?.needsValue !== false;
  },
  // Field names present in the data, for the builder's field datalist.
  get queryFieldNames() {
    return this.querySchema.fields.map((f) => f.field);
  },
  // Type options (friendly aliases first, then classes actually present).
  get queryTypeOptions() {
    const aliases = Object.keys(TYPE_ALIASES);
    const present = this.querySchema.types.map((t) => t.cls);
    return [...new Set([...aliases, ...present])];
  },
  get queryRelOptions() {
    return this.querySchema.relTypes;
  },
  // Distinct sampled values for a field (enum-like fields), for a value datalist.
  queryFieldValues(field) {
    return (this.querySchema.valuesByField[field] || []).map((v) => v.value);
  },

  // --- Panel + mode -------------------------------------------------------

  toggleQueryPanel() {
    this.queryPanelOpen = !this.queryPanelOpen;
    if (this.queryPanelOpen) this.$nextTick(() => this.$refs.queryInput?.focus?.());
  },
  closeQueryPanel() {
    this.queryPanelOpen = false;
    this.queryAcOpen = false;
  },
  setQueryMode(mode) {
    this.queryMode = mode;
    this.queryAcOpen = false;
    // Entering text mode: reflect the current builder as text. Entering the
    // builder: parse the text so both stay consistent.
    if (mode === 'text') {
      this.queryText = hasConditions(this.queryBuilder) ? serializeQuery(this.queryBuilder) : '';
    } else {
      const { ast, error } = parseQuery(this.queryText);
      if (!error) this.queryBuilder = ast || newGroup('and');
    }
  },
  // The visual builder edits a flat list of conditions under one AND/OR root.
  // A query with nested grouping (only reachable via the text box) stays
  // text-only; the builder shows a notice pointing there.
  get queryBuilderEditable() {
    return (this.queryBuilder.children || []).every((c) => !!c.kind);
  },
  // A few ready-made queries surfaced as chips for discoverability.
  get queryExamples() {
    return [
      { label: 'Packages named *ssl*', q: 'type:Package name:*ssl*' },
      { label: 'C/C++ source files', q: 'type:File (name:*.c OR name:*.h OR name:*.cpp)' },
      { label: 'No concluded license', q: 'type:Package NOT ->hasConcludedLicense' }
    ];
  },
  applyExample(q) {
    this.queryText = q;
    this._applyFromText();
  },

  // --- Visual builder edits ----------------------------------------------

  addQueryCondition(group, kind = 'type') {
    group.children.push(
      kind === 'prop' ? newPropCond() : kind === 'rel' ? newRelCond() : newTypeCond()
    );
    this.onBuilderChange();
  },
  addQueryGroup(group) {
    group.children.push({ op: 'or', not: false, children: [newPropCond()] });
    this.onBuilderChange();
  },
  removeQueryChild(group, index) {
    group.children.splice(index, 1);
    this.onBuilderChange();
  },
  setGroupOp(group, op) {
    group.op = op;
    this.onBuilderChange();
  },
  toggleQueryNot(node) {
    node.not = !node.not;
    this.onBuilderChange();
  },
  // Replaces a condition in place when the user switches its kind (Type/Prop/Rel).
  changeConditionKind(group, index, kind) {
    group.children[index] =
      kind === 'prop' ? newPropCond() : kind === 'rel' ? newRelCond() : newTypeCond();
    this.onBuilderChange();
  },
  // Relationship target (optional nested condition): a Type or Property leaf.
  addRelTarget(relNode) {
    relNode.target = newTypeCond();
    this.onBuilderChange();
  },
  removeRelTarget(relNode) {
    relNode.target = null;
    this.onBuilderChange();
  },
  setTargetKind(relNode, kind) {
    relNode.target = kind === 'prop' ? newPropCond() : newTypeCond();
    this.onBuilderChange();
  },

  // Any builder mutation: mirror to the text box and re-apply.
  onBuilderChange() {
    this.queryText = hasConditions(this.queryBuilder) ? serializeQuery(this.queryBuilder) : '';
    this.queryError = '';
    this._recompileAndApply();
  },

  // --- Text mode ----------------------------------------------------------

  onQueryInput(event) {
    this._computeAutocomplete(event.target);
    clearTimeout(this._queryApplyTimer);
    this._queryApplyTimer = setTimeout(() => this._applyFromText(), 200);
  },
  _applyFromText() {
    const { ast, error } = parseQuery(this.queryText);
    if (error) {
      this.queryError = error;
      return;
    }
    this.queryError = '';
    this.queryBuilder = ast || newGroup('and');
    this._recompileAndApply();
  },

  onQueryKeydown(event) {
    if (!this.queryAcOpen || !this.queryAcItems.length) return;
    const n = this.queryAcItems.length;
    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault();
        this.queryAcIndex = (this.queryAcIndex + 1) % n;
        break;
      case 'ArrowUp':
        event.preventDefault();
        this.queryAcIndex = (this.queryAcIndex - 1 + n) % n;
        break;
      case 'Enter':
      case 'Tab':
        event.preventDefault();
        this.acceptAutocomplete(this.queryAcIndex);
        break;
      case 'Escape':
        event.preventDefault();
        this.queryAcOpen = false;
        break;
      default:
        break;
    }
  },

  closeAutocomplete() {
    this.queryAcOpen = false;
  },
  // Close the popover after a blur, but late enough that a click on an item
  // (which fires mousedown first) still lands.
  queryAcBlur() {
    setTimeout(() => {
      this.queryAcOpen = false;
    }, 150);
  },

  _computeAutocomplete(el) {
    if (!el) {
      this.queryAcOpen = false;
      return;
    }
    const value = el.value;
    const caret = el.selectionStart ?? value.length;
    let start = caret;
    while (start > 0 && !/[\s()]/.test(value[start - 1])) start--;
    const token = value.slice(start, caret);
    this._queryAcTokenStart = start;
    this._queryAcCaret = caret;
    const items = this._suggestFor(token);
    this.queryAcItems = items.slice(0, 12);
    this.queryAcIndex = 0;
    this.queryAcOpen = items.length > 0 && caret > 0;
  },

  _suggestFor(token) {
    const schema = this.querySchema;
    const start = this._queryAcTokenStart;
    const lc = token.toLowerCase();

    // Relationship: ->rel / <-rel  (nested target completion stays text-only).
    if ((token.startsWith('->') || token.startsWith('<-')) && !token.includes('.')) {
      this._queryAcSegStart = start + 2;
      return this._filter(
        schema.relTypes.map((r) => ({ label: r, insert: r, kind: 'rel', trailing: true })),
        token.slice(2)
      );
    }
    // type:… -> aliases + present classes.
    if (lc.startsWith('type:') || lc.startsWith('type=')) {
      this._queryAcSegStart = start + 5;
      return this._filter(this._typeSuggestions(), token.slice(5));
    }
    // has:… -> field names.
    if (lc.startsWith('has:')) {
      this._queryAcSegStart = start + 4;
      return this._filter(this._fieldSuggestions(false), token.slice(4));
    }
    // field:value / field=value / field~value -> value suggestions for that field.
    const op = /^([A-Za-z0-9_.]+)(:|=|~)(.*)$/.exec(token);
    if (op) {
      const field = op[1];
      this._queryAcSegStart = start + field.length + 1;
      const seg = op[3].replace(/^[><=?]*/, '');
      const vals = (schema.valuesByField[field] || []).map((v) => ({
        label: v.label || v.value,
        insert: v.value,
        kind: 'value',
        trailing: true
      }));
      return this._filter(vals, seg);
    }
    // Bare token -> starters + fields.
    this._queryAcSegStart = start;
    const starters = [
      { label: 'type:', insert: 'type:', kind: 'starter', hint: 'by SPDX type' },
      { label: 'has:', insert: 'has:', kind: 'starter', hint: 'field exists' },
      { label: '->', insert: '->', kind: 'starter', hint: 'outgoing link' },
      { label: '<-', insert: '<-', kind: 'starter', hint: 'incoming link' }
    ];
    return this._filter([...starters, ...this._fieldSuggestions(true)], token);
  },

  _typeSuggestions() {
    const aliases = Object.keys(TYPE_ALIASES).map((a) => ({
      label: a,
      insert: a,
      kind: 'type',
      hint: 'alias',
      trailing: true
    }));
    const present = this.querySchema.types.map((t) => ({
      label: t.cls,
      insert: t.cls,
      kind: 'type',
      hint: String(t.count),
      trailing: true
    }));
    return [...aliases, ...present];
  },

  _fieldSuggestions(withColon) {
    return this.querySchema.fields.map((f) => ({
      label: withColon ? `${f.field}:` : f.field,
      insert: withColon ? `${f.field}:` : f.field,
      kind: 'field',
      hint: f.kind,
      trailing: !withColon
    }));
  },

  _filter(items, seg) {
    const q = (seg || '').toLowerCase();
    if (!q) return items.slice(0, 20);
    const starts = [];
    const has = [];
    for (const it of items) {
      const l = it.label.toLowerCase();
      if (l.startsWith(q)) starts.push(it);
      else if (l.includes(q)) has.push(it);
    }
    return [...starts, ...has].slice(0, 20);
  },

  acceptAutocomplete(index) {
    const item = this.queryAcItems[index];
    if (!item) return;
    const el = this.$refs.queryInput;
    const value = this.queryText;
    const before = value.slice(0, this._queryAcSegStart);
    const after = value.slice(this._queryAcCaret);
    const insert = item.insert + (item.trailing ? ' ' : '');
    this.queryText = before + insert + after;
    this.queryAcOpen = false;
    const pos = (before + insert).length;
    // rAF (not $nextTick) so the caret set survives Alpine's DOM update.
    requestAnimationFrame(() => {
      if (!el) return;
      el.focus();
      el.setSelectionRange(pos, pos);
      this._computeAutocomplete(el);
    });
    clearTimeout(this._queryApplyTimer);
    this._queryApplyTimer = setTimeout(() => this._applyFromText(), 200);
  },

  // --- Compile + apply ----------------------------------------------------

  _queryCtx() {
    return {
      elementMap: this.elementMap,
      relFrom: (id) => this.relFromIndex.get(id) || [],
      relTo: (id) => this.relToIndex.get(id) || []
    };
  },

  _recompileAndApply() {
    const root = this.queryBuilder;
    if (!hasConditions(root)) {
      this.queryActive = false;
      this.graphQueryPredicate = null;
      this.queryResults = [];
      this.queryResultTotal = 0;
      this.graphSearch();
      return;
    }
    const ctx = this._queryCtx();
    const compiled = compileQuery(root);
    this.graphQueryPredicate = (el) => compiled(el, ctx);
    this.queryActive = true;
    this._computeResults(compiled, ctx);
    this.graphSearch();
  },

  _computeResults(compiled, ctx) {
    const rows = [];
    let total = 0;
    for (const el of this.elementMap.values()) {
      if (el.placeholder || !el.type) continue;
      if (!compiled(el, ctx)) continue;
      total++;
      if (rows.length < RESULT_CAP) rows.push(this._queryResultRow(el));
    }
    this.queryResults = rows;
    this.queryResultTotal = total;
    this.queryResultLimit = 50;
  },

  _queryResultRow(el) {
    return {
      id: el.spdxId,
      name: el.name || this.cleanName(el.spdxId),
      nodeType: this.getNodeType(el),
      typeLabel: friendlyTypeLabel(el.type),
      sub: el.spdxId
    };
  },

  get queryResultsShown() {
    return this.queryResults.slice(0, this.queryResultLimit);
  },
  get queryHasMore() {
    return this.queryResults.length > this.queryResultLimit;
  },
  loadMoreResults() {
    this.queryResultLimit += 100;
  },
  // Matches that are not currently drawn (hidden by a node/edge filter or folded
  // into a cluster), so the list count and the graph glow can legitimately differ.
  get queryHiddenCount() {
    return Math.max(0, this.queryResultTotal - this.graphMatchCount);
  },

  selectQueryResult(id) {
    this.selectGraphNode(id);
    if (this.graphSyncSelection) this.graphSyncSelection(id);
  },

  clearQuery() {
    this.queryText = '';
    this.queryBuilder = newGroup('and');
    this.queryError = '';
    this.queryAcOpen = false;
    this.queryActive = false;
    this.graphQueryPredicate = null;
    this.queryResults = [];
    this.queryResultTotal = 0;
    this.graphSearch();
  },

  // Fresh SBOM: drop any query so a stale predicate never lingers over new data.
  _resetQuery() {
    schemaKey = null;
    schemaVal = null;
    this.queryText = '';
    this.queryBuilder = newGroup('and');
    this.queryError = '';
    this.queryAcOpen = false;
    this.queryActive = false;
    this.graphQueryPredicate = null;
    this.queryResults = [];
    this.queryResultTotal = 0;
    this.queryResultLimit = 50;
  }
};
