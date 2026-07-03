/* ==========================================================================
   Global search
   The header search box: a fuzzy-ranked lookup across every navigable element
   in the loaded document (packages, files, build configs, builds, tools,
   licenses, vulnerabilities). Returns the top few matches for a styled
   command-palette style dropdown; picking one navigates to its list card.
   Per-view "filter" boxes (packages / files) are separate — this box is only
   the cross-cutting jump-to-anything search.
   ========================================================================== */

const SEARCH_LIMIT = 10; // top-N matches surfaced in the dropdown
const MIN_QUERY = 1; // characters before we bother scoring

// Inner SVG markup per node type (stroked, sized by the wrapping <svg>). Mirrors
// the sidebar/list iconography so a result reads as the same "kind" of thing.
const SEARCH_ICONS = {
  package:
    '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/>',
  ai: '<rect x="6" y="6" width="12" height="12" rx="2" stroke-width="2"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2"/>',
  dataset:
    '<ellipse cx="12" cy="5" rx="8" ry="3" stroke-width="2"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 5v6c0 1.66 3.58 3 8 3s8-1.34 8-3V5M4 11v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6"/>',
  file: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>',
  config:
    '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"/>',
  build:
    '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"/>',
  tool: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21.75 6.75a4.5 4.5 0 01-4.884 4.484c-1.076-.091-2.264.071-2.95.904l-7.152 8.684a2.548 2.548 0 11-3.586-3.586l8.684-7.152c.833-.686.995-1.874.904-2.95a4.5 4.5 0 016.336-4.486l-3.276 3.276a3.004 3.004 0 002.25 2.25l3.276-3.276c.256.565.398 1.192.398 1.852z"/>',
  license:
    '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>',
  vulnerability:
    '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01M12 3l7 4v5c0 4.418-3 8.418-7 9.5C8 20.418 5 16.418 5 12V7l7-4z"/>'
};

// Human label per node type, shown as the chip on the right of a result row.
const SEARCH_TYPE_LABELS = {
  package: 'Package',
  ai: 'AI model',
  dataset: 'Dataset',
  file: 'File',
  config: 'Build config',
  build: 'Build',
  tool: 'Tool',
  license: 'License',
  vulnerability: 'Vulnerability'
};

// Memo for the (potentially large — ~30k files) searchable corpus. Rebuilt only
// when a collection's length changes, i.e. when a fresh document is parsed; kept
// off the reactive state so it isn't proxied.
let searchCorpusKey = null;
let searchCorpusVal = [];
// Memo for the last scored result set, so unrelated reactive churn (e.g. hover
// state changing while the dropdown is open) doesn't re-score the whole corpus.
let searchResultsQuery = null;
let searchResultsCorpus = null;
let searchResultsVal = [];

export const searchMixin = {
  _resetSearchMemos() {
    searchCorpusKey = null;
    searchResultsQuery = null;
  },

  // Flat, pre-lowercased index of everything the header search can jump to. Each
  // entry carries what the dropdown needs to render (name/sub/nodeType) plus the
  // lowercased haystacks used for scoring.
  get searchCorpus() {
    const key = [
      this.packages.length,
      this.files.length,
      this.buildConfigs.length,
      this.builds.length,
      this.tools.length,
      this.licenses.length,
      this.vulnerabilities.length
    ].join('|');
    if (key === searchCorpusKey) return searchCorpusVal;

    const out = [];
    const add = (id, nodeType, name, sub, extra) => {
      if (!id || !name) return;
      out.push({
        id,
        nodeType,
        typeLabel: SEARCH_TYPE_LABELS[nodeType] || 'Element',
        name,
        sub: sub || '',
        _n: name.toLowerCase(),
        _e: (extra || '').toLowerCase()
      });
    };

    for (const p of this.packages) {
      const nodeType = this.getNodeType(p); // package | ai | dataset
      const name = p.name || this.cleanName(p.spdxId);
      const sub = this.isMeaningful(p.software_packageVersion)
        ? `v${p.software_packageVersion}`
        : '';
      add(p.spdxId, nodeType, name, sub, p.spdxId);
    }
    for (const f of this.files) {
      add(f.spdxId, 'file', f.name || this.cleanName(f.spdxId), '', f.spdxId);
    }
    for (const c of this.buildConfigs) {
      add(c.spdxId, 'config', c.name || this.cleanName(c.spdxId), '', c.spdxId);
    }
    for (const b of this.builds) {
      add(b.spdxId, 'build', this.buildDisplayName(b), b.build_buildId || '', b.build_buildId);
    }
    for (const t of this.tools) {
      add(t.spdxId, 'tool', t.name || this.cleanName(t.spdxId), '', t.spdxId);
    }
    for (const l of this.licenses) {
      const sub = l.userCount ? `Used by ${l.userCount}` : '';
      add(l.id, 'license', l.label || l.id, sub, l.id);
    }
    for (const v of this.vulnerabilities) {
      const sub = v.packageCount
        ? `${v.packageCount} package${v.packageCount === 1 ? '' : 's'} affected`
        : '';
      add(v.spdxId, 'vulnerability', v.name, sub, '');
    }

    searchCorpusKey = key;
    searchCorpusVal = out;
    return out;
  },

  // Scores one field: exact > prefix > word-start > substring, plus a coverage
  // bonus so a query that spans most of a short name (e.g. "apach" in
  // "Apache-2.0") outranks the same substring buried in a long one.
  _fieldScore(text, q, weight) {
    if (!text) return 0;
    const i = text.indexOf(q);
    if (i < 0) return 0;
    let s;
    if (text === q) s = 1000;
    else if (i === 0) s = 800;
    else if (!/[a-z0-9]/i.test(text[i - 1]))
      s = 600; // query starts a new word/segment
    else s = 300;
    s += (q.length / text.length) * 200;
    return s * weight;
  },

  // Best score for an entry across its name (full weight) and its id/extra
  // haystack (reduced weight, so an id-only hit ranks below a name hit).
  _entryScore(entry, q) {
    return Math.max(this._fieldScore(entry._n, q, 1), this._fieldScore(entry._e, q, 0.55));
  },

  // Top matches for the current query, best first. Memoized on (query, corpus)
  // so it only recomputes when the text or the underlying document changes.
  get searchResults() {
    const q = (this.searchQuery || '').trim().toLowerCase();
    const corpus = this.searchCorpus;
    if (q.length < MIN_QUERY) return [];
    if (q === searchResultsQuery && corpus === searchResultsCorpus) return searchResultsVal;

    const scored = [];
    for (const entry of corpus) {
      const score = this._entryScore(entry, q);
      if (score > 0) scored.push({ entry, score });
    }
    // Rank by score, then shorter name (tighter match), then alphabetical.
    scored.sort(
      (a, b) =>
        b.score - a.score ||
        a.entry._n.length - b.entry._n.length ||
        a.entry._n.localeCompare(b.entry._n)
    );
    const results = scored.slice(0, SEARCH_LIMIT).map((s) => s.entry);

    searchResultsQuery = q;
    searchResultsCorpus = corpus;
    searchResultsVal = results;
    return results;
  },

  searchIconSvg(nodeType) {
    return SEARCH_ICONS[nodeType] || SEARCH_ICONS.package;
  },

  _escapeHtml(str) {
    return String(str).replace(
      /[&<>"']/g,
      (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]
    );
  },

  // Escapes the label and wraps the matched run in a highlight span, so the part
  // the user typed stands out inside the result name.
  searchHighlight(text, query) {
    const esc = this._escapeHtml(text || '');
    const q = (query || '').trim();
    if (!q) return esc;
    const i = (text || '').toLowerCase().indexOf(q.toLowerCase());
    if (i < 0) return esc;
    const before = this._escapeHtml(text.slice(0, i));
    const hit = this._escapeHtml(text.slice(i, i + q.length));
    const after = this._escapeHtml(text.slice(i + q.length));
    return `${before}<span class="search-hl">${hit}</span>${after}`;
  },

  openSearch() {
    if ((this.searchQuery || '').trim()) this.searchOpen = true;
    this.searchActiveIndex = 0;
  },
  closeSearch() {
    this.searchOpen = false;
  },
  clearSearch() {
    this.searchQuery = '';
    this.searchOpen = false;
    this.searchActiveIndex = 0;
  },

  // Jump to a result's list card and dismiss the dropdown. Licenses are keyed by
  // their (possibly non-element) id, so route them explicitly; everything else
  // routes by spdxId through the shared navigateTo dispatcher.
  selectSearchResult(result) {
    if (!result) return;
    this.searchOpen = false;
    this.searchQuery = '';
    this.searchActiveIndex = 0;
    if (result.nodeType === 'license') {
      this.navigateToLicense(result.id);
    } else {
      this.navigateTo(result.id);
    }
  },

  // Arrow-key / Enter handling for the results list.
  searchKeydown(event) {
    const results = this.searchResults;
    if (event.key === 'ArrowDown') {
      if (!results.length) return;
      event.preventDefault();
      this.searchOpen = true;
      this.searchActiveIndex = (this.searchActiveIndex + 1) % results.length;
    } else if (event.key === 'ArrowUp') {
      if (!results.length) return;
      event.preventDefault();
      this.searchActiveIndex = (this.searchActiveIndex - 1 + results.length) % results.length;
    } else if (event.key === 'Enter') {
      if (!results.length) return;
      event.preventDefault();
      this.selectSearchResult(results[this.searchActiveIndex] || results[0]);
      event.target.blur();
    } else if (event.key === 'Escape') {
      this.closeSearch();
    }
  }
};
