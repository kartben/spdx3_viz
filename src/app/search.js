/* Global header search: a fuzzy-ranked lookup across every navigable element in
   the loaded document, surfacing the top matches in a command-palette dropdown
   where picking one navigates to its list card. Distinct from the per-view
   filter boxes. */

const SEARCH_LIMIT = 10; // top-N matches surfaced in the dropdown
const MIN_QUERY = 1; // characters before we bother scoring

// Human label per node type, shown as the chip on the right of a result row.
const SEARCH_TYPE_LABELS = {
  package: 'Package',
  ai: 'AI model',
  dataset: 'Dataset',
  file: 'File',
  hardware: 'Hardware',
  requirement: 'Requirement',
  config: 'Build config',
  build: 'Build',
  tool: 'Tool',
  license: 'License',
  vulnerability: 'Vulnerability',
  agent: 'Agent'
};

// Memo for the searchable corpus, rebuilt only when a collection's length
// changes (i.e. a fresh document is parsed); kept off the reactive state.
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
      this.hardware.length,
      this.requirements.length,
      this.buildConfigs.length,
      this.builds.length,
      this.tools.length,
      this.licenses.length,
      this.vulnerabilities.length,
      this.agents.length
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
    for (const h of this.hardware) {
      add(
        h.spdxId,
        'hardware',
        h.name || this.cleanName(h.spdxId),
        h.hardware_partNumber || '',
        h.hardware_partNumber + ' ' + h.spdxId
      );
    }
    for (const r of this.requirements) {
      // Prefer the requirement UID as the subtitle, else the statement, so a
      // requirement is findable by either its id or its text.
      const uid = this.externalIdentifiers(r)[0]?.identifier || '';
      const statement = r.requirementStatement || r.functionalsafety_assumptionStatement || '';
      add(
        r.spdxId,
        'requirement',
        r.name || this.cleanName(r.spdxId),
        uid || statement,
        `${uid} ${statement} ${r.spdxId}`
      );
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
    for (const a of this.agents) {
      const links = this.agentLinkCount(a);
      const sub = links ? `${links} link${links === 1 ? '' : 's'}` : this.agentTypeLabel(a);
      add(
        a.spdxId,
        'agent',
        a.name || this.cleanName(a.spdxId),
        sub,
        `${this.agentEmail(a)} ${a.spdxId}`
      );
    }

    searchCorpusKey = key;
    searchCorpusVal = out;
    return out;
  },

  // Scores one field: exact > prefix > word-start > substring, plus a coverage
  // bonus so a query spanning most of a short name outranks the same substring
  // buried in a long one.
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
