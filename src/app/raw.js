import { copyToClipboard, formatByteSize } from '../lib/index.js';

/* Raw JSON-LD view: shows the underlying file(s) as loaded (or pretty-printed)
   with lightweight syntax highlighting. String values that are the spdxId of a
   known element render as links to wherever that element is visualized. One
   file shows at a time so only the active file's markup stays in the DOM. */

const HIGHLIGHT_MAX_CHARS = 10_000_000;
const INLINE_MAX_CHARS = 50_000_000;

function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function escapeAttr(s) {
  return escapeHtml(s).replace(/"/g, '&quot;');
}

// Matches one JSON token: a string (optionally a key when followed by `:`),
// true/false/null, or a number. Structural characters and whitespace fall in
// the gaps between matches and are emitted as escaped plain text.
const JSON_TOKEN_RE =
  /"(\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?/g;

// Single-pass tokenizer → HTML with classed spans. `isLink(value)` decides
// whether a string value (the text between the quotes) should become a nav
// link. Works on the raw (unescaped) text and escapes each piece as it goes,
// so link lookups see the real id, not an HTML-escaped one.
function renderJsonLd(text, isLink) {
  let out = '';
  let last = 0;
  let m;
  JSON_TOKEN_RE.lastIndex = 0;
  while ((m = JSON_TOKEN_RE.exec(text)) !== null) {
    if (m.index > last) out += escapeHtml(text.slice(last, m.index));
    last = JSON_TOKEN_RE.lastIndex;
    const tok = m[0];
    if (tok[0] === '"') {
      if (tok[tok.length - 1] === ':') {
        // "key": (a string followed by a colon is always an object key)
        out += `<span class="jsonld-key">${escapeHtml(tok)}</span>`;
      } else {
        const value = tok.slice(1, -1); // inner text, good enough for id lookup
        if (isLink && isLink(value)) {
          out +=
            `<span class="jsonld-link" data-spdxid="${escapeAttr(value)}" ` +
            `role="link" tabindex="0" title="Go to this element">${escapeHtml(tok)}</span>`;
        } else {
          out += `<span class="jsonld-string">${escapeHtml(tok)}</span>`;
        }
      }
    } else if (tok === 'true' || tok === 'false') {
      out += `<span class="jsonld-bool">${tok}</span>`;
    } else if (tok === 'null') {
      out += `<span class="jsonld-null">${tok}</span>`;
    } else {
      out += `<span class="jsonld-num">${tok}</span>`;
    }
  }
  if (last < text.length) out += escapeHtml(text.slice(last));
  return out;
}

// Pretty-print when the text parses; fall back to the original on failure so a
// malformed file still displays (raw) rather than blowing up the view.
function prettyPrint(text) {
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return text;
  }
}

export const rawMixin = {
  // Clamped index of the file the Raw view is showing (safe after a removal).
  get rawIndex() {
    if (!this.loadedFiles.length) return 0;
    return Math.min(Math.max(this.rawActiveFile, 0), this.loadedFiles.length - 1);
  },
  // The currently shown file record ({ name, text }) or null when none loaded.
  get rawFile() {
    return this.loadedFiles[this.rawIndex] || null;
  },

  // True when `id` resolves to a real element, so every id reference (spdxId,
  // from, to, element, creationInfo, …) becomes a link. Elements with a
  // dedicated list open there; the rest open in the detail panel (see
  // rawNavigate). Placeholders / NoAssertion sentinels stay plain.
  _rawLinkable(id) {
    const el = this.elementMap.get(id);
    return !!el && !el.placeholder;
  },

  // The exact string shown in the code block: pretty-printed when the Formatted
  // toggle is on (and the file is small enough to reparse), else as loaded.
  _rawSource(index) {
    const f = this.loadedFiles[index];
    if (!f) return '';
    if (this.rawPretty && f.text.length <= INLINE_MAX_CHARS) return prettyPrint(f.text);
    return f.text;
  },

  // HTML for the code block: highlighted + linkified, or escaped plain text for
  // files too big to tokenize. Only called from an x-if that already excluded
  // oversized (download-only) files.
  rawHighlighted(index) {
    const f = this.loadedFiles[index];
    if (!f) return '';
    const src = this._rawSource(index);
    if (f.text.length > HIGHLIGHT_MAX_CHARS) return escapeHtml(src);
    return renderJsonLd(src, (id) => this._rawLinkable(id));
  },

  rawSizeLabel(index) {
    const f = this.loadedFiles[index];
    return f ? formatByteSize(f.text.length) : '';
  },
  // File too big to render inline at all.
  rawTooLarge(index) {
    const f = this.loadedFiles[index];
    return !!f && f.text.length > INLINE_MAX_CHARS;
  },
  // Rendered inline, but as plain text because highlighting would be too slow.
  rawHighlightDisabled(index) {
    const f = this.loadedFiles[index];
    return !!f && f.text.length > HIGHLIGHT_MAX_CHARS && f.text.length <= INLINE_MAX_CHARS;
  },

  // Pick a file to display, resetting the scroll to the top of the new file.
  selectRawFile(i) {
    if (i === this.rawActiveFile) return;
    this.rawActiveFile = i;
    this._resetRawScroll();
  },
  // Flip between pretty-printed and as-loaded; scroll back to the top since the
  // line layout changes completely.
  toggleRawPretty() {
    this.rawPretty = !this.rawPretty;
    this._resetRawScroll();
  },
  _resetRawScroll() {
    // A macrotask so it runs after Alpine's microtask flush has swapped the
    // (possibly large) x-html content into the DOM; setting scrollTop any
    // earlier would be a no-op against the old content's height.
    setTimeout(() => {
      const box = document.getElementById('rawScrollBox');
      if (box) box.scrollTop = 0;
    }, 0);
  },

  // Delegated handler on the code block: a click (or Enter) on a linkified id
  // takes you to that element — its dedicated list view when it has one,
  // otherwise its detail panel (agents, the SBOM doc, relationships, …).
  rawNavigate(e) {
    const target = e.target.closest?.('[data-spdxid]');
    if (!target) return;
    e.preventDefault();
    const id = target.getAttribute('data-spdxid');
    if (!id) return;
    const el = this.elementMap.get(id);
    if (el && this.listTargetFor(el)) this.navigateTo(id);
    else this.selectGraphNode(id);
  },

  copyRaw(index) {
    copyToClipboard(this._rawSource(index)).then(() => {
      this.toastMsg = 'Copied to clipboard';
      setTimeout(() => (this.toastMsg = ''), 2000);
    });
  },

  // Download the file exactly as it was loaded (never the pretty-printed form).
  downloadRaw(index) {
    const f = this.loadedFiles[index];
    if (!f) return;
    const blob = new Blob([f.text], { type: 'application/ld+json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = f.name || 'document.jsonld';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
};
