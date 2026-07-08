/* File loading and parse orchestration: reading files/samples, driving the
   progress bar, and applying the worker's parsed result to component state. */

import { parseShareHash } from '../lib/index.js';

/* A single long-lived parser worker, kept off the reactive state so it is never
   proxied; parsing runs here to keep the main thread responsive.
   latestParseReqId lets us ignore stale results when a newer load supersedes an
   in-flight one. */
let parserWorker = null;
let parseReqSeq = 0;
let latestParseReqId = 0;

// VEX edges and the Vulnerabilities node type default to off since a large VEX
// set can swamp the graph; when there are fewer than this many VEX edges we
// enable the vuln node type and all four VEX edge types at load time.
const VEX_AUTO_SHOW_MAX = 200;
const VEX_FILTER_KEYS = new Set([
  'vulnerability',
  'fixedIn',
  'doesNotAffect',
  'affects',
  'underInvestigation'
]);

function getParserWorker() {
  if (!parserWorker) {
    parserWorker = new Worker(new URL('../parser/parser.worker.js', import.meta.url), {
      type: 'module'
    });
  }
  return parserWorker;
}

/* Marks an object so Alpine's reactivity leaves it untouched: the parsed SBOM is
   large and immutable, so deep-proxying only adds per-access overhead. `__v_skip`
   is the flag @vue/reactivity checks; set non-enumerable so it never leaks into
   iteration. */
function markRaw(value) {
  if (
    value &&
    typeof value === 'object' &&
    !Object.prototype.hasOwnProperty.call(value, '__v_skip')
  ) {
    Object.defineProperty(value, '__v_skip', { value: true, configurable: true });
  }
  return value;
}

/* Marks every object-valued property of a payload raw, then returns it.
   Marking the top-level containers (Maps/arrays) is enough: reading them no
   longer returns a proxy, so their elements aren't proxied on access either. */
function markPayloadRaw(payload) {
  Object.keys(payload || {}).forEach((key) => markRaw(payload[key]));
  return payload;
}

// Human-readable size for a byte count using decimal (1000-based) units.
// Returns '' for anything that isn't a positive, finite number.
function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '';
  const units = ['B', 'KB', 'MB', 'GB'];
  let n = bytes;
  let i = 0;
  while (n >= 1000 && i < units.length - 1) {
    n /= 1000;
    i++;
  }
  const rounded = i === 0 ? n : n >= 100 ? Math.round(n) : Math.round(n * 10) / 10;
  return `${rounded} ${units[i]}`;
}

export const loadingMixin = {
  // Bundled demo SBOMs — listed in samples/samples.json, loaded over fetch
  async loadSampleManifest() {
    try {
      const res = await fetch('samples/samples.json');
      if (res.ok) {
        this.samples = (await res.json()).filter((s) => !s.disabled);
        // Sizes come from the manifest (uncompressed totals) so the label
        // reflects the real download rather than a gzipped Content-Length.
        this.samples.forEach((s) => {
          if (s.size) s.sizeLabel = formatBytes(s.size);
        });
      }
    } catch {
      /* demos just won't show if the manifest is missing */
    }
  },
  // Startup: a share link in the URL auto-loads its sample, then _applyDeepLink
  // restores the view/element once parsing completes.
  _maybeLoadFromUrl() {
    const link = parseShareHash(location.hash);
    if (!link) return;
    const sample = this.samples.find((s) => s.id === link.sample);
    if (!sample) return;
    this._pendingDeepLink = link;
    this.loadSample(sample);
  },
  async loadSample(sample) {
    this.loadingSample = sample.id;
    this.sampleError = '';
    this._beginParseSession(); // show the overlay during download too
    this.progressPhase = 'Downloading…';
    try {
      const loaded = [];
      const total = sample.files.length;
      for (let i = 0; i < sample.files.length; i++) {
        const fname = sample.files[i];
        const res = await fetch(`${sample.dir}/${fname}`);
        if (!res.ok) throw new Error(`${fname} (HTTP ${res.status})`);
        const text = await this._readResponseWithProgress(res, i, total);
        loaded.push({ name: fname, text });
      }
      this.loadedFiles = loaded; // replace — the drop zone starts empty
      this.loadedSampleId = sample.id; // pure sample content: the URL can link back to it
      this.rebuildFromLoadedFiles(); // existing merge + parse path (session continues)
      this.dataLoaded = true;
    } catch (err) {
      this.parsing = false;
      this.progressEta = null;
      this.sampleError = `Could not load ${sample.name}: ${err.message}`;
    } finally {
      this.loadingSample = null;
    }
  },

  // Streams a fetch response, advancing the download band of the progress bar.
  // Falls back to a plain read when the body/Content-Length isn't available.
  async _readResponseWithProgress(res, fileIndex, totalFiles) {
    const len = Number(res.headers.get('Content-Length'));
    if (!res.body || !len) {
      const text = await res.text();
      this._setProgress('download', (fileIndex + 1) / totalFiles);
      return text;
    }
    const reader = res.body.getReader();
    const chunks = [];
    let received = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      received += value.length;
      this._setProgress('download', (fileIndex + Math.min(1, received / len)) / totalFiles);
    }
    return new Blob(chunks).text();
  },

  // File handling — supports multiple files
  handleFileDrop(e) {
    e.target.closest?.('.drop-zone')?.classList.remove('drag-over');
    const files = [...(e.dataTransfer.files || [])];
    if (files.length) this.readFiles(files);
  },
  handleFileInput(e) {
    const files = [...(e.target.files || [])];
    if (files.length) this.readFiles(files);
    e.target.value = ''; // reset so same file can be re-added
  },
  readFiles(fileList) {
    this.loadedSampleId = null; // user files (even added to a sample) aren't linkable
    this._beginParseSession(); // show the overlay during file reads too
    this.progressPhase = 'Reading files…';
    const total = fileList.length;
    const loaded = new Array(total); // preserve input order
    const fileProgress = new Array(total).fill(0);
    let remaining = total;
    fileList.forEach((file, i) => {
      const reader = new FileReader();
      reader.onprogress = (ev) => {
        if (!ev.lengthComputable) return;
        fileProgress[i] = ev.loaded / ev.total;
        const sum = fileProgress.reduce((a, b) => a + b, 0);
        this._setProgress('download', sum / total);
      };
      reader.onload = (ev) => {
        // Store the raw text; JSON.parse happens in the worker so the main
        // thread never blocks on large files.
        loaded[i] = { name: file.name, text: ev.target.result };
        fileProgress[i] = 1;
        remaining--;
        if (remaining === 0) {
          loaded.forEach((f) => this.loadedFiles.push(f));
          this.rebuildFromLoadedFiles(); // session continues into the worker
          this.dataLoaded = true;
        }
      };
      reader.readAsText(file);
    });
  },
  removeFile(index) {
    this.loadedSampleId = null;
    this.loadedFiles.splice(index, 1);
    if (this.loadedFiles.length === 0) {
      this.dataLoaded = false;
      return;
    }
    // Keep the Raw view's selected file in range after a removal.
    if (this.rawActiveFile >= this.loadedFiles.length) this.rawActiveFile = 0;
    this.rebuildFromLoadedFiles();
  },

  // Begins a load/parse session: shows the overlay and resets the progress
  // bar + ETA timer. Callers (loadSample/readFiles) start this before the
  // download phase so the bar covers download + parse; parseData only starts
  // it if a session isn't already running (e.g. removing a file re-parses
  // from cached text with no download).
  _beginParseSession() {
    this.parsing = true;
    this.parseError = '';
    this.progress = 0;
    this.progressPhase = '';
    this.progressEta = null;
    this._progressStart = performance.now();
    this._progressEtaSmoothed = null;
  },

  // Maps a phase + within-phase fraction (0..1) onto the overall bar and
  // updates the ETA from elapsed time vs. overall fraction.
  _setProgress(phase, value) {
    const bands = {
      download: [0, 0.3],
      json: [0.3, 0.5],
      graph: [0.5, 0.78],
      index: [0.78, 0.99]
    };
    const labels = {
      download: 'Downloading…',
      json: 'Reading JSON…',
      graph: 'Building graph…',
      index: 'Indexing relationships…'
    };
    const [lo, hi] = bands[phase] || [0, 1];
    const v = Math.max(0, Math.min(1, value));
    const overall = Math.min(0.99, lo + v * (hi - lo));
    // Progress only moves forward (phases can briefly overlap across files).
    if (overall >= this.progress) this.progress = overall;
    this.progressPhase = labels[phase] || '';

    const elapsed = (performance.now() - (this._progressStart || performance.now())) / 1000;
    if (this.progress > 0.04 && this.progress < 0.985) {
      const eta = (elapsed * (1 - this.progress)) / this.progress;
      // Exponential smoothing so the number doesn't jitter.
      this._progressEtaSmoothed =
        this._progressEtaSmoothed == null ? eta : this._progressEtaSmoothed * 0.6 + eta * 0.4;
      this.progressEta = this._progressEtaSmoothed;
    }
  },

  // Merge all loaded files and re-parse (off the main thread)
  rebuildFromLoadedFiles() {
    this.parseData(this.loadedFiles);
  },

  // Parse the loaded files in the worker, then apply the result.
  // `files` is [{ name, text }]; parsing (JSON.parse + graph + indexes) runs
  // in parser.worker.js so the UI never freezes on large SBOMs.
  parseData(files) {
    const worker = getParserWorker();
    const reqId = ++parseReqSeq;
    latestParseReqId = reqId;
    if (!this.parsing) this._beginParseSession(); // re-parse path (no download)

    worker.onmessage = (event) => {
      const msg = event.data || {};
      if (msg.id !== latestParseReqId) return; // a newer load superseded this one

      if (msg.type === 'progress') {
        this._setProgress(msg.phase, msg.value);
        return;
      }

      // type === 'done'
      this.parsing = false;
      this.progress = 1;
      this.progressEta = null;

      if (!msg.ok) {
        this.parseError = msg.error || 'Failed to parse SBOM';
        console.error('SBOM parse failed:', this.parseError);
        this.toastMsg = 'Error parsing SBOM: ' + this.parseError;
        setTimeout(() => (this.toastMsg = ''), 5000);
        return;
      }

      Object.assign(this, markPayloadRaw(msg.parsed));
      Object.assign(this, markPayloadRaw(msg.indexes));

      // Fresh data: show vulnerabilities + their VEX edges by default only for a
      // small VEX set, otherwise keep them off. Reset deterministically per load.
      const showVex =
        this.vexRelationships.length > 0 && this.vexRelationships.length < VEX_AUTO_SHOW_MAX;
      this.graphFilters.forEach((f) => {
        if (VEX_FILTER_KEYS.has(f.key)) f.active = showVex;
      });
      // Fresh data: re-enable every lifecycle scope so a previous SBOM's
      // narrowed-to-runtime view doesn't silently hide edges in the new one.
      this.scopeFilters.forEach((f) => (f.active = true));
      this.relationshipScopeFilter = 'all';

      this.views.find((v) => v.id === 'packages').count = this.plainPackages.length;
      this.views.find((v) => v.id === 'ai').count = this.aiPackages.length;
      this.views.find((v) => v.id === 'dataset').count = this.datasetPackages.length;
      this.views.find((v) => v.id === 'files').count = this.files.length;
      this.views.find((v) => v.id === 'hardware').count = this.hardware.length;
      this.views.find((v) => v.id === 'supplychain').count = this.supplyChain.length;
      this.views.find((v) => v.id === 'requirements').count = this.requirements.length;
      this.views.find((v) => v.id === 'licenses').count = this.licenses.length;
      this.views.find((v) => v.id === 'security').count = this.vulnerabilities.length;
      this.views.find((v) => v.id === 'configs').count = this.buildConfigs.length;
      this.views.find((v) => v.id === 'build').count = this.builds.length;
      this.views.find((v) => v.id === 'agents').count = this.agents.length;
      this.expandedClusters = new Set(); // fresh data: start fully collapsed
      this._resetGraphHeat(); // drop a heat lens the new SBOM can't honour
      this.cveDetails = {}; // drop cached CVE fetches from the previous SBOM
      this.impactFocus = null; // drop any Impact-tab focus from the previous SBOM
      this._impactHookOpenId = null;
      this._resetListMemos(); // invalidate the build + vulnerability sort memos for new data
      this._resetSearchMemos(); // and the global-search corpus / results memos
      this._resetQuery(); // and any structured query from the previous SBOM
      this._resetImpactMemos(); // and the impact rankings / blast-radius caches
      // Fresh data: reset the streaming cursors so every list view streams its
      // (new) content on next visit, and kick the one currently shown.
      this._resetStreaming();

      // A share link's target can only be applied now that the data exists.
      if (this._pendingDeepLink) {
        const link = this._pendingDeepLink;
        this._pendingDeepLink = null;
        this.$nextTick(() => this._applyDeepLink(link));
      }

      // Re-render D3 views if currently active (they don't auto-update from
      // Alpine reactivity).
      this.$nextTick(() => {
        if (this.currentView === 'graph') this.renderGraph();
      });
    };

    worker.onerror = (err) => {
      if (latestParseReqId !== reqId) return;
      this.parsing = false;
      this.progressEta = null;
      this.parseError = err.message || 'Worker error';
      console.error('Parser worker error:', this.parseError);
      this.toastMsg = 'Parser worker error: ' + this.parseError;
      setTimeout(() => (this.toastMsg = ''), 5000);
    };

    worker.postMessage({
      id: reqId,
      files: files.map((f) => ({ name: f.name, text: f.text }))
    });
  }
};
