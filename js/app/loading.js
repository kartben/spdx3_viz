/* ==========================================================================
   File loading + parse orchestration
   Reading dropped/picked files and bundled samples, driving the progress bar,
   and applying the worker's parsed result to the component state.
   ========================================================================== */

/* Parser worker
   A single long-lived worker, kept off the Alpine reactive state so it is
   never proxied. Parsing large SBOMs (JSON.parse + index building) runs here
   so the main thread stays responsive. latestParseReqId lets us ignore stale
   results when the user loads a second SBOM before the first finishes. */
let parserWorker = null;
let parseReqSeq = 0;
let latestParseReqId = 0;

function getParserWorker() {
  if (!parserWorker) {
    parserWorker = new Worker(new URL('../parser.worker.js', import.meta.url), { type: 'module' });
  }
  return parserWorker;
}

/* Marks an object so Alpine's (Vue) reactivity leaves it untouched. The parsed
   SBOM is large (the Linux kernel set is ~8k elements / ~3.9k relationships)
   and fully immutable after parsing, so deep-proxying it just adds per-access
   overhead to every render. `__v_skip` is the flag @vue/reactivity checks to
   skip an object; we set it non-enumerable so it never leaks into iteration. */
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

// Human-readable size for a byte count (e.g. 1536 → "1.5 KB"). Returns '' for
// anything that isn't a positive, finite number so callers can skip the label.
function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '';
  const units = ['B', 'KB', 'MB', 'GB'];
  let n = bytes;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
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
        this.samples = await res.json();
        this._fetchSampleSizes(); // fill in each card's download size in the background
      }
    } catch {
      /* demos just won't show if the manifest is missing */
    }
  },

  // HEAD each sample's file(s) to sum their download size, then surface a
  // human-readable label on the card. Runs after the manifest loads; a failed
  // request (or a server that omits Content-Length) just leaves the size unset.
  async _fetchSampleSizes() {
    await Promise.all(
      this.samples.map(async (sample) => {
        try {
          const sizes = await Promise.all(
            sample.files.map(async (fname) => {
              const res = await fetch(`${sample.dir}/${fname}`, { method: 'HEAD' });
              return res.ok ? Number(res.headers.get('Content-Length')) : NaN;
            })
          );
          const total = sizes.reduce((sum, n) => sum + n, 0);
          if (Number.isFinite(total) && total > 0) {
            sample.size = total;
            sample.sizeLabel = formatBytes(total);
          }
        } catch {
          /* leave the size unset if a HEAD request fails */
        }
      })
    );
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
    this.loadedFiles.splice(index, 1);
    if (this.loadedFiles.length === 0) {
      this.dataLoaded = false;
      return;
    }
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

      this.views.find((v) => v.id === 'packages').count = this.packages.length;
      this.views.find((v) => v.id === 'files').count = this.files.length;
      this.views.find((v) => v.id === 'licenses').count = this.licenses.length;
      this.views.find((v) => v.id === 'security').count = this.vulnerabilities.length;
      this.views.find((v) => v.id === 'configs').count = this.buildConfigs.length;
      this.views.find((v) => v.id === 'build').count = this.builds.length;
      this.expandedClusters = new Set(); // fresh data: start fully collapsed
      this.cveDetails = {}; // drop cached CVE fetches from the previous SBOM
      this._resetListMemos(); // invalidate the build + vulnerability sort memos for new data
      // Fresh data: reset the streaming cursors so every list view streams its
      // (new) content on next visit, and kick the one currently shown.
      this._resetStreaming();

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
