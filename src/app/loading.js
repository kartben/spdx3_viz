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

/* Every loaded file gets a process-unique id. Names collide across samples
   (zephyr/app.jsonld vs zephyr-experimental/app.jsonld) and indexes shift as
   files come and go, so the Files dialog identifies a loaded file by its uid. */
let fileUidSeq = 0;

// Stamps a freshly loaded {name, text, src?} with its uid and load time. The
// timestamp is what the Files dialog shows next to a user's own files, which
// carry no sample path to identify them by.
export function tagLoadedFile(file) {
  return { ...file, uid: ++fileUidSeq, addedAt: Date.now() };
}

// A single JS string tops out near 512 MiB (V8's max string length), so a file
// at or above this size can't be read into one string + JSON.parse-d. Such
// files are kept as their Blob and stream-parsed in the worker instead. The
// margin under 512 MiB covers UTF-8 multi-byte inflation. Large files carry no
// `text`, so the Raw JSON-LD view shows them as download-only.
export const STREAM_THRESHOLD = 256 * 1024 * 1024;

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
export function formatBytes(bytes) {
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
  // True once any of the user's own files is merged in, which the header chip
  // flags: from the parsed data alone there is no telling a sample apart from
  // something the user dropped on top of it.
  get hasOwnLoadedFiles() {
    return this.loadedFiles.some((f) => !f.src);
  },
  // The header chip's tooltip: every loaded file, the user's own ones marked.
  get loadedFilesTooltip() {
    const names = this.loadedFiles.map((f) => (f.src ? f.name : `${f.name} (your file)`));
    return `${names.join('\n')}\n\nClick to view the raw JSON-LD`;
  },

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
        const path = `${sample.dir}/${fname}`;
        const res = await fetch(path);
        if (!res.ok) throw new Error(`${fname} (HTTP ${res.status})`);
        // The manifest size is the uncompressed total; use it as the download
        // denominator (see _readResponseWithProgress). Split evenly when a
        // sample has several files (per-file sizes aren't in the manifest).
        const expectedSize = sample.size ? sample.size / sample.files.length : 0;
        const result = await this._readResponseWithProgress(res, i, total, expectedSize);
        loaded.push(
          tagLoadedFile(
            typeof result === 'string'
              ? { name: fname, text: result, src: path }
              : { name: fname, blob: result, src: path, size: result.size }
          )
        );
      }
      this.loadedFiles = loaded; // replace: the drop zone starts empty
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
  // Falls back to a plain read when the body/total size isn't available.
  // Returns a string for normal files, or the raw Blob for ones too big to hold
  // as one JS string (see STREAM_THRESHOLD); callers await it and branch on the
  // type. Awaiting a Blob is a no-op, so the two shapes unify at the call site.
  //
  // `expectedSize` is the file's uncompressed size (from the manifest). Prefer
  // it over Content-Length: hosts like GitHub Pages gzip large files, so
  // Content-Length is the *compressed* size (~72 MB for the 988 MB Yocto SBOM)
  // while the body reader yields decompressed bytes, which would peg the bar at
  // 100% after ~7% of the real download and then look stuck.
  async _readResponseWithProgress(res, fileIndex, totalFiles, expectedSize = 0) {
    const total = expectedSize || Number(res.headers.get('Content-Length')) || 0;
    if (!res.body || !total) {
      const blob = await res.blob();
      this._setProgress('download', (fileIndex + 1) / totalFiles);
      return blob.size >= STREAM_THRESHOLD ? blob : blob.text();
    }
    const reader = res.body.getReader();
    const chunks = [];
    let received = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      received += value.length;
      this._setProgress('download', (fileIndex + Math.min(1, received / total)) / totalFiles);
    }
    const blob = new Blob(chunks);
    return blob.size >= STREAM_THRESHOLD ? blob : blob.text();
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
  // A share link replays a sample by id, so the URL is only honest while the
  // loaded set is exactly one sample's files. Recomputed after every add/remove
  // rather than latched, so dropping an extra file un-shares the session and
  // removing it again restores the link.
  _recomputeLoadedSampleId() {
    const srcs = this.loadedFiles.map((f) => f.src);
    // An empty document matches no sample: `[].every()` is true, so without the
    // length check a zero-file sample would claim it.
    this.loadedSampleId =
      srcs.length > 0 && srcs.every(Boolean)
        ? (this.samples.find(
            (s) =>
              s.files.length === srcs.length && s.files.every((f) => srcs.includes(`${s.dir}/${f}`))
          )?.id ?? null)
        : null;
  },
  readFiles(fileList) {
    this.loadedSampleId = null; // user files (even added to a sample) aren't linkable
    this._beginParseSession(); // show the overlay during file reads too
    this.progressPhase = 'Reading files…';
    const total = fileList.length;
    const loaded = new Array(total); // preserve input order
    const fileProgress = new Array(total).fill(0);
    let remaining = total;
    const finishOne = () => {
      remaining--;
      if (remaining === 0) {
        loaded.forEach((f) => this.loadedFiles.push(f));
        this.rebuildFromLoadedFiles(); // session continues into the worker
        this.dataLoaded = true;
      }
    };
    fileList.forEach((file, i) => {
      // Too big to hold as one string: keep the Blob and let the worker stream
      // it. No FileReader read, so it contributes its full weight to the bar at
      // once (the real cost is the worker's streamed json phase).
      if (file.size >= STREAM_THRESHOLD) {
        loaded[i] = tagLoadedFile({ name: file.name, blob: file, size: file.size });
        fileProgress[i] = 1;
        this._setProgress('download', fileProgress.reduce((a, b) => a + b, 0) / total);
        finishOne();
        return;
      }
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
        loaded[i] = tagLoadedFile({ name: file.name, text: ev.target.result, size: file.size });
        fileProgress[i] = 1;
        finishOne();
      };
      reader.readAsText(file);
    });
  },
  // Swaps in a new loaded set (the Files dialog's add + remove result) and
  // re-parses. An empty set means everything was removed, which is the same
  // state as never having loaded anything.
  applyLoadedFiles(files) {
    this.loadedFiles = files;
    this._recomputeLoadedSampleId();
    if (files.length === 0) {
      this.dataLoaded = false;
      return;
    }
    // Keep the Raw view's selected file in range after a removal.
    if (this.rawActiveFile >= files.length) this.rawActiveFile = 0;
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
    this.progressAnimateMs = 150; // snappy transitions for the frequent phases
    this._progressMark = null; // last {t, p} used to measure the rate
    this._progressRate = null; // smoothed bar-fraction/second of recent progress
  },

  // Maps a phase + within-phase fraction (0..1) onto the overall bar and
  // updates the ETA. The estimate uses a smoothed *recent* progress rate, not
  // the average since the start: the phases move at very different speeds (a
  // streamed file's download is instant, then parsing crawls), so an
  // average-since-start ETA is anchored to the fast early phases and reads far
  // too low. A recent-rate estimate re-converges within a second or two.
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

    const now = performance.now();
    const p = this.progress;
    const mark = this._progressMark;
    if (!mark) {
      this._progressMark = { t: now, p };
    } else if (p > mark.p && now - mark.t >= 50) {
      // Measure over >=50ms windows so bursts of near-instant updates can't
      // spike the rate; stalls fold in naturally (the window just grows).
      const inst = (p - mark.p) / ((now - mark.t) / 1000);
      this._progressRate =
        this._progressRate == null ? inst : this._progressRate * 0.6 + inst * 0.4;
      this._progressMark = { t: now, p };
    }
    if (this._progressRate > 0 && p > 0.02 && p < 0.985) {
      this.progressEta = (1 - p) / this._progressRate;
    } else if (p >= 0.985) {
      this.progressEta = null;
    }
  },

  // Merge all loaded files and re-parse (off the main thread)
  rebuildFromLoadedFiles() {
    this.parseData(this.loadedFiles);
  },

  // Parse the loaded files, then apply the result. Normally this runs in
  // parser.worker.js so the UI never freezes on large SBOMs. But a file too big
  // to hold as one JS string arrives as a Blob, and the model it parses into can
  // be too big to structured-clone back out of the worker (it OOMs on
  // postMessage). Those we parse on the main thread instead: a brief stall, but
  // no doubling of ~GB of data across the worker boundary.
  parseData(files) {
    const reqId = ++parseReqSeq;
    latestParseReqId = reqId;
    if (!this.parsing) this._beginParseSession(); // re-parse path (no download)

    if (files.some((f) => f.blob)) {
      this._parseOnMainThread(files, reqId);
      return;
    }

    const worker = getParserWorker();
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
        this._onParseError(msg.error);
        return;
      }

      this._applyParsedResult(msg.parsed, msg.indexes);
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
      files: files.map((f) => ({ name: f.name, text: f.text, blob: f.blob }))
    });
  },

  // Parse on the main thread (see parseData). Used for blob-backed files whose
  // result can't be cloned out of the worker. The streaming (json) phase yields
  // periodically so the progress bar animates from real byte progress. The graph
  // and index phases each run as one synchronous block that would freeze the
  // bar, so instead of reporting their (unpaintable) fractions we hand the bar a
  // compositor-driven sweep toward the phase's end over roughly its expected
  // duration, started just before the block via onPhase. A brief stall on those
  // is the accepted cost of loading a multi-hundred-MB SBOM without a worker.
  async _parseOnMainThread(files, reqId) {
    // Two rAFs guarantee a committed, painted frame, so the progress bar's
    // transform transition is handed to the compositor before the next
    // synchronous phase blocks the main thread (a bare setTimeout may not have
    // produced a frame yet, leaving the bar frozen).
    const yieldToPaint = () =>
      new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    await yieldToPaint(); // let the overlay paint before any blocking work
    try {
      const { parseFiles } = await import('../parser/parse-files.js');
      const { parsed, indexes } = await parseFiles(
        files,
        // Only the streaming (json) phase reports fractions; its yields let them
        // paint. Graph/index fractions can't paint (the thread is blocked), so
        // the sweep set up in onPhase drives the bar instead.
        (phase, value) => {
          if (reqId === latestParseReqId && phase === 'json') this._setProgress(phase, value);
        },
        (phase, count) => this._beginParsePhaseSweep(phase, count, yieldToPaint)
      );
      if (reqId !== latestParseReqId) return; // superseded

      // Applying the result and Alpine's first dashboard render is itself a
      // synchronous block (hundreds of ms to a couple of seconds on a huge
      // SBOM). Sweep the bar across the reserved tail (0.90 → 0.99) while it
      // runs, and only complete + hide the overlay once that render has painted
      // (nextTick) so the bar never freezes at 99%.
      this.progressPhase = 'Finalizing…';
      this.progressEta = null;
      this.progressAnimateMs = this._estParsePhaseMs('finalize', parsed?.elementMap?.size || 0);
      this.progress = 0.99;
      await yieldToPaint(); // commit the tail sweep before the render blocks
      this._applyParsedResult(parsed, indexes);
      this.$nextTick(() => {
        this.progressAnimateMs = 150;
        this.progress = 1;
        this.parsing = false;
      });
    } catch (err) {
      if (reqId !== latestParseReqId) return;
      this.parsing = false;
      this.progressEta = null;
      this._onParseError(err && err.message ? err.message : String(err));
    }
  },

  // Rough per-phase duration estimate (ms) from item count, used only to size
  // the bar's sweep. Overshooting parks the bar near the phase end with the
  // sheen still moving; undershooting completes early and snaps forward.
  _estParsePhaseMs(phase, count) {
    const perItem = phase === 'graph' ? 0.0024 : phase === 'index' ? 0.003 : 0.0013;
    return Math.min(15000, Math.max(500, Math.round(count * perItem)));
  },

  // Sets the progress bar sweeping toward a phase's end over roughly how long
  // that phase will block, then yields once so the transition starts painting
  // before the synchronous work begins.
  async _beginParsePhaseSweep(phase, count, yieldToPaint) {
    const spec =
      phase === 'graph'
        ? { target: 0.75, label: 'Building graph…' }
        : { target: 0.9, label: 'Indexing relationships…' };
    const estMs = this._estParsePhaseMs(phase, count);
    this.progressPhase = spec.label;
    this.progressEta = estMs / 1000;
    this.progressAnimateMs = estMs;
    this.progress = spec.target;
    await yieldToPaint(); // start the transition before the block monopolizes the thread
  },

  _onParseError(error) {
    this.parseError = error || 'Failed to parse SBOM';
    console.error('SBOM parse failed:', this.parseError);
    this.toastMsg = 'Error parsing SBOM: ' + this.parseError;
    setTimeout(() => (this.toastMsg = ''), 5000);
  },

  // Applies a freshly parsed model + indexes to component state and resets all
  // the per-SBOM view state. Shared by the worker and main-thread parse paths.
  _applyParsedResult(parsed, indexes) {
    Object.assign(this, markPayloadRaw(parsed));
    Object.assign(this, markPayloadRaw(indexes));

    {
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
      this.views.find((v) => v.id === 'remediation').count = this.remediationFindings.length;
      this.requirementSearch = '';
      this.requirementKindFilter = '';
      this.requirementStatusFilter = '';
      this.requirementSpecFilter = '';
      this.collapsedReqs = {};
      // Prefer Decomposition when the SBOM has tracedToDetail hierarchy.
      this.requirementLayout = this.hasSafetyDecomposition ? 'tree' : 'list';
      this.remediationCategoryFilter = '';
      this.remediationSeverityFilter = '';
      this.expandedClusters = new Set(); // fresh data: start fully collapsed
      this._resetGraphHeat(); // drop a heat lens the new SBOM can't honour
      this.cveDetails = {}; // drop cached CVE fetches from the previous SBOM
      this.resetOnlineSync(); // drop OSV online findings from the previous SBOM
      // If the CVE affected-files bundle is already loaded, link this SBOM's CVEs
      // to its files right away (resetOnlineSync cleared the previous edges).
      if (this.cveAffectedBundleStatus === 'done') this._rebuildAffectedFileLinks();
      this.impactFocus = null; // drop any Impact-tab focus from the previous SBOM
      this.impactSearch = '';
      this._impactHookOpenId = null;
      this._resetListMemos(); // invalidate the build + vulnerability sort memos for new data
      this._resetSearchMemos(); // and the global-search corpus / results memos
      this._resetImpactMemos(); // and the impact ranking / blast-radius caches
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
    }
  }
};
