/* The Files dialog: the one place to change what the current document is made
   of. A checked box means "in the document once you apply", so ticking an
   unloaded sample file queues an add and unticking a loaded one queues a
   removal. Everything is staged, then fetched/read/dropped in a single batch so
   a big SBOM is only re-parsed once. */

import { formatBytes, tagLoadedFile, STREAM_THRESHOLD } from './loading.js';

/* Staged local files live here, not in Alpine state: a File put on a reactive
   object comes back as a Proxy, and its native methods (text(), slice()) throw
   on a proxied receiver. State mirrors only the name/size needed to draw them. */
let stagedLocal = [];

// Coarse "when did this land" label for the user's own files, which have no
// sample path to recognise them by. Computed on render, so it only refreshes
// when the dialog reopens; that's precise enough for minutes-to-days ages.
function relativeTime(ts) {
  const seconds = Math.max(0, (Date.now() - ts) / 1000);
  if (seconds < 45) return 'just now';
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  return `${Math.round(hours / 24)} d ago`;
}

export const addFilesMixin = {
  openAddFilesModal() {
    this.addFilesQuery = '';
    this.addFilesStaged = [];
    this.addFilesRemove = [];
    this.addFilesExpanded = {};
    this.addFilesError = '';
    stagedLocal = [];
    this.addFilesLocal = [];
    this.addFilesOpen = true;
    this.$nextTick(() => this.$refs.addFilesSearch?.focus());
  },
  closeAddFilesModal() {
    this.addFilesOpen = false;
  },

  /* The sample list as the dialog draws it: one group per sample, filtered by
     the query. A query matching the sample name keeps all of its files;
     otherwise only the files whose own name matches survive, and a group with
     nothing left drops out.

     `on` is the state a file will be in after Apply, which is what the checkbox
     reflects: loaded and not being removed, or not loaded and staged. */
  get addFilesGroups() {
    const q = this.addFilesQuery.trim().toLowerCase();
    const loadedBySrc = new Map(this.loadedFiles.filter((f) => f.src).map((f) => [f.src, f]));
    const staged = new Set(this.addFilesStaged);
    const removing = new Set(this.addFilesRemove);
    const groups = [];
    for (const s of this.samples) {
      const nameHit = !q || s.name.toLowerCase().includes(q);
      const files = s.files
        .filter((f) => nameHit || f.toLowerCase().includes(q))
        .map((f) => {
          const path = `${s.dir}/${f}`;
          const uid = loadedBySrc.get(path)?.uid ?? null;
          const removed = uid !== null && removing.has(uid);
          return {
            name: f,
            path,
            uid,
            loaded: uid !== null,
            removed,
            on: uid !== null ? !removed : staged.has(path)
          };
        });
      if (!files.length) continue;
      const onCount = files.filter((f) => f.on).length;
      groups.push({
        id: s.id,
        name: s.name,
        icon: s.icon ? `${s.dir}/${s.icon}` : '',
        emoji: s.emoji || '',
        sizeLabel: s.sizeLabel || '',
        fileCount: s.files.length,
        multi: s.files.length > 1,
        files,
        loadedCount: files.filter((f) => f.loaded).length,
        allOn: onCount === files.length,
        someOn: onCount > 0
      });
    }
    return groups;
  },

  // Multi-file groups collapse by default. A search expands everything (the
  // matches are the point), and a sample the document only partly holds opens on
  // its own so the missing files are visible without a click.
  addFilesGroupOpen(g) {
    if (this.addFilesQuery.trim()) return true;
    const explicit = this.addFilesExpanded[g.id];
    if (explicit !== undefined) return explicit;
    return g.loadedCount > 0 && g.loadedCount < g.files.length;
  },
  toggleAddFilesGroup(g) {
    this.addFilesExpanded = { ...this.addFilesExpanded, [g.id]: !this.addFilesGroupOpen(g) };
  },

  // One file row: queues the add or the removal that flips it to the other state.
  toggleAddFilesFile(file) {
    if (file.loaded) {
      this._toggleRemoval(file.uid);
      return;
    }
    this.addFilesStaged = this.addFilesStaged.includes(file.path)
      ? this.addFilesStaged.filter((p) => p !== file.path)
      : [...this.addFilesStaged, file.path];
  },
  // The group checkbox drives every file the group currently shows to the same
  // state: all in, or all out.
  toggleAddFilesGroupAll(g) {
    const turnOn = !g.allOn;
    const paths = new Set(this.addFilesStaged);
    const removing = new Set(this.addFilesRemove);
    for (const f of g.files) {
      if (f.loaded && turnOn) removing.delete(f.uid);
      else if (f.loaded) removing.add(f.uid);
      else if (turnOn) paths.add(f.path);
      else paths.delete(f.path);
    }
    this.addFilesStaged = [...paths];
    this.addFilesRemove = [...removing];
  },
  _toggleRemoval(uid) {
    this.addFilesRemove = this.addFilesRemove.includes(uid)
      ? this.addFilesRemove.filter((u) => u !== uid)
      : [...this.addFilesRemove, uid];
  },

  /* The user's own files: the ones already in the document (with the age that
     tells them apart from the samples) followed by the ones staged this time
     round. `index` addresses stagedLocal for the new ones. */
  get addFilesOwn() {
    const removing = new Set(this.addFilesRemove);
    const loaded = this.loadedFiles
      .filter((f) => !f.src)
      .map((f) => ({
        key: `uid:${f.uid}`,
        uid: f.uid,
        name: f.name,
        sizeLabel: formatBytes(f.size),
        age: relativeTime(f.addedAt),
        isNew: false,
        on: !removing.has(f.uid)
      }));
    const fresh = this.addFilesLocal.map((f, index) => ({
      key: `new:${f.name}:${f.size}`,
      index,
      name: f.name,
      sizeLabel: formatBytes(f.size),
      age: '',
      isNew: true,
      on: true
    }));
    return [...loaded, ...fresh];
  },
  toggleAddFilesOwn(row) {
    if (row.isNew) this.addFilesUnstageLocal(row.index);
    else this._toggleRemoval(row.uid);
  },

  // Local files: dropped or browsed, staged until the user applies.
  addFilesStageLocal(fileList) {
    for (const f of [...fileList]) {
      if (stagedLocal.some((x) => x.name === f.name && x.size === f.size)) continue;
      stagedLocal.push(f);
    }
    this.addFilesLocal = stagedLocal.map((f) => ({ name: f.name, size: f.size }));
  },
  addFilesUnstageLocal(index) {
    stagedLocal.splice(index, 1);
    this.addFilesLocal = stagedLocal.map((f) => ({ name: f.name, size: f.size }));
  },
  addFilesDrop(e) {
    e.target.closest?.('.drop-zone')?.classList.remove('drag-over');
    const files = [...(e.dataTransfer.files || [])];
    if (files.length) this.addFilesStageLocal(files);
  },
  addFilesBrowse(e) {
    const files = [...(e.target.files || [])];
    if (files.length) this.addFilesStageLocal(files);
    e.target.value = ''; // reset so the same file can be picked again
  },

  get addFilesAddCount() {
    return this.addFilesStaged.length + this.addFilesLocal.length;
  },
  get addFilesRemoveCount() {
    return this.addFilesRemove.length;
  },
  // How many files the document would hold after applying. Zero is refused: it
  // would silently unload the document from a dialog about editing it.
  get addFilesResultCount() {
    return this.loadedFiles.length - this.addFilesRemoveCount + this.addFilesAddCount;
  },
  get addFilesCanApply() {
    return (
      (this.addFilesAddCount > 0 || this.addFilesRemoveCount > 0) && this.addFilesResultCount > 0
    );
  },
  get addFilesStatus() {
    if (this.addFilesResultCount === 0) return 'At least one file must stay loaded';
    const parts = [];
    if (this.addFilesAddCount) parts.push(`${this.addFilesAddCount} to add`);
    if (this.addFilesRemoveCount) parts.push(`${this.addFilesRemoveCount} to remove`);
    return parts.length ? parts.join(' · ') : 'No changes yet';
  },
  get addFilesApplyLabel() {
    const adds = this.addFilesAddCount;
    const removes = this.addFilesRemoveCount;
    if (adds && removes) return 'Apply changes';
    if (removes) return `Remove ${removes} file${removes === 1 ? '' : 's'}`;
    if (adds) return `Add ${adds} file${adds === 1 ? '' : 's'}`;
    return 'Apply';
  },

  // Fetch the staged sample files, read the staged local ones, drop whatever was
  // unchecked, and re-parse once. Reuses the load overlay so a large sample still
  // shows download + parse progress, which is why the dialog closes before the
  // download rather than after: it sits above the overlay.
  //
  // A failed fetch aborts the whole batch, so a half-applied set never reaches
  // the parser, and reopens the dialog on the untouched staging with the error
  // shown. Nothing is cleared until the batch is known to be good, so the user
  // can retry or drop the offending pick instead of rebuilding the selection.
  async confirmAddFiles() {
    if (!this.addFilesCanApply) return;
    const paths = [...this.addFilesStaged];
    const locals = stagedLocal.slice();
    const removing = new Set(this.addFilesRemove);
    const kept = this.loadedFiles.filter((f) => !removing.has(f.uid));
    this.addFilesOpen = false;
    this.addFilesError = '';

    const added = [];
    if (paths.length || locals.length) {
      this._beginParseSession();
      this.progressPhase = 'Downloading…';
      const total = paths.length + locals.length;
      try {
        for (const path of paths) {
          const name = path.slice(path.lastIndexOf('/') + 1);
          const res = await fetch(path);
          if (!res.ok) throw new Error(`${name} (HTTP ${res.status})`);
          const result = await this._readResponseWithProgress(res, added.length, total);
          added.push(
            tagLoadedFile(
              typeof result === 'string'
                ? { name, text: result, src: path }
                : { name, blob: result, src: path, size: result.size }
            )
          );
        }
        for (const file of locals) {
          // Files too big for one JS string are kept as their Blob and
          // stream-parsed in the worker (see STREAM_THRESHOLD).
          if (file.size >= STREAM_THRESHOLD) {
            added.push(tagLoadedFile({ name: file.name, blob: file, size: file.size }));
          } else {
            const text = await file.text();
            added.push(tagLoadedFile({ name: file.name, text, size: file.size }));
          }
          this._setProgress('download', added.length / total);
        }
      } catch (err) {
        this.parsing = false;
        this.progressEta = null;
        this.addFilesError = `Could not add files: ${err.message}`;
        this.addFilesOpen = true; // staging survived: let the user retry
        return;
      }
    }

    stagedLocal = [];
    this.addFilesLocal = [];
    this.addFilesStaged = [];
    this.addFilesRemove = [];
    this.applyLoadedFiles([...kept, ...added]);
  }
};
