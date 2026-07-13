/**
 * Runs the parse off the main thread so the UI stays responsive on large SBOMs.
 *
 * Shares the core pipeline (parseFiles) with the main-thread fallback for a
 * single source of truth; Map/Set survive postMessage via structured clone.
 *
 * Protocol:
 *   main → worker: { id, files: [{ name, text }] }        // small files
 *                  { id, files: [{ name, blob }] }         // large files (streamed)
 *   worker → main: { id, type: 'progress', phase, value }   // 0..1 within phase
 *                  { id, type: 'done', ok: true, parsed, indexes }
 *                  { id, type: 'done', ok: false, error }
 *
 * A file too big to hold as one JS string (~512 MiB) arrives as a `blob` and is
 * stream-parsed a chunk at a time instead of JSON.parse-d whole; small files
 * still arrive as `text`. A result too big to structured-clone back is handled
 * by the caller (it re-parses on the main thread); see parseData.
 *
 * @module parser.worker
 */

import { parseFiles } from './parse-files.js';

self.onmessage = async (event) => {
  const { id, files } = event.data || {};
  const post = (msg) => self.postMessage({ id, ...msg });

  try {
    const { parsed, indexes } = await parseFiles(files, (phase, value) =>
      post({ type: 'progress', phase, value })
    );
    post({ type: 'done', ok: true, parsed, indexes });
  } catch (err) {
    post({ type: 'done', ok: false, error: err && err.message ? err.message : String(err) });
  }
};
