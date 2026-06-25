/**
 * SPDX 3.0 SBOM Visualizer - Parser Web Worker
 *
 * Runs the expensive parse off the main thread so the UI never freezes while
 * loading large SBOMs (e.g. the Linux kernel: ~8.6 MB / ~8k elements).
 *
 * It reuses the exact same pure functions the app uses on the main thread
 * (parseGraph + buildRelationshipIndexes from parser.js), so there is a single
 * source of truth for parsing. JS Map/Set survive postMessage via structured
 * clone, so the element map and relationship indexes transfer back as-is.
 *
 * Protocol:
 *   main → worker: { id, files: [{ name, text }] }
 *   worker → main: { id, type: 'progress', phase, value }   // 0..1 within phase
 *                  { id, type: 'done', ok: true, parsed, indexes }
 *                  { id, type: 'done', ok: false, error }
 *
 * @module parser.worker
 */

import { parseGraph, buildRelationshipIndexes } from './parser.js';

self.onmessage = (event) => {
  const { id, files } = event.data || {};
  const post = (msg) => self.postMessage({ id, ...msg });
  const progress = (phase, value) => post({ type: 'progress', phase, value });

  try {
    // Merge every file's @graph array into one (same logic as the old
    // main-thread rebuildFromLoadedFiles), JSON-parsing each file here so the
    // 8 MB+ JSON.parse cost stays off the UI thread too. Report JSON progress
    // weighted by byte size so the bar advances as each file is parsed.
    const totalBytes = (files || []).reduce((sum, f) => sum + (f.text ? f.text.length : 0), 0) || 1;
    let bytesDone = 0;
    const mergedGraph = [];
    (files || []).forEach((file) => {
      let data;
      try {
        data = JSON.parse(file.text);
      } catch (err) {
        throw new Error(`${file.name}: ${err.message}`);
      }
      const graph = data['@graph'] || [];
      graph.forEach((item) => mergedGraph.push(item));
      bytesDone += file.text ? file.text.length : 0;
      progress('json', bytesDone / totalBytes);
    });

    const parsed = parseGraph(mergedGraph, (p) => progress('graph', p));
    const indexes = buildRelationshipIndexes(parsed.relationships, (p) => progress('index', p));

    post({ type: 'done', ok: true, parsed, indexes });
  } catch (err) {
    post({ type: 'done', ok: false, error: err && err.message ? err.message : String(err) });
  }
};
