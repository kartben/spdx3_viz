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
 *   worker → main: { id, ok: true, parsed, indexes }
 *                  { id, ok: false, error }
 *
 * @module parser.worker
 */

import { parseGraph, buildRelationshipIndexes } from './parser.js';

self.onmessage = (event) => {
  const { id, files } = event.data || {};

  try {
    // Merge every file's @graph array into one (same logic as the old
    // main-thread rebuildFromLoadedFiles), JSON-parsing each file here so the
    // 8 MB+ JSON.parse cost stays off the UI thread too.
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
    });

    const parsed = parseGraph(mergedGraph);
    const indexes = buildRelationshipIndexes(parsed.relationships);

    self.postMessage({ id, ok: true, parsed, indexes });
  } catch (err) {
    self.postMessage({ id, ok: false, error: err && err.message ? err.message : String(err) });
  }
};
