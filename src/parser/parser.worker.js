/**
 * Runs the parse off the main thread so the UI stays responsive on large SBOMs.
 *
 * Reuses the same pure functions as the main thread (parseGraph +
 * buildRelationshipIndexes) for a single source of truth; Map/Set survive
 * postMessage via structured clone.
 *
 * Protocol:
 *   main → worker: { id, files: [{ name, text }] }
 *   worker → main: { id, type: 'progress', phase, value }   // 0..1 within phase
 *                  { id, type: 'done', ok: true, parsed, indexes }
 *                  { id, type: 'done', ok: false, error }
 *
 * @module parser.worker
 */

import { parseGraph, buildRelationshipIndexes, buildFileSourceIndex } from './parser.js';

self.onmessage = (event) => {
  const { id, files } = event.data || {};
  const post = (msg) => self.postMessage({ id, ...msg });
  const progress = (phase, value) => post({ type: 'progress', phase, value });

  try {
    // Merge every file's @graph array into one, JSON-parsing each file here so
    // that cost stays off the UI thread. Progress is weighted by byte size.
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
    const fileSourceIndex = buildFileSourceIndex(parsed, indexes);

    post({ type: 'done', ok: true, parsed, indexes: { ...indexes, fileSourceIndex } });
  } catch (err) {
    post({ type: 'done', ok: false, error: err && err.message ? err.message : String(err) });
  }
};
