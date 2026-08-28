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
 *   …or, for a model too big to clone back in one piece:
 *                  { id, type: 'chunkBegin', elements, chunks }
 *                  { id, type: 'chunk', entries }               // elementMap, in slices
 *                  { id, type: 'part', scope, key, kind, data } // the rest, elements as ids
 *                  { id, type: 'chunkEnd' }
 *
 * A file too big to hold as one JS string (~512 MiB) arrives as a `blob` and is
 * stream-parsed a chunk at a time instead of JSON.parse-d whole; small files
 * still arrive as `text`. A postMessage that outright OOMs the worker surfaces
 * as the worker's error event, and the caller falls back to the main thread.
 * See parseData.
 *
 * @module parser.worker
 */

import { parseFiles } from './parse-files.js';
import { chunkEntries, encodeRefs } from './transfer.js';

// Elements per chunk when the model is handed over in pieces. Tuned on the
// 988 MB Yocto sample: the cost per element is flat across a wide range, so the
// size is chosen for the pause it costs the main thread to take one chunk in,
// not for throughput.
const CHUNK_SIZE = 25000;
const CHUNK_ABOVE_ELEMENTS = 400000;
// Entries per message for the collections that follow the elements.
const PART_SIZE = 50000;

self.onmessage = async (event) => {
  const { id, files } = event.data || {};
  const post = (msg) => self.postMessage({ id, ...msg });

  try {
    const { parsed, indexes } = await parseFiles(files, (phase, value) =>
      post({ type: 'progress', phase, value })
    );
    // Above this many elements the one-piece hand-over is not worth attempting:
    // it runs the worker out of memory on the way out, and the failure costs a
    // full serialization pass before it reports. Below it, one clone is both
    // faster and simpler than chunking.
    if ((parsed?.elementMap?.size || 0) >= CHUNK_ABOVE_ELEMENTS) {
      postChunked(post, parsed, indexes);
      return;
    }
    try {
      post({ type: 'done', ok: true, parsed, indexes });
    } catch {
      // Too big to hand over in one piece. Send the elements as chunks and the
      // rest with references to them replaced by markers; see parser/transfer.
      try {
        postChunked(post, parsed, indexes);
      } catch (err) {
        post({ type: 'done', ok: false, tooBig: true, chunkError: String(err?.message || err) });
      }
    }
  } catch (err) {
    post({ type: 'done', ok: false, error: err && err.message ? err.message : String(err) });
  }
};

/**
 * Hands the model over in pieces.
 *
 * The elements go first, as chunks of `elementMap`. Everything else follows
 * key by key with its elements replaced by markers — and a key that is itself
 * large (a million-element SBOM has ~650k relationships and ~650k files) is
 * split again, because the collected remainder is over the clone limit on its
 * own even once the elements in it are just ids.
 */
function postChunked(post, parsed, indexes) {
  const elementMap = parsed.elementMap;
  const chunkCount = Math.ceil(elementMap.size / CHUNK_SIZE);
  post({ type: 'chunkBegin', elements: elementMap.size, chunks: chunkCount });
  for (const entries of chunkEntries(elementMap, CHUNK_SIZE)) post({ type: 'chunk', entries });

  // elementMap travelled as chunks, so it is dropped from the rest.
  const { elementMap: _sent, ...restOfParsed } = parsed;
  postParts(post, 'parsed', restOfParsed, elementMap);
  postParts(post, 'indexes', indexes, elementMap);
  post({ type: 'chunkEnd' });
}

/**
 * Sends one collection's keys, splitting any that is too large to go at once.
 *
 * Each slice is encoded as it is sent, not encoded whole and then sliced: a key
 * like `files` holds ~650k elements, and walking all of them before the first
 * message goes out leaves the main thread with nothing to do for seconds.
 */
function postParts(post, scope, source, elementMap) {
  for (const key of Object.keys(source)) {
    const value = source[key];

    if (Array.isArray(value) && value.length > PART_SIZE) {
      for (let i = 0; i < value.length; i += PART_SIZE) {
        const slice = value.slice(i, i + PART_SIZE);
        post({ type: 'part', scope, key, kind: 'array', data: encodeRefs(slice, elementMap) });
      }
      continue;
    }
    if (value instanceof Map && value.size > PART_SIZE) {
      for (const entries of chunkEntries(value, PART_SIZE)) {
        const data = entries.map(([k, v]) => [k, encodeRefs(v, elementMap)]);
        post({ type: 'part', scope, key, kind: 'map', data });
      }
      continue;
    }
    post({ type: 'part', scope, key, kind: 'whole', data: encodeRefs(value, elementMap) });
  }
}
