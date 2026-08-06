/**
 * The core parse pipeline shared by the worker and the main-thread fallback:
 * merge every file's `@graph` into one array, then build the model and indexes.
 *
 * Files arrive as `{ name, text }` or `{ name, blob }`. A blob is read here
 * rather than by the caller, so the main thread never has to materialize a large
 * string; if it is too big to hold as one JS string (~512 MiB) it is streamed
 * item by item instead (see forEachGraphItem).
 *
 * The worker runs this and structured-clones the result back. That clone
 * duplicates the whole model, so for a very large SBOM (millions of elements) it
 * can exhaust memory; the caller runs this directly on the main thread in that
 * case, trading a brief UI stall for not doubling ~GB of data across the worker
 * boundary.
 *
 * @module parser/parse-files
 */

import { parseGraph, buildRelationshipIndexes, buildFileSourceIndex } from './parser.js';
import { forEachGraphItem } from './stream-graph.js';

// A single JS string tops out near 512 MiB (V8's max string length), so a blob
// at or above this size can't be read into one and JSON.parse-d; it is scanned
// as a byte stream instead. The margin under 512 MiB covers UTF-8 multi-byte
// inflation. Streaming is the slower path, so it is only for what needs it.
export const STREAM_THRESHOLD = 256 * 1024 * 1024;

// Recognizes the formats people most often drop here by mistake, so a wrong
// file fails with a specific message instead of parsing into an empty model:
// without this, any JSON that merely lacks `@graph` (a CycloneDX BOM, an SPDX
// 2.x document, a package-lock.json) would load "successfully" as zero
// elements. Returns the message, or null when the shape looks like SPDX 3.
// A bare top-level array is accepted as the graph itself, matching the parser.
export function unsupportedFormatMessage(data, name) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
  if (data.bomFormat === 'CycloneDX') {
    return `${name} is a CycloneDX BOM, not an SPDX 3 document. Convert it to SPDX 3 JSON-LD first, then load the result.`;
  }
  if (typeof data.spdxVersion === 'string' && data.spdxVersion.startsWith('SPDX-')) {
    return `${name} is an ${data.spdxVersion} document. This tool reads SPDX 3 JSON-LD; convert the file to SPDX 3 first.`;
  }
  if (!Array.isArray(data['@graph'])) {
    return `${name} has no @graph array, so it does not look like an SPDX 3 JSON-LD document.`;
  }
  return null;
}

/**
 * @param {Array<{name:string, text?:string, blob?:Blob}>} files
 * @param {(phase: 'json'|'graph'|'index', value: number) => void} progress
 * @param {(phase: 'graph'|'index', count: number) => Promise<void>} [onPhase]
 *   awaited before each heavy synchronous phase, with the item count so the
 *   caller can size a progress animation and let the bar paint (the worker
 *   leaves it undefined).
 * @returns {Promise<{ parsed: any, indexes: any }>}
 */
export async function parseFiles(files, progress, onPhase) {
  const sizeOf = (f) => (f?.blob ? f.blob.size : f?.text ? f.text.length : 0);
  const totalBytes = (files || []).reduce((sum, f) => sum + sizeOf(f), 0) || 1;
  let bytesDone = 0;
  const mergedGraph = [];

  for (const file of files || []) {
    if (!file) continue;
    if (file.blob && file.blob.size >= STREAM_THRESHOLD) {
      // Too large for one string: stream its @graph, parsing item by item.
      // Throttle progress to ~0.2% steps: a multi-hundred-MB file yields
      // thousands of chunks, and one update each would swamp the listener.
      let lastPosted = -1;
      try {
        await forEachGraphItem(
          file.blob,
          (item) => mergedGraph.push(item),
          (read) => {
            const frac = (bytesDone + read) / totalBytes;
            if (frac - lastPosted >= 0.002) {
              lastPosted = frac;
              progress('json', frac);
            }
          }
        );
      } catch (err) {
        throw new Error(`${file.name}: ${err.message}`);
      }
    } else {
      let data;
      try {
        // Reading the blob here rather than at the call site is the point of
        // accepting one: decoding tens of megabytes into a string is a single
        // uninterruptible task, and this runs in the worker.
        data = JSON.parse(file.blob ? await file.blob.text() : file.text);
      } catch (err) {
        throw new Error(`${file.name}: ${err.message}`);
      }
      const formatError = unsupportedFormatMessage(data, file.name);
      if (formatError) throw new Error(formatError);
      const graph = Array.isArray(data) ? data : data['@graph'];
      graph.forEach((item) => mergedGraph.push(item));
    }
    bytesDone += sizeOf(file);
    progress('json', bytesDone / totalBytes);
  }

  // Structurally valid but empty (an empty @graph, or a streamed file whose
  // @graph never appeared): refuse rather than open an app with every view at
  // zero and nothing to explain why.
  if (mergedGraph.length === 0) {
    const names = (files || [])
      .filter(Boolean)
      .map((f) => f.name)
      .join(', ');
    throw new Error(`No SPDX elements found in ${names || 'the loaded files'}.`);
  }

  if (onPhase) await onPhase('graph', mergedGraph.length);
  const parsed = parseGraph(mergedGraph, (p) => progress('graph', p));
  if (onPhase) await onPhase('index', parsed.relationships.length);
  const indexes = buildRelationshipIndexes(parsed.relationships, (p) => progress('index', p));
  const fileSourceIndex = buildFileSourceIndex(parsed, indexes);

  return { parsed, indexes: { ...indexes, fileSourceIndex } };
}
