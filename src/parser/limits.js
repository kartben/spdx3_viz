/**
 * Size limits shared between the parse pipeline and the loading orchestration.
 *
 * A separate module so the main thread can consult them without importing the
 * parser itself: parse-files.js (and everything under it) stays a dynamic
 * import that only loads inside the worker or on the main-thread fallback.
 *
 * @module parser/limits
 */

// A single JS string tops out near 512 MiB (V8's max string length), so a blob
// at or above this size can't be read into one and JSON.parse-d; it is scanned
// as a byte stream instead. The margin under 512 MiB covers UTF-8 multi-byte
// inflation. Streaming is the slower path, so it is only for what needs it.
//
// The same size marks where a parse starts on the main thread rather than in
// the worker: a document this large parses into a model that plausibly cannot
// be structured-cloned back across the worker boundary, and a doomed worker
// attempt would parse everything twice (see parseData).
export const STREAM_THRESHOLD = 256 * 1024 * 1024;
