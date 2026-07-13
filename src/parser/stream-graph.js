/**
 * Streaming extractor for the `@graph` array of a (potentially huge) SPDX
 * JSON-LD file.
 *
 * A browser/V8 string maxes out at ~512 MiB (536,870,888 code units), so a file
 * bigger than that can never be read into one string and handed to JSON.parse:
 * the read truncates and JSON.parse throws "Unexpected end of JSON input". This
 * reads the file as a byte stream, scans it a chunk at a time, and JSON.parses
 * each top-level `@graph` element on its own (individual nodes are small), so
 * peak memory is one element plus one chunk, never the whole document.
 *
 * Supports both shapes the worker accepts: an object with an `@graph` array, and
 * a bare top-level array (treated as the graph itself).
 *
 * @module parser/stream-graph
 */

// Character codes used by the scanner (charCodeAt beats string compares here).
const QUOTE = 34; // "
const BACKSLASH = 92; // \
const LBRACE = 123; // {
const RBRACE = 125; // }
const LBRACKET = 91; // [
const RBRACKET = 93; // ]
const COLON = 58; // :
const SPACE = 32;
const TAB = 9;
const LF = 10;
const CR = 13;

function isWs(c) {
  return c === SPACE || c === TAB || c === LF || c === CR;
}

// The next character that ends or escapes within a JSON string: a closing quote
// or a backslash. Used to fast-forward through string bodies in one scan that
// stops at the first hit, rather than two indexOf calls (indexOf for an absent
// backslash scans to the buffer end every time, which is quadratic when the
// stream yields large, mostly-string chunks).
const STRING_STOP = /[\\"]/g;

/**
 * Reads `blob`, invoking `onItem(obj)` for every element of its `@graph` array
 * (or of the top-level array). `onProgress(bytesRead)` is called after each
 * chunk with the running byte count so callers can drive a progress bar.
 *
 * @param {Blob} blob
 * @param {(item: any) => void} onItem
 * @param {(bytesRead: number) => void} [onProgress]
 * @returns {Promise<void>}
 */
export async function forEachGraphItem(blob, onItem, onProgress) {
  const reader = blob.stream().getReader();
  const decoder = new TextDecoder();

  // When this runs on the UI thread (large SBOMs parse there, not in the worker,
  // because their result can't be cloned out of it), yield a macrotask every so
  // often so the browser can paint the progress bar instead of freezing for the
  // whole multi-second stream. Time-based so small files never pay for it.
  let lastYield = Date.now();

  let buf = ''; // unconsumed text; kept minimal (see trimming below)
  let pos = 0; // next index in buf to scan (resumes across chunks)
  let bytesRead = 0;

  // Overall phase.
  let entered = false; // inside the graph array, extracting elements
  let rootSeen = false; // seen the first structural char (`{` or `[`)
  let finished = false; // hit the array's closing `]`

  // Seek phase: locate the `@graph` array. We look for the string token
  // `@graph`, then `:`, then `[`. A bare leading `[` means the whole document
  // is the array.
  let seekStr = false; // scanning a string token
  let seekEsc = false; // previous char was a backslash inside that string
  let seekBuf = ''; // that string's content (capped: we only match '@graph')
  let seekMode = 'scan'; // 'scan' | 'afterGraph' | 'afterColon'

  // Capture phase: accumulate one balanced element, then JSON.parse it.
  let capturing = false;
  let capDepth = 0; // brace/bracket nesting within the element
  let capStart = -1; // element's start index within buf
  let capStr = false; // inside a string within the element
  let capEsc = false; // previous char was a backslash inside that string

  const emit = (chunk) => {
    let obj;
    try {
      obj = JSON.parse(chunk);
    } catch (err) {
      throw new Error(`graph item: ${err.message} (near: ${chunk.slice(0, 140)})`);
    }
    onItem(obj);
  };

  for (;;) {
    const { value, done } = await reader.read();
    if (value && value.length) {
      buf += decoder.decode(value, { stream: true });
      bytesRead += value.length;
      if (onProgress) onProgress(bytesRead);
    }
    // Flush any bytes the decoder is holding for a multi-byte char that ended
    // exactly at the stream's end, so trailing content isn't dropped.
    if (done) buf += decoder.decode();

    const n = buf.length;
    while (pos < n) {
      if (!entered) {
        // ---- SEEK: find the @graph array ----
        const c = buf.charCodeAt(pos);
        if (seekStr) {
          if (seekEsc) {
            seekEsc = false;
            if (seekBuf.length < 8) seekBuf += buf[pos];
          } else if (c === BACKSLASH) {
            seekEsc = true;
          } else if (c === QUOTE) {
            seekStr = false;
            seekMode = seekBuf === '@graph' ? 'afterGraph' : 'scan';
          } else if (seekBuf.length < 8) {
            seekBuf += buf[pos];
          }
          pos++;
          continue;
        }
        if (c === QUOTE) {
          seekStr = true;
          seekBuf = '';
          pos++;
          continue;
        }
        if (isWs(c)) {
          pos++;
          continue;
        }
        if (c === LBRACKET) {
          // Either the @graph array's `[`, or (before any `{`) a root-level
          // array that is itself the graph.
          if (seekMode === 'afterColon' || !rootSeen) entered = true;
          rootSeen = true;
          pos++;
          continue;
        }
        if (c === LBRACE) {
          rootSeen = true;
          seekMode = 'scan';
          pos++;
          continue;
        }
        if (c === COLON) {
          seekMode = seekMode === 'afterGraph' ? 'afterColon' : 'scan';
          pos++;
          continue;
        }
        // Any other non-ws char breaks a pending @graph match.
        seekMode = 'scan';
        pos++;
        continue;
      }

      // ---- ARRAY: extract elements ----
      if (capturing) {
        if (capStr) {
          // Fast-forward through string contents to the next quote/backslash in
          // a single scan (see STRING_STOP).
          if (capEsc) {
            capEsc = false;
            pos++;
            continue;
          }
          STRING_STOP.lastIndex = pos;
          const m = STRING_STOP.exec(buf);
          if (!m) {
            pos = n; // string continues past this chunk
            break;
          }
          if (m[0] === '\\') {
            capEsc = true;
            pos = m.index + 1;
            continue;
          }
          capStr = false; // closing quote
          pos = m.index + 1;
          continue;
        }
        const c = buf.charCodeAt(pos);
        if (c === QUOTE) {
          capStr = true;
          pos++;
          continue;
        }
        if (c === LBRACE || c === LBRACKET) {
          capDepth++;
          pos++;
          continue;
        }
        if (c === RBRACE || c === RBRACKET) {
          capDepth--;
          pos++;
          if (capDepth === 0) {
            emit(buf.slice(capStart, pos));
            capturing = false;
          }
          continue;
        }
        pos++;
        continue;
      }

      // Between elements: skip ws/commas, start an element, or end the array.
      const c = buf.charCodeAt(pos);
      if (c === RBRACKET) {
        finished = true;
        pos++;
        break;
      }
      if (c === LBRACE || c === LBRACKET) {
        capturing = true;
        capDepth = 1;
        capStart = pos;
        capStr = false;
        capEsc = false;
        pos++;
        continue;
      }
      pos++; // whitespace or comma
    }

    // Trim consumed text. Mid-element we must retain from capStart; otherwise
    // everything scanned so far is safe to drop (seek strings are captured into
    // seekBuf, not buf, so they survive a trim).
    if (capturing) {
      if (capStart > 0) {
        buf = buf.slice(capStart);
        pos -= capStart;
        capStart = 0;
      }
    } else {
      buf = '';
      pos = 0;
    }

    if (finished) break;
    if (done) break;

    if (Date.now() - lastYield >= 64) {
      await new Promise((resolve) => setTimeout(resolve));
      lastYield = Date.now();
    }
  }
}
