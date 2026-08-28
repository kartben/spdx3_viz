/**
 * Moves a parsed model across the worker boundary without cloning it whole.
 *
 * structuredClone preserves shared references, but only within one call: the
 * parsed model is one graph in which `packages`, `files`, `relationships` and
 * several indexes hold the very objects `elementMap` holds, so cloning it in
 * pieces would hand the main thread two or three copies of every element. On a
 * ~1M-element SBOM cloning it whole instead runs the worker out of memory.
 *
 * So the element objects travel once, as chunks of `elementMap` — they carry no
 * references to each other, only id strings, which is what makes chunking them
 * safe — and everything else travels with each element replaced by a marker
 * naming its id. The main thread rebuilds `elementMap` from the chunks and then
 * swaps the markers back for the real objects, restoring the sharing exactly.
 *
 * @module parser/transfer
 */

// A NUL-prefixed marker cannot collide with an id or any other string in the
// model: JSON has no way to produce a NUL in a parsed string here.
const REF_PREFIX = '\u0000#';

/**
 * Replaces every element object with a marker naming its id.
 *
 * @param {*} value Any part of the parsed model.
 * @param {Map} elementMap The model's elements, keyed by id.
 * @returns {*} A copy in which elements are `\0#<id>` markers.
 */
export function encodeRefs(value, elementMap) {
  if (typeof value !== 'object' || value === null) return value;

  const id = value.spdxId;
  if (typeof id === 'string' && elementMap.get(id) === value) return REF_PREFIX + id;

  if (Array.isArray(value)) return value.map((v) => encodeRefs(v, elementMap));
  if (value instanceof Map) {
    const out = new Map();
    for (const [k, v] of value) out.set(k, encodeRefs(v, elementMap));
    return out;
  }
  if (value instanceof Set) {
    const out = new Set();
    for (const v of value) out.add(encodeRefs(v, elementMap));
    return out;
  }
  // Anything with a prototype of its own (Date, RegExp, …) is left alone;
  // structuredClone handles those, and they never hold elements.
  if (Object.getPrototypeOf(value) !== Object.prototype) return value;

  const out = {};
  for (const k in value) out[k] = encodeRefs(value[k], elementMap);
  return out;
}

/**
 * Swaps the markers left by {@link encodeRefs} back for the real elements.
 * Mutates in place: the decoded structure was just cloned in, so nothing else
 * holds it, and rebuilding it again would double the work on a large model.
 *
 * @param {*} value Any part of the decoded payload.
 * @param {Map} elementMap The rebuilt elements, keyed by id.
 * @returns {*} The same structure with markers resolved.
 */
export function decodeRefs(value, elementMap) {
  if (typeof value === 'string') {
    return value.startsWith(REF_PREFIX) ? elementMap.get(value.slice(REF_PREFIX.length)) : value;
  }
  if (typeof value !== 'object' || value === null) return value;

  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) value[i] = decodeRefs(value[i], elementMap);
    return value;
  }
  if (value instanceof Map) {
    for (const [k, v] of value) value.set(k, decodeRefs(v, elementMap));
    return value;
  }
  if (value instanceof Set) {
    const resolved = [...value].map((v) => decodeRefs(v, elementMap));
    value.clear();
    for (const v of resolved) value.add(v);
    return value;
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) return value;

  for (const k in value) value[k] = decodeRefs(value[k], elementMap);
  return value;
}

/**
 * Yields a Map's entries in arrays of at most `size`, each small enough to
 * clone on its own.
 *
 * A generator, not an array of arrays: collecting every chunk first copies the
 * whole map before the first one can be sent, which on a million-element model
 * is seconds of silence at exactly the moment the caller wants to start
 * streaming.
 *
 * @param {Map} map
 * @param {number} size
 * @yields {Array} chunk of `[key, value]` pairs
 */
export function* chunkEntries(map, size) {
  let current = [];
  for (const entry of map) {
    current.push(entry);
    if (current.length >= size) {
      yield current;
      current = [];
    }
  }
  if (current.length) yield current;
}
