/**
 * SPDX 3.0 SBOM Visualizer - SPDX model facade
 *
 * Single entry point for the machine-readable SPDX model (class names, property
 * names, subclass hierarchy, enumerated vocabularies). The per-version data in
 * js/generated/ is produced from the official SPDX SHACL/OWL model by
 * scripts/gen-model.mjs (`npm run gen:model`), so the app's SPDX type strings
 * are validated against the spec rather than hand-maintained.
 *
 * The app currently targets SPDX 3.0.1; switch versions by changing the import
 * below (3.1 / 3.1-dev are also generated).
 *
 * @module spdx-model
 */

import {
  SPDX_VERSION,
  SPDX_MODEL_SOURCE,
  CLASSES,
  PROPERTIES,
  SUPERCLASSES,
  VOCABULARIES
} from './generated/spdx-model.3.0.1.js';

export { SPDX_VERSION, SPDX_MODEL_SOURCE, CLASSES, PROPERTIES, SUPERCLASSES, VOCABULARIES };

/**
 * True if `type` equals `ancestor` or transitively derives from it via
 * rdfs:subClassOf. Used to categorize elements by the model hierarchy (e.g. AI
 * and dataset packages, and any future software_Package subclass, count as
 * packages) instead of enumerating subclasses by hand.
 *
 * @param {string} type - Element class name (as it appears as `type`)
 * @param {string} ancestor - Candidate ancestor class name
 * @returns {boolean}
 */
export function isSubclassOf(type, ancestor) {
  if (!type || !ancestor) return false;
  if (type === ancestor) return true;
  const seen = new Set();
  const stack = [type];
  while (stack.length) {
    const current = stack.pop();
    if (seen.has(current)) continue;
    seen.add(current);
    for (const superClass of SUPERCLASSES[current] || []) {
      if (superClass === ancestor) return true;
      stack.push(superClass);
    }
  }
  return false;
}

/**
 * True if `term` is a class defined by the active SPDX model.
 * @param {string} term
 * @returns {boolean}
 */
export const isKnownClass = (term) => CLASSES.has(term);

/**
 * True if `term` is a property defined by the active SPDX model.
 * @param {string} term
 * @returns {boolean}
 */
export const isKnownProperty = (term) => PROPERTIES.has(term);
