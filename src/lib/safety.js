/**
 * Functional Safety display helpers: plain titles, producer metadata
 * (adequacy, evidence, level), evidence targets, and Specification →
 * hasRequirement grouping. Keeps SPDX-native structure readable without
 * producer jargon (adequacy, SYRS/SRS tags, …).
 *
 * @module lib/safety
 */
import { isMeaningfulValue } from './format.js';

const PRODUCER_META_PREFIXES = [
  'status:',
  'requirement-type:',
  'requirement_type:',
  'requirement-level:',
  'component:',
  'adequacy:',
  'evidence:'
];

/**
 * Read a `<prefix>:<value>` producer identifier off an element.
 *
 * @param {Object|null|undefined} el
 * @param {string} prefix - without the colon, e.g. 'adequacy'
 * @param {(el: Object) => Array<{identifier: string}>} [getIds]
 * @returns {string} the value, or '' when the element carries no such identifier
 */
export function producerMetaValue(el, prefix, getIds) {
  if (!el) return '';
  const ids = typeof getIds === 'function' ? getIds(el) : el.externalIdentifier || [];
  const want = `${prefix}:`;
  for (const id of ids || []) {
    const raw = String(id?.identifier || '').trim();
    if (raw.toLowerCase().startsWith(want)) return raw.slice(want.length).trim();
  }
  return '';
}

/**
 * True when an externalIdentifier value is producer metadata rather than a UID.
 * @param {string} identifier
 * @returns {boolean}
 */
export function isProducerMetaIdentifier(identifier) {
  const s = String(identifier || '')
    .trim()
    .toLowerCase();
  return PRODUCER_META_PREFIXES.some((p) => s.startsWith(p));
}

/**
 * Human title for a requirement: prefer the part after "UID: " when the name
 * already embeds the controlled identifier.
 *
 * @param {Object|null|undefined} el
 * @param {(el: Object) => Array<{identifier: string}>} [getIds]
 * @returns {string}
 */
export function requirementDisplayName(el, getIds) {
  if (!el) return '';
  const raw = (el.name || '').trim();
  if (!raw) return '';
  const m = raw.match(/^([^:]+):\s+(.+)$/);
  if (!m) return raw;
  const prefix = m[1].trim();
  const rest = m[2].trim();
  if (!rest) return raw;

  const uids = [];
  if (isMeaningfulValue(el.requirementUID?.identifier)) {
    uids.push(String(el.requirementUID.identifier).trim());
  }
  const ids = typeof getIds === 'function' ? getIds(el) : [];
  ids.forEach((id) => {
    if (id?.identifier && !isProducerMetaIdentifier(id.identifier)) {
      uids.push(String(id.identifier).trim());
    }
  });
  if (uids.some((u) => u === prefix)) return rest;
  return raw;
}

/**
 * Short label for a Specification facet chip: prefer the human part after "CODE: ".
 * @param {Object|null|undefined} el
 * @returns {string}
 */
export function specificationFacetLabel(el) {
  if (!el) return '';
  const raw = (el.name || '').trim();
  if (!raw) return '';
  const m = raw.match(/^([^:]+):\s+(.+)$/);
  return m ? m[2].trim() || raw : raw;
}

/**
 * Build Specification facets from hasRequirement edges.
 *
 * @param {Array<Object>} relationships
 * @param {Map<string, Object>} elementMap
 * @param {(type: string|undefined, base: string) => boolean} isA
 * @param {string} specificationClass
 * @param {Set<string>} [requirementIds] - when set, only count requirement targets
 * @returns {Array<{id: string, name: string, label: string, count: number, requirementIds: string[]}>}
 */
export function buildSafetySpecFacets(
  relationships,
  elementMap,
  isA,
  specificationClass,
  requirementIds
) {
  /** @type {Map<string, Set<string>>} */
  const members = new Map();
  (relationships || []).forEach((rel) => {
    if (rel?.relationshipType !== 'hasRequirement') return;
    const from = rel.from;
    const fromEl = elementMap?.get(from);
    if (!fromEl || !isA(fromEl.type, specificationClass)) return;
    const tos = Array.isArray(rel.to) ? rel.to : rel.to ? [rel.to] : [];
    let set = members.get(from);
    if (!set) {
      set = new Set();
      members.set(from, set);
    }
    tos.forEach((t) => {
      if (!t) return;
      if (requirementIds && !requirementIds.has(t)) return;
      set.add(t);
    });
  });

  return [...members.entries()]
    .map(([id, set]) => {
      const el = elementMap.get(id);
      const name = el?.name || id;
      return {
        id,
        name,
        label: specificationFacetLabel(el) || name,
        count: set.size,
        requirementIds: [...set]
      };
    })
    .filter((f) => f.count > 0)
    .sort(
      (a, b) => b.count - a.count || a.label.localeCompare(b.label, undefined, { numeric: true })
    );
}
