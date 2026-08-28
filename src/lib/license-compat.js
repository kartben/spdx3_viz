/**
 * FOSS license compatibility, in the same spirit as flict: OSADL's matrix
 * answers "can a project under outbound include a component under inbound?",
 * and SPDX expressions combine those cells with AND (all) / OR (any).
 *
 * The matrix snapshot lives in `src/data/osadl-matrix.json` (CC-BY-4.0, OSADL).
 * This module does not vendor flict itself (GPL-3.0-or-later).
 *
 * @module lib/license-compat
 */

import {
  licenseIndividualToken,
  licenseExpressionAtomIds,
  normalizeSpdxLicenseId,
  parseLicenseExpression,
  resolveLicenseExpression
} from './licenses.js';
import { isMeaningfulValue } from './format.js';

/** @typedef {import('./licenses.js').LicenseExpressionNode} LicenseExpressionNode */

export const OSADL_MATRIX_SOURCE_URL = 'https://www.osadl.org/fileadmin/checklists/matrix.json';
export const OSADL_CHECKLISTS_URL =
  'https://www.osadl.org/OSADL-Open-Source-License-Checklists.oss-compliance-lists.0.html';
export const OSADL_LICENSE = 'CC-BY-4.0';

/** Pairwise cell / expression-eval status. `same` is the matrix diagonal. */
export const COMPAT_STATUS = {
  YES: 'yes',
  NO: 'no',
  SAME: 'same',
  CHECK: 'check',
  UNKNOWN: 'unknown',
  UNDEF: 'undef'
};

const STATUS_RANK = {
  [COMPAT_STATUS.NO]: 0,
  [COMPAT_STATUS.UNDEF]: 1,
  [COMPAT_STATUS.UNKNOWN]: 2,
  [COMPAT_STATUS.CHECK]: 3,
  [COMPAT_STATUS.YES]: 4,
  [COMPAT_STATUS.SAME]: 4
};

const CELL_STATUS = {
  Yes: COMPAT_STATUS.YES,
  No: COMPAT_STATUS.NO,
  Same: COMPAT_STATUS.SAME,
  Unknown: COMPAT_STATUS.UNKNOWN,
  'Check dependency': COMPAT_STATUS.CHECK
};

export const COMPAT_STATUS_META = {
  [COMPAT_STATUS.YES]: {
    key: COMPAT_STATUS.YES,
    label: 'Compatible',
    short: 'Yes',
    badgeClass: 'bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30',
    cellClass: 'bg-emerald-500/35 text-emerald-100',
    dotClass: 'bg-emerald-400'
  },
  [COMPAT_STATUS.SAME]: {
    key: COMPAT_STATUS.SAME,
    label: 'Same license',
    short: 'Same',
    badgeClass: 'bg-slate-500/20 text-slate-300 ring-1 ring-slate-500/30',
    cellClass: 'bg-slate-600/50 text-slate-200',
    dotClass: 'bg-slate-400'
  },
  [COMPAT_STATUS.NO]: {
    key: COMPAT_STATUS.NO,
    label: 'Incompatible',
    short: 'No',
    badgeClass: 'bg-rose-500/15 text-rose-300 ring-1 ring-rose-500/30',
    cellClass: 'bg-rose-500/40 text-rose-100',
    dotClass: 'bg-rose-400'
  },
  [COMPAT_STATUS.CHECK]: {
    key: COMPAT_STATUS.CHECK,
    label: 'Check dependencies',
    short: 'Check',
    badgeClass: 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30',
    cellClass: 'bg-amber-500/35 text-amber-100',
    dotClass: 'bg-amber-400'
  },
  [COMPAT_STATUS.UNKNOWN]: {
    key: COMPAT_STATUS.UNKNOWN,
    label: 'Unknown',
    short: '?',
    badgeClass: 'bg-slate-600/20 text-slate-300 ring-1 ring-slate-500/30',
    cellClass: 'bg-slate-700/80 text-slate-400',
    dotClass: 'bg-slate-500'
  },
  [COMPAT_STATUS.UNDEF]: {
    key: COMPAT_STATUS.UNDEF,
    label: 'Not in OSADL',
    short: '—',
    badgeClass: 'bg-slate-700/40 text-slate-400 ring-1 ring-slate-600/40',
    cellClass: 'bg-slate-800 text-slate-500',
    dotClass: 'bg-slate-600'
  }
};

export const COMPAT_VERDICT = {
  EMPTY: 'empty',
  INCOMPLETE: 'incomplete',
  COMPATIBLE: 'compatible',
  CONSTRAINED: 'constrained',
  BLOCKED: 'blocked'
};

export const COMPAT_VERDICT_META = {
  [COMPAT_VERDICT.EMPTY]: {
    key: COMPAT_VERDICT.EMPTY,
    label: 'No licenses to check',
    badgeClass: 'bg-slate-600/20 text-slate-300 ring-1 ring-slate-500/30',
    iconClass: 'text-slate-400'
  },
  [COMPAT_VERDICT.INCOMPLETE]: {
    key: COMPAT_VERDICT.INCOMPLETE,
    label: 'Not in the OSADL matrix',
    badgeClass: 'bg-slate-600/20 text-slate-300 ring-1 ring-slate-500/30',
    iconClass: 'text-slate-400'
  },
  [COMPAT_VERDICT.COMPATIBLE]: {
    key: COMPAT_VERDICT.COMPATIBLE,
    label: 'Can be combined',
    badgeClass: 'bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30',
    iconClass: 'text-emerald-400'
  },
  [COMPAT_VERDICT.CONSTRAINED]: {
    key: COMPAT_VERDICT.CONSTRAINED,
    label: 'Outbound license is constrained',
    badgeClass: 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30',
    iconClass: 'text-amber-400'
  },
  [COMPAT_VERDICT.BLOCKED]: {
    key: COMPAT_VERDICT.BLOCKED,
    label: 'No covering outbound license',
    badgeClass: 'bg-rose-500/15 text-rose-300 ring-1 ring-rose-500/30',
    iconClass: 'text-rose-400'
  }
};

/** Above this many distinct licenses, the labeled matrix is skipped. */
export const COMPAT_MATRIX_MAX = 16;

/**
 * @typedef {{ timestamp: string, rows: Record<string, Record<string, string>>, ids: string[] }} OsadlMatrix
 */

/**
 * @param {object} data - Raw OSADL matrix.json object
 * @returns {OsadlMatrix}
 */
export function parseOsadlMatrix(data) {
  const rows = {};
  let timestamp = '';
  if (!data || typeof data !== 'object') {
    return { timestamp, rows, ids: [] };
  }
  for (const [key, value] of Object.entries(data)) {
    if (key === 'timestamp') {
      timestamp = String(value || '');
      continue;
    }
    if (key === 'timeformat' || key === 'Compatibility') continue;
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      rows[key] = value;
    }
  }
  return {
    timestamp,
    rows,
    ids: Object.keys(rows).sort((a, b) => a.localeCompare(b))
  };
}

/**
 * Lazy-loads the bundled OSADL matrix snapshot.
 *
 * @returns {Promise<OsadlMatrix>}
 */
export async function loadOsadlMatrix() {
  const mod = await import('../data/osadl-matrix.json');
  return parseOsadlMatrix(mod.default);
}

/**
 * True when `status` means the outbound may include the inbound.
 *
 * @param {string} status
 * @returns {boolean}
 */
export function isCompatYes(status) {
  return status === COMPAT_STATUS.YES || status === COMPAT_STATUS.SAME;
}

/**
 * @param {string} status
 * @returns {(typeof COMPAT_STATUS_META)[string]}
 */
export function compatStatusMeta(status) {
  return COMPAT_STATUS_META[status] || COMPAT_STATUS_META[COMPAT_STATUS.UNDEF];
}

/**
 * Resolves an SPDX id (or `WITH` pair) onto a matrix row/column key.
 *
 * @param {string} id
 * @param {OsadlMatrix} matrix
 * @returns {string} Matrix key, or '' when unsupported
 */
export function resolveMatrixLicenseId(id, matrix) {
  const raw = String(id || '').trim();
  if (!raw || !matrix?.rows) return '';
  if (matrix.rows[raw]) return raw;
  const normalized = normalizeSpdxLicenseId(raw);
  if (normalized && matrix.rows[normalized]) return normalized;
  if (raw.includes(' WITH ')) {
    const [licenseId, exceptionId] = raw.split(/\s+WITH\s+/);
    const normLicense = normalizeSpdxLicenseId(licenseId) || licenseId;
    const withKey = `${normLicense} WITH ${exceptionId}`;
    if (matrix.rows[withKey]) return withKey;
  }
  if (raw.endsWith('+')) {
    const base = normalizeSpdxLicenseId(raw.slice(0, -1)) || raw.slice(0, -1);
    if (base && matrix.rows[base]) return base;
  }
  return '';
}

/**
 * OSADL cell: can a project under `outbound` include a component under `inbound`?
 *
 * @param {string} outbound
 * @param {string} inbound
 * @param {OsadlMatrix} matrix
 * @returns {string} COMPAT_STATUS value
 */
export function getCompatibility(outbound, inbound, matrix) {
  const outKey = resolveMatrixLicenseId(outbound, matrix);
  const inKey = resolveMatrixLicenseId(inbound, matrix);
  if (!outKey || !inKey) return COMPAT_STATUS.UNDEF;
  if (outKey === inKey) {
    const diag = matrix.rows[outKey]?.[inKey];
    return CELL_STATUS[diag] || COMPAT_STATUS.SAME;
  }
  const raw = matrix.rows[outKey]?.[inKey];
  return CELL_STATUS[raw] || COMPAT_STATUS.UNDEF;
}

/**
 * @param {string} a
 * @param {string} b
 * @returns {string}
 */
function worseStatus(a, b) {
  return (STATUS_RANK[a] ?? 1) <= (STATUS_RANK[b] ?? 1) ? a : b;
}

/**
 * @param {string} a
 * @param {string} b
 * @returns {string}
 */
function betterStatus(a, b) {
  return (STATUS_RANK[a] ?? 1) >= (STATUS_RANK[b] ?? 1) ? a : b;
}

/**
 * Evaluates whether `outbound` can include the inbound expression.
 *
 * AND: every operand must be compatible (worst status).
 * OR: any operand is enough (best status).
 * WITH: prefer the combined matrix key, otherwise fall back to the license
 * with a `check` so an unknown exception is not silently ignored.
 *
 * @param {string} outbound
 * @param {LicenseExpressionNode|null|undefined} node
 * @param {OsadlMatrix} matrix
 * @returns {string}
 */
export function evaluateOutboundAgainst(outbound, node, matrix) {
  if (!node) return COMPAT_STATUS.UNDEF;

  if (node.type === 'id') {
    return getCompatibility(outbound, node.id, matrix);
  }

  if (node.type === 'with') {
    const licenseId = normalizeSpdxLicenseId(node.licenseId) || node.licenseId;
    const withId = `${licenseId} WITH ${node.exceptionId}`;
    const direct = getCompatibility(outbound, withId, matrix);
    if (direct !== COMPAT_STATUS.UNDEF) return direct;
    const base = getCompatibility(outbound, licenseId, matrix);
    if (isCompatYes(base)) return COMPAT_STATUS.CHECK;
    return base;
  }

  if (node.type === 'compound') {
    const left = evaluateOutboundAgainst(outbound, node.left, matrix);
    const right = evaluateOutboundAgainst(outbound, node.right, matrix);
    const combined = node.op === 'OR' ? betterStatus(left, right) : worseStatus(left, right);
    return combined === COMPAT_STATUS.SAME ? COMPAT_STATUS.YES : combined;
  }

  return COMPAT_STATUS.UNDEF;
}

/**
 * @param {LicenseExpressionNode[]} trees
 * @returns {LicenseExpressionNode|null}
 */
export function andTrees(trees) {
  const list = trees.filter(Boolean);
  if (!list.length) return null;
  return list.reduce((left, right) => ({ type: 'compound', op: 'AND', left, right }));
}

/**
 * Outbound licenses in the matrix that can include the inbound expression.
 *
 * @param {LicenseExpressionNode|null} inboundTree
 * @param {OsadlMatrix} matrix
 * @returns {string[]}
 */
export function outboundCandidates(inboundTree, matrix) {
  if (!inboundTree || !matrix?.ids) return [];
  const found = [];
  for (const outbound of matrix.ids) {
    if (isCompatYes(evaluateOutboundAgainst(outbound, inboundTree, matrix))) {
      found.push(outbound);
    }
  }
  return found;
}

/**
 * @param {string} expression
 * @returns {boolean}
 */
function isSkippedExpression(expression) {
  const text = String(expression || '').trim();
  if (!text) return true;
  if (/\bNoAssertion\b/i.test(text)) return true;
  if (/^(NONE|NOASSERTION)$/i.test(text)) return true;
  return false;
}

/**
 * @param {string} id
 * @param {Map<string, object>} [elementMap]
 * @param {string} [label]
 * @returns {string}
 */
function isUsableLicenseString(value, matrix) {
  if (!value || isSkippedExpression(value)) return false;
  if (/\b(AND|OR|WITH)\b/.test(value) || /^LicenseRef-/i.test(value)) return true;
  const tree = parseLicenseExpression(value);
  const atoms = tree ? licenseExpressionAtomIds(tree) : [value];
  return atoms.some((atom) => resolveMatrixLicenseId(atom, matrix) || /^LicenseRef-/i.test(atom));
}

function expressionForLicense(id, elementMap, label, matrix) {
  const resolved = resolveLicenseExpression(id, elementMap);
  const fallback = String(label || '').trim();
  if (isUsableLicenseString(resolved, matrix)) return resolved;
  if (
    fallback &&
    !isSkippedExpression(fallback) &&
    fallback !== 'No assertion' &&
    fallback !== 'None'
  ) {
    return fallback;
  }
  return resolved && !isSkippedExpression(resolved) ? resolved : '';
}

/**
 * Short label for a license id that may be a URL or a LicenseRef.
 *
 * @param {string} id
 * @returns {string}
 */
export function shortLicenseLabel(id) {
  const raw = String(id || '').trim();
  if (!raw) return '';
  const ref = raw.match(/LicenseRef-[A-Za-z0-9.+-]+/);
  if (ref) return ref[0];
  if (/^https?:\/\//i.test(raw)) {
    try {
      return decodeURIComponent(raw.split('/').pop() || raw) || raw;
    } catch {
      return raw.split('/').pop() || raw;
    }
  }
  return raw;
}

/**
 * Builds the license-view compatibility report for one SBOM.
 *
 * @param {Array<{id: string, label: string, userCount?: number}>} licenses
 * @param {Map<string, object>} [elementMap]
 * @param {OsadlMatrix} matrix
 * @returns {object}
 */
export function analyzeSbomLicenses(licenses, elementMap, matrix) {
  const empty = {
    timestamp: matrix?.timestamp || '',
    verdict: COMPAT_VERDICT.EMPTY,
    atoms: [],
    pairwise: {},
    conflicts: [],
    groupedConflicts: [],
    checks: [],
    candidates: [],
    sbomCandidates: [],
    unsupported: [],
    byId: {},
    showMatrix: false
  };

  if (!matrix?.ids?.length) return empty;
  const list = Array.isArray(licenses) ? licenses : [];

  /** @type {Array<{id: string, label: string, userCount: number, expression: string, tree: LicenseExpressionNode|null, atoms: string[], supportedAtoms: string[], unsupportedAtoms: string[]}>} */
  const entries = [];
  const atomUsers = new Map();
  const atomSourceIds = new Map();

  for (const lic of list) {
    if (!lic?.id || licenseIndividualToken(lic.id)) continue;
    if (!isMeaningfulValue(lic.label) && !lic.id) continue;
    const expression = expressionForLicense(lic.id, elementMap, lic.label, matrix);
    if (!expression) continue;

    const tree = parseLicenseExpression(expression);
    const rawAtoms = tree
      ? licenseExpressionAtomIds(tree)
      : [normalizeSpdxLicenseId(expression) || expression];
    const supportedAtoms = [];
    const unsupportedAtoms = [];
    for (const atom of rawAtoms) {
      const key = resolveMatrixLicenseId(atom, matrix);
      if (key) supportedAtoms.push(key);
      else unsupportedAtoms.push(atom);
    }

    entries.push({
      id: lic.id,
      label: lic.label || expression,
      userCount: lic.userCount || 0,
      expression,
      tree,
      atoms: rawAtoms,
      supportedAtoms,
      unsupportedAtoms
    });

    for (const atom of [...supportedAtoms, ...unsupportedAtoms]) {
      atomUsers.set(atom, (atomUsers.get(atom) || 0) + (lic.userCount || 0));
      if (!atomSourceIds.has(atom)) atomSourceIds.set(atom, []);
      atomSourceIds.get(atom).push(lic.id);
    }
  }

  if (!entries.length) return { ...empty, timestamp: matrix.timestamp };

  const supportedSet = new Set();
  for (const entry of entries) {
    for (const atom of entry.supportedAtoms) supportedSet.add(atom);
  }
  const atoms = [...supportedSet].sort((a, b) => a.localeCompare(b));

  const unsupportedMap = new Map();
  for (const entry of entries) {
    for (const atom of entry.unsupportedAtoms) {
      if (!unsupportedMap.has(atom)) {
        unsupportedMap.set(atom, {
          id: atom,
          label: shortLicenseLabel(atom),
          userCount: 0,
          sourceIds: []
        });
      }
      const row = unsupportedMap.get(atom);
      row.userCount += entry.userCount;
      row.sourceIds.push(entry.id);
    }
  }
  const unsupported = [...unsupportedMap.values()].sort(
    (a, b) => b.userCount - a.userCount || a.label.localeCompare(b.label)
  );

  /** @type {Record<string, Record<string, string>>} */
  const pairwise = {};
  /** @type {Array<{outbound: string, inbound: string, status: string}>} */
  const conflicts = [];
  /** @type {Array<{outbound: string, inbound: string, status: string}>} */
  const checks = [];
  for (const outbound of atoms) {
    pairwise[outbound] = {};
    for (const inbound of atoms) {
      const status = getCompatibility(outbound, inbound, matrix);
      pairwise[outbound][inbound] = status;
      if (outbound === inbound) continue;
      if (status === COMPAT_STATUS.NO) conflicts.push({ outbound, inbound, status });
      else if (status === COMPAT_STATUS.CHECK) checks.push({ outbound, inbound, status });
    }
  }

  const groupedConflicts = groupConflictsByOutbound(conflicts);

  const supportedTrees = entries
    .filter((entry) => entry.tree && entry.supportedAtoms.length && !entry.unsupportedAtoms.length)
    .map((entry) => entry.tree);
  // An expression that mixes a known license with a LicenseRef still contributes
  // its known atoms, as an AND of those atoms, so a custom exception doesn't
  // hide the rest of the SBOM.
  for (const entry of entries) {
    if (entry.tree && entry.supportedAtoms.length && entry.unsupportedAtoms.length) {
      const partial = andTrees(entry.supportedAtoms.map((id) => ({ type: 'id', id })));
      if (partial) supportedTrees.push(partial);
    } else if (!entry.tree && entry.supportedAtoms.length) {
      supportedTrees.push({ type: 'id', id: entry.supportedAtoms[0] });
    }
  }

  const inboundTree = andTrees(supportedTrees);
  const rawCandidates = inboundTree ? outboundCandidates(inboundTree, matrix) : [];
  const atomSet = new Set(atoms);
  const atomIndex = new Map(atoms.map((id, i) => [id, i]));
  const candidates = rawCandidates.map((id) => ({
    id,
    inSbom: atomSet.has(id)
  }));
  candidates.sort((a, b) => {
    if (a.inSbom !== b.inSbom) return a.inSbom ? -1 : 1;
    const ai = atomIndex.has(a.id) ? atomIndex.get(a.id) : 9999;
    const bi = atomIndex.has(b.id) ? atomIndex.get(b.id) : 9999;
    if (a.inSbom && b.inSbom && ai !== bi) return ai - bi;
    return a.id.localeCompare(b.id);
  });
  const sbomCandidates = candidates.filter((c) => c.inSbom);

  /** @type {Record<string, object>} */
  const byId = {};
  for (const entry of entries) {
    const asOutbound = { yes: [], no: [], check: [], unknown: [], undef: [] };
    const primary = entry.supportedAtoms[0] || '';
    if (primary) {
      for (const other of atoms) {
        if (other === primary) continue;
        const status = pairwise[primary]?.[other] || COMPAT_STATUS.UNDEF;
        if (isCompatYes(status)) asOutbound.yes.push(other);
        else if (status === COMPAT_STATUS.NO) asOutbound.no.push(other);
        else if (status === COMPAT_STATUS.CHECK) asOutbound.check.push(other);
        else if (status === COMPAT_STATUS.UNKNOWN) asOutbound.unknown.push(other);
        else asOutbound.undef.push(other);
      }
    }
    const conflictCount = asOutbound.no.length;
    let kind = 'ok';
    if (entry.unsupportedAtoms.length && !entry.supportedAtoms.length) kind = 'unsupported';
    else if (conflictCount) kind = 'conflict';
    else if (asOutbound.check.length || asOutbound.unknown.length) kind = 'review';
    byId[entry.id] = {
      kind,
      atoms: entry.supportedAtoms,
      unsupportedAtoms: entry.unsupportedAtoms,
      conflictCount,
      asOutbound,
      isCandidate: primary
        ? atomSet.has(primary) && sbomCandidates.some((c) => c.id === primary)
        : false
    };
  }

  let verdict = COMPAT_VERDICT.COMPATIBLE;
  if (!atoms.length) verdict = COMPAT_VERDICT.INCOMPLETE;
  else if (!candidates.length) verdict = COMPAT_VERDICT.BLOCKED;
  else if (conflicts.length) verdict = COMPAT_VERDICT.CONSTRAINED;

  return {
    timestamp: matrix.timestamp,
    verdict,
    atoms,
    pairwise,
    conflicts,
    groupedConflicts,
    checks,
    candidates,
    sbomCandidates,
    unsupported,
    atomSources: Object.fromEntries(atomSourceIds),
    byId,
    showMatrix: atoms.length >= 2 && atoms.length <= COMPAT_MATRIX_MAX,
    atomCount: atoms.length,
    supportedEntryCount: entries.filter((e) => e.supportedAtoms.length).length
  };
}

/**
 * Collapses pairwise "cannot include" rows into one row per outbound license
 * so a large SBOM doesn't dump hundreds of lines.
 *
 * @param {Array<{outbound: string, inbound: string}>} conflicts
 * @returns {Array<{outbound: string, inbounds: string[]}>}
 */
export function groupConflictsByOutbound(conflicts) {
  const byOut = new Map();
  for (const row of conflicts || []) {
    if (!row?.outbound || !row?.inbound) continue;
    if (!byOut.has(row.outbound)) byOut.set(row.outbound, []);
    byOut.get(row.outbound).push(row.inbound);
  }
  return [...byOut.entries()]
    .map(([outbound, inbounds]) => ({
      outbound,
      inbounds: [...new Set(inbounds)].sort((a, b) => a.localeCompare(b))
    }))
    .sort((a, b) => b.inbounds.length - a.inbounds.length || a.outbound.localeCompare(b.outbound));
}

/**
 * Compact "A, B, and N more" label for a grouped cannot-include list.
 *
 * @param {string[]} inbounds
 * @param {{preview?: number, maxPlain?: number}} [opts]
 * @returns {string}
 */
export function formatInboundList(inbounds, opts = {}) {
  const list = Array.isArray(inbounds) ? inbounds : [];
  const preview = opts.preview ?? 2;
  const maxPlain = opts.maxPlain ?? 3;
  if (list.length <= maxPlain) return list.join(', ');
  return `${list.slice(0, preview).join(', ')}, and ${list.length - preview} more`;
}

/**
 * Short explanation of one matrix cell, for tooltips and the selected-cell
 * detail under the matrix.
 *
 * @param {string} outbound
 * @param {string} inbound
 * @param {string} status
 * @returns {string}
 */
export function describeCompatibility(outbound, inbound, status) {
  const out = outbound || 'this license';
  const inn = inbound || 'that license';
  if (status === COMPAT_STATUS.SAME || outbound === inbound) {
    return `${out} with itself.`;
  }
  if (status === COMPAT_STATUS.YES) {
    return `A project under ${out} can include ${inn} code.`;
  }
  if (status === COMPAT_STATUS.NO) {
    return `A project under ${out} cannot include ${inn} code.`;
  }
  if (status === COMPAT_STATUS.CHECK) {
    return `Whether ${out} can include ${inn} depends on how the ${inn} component is used. Check the OSADL checklist.`;
  }
  if (status === COMPAT_STATUS.UNKNOWN) {
    return `OSADL has not classified whether ${out} can include ${inn}.`;
  }
  return `${out} or ${inn} is not in the OSADL compatibility matrix.`;
}

/**
 * Formats the OSADL timestamp for display (date only when parseable).
 *
 * @param {string} timestamp
 * @returns {string}
 */
export function formatMatrixTimestamp(timestamp) {
  const raw = String(timestamp || '').trim();
  if (!raw) return '';
  const day = raw.slice(0, 10);
  return /^\d{4}-\d{2}-\d{2}$/.test(day) ? day : raw;
}
