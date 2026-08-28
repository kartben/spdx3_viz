/**
 * License compatibility analysis, in the spirit of flict
 * (https://github.com/vinland-technology/flict) but running in the browser
 * against the vendored OSADL matrix.
 *
 * The whole model is one directional question: may a component licensed X be
 * distributed inside a work licensed Y? OSADL answers it for 119 licenses;
 * everything here is expression handling on top of that lookup.
 *
 * Nothing in this module is legal advice. It reports what the matrix says, and
 * says so plainly when the matrix has nothing to say.
 *
 * @module lib/compatibility
 */
import { parseLicenseExpression } from './licenses.js';
import { COMPAT_LICENSES, COMPAT_ROWS } from './osadl-matrix.js';

/**
 * Verdict for a license or expression against an outbound license.
 *
 * - `compatible`  the component may go into the outbound work (OSADL Yes/Same)
 * - `conflict`    it may not (OSADL No)
 * - `review`      it depends on how the component is used (OSADL Check dependency)
 * - `unrated`     the matrix does not cover this license, so nothing is claimed
 *
 * @typedef {'compatible' | 'conflict' | 'review' | 'unrated'} CompatStatus
 */

/** Matrix cell code to verdict. */
const CODE_STATUS = {
  Y: 'compatible',
  S: 'compatible',
  N: 'conflict',
  D: 'review',
  U: 'unrated'
};

/**
 * How verdicts combine. A set of licenses is only as good as its worst member,
 * and a choice of alternatives is as good as its best one, so both directions
 * are decided by this ordering.
 * @type {Record<CompatStatus, number>}
 */
const STATUS_RANK = { conflict: 0, unrated: 1, review: 2, compatible: 3 };

/** Display order and labels, worst first: how the UI groups and counts them. */
export const COMPAT_STATUS_META = [
  { id: 'conflict', label: 'Conflict', short: 'Conflict' },
  { id: 'review', label: 'Depends on use', short: 'Review' },
  { id: 'unrated', label: 'Not rated', short: 'Not rated' },
  { id: 'compatible', label: 'Compatible', short: 'Compatible' }
];

const LICENSE_INDEX = new Map(COMPAT_LICENSES.map((id, i) => [id, i]));

// Case-insensitive fallback: SPDX ids are case-sensitive, but real SBOMs carry
// `apache-2.0` and `MIT ` often enough that failing them as unrated would be a
// worse answer than matching the canonical id.
const LICENSE_INDEX_CI = new Map(COMPAT_LICENSES.map((id, i) => [id.toLowerCase(), i]));

/**
 * Outbound "license" for a closed-source product. Not an SPDX identifier and
 * not a matrix row: OSADL rates open source licenses against each other, and
 * has nothing to say about a work whose source is never published.
 */
export const PROPRIETARY_OUTBOUND = 'Proprietary';

/**
 * Permissive licenses used to derive the proprietary answer. A proprietary work
 * carries at least the restrictions these do, since it does not offer source at
 * all, so a component no permissive outbound work can absorb cannot go into a
 * proprietary one either.
 *
 * In the matrix as vendored, all seven accept exactly the same 87 licenses.
 * Taking the intersection rather than trusting one row keeps the answer
 * conservative if a future revision makes them disagree.
 */
const PERMISSIVE_REFERENCES = [
  'MIT',
  'BSD-3-Clause',
  'Apache-2.0',
  'ISC',
  '0BSD',
  'Zlib',
  'BSL-1.0'
];

let proprietarySafeIds = null;

// Licenses that every permissive reference row accepts, and so the ones a
// proprietary work can take in. Built once, on first use.
function proprietarySafe() {
  if (proprietarySafeIds) return proprietarySafeIds;
  const rows = PERMISSIVE_REFERENCES.map((id) => resolveLicenseIndex(id)).filter((i) => i >= 0);
  proprietarySafeIds = new Set(
    COMPAT_LICENSES.filter((_, col) => rows.every((row) => 'YS'.includes(COMPAT_ROWS[row][col])))
  );
  return proprietarySafeIds;
}

/**
 * True when the identifier can be used as an outbound license: one the matrix
 * rates, or the derived proprietary option.
 *
 * @param {string} licenseId
 * @returns {boolean}
 */
export function isRatedLicense(licenseId) {
  return licenseId === PROPRIETARY_OUTBOUND || resolveLicenseIndex(licenseId) >= 0;
}

/**
 * Every outbound license that can be checked against: the proprietary option
 * first, since it answers a question no SPDX identifier does, then the matrix's
 * licenses in identifier order.
 *
 * @returns {string[]}
 */
export function ratedLicenses() {
  return [PROPRIETARY_OUTBOUND, ...[...COMPAT_LICENSES].sort((a, b) => a.localeCompare(b))];
}

function resolveLicenseIndex(licenseId) {
  if (typeof licenseId !== 'string') return -1;
  const trimmed = licenseId.trim();
  if (!trimmed) return -1;
  const exact = LICENSE_INDEX.get(trimmed);
  if (exact !== undefined) return exact;
  const insensitive = LICENSE_INDEX_CI.get(trimmed.toLowerCase());
  return insensitive === undefined ? -1 : insensitive;
}

/**
 * @typedef {Object} ResolvedLicense
 * @property {string} token - the identifier as written in the expression
 * @property {string} id - the matrix identifier it was matched to, or '' when unrated
 * @property {boolean} exact - false when a fallback was applied (see resolveLicenseToken)
 * @property {string} note - why the fallback was applied, for the UI to show
 */

/**
 * Maps one expression token onto a matrix identifier.
 *
 * Three fallbacks, each of which can only make the verdict more cautious:
 * a `+` suffix means "or later", which the matrix spells out; a `WITH` clause
 * falls back to the bare license, since an exception only ever relaxes terms
 * that the matrix already rated; and a bare `GPL-2.0` style id (deprecated but
 * still common) resolves to its `-only` form, the stricter reading.
 *
 * @param {string} token
 * @returns {ResolvedLicense}
 */
export function resolveLicenseToken(token) {
  const raw = String(token || '').trim();
  const miss = { token: raw, id: '', exact: false, note: '' };
  if (!raw) return miss;

  if (resolveLicenseIndex(raw) >= 0) {
    return { token: raw, id: COMPAT_LICENSES[resolveLicenseIndex(raw)], exact: true, note: '' };
  }

  if (raw.endsWith('+')) {
    const base = raw.slice(0, -1);
    for (const candidate of [`${base}-or-later`, base]) {
      const index = resolveLicenseIndex(candidate);
      if (index >= 0) {
        return {
          token: raw,
          id: COMPAT_LICENSES[index],
          exact: false,
          note: `read as ${COMPAT_LICENSES[index]}`
        };
      }
    }
  }

  if (raw.includes(' WITH ')) {
    const base = resolveLicenseToken(raw.split(' WITH ')[0]);
    if (base.id) {
      return {
        token: raw,
        id: base.id,
        exact: false,
        note: `exception not rated; checked as ${base.id} alone`
      };
    }
  }

  const onlyIndex = resolveLicenseIndex(`${raw}-only`);
  if (onlyIndex >= 0) {
    return {
      token: raw,
      id: COMPAT_LICENSES[onlyIndex],
      exact: false,
      note: `read as ${COMPAT_LICENSES[onlyIndex]}`
    };
  }

  return miss;
}

/**
 * The matrix verdict for one identifier pair, both already resolved.
 *
 * @param {string} outboundId - the license of the combined work
 * @param {string} inboundId - the license of the component going into it
 * @returns {CompatStatus}
 */
export function licensePairStatus(outboundId, inboundId) {
  const col = resolveLicenseIndex(inboundId);
  if (col < 0) return 'unrated';
  if (outboundId === PROPRIETARY_OUTBOUND) {
    return proprietarySafe().has(COMPAT_LICENSES[col]) ? 'compatible' : 'conflict';
  }
  const row = resolveLicenseIndex(outboundId);
  if (row < 0) return 'unrated';
  return CODE_STATUS[COMPAT_ROWS[row][col]] || 'unrated';
}

/**
 * True when the pair is the same license, which the matrix marks separately
 * from a plain "yes" and which reads better as such in the UI.
 *
 * @param {string} outboundId
 * @param {string} inboundId
 * @returns {boolean}
 */
export function isSameLicense(outboundId, inboundId) {
  const row = resolveLicenseIndex(outboundId);
  const col = resolveLicenseIndex(inboundId);
  return row >= 0 && row === col;
}

/**
 * Expands an expression into its alternatives: every combination of licenses
 * that would satisfy it, as disjunctive normal form. `MIT OR (GPL-2.0-only AND
 * BSD-3-Clause)` yields `[['MIT'], ['GPL-2.0-only', 'BSD-3-Clause']]`.
 *
 * Satisfying any one alternative satisfies the expression, so compatibility is
 * decided by the best alternative, not the average.
 *
 * @param {string} expression
 * @returns {string[][]} one array of license tokens per alternative, or [] when
 *   the expression could not be parsed
 */
export function licenseAlternatives(expression) {
  const tree = parseLicenseExpression(expression);
  return tree ? expandNode(tree) : [];
}

function expandNode(node) {
  if (node.type === 'id') return [[node.id]];
  if (node.type === 'with') return [[`${node.licenseId} WITH ${node.exceptionId}`]];
  if (node.op === 'OR') return [...expandNode(node.left), ...expandNode(node.right)];

  // AND distributes over the alternatives on both sides.
  const left = expandNode(node.left);
  const right = expandNode(node.right);
  const out = [];
  for (const a of left) {
    for (const b of right) out.push([...new Set([...a, ...b])]);
  }
  return out;
}

/**
 * @typedef {Object} CompatTerm
 * @property {string} token - identifier as written
 * @property {string} id - matrix identifier it resolved to, '' when unrated
 * @property {CompatStatus} status
 * @property {string} note - fallback explanation, '' when the match was exact
 *
 * @typedef {Object} CompatCheck
 * @property {CompatStatus} status - the expression's overall verdict
 * @property {string[]} alternative - the licenses of the alternative that decided it
 * @property {CompatTerm[]} terms - every license in that alternative, with its own verdict
 * @property {CompatTerm[]} blockers - the terms that are not compatible
 * @property {boolean} sameLicense - true when the expression is exactly the outbound license
 * @property {boolean} choice - true when the expression offered more than one alternative
 * @property {boolean} parsed - false when the expression is not a valid SPDX expression
 */

/**
 * Checks whether a component's license expression may be distributed inside a
 * work licensed `outbound`.
 *
 * @param {string} expression - the component's SPDX license expression
 * @param {string} outbound - SPDX id of the outbound license
 * @returns {CompatCheck}
 */
export function checkLicenseExpression(expression, outbound) {
  const alternatives = licenseAlternatives(expression);
  if (!alternatives.length) {
    return {
      status: 'unrated',
      alternative: [],
      terms: [],
      blockers: [],
      sameLicense: false,
      choice: false,
      parsed: false
    };
  }

  let best = null;
  for (const alternative of alternatives) {
    const terms = alternative.map((token) => {
      const resolved = resolveLicenseToken(token);
      return {
        token,
        id: resolved.id,
        note: resolved.note,
        status: resolved.id ? licensePairStatus(outbound, resolved.id) : 'unrated'
      };
    });
    const status = terms.reduce(
      (worst, term) => (STATUS_RANK[term.status] < STATUS_RANK[worst] ? term.status : worst),
      /** @type {CompatStatus} */ ('compatible')
    );
    const candidate = {
      status,
      alternative,
      terms,
      blockers: terms.filter((term) => term.status !== 'compatible'),
      sameLicense: terms.length === 1 && !!terms[0].id && isSameLicense(outbound, terms[0].id),
      choice: alternatives.length > 1,
      parsed: true
    };
    // Prefer the best verdict; between equals, prefer the simpler alternative so
    // the explanation names the shortest route to that answer.
    if (
      !best ||
      STATUS_RANK[candidate.status] > STATUS_RANK[best.status] ||
      (candidate.status === best.status && candidate.alternative.length < best.alternative.length)
    ) {
      best = candidate;
    }
  }
  return best;
}

/**
 * @typedef {Object} CompatSubject
 * @property {string} id - stable key for the license (the app passes the license element id)
 * @property {string} expression - SPDX expression to check
 * @property {string} [label] - display label, defaults to the expression
 * @property {string[]} [elements] - spdxIds of elements carrying this license
 *
 * @typedef {CompatCheck & CompatSubject & {elementCount: number}} CompatFinding
 *
 * @typedef {Object} CompatReport
 * @property {string} outbound - the outbound license the report was computed for
 * @property {CompatFinding[]} findings - one per subject, worst verdict first
 * @property {Record<CompatStatus, {licenses: number, elements: number}>} totals
 * @property {number} licenseCount - subjects checked
 * @property {number} elementCount - distinct elements covered
 * @property {number} clearElementCount - elements carrying no conflicting license
 */

/**
 * Checks a whole set of licenses against one outbound license.
 *
 * Element counts overlap by design: one package may declare several licenses,
 * so a package can land in both the compatible and the conflict bucket. The
 * separate `clearElementCount` is the honest "how much of this is shippable"
 * figure.
 *
 * @param {CompatSubject[]} subjects
 * @param {string} outbound
 * @returns {CompatReport}
 */
export function buildCompatReport(subjects, outbound) {
  /** @type {Record<string, {licenses: number, elements: Set<string>}>} */
  const totals = {};
  for (const meta of COMPAT_STATUS_META) totals[meta.id] = { licenses: 0, elements: new Set() };

  const allElements = new Set();
  const conflicted = new Set();
  const findings = (subjects || []).map((subject) => {
    const check = checkLicenseExpression(subject.expression, outbound);
    const elements = subject.elements || [];
    totals[check.status].licenses += 1;
    for (const element of elements) {
      allElements.add(element);
      totals[check.status].elements.add(element);
      if (check.status === 'conflict') conflicted.add(element);
    }
    return {
      ...subject,
      ...check,
      label: subject.label || subject.expression,
      elementCount: elements.length
    };
  });

  findings.sort(
    (a, b) =>
      STATUS_RANK[a.status] - STATUS_RANK[b.status] ||
      b.elementCount - a.elementCount ||
      String(a.label).localeCompare(String(b.label))
  );

  return {
    outbound,
    findings,
    totals: Object.fromEntries(
      Object.entries(totals).map(([status, value]) => [
        status,
        { licenses: value.licenses, elements: value.elements.size }
      ])
    ),
    licenseCount: findings.length,
    elementCount: allElements.size,
    clearElementCount: allElements.size - conflicted.size
  };
}

/**
 * @typedef {Object} OutboundCandidate
 * @property {string} id - SPDX id of the candidate outbound license
 * @property {number} conflict - licenses that could not go into it
 * @property {number} review - licenses whose answer depends on how they are used
 * @property {number} unrated - licenses the matrix does not cover
 * @property {number} compatible - licenses that could go into it
 * @property {number} blockedElements - elements carrying at least one conflicting license
 */

/**
 * Ranks every outbound license by how well it works for this set of components.
 * flict calls this `outbound-candidate`. The proprietary option is ranked
 * alongside the SPDX licenses, since "could I ship this closed-source?" is one
 * of the answers people come here for.
 *
 * Unrated licenses are identical for every candidate (they depend on the
 * component, not the outbound choice), so they do not affect the ranking.
 *
 * @param {CompatSubject[]} subjects
 * @param {{limit?: number}} [opts]
 * @returns {OutboundCandidate[]} best first
 */
export function outboundCandidates(subjects, opts = {}) {
  const list = subjects || [];
  // Pre-expand once: the alternatives of a subject do not depend on the
  // candidate, so expanding inside the 119-candidate loop would be wasted work.
  const expanded = list.map((subject) => ({
    elements: subject.elements || [],
    alternatives: licenseAlternatives(subject.expression).map((alternative) =>
      alternative.map((token) => resolveLicenseToken(token).id)
    )
  }));

  const candidates = [PROPRIETARY_OUTBOUND, ...COMPAT_LICENSES].map((id) => {
    const tally = { id, conflict: 0, review: 0, unrated: 0, compatible: 0, blockedElements: 0 };
    const blocked = new Set();
    for (const subject of expanded) {
      const status = subject.alternatives.length
        ? bestAlternativeStatus(subject.alternatives, id)
        : 'unrated';
      tally[status] += 1;
      if (status === 'conflict') for (const element of subject.elements) blocked.add(element);
    }
    tally.blockedElements = blocked.size;
    return tally;
  });

  candidates.sort(
    (a, b) =>
      a.conflict - b.conflict ||
      a.blockedElements - b.blockedElements ||
      a.review - b.review ||
      b.compatible - a.compatible ||
      a.id.localeCompare(b.id)
  );
  return opts.limit ? candidates.slice(0, opts.limit) : candidates;
}

function bestAlternativeStatus(alternatives, outbound) {
  let best = 'conflict';
  for (const alternative of alternatives) {
    let worst = 'compatible';
    for (const id of alternative) {
      const status = id ? licensePairStatus(outbound, id) : 'unrated';
      if (STATUS_RANK[status] < STATUS_RANK[worst]) worst = status;
    }
    if (STATUS_RANK[worst] > STATUS_RANK[best]) best = worst;
  }
  return best;
}

/**
 * Pairwise grid over a set of licenses, for the compatibility matrix. Every
 * cell is `rows[i].cells[j]`: taking column j's license into a work licensed
 * under row i's.
 *
 * @param {Array<{id: string, expression: string, label?: string, elementCount?: number}>} entries
 * @returns {{licenses: Array<Object>, rows: Array<{id: string, cells: Array<{status: CompatStatus, same: boolean}>}>, conflictPairs: number}}
 *   `conflictPairs` counts license pairs that conflict in both directions, and
 *   so can never appear in one combined work whichever way round they are used.
 */
export function buildCompatMatrix(entries) {
  const licenses = (entries || []).map((entry) => {
    const alternatives = licenseAlternatives(entry.expression);
    // A matrix cell needs one identifier per axis, so only expressions that
    // reduce to a single license are rated; anything else shows as unrated.
    const single =
      alternatives.length === 1 && alternatives[0].length === 1
        ? resolveLicenseToken(alternatives[0][0])
        : null;
    return {
      ...entry,
      label: entry.label || entry.expression,
      matrixId: single?.id || '',
      approximate: !!single && !single.exact,
      note: single?.note || ''
    };
  });

  const rows = licenses.map((row) => ({
    id: row.id,
    cells: licenses.map((col) => ({
      status:
        row.matrixId && col.matrixId ? licensePairStatus(row.matrixId, col.matrixId) : 'unrated',
      same: !!row.matrixId && isSameLicense(row.matrixId, col.matrixId)
    }))
  }));

  let conflictPairs = 0;
  for (let i = 0; i < rows.length; i++) {
    for (let j = i + 1; j < rows.length; j++) {
      if (rows[i].cells[j].status === 'conflict' && rows[j].cells[i].status === 'conflict') {
        conflictPairs += 1;
      }
    }
  }

  return { licenses, rows, conflictPairs };
}
