import {
  buildCompatMatrix,
  buildCompatReport,
  DISTRIBUTED_EDGE_TYPES,
  COMPAT_MATRIX_DATE,
  COMPAT_MATRIX_URL,
  COMPAT_STATUS_META,
  isRatedLicense,
  licenseAlternatives,
  licenseIndividualToken,
  outboundCandidates,
  PROPRIETARY_OUTBOUND,
  ratedLicenses,
  resolveLicenseToken
} from '../lib/index.js';

/* License compatibility: the Licenses view's second tab. Answers "can all of
   this ship under one license?" against the vendored OSADL matrix, the way
   flict does, plus the pairwise grid behind it.

   Every result here is memoized off the reactive state, keyed on the inputs
   that actually change it: the analysis only runs when the tab is open, and
   re-runs only when the licenses, the outbound choice, or the scope move. */

let subjectsKey = null;
let subjectsVal = { subjects: [], unasserted: 0, scopeSize: 0 };
let reportKey = null;
let reportVal = null;
let candidatesKey = null;
let candidatesVal = [];
let matrixKey = null;
let matrixVal = { licenses: [], rows: [], conflictPairs: 0, hidden: 0 };
let scopeKey = null;
let scopeVal = null;
let documentLicenseSrc = null;
let documentLicenseVal = 0;

// Licenses gridded in the matrix before "show all", and the hard ceiling after
// it: the grid is O(n²) cells, so a rootfs SBOM with thousands of licenses gets
// its most-used ones rather than a page that never paints.
const MATRIX_PREVIEW = 15;
const MATRIX_MAX = 80;

const STATUS_BADGE = {
  conflict: 'bg-rose-500/15 text-rose-300',
  review: 'bg-amber-500/15 text-amber-300',
  unrated: 'bg-slate-600/30 text-slate-300',
  compatible: 'bg-emerald-500/15 text-emerald-300'
};

const STATUS_ACCENT = {
  conflict: 'text-rose-400',
  review: 'text-amber-400',
  unrated: 'text-slate-400',
  compatible: 'text-emerald-400'
};

const STATUS_CELL = {
  conflict: 'bg-rose-500/45',
  review: 'bg-amber-500/45',
  unrated: 'bg-slate-500/15',
  compatible: 'bg-emerald-500/35'
};

const STATUS_BLURB = {
  conflict: 'cannot go into the outbound work',
  review: 'depends on how the component is used',
  unrated: 'not covered by the OSADL matrix',
  compatible: 'can go into the outbound work'
};

export const compatibilityMixin = {
  _resetCompatMemos() {
    subjectsKey = null;
    reportKey = null;
    candidatesKey = null;
    matrixKey = null;
    scopeKey = null;
    scopeVal = null;
    documentLicenseSrc = null;
  },

  get compatMatrixDate() {
    return COMPAT_MATRIX_DATE.slice(0, 10);
  },
  get compatMatrixUrl() {
    return COMPAT_MATRIX_URL;
  },
  get compatStatuses() {
    return COMPAT_STATUS_META;
  },
  get compatProprietaryId() {
    return PROPRIETARY_OUTBOUND;
  },
  // True while the proprietary option is the outbound, which the UI annotates:
  // it is derived from the matrix rather than read off a row of it.
  get compatIsProprietary() {
    return this.compatReport.outbound === PROPRIETARY_OUTBOUND;
  },

  compatStatusLabel(status) {
    return COMPAT_STATUS_META.find((meta) => meta.id === status)?.label || status;
  },
  compatStatusBadge(status) {
    return STATUS_BADGE[status] || STATUS_BADGE.unrated;
  },
  compatStatusAccent(status) {
    return STATUS_ACCENT[status] || STATUS_ACCENT.unrated;
  },
  compatStatusCell(status) {
    return STATUS_CELL[status] || STATUS_CELL.unrated;
  },

  // ---- scope --------------------------------------------------------------

  // Elements in scope, or null when every license in the document counts.
  //
  // A package scope is its dependency closure (the package plus everything it
  // pulls in), which is the unit flict actually verifies: a package's own
  // license against its dependencies'. With the distributed-only filter on,
  // the walk follows just the edges that put a component inside what ships,
  // and at document scope it starts from the graph's roots instead.
  //
  // The walk also steps back through build lineage: from an artifact to the
  // build that produced it, then to that build's inputs. Unlike the Impact
  // view, which asks what depends on what, a license check has to follow how
  // things were made. A source file compiled into a shipped binary carries its
  // license into that binary, and some SBOMs (Zephyr's among them) record the
  // link only this way, with the licensed sources on a package tree the build
  // tree never points at.
  get compatScopeElements() {
    const focus = this.compatScope;
    const distributed = this.compatEdgeFilter === 'distributed';
    if (!focus && !distributed) return null;

    const key = `${focus}|${this.compatEdgeFilter}`;
    if (scopeKey === key && scopeVal) return scopeVal;

    const roots = focus ? [focus] : [...this.impactRoots];
    const seen = new Set(roots);
    const queue = [...roots];
    let head = 0;
    const visit = (id) => {
      if (seen.has(id)) return;
      seen.add(id);
      queue.push(id);
    };
    while (head < queue.length) {
      const node = queue[head++];
      for (const child of this.impactChildIndex.get(node) || []) {
        if (distributed && !DISTRIBUTED_EDGE_TYPES.has(child.rel)) continue;
        visit(child.id);
      }
      for (const build of this.producedByBuildIndex.get(node) || []) {
        visit(build);
        for (const input of this.buildInputIndex.get(build) || []) visit(input);
      }
    }
    scopeKey = key;
    scopeVal = seen;
    return seen;
  },

  // Name for the scope chip in the toolbar.
  get compatScopeLabel() {
    if (this.compatScope) return this.relTargetDisplayName(this.compatScope);
    return this.compatEdgeFilter === 'distributed' ? 'What this document ships' : 'Whole document';
  },

  // The same scope as a noun phrase that reads inside a sentence, which the
  // chip label does not ("All 6 licenses in What this document ships…").
  get compatScopeSentence() {
    const distributed = this.compatEdgeFilter === 'distributed';
    if (this.compatScope) {
      const name = this.relTargetDisplayName(this.compatScope);
      return distributed ? `what ${name} ships` : `${name} and its dependencies`;
    }
    return distributed ? 'what this document ships' : 'this document';
  },

  // The distributed-only walk needs a graph to walk. Offering it on a flat
  // package list would silently empty the report.
  get canFilterCompatEdges() {
    return this.hasImpactData && (!!this.compatScope || this.impactRoots.size > 0);
  },

  setCompatEdgeFilter(filter) {
    this.compatEdgeFilter = filter;
    this.compatStatusFilter = '';
    this._scheduleNavPush();
  },

  // Packages offerable as a scope: only those that actually pull something in,
  // since a leaf package's closure is just itself.
  get compatScopeOptions() {
    const query = this.compatScopeSearch.trim().toLowerCase();
    const options = [];
    for (const pkg of this.packages) {
      if (!this.impactChildIndex.has(pkg.spdxId)) continue;
      const label = this.relTargetDisplayName(pkg.spdxId);
      if (query && !label.toLowerCase().includes(query)) continue;
      options.push({ id: pkg.spdxId, label, deps: this.impactChildIndex.get(pkg.spdxId).length });
      if (options.length >= 200) break;
    }
    return options.sort((a, b) => b.deps - a.deps || a.label.localeCompare(b.label));
  },

  get canScopeCompat() {
    return this.hasImpactData && this.packages.length > 0;
  },

  setCompatScope(id) {
    this.compatScope = id || '';
    this.compatScopePickerOpen = false;
    this.compatScopeSearch = '';
    this.compatStatusFilter = '';
    this._scheduleNavPush();
  },

  // ---- the licenses under analysis ---------------------------------------

  // The license list turned into checkable subjects, scoped and stripped of the
  // NoAssertion / None individuals: those record the absence of a license, and
  // counting them as findings would bury the real ones. They are reported
  // separately as a coverage gap instead.
  get compatSubjects() {
    const scope = this.compatScopeElements;
    const key = `${this.licenses.length}|${this.compatScope}|${this.compatEdgeFilter}|${scope ? scope.size : 0}`;
    if (key === subjectsKey) return subjectsVal;

    const subjects = [];
    const unassertedElements = new Set();
    const covered = new Set();

    for (const lic of this.licenses) {
      const users = [...new Set([...lic.declaredBy, ...lic.concludedBy])].filter(
        (id) => !scope || scope.has(id)
      );
      if (!users.length) continue;
      if (licenseIndividualToken(lic.id)) {
        for (const id of users) unassertedElements.add(id);
        continue;
      }
      for (const id of users) covered.add(id);
      // A custom license element carries no expression of its own, and its
      // element URL resolves in place of one. A URL is not an expression, so
      // fall back to the element's name, where converters routinely leave a
      // real one ("GPL-2.0-or-later WITH Texinfo-exception"). Flagged as
      // `named` so the finding can say where the identifier came from.
      const expression = this.licenseExpressionFor(lic.id);
      const named = !expression || /^https?:\/\//i.test(expression);
      subjects.push({
        id: lic.id,
        label: lic.label,
        expression: named ? lic.label : expression,
        named,
        elements: users
      });
    }

    // An element with any real license is covered, even if it also carries a
    // NoAssertion relationship, so only the wholly unasserted ones are a gap.
    for (const id of covered) unassertedElements.delete(id);

    subjectsKey = key;
    subjectsVal = {
      subjects,
      unasserted: unassertedElements.size,
      unassertedIds: [...unassertedElements],
      scopeSize: scope ? scope.size : 0
    };
    return subjectsVal;
  },

  get compatUnassertedCount() {
    return this.compatSubjects.unasserted;
  },

  get compatUnassertedIds() {
    return this.compatSubjects.unassertedIds || [];
  },

  // True when there is anything to analyse at all.
  get hasCompatData() {
    return this.licenses.length > 0;
  },

  // ---- outbound license ---------------------------------------------------

  /** Every license the matrix rates, filtered by the picker's search box. */
  get compatOutboundOptions() {
    const query = this.compatOutboundSearch.trim().toLowerCase();
    const all = ratedLicenses();
    return query ? all.filter((id) => id.toLowerCase().includes(query)) : all;
  },

  // A first guess so the tab opens on an answer rather than an empty picker:
  // the root element's own license if the matrix rates it, else the most-used
  // rated license, else whichever license conflicts with the least here.
  get compatDefaultOutbound() {
    for (const rootId of this.rootElementIds) {
      for (const lic of this.elementLicenses(rootId)) {
        const resolved = resolveLicenseToken(this.licenseExpressionFor(lic.id) || '');
        if (resolved.id) return resolved.id;
      }
    }
    for (const lic of this.licenses) {
      const resolved = resolveLicenseToken(this.licenseExpressionFor(lic.id) || '');
      if (resolved.id) return resolved.id;
    }
    return this.compatCandidates[0]?.id || '';
  },

  get compatOutboundLicense() {
    if (this.compatOutbound && isRatedLicense(this.compatOutbound)) return this.compatOutbound;
    return this.compatDefaultOutbound;
  },

  setCompatOutbound(id) {
    this.compatOutbound = id;
    this.compatOutboundTouched = true;
    this.compatOutboundPickerOpen = false;
    this.compatOutboundSearch = '';
    this.compatStatusFilter = '';
    this._scheduleNavPush();
  },

  // ---- the report ---------------------------------------------------------

  get compatReport() {
    const outbound = this.compatOutboundLicense;
    const { subjects } = this.compatSubjects;
    const key = `${subjectsKey}|${outbound}`;
    if (key === reportKey) return reportVal;
    reportVal = buildCompatReport(subjects, outbound);
    reportKey = key;
    return reportVal;
  },

  // Tiles across the top: one per status, in worst-first order, each carrying
  // both counts because "3 licenses" and "71 elements" are different questions.
  get compatTiles() {
    const report = this.compatReport;
    return COMPAT_STATUS_META.map((meta) => ({
      ...meta,
      licenses: report.totals[meta.id].licenses,
      elements: report.totals[meta.id].elements
    }));
  },

  get compatFindings() {
    const findings = this.compatReport.findings;
    return this.compatStatusFilter
      ? findings.filter((finding) => finding.status === this.compatStatusFilter)
      : findings;
  },

  get compatVisibleFindings() {
    return this.compatFindings.slice(0, this.revealLimit(`compat:${this.compatStatusFilter}`));
  },

  get compatHiddenFindingCount() {
    return Math.max(0, this.compatFindings.length - this.compatVisibleFindings.length);
  },

  toggleCompatStatusFilter(status) {
    this.compatStatusFilter = this.compatStatusFilter === status ? '' : status;
  },

  // How many elements the current scope covers, whether or not they carry a
  // license. Used to explain an empty result rather than just reporting one.
  get compatScopeSize() {
    return this.compatScopeElements?.size ?? 0;
  },

  // Real licenses anywhere in the document, ignoring scope and the NoAssertion
  // / None individuals. Tells "this scope cannot see the licenses" apart from
  // "this document has none".
  get compatDocumentLicenseCount() {
    if (documentLicenseSrc === this.licenses) return documentLicenseVal;
    documentLicenseVal = this.licenses.filter((lic) => !licenseIndividualToken(lic.id)).length;
    documentLicenseSrc = this.licenses;
    return documentLicenseVal;
  },

  // True when the scope holds elements, none of them names a license, and the
  // document does have licenses elsewhere. Common where an SBOM records them on
  // a separate tree of source packages that the build tree never reaches, which
  // is worth explaining rather than reporting as an empty list.
  get compatScopeHasNoLicenses() {
    return (
      this.compatReport.licenseCount === 0 &&
      this.compatScopeSize > 0 &&
      this.compatDocumentLicenseCount > 0
    );
  },

  // One sentence stating the outcome, so the answer does not have to be
  // reassembled from the tiles.
  get compatHeadline() {
    const report = this.compatReport;
    const outbound = report.outbound;
    if (!outbound) return 'No license in this document is covered by the OSADL matrix.';
    if (!report.licenseCount) {
      const scope = this.compatScopeSentence;
      if (!this.compatScopeSize) return `Nothing in ${scope} to check.`;
      const size = this.compatScopeSize;
      const unasserted = this.compatUnassertedCount;
      const detail = unasserted
        ? `all ${unasserted === size ? '' : `${unasserted} of `}${size} declare no license`
        : `none of the ${size} carries a license relationship`;
      return `Nothing to check: ${scope} covers ${size} ${size === 1 ? 'element' : 'elements'}, and ${detail}.`;
    }

    const conflicts = report.totals.conflict.licenses;
    const scope = this.compatScopeSentence;
    // "a work licensed X" does not read for the proprietary option, which is a
    // product rather than a license.
    const target = this.compatIsProprietary
      ? 'a closed-source product'
      : `a work licensed ${outbound}`;
    if (!conflicts) {
      const review = report.totals.review.licenses;
      const tail = review
        ? ` ${review} ${review === 1 ? 'needs' : 'need'} a look at how the component is used.`
        : '';
      return `All ${report.licenseCount} ${report.licenseCount === 1 ? 'license' : 'licenses'} in ${scope} can go into ${target}.${tail}`;
    }
    return `${conflicts} of the ${report.licenseCount} licenses in ${scope} cannot go into ${target}, leaving ${report.clearElementCount} of ${report.elementCount} elements clear.`;
  },

  get compatHasConflicts() {
    return this.compatReport.totals.conflict.licenses > 0;
  },

  // Elements carrying a given license, for a finding's drill-down.
  compatFindingElements(finding) {
    return (finding.elements || []).slice(0, this.revealLimit(`compatEl:${finding.id}`));
  },

  compatFindingHiddenCount(finding) {
    return Math.max(
      0,
      (finding.elements || []).length - this.compatFindingElements(finding).length
    );
  },

  // Why this finding got its verdict, in a sentence. Reads from the resolved
  // alternative, so a choice expression explains which branch decided it.
  compatFindingReason(finding) {
    const outbound = this.compatIsProprietary
      ? 'a closed-source product'
      : `a work licensed ${this.compatReport.outbound}`;
    if (!finding.parsed) {
      return `"${finding.label}" is not a license expression the matrix can be read for, so no claim is made about it.`;
    }

    // Read from the element's name rather than a declared expression, which is
    // worth saying: the name is free text, so the identifier is inferred.
    const source = finding.named
      ? ' This element declares no SPDX expression, so the check reads its name.'
      : '';
    // A choice expression that resolves to the outbound license is worth
    // explaining as the branch it took, not just as "the same license".
    if (finding.sameLicense) {
      return finding.choice
        ? `Satisfied by taking ${finding.alternative[0]}, the same license as the outbound work.${source}`
        : 'Same license as the outbound work.';
    }

    if (finding.status === 'compatible') {
      const via = finding.choice
        ? ` Satisfied by taking ${finding.alternative.join(' AND ')}.`
        : '';
      return `The OSADL matrix rates this as usable inside ${outbound}.${via}${source}`;
    }
    const blockers = finding.blockers
      .map((term) => (term.note ? `${term.token} (${term.note})` : term.token))
      .join(', ');
    if (finding.status === 'unrated') {
      return `The matrix has no entry for ${blockers}, so nothing is claimed either way.${source}`;
    }
    if (finding.status === 'review') {
      return `Whether ${blockers} may go into ${outbound} depends on how it is used, typically on the linking model.${source}`;
    }
    if (finding.choice) {
      return `No branch of this expression clears ${outbound}. The closest, ${finding.alternative.join(' AND ')}, is blocked by ${blockers}.${source}`;
    }
    return `${blockers} cannot go into ${outbound}, so it is the blocking license.${source}`;
  },

  // The verbatim matrix reading behind a finding, shown small under the reason
  // so the claim is traceable to a specific cell.
  compatFindingRule(finding) {
    const outbound = this.compatReport.outbound;
    if (!finding.parsed || !finding.terms.length) return '';
    const term = finding.blockers[0] || finding.terms[0];
    if (!term.id) return `OSADL: ${term.token} not listed`;
    // The proprietary outbound is not a row of the matrix, so cite what it was
    // actually derived from rather than implying OSADL rated it.
    if (outbound === this.compatProprietaryId) {
      return term.status === 'compatible'
        ? `OSADL: every permissive outbound license accepts ${term.id}`
        : `OSADL: no permissive outbound license accepts ${term.id}`;
    }
    return `OSADL: outbound ${outbound}, inbound ${term.id}, ${this.compatStatusLabel(term.status).toLowerCase()}`;
  },

  // ---- outbound candidates ------------------------------------------------

  // Matrix identifiers this document already uses, so an equally good candidate
  // the project has already adopted outranks one that merely sorts first.
  get compatUsedLicenseIds() {
    const used = new Set();
    for (const subject of this.compatSubjects.subjects) {
      for (const alternative of licenseAlternatives(subject.expression)) {
        for (const token of alternative) {
          const id = resolveLicenseToken(token).id;
          if (id) used.add(id);
        }
      }
    }
    return used;
  },

  get compatCandidates() {
    const { subjects } = this.compatSubjects;
    if (subjectsKey === candidatesKey) return candidatesVal;
    candidatesVal = outboundCandidates(subjects, {
      limit: 12,
      prefer: this.compatUsedLicenseIds
    });
    candidatesKey = subjectsKey;
    return candidatesVal;
  },

  // True when nothing in the matrix clears the whole scope, which is the normal
  // answer for an OS image and worth saying out loud rather than implying.
  get compatHasCleanCandidate() {
    return this.compatCandidates.some((candidate) => candidate.conflict === 0);
  },

  // Candidates that actually beat the current outbound license. The ranking on
  // its own is not an answer: offered whole it lists options worse than the one
  // in use, and when the current pick already clears everything it is just the
  // matrix in tie-break order. Either way it reads as a recommendation to switch
  // when there is nothing to switch to, so the rail only shows these.
  get compatBetterCandidates() {
    const totals = this.compatReport.totals;
    const conflicts = totals.conflict.licenses;
    const review = totals.review.licenses;
    const current = this.compatReport.outbound;
    const used = this.compatUsedLicenseIds;
    return this.compatCandidates
      .filter(
        (candidate) =>
          candidate.id !== current &&
          (candidate.conflict < conflicts ||
            (candidate.conflict === conflicts && candidate.review < review))
      )
      .slice(0, 6)
      .map((candidate) => ({ ...candidate, used: used.has(candidate.id) }));
  },

  // ---- the matrix ---------------------------------------------------------

  // Only licenses the matrix actually rates are gridded: an unrated license
  // contributes a blank row and a blank column, which is noise. How many were
  // left out is reported next to the grid.
  get compatMatrix() {
    const { subjects } = this.compatSubjects;
    const key = `${subjectsKey}|${this.compatMatrixAll}`;
    if (key === matrixKey) return matrixVal;

    const rated = subjects
      .map((subject) => ({ ...subject, elementCount: subject.elements.length }))
      .filter((subject) => {
        // A grid axis needs one identifier, so only expressions that reduce to
        // a single rated license can be plotted.
        const alternatives = licenseAlternatives(subject.expression);
        if (alternatives.length !== 1 || alternatives[0].length !== 1) return false;
        return !!resolveLicenseToken(alternatives[0][0]).id;
      })
      .sort((a, b) => b.elementCount - a.elementCount || a.label.localeCompare(b.label));

    const limit = this.compatMatrixAll ? MATRIX_MAX : MATRIX_PREVIEW;
    const shown = rated.slice(0, limit);
    matrixVal = {
      ...buildCompatMatrix(shown),
      hidden: rated.length - shown.length,
      unrated: subjects.length - rated.length,
      capped: this.compatMatrixAll && rated.length > MATRIX_MAX
    };
    matrixKey = key;
    return matrixVal;
  },

  get compatMatrixCanExpand() {
    return this.compatMatrix.hidden > 0 || this.compatMatrixAll;
  },

  setCompatMatrixHover(row, col) {
    this.compatMatrixHover = row == null ? null : { row, col };
  },

  // The hovered cell spelled out, because "A is compatible with B" is ambiguous
  // and the direction is the whole point.
  get compatMatrixExplanation() {
    const hover = this.compatMatrixHover;
    const matrix = this.compatMatrix;
    if (!hover || !matrix.licenses[hover.row] || !matrix.licenses[hover.col]) return null;
    const outbound = matrix.licenses[hover.row];
    const inbound = matrix.licenses[hover.col];
    const cell = matrix.rows[hover.row].cells[hover.col];
    const verb = cell.same
      ? 'is the same license'
      : `${cell.status === 'conflict' ? 'cannot' : cell.status === 'compatible' ? 'can' : 'may be able to'} be included`;
    return {
      outbound: outbound.label,
      inbound: inbound.label,
      status: cell.status,
      label: cell.same ? 'Same license' : this.compatStatusLabel(cell.status),
      sentence: cell.same
        ? `A work licensed ${outbound.label} taking in ${inbound.label} ${verb}.`
        : `${inbound.label} ${verb} in a work licensed ${outbound.label}: ${STATUS_BLURB[cell.status]}.`
    };
  },

  // ---- view wiring --------------------------------------------------------

  setLicenseViewMode(mode) {
    this.licenseViewMode = mode;
    if (mode === 'compatibility' && !this.compatOutboundTouched && !this.compatOutbound) {
      this.compatOutbound = this.compatDefaultOutbound;
    }
    this._scheduleNavPush();
  },

  setCompatPanel(panel) {
    this.compatPanel = panel;
    this._scheduleNavPush();
  }
};
