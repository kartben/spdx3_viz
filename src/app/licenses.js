import {
  displayLicenseExpression,
  renderLicenseExpression,
  licenseIndividualLabel,
  licenseIndividualInfo,
  licenseIndividualToken,
  extractSpdxLicenseId,
  resolveLicenseExpression,
  extractLicenseExpressionParts,
  spdxLicenseJsonUrl,
  spdxLicenseExceptionJsonUrl,
  spdxLicensePageUrl,
  spdxLicenseExceptionPageUrl,
  loadOsadlMatrix,
  analyzeSbomLicenses,
  compatStatusMeta,
  describeCompatibility,
  formatMatrixTimestamp,
  COMPAT_VERDICT_META,
  OSADL_CHECKLISTS_URL,
  OSADL_LICENSE
} from '../lib/index.js';

/* Licenses: labels, expression resolution, and the license-text modal, which
   shows SBOM-embedded text directly and otherwise fetches from the SPDX License
   List on demand (cached in licenseTextCache). Compatibility uses the bundled
   OSADL matrix (loaded once, kept off the reactive state). */

const licenseTextCache = new Map(); // licenseId -> { name, text }

const CANDIDATE_PREVIEW = 8;
const CONFLICT_PREVIEW = 8;

let osadlMatrix = null;
let osadlLoad = null;
let compatReportLicenses = null;
let compatReportMatrix = null;
let compatReportVal = null;

export const licensesMixin = {
  licenseUsers(id) {
    return this.licenseUsersIndex.get(id) || [];
  },
  licenseLabel(id) {
    const lic = this.licenses.find((l) => l.id === id);
    if (lic) return lic.label;
    const el = this.elementMap.get(id);
    if (el?.simplelicensing_licenseExpression) {
      return displayLicenseExpression(el, this.elementMap);
    }
    const expandedExpr = renderLicenseExpression(el, this.elementMap);
    if (expandedExpr) return expandedExpr;
    if (id.startsWith('https://spdx.org/licenses/')) {
      return id.replace('https://spdx.org/licenses/', '');
    }
    const individual = licenseIndividualLabel(id);
    if (individual) return individual;
    if (el?.name) return el.name;
    return this.cleanName(id);
  },
  elementLicenses(spdxId) {
    const entries = [];
    const seen = new Set();
    for (const rel of this.outgoingRels(spdxId)) {
      if (
        rel.relationshipType !== 'hasConcludedLicense' &&
        rel.relationshipType !== 'hasDeclaredLicense'
      ) {
        continue;
      }
      const kind = rel.relationshipType === 'hasDeclaredLicense' ? 'declared' : 'concluded';
      const targets = Array.isArray(rel.to) ? rel.to : [rel.to];
      for (const id of targets) {
        if (!id) continue;
        const key = `${kind}:${id}`;
        if (seen.has(key)) continue;
        seen.add(key);
        entries.push({ id, kind, label: this.licenseLabel(id) });
      }
    }
    return entries.sort((a, b) => {
      if (a.kind !== b.kind) return a.kind === 'concluded' ? -1 : 1;
      return a.label.localeCompare(b.label);
    });
  },
  // Licenses that name an actual license, dropping the ExpandedLicensing
  // NoAssertion / None individuals (they record the absence of one) and folding
  // a license that is both declared and concluded into one entry. List rows read
  // these so a scan isn't filled with "No assertion" and duplicate chips; the
  // expanded card still shows every license relationship.
  concreteLicenses(spdxId) {
    const seen = new Set();
    return this.elementLicenses(spdxId).filter((lic) => {
      if (licenseIndividualToken(lic.id) || seen.has(lic.label)) return false;
      seen.add(lic.label);
      return true;
    });
  },
  spdxLicenseIdFor(licenseRef) {
    return extractSpdxLicenseId(licenseRef, this.elementMap);
  },
  licenseExpressionFor(licenseRef) {
    return resolveLicenseExpression(licenseRef, this.elementMap);
  },
  licenseExpressionParts(licenseRef) {
    return extractLicenseExpressionParts(this.licenseExpressionFor(licenseRef));
  },
  spdxLicensePageUrl(licenseId) {
    return spdxLicensePageUrl(licenseId);
  },
  licenseModalActivePart() {
    return this.licenseModalParts[this.licenseModalActiveIndex] || null;
  },
  licenseModalLoading() {
    return this.licenseModalParts.some((part) => part.loading);
  },
  licenseModalError() {
    const active = this.licenseModalActivePart();
    return active?.error && !active?.text ? active.error : '';
  },
  licenseModalText() {
    return this.licenseModalActivePart()?.text || '';
  },
  // Full license text embedded in the SBOM itself
  // (simplelicensing_SimpleLicensingText elements) — no fetch needed.
  inlineLicenseText(licenseRef) {
    return this.elementMap.get(licenseRef)?.simplelicensing_licenseText || '';
  },
  canShowLicenseText(licenseRef) {
    return (
      !!this.inlineLicenseText(licenseRef) || this.licenseExpressionParts(licenseRef).length > 0
    );
  },
  licenseTextActionLabel(licenseRef) {
    return this.licenseExpressionParts(licenseRef).length > 1
      ? 'View licenses text'
      : 'View license text';
  },
  licenseModalHeadingLabel() {
    if (this.licenseModalActivePart()?.kind === 'individual') return 'SPDX definition';
    return this.licenseModalParts.length > 1 ? 'Licenses text' : 'License text';
  },
  licenseModalMainPageUrl() {
    if (this.licenseModalParts.length !== 1) return '';
    const part = this.licenseModalParts[0];
    if (part.kind === 'license') return spdxLicensePageUrl(part.id);
    if (part.kind === 'exception') return spdxLicenseExceptionPageUrl(part.id);
    if (part.kind === 'individual') return part.docUrl || '';
    return '';
  },
  closeLicenseModal() {
    this.licenseModalOpen = false;
    this.licenseModalParts = [];
    this.licenseModalActiveIndex = 0;
    this.licenseModalExpression = '';
  },
  licensePartCacheKey(part) {
    return `${part.kind}:${part.id}`;
  },
  createLicenseModalPart(part) {
    const label =
      part.kind === 'exception' && part.withLicense
        ? `${part.withLicense} WITH ${part.id}`
        : part.id;
    return {
      id: part.id,
      kind: part.kind,
      withLicense: part.withLicense || '',
      label,
      name: label,
      text: '',
      error: '',
      loading: false,
      loaded: false
    };
  },
  async fetchLicensePartText(part) {
    if (part.loaded) return; // text already resolved from the SBOM itself
    const cacheKey = this.licensePartCacheKey(part);
    const cached = licenseTextCache.get(cacheKey);
    if (cached) {
      part.name = cached.name;
      part.text = cached.text;
      part.loaded = true;
      part.loading = false;
      part.error = '';
      return;
    }

    part.loading = true;
    part.error = '';

    try {
      const url =
        part.kind === 'exception'
          ? spdxLicenseExceptionJsonUrl(part.id)
          : spdxLicenseJsonUrl(part.id);
      const res = await fetch(url);
      if (!res.ok) throw new Error(`Not found (${res.status})`);
      const data = await res.json();
      const text =
        part.kind === 'exception' ? data.licenseExceptionText || '' : data.licenseText || '';
      if (!text) throw new Error('No license text in response');
      const name = data.name || part.label;
      licenseTextCache.set(cacheKey, { name, text });
      part.name = name;
      part.text = text;
      part.loaded = true;
    } catch (err) {
      part.error = err.message || 'Failed to load license text';
    } finally {
      part.loading = false;
    }
  },
  async selectLicenseModalPart(index) {
    if (index < 0 || index >= this.licenseModalParts.length) return;
    this.licenseModalActiveIndex = index;
    const part = this.licenseModalParts[index];
    if (!part.loaded && !part.loading) {
      await this.fetchLicensePartText(part);
    }
  },
  async showLicenseText(licenseRef) {
    // ExpandedLicensing individuals (NoAssertion / None) have no license text;
    // show their verbatim SPDX definition instead of failing to parse them.
    const individual = licenseIndividualInfo(licenseRef);
    if (individual) {
      this.licenseModalOpen = true;
      this.licenseModalRef = licenseRef;
      this.licenseModalExpression = individual.label;
      this.licenseModalActiveIndex = 0;
      this.licenseModalParts = [
        {
          id: '',
          kind: 'individual',
          withLicense: '',
          label: individual.label,
          name: individual.summary,
          text: individual.detail,
          docUrl: individual.docUrl,
          error: '',
          loading: false,
          loaded: true
        }
      ];
      return;
    }

    // Text embedded in the SBOM: show it directly, no expression parsing/fetching.
    const inlineText = this.inlineLicenseText(licenseRef);
    if (inlineText) {
      const label = this.licenseLabel(licenseRef);
      this.licenseModalOpen = true;
      this.licenseModalRef = licenseRef;
      this.licenseModalExpression = label;
      this.licenseModalActiveIndex = 0;
      this.licenseModalParts = [
        {
          id: '',
          kind: 'inline',
          withLicense: '',
          label,
          name: label,
          text: inlineText,
          error: '',
          loading: false,
          loaded: true
        }
      ];
      return;
    }

    const expression = this.licenseExpressionFor(licenseRef);
    const parsedParts = extractLicenseExpressionParts(expression);

    this.licenseModalOpen = true;
    this.licenseModalRef = licenseRef;
    // Show the display form (custom LicenseRef ids resolved to names); the
    // raw expression is still what gets parsed into parts above.
    this.licenseModalExpression =
      displayLicenseExpression(this.elementMap.get(licenseRef), this.elementMap) || expression;
    this.licenseModalActiveIndex = 0;
    this.licenseModalParts = parsedParts.map((part) => this.createLicenseModalPart(part));

    // Custom LicenseRef-… parts: the expression element's customIdToUri map
    // points at simplelicensing_SimpleLicensingText elements carrying the full
    // text inside the SBOM — use that instead of fetching from the SPDX License
    // List, where custom refs don't exist.
    const customIdMap = this.elementMap.get(licenseRef)?.simplelicensing_customIdToUri || [];
    this.licenseModalParts.forEach((part) => {
      const entry = customIdMap.find((e) => e?.key === part.id);
      const textEl = entry && this.elementMap.get(entry.value);
      if (textEl?.simplelicensing_licenseText) {
        part.kind = 'inline';
        part.name = textEl.name || part.label;
        part.label = textEl.name || part.label;
        part.text = textEl.simplelicensing_licenseText;
        part.loaded = true;
      }
    });

    if (!parsedParts.length) {
      this.licenseModalParts = [
        {
          id: '',
          kind: 'license',
          withLicense: '',
          label: this.licenseLabel(licenseRef),
          name: this.licenseLabel(licenseRef),
          text: '',
          error: 'Could not parse this license expression.',
          loading: false,
          loaded: true
        }
      ];
      return;
    }

    await this.fetchLicensePartText(this.licenseModalParts[0]);
  },

  osadlChecklistsUrl() {
    return OSADL_CHECKLISTS_URL;
  },
  osadlLicenseId() {
    return OSADL_LICENSE;
  },

  async ensureLicenseCompat() {
    if (osadlMatrix) {
      this.licenseCompat.status = 'ready';
      this.licenseCompat.timestamp = osadlMatrix.timestamp;
      this.licenseCompat.error = '';
      return;
    }
    if (osadlLoad) return osadlLoad;
    this.licenseCompat.status = 'loading';
    osadlLoad = loadOsadlMatrix()
      .then((matrix) => {
        osadlMatrix = matrix;
        this.licenseCompat.status = 'ready';
        this.licenseCompat.timestamp = matrix.timestamp;
        this.licenseCompat.error = '';
      })
      .catch((err) => {
        osadlLoad = null;
        this.licenseCompat.status = 'error';
        this.licenseCompat.error = err.message || 'Failed to load the OSADL matrix';
      });
    return osadlLoad;
  },

  get licenseCompatReport() {
    if (this.licenseCompat.status !== 'ready' || !osadlMatrix) return null;
    if (compatReportLicenses === this.licenses && compatReportMatrix === osadlMatrix) {
      return compatReportVal;
    }
    compatReportVal = analyzeSbomLicenses(this.licenses, this.elementMap, osadlMatrix);
    compatReportLicenses = this.licenses;
    compatReportMatrix = osadlMatrix;
    return compatReportVal;
  },

  licenseCompatInfo(id) {
    return this.licenseCompatReport?.byId[id] || null;
  },

  licenseCompatKind(id) {
    return this.licenseCompatInfo(id)?.kind || '';
  },

  compatStatusMeta(status) {
    return compatStatusMeta(status);
  },

  licenseCompatVerdictMeta() {
    const verdict = this.licenseCompatReport?.verdict;
    return COMPAT_VERDICT_META[verdict] || COMPAT_VERDICT_META.incomplete;
  },

  formatOsadlDate() {
    return formatMatrixTimestamp(this.licenseCompat.timestamp);
  },

  licenseCompatHeadline() {
    const report = this.licenseCompatReport;
    if (!report) return { title: '', detail: '' };
    if (report.verdict === 'empty') {
      return { title: 'No licenses to check', detail: '' };
    }
    if (report.verdict === 'incomplete') {
      return {
        title: 'None of these licenses are in the OSADL matrix',
        detail:
          'Custom LicenseRef ids and uncommon licenses cannot be checked automatically. Open a license for its text.'
      };
    }
    if (report.verdict === 'blocked') {
      return {
        title: 'No OSADL outbound license covers this combination',
        detail:
          'Among the licenses OSADL knows, nothing can include every inbound license in this SBOM. That often means GPLv2 and Apache-2.0 together.'
      };
    }
    const sbomNames = report.sbomCandidates.map((c) => c.id);
    if (report.verdict === 'constrained') {
      if (sbomNames.length === 1) {
        return {
          title: `Shippable under ${sbomNames[0]}`,
          detail:
            'Some licenses in this SBOM cannot include others. Shipping under this one covers the combination OSADL knows about.'
        };
      }
      if (sbomNames.length > 1) {
        return {
          title: `Shippable under ${sbomNames[0]} or ${sbomNames[1]}${sbomNames.length > 2 ? ` (+${sbomNames.length - 2})` : ''}`,
          detail:
            'Some licenses in this SBOM cannot include others. Any of these already-used licenses can cover the rest.'
        };
      }
      return {
        title: 'Shippable, but not under a license already in this SBOM',
        detail:
          'None of the licenses already used can include the rest. Pick one of the outbound candidates below.'
      };
    }
    if (report.atomCount === 1) {
      return {
        title: `${report.atoms[0]} can cover this SBOM`,
        detail: `${report.candidates.length} outbound licenses in the OSADL matrix can include it.`
      };
    }
    return {
      title: 'These licenses can be combined',
      detail: `${report.candidates.length} outbound licenses in the OSADL matrix can cover this SBOM.`
    };
  },

  visibleCompatCandidates() {
    const all = this.licenseCompatReport?.candidates || [];
    if (this.licenseCompatShowAllCandidates) return all;
    return all.slice(0, CANDIDATE_PREVIEW);
  },

  hiddenCompatCandidateCount() {
    const total = this.licenseCompatReport?.candidates?.length || 0;
    if (this.licenseCompatShowAllCandidates) return 0;
    return Math.max(0, total - CANDIDATE_PREVIEW);
  },

  visibleCompatConflicts() {
    const all = this.licenseCompatReport?.conflicts || [];
    if (this.licenseCompatShowAllConflicts) return all;
    return all.slice(0, CONFLICT_PREVIEW);
  },

  hiddenCompatConflictCount() {
    const total = this.licenseCompatReport?.conflicts?.length || 0;
    return this.licenseCompatShowAllConflicts ? 0 : Math.max(0, total - CONFLICT_PREVIEW);
  },

  compatCellStatus(outbound, inbound) {
    return this.licenseCompatReport?.pairwise?.[outbound]?.[inbound] || 'undef';
  },

  compatCellDescription(outbound, inbound) {
    return describeCompatibility(outbound, inbound, this.compatCellStatus(outbound, inbound));
  },

  selectCompatCell(outbound, inbound) {
    this.licenseCompatCell = { outbound, inbound };
    this.licenseCompatPanel = 'matrix';
  },

  jumpToCompatLicense(atomId) {
    const sources = this.licenseCompatReport?.atomSources?.[atomId];
    const target = sources?.[0];
    if (target) this.navigateToLicense(target);
  },

  jumpToCandidate(candidate) {
    if (candidate?.inSbom) this.jumpToCompatLicense(candidate.id);
  },

  licenseCompatFilterCount(kind) {
    const byId = this.licenseCompatReport?.byId;
    if (!byId) return 0;
    let n = 0;
    for (const info of Object.values(byId)) {
      if (info.kind === kind) n++;
    }
    return n;
  }
};
