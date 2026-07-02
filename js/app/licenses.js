import {
  displayLicenseExpression,
  renderLicenseExpression,
  extractSpdxLicenseId,
  resolveLicenseExpression,
  extractLicenseExpressionParts,
  spdxLicenseJsonUrl,
  spdxLicenseExceptionJsonUrl,
  spdxLicensePageUrl,
  spdxLicenseExceptionPageUrl
} from '../utils.js';

/* ==========================================================================
   Licenses
   License labels, expression resolution, and the license-text modal — which
   shows text embedded in the SBOM directly and otherwise fetches it from the
   SPDX License List on demand (cached in licenseTextCache).
   ========================================================================== */

const licenseTextCache = new Map(); // licenseId -> { name, text }

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
    if (id.includes('NoAssertion')) return 'NoAssertion';
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
  // Full license text embedded in the SBOM itself (simplelicensing_SimpleLicensingText
  // elements, e.g. Yocto's custom/CLOSED licenses) — no fetch needed.
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
    return this.licenseModalParts.length > 1 ? 'Licenses text' : 'License text';
  },
  licenseModalMainPageUrl() {
    if (this.licenseModalParts.length !== 1) return '';
    const part = this.licenseModalParts[0];
    if (part.kind === 'license') return spdxLicensePageUrl(part.id);
    if (part.kind === 'exception') return spdxLicenseExceptionPageUrl(part.id);
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
    // text inside the SBOM (e.g. Yocto's LicenseRef-PD) — use that instead of
    // fetching from the SPDX License List (where custom refs don't exist).
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
  }
};
