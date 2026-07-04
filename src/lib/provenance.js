/**
 * Provenance / identifier helpers: external identifiers (PackageURL, CPE),
 * CycloneDX property surfacing, and vulnerability lookups.
 *
 * @module lib/provenance
 */
import { isMeaningfulValue } from './format.js';

const EXTERNAL_ID_LABELS = {
  cve: 'CVE',
  packageUrl: 'PackageURL',
  cpe22: 'CPE 2.2',
  cpe23: 'CPE 2.3',
  gitoid: 'gitoid',
  swid: 'SWID',
  swhid: 'SWHID',
  urlScheme: 'URL',
  securityOther: 'Security ref',
  other: 'Other'
};

/**
 * Resolves an element's externalIdentifier entries (PackageURL, CPE, gitoid, …)
 * into display rows, keeping only those with a meaningful value.
 *
 * @param {Object} element
 * @returns {Array<{type: string, label: string, identifier: string, isUrl: boolean}>}
 */
export function getExternalIdentifiers(element) {
  const ids = element?.externalIdentifier;
  if (!Array.isArray(ids)) return [];
  return ids
    .filter((id) => id && isMeaningfulValue(id.identifier))
    .map((id) => {
      const type = id.externalIdentifierType || 'other';
      const identifier = String(id.identifier).trim();
      return {
        type,
        label: EXTERNAL_ID_LABELS[type] || type,
        identifier,
        isUrl: /^https?:\/\//i.test(identifier)
      };
    });
}

// Verbose CycloneDX properties (serialized JSON blobs), sorted after the
// concise scalar properties so the useful bits stay at the top of the list.
const CDX_VERBOSE_PROPERTIES = new Set([
  'hashes',
  'licenses',
  'evidence',
  'externalReferences',
  'metadataTools',
  'metadataAuthors'
]);

/**
 * Parses a CycloneDX property value that carries serialized JSON. Returns the
 * parsed object/array, or null when the value is a plain scalar string.
 *
 * @param {string} value
 * @returns {Object|Array|null}
 */
function parseCdxJsonValue(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!(trimmed.startsWith('{') || trimmed.startsWith('['))) return null;
  try {
    const parsed = JSON.parse(trimmed);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * Flattens the CycloneDX properties an element carries via the SPDX 3
 * CdxPropertiesExtension. Each entry keeps its raw property name, the string
 * value, and (when the value is serialized JSON) a pretty-printed form.
 *
 * @see https://spdx.github.io/spdx-spec/v3.0.1/model/Extension/Classes/CdxPropertiesExtension/
 * @param {Object} element - The SPDX element
 * @returns {Array<{name: string, value: string, json: (Object|Array|null), pretty: string}>}
 */
export function getCdxProperties(element) {
  const raw = element?.extension;
  if (!raw) return [];
  const extensions = Array.isArray(raw) ? raw : [raw];
  const entries = [];
  for (const ext of extensions) {
    const props = ext?.extension_cdxProperty;
    if (!Array.isArray(props)) continue;
    for (const prop of props) {
      const name = prop?.extension_cdxPropName;
      if (name == null) continue;
      const value = prop?.extension_cdxPropValue;
      // Drop entries with no meaningful value.
      if (!isMeaningfulValue(value)) continue;
      const json = parseCdxJsonValue(String(value));
      entries.push({
        name,
        value: String(value).trim(),
        json,
        pretty: json ? JSON.stringify(json, null, 2) : ''
      });
    }
  }
  // Concise scalar properties first; verbose JSON blobs last.
  return entries.sort(
    (a, b) =>
      Number(CDX_VERBOSE_PROPERTIES.has(a.name)) - Number(CDX_VERBOSE_PROPERTIES.has(b.name))
  );
}

/**
 * Splits a string on an unescaped separator (CPE 2.3 escapes special chars with
 * a backslash, e.g. `foo\:bar`).
 *
 * @param {string} str
 * @param {string} sep - single character separator
 * @returns {string[]}
 */
function splitUnescaped(str, sep) {
  const out = [];
  let cur = '';
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    if (ch === '\\' && i + 1 < str.length) {
      cur += ch + str[i + 1];
      i++;
      continue;
    }
    if (ch === sep) {
      out.push(cur);
      cur = '';
      continue;
    }
    cur += ch;
  }
  out.push(cur);
  return out;
}

/**
 * Parses a CPE 2.2 URI (`cpe:/a:vendor:product:version`) or CPE 2.3 formatted
 * string (`cpe:2.3:part:vendor:product:version:…`) into its leading fields.
 * `*` / `-` / empty are normalized to '' (ANY / N-A).
 *
 * @param {string} identifier
 * @returns {{part: string, vendor: string, product: string, version: string}|null}
 */
export function parseCpe(identifier) {
  const raw = String(identifier || '').trim();
  if (!raw) return null;

  let fields;
  if (/^cpe:2\.3:/i.test(raw)) {
    fields = splitUnescaped(raw.slice('cpe:2.3:'.length), ':');
  } else if (/^cpe:\//i.test(raw)) {
    fields = raw.slice('cpe:/'.length).split(':');
  } else {
    return null;
  }

  const clean = (v) => {
    if (v == null) return '';
    const s = v.replace(/\\(.)/g, '$1').trim();
    return s === '*' || s === '-' ? '' : s;
  };

  return {
    part: clean(fields[0]),
    vendor: clean(fields[1]),
    product: clean(fields[2]),
    version: clean(fields[3])
  };
}

/**
 * Builds a vulnerability-database lookup link for a package/tool external
 * identifier. Only CPEs (cpe22/cpe23) are linked. Searches cve.org by the CPE's
 * product name, which tolerates the wildcard part/vendor fields that NVD's
 * exact-CPE search rejects.
 *
 * @param {{type: string, identifier: string}} eid
 * @returns {{url: string, label: string}|null}
 */
export function getVulnerabilityLookup(eid) {
  if (!eid || !isMeaningfulValue(eid.identifier)) return null;
  if (eid.type !== 'cpe22' && eid.type !== 'cpe23') return null;

  const cpe = parseCpe(eid.identifier);
  if (!cpe || !cpe.product) return null;

  // CPE products use '_' for spaces.
  const product = cpe.product.replace(/_/g, ' ');
  return {
    url: 'https://www.cve.org/CVERecord/SearchResults?query=' + encodeURIComponent(product),
    label: `Search cve.org for "${product}" CVEs`
  };
}
