/**
 * Experimental CPE product-name normalization, to test whether cheap,
 * data-free normalization can lift the NVD CPE match rate for SBOMs whose CPEs
 * are generator guesses (e.g. Syft emitting `cpe:2.3:a:libpam0g:libpam0g:...`
 * when NVD knows the product under a different name).
 *
 * Pure and side-effect-free so it can be unit tested and imported by the
 * measurement script without triggering a network run.
 *
 * @module scripts/cpe-normalize
 */

// Illustrative seed of binary/soname -> NVD-ish product tokens. A real mapping
// would come from a curated source (e.g. distro source-package tables, or
// Grype's cpe hints); this is only enough to demonstrate the concept in the
// measurement, and the run reports how much it actually helps.
export const PRODUCT_ALIASES = {
  libpam0g: 'linux_pam',
  'libpam-modules': 'linux_pam',
  'libpam-runtime': 'linux_pam',
  libssl3: 'openssl',
  libssl1: 'openssl',
  libcrypto: 'openssl',
  libgnutls30: 'gnutls',
  zlib1g: 'zlib',
  libzstd1: 'zstd',
  liblz4: 'lz4',
  libgcrypt20: 'libgcrypt',
  libsystemd0: 'systemd',
  libudev1: 'systemd',
  libc6: 'glibc',
  libc: 'glibc'
};

/**
 * Lowercases and strips a package epoch/revision noise from a raw CPE token.
 * @param {string} s
 * @returns {string}
 */
function base(s) {
  return String(s || '')
    .trim()
    .toLowerCase();
}

/**
 * Generates candidate product tokens for a raw CPE product, cheapest/safest
 * transforms first. Data-free: separator unification, `lib` prefix removal, and
 * trailing soname/version stripping (`libpam0g` → `pam`, `libcurl4` → `curl`).
 *
 * @param {string} product
 * @returns {string[]} de-duplicated candidate tokens, most-specific first
 */
export function productVariants(product) {
  const p = base(product);
  if (!p) return [];
  const out = [];
  const add = (v) => {
    if (v && !out.includes(v)) out.push(v);
  };

  add(p);
  add(p.replace(/-/g, '_'));
  add(p.replace(/_/g, '-'));
  add(p.replace(/[-_]/g, ''));

  // Drop a leading `lib`, then strip a trailing soname/version (digits + optional
  // letters): libpam0g -> pam, libssl3 -> ssl, libexpat1 -> expat, libcurl4 -> curl.
  const noLib = p.replace(/^lib/, '');
  if (noLib !== p) {
    add(noLib);
    add(noLib.replace(/[-_]/g, ''));
  }
  const stripped = noLib.replace(/[0-9]+[a-z]*$/, '').replace(/[-_]+$/, '');
  if (stripped && stripped.length >= 2) {
    add(stripped);
    add(stripped.replace(/[-_]/g, ''));
  }

  // Curated alias, if any (tried last as the strongest but least general).
  const alias = PRODUCT_ALIASES[p] || PRODUCT_ALIASES[noLib];
  if (alias) add(alias);

  return out;
}

/**
 * Candidate vendor tokens (same lexical transforms; vendors are often equal to
 * the product in generator-guessed CPEs).
 * @param {string} vendor
 * @returns {string[]}
 */
export function vendorVariants(vendor) {
  return productVariants(vendor);
}

/**
 * Whether the curated alias map has an entry for this product (used to attribute
 * the marginal lift the alias step provides).
 * @param {string} product
 * @returns {string|null}
 */
export function aliasFor(product) {
  const p = base(product);
  return PRODUCT_ALIASES[p] || PRODUCT_ALIASES[p.replace(/^lib/, '')] || null;
}
