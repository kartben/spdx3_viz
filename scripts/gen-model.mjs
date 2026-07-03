#!/usr/bin/env node
/**
 * SPDX model code generator.
 *
 * Derives the machine-readable slice of the SPDX model (class names, property
 * names, the subclass hierarchy, and enumerated vocabularies) from the official
 * SHACL/OWL model published by the SPDX project, and writes one ES module per
 * version to js/generated/. The visualizer imports these so its SPDX type
 * strings are validated against the spec instead of being hand-maintained.
 *
 * The model is read from the canonical Turtle (`spdx-model.ttl`) — the same
 * SHACL/OWL artifact shacl2code / spdx-python-model consume — parsed with N3
 * (a dev-only dependency; nothing here ships to the browser). The JSON-LD
 * `spdx-context.jsonld` is still read to cross-check the IRI -> term naming rule.
 *
 * Usage:
 *   node scripts/gen-model.mjs            # regenerate every version
 *   node scripts/gen-model.mjs 3.0.1      # regenerate only the listed version(s)
 *   node scripts/gen-model.mjs --check    # fail if committed output is stale
 *
 * Offline / reproducible builds: set SPDX_MODEL_DIR to a directory containing
 * <version>/spdx-context.jsonld and <version>/spdx-model.ttl and the model is
 * read from disk instead of fetched.
 *
 * @module scripts/gen-model
 */

import { writeFileSync, readFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { Parser } from 'n3';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const OUT_DIR = join(ROOT, 'js', 'generated');

/**
 * Versions to generate. Each version's RDF artifacts live under a stable base
 * URL on the SPDX spec site. 3.0.1 is what the app targets today; 3.1 / 3.1-dev
 * are generated so the model is ready to switch to.
 */
const VERSIONS = [
  { id: '3.0.1', base: 'https://spdx.github.io/spdx-spec/v3.0.1/rdf/' },
  { id: '3.1', base: 'https://spdx.github.io/spdx-spec/v3.1/rdf/' },
  { id: '3.1-dev', base: 'https://spdx.github.io/spdx-spec/v3.1-dev/rdf/' }
];

const RDF = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#';
const RDFS = 'http://www.w3.org/2000/01/rdf-schema#';
const OWL = 'http://www.w3.org/2002/07/owl#';

const RDF_TYPE = `${RDF}type`;
const RDFS_SUBCLASS_OF = `${RDFS}subClassOf`;
const OWL_CLASS = `${OWL}Class`;
const OWL_DATATYPE_PROPERTY = `${OWL}DatatypeProperty`;
const OWL_OBJECT_PROPERTY = `${OWL}ObjectProperty`;
const OWL_NAMED_INDIVIDUAL = `${OWL}NamedIndividual`;

/**
 * Reads a model artifact as text, from SPDX_MODEL_DIR when set (offline) or over
 * the network otherwise.
 * @param {{id: string, base: string}} version
 * @param {string} file
 * @returns {Promise<string>}
 */
async function loadText(version, file) {
  const dir = process.env.SPDX_MODEL_DIR;
  if (dir) return readFileSync(join(dir, version.id, file), 'utf8');
  const url = version.base + file;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`fetch ${url} -> HTTP ${res.status}`);
  return res.text();
}

/**
 * Reads and parses a JSON model artifact.
 * @param {{id: string, base: string}} version
 * @param {string} file
 * @returns {Promise<any>}
 */
async function loadJson(version, file) {
  return JSON.parse(await loadText(version, file));
}

/**
 * Converts a model IRI (.../terms/<Profile>/<LocalName>) to the term name used
 * in the SPDX JSON-LD serialization: the Core profile is dropped, every other
 * profile becomes a lowercased prefix (Software -> software_, AI -> ai_, ...).
 * This exact rule is checked against the JSON-LD @context in validateNaming().
 * @param {string} iri
 * @returns {string|null}
 */
function iriToTerm(iri) {
  const m = /\/terms\/([^/]+)\/([^/]+)$/.exec(iri);
  if (!m) return null;
  const [, profile, local] = m;
  return profile === 'Core' ? local : `${profile.toLowerCase()}_${local}`;
}

/**
 * Asserts that iriToTerm() reproduces every class/property term declared in the
 * JSON-LD @context. If the SPDX project ever changes the naming convention this
 * throws loudly rather than emitting a subtly wrong model.
 * @param {any} context
 */
function validateNaming(context) {
  const ctx = context['@context'] || {};
  const bad = [];
  for (const [key, val] of Object.entries(ctx)) {
    const iri = typeof val === 'string' ? val : val && typeof val === 'object' ? val['@id'] : null;
    if (!iri || !iri.startsWith('http') || !iri.includes('/terms/')) continue;
    if (!/\/terms\/[^/]+\/[^/]+$/.test(iri)) continue; // skip the bare `spdx` prefix
    const term = iriToTerm(iri);
    if (term !== key) bad.push(`  context "${key}" != derived("${iri}") = "${term}"`);
  }
  if (bad.length) {
    throw new Error(`SPDX naming convention changed:\n${bad.join('\n')}`);
  }
}

/**
 * Extracts classes, properties, the subclass hierarchy and enumerated
 * vocabularies from the Turtle SHACL/OWL model.
 * @param {string} ttl - Contents of spdx-model.ttl
 */
function buildModel(ttl) {
  const quads = new Parser().parse(ttl);

  // Index the two predicates we care about by subject IRI (ignoring blank-node
  // subjects, e.g. the owl:Restriction / sh:property shapes).
  /** @type {Map<string, Set<string>>} */
  const typesOf = new Map();
  /** @type {Map<string, Set<string>>} */
  const supersOf = new Map();
  const add = (map, key, value) => {
    let set = map.get(key);
    if (!set) map.set(key, (set = new Set()));
    set.add(value);
  };

  for (const { subject, predicate, object } of quads) {
    if (subject.termType !== 'NamedNode') continue;
    if (predicate.value === RDF_TYPE && object.termType === 'NamedNode') {
      add(typesOf, subject.value, object.value);
    } else if (
      predicate.value === RDFS_SUBCLASS_OF &&
      object.termType === 'NamedNode' &&
      object.value.includes('/terms/') // named superclasses only, not restrictions
    ) {
      add(supersOf, subject.value, object.value);
    }
  }

  const classes = new Set();
  const properties = new Set();
  /** @type {Object<string, Set<string>>} */
  const superclasses = {};
  /** @type {Object<string, Set<string>>} */
  const vocabularies = {};

  for (const [iri, types] of typesOf) {
    if (types.has(OWL_CLASS)) {
      const term = iriToTerm(iri);
      if (term) {
        classes.add(term);
        const supers = [...(supersOf.get(iri) || [])].map(iriToTerm).filter(Boolean);
        if (supers.length) {
          const set = (superclasses[term] ||= new Set());
          supers.forEach((s) => set.add(s));
        }
      }
    }

    if (types.has(OWL_DATATYPE_PROPERTY) || types.has(OWL_OBJECT_PROPERTY)) {
      const term = iriToTerm(iri);
      if (term) properties.add(term);
    }

    if (types.has(OWL_NAMED_INDIVIDUAL)) {
      // A NamedIndividual is typed by owl:NamedIndividual plus its vocabulary
      // class (e.g. .../Core/RelationshipType); the member value is the IRI's
      // last path segment, matching how it appears in the JSON serialization.
      const vocabIri = [...types].find((t) => t.includes('/terms/') && !t.startsWith(OWL));
      if (vocabIri) {
        const vt = iriToTerm(vocabIri);
        const member = iri.slice(iri.lastIndexOf('/') + 1);
        if (vt && member) (vocabularies[vt] ||= new Set()).add(member);
      }
    }
  }

  return { classes, properties, superclasses, vocabularies };
}

/**
 * Renders the generated ES module for a version. Output is deterministic
 * (everything sorted) so the drift check produces stable diffs.
 * @param {{id: string, base: string}} version
 * @param {ReturnType<typeof buildModel>} model
 */
function serialize(version, model) {
  const sorted = (set) => [...set].sort();
  const j = (x) => JSON.stringify(x);

  const setLiteral = (name, values) =>
    `export const ${name} = new Set([\n${values.map((v) => `  ${j(v)}`).join(',\n')}\n]);`;

  const mapLiteral = (name, map) => {
    const keys = Object.keys(map).sort();
    if (!keys.length) return `export const ${name} = {};`;
    const body = keys.map((k) => `  ${j(k)}: [${sorted(map[k]).map(j).join(', ')}]`).join(',\n');
    return `export const ${name} = {\n${body}\n};`;
  };

  return `// @generated by scripts/gen-model.mjs from the official SPDX model — DO NOT EDIT.
// Source: ${version.base}spdx-model.ttl
// Regenerate with \`npm run gen:model\`.
//
// The machine-readable slice of the SPDX ${version.id} model: class names,
// property names, the subclass hierarchy (rdfs:subClassOf) and enumerated
// vocabularies, derived directly from the SPDX SHACL/OWL model. Application
// logic lives in js/parser.js; this file only mirrors the spec vocabulary.

export const SPDX_VERSION = ${j(version.id)};
export const SPDX_MODEL_SOURCE = ${j(`${version.base}spdx-model.ttl`)};

/** Every class name, exactly as it appears as \`type\` in SPDX JSON-LD. */
${setLiteral('CLASSES', sorted(model.classes))}

/** Every property name, exactly as it appears as an object key in SPDX JSON-LD. */
${setLiteral('PROPERTIES', sorted(model.properties))}

/** Direct superclass(es) of each class (rdfs:subClassOf), keyed by class name. */
${mapLiteral('SUPERCLASSES', model.superclasses)}

/** Enumerated vocabularies: vocabulary/enum type name -> member value names. */
${mapLiteral('VOCABULARIES', model.vocabularies)}
`;
}

/**
 * Fetches and builds the generated module string for one version.
 * @param {{id: string, base: string}} version
 */
async function generateOne(version) {
  const [context, ttl] = await Promise.all([
    loadJson(version, 'spdx-context.jsonld'),
    loadText(version, 'spdx-model.ttl')
  ]);
  validateNaming(context);
  const built = buildModel(ttl);
  const out = serialize(version, built);
  const stats = {
    classes: built.classes.size,
    properties: built.properties.size,
    subclassOf: Object.keys(built.superclasses).length,
    vocabularies: Object.keys(built.vocabularies).length
  };
  return { out, stats };
}

async function main() {
  const args = process.argv.slice(2);
  const check = args.includes('--check');
  const wanted = args.filter((a) => !a.startsWith('--'));
  const versions = wanted.length ? VERSIONS.filter((v) => wanted.includes(v.id)) : VERSIONS;
  if (wanted.length && versions.length !== wanted.length) {
    const known = VERSIONS.map((v) => v.id).join(', ');
    throw new Error(`unknown version(s); known versions: ${known}`);
  }

  if (!check) mkdirSync(OUT_DIR, { recursive: true });

  let drift = false;
  for (const version of versions) {
    const { out, stats } = await generateOne(version);
    const file = join(OUT_DIR, `spdx-model.${version.id}.js`);
    const rel = `js/generated/spdx-model.${version.id}.js`;
    if (check) {
      const current = existsSync(file) ? readFileSync(file, 'utf8') : '';
      if (current !== out) {
        drift = true;
        console.error(`DRIFT  ${rel} is out of date — run \`npm run gen:model\``);
      } else {
        console.log(`ok     ${rel}`);
      }
    } else {
      writeFileSync(file, out);
      console.log(
        `wrote  ${rel}  (${stats.classes} classes, ${stats.properties} properties, ` +
          `${stats.subclassOf} subclass links, ${stats.vocabularies} vocabularies)`
      );
    }
  }

  if (check && drift) process.exit(1);
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
