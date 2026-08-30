/**
 * Scoping: narrowing a document-wide answer to one part of the graph.
 *
 * Several views ask the same question of different data. A license
 * compatibility check is about one package and what it pulls in; a
 * vulnerability report is about one artifact and what it is really built from.
 * Both are a walk from a root over the dependency edge set plus build lineage,
 * so both live here, and a view differs only in the two knobs it sets.
 *
 * **Which edges** (`edgeTypes`). License obligations attach to distribution, so
 * a compatibility check can restrict the walk to the edges that put a component
 * inside what ships.
 *
 * A security scope must not do that, and the Zephyr sample shows why. Zephyr
 * records `hasPrerequisite` from `zephyr_final` to the object libraries the
 * image is linked from (`zephyr`, `app`, `arch__common`, `offsets`, ...), and
 * `hasPrerequisite` is one of the edges "distributed only" drops as
 * not-part-of-the-product. Narrowing a vulnerability report that way would
 * discard 27 packages that are literally the compiled contents of the binary.
 * The edge an SBOM chooses says how its producer models the build, not whether
 * the code runs, so {@link buildSecurityScope} always walks every dependency
 * edge, including optional, provided and prerequisite ones: a vulnerable build
 * tool or runtime-supplied library is a real finding even when it is not
 * shipped.
 *
 * **Which packages count** (`requireFiles`). Reachability alone is often too
 * generous: a build declares every component the manifest offers as an input,
 * whether or not a line of its code was compiled. In the bundled Zephyr sample
 * the closure of `zephyr_final` names 164 of the document's 165 packages, so
 * filtering on reachability hides nothing, while only 5 of its 69 `-sources`
 * packages carry a file. A CVE against one of the other 64 is a finding about
 * code that was never compiled in. Requiring a file contribution is what
 * separates the two.
 *
 * Be precise about what that test proves. "Carries no file" is a fact about the
 * document, not about the binary: a producer that records blobs, prebuilt
 * libraries or vendored code without listing files would look identical to one
 * whose component genuinely was not built. So the contribution test is a filter
 * a reader chooses, never a verdict the UI reaches on its own, and the callers
 * are expected to say how many findings it removed and offer them in one
 * click.
 *
 * @module lib/scope
 */

import { IMPACT_EDGE_TYPES } from './impact.js';

/**
 * How much of a scope's closure counts as "in scope".
 *
 * - `compiled`: only components that put a file into the artifact. The honest
 *   answer to "does this apply to what I ship?".
 * - `declared`: everything the closure names, matching what the dependency
 *   graph claims. Broader, and the right lens when auditing a manifest rather
 *   than a binary.
 * @type {ReadonlyArray<string>}
 */
export const SCOPE_REACH_MODES = ['compiled', 'declared'];

/**
 * @typedef {Object} ScopeInput
 * @property {Array<string>} roots - spdxIds to walk out from
 * @property {Map<string, Array<{id: string, rel: string}>>} impactChildIndex
 * @property {Map<string, Array<string>>} producedByBuildIndex - artifact -> builds that produced it
 * @property {Map<string, Array<string>>} buildInputIndex - build -> its inputs
 * @property {Map<string, Array<string>>} [containsIndex] - package -> contained element ids
 * @property {Map<string, Object>} [elementMap] - spdxId -> element
 * @property {Map<string, Array<Object>>} [relFromIndex]
 * @property {Map<string, Array<Object>>} [relToIndex]
 * @property {Set<string>} [edgeTypes] - edges to traverse, default every dependency edge
 * @property {boolean} [requireFiles] - keep only packages that carry a file
 */

/**
 * @typedef {Object} Scope
 * @property {Set<string>} elements - every element the walk reached
 * @property {Set<string>} packages - packages considered in scope
 * @property {number} reachedPackages - packages the closure named, before the
 *   contribution test; the gap against `packages.size` is what `requireFiles` removes
 * @property {boolean} fellBack - `requireFiles` was asked for but not applied,
 *   because nothing in the scope records a file (see {@link buildScope})
 */

/**
 * Walks everything reachable from `root`, over the dependency edge set plus
 * build lineage.
 *
 * Build lineage is not optional here. An image is linked from objects, not
 * "dependent" on them, so a pure dependency walk stops at the artifact and
 * reaches none of the sources that went into it. Stepping from an artifact back
 * to the build that produced it, and then to that build's inputs, is what
 * connects a shipped binary to the components it was compiled from.
 *
 * @param {ScopeInput} input
 * @returns {Set<string>}
 */
function reachableFrom({
  roots,
  impactChildIndex,
  producedByBuildIndex,
  buildInputIndex,
  edgeTypes = IMPACT_EDGE_TYPES
}) {
  const seen = new Set(roots);
  const queue = [...roots];
  let head = 0;
  const visit = (id) => {
    if (!id || seen.has(id)) return;
    seen.add(id);
    queue.push(id);
  };
  while (head < queue.length) {
    const node = queue[head++];
    for (const child of impactChildIndex?.get(node) || []) {
      if (child && edgeTypes.has(child.rel)) visit(child.id);
    }
    for (const build of producedByBuildIndex?.get(node) || []) {
      visit(build);
      for (const input of buildInputIndex?.get(build) || []) visit(input);
    }
  }
  return seen;
}

/**
 * Packages in `reached` that carry at least one file.
 *
 * Owning a file is the whole test. A source package is emitted for every
 * component the manifest offers, and the ones that were actually compiled are
 * exactly the ones the producer filled with files; the rest are declarations
 * with nothing behind them. There is no need to also check that the files are
 * reachable, because `contains` is itself a dependency edge, so reaching a
 * package always reaches everything in it.
 *
 * A package with no files is not evidence of absence on its own: producers
 * routinely emit a reference-only package alongside the source package that
 * carries the files (Zephyr's `-deps` / `-sources` pairs, linked by
 * `hasVariant`). Those twins are resolved afterwards, so a finding recorded
 * against the reference package is judged by whether its source twin shipped.
 *
 * @param {Set<string>} reached
 * @param {Map<string, Array<string>>} containsIndex
 * @param {Map<string, Object>} elementMap
 * @returns {Set<string>}
 */
function contributingPackages(reached, containsIndex, elementMap) {
  const contributing = new Set();
  for (const id of reached) {
    if (elementMap?.get(id)?.type !== 'software_Package') continue;
    for (const child of containsIndex?.get(id) || []) {
      if (elementMap?.get(child)?.type === 'software_File') {
        contributing.add(id);
        break;
      }
    }
  }
  return contributing;
}

/**
 * Extends a package set across `hasVariant` edges, in both directions.
 *
 * `hasVariant` says two packages describe the same component, so if either end
 * shipped, a finding against the other end is about code that shipped. Only the
 * edges among elements already reached are followed, so this widens the answer
 * without leaving the scope.
 *
 * @param {Set<string>} packages
 * @param {Set<string>} reached
 * @param {Map<string, Array<Object>>} relFromIndex
 * @param {Map<string, Array<Object>>} relToIndex
 * @returns {Set<string>}
 */
function withVariantTwins(packages, reached, relFromIndex, relToIndex) {
  const out = new Set(packages);
  const add = (id) => {
    if (id && reached.has(id)) out.add(id);
  };
  for (const id of [...packages]) {
    for (const rel of relFromIndex?.get(id) || []) {
      if (rel?.relationshipType !== 'hasVariant') continue;
      const targets = Array.isArray(rel.to) ? rel.to : [rel.to];
      targets.forEach(add);
    }
    for (const rel of relToIndex?.get(id) || []) {
      if (rel?.relationshipType !== 'hasVariant') continue;
      add(rel.from);
    }
  }
  return out;
}

/**
 * Walks a scope and reports what falls inside it.
 *
 * @param {ScopeInput} input
 * @returns {Scope}
 */
export function buildScope(input) {
  const { containsIndex, elementMap, relFromIndex, relToIndex, requireFiles } = input;

  const elements = reachableFrom(input);
  const reachedPackages = [...elements].filter(
    (id) => elementMap?.get(id)?.type === 'software_Package'
  );

  const declared = {
    elements,
    packages: new Set(reachedPackages),
    reachedPackages: reachedPackages.length,
    fellBack: false
  };
  if (!requireFiles) return declared;

  const contributing = contributingPackages(elements, containsIndex, elementMap);

  // Plenty of SBOMs record no files at all: a container scan or a dependency
  // manifest lists packages and nothing below them. There, "contributes no
  // file" is true of every package in the document and the test would answer
  // "nothing is in scope", silently emptying the report. That is the worst
  // possible failure for a vulnerability view, so when the scope contains
  // packages but none of them owns a file, the document simply does not carry
  // the detail the test needs: fall back to reachability and say so.
  if (!contributing.size && reachedPackages.length) return { ...declared, fellBack: true };

  return {
    elements,
    packages: withVariantTwins(contributing, elements, relFromIndex, relToIndex),
    reachedPackages: reachedPackages.length,
    fellBack: false
  };
}

/**
 * {@link buildScope} for the Security view: a single artifact, every dependency
 * edge, and `reach` choosing whether a declared-but-uncompiled component counts.
 *
 * @param {Object} input - as {@link ScopeInput}, with `root` and `reach`
 * @returns {Scope}
 */
export function buildSecurityScope({ root, reach, ...rest }) {
  const mode = SCOPE_REACH_MODES.includes(reach) ? reach : 'compiled';
  return buildScope({ ...rest, roots: [root], requireFiles: mode === 'compiled' });
}

/**
 * Whether a vulnerability applies within a scope.
 *
 * A finding counts when any package it is assessed against is in scope, when an
 * online scan matched it to an element in scope, or when `extraSubjects` names
 * one. Unassessed findings that name nothing at all are out of scope: a scope
 * answers "what applies to this artifact", and a finding with no subject cannot
 * answer it.
 *
 * `extraSubjects` exists because a VEX assessment is not the only way to attach
 * a vulnerability to a package. SPDX 3's `hasAssociatedVulnerability` says a
 * package has a vulnerability with no verdict attached, and an SBOM may use
 * only that, which would otherwise leave every one of its findings subjectless
 * and hidden by any scope.
 *
 * @param {Object} vuln - enriched vulnerability
 * @param {Set<string>} scopePackages
 * @param {Iterable<string>} [extraSubjects] - other elements the finding names
 * @returns {boolean}
 */
export function vulnInScope(vuln, scopePackages, extraSubjects) {
  if (!scopePackages) return true;
  for (const a of vuln?.assessments || []) {
    if (a?.packageId && scopePackages.has(a.packageId)) return true;
  }
  for (const m of vuln?.online?.matched || []) {
    if (m?.spdxId && scopePackages.has(m.spdxId)) return true;
  }
  for (const id of extraSubjects || []) {
    if (id && scopePackages.has(id)) return true;
  }
  return false;
}
