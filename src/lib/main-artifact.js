/**
 * "Main artifact" detection and reachability.
 *
 * An SBOM rarely flags which element is *the* thing it was written to describe:
 * the firmware image, the kernel, the shipped binary. This module scores every
 * element to guess that main build output (zephyr.elf, bzImage, ...) and, once
 * one is chosen, computes the "contribution set": everything that went into
 * producing or composing it. Nodes outside that set are the "orphan-ish" ones
 * the graph grays out.
 *
 * Both halves are pure so they can run in the parser and be unit-tested against
 * the bundled samples without a DOM.
 *
 * @module lib/main-artifact
 */

/** Relationship types whose `to` targets are build outputs (build → artifact). */
const OUTPUT_RELS = new Set(['hasOutput', 'generates']);

// Filename hints. Executable / firmware images read as final outputs; object
// files, archives and build metadata read as intermediates.
const IMAGE_NAME_RE = /\.(elf|bin|hex|img|efi|uf2|iso|axf|out)$/i;
const KERNEL_NAME_RE = /(^|\/)(bzimage|zimage|vmlinux|vmlinuz|u-boot|kernel|uimage)(\b|\.|$)/i;
const INTERMEDIATE_NAME_RE = /\.(a|o|lo|la|obj|ko|d|i|s|map|lst|dwo)$/i;
const METADATA_NAME_RE = /\.(cmake|ya?ml|json|txt|conf|config|dts|dtsi|ld|list|props)$/i;
const PREBUILT_NAME_RE = /(pre0|prebuilt|_pre\b|\.tmp\b)/i;

function normalizeTo(to) {
  return Array.isArray(to) ? to : to == null ? [] : [to];
}

function isCandidateType(type) {
  const t = String(type || '');
  return t.includes('File') || t.includes('Package');
}

/**
 * Scores every element as a candidate "main artifact" and returns them ranked.
 *
 * @param {Object} model
 * @param {Array<Object>} model.elements - all SPDX elements (need spdxId, type,
 *   name, software_primaryPurpose)
 * @param {Array<Object>} model.relationships - all relationship elements
 * @param {Set<string>|Array<string>} [model.rootElementIds] - declared SBOM roots
 * @returns {{candidates: Array<{id: string, name: string, score: number, reasons: string[]}>, auto: string|null}}
 *   `candidates` are score-desc (only those clearing the display threshold);
 *   `auto` is the top candidate when it's a confident, clear winner, else null.
 */
export function detectMainArtifactCandidates({
  elements = [],
  relationships = [],
  rootElementIds
}) {
  const roots = rootElementIds instanceof Set ? rootElementIds : new Set(rootElementIds || []);

  // Structural signal sets, collected in one pass over relationships.
  const buildOutputs = new Set(); // targets of hasOutput/generates
  const buildInputs = new Set(); // targets of hasInput (→ consumed, i.e. intermediate)
  const distributed = new Set(); // targets of hasDistributionArtifact
  const staticLinkSources = new Set(); // `from` of hasStaticLink (top of a link tree)
  const staticLinkTargets = new Set(); // `to` of hasStaticLink (a linked-in library)

  for (const rel of relationships) {
    const type = rel?.relationshipType;
    if (!type) continue;
    const tos = normalizeTo(rel.to);
    if (OUTPUT_RELS.has(type)) tos.forEach((id) => buildOutputs.add(id));
    else if (type === 'hasInput') tos.forEach((id) => buildInputs.add(id));
    else if (type === 'hasDistributionArtifact') tos.forEach((id) => distributed.add(id));
    else if (type === 'hasStaticLink') {
      if (rel.from) staticLinkSources.add(rel.from);
      tos.forEach((id) => staticLinkTargets.add(id));
    }
  }

  const candidates = [];
  for (const el of elements) {
    const id = el?.spdxId;
    if (!id || !isCandidateType(el.type)) continue;

    let score = 0;
    const reasons = [];
    const name = el.name || id;
    const purpose = el.software_primaryPurpose;

    if (purpose === 'application') {
      score += 45;
      reasons.push('Marked as an application');
    } else if (purpose === 'executable') {
      score += 42;
      reasons.push('Marked as an executable');
    } else if (purpose === 'library') {
      score += 8;
      reasons.push('Marked as a library');
    }

    let terminalOutput = false;
    if (buildOutputs.has(id)) {
      if (buildInputs.has(id)) {
        // Produced by one build but fed into another: an intermediate, not final.
        score += 6;
        reasons.push('Produced by a build (but also consumed as a build input)');
      } else {
        terminalOutput = true;
        score += 32;
        reasons.push('Terminal build output');
      }
    }

    if (distributed.has(id)) {
      score += 28;
      reasons.push('Published as a distribution artifact');
    }

    if (roots.has(id)) {
      score += 14;
      reasons.push('Declared as an SBOM root element');
    }

    // Root of the static-link tree (links libraries in, isn't itself linked in):
    // the classic shape of a final linked binary.
    if (staticLinkSources.has(id) && !staticLinkTargets.has(id)) {
      score += 14;
      reasons.push('Links other libraries into a final binary');
    }

    let imageName = false;
    if (KERNEL_NAME_RE.test(name)) {
      imageName = true;
      score += 26;
      reasons.push('Kernel / firmware image name');
    } else if (IMAGE_NAME_RE.test(name)) {
      imageName = true;
      score += 18;
      reasons.push('Executable image filename');
    }

    // A terminal build output whose name is an executable image is the textbook
    // "main output" (zephyr.elf, bzImage); nudge it clear of any final-package
    // sibling that merely wraps it.
    if (terminalOutput && imageName) {
      score += 8;
      reasons.push('Final build output image');
    }
    if (INTERMEDIATE_NAME_RE.test(name)) {
      score -= 30;
      reasons.push('Intermediate object / archive name');
    }
    if (METADATA_NAME_RE.test(name)) {
      score -= 24;
      reasons.push('Build-metadata filename');
    }
    if (PREBUILT_NAME_RE.test(name)) {
      score -= 14;
      reasons.push('Prebuilt / intermediate stage');
    }

    if (score > 0) candidates.push({ id, name, score, reasons });
  }

  candidates.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));

  // Only surface plausible candidates; a couple of weak name hits shouldn't fill
  // the picker.
  const DISPLAY_MIN = 12;
  const shown = candidates.filter((c) => c.score >= DISPLAY_MIN);

  // Auto-select only a confident, clear winner: high absolute score and a real
  // margin over the runner-up, so ambiguous SBOMs stay unset (the UI then just
  // offers to pick one).
  const AUTO_MIN = 40;
  const AUTO_MARGIN = 12;
  const top = shown[0];
  const second = shown[1];
  const auto =
    top && top.score >= AUTO_MIN && (!second || top.score - second.score >= AUTO_MARGIN)
      ? top.id
      : null;

  return { candidates: shown, auto };
}

/**
 * Builds the directed "contribution" adjacency: `a → {b, ...}` means b (and
 * whatever b reaches) contributed to producing or composing a. Spans dependency,
 * containment, linking, build lineage, and configuration edges so a walk from
 * the main artifact collects its whole ancestry.
 *
 * @param {Array<Object>} relationships
 * @returns {Map<string, Set<string>>}
 */
export function buildContributionAdjacency(relationships = []) {
  const adj = new Map();
  const add = (from, to) => {
    if (!from || !to || from === to) return;
    let set = adj.get(from);
    if (!set) {
      set = new Set();
      adj.set(from, set);
    }
    set.add(to);
  };

  for (const rel of relationships) {
    const type = rel?.relationshipType;
    if (!type) continue;
    const from = rel.from;
    const tos = normalizeTo(rel.to);
    switch (type) {
      // `from` is composed of / relies on `to`.
      case 'dependsOn':
      case 'contains':
      case 'hasStaticLink':
      case 'hasDynamicLink':
      case 'hasOptionalComponent':
      case 'hasPrerequisite':
      case 'hasProvidedDependency':
      case 'hasInput': // build → its inputs
      case 'ancestorOf': // root build → step builds
        tos.forEach((to) => add(from, to));
        break;
      // Output/config point the other way: the producer contributed to the target.
      case 'hasOutput':
      case 'generates':
      case 'configures':
        tos.forEach((to) => add(to, from));
        break;
      // Distribution: reach both the artifact and the package that ships it.
      case 'hasDistributionArtifact':
        tos.forEach((to) => {
          add(from, to);
          add(to, from);
        });
        break;
      default:
        break;
    }
  }
  return adj;
}

/**
 * Every element that (transitively) contributed to `rootId`, including `rootId`
 * itself. BFS over the contribution adjacency, capped for pathological graphs.
 *
 * @param {string} rootId
 * @param {Map<string, Set<string>>} adjacency
 * @param {{cap?: number}} [opts]
 * @returns {Set<string>}
 */
export function contributionSet(rootId, adjacency, opts = {}) {
  const cap = opts.cap ?? 50000;
  const seen = new Set();
  if (!rootId) return seen;
  seen.add(rootId);
  const queue = [rootId];
  let head = 0;
  while (head < queue.length) {
    const node = queue[head++];
    const next = adjacency.get(node);
    if (!next) continue;
    for (const to of next) {
      if (seen.has(to)) continue;
      if (seen.size >= cap) return seen;
      seen.add(to);
      queue.push(to);
    }
  }
  return seen;
}
