import {
  cleanName as formatSpdxName,
  cleanFileName as formatFileName,
  fileExt as getFileExtension,
  formatDate as formatDisplayDate,
  getRelationshipColor,
  getRelationshipGroupLabel,
  getRelationshipSortOrder,
  getRelationshipTargetDisplayName,
  getElementDisplayName,
  getDetailPromotedFields,
  getNodeType as resolveNodeType,
  getNodeTypeColor,
  getElementBadgeClass,
  elementIconSvg as elementIconMarkup,
  typeIconSvg as typeIconMarkup,
  iconSvg as iconMarkup,
  parseCompileFlags as parseBuildConfigFlags,
  parseBuildParameters as parseBuildParameterGroups,
  getToolUsageCount,
  getExternalIdentifiers,
  getPurlLink,
  getCdxProperties,
  snippetFileRef,
  snippetFileGroupLabel,
  snippetCompactLine,
  groupSnippetsByFile,
  isMeaningfulValue,
  enumValue,
  formatByteSize,
  formatQudtMeasure,
  formatHardwareDimensions,
  normalizeUrl,
  copyToClipboard,
  escapeHtml,
  licenseIndividualDescription,
  requirementDisplayName as formatRequirementDisplayName,
  producerMetaValue,
  isProducerMetaIdentifier,
  primaryPurposeLabel as formatPrimaryPurpose,
  splitFilePath,
  PACKAGE_GAP_META,
  PACKAGE_GAP_ORDER,
  PACKAGE_DESCRIPTION_SEGMENTS
} from '../lib/index.js';
import { COLORS, getScopeColor, SAFETY_ADEQUACY, SAFETY_STATUSES } from '../config.js';
import { CLASS, isA } from '../spdx/model.js';
import { loadHighlighter } from '../lib/highlight.js';

/* Element accessors and display helpers: thin lookups into the relationship
   indexes, name/date formatting, and the relationship-group data the detail
   panel renders. Most expose a util or index to templates as this.*(). */

// Preview cap per relationship group in the detail panel / expanded cards. A hub
// element can be tied to tens of thousands of relationships; mounting them all
// would freeze the page, so each group shows this many rows and reports the rest
// via a "+N more" indicator (mirrors agentLinkGroups' CAP).
const DETAIL_REL_CAP = 50;

// Grouped build parameters, memoized per build element (see buildParameters).
// Templates read them several times per card, and computing them for a large
// SBOM's builds each time is wasteful; keyed on the build object so a new SBOM's
// (fresh) objects miss and recompute.
const buildParameterCache = new WeakMap();

// Everything a collapsed Packages row shows, memoized per package element (see
// packageRowSummary). Without it each rendered card re-runs a dozen index
// lookups plus the VEX rollup on every reactive re-evaluation, which is what
// made scrolling a large package list stutter. Keyed on the element object, so a
// newly parsed document's (fresh) objects miss and recompute.
const packageRowCache = new WeakMap();

// Implementation / evidence groups for a requirement card, memoized per element
// so Alpine can read them several times per render without regrouping snippets.
const requirementImplCache = new WeakMap();
const requirementEvidenceCache = new WeakMap();
const EMPTY_SNIPPET_GROUPS = Object.freeze({ files: [], others: [], total: 0 });

// Licenses shown inline on a collapsed Packages row before the rest are summed up.
const ROW_LICENSE_CAP = 2;

export const accessorsMixin = {
  cleanName(spdxId) {
    return formatSpdxName(spdxId);
  },
  cleanFileName(spdxId) {
    return formatFileName(spdxId, this.elementMap);
  },
  fileExt(name) {
    return getFileExtension(name);
  },
  formatDate(date) {
    return formatDisplayDate(date);
  },
  depsOf(spdxId) {
    return this.depIndex.get(spdxId) || [];
  },
  dependentsOf(spdxId) {
    return this.dependentIndex.get(spdxId) || [];
  },
  containedFiles(spdxId) {
    return this.containsIndex.get(spdxId) || [];
  },
  parentPackage(spdxId) {
    return this.parentIndex.get(spdxId) || null;
  },
  fileTools(spdxId) {
    return this.toolIndex.get(spdxId) || [];
  },
  buildInputs(spdxId) {
    return this.buildInputIndex.get(spdxId) || [];
  },
  buildOutputs(spdxId) {
    return this.buildOutputIndex.get(spdxId) || [];
  },
  producedByBuilds(spdxId) {
    return this.producedByBuildIndex.get(spdxId) || [];
  },
  consumedByBuilds(spdxId) {
    return this.consumedByBuildIndex.get(spdxId) || [];
  },
  childBuilds(spdxId) {
    return this.buildStepIndex.get(spdxId) || [];
  },
  parentBuilds(spdxId) {
    return this.parentBuildIndex.get(spdxId) || [];
  },
  distributionArtifacts(spdxId) {
    return this.distributionArtifactIndex.get(spdxId) || [];
  },
  distributedBy(spdxId) {
    return this.distributedByIndex.get(spdxId) || [];
  },
  staticLinks(spdxId) {
    return this.staticLinkIndex.get(spdxId) || [];
  },
  configuresTargets(spdxId) {
    return this.configuresIndex.get(spdxId) || [];
  },
  configuredBy(spdxId) {
    return this.configuredByIndex.get(spdxId) || [];
  },
  // Fetches a file's source (via its raw URL) and caches it as a syntax-
  // highlighted list of lines. The Files view and the snippet popup both render
  // from this; neither knows anything about snippets.
  async loadFileSource(fileId) {
    if (this.fileSourceCache[fileId]) return;
    const url = this.fileSourceIndex.get(fileId);
    if (!url) return;
    const file = this.elementMap.get(fileId);

    this.fileSourceCache[fileId] = { loading: true, lines: null, error: null };

    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const content = await res.text();
      const lines = await this._highlightSource(content, file?.name);
      this.fileSourceCache[fileId] = {
        loading: false,
        error: null,
        lines,
        totalLines: lines.length
      };
    } catch (err) {
      this.fileSourceCache[fileId] = { loading: false, lines: null, error: err.message };
    }
  },
  // Syntax-highlights a whole file into [{ lineNum, html }], escaping to plain
  // text when no grammar matches. Async because highlight.js is loaded on first
  // use (see lib/highlight.js); a load failure falls back to plain text.
  async _highlightSource(content, fileName) {
    const ext = getFileExtension(fileName || '');
    const rawLines = content.split('\n');
    const escaped = rawLines.map(escapeHtml);

    let highlighted = null;
    const langMap = { '.c': 'c', '.h': 'c', '.cpp': 'cpp', '.py': 'python', '.js': 'javascript' };
    const lang = langMap[ext];
    try {
      const hljs = await loadHighlighter();
      const html = lang
        ? hljs.highlight(content, { language: lang, ignoreIllegals: true }).value
        : hljs.highlightAuto(content).value;
      highlighted = html.split('\n');
    } catch {
      highlighted = null;
    }

    return rawLines.map((_, i) => ({
      lineNum: i + 1,
      html: highlighted && highlighted[i] != null ? highlighted[i] : escaped[i]
    }));
  },
  outgoingRels(spdxId) {
    return this.relFromIndex.get(spdxId) || [];
  },
  incomingRels(spdxId) {
    return this.relToIndex.get(spdxId) || [];
  },

  buildSortName(build) {
    return (
      this.buildOutputs(build.spdxId)
        .map((id) => this.relTargetDisplayName(id))
        .join(' ') ||
      build.build_buildId ||
      build.spdxId ||
      ''
    );
  },

  buildDisplayName(build) {
    const outputs = this.buildOutputs(build.spdxId);
    if (outputs.length) {
      return outputs.map((id) => this.relTargetDisplayName(id)).join(', ');
    }
    return build.name || build.build_buildId || build.spdxId || 'Build';
  },

  formatCount(count) {
    return new Intl.NumberFormat().format(count || 0);
  },

  // Human "time left" label for a millisecond estimate: "~5s", "~1m 20s", "~2h 5m".
  formatEta(ms) {
    const secs = Math.max(0, Math.round((ms || 0) / 1000));
    if (secs < 60) return `~${secs}s`;
    const mins = Math.floor(secs / 60);
    const remSecs = secs % 60;
    if (mins < 60) return remSecs ? `~${mins}m ${remSecs}s` : `~${mins}m`;
    const hrs = Math.floor(mins / 60);
    const remMins = mins % 60;
    return remMins ? `~${hrs}h ${remMins}m` : `~${hrs}h`;
  },

  getBuildConfigFor(targetSpdxId) {
    const configs = this.configuredBy(targetSpdxId);
    if (!configs.length) return null;
    return this.elementMap.get(configs[0].configId);
  },

  parseCompileFlags(config) {
    return parseBuildConfigFlags(config);
  },
  // ⚠️ ZEPHYR SPECIAL CASE — read before touching. The build-parameter "token"
  // view (values split into chips coloured by compile-flag kind: -D, -I, -O,
  // -std=, -f…) is written ONLY for Zephyr, whose `urn:spdx.dev:zephyr-cmake`
  // builds store actual gcc/cmake command lines as parameters. Other producers
  // (notably Yocto/bitbake) dump unrelated, sometimes enormous strings there (a
  // single Yocto parameter can hold ~2000 tokens), where classifying every
  // token is both slow and meaningless. So we tokenize ONLY for Zephyr builds
  // and otherwise show the raw value (the template falls back to it when a
  // parameter has no tokens). Keep this narrow and obvious.
  _isZephyrCmakeBuild(build) {
    return build?.build_buildType === 'urn:spdx.dev:zephyr-cmake';
  },
  buildParameters(build) {
    if (!build || typeof build !== 'object') return []; // WeakMap key must be an object
    let cached = buildParameterCache.get(build);
    if (!cached) {
      cached = parseBuildParameterGroups(build, { tokenize: this._isZephyrCmakeBuild(build) });
      buildParameterCache.set(build, cached);
    }
    return cached;
  },
  buildParameterCount(build) {
    return this.buildParameters(build).reduce((count, group) => count + group.entries.length, 0);
  },
  buildParameterPreview(build) {
    return this.buildParameters(build)
      .flatMap((group) => group.entries)
      .slice(0, 3);
  },
  parameterTokenId(token) {
    if (typeof token === 'string') return token;
    return token?.renderKey || token?.id || this.parameterTokenText(token);
  },
  parameterTokenText(token) {
    if (typeof token === 'string') return token;
    return token?.display ?? token?.text ?? token?.value ?? '';
  },
  parameterTokenKind(token) {
    if (typeof token === 'string') return 'Value';
    return token?.kind || 'Value';
  },
  parameterTokenClass(token) {
    if (typeof token === 'string') return 'param-token param-token-value';
    return token?.className || 'param-token param-token-value';
  },
  toolUsageCount(spdxId) {
    return getToolUsageCount(spdxId, this.relationships);
  },
  externalIdentifiers(element) {
    return getExternalIdentifiers(element);
  },
  // Identifiers that are not producer rollup tags (adequacy, status, …). Those
  // already drive the status icon and filters; repeating them on the card
  // just adds a field list.
  requirementIdentifiers(element) {
    return this.externalIdentifiers(element).filter(
      (eid) => !isProducerMetaIdentifier(eid.identifier)
    );
  },
  purlLink(eid) {
    return getPurlLink(eid);
  },
  cdxProperties(element) {
    return getCdxProperties(element);
  },
  isMeaningful(value) {
    return isMeaningfulValue(value);
  },
  downloadUrl(value) {
    return normalizeUrl(value);
  },
  // The ExternalMap entry for an element imported by a loaded SpdxDocument
  // (referenced here but defined elsewhere), or null. Merged entry:
  // {locationHint, definingArtifact, verifiedUsing, importedBy}.
  externalRefFor(element) {
    if (!element?.spdxId) return null;
    return this.externalMap?.get(element.spdxId) || null;
  },
  relColor(type) {
    return getRelationshipColor(type);
  },
  // Colour for a lifecycle scope value, so the detail-panel scope badge reads the
  // same as the graph's scope legend chips.
  scopeColor(scope) {
    return getScopeColor(scope);
  },
  // CSS background for a graph edge-legend swatch, mirroring the line style the
  // edge is drawn with (solid / dotted / dashed / dash-dot) so the legend reads
  // the same as the graph.
  relEdgeSwatchStyle(filter) {
    const c = filter.color;
    switch (filter.lineStyle) {
      case 'dotted':
        return `background-image: repeating-linear-gradient(to right, ${c} 0 2px, transparent 2px 4px)`;
      case 'finedot':
        return `background-image: repeating-linear-gradient(to right, ${c} 0 1.5px, transparent 1.5px 3px)`;
      case 'dashed':
        return `background-image: repeating-linear-gradient(to right, ${c} 0 5px, transparent 5px 8px)`;
      case 'longdash':
        return `background-image: repeating-linear-gradient(to right, ${c} 0 8px, transparent 8px 12px)`;
      case 'dashdot':
        return `background-image: repeating-linear-gradient(to right, ${c} 0 5px, transparent 5px 7px, ${c} 7px 8px, transparent 8px 10px)`;
      case 'dashdotdot':
        return `background-image: repeating-linear-gradient(to right, ${c} 0 5px, transparent 5px 7px, ${c} 7px 8px, transparent 8px 9px, ${c} 9px 10px, transparent 10px 12px)`;
      case 'longdashdot':
        return `background-image: repeating-linear-gradient(to right, ${c} 0 8px, transparent 8px 10px, ${c} 10px 11px, transparent 11px 13px)`;
      default:
        return `background:${c}`;
    }
  },
  relGroupLabel(relType, direction) {
    return getRelationshipGroupLabel(relType, direction);
  },

  // Grouped relationship data for the detail panel. Parameterized on the
  // element so both the graph detail panel (this.detailElement) and the
  // expanded package card (its pkg) render the same grouped relationships.
  // `excludeKeys` drops relationship groups (by `<relType>:<direction>` key)
  // that are already surfaced by a dedicated section, e.g. the requirements
  // view renders `verifiedBy` as its own "Verification & evaluation" block.
  detailRelGroupsFor(element, { excludeKeys = null } = {}) {
    if (!element) return [];
    const id = element.spdxId;
    const groups = new Map(); // key → { label, color, items:[], total, hiddenCount }
    // Companion Sets keep dedup O(1): a hub element can be an endpoint of tens of
    // thousands of relationships, so an items.find() scan per edge would be
    // O(n^2). Each group also renders only a capped preview (the rest surface via
    // a "+N more" indicator), so we stop materializing items past DETAIL_REL_CAP
    // and just keep counting to report the true total / hidden count.
    const seen = new Map(); // key → Set<endpoint id>

    // Vulnerability associations are surfaced in the dedicated security
    // section, not the generic relationship list.
    const skip = (rel) => rel.relationshipType === 'hasAssociatedVulnerability';

    const excluded = excludeKeys ? new Set(excludeKeys) : null;

    const ensure = (key, relType, direction) => {
      let group = groups.get(key);
      if (!group) {
        group = {
          key,
          label: this.relGroupLabel(relType, direction),
          color: this.relColor(relType),
          sortOrder: this.relSortOrder(relType, direction),
          items: [],
          total: 0,
          hiddenCount: 0,
          // fileId → { ref, direction, snippetIds:[] }: snippet endpoints held
          // aside and folded in at the end (see below), one row per source file.
          snippetBuckets: new Map()
        };
        groups.set(key, group);
        seen.set(key, new Set());
      }
      return group;
    };

    // Materializes one row into a group, respecting the preview cap.
    const pushItem = (group, item) => {
      group.total++;
      if (group.items.length < DETAIL_REL_CAP) group.items.push(item);
      else group.hiddenCount++;
    };

    // Records one deduped endpoint in a group. Snippet endpoints are set aside
    // per source file (see the fold-in step after collection) so several ranges
    // of one file collapse into a single "N ranges" row; everything else
    // materializes a row immediately (up to the preview cap).
    const add = (key, endpointId, direction, scope) => {
      const set = seen.get(key);
      if (set.has(endpointId)) return;
      set.add(endpointId);
      const group = groups.get(key);

      const el = this.elementMap.get(endpointId);
      if (el?.type === 'software_Snippet') {
        const ref = snippetFileRef(el, this.elementMap);
        const fileKey = ref?.fileId || endpointId;
        let bucket = group.snippetBuckets.get(fileKey);
        if (!bucket) {
          bucket = { ref, direction, snippetIds: [] };
          group.snippetBuckets.set(fileKey, bucket);
        }
        bucket.snippetIds.push(endpointId);
        return;
      }

      pushItem(group, {
        id: endpointId,
        displayName: this.relTargetDisplayName(endpointId),
        direction,
        // LifecycleScopedRelationship scope (build / runtime / test / …)
        scope: scope || ''
      });
    };

    // Folds a file's snippet endpoints into a single row. One snippet reads as a
    // plain link into the file; several become one "N ranges" row that opens the
    // source popup with every range highlighted (see openSnippetRanges).
    const snippetRow = (bucket) => {
      const ids = bucket.snippetIds;
      const ordered = ids
        .map((id) => ({ id, el: this.elementMap.get(id) }))
        .sort(
          (a, b) =>
            (a.el?.software_lineRange?.beginIntegerRange ?? 0) -
            (b.el?.software_lineRange?.beginIntegerRange ?? 0)
        );
      if (ordered.length === 1) {
        return {
          id: ordered[0].id,
          displayName: this.relTargetDisplayName(ordered[0].id),
          direction: bucket.direction,
          scope: ''
        };
      }
      const orderedIds = ordered.map((s) => s.id);
      const base = bucket.ref?.baseName || 'snippet';
      return {
        id: orderedIds[0],
        displayName: snippetFileGroupLabel(
          base,
          ordered.map((s) => s.el)
        ),
        direction: bucket.direction,
        scope: '',
        multiRange: true,
        snippetIds: orderedIds
      };
    };

    // Outgoing: this element → targets
    (this.relFromIndex.get(id) || []).forEach((rel) => {
      if (skip(rel)) return;
      const key = rel.relationshipType + ':out';
      if (excluded?.has(key)) return;
      ensure(key, rel.relationshipType, 'out');
      const targets = Array.isArray(rel.to) ? rel.to : [rel.to];
      targets.forEach((t) => add(key, t, 'out', rel.scope));
    });

    // Incoming: sources → this element
    (this.relToIndex.get(id) || []).forEach((rel) => {
      if (skip(rel)) return;
      const key = rel.relationshipType + ':in';
      if (excluded?.has(key)) return;
      ensure(key, rel.relationshipType, 'in');
      add(key, rel.from, 'in', rel.scope);
    });

    // Fold each group's set-aside snippet endpoints into rows (one per file).
    for (const group of groups.values()) {
      for (const bucket of group.snippetBuckets.values()) pushItem(group, snippetRow(bucket));
      delete group.snippetBuckets;
    }

    return [...groups.values()].sort((a, b) => a.sortOrder - b.sortOrder);
  },

  // Grouped relationships for the currently graph-selected element.
  get detailRelGroups() {
    return this.detailRelGroupsFor(this.detailElement);
  },

  // True for Agent elements (Person / Organization / SoftwareAgent, or a bare
  // Agent) — the ones the Agents tab lists and gives a provenance-focused view.
  isAgent(el) {
    return this.getNodeType(el) === 'agent';
  },

  // Human-readable kind of an agent, used as the card/detail subtitle.
  agentTypeLabel(el) {
    switch (el?.type) {
      case 'Organization':
        return 'Organization';
      case 'Person':
        return 'Person';
      case 'SoftwareAgent':
        return 'Software agent';
      default:
        return 'Agent';
    }
  },

  // First email address carried by an agent's externalIdentifier list, or '' —
  // so templates can gate a mailto link on truthiness.
  agentEmail(el) {
    const ids = el?.externalIdentifier;
    if (!Array.isArray(ids)) return '';
    const email = ids.find((id) => id?.externalIdentifierType === 'email' && id?.identifier);
    return email?.identifier?.replace(/^mailto:/i, '') || '';
  },

  // How many elements an agent is tied to across all provenance roles, for the
  // list-card badge and the "most connected" sort.
  agentLinkCount(el) {
    const e = el && this.agentLinkIndex.get(el.spdxId);
    if (!e) return 0;
    return e.created.length + e.supplied.length + e.originated.length + e.manufactured.length;
  },

  // The provenance links an agent has, shaped like detailRelGroups so the detail
  // panel and the Agents-view card render them with the same template. Each group
  // is capped so a document-wide creator (createdBy on every element) can't mount
  // thousands of rows; the surplus is reported via hiddenCount.
  agentLinkGroups(el) {
    const entry = el && this.agentLinkIndex.get(el.spdxId);
    if (!entry) return [];
    const CAP = 50;
    const defs = [
      { bucket: 'created', label: 'Created', color: COLORS.createdBy },
      { bucket: 'manufactured', label: 'Manufacturer of', color: COLORS.hardware },
      { bucket: 'supplied', label: 'Supplier of', color: COLORS.distribution },
      { bucket: 'originated', label: 'Originator of', color: COLORS.package }
    ];
    const groups = [];
    for (const d of defs) {
      const ids = entry[d.bucket] || [];
      if (!ids.length) continue;
      groups.push({
        key: d.bucket,
        label: d.label,
        color: d.color,
        total: ids.length,
        hiddenCount: Math.max(0, ids.length - CAP),
        items: ids.slice(0, CAP).map((id) => ({ id, displayName: this.relTargetDisplayName(id) }))
      });
    }
    return groups;
  },

  // Resolves a package's agent-provenance references (suppliedBy / originatedBy)
  // into display rows, mirroring the "Supplier of" / "Originator of" links shown
  // from the Agent side. Each ref may be a bare spdxId or an inline agent object;
  // self-references and NoAssertion are dropped, duplicates collapsed, and an
  // inline name is preferred when the referenced agent isn't in the graph.
  _resolveAgentRefs(pkg, raw) {
    const arr = Array.isArray(raw) ? raw : raw == null || raw === '' ? [] : [raw];
    const out = [];
    const seen = new Set();
    for (const ref of arr) {
      let id = null;
      let name = '';
      if (typeof ref === 'string') {
        id = ref;
      } else if (ref && typeof ref === 'object') {
        id = ref.spdxId || null;
        name = ref.name || '';
      }
      if (id && (id === pkg?.spdxId || String(id).includes('NoAssertion'))) continue;
      const dedupKey = id || name;
      if (!dedupKey || seen.has(dedupKey)) continue;
      seen.add(dedupKey);
      // Prefer an inline name when the referenced agent isn't in the graph:
      // relTargetDisplayName would otherwise fall back to the raw/cleaned id.
      const displayName = !id
        ? name
        : name && !this.elementMap.has(id)
          ? name
          : this.relTargetDisplayName(id);
      out.push({ id, displayName });
    }
    return out;
  },

  // A file path split into the directory and the file name, so a list row can
  // lead with the name and let the (often far longer) path truncate instead of
  // truncating the name itself.
  fileBaseName(name) {
    return splitFilePath(name).base;
  },
  fileDirName(name) {
    return splitFilePath(name).dir;
  },
  packageGapMeta(key) {
    return PACKAGE_GAP_META[key] || { key, label: key, title: '' };
  },
  get packageGapOrder() {
    return PACKAGE_GAP_ORDER;
  },
  get packageDescriptionSegments() {
    return PACKAGE_DESCRIPTION_SEGMENTS;
  },

  // One memoized descriptor per collapsed Packages row: the badge counts, the
  // inline license chips, the VEX rollup, and the description gaps. Templates
  // read these several times per card, and a large SBOM renders hundreds of
  // cards, so they are computed once per package rather than per binding.
  packageRowSummary(pkg) {
    if (!pkg?.spdxId) return null;
    const cached = packageRowCache.get(pkg);
    if (cached) return cached;
    const id = pkg.spdxId;
    const licenses = this.concreteLicenses(id);
    const summary = {
      version: isMeaningfulValue(pkg.software_packageVersion)
        ? String(pkg.software_packageVersion)
        : '',
      purposeLabel: pkg.software_primaryPurpose
        ? formatPrimaryPurpose(pkg.software_primaryPurpose)
        : '',
      licenses: licenses.slice(0, ROW_LICENSE_CAP),
      extraLicenses: Math.max(0, licenses.length - ROW_LICENSE_CAP),
      deps: this.depsOf(id).length,
      dependents: this.dependentsOf(id).length,
      inputToBuilds: this.consumedByBuilds(id).length,
      producedByBuilds: this.producedByBuilds(id).length,
      artifacts: this.distributionArtifacts(id).length,
      vuln: this.packageVulnSummary(id)
    };
    packageRowCache.set(pkg, summary);
    return summary;
  },

  // Agent(s) that supplied this package (Artifact.suppliedBy / software_suppliedBy).
  packageSuppliers(pkg) {
    return this._resolveAgentRefs(pkg, pkg?.suppliedBy ?? pkg?.software_suppliedBy);
  },

  // Agent(s) that originated this package (Artifact.originatedBy / software_originatedBy).
  packageOriginators(pkg) {
    return this._resolveAgentRefs(pkg, pkg?.originatedBy ?? pkg?.software_originatedBy);
  },

  // Sort order for relationship groups (most relevant first)
  relSortOrder(type, dir) {
    return getRelationshipSortOrder(type, dir);
  },
  relTargetDisplayName(spdxId) {
    return getRelationshipTargetDisplayName(spdxId, this.elementMap);
  },
  // Tooltip explaining the ExpandedLicensing NoAssertion / None individuals;
  // '' (no tooltip) for any other license reference or relationship target.
  licenseIndividualTooltip(ref) {
    return licenseIndividualDescription(ref);
  },
  elementDisplayName(element) {
    return getElementDisplayName(element, this.elementMap);
  },
  detailPromotedFieldsFor(element) {
    return getDetailPromotedFields(element, this.elementMap);
  },
  get detailPromotedFields() {
    return this.detailPromotedFieldsFor(this.detailElement);
  },
  elementBadgeClass(type) {
    return getElementBadgeClass(type);
  },
  getNodeType(item) {
    return resolveNodeType(item);
  },
  nodeTypeColor(type) {
    return getNodeTypeColor(type);
  },
  // Inline Material-icon <svg> for the DOM UI (sidebar, detail panel, list rows,
  // graph legend). fill=currentColor, so callers tint via CSS/Tailwind colour.
  elementIcon(el, className) {
    return elementIconMarkup(el, className);
  },
  nodeTypeIconSvg(nodeType, className = 'w-3.5 h-3.5') {
    return typeIconMarkup(nodeType, className);
  },
  // Inline Material-icon <svg> for a raw ICON_PATHS key (toolbar toggles, etc.),
  // for callers that aren't rendering an SPDX element/node type.
  uiIconSvg(iconKey, className = 'w-3.5 h-3.5') {
    return iconMarkup(iconKey, className);
  },

  // Flattened AI-profile / Dataset-profile fields for an element (ai_AIPackage
  // or dataset_DatasetPackage), as {label, kind, value} descriptors the detail
  // panel and expanded package card render with a single data-driven template.
  // kind ∈ 'badge' | 'text' | 'longtext' | 'chips' | 'list' | 'dict'.
  profileFields(el) {
    if (!el) return [];
    const out = [];
    const push = (label, kind, value) => {
      if (kind === 'chips' || kind === 'list' || kind === 'dict') {
        if (Array.isArray(value) && value.length) out.push({ label, kind, value });
      } else if (kind === 'bytes') {
        if (Number.isFinite(value) && value > 0) {
          out.push({ label, kind: 'badge', value: formatByteSize(value) });
        }
      } else if (isMeaningfulValue(value)) {
        // 'badge' fields are all SPDX vocab enums; reduce to the short token so
        // a CURIE/IRI-serialized value (e.g. spdx:Core/PresenceType/yes) reads
        // as 'yes' rather than the full term reference.
        out.push({ label, kind, value: kind === 'badge' ? enumValue(value) : value });
      }
    };

    // AI profile (ai_AIPackage; dataset_DatasetPackage inherits these too)
    push('Type of model', 'chips', el.ai_typeOfModel);
    push('Domain', 'chips', el.ai_domain);
    push('Autonomy', 'badge', el.ai_autonomyType);
    push('Safety risk assessment', 'badge', el.ai_safetyRiskAssessment);
    push('Sensitive personal information', 'badge', el.ai_sensitivePersonalInformation);
    push('Standards compliance', 'chips', el.ai_standardCompliance);
    push('Model explainability', 'chips', el.ai_modelExplainability);
    push('Energy consumption', 'text', el.ai_energyConsumption);
    push('Limitations', 'longtext', el.ai_limitation);
    push('About the application', 'longtext', el.ai_informationAboutApplication);
    push('About training', 'longtext', el.ai_informationAboutTraining);
    push('Data preprocessing', 'list', el.ai_modelDataPreprocessing);
    push('Hyperparameters', 'dict', el.ai_hyperparameter);
    push('Metrics', 'dict', el.ai_metric);
    push('Metric decision thresholds', 'dict', el.ai_metricDecisionThreshold);

    // Dataset profile (dataset_DatasetPackage)
    push('Dataset type', 'chips', el.dataset_datasetType);
    push('Intended use', 'text', el.dataset_intendedUse);
    push('Availability', 'badge', el.dataset_datasetAvailability);
    push('Confidentiality', 'badge', el.dataset_confidentialityLevel);
    push('Sensitive personal information', 'badge', el.dataset_hasSensitivePersonalInformation);
    push('Dataset size', 'bytes', el.dataset_datasetSize);
    push('Anonymization methods', 'chips', el.dataset_anonymizationMethodUsed);
    push('Known biases', 'list', el.dataset_knownBias);
    push('Data collection process', 'longtext', el.dataset_dataCollectionProcess);
    push('Data preprocessing', 'list', el.dataset_dataPreprocessing);
    push('Dataset noise', 'longtext', el.dataset_datasetNoise);
    push('Dataset update mechanism', 'text', el.dataset_datasetUpdateMechanism);
    push('Sensors', 'dict', el.dataset_sensor);

    return out;
  },

  // Human-readable size of a software artifact (File or Package), from the
  // SPDX Software profile's software_artifactSize (bytes). Returns '' when the
  // element carries no meaningful size, so templates can gate on truthiness.
  artifactSize(el) {
    return formatByteSize(Number(el?.software_artifactSize));
  },

  // Hardware profile (SPDX 3.1): the manufacturer/producer of a hardware
  // element, resolved from its hardware_productAgent reference (→ Organization /
  // Person / SoftwareAgent). Returns { id, name } or null.
  hardwareManufacturer(el) {
    const id = el?.hardware_productAgent;
    // Skip missing and NoAssertion sentinels (e.g. Core/NoAssertionElement) so a
    // "no manufacturer stated" hardware element doesn't render a bare URL.
    if (!id || id.includes('NoAssertion')) return null;
    const agent = this.elementMap.get(id);
    return { id, name: agent?.name || this.cleanName(id) };
  },

  // Spec-sheet fields for a hardware element beyond the headline part number /
  // category (which the detail panel promotes as badges). Returned as
  // {label, value, mono} descriptors so the card and detail panel render the
  // same set with one template.
  hardwareSpecs(el) {
    if (!el) return [];
    const out = [];
    const push = (label, value, mono = false) => {
      if (isMeaningfulValue(value)) out.push({ label, value: String(value), mono });
    };
    push('Serial number', el.hardware_serialNumber, true);
    push('Batch number', el.hardware_batchNumber, true);
    push('Release date', el.hardware_releaseDate && this.formatDate(el.hardware_releaseDate));
    if (el.hardware_dimensions) {
      const dims = this.elementMap.get(el.hardware_dimensions);
      push('Dimensions', formatHardwareDimensions(dims));
    }
    push('Mass', formatQudtMeasure(el.hardware_mass));
    push('Bulk quantity', el.hardware_bulkQuantity);
    push('Additional information', el.hardware_additionalInformation);
    return out;
  },

  // FunctionalSafety profile (SPDX 3.1): spec-sheet fields for a requirement or a
  // safety artifact (verification / assumption / evaluation) beyond the headline
  // statement (which the detail panel promotes as a hero). Returned as
  // {label, value, mono} descriptors so the card and detail panel render the same
  // set with one template. Array-valued fields (rationale, verificationMethod, …)
  // are joined for display.
  safetyFields(el) {
    if (!el) return [];
    const out = [];
    const join = (v) => (Array.isArray(v) ? v.filter(isMeaningfulValue).join(', ') : v);
    const push = (label, value, mono = false) => {
      const v = join(value);
      if (isMeaningfulValue(v)) out.push({ label, value: String(v), mono });
    };
    // Requirement (Core)
    push('Lifecycle stage', el.devLifecycleStage);
    // RequirementVerification (functionalsafety): verificationMethod is a vocab
    // enum, so reduce each entry to its short token (test / analysis / ...).
    push(
      'Verification method',
      Array.isArray(el.functionalsafety_verificationMethod)
        ? el.functionalsafety_verificationMethod.map(enumValue)
        : el.functionalsafety_verificationMethod &&
            enumValue(el.functionalsafety_verificationMethod)
    );
    push('Precondition', el.functionalsafety_verificationPrecondition);
    push('Postcondition', el.functionalsafety_verificationPostcondition);
    // EvaluationResult (functionalsafety): the pass/fail is rendered as a badge via
    // evaluationResultMeta; here we resolve the verification it was based on.
    if (el.functionalsafety_evaluationBasedOn) {
      const v = this.elementMap.get(el.functionalsafety_evaluationBasedOn);
      push('Based on', v?.name || this.cleanName(el.functionalsafety_evaluationBasedOn));
    }
    // Shared: the reasoning behind the requirement / verification / evaluation
    push(
      'Rationale',
      el.rationale || el.functionalsafety_rationale || el.functionalsafety_evaluationRationale
    );
    return out;
  },

  // The verifications a requirement is linked to via `verifiedBy`, each paired
  // with its EvaluationResult (resolved through the evaluation's
  // evaluationBasedOn back-reference) — the data behind a requirement's
  // pass/fail status and its inline verification breakdown.
  requirementVerifications(el) {
    if (!el) return [];
    const out = [];
    (this.outgoingRels(el.spdxId) || []).forEach((rel) => {
      if (rel.relationshipType !== 'verifiedBy') return;
      (Array.isArray(rel.to) ? rel.to : [rel.to]).forEach((vid) => {
        const verification = this.elementMap.get(vid);
        if (verification) out.push({ id: vid, verification, evaluation: this.evaluationFor(vid) });
      });
    });
    return out;
  },

  // Ordered detail sequence for a requirement card: remaining relationship
  // groups with the "Verification & evaluation" block spliced in at the
  // verifiedBy slot. Implementation (implementedBy) and verification are hoisted
  // into their own sections so the card reads code → tests → other traces.
  // Each entry is { kind: 'rel', group } or { kind: 'verification' }.
  requirementDetailSequence(el) {
    const seq = this.detailRelGroupsFor(el, {
      excludeKeys: ['verifiedBy:out', 'implementedBy:out']
    }).map((g) => ({
      kind: 'rel',
      key: g.key,
      group: g
    }));
    if (this.requirementVerifications(el).length > 0) {
      // verifiedBy's own slot: after implementedBy, before Required by / traced.
      const pivot = this.relSortOrder('verifiedBy', 'out');
      let idx = seq.findIndex((s) => s.group.sortOrder > pivot);
      if (idx === -1) idx = seq.length;
      seq.splice(idx, 0, { kind: 'verification', key: '__verification__' });
    }
    return seq;
  },

  // The EvaluationResult whose evaluationBasedOn points at a given verification.
  evaluationFor(verificationId) {
    return (
      this.requirements.find(
        (r) =>
          r.type === 'functionalsafety_EvaluationResult' &&
          r.functionalsafety_evaluationBasedOn === verificationId
      ) || null
    );
  },

  // Overall functional-safety status of a Requirement, walking
  // Requirement --verifiedBy--> RequirementVerification <--evaluationBasedOn-- EvaluationResult.
  // A single failed evaluation dominates; otherwise all-pass wins, then
  // inconclusive, then verified-but-not-yet-evaluated, else unverified.
  requirementSafetyStatus(el) {
    if (!el || el.type !== 'Requirement') return null;
    const vers = this.requirementVerifications(el);
    if (!vers.length) {
      return SAFETY_STATUSES.unverified;
    }
    const evals = vers.map((v) =>
      enumValue(v.evaluation?.functionalsafety_evaluation).toLowerCase()
    );
    if (evals.includes('fail')) {
      return { ...SAFETY_STATUSES.failed, label: 'Verification failed' };
    }
    const decided = evals.filter(Boolean);
    if (decided.length && decided.every((e) => e === 'pass')) {
      return { ...SAFETY_STATUSES.passed, label: 'Passed' };
    }
    if (evals.includes('inconclusive')) {
      return SAFETY_STATUSES.inconclusive;
    }
    return SAFETY_STATUSES.verified;
  },

  // Human title for a requirement/FS artifact (strips embedded UID prefixes).
  requirementDisplayName(el) {
    if (!el) return '';
    if (isA(el.type, CLASS.Requirement)) {
      return (
        formatRequirementDisplayName(el, (e) => this.externalIdentifiers(e)) ||
        el.name ||
        this.cleanName(el.spdxId)
      );
    }
    return el.name || this.cleanName(el.spdxId);
  },

  // One chip label: "thread.c (77)" when the grouped snippets cover 77 unique
  // lines. Clicking the chip opens every range of that file.
  requirementFileChipLabel(file) {
    if (!file) return '';
    const name = file.baseName || 'file';
    const n = file.lineCount || 0;
    return n ? `${name} (${this.formatCount(n)})` : name;
  },
  requirementFileChipTitle(file) {
    if (!file) return '';
    const where = file.fileName || file.baseName || 'file';
    const n = file.lineCount || 0;
    if (!n) return where;
    return `${this.formatCount(n)} ${n === 1 ? 'line' : 'lines'} in ${where}`;
  },

  // Files a requirement is implemented by, snippets grouped per source file so
  // the card can show one "thread.c (N)" chip instead of a row per snippet.
  // Non-snippet targets (a whole file, a package) stay in `others`.
  requirementImplementationGroups(el) {
    if (!el?.spdxId) return EMPTY_SNIPPET_GROUPS;
    const cached = requirementImplCache.get(el);
    if (cached) return cached;
    const seen = new Set();
    const targets = [];
    (this.outgoingRels(el.spdxId) || []).forEach((rel) => {
      if (rel.relationshipType !== 'implementedBy') return;
      (Array.isArray(rel.to) ? rel.to : [rel.to]).forEach((id) => {
        if (!id || seen.has(id)) return;
        seen.add(id);
        targets.push(this.elementMap.get(id) || { spdxId: id });
      });
    });
    const grouped = groupSnippetsByFile(targets, this.elementMap);
    const result = {
      files: grouped.files,
      others: grouped.others.map((item) => ({
        id: item.spdxId,
        displayName: this.relTargetDisplayName(item.spdxId)
      })),
      total: grouped.files.reduce((n, f) => n + f.snippets.length, 0) + grouped.others.length
    };
    requirementImplCache.set(el, result);
    return result;
  },

  // Evidence targets reachable from a requirement via
  // verifiedBy → EvaluationResult --hasEvidence--> artifact/snippet/file.
  // Coverage snippets of the same file collapse to one "file (N lines)" chip.
  requirementEvidence(el) {
    if (!el?.spdxId) return EMPTY_SNIPPET_GROUPS;
    const cached = requirementEvidenceCache.get(el);
    if (cached) return cached;
    const seen = new Set();
    const targets = [];
    const pushTarget = (id) => {
      if (!id || seen.has(id)) return;
      seen.add(id);
      targets.push(this.elementMap.get(id) || { spdxId: id });
    };
    this.requirementVerifications(el).forEach(({ evaluation }) => {
      if (!evaluation?.spdxId) return;
      (this.outgoingRels(evaluation.spdxId) || []).forEach((rel) => {
        if (rel.relationshipType !== 'hasEvidence') return;
        (Array.isArray(rel.to) ? rel.to : [rel.to]).forEach(pushTarget);
      });
    });
    // Direct hasEvidence from the requirement itself (some producers skip eval).
    (this.outgoingRels(el.spdxId) || []).forEach((rel) => {
      if (rel.relationshipType !== 'hasEvidence') return;
      (Array.isArray(rel.to) ? rel.to : [rel.to]).forEach(pushTarget);
    });
    const grouped = groupSnippetsByFile(targets, this.elementMap, {
      labelOf: snippetCompactLine,
      dedupeRanges: true
    });
    const result = {
      files: grouped.files,
      others: grouped.others.map((item) => ({
        id: item.spdxId,
        name: item.description || item.name || this.cleanName(item.spdxId)
      })),
      total: grouped.files.reduce((n, f) => n + f.snippets.length, 0) + grouped.others.length
    };
    requirementEvidenceCache.set(el, result);
    return result;
  },

  // One quiet cue for a tree/list row: only surface the implementation gap.
  // Status is the icon; evidence belongs in the expanded card.
  requirementQuietCue(el) {
    if (!el || !isA(el.type, CLASS.Requirement)) return '';
    if (!this.implementedByCount(el.spdxId)) return 'no implementation';
    return '';
  },

  // Plain-language summary under an expanded requirement card.
  requirementSummaryLine(el) {
    if (!el || !isA(el.type, CLASS.Requirement)) return '';
    const parts = [];
    const status = this.requirementSafetyStatus(el);
    if (status?.key === 'passed') parts.push('Passes verification');
    else if (status?.key === 'failed') parts.push('Verification failed');
    else if (status?.key === 'inconclusive') parts.push('Verification inconclusive');
    else if (status?.key === 'verified') parts.push('Has verification');
    else if (status?.key === 'unverified') parts.push('Not verified');
    const adequacy = this.requirementAdequacyKey(el);
    if (adequacy === 'broken') parts.push('implementation never exercised by its own tests');
    else if (adequacy === 'partial') parts.push('implementation only partly exercised');
    const impl = this.requirementImplementationGroups(el);
    if (impl.total === 0) parts.push('no implementation');
    else if (impl.files.length === 1 && impl.others.length === 0) {
      parts.push(`in ${impl.files[0].baseName}`);
    } else {
      const n = impl.files.length + impl.others.length;
      parts.push(n === 1 ? 'in 1 file' : `in ${this.formatCount(n)} files`);
    }
    return parts.join(' · ');
  },

  // Presentation metadata ({label, color, dotClass, badgeClass}) for a
  // requirement verification-status key (as returned by requirementSafetyStatus)
  // or the 'noimpl' traceability-gap key. Drives the rollup bar and the
  // status-filter chips, mirroring vexStatusMeta for the security view.
  // Level a producer recorded on a Requirement ('system' or 'software'), from
  // its `requirement-level:` external identifier. '' when it carries none.
  requirementLevel(el) {
    if (!el || !isA(el.type, CLASS.Requirement)) return '';
    return producerMetaValue(el, 'requirement-level', (e) =>
      this.externalIdentifiers(e)
    ).toLowerCase();
  },

  // "True traceability" adequacy verdict a producer recorded on a Requirement
  // as an `adequacy:<verdict>` external identifier. '' when it carries none,
  // which is what an SBOM generated without a coverage matrix looks like.
  requirementAdequacyKey(el) {
    if (!el || !isA(el.type, CLASS.Requirement)) return '';
    const raw = producerMetaValue(el, 'adequacy', (e) => this.externalIdentifiers(e)).toLowerCase();
    return Object.hasOwn(SAFETY_ADEQUACY, raw) ? raw : '';
  },

  safetyAdequacyMeta(key) {
    return (
      SAFETY_ADEQUACY[key] || {
        key: key || 'unknown',
        label: key || 'Unknown',
        color: COLORS.default || '#64748b',
        badgeClass: 'bg-slate-600/20 text-slate-300 ring-1 ring-slate-500/30',
        dotClass: 'bg-slate-500',
        hint: ''
      }
    );
  },

  // Share of a rollup one bucket holds, as a CSS width for its chip's fill.
  // The fill is a coarse magnitude cue, not a measurement: under about 5% it is
  // a hairline, and the count beside the label is what carries the size.
  safetyShare(count, total) {
    return total ? `${((count / total) * 100).toFixed(2)}%` : '0%';
  },

  safetyStatusMeta(key) {
    return (
      SAFETY_STATUSES[key] || {
        key: key || 'unknown',
        label: key || 'Unknown',
        color: COLORS.default || '#64748b',
        badgeClass: 'bg-slate-600/20 text-slate-300 ring-1 ring-slate-500/30',
        dotClass: 'bg-slate-500'
      }
    );
  },

  // Decomposition tree: collapse/expand a requirement's subtree. collapsedReqs is
  // reassigned (not mutated in place) so Alpine reliably re-renders the tree.
  toggleReqCollapse(spdxId) {
    const next = { ...this.collapsedReqs };
    if (next[spdxId]) delete next[spdxId];
    else next[spdxId] = true;
    this.collapsedReqs = next;
  },

  // Decomposition tree: collapse every parent node (roots stay visible).
  collapseAllReqs() {
    const next = {};
    this.safetyDecomposition.childrenOf.forEach((_children, parentId) => {
      next[parentId] = true;
    });
    this.collapsedReqs = next;
  },

  // Decomposition tree: expand everything.
  expandAllReqs() {
    this.collapsedReqs = {};
  },

  // Friendly kind label for a functional-safety element, for the card/detail
  // type badge (Requirement / Verification / Assumption / Evaluation).
  safetyArtifactKind(el) {
    switch (el?.type) {
      case 'Requirement':
        return 'Requirement';
      case 'functionalsafety_RequirementVerification':
        return 'Verification';
      case 'functionalsafety_Assumption':
        return 'Assumption';
      case 'functionalsafety_EvaluationResult':
        return 'Evaluation';
      default:
        return '';
    }
  },

  // Number of elements a requirement is implemented by (distinct `to` targets of
  // its outgoing `implementedBy` relationships) — the headline traceability
  // count shown on a requirement card.
  implementedByCount(spdxId) {
    const targets = new Set();
    (this.outgoingRels(spdxId) || []).forEach((rel) => {
      if (rel.relationshipType !== 'implementedBy') return;
      (Array.isArray(rel.to) ? rel.to : [rel.to]).forEach((t) => t && targets.add(t));
    });
    return targets.size;
  },

  // Presentation for a FunctionalSafety EvaluationResult's pass/fail/inconclusive
  // outcome, so it can render as a status badge. Returns null for elements that
  // carry no evaluation result.
  evaluationResultMeta(el) {
    const v = el?.functionalsafety_evaluation;
    if (!isMeaningfulValue(v)) return null;
    const token = enumValue(v);
    const key = token.toLowerCase();
    const map = {
      pass: {
        key: 'pass',
        label: 'Pass',
        iconKey: 'status_pass',
        badgeClass: 'bg-emerald-500/15 text-emerald-400 ring-1 ring-emerald-500/30'
      },
      fail: {
        key: 'fail',
        label: 'Fail',
        iconKey: 'status_fail',
        badgeClass: 'bg-rose-500/15 text-rose-400 ring-1 ring-rose-500/30'
      },
      inconclusive: {
        key: 'inconclusive',
        label: 'Inconclusive',
        iconKey: 'status_inconclusive',
        badgeClass: 'bg-amber-500/15 text-amber-400 ring-1 ring-amber-500/30'
      }
    };
    return (
      map[key] || {
        key,
        label: token,
        iconKey: 'status_unverified',
        badgeClass: 'bg-slate-600/20 text-slate-300 ring-1 ring-slate-500/30'
      }
    );
  },

  // Status metadata for any safety artifact that directly carries an outcome:
  // Requirements derive their aggregate verification state, while evaluation
  // results expose their own pass/fail/inconclusive value. This lets generic
  // relationship rows decorate both kinds consistently.
  safetyArtifactStatus(el) {
    return this.requirementRowStatus(el) || this.evaluationResultMeta(el);
  },

  // What a requirement's row should show. The verification outcome alone reads
  // "Passed" for a requirement whose own tests never touch the code that
  // implements it, which is the one state this profile exists to surface: so an
  // adequacy verdict of broken/partial overrides it, and the title spells out
  // both halves. A real test failure still dominates. The Outcome rollup and
  // its filter keep using requirementSafetyStatus, so their counts are
  // unchanged.
  requirementRowStatus(el) {
    // Refined, not verified: a system requirement has no outcome of its own, so
    // it carries no status pill and does not sort into the untested band.
    if (this.requirementLevel(el) === 'system') return null;
    const status = this.requirementSafetyStatus(el);
    if (!status || status.key === 'failed') return status;
    const adequacy = this.requirementAdequacyKey(el);
    if (adequacy !== 'broken' && adequacy !== 'partial') return status;
    const meta = SAFETY_ADEQUACY[adequacy];
    return { ...meta, title: `${status.label} · ${meta.hint}` };
  },

  // Sort key for "what should I look at next", worst first. Ordered by how
  // misleading a state is rather than how bad it sounds: a requirement that
  // passes without exercising its implementation outranks an honest failure,
  // because nothing else in the UI would draw the eye to it.
  requirementAttentionRank(el) {
    if (!el || !isA(el.type, CLASS.Requirement)) return 99;
    if (this.requirementLevel(el) === 'system') return 8;
    const adequacy = this.requirementAdequacyKey(el);
    const outcome = this.requirementSafetyStatus(el)?.key;
    if (adequacy === 'broken') return 0;
    if (outcome === 'failed') return 1;
    if (adequacy === 'partial') return 2;
    if (outcome === 'unverified') return 3;
    if (outcome === 'inconclusive') return 4;
    if (adequacy === 'no-impl') return 5;
    if (adequacy && adequacy !== 'true') return 6;
    return 7;
  },

  // Normalize an SPDX enumerated (vocab) value for display in a template. Kept
  // as a thin accessor so views can render enum badges (e.g. verification
  // method) without leaking the CURIE/IRI form the JSON-LD context may use.
  enumLabel(value) {
    return enumValue(value);
  },

  placeholderElement(spdxId) {
    return {
      type: 'ExternalReference',
      spdxId,
      name: this.cleanName(spdxId),
      placeholder: true
    };
  },

  copyHash(h) {
    copyToClipboard(h).then(() => {
      this.toastMsg = 'Copied to clipboard';
      setTimeout(() => (this.toastMsg = ''), 2000);
    });
  }
};
