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
  isMeaningfulValue,
  enumValue,
  formatByteSize,
  formatQudtMeasure,
  formatHardwareDimensions,
  normalizeUrl,
  copyToClipboard,
  licenseIndividualDescription,
  requirementDisplayName as formatRequirementDisplayName,
  primaryPurposeLabel as formatPrimaryPurpose,
  splitFilePath,
  PACKAGE_GAP_META,
  PACKAGE_GAP_ORDER,
  PACKAGE_DESCRIPTION_SEGMENTS
} from '../lib/index.js';
import { COLORS, getScopeColor, SAFETY_STATUSES, SAFETY_NO_IMPL_META } from '../config.js';
import { CLASS, isA } from '../spdx/model.js';
import hljs from '../lib/highlight.js';

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

// Licenses shown inline on a collapsed Packages row before the rest are summed up.
const ROW_LICENSE_CAP = 2;

// Coarse gazetteer for the Supply Chain route map. SPDX PhysicalLocation carries
// city / country (ISO 3166-1 alpha-3) but no coordinates, so we resolve a rough
// lat/lng from the city name, falling back to a country centroid. Anything we
// cannot place drops to a schematic left-to-right layout, so this list only has
// to cover common places well; it never needs to be exhaustive.
const CITY_GAZETTEER = {
  austin: { lat: 30.27, lng: -97.74 },
  dayton: { lat: 39.76, lng: -84.19 },
  hsinchu: { lat: 24.8, lng: 120.97 },
  penang: { lat: 5.41, lng: 100.33 },
  'george town': { lat: 5.41, lng: 100.33 },
  'los angeles': { lat: 34.05, lng: -118.24 },
  denver: { lat: 39.74, lng: -104.99 },
  rawlins: { lat: 41.79, lng: -107.24 },
  phoenix: { lat: 33.45, lng: -112.07 },
  'new york': { lat: 40.71, lng: -74.01 },
  'san francisco': { lat: 37.77, lng: -122.42 },
  seattle: { lat: 47.61, lng: -122.33 },
  chicago: { lat: 41.88, lng: -87.63 },
  boston: { lat: 42.36, lng: -71.06 },
  london: { lat: 51.51, lng: -0.13 },
  paris: { lat: 48.85, lng: 2.35 },
  berlin: { lat: 52.52, lng: 13.4 },
  munich: { lat: 48.14, lng: 11.58 },
  tokyo: { lat: 35.68, lng: 139.69 },
  shanghai: { lat: 31.23, lng: 121.47 },
  shenzhen: { lat: 22.54, lng: 114.06 },
  taipei: { lat: 25.03, lng: 121.57 },
  singapore: { lat: 1.35, lng: 103.82 },
  bangalore: { lat: 12.97, lng: 77.59 },
  bengaluru: { lat: 12.97, lng: 77.59 },
  sydney: { lat: -33.87, lng: 151.21 },
  toronto: { lat: 43.65, lng: -79.38 }
};
const COUNTRY_CENTROID = {
  usa: { lat: 39.5, lng: -98.35 },
  us: { lat: 39.5, lng: -98.35 },
  twn: { lat: 23.7, lng: 121.0 },
  mys: { lat: 4.2, lng: 102.0 },
  chn: { lat: 35.0, lng: 103.0 },
  jpn: { lat: 36.2, lng: 138.3 },
  deu: { lat: 51.2, lng: 10.4 },
  gbr: { lat: 54.0, lng: -2.0 },
  fra: { lat: 46.2, lng: 2.2 },
  ind: { lat: 21.0, lng: 78.0 },
  kor: { lat: 36.5, lng: 127.8 },
  sgp: { lat: 1.35, lng: 103.8 },
  can: { lat: 56.1, lng: -106.3 },
  mex: { lat: 23.6, lng: -102.5 },
  bra: { lat: -14.2, lng: -51.9 },
  aus: { lat: -25.3, lng: 133.8 }
};

// Role of a location on the route map, inferred from its name. Drives the marker
// colour/label so origins, hubs, labs and destinations read at a glance.
const STOP_ROLES = [
  [/control tower|hq|headquarter/i, { label: 'Control tower', color: '#38bdf8' }],
  [/assembly|final assembl/i, { label: 'Assembly', color: '#818cf8' }],
  [/fab|line|smt|wafer|foundry|element/i, { label: 'Manufacturing', color: '#a78bfa' }],
  [/warehouse|staging|storage/i, { label: 'Storage', color: '#2dd4bf' }],
  [/hub|air-freight|airport|port|terminal/i, { label: 'Transit hub', color: '#22d3ee' }],
  [/lab|inspection|receiving/i, { label: 'Inspection lab', color: '#c084fc' }],
  [/site|substation|farm|plant|deploy/i, { label: 'Deployment site', color: '#34d399' }],
  [/recovery|destruction|recycl/i, { label: 'Recovery', color: '#fb7185' }]
];

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
      const lines = this._highlightSource(content, file?.name);
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
  // text when no grammar matches.
  _highlightSource(content, fileName) {
    const ext = getFileExtension(fileName || '');
    const rawLines = content.split('\n');
    const escaped = rawLines.map((l) =>
      l.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    );

    let highlighted = null;
    const langMap = { '.c': 'c', '.h': 'c', '.cpp': 'cpp', '.py': 'python', '.js': 'javascript' };
    const lang = langMap[ext];
    try {
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

  supplyChainKind(el) {
    const t = el?.type || '';
    if (!t) return '';
    if (isA(t, CLASS.supplychain_State)) return 'state';
    if (
      isA(t, CLASS.supplychain_CreateProcess) ||
      isA(t, CLASS.supplychain_ModifyProcess) ||
      isA(t, CLASS.supplychain_UseProcess) ||
      isA(t, CLASS.supplychain_BoundaryDefinitionProcess) ||
      isA(t, CLASS.supplychain_ResponsibilityChangeProcess) ||
      isA(t, CLASS.supplychain_DestroyProcess)
    ) {
      return 'process';
    }
    return 'action';
  },

  supplyChainTypeLabel(el) {
    const raw = (el?.type || '')
      .replace(/^supplychain_/, '')
      .replace(/([a-z0-9])([A-Z])/g, '$1 $2');
    return raw || 'Supply chain element';
  },

  supplyChainKindLabel(kind) {
    return { action: 'Action', process: 'Process', state: 'State' }[kind] || 'Element';
  },

  supplyChainKindBadge(kind) {
    return (
      {
        action: 'bg-slate-700/70 text-slate-200 ring-1 ring-slate-600/40',
        process: 'bg-slate-800 text-slate-300 ring-1 ring-slate-600/40',
        state: 'bg-slate-800 text-slate-300 ring-1 ring-slate-600/40'
      }[kind] || 'bg-slate-700 text-slate-300'
    );
  },

  supplyChainFamily(el) {
    const t = el?.type || '';
    if (
      isA(t, CLASS.supplychain_CreateAction) ||
      isA(t, CLASS.supplychain_CreateProcess) ||
      isA(t, CLASS.supplychain_ManufactureAction) ||
      isA(t, CLASS.supplychain_ManufactureProcess) ||
      isA(t, CLASS.supplychain_AssemblyAction) ||
      isA(t, CLASS.supplychain_AssemblyProcess) ||
      isA(t, CLASS.supplychain_HarvestAction) ||
      isA(t, CLASS.supplychain_HarvestProcess) ||
      isA(t, CLASS.supplychain_ReproduceProcess) ||
      isA(t, CLASS.supplychain_ReproduceAction)
    ) {
      return 'create';
    }
    // Move must be tested before Modify: SPDX makes Transport/Storage subclasses
    // of ModifyProcess, but here they belong to the custody/move phase, so the
    // specific classes win over the generic Modify catch-all below.
    if (
      isA(t, CLASS.supplychain_TransportAction) ||
      isA(t, CLASS.supplychain_TransportProcess) ||
      isA(t, CLASS.supplychain_StorageAction) ||
      isA(t, CLASS.supplychain_StorageProcess) ||
      isA(t, CLASS.supplychain_ResponsibilityChangeAction) ||
      isA(t, CLASS.supplychain_ResponsibilityChangeProcess) ||
      isA(t, CLASS.supplychain_BoundaryCrossingAction)
    ) {
      return 'move';
    }
    if (
      isA(t, CLASS.supplychain_ModifyAction) ||
      isA(t, CLASS.supplychain_ModifyProcess) ||
      isA(t, CLASS.supplychain_BoundaryDefinitionAction) ||
      isA(t, CLASS.supplychain_BoundaryDefinitionProcess)
    ) {
      return 'modify';
    }
    if (
      isA(t, CLASS.supplychain_InspectionAction) ||
      isA(t, CLASS.supplychain_InspectionProcess) ||
      isA(t, CLASS.supplychain_TestAction) ||
      isA(t, CLASS.supplychain_TestProcess) ||
      isA(t, CLASS.supplychain_DefinedStateProcess) ||
      isA(t, CLASS.supplychain_StateAction)
    ) {
      return 'verify';
    }
    if (isA(t, CLASS.supplychain_OutOfSpecAction) || isA(t, CLASS.supplychain_ResolutionAction)) {
      return 'exception';
    }
    if (
      isA(t, CLASS.supplychain_UseAction) ||
      isA(t, CLASS.supplychain_UseProcess) ||
      isA(t, CLASS.supplychain_PlanAction) ||
      isA(t, CLASS.supplychain_PlanProcess) ||
      isA(t, CLASS.supplychain_DestroyProcess) ||
      isA(t, CLASS.supplychain_DestroyAction)
    ) {
      return 'operate';
    }
    if (this.supplyChainKind(el) === 'process') return 'process';
    if (this.supplyChainKind(el) === 'state') return 'state';
    return 'other';
  },

  supplyChainFamilyMeta(el) {
    const meta = {
      create: {
        label: 'Create / make',
        dot: 'bg-slate-500',
        iconBg: 'bg-slate-700/60',
        text: 'text-slate-300',
        border: 'border-slate-700',
        ring: 'ring-sky-500/20',
        surface: 'bg-slate-900/50',
        hover: 'hover:bg-slate-800/70',
        panel: 'bg-slate-900/70 border-slate-700/60',
        chip: 'bg-slate-700/70 text-slate-200 ring-1 ring-slate-600/40'
      },
      modify: {
        label: 'Modify',
        dot: 'bg-slate-500',
        iconBg: 'bg-slate-700/60',
        text: 'text-slate-300',
        border: 'border-slate-700',
        ring: 'ring-amber-500/20',
        surface: 'bg-slate-900/50',
        hover: 'hover:bg-slate-800/70',
        panel: 'bg-slate-900/70 border-slate-700/60',
        chip: 'bg-slate-700/70 text-slate-200 ring-1 ring-slate-600/40'
      },
      move: {
        label: 'Move / custody',
        dot: 'bg-slate-500',
        iconBg: 'bg-slate-700/60',
        text: 'text-slate-300',
        border: 'border-slate-700',
        ring: 'ring-cyan-500/20',
        surface: 'bg-slate-900/50',
        hover: 'hover:bg-slate-800/70',
        panel: 'bg-slate-900/70 border-slate-700/60',
        chip: 'bg-slate-700/70 text-slate-200 ring-1 ring-slate-600/40'
      },
      verify: {
        label: 'Inspect / test',
        dot: 'bg-slate-500',
        iconBg: 'bg-slate-700/60',
        text: 'text-slate-300',
        border: 'border-slate-700',
        ring: 'ring-violet-500/20',
        surface: 'bg-slate-900/50',
        hover: 'hover:bg-slate-800/70',
        panel: 'bg-slate-900/70 border-slate-700/60',
        chip: 'bg-slate-700/70 text-slate-200 ring-1 ring-slate-600/40'
      },
      exception: {
        label: 'Exception path',
        dot: 'bg-rose-400',
        iconBg: 'bg-rose-500/15',
        text: 'text-rose-300',
        border: 'border-rose-500/35',
        ring: 'ring-rose-500/20',
        surface: 'bg-rose-500/[0.07]',
        hover: 'hover:bg-rose-500/[0.11]',
        panel: 'bg-rose-950/30 border-rose-500/20',
        chip: 'bg-rose-500/15 text-rose-200 ring-1 ring-rose-500/25'
      },
      operate: {
        label: 'Use / retire',
        dot: 'bg-slate-500',
        iconBg: 'bg-slate-700/60',
        text: 'text-slate-300',
        border: 'border-slate-700',
        ring: 'ring-emerald-500/20',
        surface: 'bg-slate-900/50',
        hover: 'hover:bg-slate-800/70',
        panel: 'bg-slate-900/70 border-slate-700/60',
        chip: 'bg-slate-700/70 text-slate-200 ring-1 ring-slate-600/40'
      },
      process: {
        label: 'Defined process',
        dot: 'bg-slate-500',
        iconBg: 'bg-slate-700/60',
        text: 'text-slate-300',
        border: 'border-slate-700',
        ring: 'ring-indigo-500/20',
        surface: 'bg-slate-900/50',
        hover: 'hover:bg-slate-800/70',
        panel: 'bg-slate-900/70 border-slate-700/60',
        chip: 'bg-slate-700/70 text-slate-200 ring-1 ring-slate-600/40'
      },
      state: {
        label: 'State',
        dot: 'bg-slate-500',
        iconBg: 'bg-slate-700/60',
        text: 'text-slate-300',
        border: 'border-slate-700',
        ring: 'ring-teal-500/20',
        surface: 'bg-slate-900/50',
        hover: 'hover:bg-slate-800/70',
        panel: 'bg-slate-900/70 border-slate-700/60',
        chip: 'bg-slate-700/70 text-slate-200 ring-1 ring-slate-600/40'
      },
      other: {
        label: 'Supply chain',
        dot: 'bg-slate-400',
        iconBg: 'bg-slate-500/15',
        text: 'text-slate-300',
        border: 'border-slate-500/35',
        ring: 'ring-slate-500/20',
        surface: 'bg-slate-500/[0.06]',
        hover: 'hover:bg-slate-500/[0.10]',
        panel: 'bg-slate-900/70 border-slate-700/60',
        chip: 'bg-slate-700/80 text-slate-200 ring-1 ring-slate-600/40'
      }
    };
    return meta[this.supplyChainFamily(el)] || meta.other;
  },

  supplyChainFamilyLabel(key) {
    return (
      {
        create: 'Create / make',
        modify: 'Modify',
        move: 'Move / custody',
        verify: 'Inspect & test',
        exception: 'Exception',
        operate: 'Use / retire',
        process: 'Defined process',
        other: 'Other'
      }[key] || 'Other'
    );
  },

  supplyChainProcessActionClass(process) {
    const type = process?.type || '';
    if (!type.endsWith('Process')) return '';
    if (type === CLASS.supplychain_DefinedStateProcess) return CLASS.supplychain_StateAction;
    return type.replace(/Process$/, 'Action');
  },

  supplyChainProcessActions(process) {
    const actionClass = this.supplyChainProcessActionClass(process);
    const matches = new Map();
    if (actionClass) {
      this.supplyChainActions
        .filter((action) => isA(action.type, actionClass))
        .forEach((action) => matches.set(action.spdxId, action));
    }
    this.supplyChainActions
      .filter((action) => action.supplychain_decisionProcess === process?.spdxId)
      .forEach((action) => matches.set(action.spdxId, action));
    return [...matches.values()].sort((a, b) =>
      (a.startTime || '').localeCompare(b.startTime || '')
    );
  },

  supplyChainStateActions(state) {
    return this.supplyChainActions.filter(
      (action) => action.supplychain_currentState === state?.spdxId
    );
  },

  supplyChainExceptionStatus(el) {
    if (!el) return null;
    if (isA(el.type, CLASS.supplychain_OutOfSpecAction)) {
      return {
        key: 'exception',
        label: 'Out of spec',
        badgeClass: 'bg-rose-500/15 text-rose-300 ring-1 ring-rose-500/30',
        color: COLORS.vulnerability
      };
    }
    if (
      isA(el.type, CLASS.supplychain_ResolutionAction) ||
      this.outgoingRels(el.spdxId).some((rel) => rel.relationshipType === 'resolved')
    ) {
      return {
        key: 'resolved',
        label: 'Resolved',
        badgeClass: 'bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30',
        color: COLORS.buildOutput
      };
    }
    return null;
  },

  supplyChainTimeRange(el) {
    if (!el?.startTime && !el?.endTime) return '';
    if (el.startTime && el.endTime && el.startTime !== el.endTime) {
      return `${this.formatDate(el.startTime)} → ${this.formatDate(el.endTime)}`;
    }
    return this.formatDate(el.startTime || el.endTime);
  },

  supplyChainDurationSeconds(el) {
    if (!el?.startTime || !el?.endTime) return 0;
    const start = Date.parse(el.startTime);
    const end = Date.parse(el.endTime);
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return 0;
    return Math.max(1, Math.round((end - start) / 1000));
  },

  supplyChainDurationMinutes(el) {
    const seconds = this.supplyChainDurationSeconds(el);
    return seconds ? Math.max(1, Math.round(seconds / 60)) : 0;
  },

  supplyChainDurationLabel(el) {
    const seconds = this.supplyChainDurationSeconds(el);
    if (!seconds) return '';
    if (seconds < 60) return `${seconds} second${seconds === 1 ? '' : 's'}`;
    const minutes = Math.round(seconds / 60);
    if (!minutes) return '';
    if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'}`;
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    if (hours < 24) return mins ? `${hours}h ${mins}m` : `${hours}h`;
    const days = Math.floor(hours / 24);
    const remHours = hours % 24;
    return remHours ? `${days}d ${remHours}h` : `${days}d`;
  },

  supplyChainCdxProperty(el, pattern) {
    const prop = this.cdxProperties(el).find((entry) => pattern.test(entry.name));
    return prop?.value || '';
  },

  supplyChainCdxNumber(el, pattern) {
    const raw = this.supplyChainCdxProperty(el, pattern);
    const number = Number.parseFloat(String(raw).replace(/,/g, ''));
    return Number.isFinite(number) ? number : 0;
  },

  supplyChainCarbonKg(el) {
    return this.supplyChainCdxNumber(el, /(?:co2e|co2|carbon).*kg/i);
  },

  supplyChainDistanceKm(el) {
    return this.supplyChainCdxNumber(el, /distance.*km/i);
  },

  supplyChainTransportMode(el) {
    return this.supplyChainCdxProperty(el, /transport\.mode|mode/i);
  },

  formatCarbonKg(value) {
    if (!value) return '';
    return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(value)} kg CO₂e`;
  },

  // Compact elapsed-time label between two epoch-ms instants, for timeline gap
  // markers and custody-segment durations ("45m", "3h 20m", "1d 4h", "2 days").
  supplyChainElapsedLabel(fromMs, toMs) {
    if (!Number.isFinite(fromMs) || !Number.isFinite(toMs)) return '';
    const secs = Math.round((toMs - fromMs) / 1000);
    if (secs <= 0) return '';
    if (secs < 60) return `${secs}s`;
    const mins = Math.round(secs / 60);
    if (mins < 60) return `${mins}m`;
    const hours = Math.floor(mins / 60);
    const remMins = mins % 60;
    if (hours < 24) return remMins ? `${hours}h ${remMins}m` : `${hours}h`;
    const days = Math.floor(hours / 24);
    const remHours = hours % 24;
    if (days < 3) return remHours ? `${days}d ${remHours}h` : `${days}d`;
    return `${days} days`;
  },

  // Day divider heading for the timeline ("Sat, 28 Jun 2026").
  supplyChainDayHeading(dateStr) {
    const ms = Date.parse(dateStr);
    if (!Number.isFinite(ms)) return '';
    try {
      return new Date(ms).toLocaleDateString(undefined, {
        weekday: 'short',
        day: 'numeric',
        month: 'short',
        year: 'numeric'
      });
    } catch {
      return String(dateStr).slice(0, 10);
    }
  },

  // Colour for a transport mode on the route map / custody legs. A mixed mode
  // ("road+air+road") takes the colour of its "highest" leg (air > sea > rail > road).
  supplyChainModeColor(mode) {
    const m = String(mode || '').toLowerCase();
    if (/air|flight/.test(m)) return '#a78bfa';
    if (/sea|ocean|ship|vessel/.test(m)) return '#38bdf8';
    if (/rail|train/.test(m)) return '#fbbf24';
    if (/road|truck|van|freight/.test(m)) return '#22d3ee';
    return '#94a3b8';
  },

  // "Austin, TX, USA" style place label from a PhysicalLocation's parts.
  supplyChainPlaceLabel(loc) {
    if (!loc) return '';
    return [loc.city, loc.provinceStateCode, loc.country].filter(Boolean).join(', ');
  },

  // Inferred role of a route-map stop (origin / hub / lab / destination …).
  supplyChainStopRole(loc) {
    const text = loc?.name || '';
    for (const [pattern, meta] of STOP_ROLES) {
      if (pattern.test(text)) return meta;
    }
    return { label: 'Location', color: '#94a3b8' };
  },

  // Parses an ISO 6709:2022 point string (signed decimal latitude then
  // longitude, e.g. "+30.2672-097.7431/") into { lat, lng }, or null.
  parseGeoPoint(value) {
    const m = /([+-]\d{1,3}(?:\.\d+)?)([+-]\d{1,3}(?:\.\d+)?)/.exec(String(value || ''));
    if (!m) return null;
    const lat = Number.parseFloat(m[1]);
    const lng = Number.parseFloat(m[2]);
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;
    if (Math.abs(lat) > 90 || Math.abs(lng) > 180) return null;
    return { lat, lng };
  },

  // lat/lng for a PhysicalLocation: the SBOM's own geographicPointLocation
  // (ISO 6709) first, then a coarse city / country-centroid fallback for
  // documents that omit coordinates. null when nothing resolves.
  supplyChainGeocode(loc) {
    if (!loc) return null;
    const point = Array.isArray(loc.geographicPointLocation)
      ? loc.geographicPointLocation[0]
      : loc.geographicPointLocation;
    const fromPoint = this.parseGeoPoint(point);
    if (fromPoint) return fromPoint;
    const city = String(loc.city || '')
      .trim()
      .toLowerCase();
    if (city && CITY_GAZETTEER[city]) return CITY_GAZETTEER[city];
    const country = String(loc.country || '')
      .trim()
      .toLowerCase();
    if (country && COUNTRY_CENTROID[country]) return COUNTRY_CENTROID[country];
    return null;
  },

  // Compact clock label for a timeline card header. Within a single day the date
  // is redundant (the day divider shows it), so we render just the times; a
  // cross-day action keeps the full range.
  supplyChainClock(el) {
    if (!el?.startTime && !el?.endTime) return '';
    const time = (s) => {
      const ms = Date.parse(s);
      if (!Number.isFinite(ms)) return '';
      try {
        return new Date(ms).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
      } catch {
        return '';
      }
    };
    if (el.startTime && el.endTime && el.startTime !== el.endTime) {
      const sameDay = el.startTime.slice(0, 10) === el.endTime.slice(0, 10);
      if (sameDay) return `${time(el.startTime)} → ${time(el.endTime)}`;
      return `${this.formatDate(el.startTime)} → ${this.formatDate(el.endTime)}`;
    }
    return this.formatDate(el.startTime || el.endTime);
  },

  // Delegated click for the x-html route map: a leg opens its transport action,
  // a stop opens its location.
  supplyChainMapClick(e) {
    const el = e?.target?.closest?.('[data-sc-action],[data-sc-loc]');
    if (!el) return;
    if (el.dataset.scAction) this.navigateToSupplyChain(el.dataset.scAction);
    else if (el.dataset.scLoc) this.navigateTo(el.dataset.scLoc);
  },

  // Inline stroke icon for the Supply Chain angle switcher.
  supplyChainModeIcon(key) {
    const d = {
      timeline: 'M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01',
      states:
        'M5 7a2 2 0 012-2h3v4H5V7zm9-2h3a2 2 0 012 2v2h-5V5zM5 15h5v4H7a2 2 0 01-2-2v-2zm9 0h5v2a2 2 0 01-2 2h-3v-4zM10 9h4m-2-2v10',
      processes:
        'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4',
      custody: 'M7 16V4m0 0L4 7m3-3l3 3M17 8v12m0 0l3-3m-3 3l-3-3',
      map: 'M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-1.447-.894L15 4m0 13V4m0 0L9 7'
    }[key];
    if (!d) return '';
    return `<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="${d}"/></svg>`;
  },

  // Lazily renders the product state machine into the #sc-state-diagram host.
  // Mermaid is dynamically imported so it stays out of the initial bundle;
  // failures degrade quietly since the stepper below carries the same detail.
  // The host lives inside an x-if subtree, so it may not be in the DOM the
  // instant a trigger fires; retry across a few frames until it appears.
  async renderSupplyChainStateDiagram(retries = 10) {
    const host = document.getElementById('sc-state-diagram');
    if (!host) {
      if (retries > 0) {
        requestAnimationFrame(() => this.renderSupplyChainStateDiagram(retries - 1));
      }
      return;
    }
    const source = this.supplyChainStateMermaid;
    if (!source) {
      host.innerHTML = '';
      delete host.dataset.src;
      return;
    }
    if (host.dataset.src === source) return;
    host.dataset.src = source;
    try {
      const { renderMermaid } = await import('../lib/mermaid.js');
      const svg = await renderMermaid(source);
      if (host.dataset.src !== source) return; // superseded while awaiting
      host.innerHTML = svg;
      // Best-effort click-through: a state node jumps to its stepper card.
      this.supplyChainLifecycleSteps.forEach((step, i) => {
        const node = [...host.querySelectorAll('g[id]')].find((g) =>
          new RegExp(`(?:^|[-_])s${i}(?:[-_]|$)`).test(g.id)
        );
        if (!node) return;
        node.style.cursor = 'pointer';
        node.addEventListener('click', () => this.navigateToSupplyChain(step.action.spdxId));
      });
    } catch (err) {
      console.error('Supply chain state diagram render failed', err);
      host.innerHTML =
        '<div class="text-xs text-rose-300 px-1 py-3">Could not render the state diagram.</div>';
      delete host.dataset.src;
    }
  },

  supplyChainRefName(id) {
    return id ? this.relTargetDisplayName(id) : '';
  },

  // BoundaryDefinitionAction.boundaryParameter is a set of DictionaryEntry
  // values ("key=value"). Older data may instead carry a single element
  // reference, so fall back to a ref-name lookup for a plain string.
  supplyChainBoundaryParamLabel(el) {
    const bp = el?.supplychain_boundaryParameter;
    if (!bp) return '';
    const entries = Array.isArray(bp) ? bp : [bp];
    return entries
      .map((entry) => {
        if (entry && typeof entry === 'object') {
          const key = entry.key ?? '';
          const value = entry.value ?? '';
          return key ? `${key}=${value}` : String(value);
        }
        return this.supplyChainRefName(entry);
      })
      .filter(Boolean)
      .join(' · ');
  },

  supplyChainRoute(el) {
    if (!el) return '';
    const from = this.supplyChainRefName(el.supplychain_pickupLocation);
    const to = this.supplyChainRefName(el.supplychain_dropoffLocation);
    if (from && to) return `${from} → ${to}`;
    return from || to || this.supplyChainRefName(el.actionLocation);
  },

  supplyChainStateName(el) {
    return this.supplyChainRefName(el?.supplychain_currentState);
  },

  supplyChainResponsibility(el) {
    if (!el?.supplychain_responsibilityChangedOn) return null;
    return {
      previous: this.supplyChainRefName(el.supplychain_previous),
      current: this.supplyChainRefName(el.supplychain_current),
      product: this.supplyChainRefName(el.supplychain_responsibilityChangedOn),
      category: el.supplychain_responsibilityCategory || ''
    };
  },

  supplyChainPerformerNames(el) {
    return this.outgoingRels(el?.spdxId)
      .filter((rel) => rel.relationshipType === 'performedBy')
      .flatMap((rel) => (Array.isArray(rel.to) ? rel.to : [rel.to]))
      .map((id) => this.supplyChainRefName(id))
      .filter(Boolean);
  },

  supplyChainTargets(el, relationshipType) {
    return this.outgoingRels(el?.spdxId)
      .filter((rel) => rel.relationshipType === relationshipType)
      .flatMap((rel) => (Array.isArray(rel.to) ? rel.to : [rel.to]))
      .map((id) => this.elementMap.get(id))
      .filter(Boolean);
  },

  supplyChainTargetNames(el, relationshipType, limit = 2) {
    const names = this.supplyChainTargets(el, relationshipType)
      .map((target) => target.name || this.cleanName(target.spdxId))
      .filter(Boolean);
    if (names.length <= limit) return names.join(', ');
    return `${names.slice(0, limit).join(', ')} +${names.length - limit}`;
  },

  supplyChainEvidenceCount(el) {
    return this.outgoingRels(el?.spdxId)
      .filter((rel) => rel.relationshipType === 'hasEvidence')
      .reduce((n, rel) => n + (Array.isArray(rel.to) ? rel.to.length : rel.to ? 1 : 0), 0);
  },

  supplyChainSpecRows(el) {
    const rows = [];
    const push = (label, value, mono = false) => {
      if (this.isMeaningful(value)) rows.push({ label, value, mono });
    };
    push('Time', this.supplyChainTimeRange(el));
    push('Location', this.supplyChainRefName(el?.actionLocation));
    push('Route', el?.supplychain_transportRoute);
    push('Pickup', this.supplyChainRefName(el?.supplychain_pickupLocation));
    push('Dropoff', this.supplyChainRefName(el?.supplychain_dropoffLocation));
    push('Distance', this.supplyChainDistanceKm(el) ? `${this.supplyChainDistanceKm(el)} km` : '');
    push('CO₂e', this.formatCarbonKg(this.supplyChainCarbonKg(el)));
    push('Transport mode', this.supplyChainTransportMode(el));
    push('Current state', this.supplyChainStateName(el));
    push('Decision process', this.supplyChainRefName(el?.supplychain_decisionProcess));
    push('Boundary parameter', this.supplyChainBoundaryParamLabel(el));
    push('Destruction by', this.supplyChainRefName(el?.supplychain_destructionPerformedBy));
    const responsibility = this.supplyChainResponsibility(el);
    if (responsibility) {
      push(
        'Responsibility',
        `${responsibility.previous || '—'} → ${responsibility.current || '—'}`
      );
      push('Changed on', responsibility.product);
      push('Category', responsibility.category);
    }
    push('SPDX ID', el?.spdxId, true);
    return rows;
  },

  supplyChainCardFacts(el) {
    const facts = [];
    const push = (label, value) => {
      if (this.isMeaningful(value)) facts.push({ label, value });
    };
    if (this.supplyChainKind(el) === 'process') {
      const actions = this.supplyChainProcessActions(el);
      const decisions = actions.filter(
        (action) => action.supplychain_decisionProcess === el.spdxId
      );
      push('Process class', this.supplyChainTypeLabel(el));
      push(
        'Observed actions',
        actions.length ? `${actions.length} execution(s)` : 'Definition only'
      );
      push('Used for decisions', decisions.length ? `${decisions.length} state transition(s)` : '');
      push(
        'Representative action',
        actions[0] ? actions[0].name || this.cleanName(actions[0].spdxId) : ''
      );
      return facts.slice(0, 4);
    }
    if (this.supplyChainKind(el) === 'state') {
      const stateActions = this.supplyChainStateActions(el);
      push('State class', this.supplyChainTypeLabel(el));
      push('Reached by', stateActions.length ? `${stateActions.length} transition(s)` : '');
      push(
        'Transition action',
        stateActions[0] ? stateActions[0].name || this.cleanName(stateActions[0].spdxId) : ''
      );
      push('SPDX ID', el?.spdxId);
      return facts.slice(0, 4);
    }
    push('Time', this.supplyChainTimeRange(el));
    push('Where', this.supplyChainRoute(el));
    push('CO₂e', this.formatCarbonKg(this.supplyChainCarbonKg(el)));
    push('State', this.supplyChainStateName(el));
    const responsibility = this.supplyChainResponsibility(el);
    if (responsibility) {
      push('Handoff', `${responsibility.previous || '—'} → ${responsibility.current || '—'}`);
      push('Product', responsibility.product);
    }
    push('Outputs', this.supplyChainTargetNames(el, 'hasOutput'));
    push('Affects', this.supplyChainTargetNames(el, 'affects'));
    push(
      'Evidence',
      this.supplyChainEvidenceCount(el) ? `${this.supplyChainEvidenceCount(el)} artifact(s)` : ''
    );
    return facts.slice(0, 4);
  },

  supplyChainConceptChips(el) {
    const chips = [];
    const push = (label, count, className = '') => {
      if (count > 0) chips.push({ label, count, className });
    };
    const meta = this.supplyChainFamilyMeta(el);
    const kind = this.supplyChainKind(el);
    if (kind === 'process') {
      push('actions', this.supplyChainProcessActions(el).length, meta.chip);
      push(
        'decisions',
        this.supplyChainProcessActions(el).filter(
          (action) => action.supplychain_decisionProcess === el.spdxId
        ).length,
        'bg-teal-500/15 text-teal-200 ring-1 ring-teal-500/25'
      );
    } else if (kind === 'state') {
      push('transitions', this.supplyChainStateActions(el).length, meta.chip);
    } else {
      push(
        'performers',
        this.supplyChainPerformerNames(el).length,
        'bg-lime-500/15 text-lime-200 ring-1 ring-lime-500/25'
      );
      push(
        'evidence',
        this.supplyChainEvidenceCount(el),
        'bg-amber-500/15 text-amber-200 ring-1 ring-amber-500/25'
      );
      push(
        'kg CO₂e',
        this.supplyChainCarbonKg(el),
        'bg-emerald-500/15 text-emerald-200 ring-1 ring-emerald-500/25'
      );
      push(
        'affected',
        this.supplyChainTargets(el, 'affects').length,
        'bg-cyan-500/15 text-cyan-200 ring-1 ring-cyan-500/25'
      );
      push(
        'requirements',
        this.supplyChainTargets(el, 'hasRequirement').length,
        'bg-violet-500/15 text-violet-200 ring-1 ring-violet-500/25'
      );
    }
    const relCount = this.outgoingRels(el?.spdxId).length + this.incomingRels(el?.spdxId).length;
    push('links', relCount, 'bg-slate-700/80 text-slate-200 ring-1 ring-slate-600/40');
    return chips.slice(0, 4);
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
      if (ids.length === 1) {
        return {
          id: ids[0],
          displayName: this.relTargetDisplayName(ids[0]),
          direction: bucket.direction,
          scope: ''
        };
      }
      const ordered = ids
        .map((id) => ({ id, el: this.elementMap.get(id) }))
        .sort(
          (a, b) =>
            (a.el?.software_lineRange?.beginIntegerRange ?? 0) -
            (b.el?.software_lineRange?.beginIntegerRange ?? 0)
        )
        .map((s) => s.id);
      const base = bucket.ref?.baseName || 'snippet';
      return {
        id: ordered[0],
        displayName: `${base} › ${ordered.length} ranges`,
        direction: bucket.direction,
        scope: '',
        multiRange: true,
        snippetIds: ordered
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

  // Ordered detail sequence for a requirement card: the relationship groups with
  // the "Verification & evaluation" block spliced in at the verifiedBy slot, so
  // the card reads implementation → verification → traceability. Verification is
  // shown here (not as its own hoisted section) so it never sits ahead of the
  // implementation it validates. Each entry is { kind: 'rel', group } or
  // { kind: 'verification' }.
  requirementDetailSequence(el) {
    const seq = this.detailRelGroupsFor(el, { excludeKeys: ['verifiedBy:out'] }).map((g) => ({
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

  // Evidence targets reachable from a requirement via
  // verifiedBy → EvaluationResult --hasEvidence--> artifact/snippet/file.
  requirementEvidence(el, { limit = 8 } = {}) {
    if (!el?.spdxId) return [];
    const seen = new Set();
    const out = [];
    const pushTarget = (id) => {
      if (!id || seen.has(id)) return;
      seen.add(id);
      const target = this.elementMap.get(id);
      out.push({
        id,
        name: target?.description || target?.name || this.cleanName(id),
        el: target
      });
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
    return {
      items: out.slice(0, limit),
      total: out.length,
      hiddenCount: Math.max(0, out.length - limit)
    };
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
    const impl = this.implementedByCount(el.spdxId);
    if (impl === 0) parts.push('no implementation');
    else if (impl === 1) parts.push('implemented in 1 place');
    else parts.push(`implemented in ${this.formatCount(impl)} places`);
    return parts.join(' · ');
  },

  // Presentation metadata ({label, color, dotClass, badgeClass}) for a
  // requirement verification-status key (as returned by requirementSafetyStatus)
  // or the 'noimpl' traceability-gap key. Drives the rollup bar and the
  // status-filter chips, mirroring vexStatusMeta for the security view.
  safetyStatusMeta(key) {
    if (key === SAFETY_NO_IMPL_META.key) return SAFETY_NO_IMPL_META;
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
    return this.requirementSafetyStatus(el) || this.evaluationResultMeta(el);
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
