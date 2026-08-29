import { escapeHtml } from '../lib/index.js';
import { COLORS } from '../config.js';
import { CLASS, isA } from '../spdx/model.js';

/**
 * The SupplyChain profile: everything behind the Supply Chain view.
 *
 * SPDX 3 models a physical supply chain as Actions (create, transport, use,
 * destroy) against States, tied together by custody handoffs and boundary
 * definitions. This module turns that graph into the shapes the view renders:
 * the event families and their filters, the timeline and custody journey, the
 * carbon and transport rollups, the state machine, and the route map.
 *
 * It is one module rather than two halves of `accessors` and `derived` because
 * it is one feature. Splitting it back out along the accessor/getter line would
 * put 40 formatters in one file and the 20 getters that call them in another,
 * which is where this code lived before and why both of those files had grown
 * past 1,800 lines.
 *
 * Merged onto the same Alpine object as every other mixin (see app.js), so
 * `this.*` still reaches the rest of the app: relationship lookups from
 * `accessors`, the parsed indexes from `state`, navigation from `navigation`.
 *
 * @module app/supply-chain
 */

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

// Memo slots for the getters below, kept off the reactive state so Alpine does
// not proxy them. `supplyChainActions` feeds most of the rest of this file, so a
// single identity memo on the source list spares the whole cascade a
// re-filter+sort; the counts rollup is a full scan read by every view header at
// shell mount. Cleared through resetSupplyChainMemos when a document loads.
let scActionsSrc = null;
let scActionsVal = [];
let scCountsSrc = null;
let scCountsVal = null;
let filteredSupplyChainCacheKey = null;
let filteredSupplyChainCacheVal = [];

/**
 * Drops every memoized supply chain result. Called from `_resetListMemos` in
 * derived.js when fresh data is applied, so the next getter read recomputes.
 */
export function resetSupplyChainMemos() {
  scActionsSrc = null;
  scCountsSrc = null;
  filteredSupplyChainCacheKey = null;
}

export const supplyChainMixin = {
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
        hover: 'hover:bg-rose-500/11',
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
        surface: 'bg-slate-500/6',
        hover: 'hover:bg-slate-500/10',
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

  // ---- Computed views over the parsed elements ----------------------------
  // Everything above is a per-element helper the templates call directly.
  // Everything below is a whole-collection rollup, memoized on its inputs.

  get supplyChainCounts() {
    if (scCountsSrc === this.supplyChain) return scCountsVal;
    const c = {
      actions: 0,
      processes: 0,
      states: 0,
      transports: 0,
      custody: 0,
      inspections: 0,
      tests: 0,
      exceptions: 0,
      resolutions: 0
    };
    this.supplyChain.forEach((el) => {
      const kind = this.supplyChainKind(el);
      if (kind === 'action') c.actions++;
      else if (kind === 'process') c.processes++;
      else if (kind === 'state') c.states++;
      if (isA(el.type, CLASS.supplychain_TransportAction)) c.transports++;
      if (isA(el.type, CLASS.supplychain_ResponsibilityChangeAction)) c.custody++;
      if (isA(el.type, CLASS.supplychain_InspectionAction)) c.inspections++;
      if (isA(el.type, CLASS.supplychain_TestAction)) c.tests++;
      const status = this.supplyChainExceptionStatus(el);
      if (status?.key === 'exception') c.exceptions++;
      if (status?.key === 'resolved') c.resolutions++;
    });
    scCountsVal = c;
    scCountsSrc = this.supplyChain;
    return c;
  },

  // Memoized on the source list: nearly every other supply-chain getter reads
  // this one, so without it a single render re-filters and re-sorts the whole
  // supply-chain list once per reader.
  get supplyChainActions() {
    if (scActionsSrc === this.supplyChain) return scActionsVal;
    scActionsVal = this.supplyChain
      .filter((el) => this.supplyChainKind(el) === 'action')
      .sort((a, b) => (a.startTime || '').localeCompare(b.startTime || ''));
    scActionsSrc = this.supplyChain;
    return scActionsVal;
  },

  // Timeline events: the actions that genuinely happen at a point in time.
  // StateActions are excluded here because they are the transitions of the
  // product state machine, which has its own States angle; keeping them out
  // leaves the timeline focused on the substantive supply-chain events.
  get supplyChainEvents() {
    return this.supplyChainActions.filter((el) => !isA(el.type, CLASS.supplychain_StateAction));
  },

  // Action families present among the timeline events, in phase order, each with
  // its count. Drives the timeline's filter chips (replacing the old
  // action/state/process kind chips, which mixed three different concepts).
  get supplyChainEventFamilies() {
    const order = ['create', 'modify', 'move', 'verify', 'exception', 'operate', 'other'];
    const counts = {};
    this.supplyChainEvents.forEach((el) => {
      const family = this.supplyChainFamily(el);
      counts[family] = (counts[family] || 0) + 1;
    });
    return order
      .filter((key) => counts[key])
      .map((key) => ({ key, label: this.supplyChainFamilyLabel(key), n: counts[key] }));
  },

  get supplyChainProcesses() {
    return this.supplyChain
      .filter((el) => this.supplyChainKind(el) === 'process')
      .sort((a, b) =>
        (a.name || this.cleanName(a.spdxId)).localeCompare(b.name || this.cleanName(b.spdxId))
      );
  },

  get supplyChainStates() {
    return this.supplyChain
      .filter((el) => this.supplyChainKind(el) === 'state')
      .sort((a, b) =>
        (a.name || this.cleanName(a.spdxId)).localeCompare(b.name || this.cleanName(b.spdxId))
      );
  },

  get supplyChainStateTransitions() {
    return this.supplyChainActions
      .filter((el) => isA(el.type, CLASS.supplychain_StateAction))
      .map((action, index, list) => ({
        action,
        index,
        previous: index > 0 ? this.elementMap.get(list[index - 1].supplychain_currentState) : null,
        state: this.elementMap.get(action.supplychain_currentState) || null,
        decisionProcess: this.elementMap.get(action.supplychain_decisionProcess) || null,
        status: this.supplyChainExceptionStatus(action)
      }));
  },

  get supplyChainCustodyHandoffs() {
    return this.supplyChainActions
      .filter((el) => isA(el.type, CLASS.supplychain_ResponsibilityChangeAction))
      .map((action) => ({
        action,
        previous: this.elementMap.get(action.supplychain_previous) || null,
        current: this.elementMap.get(action.supplychain_current) || null,
        product: this.elementMap.get(action.supplychain_responsibilityChangedOn) || null,
        category: action.supplychain_responsibilityCategory || '',
        location: this.elementMap.get(action.actionLocation) || null
      }));
  },

  get supplyChainTransportLegs() {
    return this.supplyChainActions
      .filter((el) => isA(el.type, CLASS.supplychain_TransportAction))
      .map((action) => ({
        action,
        pickup: this.elementMap.get(action.supplychain_pickupLocation) || null,
        dropoff: this.elementMap.get(action.supplychain_dropoffLocation) || null,
        route: action.supplychain_transportRoute || ''
      }));
  },

  get supplyChainTimelineRows() {
    const rows = this.filteredSupplyChain.map((item, index) => ({
      item,
      action: item,
      index,
      kind: this.supplyChainKind(item),
      family: this.supplyChainFamily(item),
      phase: this.supplyChainFamilyMeta(item).label,
      status: this.supplyChainExceptionStatus(item),
      duration: this.supplyChainDurationLabel(item),
      route: this.supplyChainRoute(item),
      state: this.supplyChainStateName(item),
      carbonKg: this.supplyChainCarbonKg(item),
      distanceKm: this.supplyChainDistanceKm(item),
      mode: this.supplyChainTransportMode(item),
      evidence: this.supplyChainEvidenceCount(item),
      time: item.startTime || item.endTime || ''
    }));
    // Day dividers and elapsed-time markers add breathing room and temporal
    // orientation to the chronological list. Computed over the filtered set so
    // gaps reflect only the events actually shown.
    let prevDay = null;
    let prevMs = null;
    for (const row of rows) {
      const ms = row.time ? Date.parse(row.time) : NaN;
      const day = Number.isFinite(ms) ? row.time.slice(0, 10) : null;
      row.newDay = Boolean(day) && day !== prevDay;
      row.dayLabel = row.newDay ? this.supplyChainDayHeading(row.time) : '';
      row.gapLabel =
        Number.isFinite(ms) && Number.isFinite(prevMs)
          ? this.supplyChainElapsedLabel(prevMs, ms)
          : '';
      row.stateChanges = [];
      if (Number.isFinite(ms)) {
        prevDay = day;
        prevMs = ms;
      }
    }
    // StateActions are otherwise hidden from the event list (they are the product
    // state machine's transitions), so it's easy to lose track of when the tracked
    // product changes state. Surface each transition inline, attached below the
    // last event that occurred at or before it, so the timeline shows exactly when
    // the product entered a new state.
    for (const step of this.supplyChainLifecycleSteps) {
      if (!rows.length) break;
      const stepMs = step.time ? Date.parse(step.time) : NaN;
      let target = null;
      if (Number.isFinite(stepMs)) {
        for (const row of rows) {
          const rowMs = row.time ? Date.parse(row.time) : NaN;
          if (Number.isFinite(rowMs) && rowMs <= stepMs) target = row;
        }
      }
      (target || rows[0]).stateChanges.push({
        spdxId: step.action.spdxId,
        name: step.name,
        tone: step.tone,
        time: step.time
      });
    }
    return rows;
  },

  get supplyChainCarbonSummary() {
    const rows = this.supplyChainActions
      .map((action) => ({
        action,
        kg: this.supplyChainCarbonKg(action),
        distanceKm: this.supplyChainDistanceKm(action),
        mode: this.supplyChainTransportMode(action),
        route: this.supplyChainRoute(action)
      }))
      .filter((row) => row.kg > 0);
    const totalKg = rows.reduce((total, row) => total + row.kg, 0);
    const maxKg = rows.reduce((max, row) => Math.max(max, row.kg), 0);
    return {
      rows: rows.map((row) => ({
        ...row,
        pct: maxKg ? Math.max(4, Math.round((row.kg / maxKg) * 100)) : 0
      })),
      totalKg,
      maxKg
    };
  },

  get supplyChainExceptionChains() {
    return this.supplyChainActions
      .filter((el) => isA(el.type, CLASS.supplychain_OutOfSpecAction))
      .map((exception) => {
        const seenResolutionIds = new Set();
        const resolutions = this.relationships
          .filter(
            (rel) =>
              (rel.relationshipType === 'resolved' || rel.relationshipType === 'hasResolution') &&
              (Array.isArray(rel.to) ? rel.to : [rel.to]).includes(exception.spdxId)
          )
          .map((rel) => this.elementMap.get(rel.from))
          .filter((resolution) => {
            if (!resolution || seenResolutionIds.has(resolution.spdxId)) return false;
            seenResolutionIds.add(resolution.spdxId);
            return true;
          });
        return {
          exception,
          resolutions,
          evidenceCount:
            this.supplyChainEvidenceCount(exception) +
            resolutions.reduce(
              (total, resolution) => total + this.supplyChainEvidenceCount(resolution),
              0
            )
        };
      });
  },

  get supplyChainActionLanes() {
    const lanes = [
      {
        key: 'create',
        label: 'Create / make',
        color: '#38bdf8',
        items: this.supplyChainActions.filter(
          (el) =>
            isA(el.type, CLASS.supplychain_CreateAction) ||
            isA(el.type, CLASS.supplychain_ManufactureAction) ||
            isA(el.type, CLASS.supplychain_AssemblyAction) ||
            isA(el.type, CLASS.supplychain_HarvestAction) ||
            isA(el.type, CLASS.supplychain_ReproduceAction)
        )
      },
      {
        key: 'move',
        label: 'Move / custody',
        color: '#22d3ee',
        items: this.supplyChainActions.filter(
          (el) =>
            isA(el.type, CLASS.supplychain_TransportAction) ||
            isA(el.type, CLASS.supplychain_StorageAction) ||
            isA(el.type, CLASS.supplychain_ResponsibilityChangeAction) ||
            isA(el.type, CLASS.supplychain_BoundaryCrossingAction)
        )
      },
      {
        key: 'verify',
        label: 'Inspect / test / decide',
        color: '#a78bfa',
        items: this.supplyChainActions.filter(
          (el) =>
            isA(el.type, CLASS.supplychain_InspectionAction) ||
            isA(el.type, CLASS.supplychain_TestAction) ||
            isA(el.type, CLASS.supplychain_StateAction)
        )
      },
      {
        key: 'exception',
        label: 'Exception / resolution',
        color: '#fb7185',
        items: this.supplyChainActions.filter(
          (el) =>
            isA(el.type, CLASS.supplychain_OutOfSpecAction) ||
            isA(el.type, CLASS.supplychain_ResolutionAction)
        )
      },
      {
        key: 'operate',
        label: 'Use / retire',
        color: '#34d399',
        items: this.supplyChainActions.filter(
          (el) =>
            isA(el.type, CLASS.supplychain_UseAction) ||
            isA(el.type, CLASS.supplychain_PlanAction) ||
            isA(el.type, CLASS.supplychain_DestroyAction)
        )
      }
    ];
    return lanes.filter((lane) => lane.items.length);
  },

  // Chain-of-custody relay: the ordered list of parties responsible for the
  // tracked product, each with the transport legs and checkpoints that happened
  // on their watch. Seeds the first holder from the earliest handoff's previous
  // party, then advances at each ResponsibilityChangeAction.
  get supplyChainCustodyJourney() {
    const handoffs = this.supplyChainCustodyHandoffs;
    const actions = this.supplyChainActions;
    if (!handoffs.length || !actions.length) return [];
    const firstTime = actions[0].startTime || actions[0].endTime || '';
    const last = actions[actions.length - 1];
    const lastTime = last.endTime || last.startTime || '';
    const points = [
      { holder: handoffs[0].previous, category: '', gainedVia: null, start: firstTime },
      ...handoffs.map((h) => ({
        holder: h.current,
        category: h.category,
        gainedVia: h,
        start: h.action.endTime || h.action.startTime || ''
      }))
    ];
    return points.map((p, i) => {
      const next = points[i + 1];
      const end = next ? next.gainedVia.action.startTime || next.start : lastTime;
      const inWindow = (a) => {
        const t = a.startTime || a.endTime || '';
        if (!t || t < p.start) return false;
        return next ? t < end : true;
      };
      const windowActions = actions.filter(inWindow);
      const legs = windowActions
        .filter((a) => isA(a.type, CLASS.supplychain_TransportAction))
        .map((a) => ({
          action: a,
          route: this.supplyChainRoute(a),
          mode: this.supplyChainTransportMode(a),
          distanceKm: this.supplyChainDistanceKm(a),
          carbonKg: this.supplyChainCarbonKg(a),
          duration: this.supplyChainDurationLabel(a)
        }));
      const checkpoints = windowActions
        .filter(
          (a) =>
            !isA(a.type, CLASS.supplychain_TransportAction) &&
            !isA(a.type, CLASS.supplychain_StateAction) &&
            !isA(a.type, CLASS.supplychain_ResponsibilityChangeAction) &&
            !isA(a.type, CLASS.supplychain_BoundaryDefinitionAction)
        )
        .map((a) => ({
          action: a,
          family: this.supplyChainFamily(a),
          meta: this.supplyChainFamilyMeta(a),
          status: this.supplyChainExceptionStatus(a)
        }));
      const startMs = Date.parse(p.start);
      const endMs = Date.parse(end);
      return {
        holder: p.holder,
        name: p.holder ? p.holder.name || this.cleanName(p.holder.spdxId) : 'Unassigned',
        summary: p.holder?.summary || '',
        role: i === 0 ? 'origin' : p.category || 'custody',
        gainedVia: p.gainedVia,
        handoffLocation: p.gainedVia
          ? this.supplyChainRefName(p.gainedVia.action.actionLocation)
          : '',
        start: p.start,
        end,
        duration: this.supplyChainElapsedLabel(startMs, endMs),
        legs,
        checkpoints,
        exceptions: checkpoints.filter((c) => c.status?.key === 'exception').length,
        distanceKm: legs.reduce((s, l) => s + (l.distanceKm || 0), 0),
        carbonKg: legs.reduce((s, l) => s + (l.carbonKg || 0), 0),
        index: i
      };
    });
  },

  // Product lifecycle as an ordered set of state transitions (StateActions), each
  // enriched with the state's meaning, when/where it happened, the decision
  // process that drove it, and a tone (positive / exception / neutral) for the
  // stepper node colour.
  get supplyChainLifecycleSteps() {
    return this.supplyChainStateTransitions.map((t) => {
      const name = t.state
        ? t.state.name || this.cleanName(t.state.spdxId)
        : this.supplyChainStateName(t.action) || '—';
      let tone = 'neutral';
      if (/quarantine|out.?of.?spec|reject|fail|hold/i.test(name)) tone = 'exception';
      else if (/accept|pass|deploy|resolv|complete|provision/i.test(name)) tone = 'positive';
      return {
        action: t.action,
        state: t.state,
        name,
        description: t.state?.description || t.state?.summary || '',
        time: t.action.startTime || t.action.endTime || '',
        location: this.supplyChainRefName(t.action.actionLocation),
        decisionProcess: t.decisionProcess
          ? t.decisionProcess.name || this.cleanName(t.decisionProcess.spdxId)
          : '',
        performers: this.supplyChainPerformerNames(t.action),
        evidence: this.supplyChainEvidenceCount(t.action),
        status: t.status,
        tone
      };
    });
  },

  // The product state machine as Mermaid stateDiagram-v2 source. Nodes follow
  // the StateAction trajectory (received -> ... -> deployed), transitions carry
  // their decision process as a label, and exception / positive states get a
  // themed class. Rendered lazily by renderSupplyChainStateDiagram().
  get supplyChainStateMermaid() {
    const steps = this.supplyChainLifecycleSteps;
    if (!steps.length) return '';
    // Not HTML escaping: these characters are what break stateDiagram-v2 label
    // syntax, so they are stripped rather than turned into entities (Mermaid
    // would render an entity literally).
    const mermaidLabel = (value) =>
      String(value || '')
        .replace(/[:<>"\n\r]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
    const lines = [
      'stateDiagram-v2',
      // Every state is explicitly classed: Mermaid's base theme leaves the
      // default state label the same tone as the node fill, which is unreadable
      // on the dark surface, so even neutral states carry an explicit colour.
      'classDef neutral fill:#1e293b,stroke:#475569,color:#e2e8f0',
      'classDef exception fill:#4c0519,stroke:#fb7185,color:#fecdd3',
      'classDef positive fill:#053e30,stroke:#34d399,color:#a7f3d0',
      '[*] --> s0'
    ];
    steps.forEach((step, i) => lines.push(`s${i} : ${mermaidLabel(step.name) || 'State'}`));
    steps.forEach((step, i) => {
      if (i === 0) return;
      const label = mermaidLabel((step.decisionProcess || '').replace(/\s*process$/i, ''));
      lines.push(label ? `s${i - 1} --> s${i} : ${label}` : `s${i - 1} --> s${i}`);
    });
    lines.push(`s${steps.length - 1} --> [*]`);
    steps.forEach((step, i) => {
      const cls =
        step.tone === 'exception' ? 'exception' : step.tone === 'positive' ? 'positive' : 'neutral';
      lines.push(`class s${i} ${cls}`);
    });
    return lines.join('\n');
  },

  // Defined processes (the plans) grouped by lifecycle phase, for the Processes
  // playbook. Each process keeps the actions that executed it so the plan ->
  // doing relationship stays visible.
  get supplyChainProcessGroups() {
    const order = ['create', 'modify', 'move', 'verify', 'operate', 'process', 'other'];
    const groups = new Map();
    this.supplyChainProcesses.forEach((proc) => {
      const key = this.supplyChainFamily(proc);
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(proc);
    });
    return order
      .filter((key) => groups.has(key))
      .map((key) => ({
        key,
        label: this.supplyChainFamilyLabel(key),
        processes: groups.get(key)
      }));
  },

  // Route map geometry: ordered stops (transport pickup/dropoff spine plus any
  // other action locations) projected onto an equirectangular viewBox, with the
  // transport legs as bowed connectors coloured by mode. Falls back to a
  // schematic left-to-right layout when fewer than two stops can be geocoded.
  get supplyChainRouteMap() {
    const legs = this.supplyChainTransportLegs;
    const actions = this.supplyChainActions;
    // Distinct places, keyed by city (so several facilities in one city collapse
    // to a single pin even when their geographicPointLocation coordinates
    // differ), falling back to coordinate or id. The route follows the tracked
    // product's handling, so component-origin (create/manufacture/harvest)
    // locations are left off the route; they belong to the custody and timeline
    // angles.
    const placeKey = (loc) => {
      const c = this.supplyChainGeocode(loc);
      const city = String(loc.city || '')
        .trim()
        .toLowerCase();
      const key = city
        ? `${city}|${String(loc.country || '').toLowerCase()}`
        : c
          ? `${c.lat},${c.lng}`
          : loc.spdxId;
      return { key, coord: c };
    };
    const spdxToKey = new Map();
    const keyInfo = new Map();
    const keyOrder = [];
    const consider = (loc) => {
      if (!loc) return;
      const { key, coord } = placeKey(loc);
      spdxToKey.set(loc.spdxId, key);
      if (!keyInfo.has(key)) {
        keyInfo.set(key, { loc, coord });
        keyOrder.push(key);
      }
    };
    for (const leg of legs) {
      consider(leg.pickup);
      consider(leg.dropoff);
    }
    for (const a of actions) {
      if (this.supplyChainFamily(a) === 'create') continue;
      consider(this.elementMap.get(a.actionLocation));
    }
    if (!keyOrder.length) {
      return { stops: [], connectors: [], projected: false, viewBox: '0 0 1000 460' };
    }
    // Order pins by when the product first reaches each place.
    const timeByKey = new Map();
    for (const a of actions) {
      if (this.supplyChainFamily(a) === 'create') continue;
      const loc = this.elementMap.get(a.actionLocation);
      if (!loc) continue;
      const key = spdxToKey.get(loc.spdxId);
      const t = a.startTime || a.endTime || '';
      if (t && (!timeByKey.has(key) || t < timeByKey.get(key))) timeByKey.set(key, t);
    }
    const geo = keyOrder
      .map((key) => ({ key, ...keyInfo.get(key) }))
      .sort((a, b) => {
        const ta = timeByKey.get(a.key) || '';
        const tb = timeByKey.get(b.key) || '';
        if (ta && tb) return ta.localeCompare(tb);
        if (ta) return -1;
        if (tb) return 1;
        return 0;
      });

    const W = 1000;
    const H = 460;
    const padX = 90;
    const padY = 70;
    const geocoded = geo.filter((g) => g.coord);
    const projected = geocoded.length >= 2;

    let placed;
    if (projected) {
      const lats = geocoded.map((g) => g.coord.lat);
      const lngs = geocoded.map((g) => g.coord.lng);
      let minLat = Math.min(...lats);
      let maxLat = Math.max(...lats);
      let minLng = Math.min(...lngs);
      let maxLng = Math.max(...lngs);
      const latPad = Math.max(0.5, (maxLat - minLat) * 0.14);
      const lngPad = Math.max(0.5, (maxLng - minLng) * 0.14);
      minLat -= latPad;
      maxLat += latPad;
      minLng -= lngPad;
      maxLng += lngPad;
      const project = (c) => ({
        x: padX + ((c.lng - minLng) / (maxLng - minLng)) * (W - 2 * padX),
        y: padY + ((maxLat - c.lat) / (maxLat - minLat)) * (H - 2 * padY)
      });
      placed = geo.map((g, i) =>
        g.coord
          ? { key: g.key, loc: g.loc, ...project(g.coord), geocoded: true }
          : {
              key: g.key,
              loc: g.loc,
              x: padX + (i / Math.max(1, geo.length - 1)) * (W - 2 * padX),
              y: H / 2,
              geocoded: false
            }
      );
    } else {
      placed = geo.map((g, i) => ({
        key: g.key,
        loc: g.loc,
        x: padX + (i / Math.max(1, geo.length - 1)) * (W - 2 * padX),
        y: H / 2 + (i % 2 ? 30 : -30),
        geocoded: false
      }));
    }

    const posByKey = new Map(placed.map((p) => [p.key, p]));
    const stops = placed.map((p, i) => ({
      spdxId: p.loc.spdxId,
      x: Number(p.x.toFixed(1)),
      y: Number(p.y.toFixed(1)),
      order: i + 1,
      geocoded: p.geocoded,
      name: p.loc.name || this.cleanName(p.loc.spdxId),
      place: this.supplyChainPlaceLabel(p.loc),
      role: this.supplyChainStopRole(p.loc)
    }));

    const connectors = legs
      .map((leg) => {
        const a = leg.pickup ? posByKey.get(spdxToKey.get(leg.pickup.spdxId)) : null;
        const b = leg.dropoff ? posByKey.get(spdxToKey.get(leg.dropoff.spdxId)) : null;
        if (!a || !b) return null;
        const mx = (a.x + b.x) / 2;
        const my = (a.y + b.y) / 2;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const len = Math.hypot(dx, dy) || 1;
        const bow = Math.min(90, len * 0.24);
        const cx = mx + (-dy / len) * bow;
        const cy = my + (dx / len) * bow;
        return {
          id: leg.action.spdxId,
          action: leg.action,
          d: `M ${a.x.toFixed(1)} ${a.y.toFixed(1)} Q ${cx.toFixed(1)} ${cy.toFixed(1)} ${b.x.toFixed(1)} ${b.y.toFixed(1)}`,
          labelX: Number(cx.toFixed(1)),
          labelY: Number(cy.toFixed(1)),
          mode: this.supplyChainTransportMode(leg.action),
          color: this.supplyChainModeColor(this.supplyChainTransportMode(leg.action)),
          distanceKm: this.supplyChainDistanceKm(leg.action),
          carbonKg: this.supplyChainCarbonKg(leg.action),
          route: leg.route
        };
      })
      .filter(Boolean);

    return {
      stops,
      connectors,
      projected,
      viewBox: `0 0 ${W} ${H}`,
      totalDistanceKm: connectors.reduce((s, c) => s + (c.distanceKm || 0), 0),
      totalCarbonKg: connectors.reduce((s, c) => s + (c.carbonKg || 0), 0)
    };
  },

  // The route map as a self-contained SVG string for x-html. Kept a string (not
  // inline template markup) because Alpine's <template x-for> is illegal inside
  // <svg> foreign content. Stops/legs carry data-sc-* ids for delegated clicks.
  get supplyChainRouteMapSvg() {
    const map = this.supplyChainRouteMap;
    if (!map.stops.length) return '';
    const km = (v) => `${Math.round(v).toLocaleString()} km`;
    const grid =
      [92, 184, 276, 368].map((y) => `<line x1="0" y1="${y}" x2="1000" y2="${y}"/>`).join('') +
      [200, 400, 600, 800].map((x) => `<line x1="${x}" y1="0" x2="${x}" y2="460"/>`).join('');
    const conns = map.connectors
      .map((c) => {
        const label = this.formatCarbonKg(c.carbonKg) || (c.distanceKm ? km(c.distanceKm) : c.mode);
        return (
          `<path d="${c.d}" fill="none" stroke="${c.color}" stroke-width="2.5" stroke-linecap="round" class="sc-flow" opacity="0.9"/>` +
          `<g class="cursor-pointer" data-sc-action="${escapeHtml(c.action.spdxId)}">` +
          `<rect x="${c.labelX - 36}" y="${c.labelY - 10}" width="72" height="18" rx="9" fill="#0f172a" stroke="#334155"/>` +
          `<text x="${c.labelX}" y="${c.labelY + 3}" text-anchor="middle" font-size="10" font-weight="600" fill="${c.color}">${escapeHtml(label)}</text></g>`
        );
      })
      .join('');
    const stops = map.stops
      .map(
        (s) =>
          `<g class="cursor-pointer" data-sc-loc="${escapeHtml(s.spdxId)}">` +
          `<circle cx="${s.x}" cy="${s.y}" r="12" fill="none" stroke="${s.role.color}" stroke-width="1" opacity="0.4"/>` +
          `<circle cx="${s.x}" cy="${s.y}" r="6.5" fill="${s.role.color}" stroke="#0b1220" stroke-width="2"/>` +
          `<text x="${s.x}" y="${s.y - 16}" text-anchor="middle" font-size="11.5" font-weight="600" fill="#e2e8f0">${escapeHtml(s.place || s.name)}</text>` +
          `<text x="${s.x}" y="${s.y + 23}" text-anchor="middle" font-size="9.5" fill="${s.role.color}">${escapeHtml(`#${s.order} · ${s.role.label}`)}</text></g>`
      )
      .join('');
    return (
      `<svg viewBox="${map.viewBox}" class="w-full block" preserveAspectRatio="xMidYMid meet" style="aspect-ratio:1000/460">` +
      `<rect x="0" y="0" width="1000" height="460" fill="#0b1220"/>` +
      `<g stroke="#152033" stroke-width="1">${grid}</g>${conns}${stops}</svg>`
    );
  },

  get filteredSupplyChain() {
    const events = this.supplyChainEvents;
    const key = `${events.length}|${this.supplyChainFamilyFilter}|${this.supplyChainExceptionFilter}|${this.supplyChainSearch}`;
    if (key === filteredSupplyChainCacheKey) return filteredSupplyChainCacheVal;

    let items = events;
    if (this.supplyChainFamilyFilter) {
      items = items.filter((el) => this.supplyChainFamily(el) === this.supplyChainFamilyFilter);
    }
    if (this.supplyChainExceptionFilter) {
      items = items.filter(
        (el) => this.supplyChainExceptionStatus(el)?.key === this.supplyChainExceptionFilter
      );
    }
    if (this.supplyChainSearch) {
      const q = this.supplyChainSearch.toLowerCase();
      items = items.filter(
        (el) =>
          (el.name || '').toLowerCase().includes(q) ||
          this.cleanName(el.spdxId).toLowerCase().includes(q) ||
          (el.description || '').toLowerCase().includes(q) ||
          (el.summary || '').toLowerCase().includes(q) ||
          (el.supplychain_transportRoute || '').toLowerCase().includes(q) ||
          this.supplyChainTypeLabel(el).toLowerCase().includes(q)
      );
    }
    filteredSupplyChainCacheVal = [...items].sort((a, b) => {
      const at = a.startTime || a.endTime || '';
      const bt = b.startTime || b.endTime || '';
      if (at && !bt) return -1;
      if (!at && bt) return 1;
      if (at && bt) {
        return (
          at.localeCompare(bt) ||
          this.supplyChainTypeLabel(a).localeCompare(this.supplyChainTypeLabel(b))
        );
      }
      return (a.name || this.cleanName(a.spdxId)).localeCompare(b.name || this.cleanName(b.spdxId));
    });
    filteredSupplyChainCacheKey = key;
    return filteredSupplyChainCacheVal;
  }
};
