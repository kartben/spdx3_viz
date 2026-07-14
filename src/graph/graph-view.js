import * as d3 from 'd3';

import {
  getRelationshipColor,
  getNodeType,
  getNodeTypeColor,
  cleanName,
  dirPrefix,
  iconKeyForElement,
  getNodeIconPath2D,
  snippetFileRef,
  computeLayers,
  bfsDepths,
  orderLaneTypes,
  DEFAULT_GRAPH_LAYOUT
} from '../lib/index.js';

// Icon-node mode: below this on-screen node radius (px) icons are illegible, so
// fall back to a plain dot. Glyphs are scaled to span ICON_SPAN * diameter, over
// a faint type-coloured halo that keeps the colour legend and a clear hit target.
const ICON_MIN_PX = 7;
const ICON_SPAN = 1.2;
const ICON_HALO_ALPHA = 0.22;

const INPUT_LAYOUT_LINKS_PER_BUILD = 8;
// Above this many underlying nodes or edges, force-collapse into clusters for
// readability (a flat graph of many thousands of nodes or a hairball of edges
// is unusable) and surface a hint.
const MAX_FLAT_NODES = 5000;
const MAX_FLAT_EDGES = 15000;
// Only draw labels past this zoom level, capped per frame, since they become noise when zoomed out.
const LABEL_ZOOM_THRESHOLD = 1.1;
const MAX_LABELS = 400;
// World-space padding for viewport culling so edge-of-screen nodes/edges still draw.
const CULL_PAD = 80;
// Per-type dash signatures so a link's semantics read from the line style, not just colour.
// Patterns are in screen pixels (divided by zoom factor k) to stay a constant on-screen size;
// returns null for solid (default) edges.
function dashPatternFor(type, lineWidth, k) {
  switch (type) {
    case 'usesTool':
    case 'verifiedBy':
      return [lineWidth, 4 / k];
    case 'hasDynamicLink':
    case 'implementedBy':
      return [7 / k, 5 / k];
    case 'conformsTo':
      // Longer dash than implementedBy so the two FunctionalSafety "dashed" edges don't read as one.
      return [12 / k, 6 / k];
    case 'hasOptionalComponent':
    case 'assumes':
      return [8 / k, 4 / k, lineWidth, 4 / k];
    case 'evaluationBasedOn':
      // Dash-dot-dot: one dash longer beat than assumes' dash-dot.
      return [8 / k, 3 / k, lineWidth, 3 / k, lineWidth, 3 / k];
    case 'tracedToDetail':
      // Long-dash-dot: a longer lead dash than assumes' dash-dot keeps the two apart.
      return [12 / k, 4 / k, lineWidth, 4 / k];
    case 'createdBy':
    case 'suppliedBy':
    case 'originatedBy':
    case 'manufacturedBy':
      // Fine dots read as a lightweight provenance link, distinct from structural edges.
      return [lineWidth, 3 / k];
    case 'hasEvidence':
      // Denser than the provenance dots above so it doesn't read as the same edge kind.
      return [lineWidth, 2 / k];
    case 'affectsFile':
      // Inferred vuln -> file link: an even dash so it reads as "derived", distinct
      // from the solid VEX `affects` edge in the same vulnerability colour family.
      return [6 / k, 4 / k];
    default:
      return null;
  }
}
// Relationship types drawn with an arrowhead at their head end; hasInput points at its source and
// hasOutput at its target, so the pair reads as inputs → build → outputs.
const ARROW_REL_TYPES = new Set(['hasInput', 'hasOutput']);
// Arrowhead dimensions in screen pixels (divided by zoom to stay a constant on-screen size).
const ARROW_LEN = 7;
const ARROW_HALF_WIDTH = 3;
// Hover "flow" animation: dashes march along a hovered node's directed edges in the flow direction.
// Dash/gap are screen pixels; SPEED is screen px per frame.
const FLOW_DASH = 5;
const FLOW_GAP = 12;
const FLOW_PERIOD = FLOW_DASH + FLOW_GAP;
const FLOW_SPEED = 0.3;

// Edge hover: how close (screen px) the pointer must be to a link to tooltip it, and
// the edge count above which the per-move linear scan is skipped (a dense hairball is
// unreadable anyway, so edge inspection there isn't worth the hit-test cost).
const EDGE_HIT_PX = 6;
const EDGE_HOVER_MAX = 8000;

function asTargets(to) {
  return Array.isArray(to) ? to : [to];
}

function placeholderFor(spdxId, rel, role) {
  const buildRelationshipTypes = new Set(['hasInput', 'hasOutput', 'ancestorOf']);
  const fileRelationshipTypes = new Set([
    'hasInput',
    'hasOutput',
    'hasDistributionArtifact',
    'contains',
    'generates'
  ]);

  const vexRelationshipTypes = new Set([
    'fixedIn',
    'doesNotAffect',
    'affects',
    'underInvestigation'
  ]);

  let type = 'ExternalReference';
  if (role === 'source' && vexRelationshipTypes.has(rel.relationshipType)) {
    type = 'security_Vulnerability';
  } else if (role === 'source' && buildRelationshipTypes.has(rel.relationshipType)) {
    type = 'build_Build';
  } else if (rel.relationshipType === 'ancestorOf') {
    type = 'build_Build';
  } else if (role === 'target' && fileRelationshipTypes.has(rel.relationshipType)) {
    type = 'software_File';
  }

  return {
    type,
    spdxId,
    name: cleanName(spdxId),
    placeholder: true
  };
}

function createLayoutLinks(links) {
  const inputLinksByBuild = new Map();
  const layoutLinks = [];

  links.forEach((link) => {
    if (link.type === 'hasInput') {
      const count = inputLinksByBuild.get(link.sourceId) || 0;
      if (count >= INPUT_LAYOUT_LINKS_PER_BUILD) return;
      inputLinksByBuild.set(link.sourceId, count + 1);
    }

    layoutLinks.push({
      source: link.sourceId,
      target: link.targetId,
      type: link.type
    });
  });

  return layoutLinks;
}

function groupLinksByColor(links) {
  const groups = new Map();
  links.forEach((link) => {
    if (!groups.has(link.color)) groups.set(link.color, []);
    groups.get(link.color).push(link);
  });
  return groups;
}

function dominantType(members) {
  const counts = new Map();
  let best = members[0]?.type || 'file';
  let bestN = 0;
  members.forEach((m) => {
    const n = (counts.get(m.type) || 0) + 1;
    counts.set(m.type, n);
    if (n > bestN) {
      bestN = n;
      best = m.type;
    }
  });
  return best;
}

function escapeHtml(value) {
  return String(value).replace(
    /[&<>"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]
  );
}

// Squared distance from point (px,py) to the segment (ax,ay)-(bx,by); used for edge hit-testing.
function distToSegment2(px, py, ax, ay, bx, by) {
  const dx = bx - ax;
  const dy = by - ay;
  const len2 = dx * dx + dy * dy;
  let t = len2 ? ((px - ax) * dx + (py - ay) * dy) / len2 : 0;
  t = t < 0 ? 0 : t > 1 ? 1 : t;
  const cx = ax + t * dx;
  const cy = ay + t * dy;
  const ex = px - cx;
  const ey = py - cy;
  return ex * ex + ey * ey;
}

export function renderGraph(app, retry = 0) {
  const container = document.getElementById('graphContainer');
  if (!container) return;

  // Drop any previous canvas/svg but keep the tooltip element.
  container.querySelectorAll('svg, canvas').forEach((el) => el.remove());
  if (app.graphSim) app.graphSim.stop();
  if (app.graphFlowRAF) {
    cancelAnimationFrame(app.graphFlowRAF); // stop a hover-flow loop from the old canvas
    app.graphFlowRAF = 0;
  }

  // clientWidth/Height can momentarily read 0 (some browsers lay out a just-shown flex view a frame
  // late), so fall back to getBoundingClientRect and, if still unsized, retry next frame (bounded).
  const rect = container.getBoundingClientRect();
  const width = container.clientWidth || Math.round(rect.width);
  const height = container.clientHeight || Math.round(rect.height);
  if (!width || !height) {
    if (retry < 20) requestAnimationFrame(() => renderGraph(app, retry + 1));
    return;
  }

  const activeNodeTypes = new Set(
    app.graphFilters.filter((f) => !f.isRel && f.active).map((f) => f.key)
  );
  const activeRelTypes = new Set(
    app.graphFilters.filter((f) => f.isRel && f.active).map((f) => f.key)
  );

  // Lifecycle-scope filtering: an edge is kept only if its scope bucket
  // (LifecycleScopedRelationship.scope, or 'unscoped') is active. Scope filtering
  // only applies when the data carries scopes at all; `scopeNarrowed` (some
  // present scope switched off) additionally prunes nodes left with no edge, so
  // narrowing to e.g. Runtime isolates that subgraph instead of leaving a cloud
  // of disconnected build-only nodes.
  const presentScopes = new Set(app.presentScopes || []);
  const scopeFiltersActive = presentScopes.size > 0;
  const activeScopes = new Set((app.scopeFilters || []).filter((f) => f.active).map((f) => f.key));
  const scopeNarrowed = scopeFiltersActive && [...presentScopes].some((s) => !activeScopes.has(s));
  const scopeOf = (rel) => rel.scope || 'unscoped';
  const scopeAllows = (scope) => !scopeFiltersActive || activeScopes.has(scope);

  // 1. Underlying nodes (one per SPDX element that passes the type filters).
  const uNodeIds = new Set();
  const uNodes = [];
  const uNodeById = new Map();

  const addNode = (spdxId, rel = null, role = 'target') => {
    if (!spdxId) return null;
    if (uNodeIds.has(spdxId)) return uNodeById.get(spdxId);

    // A virtual (online-scan) vulnerability isn't in elementMap (kept out so the
    // SBOM element count stays true), so fall back to the scan's own map.
    let el = app.elementMap.get(spdxId) || app.virtualVulnMap?.get(spdxId);
    if (!el) {
      el = placeholderFor(spdxId, rel || {}, role);
      // For an unresolved reference declared as an ExternalMap import, attach where it's
      // defined so the node can point at the external location instead of being a bare unknown.
      const ext = app.externalMap?.get(spdxId);
      if (ext) {
        el.external = true;
        el.locationHint = ext.locationHint;
        el.definingArtifact = ext.definingArtifact;
        el.importedBy = ext.importedBy;
        if (ext.verifiedUsing?.length) el.verifiedUsing = ext.verifiedUsing;
      }
    }
    const type = getNodeType(el);
    if (!activeNodeTypes.has(type)) return null;

    const node = { id: spdxId, name: el.name || cleanName(spdxId), type, data: el };
    uNodeIds.add(spdxId);
    uNodeById.set(spdxId, node);
    uNodes.push(node);
    return node;
  };

  app.packages.forEach((p) => addNode(p.spdxId));
  app.files.forEach((f) => addNode(f.spdxId));
  (app.hardware || []).forEach((h) => addNode(h.spdxId));
  (app.supplyChain || []).forEach((s) => addNode(s.spdxId));
  (app.requirements || []).forEach((r) => addNode(r.spdxId));
  app.tools.forEach((t) => addNode(t.spdxId));
  app.buildConfigs.forEach((c) => addNode(c.spdxId));
  (app.builds || []).forEach((b) => addNode(b.spdxId));
  if (!app.builds?.length && app.buildInfo) addNode(app.buildInfo.spdxId);

  // Snapshot the "real" element nodes before agents/placeholders are added, so
  // the createdBy synthesis below links from these to their creating agents.
  const createdByHosts = [...uNodes];
  // Agents (Person / Organization / SoftwareAgent) become nodes in their own
  // right, so an agent shows even when the createdBy edge type is toggled off.
  (app.agents || []).forEach((a) => addNode(a.spdxId));

  // A snippet is never its own graph node, so an edge that lands on one is redirected to the
  // file it came from (via snippetFileRef, the same resolver the source/detail views use) and
  // tagged with the snippet name. This surfaces requirement→snippet traceability (e.g. a
  // Requirement's `implementedBy → snippet` reads as an edge to the file) while letting the
  // tooltip hint it's routed "via snippet …" rather than a direct file relationship. Non-snippets,
  // and snippets with no resolvable source file, pass through unchanged (the latter then drop as
  // before instead of pointing at a phantom node).
  //
  // Only snippet endpoints ever redirect, but this runs for both ends of every relationship
  // (millions of times on a big SBOM). Most SBOMs have no snippets at all, so gate the lookup on
  // a set of the actual snippet ids: a non-snippet endpoint then skips the elementMap.get +
  // snippetFileRef entirely and passes straight through, unchanged.
  const snippetIds = app.snippets?.length ? new Set(app.snippets.map((s) => s.spdxId)) : null;
  const redirectSnippet = (spdxId) => {
    if (!snippetIds || !snippetIds.has(spdxId)) return { id: spdxId, snippet: null };
    const ref = snippetFileRef(app.elementMap.get(spdxId), app.elementMap);
    if (!ref || !ref.fileId) return { id: spdxId, snippet: null };
    return { id: ref.fileId, snippet: ref.name || cleanName(spdxId) };
  };

  // 2. Underlying links.
  const uLinks = [];
  const addRelLinks = (rel) => {
    if (rel.relationshipType === 'hasConcludedLicense') return;
    if (!activeRelTypes.has(rel.relationshipType)) return;
    const scope = scopeOf(rel);
    if (!scopeAllows(scope)) return;

    const src = redirectSnippet(rel.from);
    const sourceNode = addNode(src.id, rel, 'source');
    asTargets(rel.to).forEach((target) => {
      const tgt = redirectSnippet(target);
      const targetNode = addNode(tgt.id, rel, 'target');
      if (!sourceNode || !targetNode) return;
      uLinks.push({
        sourceId: src.id,
        targetId: tgt.id,
        type: rel.relationshipType,
        scope,
        viaSnippet: tgt.snippet || src.snippet || null
      });
    });
  };
  app.relationships.forEach(addRelLinks);
  // VEX assessment relationships live outside the generic relationships array and only become
  // nodes/edges when the Vulnerabilities node type and a VEX edge type are enabled (both off by default).
  (app.vexRelationships || []).forEach(addRelLinks);
  // Virtual VEX edges: online-scan findings connected to the component(s) they
  // hit. They ride the same `affects`/vulnerability toggles as real VEX edges.
  (app.virtualVexRelationships || []).forEach(addRelLinks);
  // Inferred vuln -> file edges: a CVE record's affected files matched to Files in
  // this SBOM. Their own `affectsFile` toggle (and the vulnerability node type)
  // gate them, kept separate from real VEX edges.
  (app.affectedFileRelationships || []).forEach(addRelLinks);

  // Agent provenance edges: beyond the generic Relationship array, an element
  // can name agent(s) directly — CreationInfo.createdBy, an Artifact's
  // suppliedBy / originatedBy, or a Hardware element's productAgent. Synthesize
  // element → agent links for each so provenance shows on the graph like any
  // other relationship, toggled independently via the graph filters.
  const asArray = (v) => (Array.isArray(v) ? v : v == null || v === '' ? [] : [v]);
  const resolveCreationInfo = (el) => {
    const ci = el?.creationInfo;
    if (typeof ci === 'string') return app.elementMap.get(ci) || null;
    return ci || null;
  };
  const agentEdgeSources = {
    createdBy: (data) => resolveCreationInfo(data)?.createdBy,
    suppliedBy: (data) => data.suppliedBy ?? data.software_suppliedBy,
    originatedBy: (data) => data.originatedBy ?? data.software_originatedBy,
    manufacturedBy: (data) => data.hardware_productAgent
  };
  Object.entries(agentEdgeSources).forEach(([type, getAgents]) => {
    if (!activeRelTypes.has(type)) return;
    // Provenance edges carry no lifecycle scope, so they follow the 'unscoped' toggle.
    if (!scopeAllows('unscoped')) return;
    createdByHosts.forEach((host) => {
      asArray(getAgents(host.data)).forEach((agentId) => {
        if (!agentId) return;
        const agentNode = addNode(agentId, { relationshipType: type }, 'target');
        if (!agentNode) return;
        uLinks.push({ sourceId: host.id, targetId: agentId, type, scope: 'unscoped' });
      });
    });
  });

  // 2b. When a lifecycle scope has been switched off, drop nodes left with no
  // surviving edge so the remaining scope (e.g. Runtime) reads as an isolated
  // subgraph rather than its edges floating amid every build-only node. Only
  // runs while narrowed; the default all-scopes-on view keeps every node.
  if (scopeNarrowed) {
    const linked = new Set();
    uLinks.forEach((l) => {
      linked.add(l.sourceId);
      linked.add(l.targetId);
    });
    for (let i = uNodes.length - 1; i >= 0; i--) {
      const id = uNodes[i].id;
      if (!linked.has(id)) {
        uNodes.splice(i, 1);
        uNodeIds.delete(id);
        uNodeById.delete(id);
      }
    }
  }

  // 3. Hierarchical clustering: group files into their parent package (else directory) and
  //    build steps into their root build; everything else is its own node.
  let aggregate = app.graphAggregate;
  app.graphTruncated = false;
  if (!aggregate && (uNodes.length > MAX_FLAT_NODES || uLinks.length > MAX_FLAT_EDGES)) {
    aggregate = true;
    app.graphTruncated = true;
  }
  const expanded = app.expandedClusters instanceof Set ? app.expandedClusters : new Set();

  const clusterKeyFor = (node) => {
    if (!aggregate) return 'self:' + node.id;
    if (node.type === 'package') {
      // A package that contains or generates other elements stays its own
      // cluster anchor so it remains visible. A leaf package folds into the
      // package that contains or generates it, so the large package sets that
      // make distro SBOMs unreadable (a container image's RPMs, a source
      // package's many binaries) collapse into one expandable bubble.
      const contained = app.containsIndex.get(node.id);
      const generated = app.buildOutputIndex.get(node.id);
      if ((contained && contained.length) || (generated && generated.length)) {
        return 'pkg:' + node.id;
      }
      const parent = app.parentIndex.get(node.id) || app.producedByBuildIndex.get(node.id)?.[0];
      const parentNode = parent && uNodeById.get(parent);
      if (parentNode && parentNode.type === 'package') return 'pkg:' + parent;
      return 'pkg:' + node.id;
    }
    if (node.type === 'file') {
      // Only cluster a file into a parent that is an actual package; a pseudo-root file parent
      // would collapse the whole tree, so fall through to directory grouping.
      const parent = app.parentIndex.get(node.id);
      const parentNode = parent && uNodeById.get(parent);
      if (parentNode && parentNode.type === 'package') return 'pkg:' + parent;
      const dir = dirPrefix(node.name);
      if (dir) return 'dir:' + dir;
      return 'self:' + node.id;
    }
    if (node.type === 'build') {
      const parents = app.parentBuildIndex.get(node.id);
      if (parents && parents.length) return 'build:' + parents[0];
      return 'build:' + node.id; // a root build keys on itself
    }
    return 'self:' + node.id;
  };

  const clusters = new Map(); // key -> { key, kind, anchorId, members, primary }
  uNodes.forEach((node) => {
    const key = clusterKeyFor(node);
    const sep = key.indexOf(':');
    const kind = key.slice(0, sep);
    const anchorId = key.slice(sep + 1);
    let c = clusters.get(key);
    if (!c) {
      c = { key, kind, anchorId, members: [], primary: null };
      clusters.set(key, c);
    }
    c.members.push(node);
    if (node.id === anchorId) c.primary = node;
  });

  const clusterLabel = (c) => {
    if (c.kind === 'dir') return c.anchorId + '/';
    if (c.primary) return c.primary.name;
    return cleanName(c.anchorId);
  };

  // 4. Render nodes + map every underlying id to its render id.
  const renderById = new Map();
  const renderNodes = [];
  const renderKeyOf = new Map(); // underlying id -> render node id

  let expandedClusterCount = 0; // drilled-into clusters actually present this render
  clusters.forEach((c) => {
    const expandable = aggregate && c.members.length > 1 && c.kind !== 'self';
    const collapsed = expandable && !expanded.has(c.key);
    if (expandable && !collapsed) expandedClusterCount += 1;

    if (collapsed) {
      const node = {
        id: c.key,
        isCluster: true,
        clusterKey: c.key,
        clusterKind: c.kind,
        memberCount: c.members.length,
        name: clusterLabel(c),
        type: c.primary ? c.primary.type : dominantType(c.members),
        data: c.primary
          ? c.primary.data
          : { type: 'cluster', name: clusterLabel(c), placeholder: true }
      };
      renderById.set(node.id, node);
      renderNodes.push(node);
      c.members.forEach((m) => renderKeyOf.set(m.id, c.key));
    } else {
      c.members.forEach((m) => {
        renderById.set(m.id, m);
        renderNodes.push(m);
        renderKeyOf.set(m.id, m.id);
      });
    }
  });
  // Mirror into reactive state so the "collapse all" control shows only while
  // at least one cluster is drilled in (Set mutations aren't Alpine-tracked).
  app.graphExpandedCount = expandedClusterCount;

  // 5. Remap links onto render nodes, drop self-loops, dedupe, weight.
  const linkMap = new Map();
  uLinks.forEach((l) => {
    const s = renderKeyOf.get(l.sourceId);
    const t = renderKeyOf.get(l.targetId);
    if (!s || !t || s === t) return;
    const key = s + ' ' + t + ' ' + l.type;
    let link = linkMap.get(key);
    if (!link) {
      link = {
        sourceId: s,
        targetId: t,
        type: l.type,
        color: getRelationshipColor(l.type),
        weight: 0
      };
      linkMap.set(key, link);
    }
    link.weight++;
    // Collapse multiple snippets of the same file (targeted by the same source) into one
    // edge, keeping the distinct snippet names for the "via snippet …" hover hint.
    if (l.viaSnippet) (link.viaSnippets ||= new Set()).add(l.viaSnippet);
  });
  const links = [...linkMap.values()];
  links.forEach((l) => {
    l.sourceNode = renderById.get(l.sourceId);
    l.targetNode = renderById.get(l.targetId);
  });

  const connCount = new Map();
  const connectedIndex = new Map();
  const linksByNode = new Map();
  const connect = (sourceId, targetId, link) => {
    connCount.set(sourceId, (connCount.get(sourceId) || 0) + 1);
    connCount.set(targetId, (connCount.get(targetId) || 0) + 1);
    if (!connectedIndex.has(sourceId)) connectedIndex.set(sourceId, new Set([sourceId]));
    if (!connectedIndex.has(targetId)) connectedIndex.set(targetId, new Set([targetId]));
    connectedIndex.get(sourceId).add(targetId);
    connectedIndex.get(targetId).add(sourceId);
    if (!linksByNode.has(sourceId)) linksByNode.set(sourceId, []);
    if (!linksByNode.has(targetId)) linksByNode.set(targetId, []);
    linksByNode.get(sourceId).push(link);
    linksByNode.get(targetId).push(link);
  };
  links.forEach((link) => connect(link.sourceId, link.targetId, link));

  // Optionally drop nodes left with no surviving edge (after aggregation and every
  // other active filter), so a sparse graph isn't cluttered with isolated dots.
  if (app.graphHideOrphans) {
    for (let i = renderNodes.length - 1; i >= 0; i--) {
      const id = renderNodes[i].id;
      if (!connCount.get(id)) {
        renderById.delete(id);
        renderNodes.splice(i, 1);
      }
    }
  }

  // Live readout for the controls bar.
  app.graphNodeCount = renderNodes.length;
  app.graphEdgeCount = links.length;

  // Layout: how the force simulation positions nodes. The default 'organic' is
  // pure physics; the others precompute a per-node target (a hierarchy layer, a
  // radial ring, an artifact-distance ring, a type lane) and pin nodes toward it
  // so the same canvas/draw path renders as a hierarchy, radial, spotlight or
  // lane view. Each returns { configure(sim), seed()|null, radiusBoost|null }:
  // configure wires the forces, seed sets deterministic starting coordinates
  // (fewer edge crossings, faster settle), and radiusBoost enlarges chosen nodes
  // (spotlight grows the final artifacts). Built here so it can size nodes below.
  const buildLayout = () => {
    const layoutKey = app.graphLayout || DEFAULT_GRAPH_LAYOUT;
    const big = renderNodes.length > 4000;
    const huge = renderNodes.length > 12000;
    const cx = width / 2;
    const cy = height / 2;
    const nodeIds = renderNodes.map((d) => d.id);
    // Golden angle: a deterministic seed spread that needs no Math.random, so a
    // rebuild reproduces the same starting arrangement.
    const GOLDEN = 2.399963229728653;

    // High-fan-out "connector" nodes (a tool used by every file, an agent that
    // created everything, a build with hundreds of outputs) bias every layout:
    // their many links drag neighbours into a ball and shift the centre of mass,
    // and in the radial/spotlight layouts they act as shortcuts that collapse
    // graph distance. `hubDamp` weakens the pull of a link touching such a node
    // in inverse proportion to its degree (d3's own default link heuristic,
    // applied only past the hub threshold so ordinary edges keep their tuned
    // strength); the radial/spotlight BFS additionally refuses to route through
    // them (see `hubs` passed as `block`). hasInput is already capped upstream in
    // createLayoutLinks, so this mainly tames contains / hasOutput / ancestorOf.
    const HUB_DEGREE = 40;
    const hubs = new Set();
    nodeIds.forEach((id) => {
      if ((connCount.get(id) || 0) > HUB_DEGREE) hubs.add(id);
    });
    const hubDamp = (l) => {
      const maxDeg = Math.max(connCount.get(l.source.id) || 0, connCount.get(l.target.id) || 0);
      return maxDeg > HUB_DEGREE ? HUB_DEGREE / maxDeg : 1;
    };

    const makeCharge = (strength) => {
      const c = d3.forceManyBody().strength(strength);
      // On big graphs the charge force dominates each tick, so raise Barnes-Hut's
      // theta and cap the interaction distance (mirrors the old organic tuning).
      if (big) c.theta(huge ? 1.6 : 1.4).distanceMax(huge ? 500 : 900);
      return c;
    };
    const linkForce = (distance, strength) =>
      d3
        .forceLink(createLayoutLinks(links))
        .id((d) => d.id)
        .distance(distance)
        .strength((l) => strength * hubDamp(l));
    const applyDecay = (sim) => {
      // Big graphs reach a readable spread quickly, so decay faster and stop
      // sooner rather than grinding through d3's default ~300 micro-adjust ticks.
      if (big) sim.alphaDecay(0.06).alphaMin(0.006);
      return sim;
    };
    // Structural flow direction of an edge, [from, to]: hasInput points at its
    // source (input feeds the build), so it flows target -> source; every other
    // edge flows source -> target.
    const flowOf = (l) =>
      l.type === 'hasInput' ? [l.targetId, l.sourceId] : [l.sourceId, l.targetId];
    const undirectedAdjacency = () => {
      const adj = new Map(nodeIds.map((id) => [id, new Set()]));
      links.forEach((l) => {
        adj.get(l.sourceId)?.add(l.targetId);
        adj.get(l.targetId)?.add(l.sourceId);
      });
      return adj;
    };
    const mostConnected = () => {
      let best = nodeIds[0];
      let bestN = -1;
      nodeIds.forEach((id) => {
        const n = connCount.get(id) || 0;
        if (n > bestN) {
          bestN = n;
          best = id;
        }
      });
      return best;
    };

    if (layoutKey === 'hierarchy') {
      const layer = computeLayers(nodeIds, links.map(flowOf));
      const gap = 120;
      const topPad = 70;
      const layerY = (d) => topPad + (layer.get(d.id) || 0) * gap;
      const perLayer = new Map();
      renderNodes.forEach((d) => {
        const L = layer.get(d.id) || 0;
        if (!perLayer.has(L)) perLayer.set(L, []);
        perLayer.get(L).push(d);
      });
      const seed = () => {
        perLayer.forEach((list) => {
          const n = list.length;
          const spanW = Math.max(width, n * 26);
          list.forEach((d, i) => {
            d.x = cx - spanW / 2 + (spanW * (i + 0.5)) / n;
            d.y = layerY(d);
          });
        });
      };
      const configure = (sim) =>
        applyDecay(
          sim
            // Weak links so the layer bands hold instead of collapsing vertically.
            .force('link', linkForce(50, 0.06))
            .force('charge', makeCharge(-220))
            .force(
              'collision',
              d3.forceCollide().radius((d) => d._r + 6)
            )
            .force('x', d3.forceX(cx).strength(0.03))
            .force('y', d3.forceY(layerY).strength(0.9))
        );
      return { configure, seed, radiusBoost: null };
    }

    if (layoutKey === 'radial') {
      const adjacency = undirectedAdjacency();
      // Roots: rendered nodes standing in for a declared SBOM/document rootElement.
      const roots = new Set();
      (app.rootElementIds instanceof Set ? app.rootElementIds : []).forEach((id) => {
        const rid = renderKeyOf.get(id);
        if (rid && renderById.has(rid)) roots.add(rid);
      });
      // Fallbacks so the rings still centre on something sensible: flow sources
      // (nothing points into them), else the single most-connected node.
      if (!roots.size) {
        const indeg = new Map(nodeIds.map((id) => [id, 0]));
        links.forEach((l) => {
          const to = flowOf(l)[1];
          indeg.set(to, (indeg.get(to) || 0) + 1);
        });
        nodeIds.forEach((id) => {
          if ((indeg.get(id) || 0) === 0 && adjacency.get(id)?.size) roots.add(id);
        });
      }
      if (!roots.size && nodeIds.length) roots.add(mostConnected());
      // Don't let a hub bridge the rings (unless it is itself a chosen root).
      const block = new Set([...hubs].filter((h) => !roots.has(h)));
      const depth = bfsDepths(nodeIds, adjacency, roots, { block });
      let maxDepth = 0;
      depth.forEach((v) => (maxDepth = Math.max(maxDepth, v)));
      const ring = Math.max(
        55,
        Math.min(120, (Math.min(width, height) * 0.42) / Math.max(maxDepth, 1))
      );
      const radiusOf = (d) => (depth.get(d.id) || 0) * ring;
      const seed = () => {
        renderNodes.forEach((d, i) => {
          const a = i * GOLDEN;
          const r = radiusOf(d);
          d.x = cx + Math.cos(a) * r;
          d.y = cy + Math.sin(a) * r;
        });
      };
      const configure = (sim) =>
        applyDecay(
          sim
            .force('link', linkForce(45, 0.05))
            .force('charge', makeCharge(-140))
            .force(
              'collision',
              d3.forceCollide().radius((d) => d._r + 4)
            )
            .force('radial', d3.forceRadial(radiusOf, cx, cy).strength(0.85))
        );
      return { configure, seed, radiusBoost: null };
    }

    if (layoutKey === 'spotlight') {
      // Key artifacts: declared roots, terminal build outputs (produced by a
      // build but not consumed by another), and distributed artifacts. These are
      // the "final" things a build ships; everything else orbits by graph distance.
      const keys = new Set();
      const addKey = (uid) => {
        const rid = renderKeyOf.get(uid);
        if (rid && renderById.has(rid)) keys.add(rid);
      };
      (app.rootElementIds instanceof Set ? app.rootElementIds : []).forEach(addKey);
      const produced =
        app.producedByBuildIndex instanceof Map ? app.producedByBuildIndex : new Map();
      const consumed =
        app.consumedByBuildIndex instanceof Map ? app.consumedByBuildIndex : new Map();
      produced.forEach((_v, uid) => {
        if (!consumed.has(uid)) addKey(uid);
      });
      (app.distributedByIndex instanceof Map ? app.distributedByIndex : new Map()).forEach(
        (_v, uid) => addKey(uid)
      );
      const adjacency = undirectedAdjacency();
      // Fallback: no build/root signal, so treat flow sinks (nothing flows out of
      // them) as the products; else the single most-connected node.
      if (!keys.size) {
        const outdeg = new Map(nodeIds.map((id) => [id, 0]));
        links.forEach((l) => {
          const from = flowOf(l)[0];
          outdeg.set(from, (outdeg.get(from) || 0) + 1);
        });
        nodeIds.forEach((id) => {
          if ((outdeg.get(id) || 0) === 0 && adjacency.get(id)?.size) keys.add(id);
        });
      }
      if (!keys.size && nodeIds.length) keys.add(mostConnected());
      // Orbit rings by true distance from the artifacts: don't let a shared hub
      // collapse everything it touches to the same ring (unless it is a key node).
      const block = new Set([...hubs].filter((h) => !keys.has(h)));
      const dist = bfsDepths(nodeIds, adjacency, keys, { block });
      const base = 110;
      const ring = 78;
      const radiusOf = (d) => (keys.has(d.id) ? 0 : base + (dist.get(d.id) || 0) * ring);
      const radiusBoost = new Map();
      keys.forEach((id) => radiusBoost.set(id, 1.9));
      const seed = () => {
        let ki = 0;
        renderNodes.forEach((d, i) => {
          if (keys.has(d.id)) {
            const a = ki++ * GOLDEN;
            d.x = cx + Math.cos(a) * 24;
            d.y = cy + Math.sin(a) * 24;
          } else {
            const a = i * GOLDEN;
            const r = radiusOf(d);
            d.x = cx + Math.cos(a) * r;
            d.y = cy + Math.sin(a) * r;
          }
        });
      };
      const configure = (sim) =>
        applyDecay(
          sim
            .force('link', linkForce(55, 0.05))
            .force('charge', makeCharge(-170))
            .force(
              'collision',
              d3.forceCollide().radius((d) => d._r + 5)
            )
            .force(
              'radial',
              d3.forceRadial(radiusOf, cx, cy).strength((d) => (keys.has(d.id) ? 0.9 : 0.72))
            )
        );
      return { configure, seed, radiusBoost };
    }

    if (layoutKey === 'lanes') {
      const types = orderLaneTypes(renderNodes.map((d) => d.type));
      const laneIndex = new Map(types.map((t, i) => [t, i]));
      const n = Math.max(types.length, 1);
      const laneX = (d) => (width * (laneIndex.get(d.type) + 1)) / (n + 1);
      const perLane = new Map();
      renderNodes.forEach((d) => {
        if (!perLane.has(d.type)) perLane.set(d.type, []);
        perLane.get(d.type).push(d);
      });
      const seed = () => {
        perLane.forEach((list) => {
          const m = list.length;
          const spanH = Math.max(height, m * 22);
          list.forEach((d, i) => {
            d.x = laneX(d);
            d.y = cy - spanH / 2 + (spanH * (i + 0.5)) / m;
          });
        });
      };
      const configure = (sim) =>
        applyDecay(
          sim
            // Very weak links: they cross lanes, so they must not drag a node off
            // its column. Charge + collision spread each lane out vertically.
            .force('link', linkForce(40, 0.02))
            .force('charge', makeCharge(-120))
            .force(
              'collision',
              d3.forceCollide().radius((d) => d._r + 4)
            )
            .force('x', d3.forceX(laneX).strength(0.92))
            .force('y', d3.forceY(cy).strength(0.045))
        );
      return { configure, seed, radiusBoost: null };
    }

    // organic (default): the original pure-physics force set.
    const configure = (sim) =>
      applyDecay(
        sim
          .force(
            'link',
            d3
              .forceLink(createLayoutLinks(links))
              .id((d) => d.id)
              .distance((d) => (d.type === 'hasInput' ? 85 : 60))
              .strength((l) => (l.type === 'hasInput' ? 0.05 : 0.18) * hubDamp(l))
          )
          .force('charge', makeCharge(-150))
          .force('center', d3.forceCenter(cx, cy))
          .force(
            'collision',
            d3.forceCollide().radius((d) => d._r + 4)
          )
          .force('x', d3.forceX(cx).strength(0.045))
          .force('y', d3.forceY(cy).strength(0.045))
      );
    return { configure, seed: null, radiusBoost: null };
  };
  const layout = buildLayout();

  // 6. Canvas (edges + nodes + labels on one surface).
  const canvas = document.createElement('canvas');
  canvas.className = 'graph-canvas';
  container.appendChild(canvas);

  const dpr = globalThis.devicePixelRatio || 1;
  canvas.width = width * dpr;
  canvas.height = height * dpr;
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;
  const ctx = canvas.getContext('2d');

  const computeRadius = (d) =>
    d.isCluster
      ? Math.max(9, Math.min(30, 7 + Math.sqrt(d.memberCount) * 1.6))
      : Math.max(5, Math.min(16, 4 + Math.sqrt(connCount.get(d.id) || 0) * 1.2));

  // Precompute each node's static draw properties once (radius from connection/member counts,
  // fill/stroke from node type) to avoid per-tick sqrt() and per-frame colour parses on large graphs.
  const typeFill = new Map();
  const typeStroke = new Map();
  const fillForType = (type) => {
    let f = typeFill.get(type);
    if (f === undefined) {
      f = getNodeTypeColor(type);
      typeFill.set(type, f);
    }
    return f;
  };
  const strokeForType = (type) => {
    let s = typeStroke.get(type);
    if (s === undefined) {
      s = d3.color(getNodeTypeColor(type)).brighter(0.5).toString();
      typeStroke.set(type, s);
    }
    return s;
  };
  renderNodes.forEach((d) => {
    // A layout may enlarge chosen nodes (spotlight grows the final artifacts).
    const boost = layout.radiusBoost?.get(d.id) || 1;
    d._r = computeRadius(d) * boost;
    d._fill = fillForType(d.type);
    d._stroke = d.isCluster ? 'rgba(255,255,255,0.85)' : strokeForType(d.type);
    // Resolved once here (not per frame); clusters stand for many elements so they
    // keep the plain disc rather than any single member's glyph.
    d._iconKey = d.isCluster ? null : iconKeyForElement(d.data, d.type);
  });
  const radiusFor = (d) => d._r;

  // Nodes standing in for an unresolved ExternalMap import get a dashed grey ring; a small dedicated
  // draw pass is cheaper than special-casing the batched node loop.
  const externalRenderNodes = renderNodes.filter((d) => !d.isCluster && d.data?.external);
  const EXTERNAL_RING_COLOR = getNodeTypeColor('external');
  // Virtual (online-scan) vulnerabilities get their own dashed ring so it's clear
  // at a glance they were found by a scan, not carried by the SBOM.
  const virtualRenderNodes = renderNodes.filter((d) => !d.isCluster && d.data?.virtual);
  const VIRTUAL_RING_COLOR = getNodeTypeColor('vulnerability');
  // Draw bigger nodes' labels first so the MAX_LABELS cap keeps the useful ones.
  const labelOrder = [...renderNodes].sort((a, b) => b._r - a._r);

  const groupedLinks = groupLinksByColor(links);
  let currentTransform = d3.zoomIdentity;
  let hoverNodeId = null;
  let selectedNodeId = app.graphSelectedNodeId;
  if (selectedNodeId && !renderById.has(selectedNodeId)) {
    selectedNodeId = null;
    app.graphSelectedNodeId = null;
  }
  let highlightedNodeId = hoverNodeId ?? selectedNodeId;
  let drawFrame = 0;
  let flowPhase = 0; // animated dash offset (screen px) for the hover flow
  let view = { x0: 0, y0: 0, x1: width, y1: height };

  const nodeInView = (d) =>
    d.x >= view.x0 - CULL_PAD &&
    d.x <= view.x1 + CULL_PAD &&
    d.y >= view.y0 - CULL_PAD &&
    d.y <= view.y1 + CULL_PAD;

  // headAlpha keeps arrowheads opaque while the shaft is dimmed; defaults to the shaft alpha.
  const drawLinkGroups = (groups, alpha, lineWidth, headAlpha = alpha) => {
    const k = currentTransform.k;
    // Arrowheads a constant on-screen size, growing only slightly on thicker edges.
    const headLen = (ARROW_LEN + lineWidth * k) / k;
    const headHalf = (ARROW_HALF_WIDTH + lineWidth * k * 0.6) / k;

    groups.forEach((group, color) => {
      ctx.strokeStyle = color;
      ctx.globalAlpha = alpha;
      ctx.lineWidth = lineWidth;

      // Solid shafts batched into one path per colour; dashed edges (bucketed by pattern) and
      // filled arrowheads are collected and drawn separately since one path can't mix dashes.
      let dashedBuckets = null; // Map<patternKey, { pattern, pts:[a,b,…] }>
      let arrows = null;
      ctx.setLineDash([]);
      ctx.beginPath();
      group.forEach((link) => {
        const a = link.sourceNode;
        const b = link.targetNode;
        if (!a || !b || a.x == null || b.x == null) return;
        if (!nodeInView(a) && !nodeInView(b)) return; // viewport culling

        const dash = dashPatternFor(link.type, lineWidth, k);
        if (dash) {
          const key = dash.join(',');
          dashedBuckets ||= new Map();
          let bucket = dashedBuckets.get(key);
          if (!bucket) {
            bucket = { pattern: dash, pts: [] };
            dashedBuckets.set(key, bucket);
          }
          bucket.pts.push(a, b);
          return;
        }
        if (!ARROW_REL_TYPES.has(link.type)) {
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          return;
        }
        // Head sits on the source for hasInput and the target for hasOutput; shaft stops at its base.
        const head = link.type === 'hasInput' ? a : b;
        const tail = link.type === 'hasInput' ? b : a;
        const dx = head.x - tail.x;
        const dy = head.y - tail.y;
        const dist = Math.hypot(dx, dy);
        const gap = radiusFor(head); // land the tip on the head node's rim
        if (dist <= gap + headLen) {
          // Too short for a head; just draw the bare shaft.
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          return;
        }
        const ux = dx / dist;
        const uy = dy / dist;
        const tipX = head.x - ux * gap;
        const tipY = head.y - uy * gap;
        const baseX = tipX - ux * headLen;
        const baseY = tipY - uy * headLen;
        ctx.moveTo(tail.x, tail.y);
        ctx.lineTo(baseX, baseY);
        (arrows ||= []).push({ tipX, tipY, baseX, baseY, nx: -uy, ny: ux });
      });
      ctx.stroke();

      if (arrows) {
        ctx.globalAlpha = headAlpha;
        ctx.beginPath();
        ctx.fillStyle = color;
        arrows.forEach((ar) => {
          ctx.moveTo(ar.tipX, ar.tipY);
          ctx.lineTo(ar.baseX + ar.nx * headHalf, ar.baseY + ar.ny * headHalf);
          ctx.lineTo(ar.baseX - ar.nx * headHalf, ar.baseY - ar.ny * headHalf);
          ctx.closePath();
        });
        ctx.fill();
      }

      if (dashedBuckets) {
        ctx.globalAlpha = alpha;
        dashedBuckets.forEach(({ pattern, pts }) => {
          ctx.setLineDash(pattern);
          ctx.beginPath();
          for (let i = 0; i < pts.length; i += 2) {
            ctx.moveTo(pts[i].x, pts[i].y);
            ctx.lineTo(pts[i + 1].x, pts[i + 1].y);
          }
          ctx.stroke();
        });
        ctx.setLineDash([]);
      }
    });
  };

  // A node's fill/stroke/cluster flag are fixed for the life of a render, so the
  // fill/stroke buckets never change membership. Group them once here instead of
  // rebuilding the grouping on every frame of the fast path (which redraws
  // constantly through the settle animation and every pan/zoom); the draw loop
  // below just culls by viewport within each precomputed bucket.
  const nodeBuckets = (() => {
    const m = new Map();
    renderNodes.forEach((d) => {
      const key = d._fill + '|' + d._stroke + '|' + (d.isCluster ? 1 : 0);
      let b = m.get(key);
      if (!b) {
        b = { fill: d._fill, stroke: d._stroke, isCluster: d.isCluster, list: [] };
        m.set(key, b);
      }
      b.list.push(d);
    });
    return [...m.values()];
  })();

  // Fast path for the common "no search, nothing highlighted" view: every node is fully opaque, so
  // emit one fill()+stroke() per precomputed bucket instead of per node.
  const drawNodesFast = () => {
    const k = currentTransform.k;
    ctx.globalAlpha = 1;
    nodeBuckets.forEach((b) => {
      ctx.beginPath();
      let any = false;
      b.list.forEach((d) => {
        if (d.x == null || !nodeInView(d)) return;
        any = true;
        ctx.moveTo(d.x + d._r, d.y); // moveTo before arc so circles don't chain
        ctx.arc(d.x, d.y, d._r, 0, 2 * Math.PI);
      });
      if (!any) return;
      ctx.fillStyle = b.fill;
      ctx.fill();
      ctx.lineWidth = (b.isCluster ? 2.5 : 1.5) / k;
      ctx.strokeStyle = b.stroke;
      ctx.stroke();
    });
  };

  // Dashed grey outline around unresolved external references, drawn after node fills so it sits on
  // top; nodes faded out by search/hover are skipped so the ring tracks the same emphasis.
  const drawExternalRings = () => {
    if (!externalRenderNodes.length) return;
    const k = currentTransform.k;
    ctx.save();
    ctx.setLineDash([3 / k, 3 / k]);
    ctx.lineWidth = 1.5 / k;
    ctx.strokeStyle = EXTERNAL_RING_COLOR;
    externalRenderNodes.forEach((d) => {
      if (d.x == null || !nodeInView(d)) return;
      const ss = nodeSearchStyle(d.id);
      if (ss.hidden) return;
      ctx.globalAlpha = ss.alpha;
      const r = radiusFor(d) + 2.5 / k;
      ctx.beginPath();
      ctx.arc(d.x, d.y, r, 0, 2 * Math.PI);
      ctx.stroke();
    });
    ctx.setLineDash([]);
    ctx.globalAlpha = 1;
    ctx.restore();
  };

  // Dashed ring in the vulnerability colour around virtual (online-scan) vuln
  // nodes, mirroring the external-ring pass so it sits on top of the node fills
  // and tracks the same search/hover emphasis.
  const drawVirtualRings = () => {
    if (!virtualRenderNodes.length) return;
    const k = currentTransform.k;
    ctx.save();
    ctx.setLineDash([4 / k, 3 / k]);
    ctx.lineWidth = 1.5 / k;
    ctx.strokeStyle = VIRTUAL_RING_COLOR;
    virtualRenderNodes.forEach((d) => {
      if (d.x == null || !nodeInView(d)) return;
      const ss = nodeSearchStyle(d.id);
      if (ss.hidden) return;
      ctx.globalAlpha = ss.alpha;
      const r = radiusFor(d) + 2.5 / k;
      ctx.beginPath();
      ctx.arc(d.x, d.y, r, 0, 2 * Math.PI);
      ctx.stroke();
    });
    ctx.setLineDash([]);
    ctx.globalAlpha = 1;
    ctx.restore();
  };

  // One icon node: a faint type-colour halo (which keeps the colour legend and a
  // clear hit target) with the Material glyph, tinted a shade brighter, on top.
  const drawIconNode = (d, r, k, alpha) => {
    const path = getNodeIconPath2D(d._iconKey);
    if (!path) {
      ctx.globalAlpha = alpha;
      ctx.beginPath();
      ctx.arc(d.x, d.y, r, 0, 2 * Math.PI);
      ctx.fillStyle = d._fill;
      ctx.fill();
      ctx.lineWidth = 1.5 / k;
      ctx.strokeStyle = d._stroke;
      ctx.stroke();
      return;
    }
    ctx.globalAlpha = alpha * ICON_HALO_ALPHA;
    ctx.beginPath();
    ctx.arc(d.x, d.y, r, 0, 2 * Math.PI);
    ctx.fillStyle = d._fill;
    ctx.fill();

    const size = r * 2 * ICON_SPAN;
    const s = size / 24; // Material icons live in a 24x24 box
    ctx.globalAlpha = alpha;
    ctx.fillStyle = d._stroke; // brighter than the fill so the glyph reads on the halo
    ctx.save();
    ctx.translate(d.x - size / 2, d.y - size / 2);
    ctx.scale(s, s);
    ctx.fill(path);
    ctx.restore();
  };

  // Gold halo marking the main-artifact node, drawn full-opacity over whatever
  // dimming is in effect so the focused artifact is always the anchor on screen.
  const drawArtifactRing = (d, r, k) => {
    ctx.globalAlpha = 1;
    ctx.beginPath();
    ctx.arc(d.x, d.y, r + 4.5 / k, 0, 2 * Math.PI);
    ctx.strokeStyle = '#facc15';
    ctx.lineWidth = 2.5 / k;
    ctx.stroke();
  };

  // Icon-mode node pass: unifies the plain/hover/search cases (alpha comes from
  // the search style + hover focus). Clusters, glyph-less nodes, and nodes too
  // small on screen keep the plain dot; everything else draws its Material glyph.
  const drawNodesIcons = () => {
    const k = currentTransform.k;
    const minR = ICON_MIN_PX / k;
    const connected =
      !searchActive && highlightedNodeId
        ? connectedIndex.get(highlightedNodeId) || new Set([highlightedNodeId])
        : null;
    renderNodes.forEach((d) => {
      if (d.x == null || !nodeInView(d)) return;
      const ss = nodeSearchStyle(d.id);
      if (ss.hidden) return;
      const r = radiusFor(d);
      let alpha = ss.alpha;
      if (connected && !connected.has(d.id)) alpha = 0.12;
      if (d.isCluster || !d._iconKey || r < minR) {
        ctx.globalAlpha = alpha;
        ctx.beginPath();
        ctx.arc(d.x, d.y, r, 0, 2 * Math.PI);
        ctx.fillStyle = d._fill;
        ctx.fill();
        ctx.lineWidth = (d.isCluster ? 2.5 : 1.5) / k;
        ctx.strokeStyle = d._stroke;
        ctx.stroke();
      } else {
        drawIconNode(d, r, k, alpha);
      }
      if (searchActive && matchSet.has(d.id)) {
        // Amber ring so search hits pop regardless of node colour.
        ctx.globalAlpha = 1;
        ctx.beginPath();
        ctx.arc(d.x, d.y, r + 3 / k, 0, 2 * Math.PI);
        ctx.strokeStyle = '#fbbf24';
        ctx.lineWidth = 2 / k;
        ctx.stroke();
      }
      if (focusActive && d.id === focusArtifactRenderId) drawArtifactRing(d, r, k);
    });
    ctx.globalAlpha = 1;
    drawExternalRings();
    drawVirtualRings();
  };

  const drawNodes = () => {
    if (app.graphUseIcons) {
      drawNodesIcons();
      return;
    }
    if (!searchActive && !highlightedNodeId && !focusActive) {
      drawNodesFast();
      drawExternalRings();
      drawVirtualRings();
      return;
    }
    // Hover emphasis is suppressed while a search overlay is active so the
    // search visualization stays stable as the pointer moves.
    const connected =
      !searchActive && highlightedNodeId
        ? connectedIndex.get(highlightedNodeId) || new Set([highlightedNodeId])
        : null;
    const k = currentTransform.k;
    renderNodes.forEach((d) => {
      if (d.x == null || !nodeInView(d)) return;
      const ss = nodeSearchStyle(d.id);
      if (ss.hidden) return; // focus mode hides non-match/non-neighbour nodes
      const r = radiusFor(d);
      let alpha = ss.alpha;
      if (connected && !connected.has(d.id)) alpha = 0.12;
      ctx.globalAlpha = alpha;
      ctx.beginPath();
      ctx.arc(d.x, d.y, r, 0, 2 * Math.PI);
      ctx.fillStyle = d._fill;
      ctx.fill();
      ctx.lineWidth = (d.isCluster ? 2.5 : 1.5) / k;
      ctx.strokeStyle = d._stroke;
      ctx.stroke();
      if (searchActive && matchSet.has(d.id)) {
        // Amber ring so search hits pop regardless of node colour.
        ctx.globalAlpha = 1;
        ctx.beginPath();
        ctx.arc(d.x, d.y, r + 3 / k, 0, 2 * Math.PI);
        ctx.strokeStyle = '#fbbf24';
        ctx.lineWidth = 2 / k;
        ctx.stroke();
      }
      if (focusActive && d.id === focusArtifactRenderId) drawArtifactRing(d, r, k);
    });
    ctx.globalAlpha = 1;
    drawExternalRings();
    drawVirtualRings();
  };

  // Screen-space label decluttering: labels are placed greedily in priority order and any that would
  // overlap one already drawn is skipped, keeping dense areas readable without re-laying out the graph.
  const LABEL_CELL = 13; // grid cell size in screen px (≈ label line height)
  let labelCells = null;
  const reserveLabel = (x0, y0, x1, y1) => {
    const cx0 = Math.floor(x0 / LABEL_CELL);
    const cx1 = Math.floor(x1 / LABEL_CELL);
    const cy0 = Math.floor(y0 / LABEL_CELL);
    const cy1 = Math.floor(y1 / LABEL_CELL);
    for (let cy = cy0; cy <= cy1; cy++) {
      for (let cx = cx0; cx <= cx1; cx++) {
        if (labelCells.has(cy * 100000 + cx)) return false; // occupied → collide
      }
    }
    for (let cy = cy0; cy <= cy1; cy++) {
      for (let cx = cx0; cx <= cx1; cx++) labelCells.add(cy * 100000 + cx);
    }
    return true;
  };

  const drawLabel = (d, isMatch) => {
    const sx = currentTransform.applyX(d.x);
    const sy = currentTransform.applyY(d.y);
    if (sx < -60 || sx > width + 60 || sy < -20 || sy > height + 20) return false;
    const r = radiusFor(d) * currentTransform.k;
    const text = d.isCluster ? `${d.name} · ${d.memberCount}` : d.name;
    const tx = sx + r + 4;
    const tw = ctx.measureText(text).width;
    // Reserve the label's box; bail if it would overlap a label already drawn.
    if (!reserveLabel(tx - 1, sy - 6, tx + tw + 1, sy + 6)) return false;
    if (isMatch) {
      // Subtle backdrop so match labels stay legible over the busy edge mesh.
      ctx.globalAlpha = 0.85;
      ctx.fillStyle = 'rgba(15,23,42,0.9)';
      ctx.fillRect(tx - 2, sy - 7, tw + 4, 14);
    }
    ctx.globalAlpha = isMatch ? 1 : nodeSearchStyle(d.id).alpha;
    ctx.fillStyle = isMatch ? '#fbbf24' : d.isCluster ? '#e2e8f0' : '#94a3b8';
    ctx.fillText(text, tx, sy);
    return true;
  };

  const drawLabels = () => {
    const zoomedIn = currentTransform.k >= LABEL_ZOOM_THRESHOLD;
    if (!searchActive && !zoomedIn) return;
    ctx.save();
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); // screen space → constant-size text
    ctx.font = '11px ui-sans-serif, system-ui, -apple-system, sans-serif';
    ctx.textBaseline = 'middle';
    labelCells = new Set(); // reset the occupancy grid each frame
    let drawn = 0;

    // Search hits always get a label, even zoomed out, so they're findable.
    if (searchActive) {
      for (const d of matchLabelList) {
        if (drawn >= MAX_LABELS) break;
        if (d.x == null) continue;
        if (drawLabel(d, true)) drawn++;
      }
    }

    // Remaining (non-match) labels only once zoomed in, respecting hover focus when not searching.
    if (zoomedIn) {
      const connected =
        !searchActive && highlightedNodeId
          ? connectedIndex.get(highlightedNodeId) || new Set([highlightedNodeId])
          : null;
      for (const d of labelOrder) {
        if (drawn >= MAX_LABELS) break;
        if (d.x == null) continue;
        if (searchActive && matchSet.has(d.id)) continue; // already drawn above
        const ss = nodeSearchStyle(d.id);
        if (ss.hidden) continue;
        if (!searchActive && connected && !connected.has(d.id)) continue;
        if (drawLabel(d, false)) drawn++;
      }
    }

    ctx.globalAlpha = 1;
    ctx.restore();
  };

  // The hovered node's directed (hasInput/hasOutput) links, or null; drives the flow animation and its dimmed base shaft.
  const highlightedDirectedLinks = () => {
    if (searchActive || !highlightedNodeId) return null;
    const hl = linksByNode.get(highlightedNodeId);
    if (!hl) return null;
    const directed = hl.filter((l) => ARROW_REL_TYPES.has(l.type));
    return directed.length ? directed : null;
  };

  // Marching dashes along the directed edges, animated by flowPhase; each edge is drawn
  // tail → head so the dashes travel in the relationship's direction.
  const drawFlowOverlay = (directed, lineWidth) => {
    const k = currentTransform.k;
    const headRoom = (ARROW_LEN + 4) / k; // stop short of the head so it stays clean
    ctx.lineCap = 'round';
    ctx.setLineDash([FLOW_DASH / k, FLOW_GAP / k]);
    ctx.lineDashOffset = -flowPhase / k; // decreasing → dashes move toward head
    groupLinksByColor(directed).forEach((group, color) => {
      ctx.strokeStyle = color;
      ctx.globalAlpha = 0.95;
      ctx.lineWidth = lineWidth;
      ctx.beginPath();
      group.forEach((link) => {
        const a = link.sourceNode;
        const b = link.targetNode;
        if (!a || !b || a.x == null || b.x == null) return;
        if (!nodeInView(a) && !nodeInView(b)) return;
        const head = link.type === 'hasInput' ? a : b;
        const tail = link.type === 'hasInput' ? b : a;
        const dx = head.x - tail.x;
        const dy = head.y - tail.y;
        const dist = Math.hypot(dx, dy);
        const stop = radiusFor(head) + headRoom;
        ctx.moveTo(tail.x, tail.y);
        if (dist <= stop) {
          ctx.lineTo(head.x, head.y);
        } else {
          ctx.lineTo(head.x - (dx / dist) * stop, head.y - (dy / dist) * stop);
        }
      });
      ctx.stroke();
    });
    ctx.setLineDash([]);
    ctx.lineDashOffset = 0;
  };

  // 6c. Heatmap overlay: fold the app's per-element heat index onto render nodes
  //     (a collapsed cluster inherits its hottest member) and bloom a glow over
  //     the hot regions. Purely additive layers around the normal draw, so the
  //     base graph is untouched and toggling a mode only repaints.
  let heatNodes = []; // render nodes carrying heat, precomputed for the draw loop
  const HEAT_MIN_PX = 26; // screen-space glow floor so heat still pools when zoomed out
  const HEAT_GLOW_ALPHA = 0.6; // peak core alpha before additive accumulation
  const heatGradientCache = new Map(); // `${color}|${level}` -> unit radial gradient
  const heatGradient = (color, level) => {
    const key = color + '|' + level;
    let g = heatGradientCache.get(key);
    if (!g) {
      // A unit gradient at the origin, drawn via translate+scale, so one object
      // serves every hot node of this colour/intensity band (no per-frame alloc).
      g = ctx.createRadialGradient(0, 0, 0, 0, 0, 1);
      const c = d3.color(color) || d3.color('#f43f5e');
      const a = HEAT_GLOW_ALPHA * level;
      const at = (alpha) => {
        c.opacity = alpha;
        return c.toString();
      };
      g.addColorStop(0, at(a));
      g.addColorStop(0.45, at(a * 0.45));
      g.addColorStop(1, at(0));
      heatGradientCache.set(key, g);
    }
    return g;
  };

  const buildHeat = () => {
    renderNodes.forEach((d) => {
      d._heat = null;
    });
    const index = app.graphHeatActive ? app.graphHeatData() : null;
    if (!index || !index.size) {
      heatNodes = [];
      return;
    }
    index.forEach((h, id) => {
      const node = renderById.get(renderKeyOf.get(id));
      if (!node) return;
      if (!node._heat || h.intensity > node._heat.intensity) {
        node._heat = { intensity: h.intensity, color: h.color };
      }
    });
    heatNodes = renderNodes.filter((d) => d._heat);
  };

  // Soft additive glow behind edges/nodes: neighbouring hot nodes pool into one
  // hotter region, and a lone hot node still blooms visibly.
  const drawHeatGlow = () => {
    if (!heatNodes.length) return;
    const k = currentTransform.k;
    const minR = HEAT_MIN_PX / k;
    ctx.save();
    ctx.globalCompositeOperation = 'lighter';
    heatNodes.forEach((d) => {
      if (d.x == null) return;
      const h = d._heat;
      const level = Math.max(0.15, Math.round(h.intensity * 10) / 10);
      const R = Math.max(minR, radiusFor(d) * 2.6) * (0.7 + 0.6 * h.intensity);
      // Cull by the glow's own extent so a big blob just off-screen still bleeds in.
      if (d.x + R < view.x0 || d.x - R > view.x1 || d.y + R < view.y0 || d.y - R > view.y1) {
        return;
      }
      ctx.save();
      ctx.translate(d.x, d.y);
      ctx.scale(R, R);
      ctx.fillStyle = heatGradient(h.color, level);
      ctx.beginPath();
      ctx.arc(0, 0, 1, 0, 2 * Math.PI);
      ctx.fill();
      ctx.restore();
    });
    ctx.restore();
  };

  // A crisp ring in the heat colour on top of each hot node, so individual
  // relevant elements stay pinpointable even where the glow is faint. Tracks
  // search/hover emphasis so it fades with the node it marks.
  const drawHeatMarkers = () => {
    if (!heatNodes.length) return;
    const k = currentTransform.k;
    ctx.lineWidth = 2 / k;
    heatNodes.forEach((d) => {
      if (d.x == null || !nodeInView(d)) return;
      if (nodeSearchStyle(d.id).hidden) return;
      ctx.globalAlpha = 0.9;
      ctx.strokeStyle = d._heat.color;
      ctx.beginPath();
      ctx.arc(d.x, d.y, radiusFor(d) + 2.5 / k, 0, 2 * Math.PI);
      ctx.stroke();
    });
    ctx.globalAlpha = 1;
  };

  buildHeat();

  const drawCanvas = () => {
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);
    const k = currentTransform.k;
    view = {
      x0: -currentTransform.x / k,
      y0: -currentTransform.y / k,
      x1: (width - currentTransform.x) / k,
      y1: (height - currentTransform.y) / k
    };

    ctx.save();
    ctx.translate(currentTransform.x, currentTransform.y);
    ctx.scale(k, k);
    ctx.lineCap = 'round';

    drawHeatGlow(); // behind edges/nodes so hot regions read as ambient warmth

    if (searchActive) {
      // Links touching a match are emphasised; the rest stay faint.
      if (searchDimGroups) drawLinkGroups(searchDimGroups, 0.06, 0.7 / k);
      if (searchHotGroups) drawLinkGroups(searchHotGroups, 0.5, 1.4 / k);
    } else if (highlightedNodeId) {
      drawLinkGroups(groupedLinks, 0.04, 0.7 / k);
      const hl = linksByNode.get(highlightedNodeId) || [];
      const directed = highlightedDirectedLinks();
      if (directed) {
        // Non-directed edges stay bright/solid; directed edges get a dim base shaft so the flow reads as motion.
        const others = hl.filter((l) => !ARROW_REL_TYPES.has(l.type));
        if (others.length) drawLinkGroups(groupLinksByColor(others), 0.85, 1.6 / k);
        // Dim shaft, but keep the arrowheads opaque so direction stays clear.
        drawLinkGroups(groupLinksByColor(directed), 0.3, 1 / k, 1);
        drawFlowOverlay(directed, 1.8 / k);
      } else {
        drawLinkGroups(groupLinksByColor(hl), 0.85, 1.6 / k);
      }
    } else if (focusActive) {
      // Links inside the artifact's contribution set stay legible; the rest fade
      // to a faint backdrop, mirroring the node dimming.
      if (focusDimGroups) drawLinkGroups(focusDimGroups, 0.04, 0.7 / k);
      if (focusHotGroups) drawLinkGroups(focusHotGroups, 0.24, 0.9 / k);
    } else {
      drawLinkGroups(groupedLinks, 0.22, 0.85 / k);
    }
    drawNodes();
    drawHeatMarkers(); // crisp rings on top so each hot element stays pinpointable

    ctx.restore();
    ctx.globalAlpha = 1;
    drawLabels();
  };

  const queueDraw = () => {
    if (drawFrame) return;
    drawFrame = requestAnimationFrame(() => {
      drawFrame = 0;
      drawCanvas();
    });
  };

  // Self-perpetuating loop advancing the flow animation while a node with directed edges is hovered;
  // stops itself once the hover no longer applies. The handle lives on `app` so a rebuild can cancel a stale loop.
  const flowTick = () => {
    if (!highlightedDirectedLinks()) {
      app.graphFlowRAF = 0;
      return;
    }
    flowPhase = (flowPhase + FLOW_SPEED) % FLOW_PERIOD;
    drawCanvas();
    app.graphFlowRAF = requestAnimationFrame(flowTick);
  };
  const setFlow = () => {
    if (highlightedDirectedLinks()) {
      if (!app.graphFlowRAF) app.graphFlowRAF = requestAnimationFrame(flowTick);
    } else if (app.graphFlowRAF) {
      cancelAnimationFrame(app.graphFlowRAF);
      app.graphFlowRAF = 0;
    }
  };
  const syncHighlight = () => {
    const next = hoverNodeId ?? selectedNodeId;
    if (next === highlightedNodeId) return;
    highlightedNodeId = next;
    setFlow();
    queueDraw();
  };

  // 6b. Search overlay: recomputes the match/neighbour sets and link partitions then redraws,
  //     without rebuilding the graph or restarting the simulation, so typing doesn't re-layout.
  // Shared style objects (avoid per-node allocation in the draw loop).
  const SS_VISIBLE = { hidden: false, alpha: 1 };
  const SS_NEIGHBOR = { hidden: false, alpha: 0.4 };
  const SS_HIDDEN = { hidden: true, alpha: 0 };
  const SS_DIM = { hidden: false, alpha: 0.1 };
  // Main-artifact focus lens: nodes that didn't contribute to the artifact fade
  // right back so the artifact's real footprint stands out.
  const SS_FOCUS_DIM = { hidden: false, alpha: 0.07 };

  let searchActive = false;
  let searchFocusMode = false; // 'focus' hides non-matches; 'dim' just fades them
  let matchSet = new Set(); // render-node ids whose underlying element matches
  let neighborSet = new Set(); // direct neighbours of matches (focus mode only)
  let matchLabelList = []; // matched render nodes, largest first, for labelling
  let searchDimGroups = null; // colour-grouped links not touching a match
  let searchHotGroups = null; // colour-grouped links touching a match
  const searchTextCache = new Map(); // underlying id -> { name, full|null }

  // Main-artifact focus overlay (see recomputeFocus). focusSet holds render-node
  // ids in the artifact's contribution set; focusDim/HotGroups partition links by
  // whether both endpoints are in it.
  let focusActive = false;
  let focusSet = new Set();
  let focusArtifactRenderId = null;
  let focusDimGroups = null;
  let focusHotGroups = null;

  const searchTextOf = (uNode) => {
    let entry = searchTextCache.get(uNode.id);
    if (!entry) {
      entry = { name: ((uNode.name || '') + ' ' + (uNode.id || '')).toLowerCase(), full: null };
      searchTextCache.set(uNode.id, entry);
    }
    return entry;
  };
  // Full-text lazily serialises the whole element once, then caches it.
  const fullTextOf = (uNode) => {
    const entry = searchTextOf(uNode);
    if (entry.full == null) {
      try {
        entry.full = (entry.name + ' ' + JSON.stringify(uNode.data || {})).toLowerCase();
      } catch {
        entry.full = entry.name;
      }
    }
    return entry.full;
  };

  // Combined node style: the main-artifact focus lens is a persistent backdrop
  // (dim everything outside the contribution set), which the transient search
  // overlay then paints on top of.
  const nodeSearchStyle = (id) => {
    if (focusActive && !focusSet.has(id)) {
      // A search hit outside the focus set still gets the (brighter) search dim
      // so it stays findable; everything else fades to the focus backdrop.
      return searchActive && matchSet.has(id) ? SS_DIM : SS_FOCUS_DIM;
    }
    if (!searchActive || matchSet.has(id)) return SS_VISIBLE;
    if (searchFocusMode) return neighborSet.has(id) ? SS_NEIGHBOR : SS_HIDDEN;
    return SS_DIM;
  };

  const recomputeSearch = () => {
    const raw = (app.graphSearchQuery || '').trim().toLowerCase();
    const tokens = raw.split(/\s+/).filter(Boolean);
    searchActive = tokens.length > 0;
    searchFocusMode = app.graphSearchMode === 'focus';
    matchSet = new Set();
    neighborSet = new Set();
    matchLabelList = [];
    searchDimGroups = null;
    searchHotGroups = null;

    if (searchActive) {
      const fullText = !!app.graphSearchFullText;
      const matches = (hay) => tokens.every((t) => hay.includes(t));
      // Match on the underlying elements, then fold each hit up to its render node so a collapsed
      // cluster lights up when any member matches.
      uNodes.forEach((u) => {
        const hay = fullText ? fullTextOf(u) : searchTextOf(u).name;
        if (matches(hay)) {
          const rid = renderKeyOf.get(u.id);
          if (rid) matchSet.add(rid);
        }
      });
      matchSet.forEach((id) => {
        const conn = connectedIndex.get(id);
        if (conn) conn.forEach((n) => !matchSet.has(n) && neighborSet.add(n));
      });
      matchLabelList = labelOrder.filter((d) => matchSet.has(d.id));

      const dim = [];
      const hot = [];
      links.forEach((l) => {
        if (searchFocusMode) {
          const sVis = matchSet.has(l.sourceId) || neighborSet.has(l.sourceId);
          const tVis = matchSet.has(l.targetId) || neighborSet.has(l.targetId);
          if (!sVis || !tVis) return; // both endpoints must be visible
        }
        if (matchSet.has(l.sourceId) || matchSet.has(l.targetId)) hot.push(l);
        else dim.push(l);
      });
      searchDimGroups = groupLinksByColor(dim);
      searchHotGroups = groupLinksByColor(hot);
    }

    app.graphMatchCount = matchSet.size;
    queueDraw();
  };

  // Focus overlay: folds the app's main-artifact contribution set (underlying
  // spdxIds) up to render-node ids, then partitions links by whether they stay
  // inside it. A pure repaint, like the search/heat overlays — no rebuild.
  const recomputeFocus = () => {
    focusActive = false;
    focusSet = new Set();
    focusArtifactRenderId = null;
    focusDimGroups = null;
    focusHotGroups = null;

    if (app.graphFocusMainArtifact && app.mainArtifactId) {
      const contrib = app.mainArtifactContributionSet;
      contrib.forEach((uid) => {
        const rid = renderKeyOf.get(uid);
        if (rid) focusSet.add(rid);
      });
      focusArtifactRenderId = renderKeyOf.get(app.mainArtifactId) || null;
      // If nothing in the set is actually on screen (artifact filtered out),
      // don't fade the whole graph to nothing — leave the lens off.
      focusActive = focusSet.size > 0;
    }

    if (focusActive) {
      const dim = [];
      const hot = [];
      links.forEach((l) => {
        if (focusSet.has(l.sourceId) && focusSet.has(l.targetId)) hot.push(l);
        else dim.push(l);
      });
      focusDimGroups = groupLinksByColor(dim);
      focusHotGroups = groupLinksByColor(hot);
    }
    queueDraw();
  };

  // 7. Force simulation (main thread; ticks redraw the canvas). The active
  // layout (organic/hierarchy/radial/spotlight/lanes) seeds any starting
  // positions and wires the forces; see buildLayout above.
  if (layout.seed) layout.seed();
  const sim = d3.forceSimulation(renderNodes);
  layout.configure(sim);

  // Hit-testing quadtree, rebuilt lazily only after the simulation moves nodes (flagged on tick),
  // so hover/drag hit-tests on a settled layout reuse it in O(log n) instead of rebuilding per mousemove.
  let hitTree = null;
  let hitTreeDirty = true;
  const findNode = (wx, wy, r) => {
    if (hitTreeDirty || !hitTree) {
      hitTree = d3.quadtree(
        renderNodes,
        (d) => d.x,
        (d) => d.y
      );
      hitTreeDirty = false;
    }
    return hitTree.find(wx, wy, r);
  };

  // Auto-fit keeps the whole layout framed while it settles, so any rebuild
  // (filters, hide orphans, aggregate, expand, first load) reframes without the
  // user waiting for the force sim to fully cool. It runs live (instant, no
  // transition) during the build's own settle only: `building` gates it off once
  // the layout first ends, so a later reheat (dragging a node) does not yank the
  // view, and `dragging` suppresses it mid-drag. A user who has panned/zoomed
  // (auto-fit off) is left alone. `app.graphFitView` is defined further below but
  // only ever called here asynchronously, by which point it is assigned.
  let building = true;
  let dragging = false;
  let lastFitAt = 0;
  const autoFitTick = () => {
    if (!building || dragging || app.graphAutoFit === false || !app.graphFitView) return;
    const now = performance.now();
    if (now - lastFitAt < 90) return; // throttle so we reframe ~10x/s, not every tick
    lastFitAt = now;
    app.graphFitView(0);
  };

  sim.on('tick', () => {
    hitTreeDirty = true;
    queueDraw();
    autoFitTick();
  });

  sim.on('end', () => {
    if (!building) return; // ignore reheats (e.g. node drag) after the first settle
    building = false;
    if (app.graphAutoFit !== false && app.graphFitView) app.graphFitView();
  });

  // 8. Interaction: zoom/pan, node drag, hover, click, double-click expand; hit-testing via findNode().
  const nodeAtCanvas = (px, py) => {
    const wx = currentTransform.invertX(px);
    const wy = currentTransform.invertY(py);
    const found = findNode(wx, wy, 40 / currentTransform.k);
    if (!found || nodeSearchStyle(found.id).hidden) return null;
    const r = radiusFor(found);
    const dx = found.x - wx;
    const dy = found.y - wy;
    return dx * dx + dy * dy <= (r + 4) * (r + 4) ? found : null;
  };
  const pointerNode = (event) => {
    const rect = canvas.getBoundingClientRect();
    return nodeAtCanvas(event.clientX - rect.left, event.clientY - rect.top);
  };

  // Nearest visible edge within EDGE_HIT_PX of the pointer, or null. Backs the edge tooltip
  // (notably the "via snippet" hint). Linear over visible links, so it's skipped while searching
  // (the overlay owns emphasis then) and on very dense graphs where the scan wouldn't pay off.
  const edgeAtCanvas = (px, py) => {
    if (searchActive || links.length > EDGE_HOVER_MAX) return null;
    const wx = currentTransform.invertX(px);
    const wy = currentTransform.invertY(py);
    const tol = EDGE_HIT_PX / currentTransform.k;
    let best = null;
    let bestD2 = tol * tol;
    for (const link of links) {
      const a = link.sourceNode;
      const b = link.targetNode;
      if (!a || !b || a.x == null || b.x == null) continue;
      if (!nodeInView(a) && !nodeInView(b)) continue;
      const d2 = distToSegment2(wx, wy, a.x, a.y, b.x, b.y);
      if (d2 < bestD2) {
        bestD2 = d2;
        best = link;
      }
    }
    return best;
  };

  // Tooltip body for a hovered edge: the relationship type (matching the legend labels), its
  // endpoints, and, for snippet-redirected edges, the snippet name(s) the traceability runs through.
  const edgeTooltipHtml = (edge) => {
    const s = edge.sourceNode?.name || cleanName(edge.sourceId);
    const t = edge.targetNode?.name || cleanName(edge.targetId);
    let hint = '';
    if (edge.viaSnippets?.size) {
      const names = [...edge.viaSnippets];
      const shown = names.slice(0, 3).join(', ');
      const extra = names.length > 3 ? ` +${names.length - 3} more` : '';
      hint =
        `<div class="text-xs mt-1">via snippet${names.length > 1 ? 's' : ''} ` +
        `${escapeHtml(shown)}${escapeHtml(extra)}</div>`;
    } else if (edge.weight > 1) {
      hint = `<div class="text-xs mt-1">${edge.weight} relationships</div>`;
    }
    return (
      `<div class="font-semibold text-white">${escapeHtml(edge.type)}</div>` +
      `<div class="text-slate-400 text-xs">${escapeHtml(s)} → ${escapeHtml(t)}</div>` +
      hint
    );
  };

  const sel = d3.select(canvas);

  app.graphZoom = d3
    .zoom()
    .scaleExtent([0.02, 8])
    .filter((event) => {
      if (event.type === 'wheel') return true;
      if (event.type === 'dblclick') return false; // handled below
      const [px, py] = d3.pointer(event, canvas);
      return !nodeAtCanvas(px, py); // pan only when not starting on a node
    })
    .on('zoom', (event) => {
      currentTransform = event.transform;
      app.graphTransform = event.transform; // remembered so a rebuild can restore the user's view
      // A real gesture (wheel/pan) means the user is driving the view, so stop
      // auto-fitting on rebuilds until they hit "reset zoom" again. Programmatic
      // transforms (fit/restore) have no sourceEvent and must not flip this.
      if (event.sourceEvent) app.graphAutoFit = false;
      queueDraw();
    });

  const drag = d3
    .drag()
    .subject((event) => {
      const wx = currentTransform.invertX(event.x);
      const wy = currentTransform.invertY(event.y);
      const found = findNode(wx, wy, 40 / currentTransform.k);
      if (!found || nodeSearchStyle(found.id).hidden) return null;
      const r = radiusFor(found);
      return (found.x - wx) ** 2 + (found.y - wy) ** 2 <= (r + 4) ** 2 ? found : null;
    })
    .on('start', (event) => {
      if (!event.subject) return;
      dragging = true; // hold auto-fit while the user repositions a node
      if (!event.active) sim.alphaTarget(0.3).restart();
      event.subject.fx = event.subject.x;
      event.subject.fy = event.subject.y;
    })
    .on('drag', (event) => {
      if (!event.subject) return;
      event.subject.fx = currentTransform.invertX(event.x);
      event.subject.fy = currentTransform.invertY(event.y);
      queueDraw();
    })
    .on('end', (event) => {
      if (!event.subject) return;
      dragging = false;
      if (!event.active) sim.alphaTarget(0);
      event.subject.fx = null;
      event.subject.fy = null;
    });

  sel.call(app.graphZoom).on('dblclick.zoom', null);
  sel.call(drag);

  // A rebuild makes a fresh canvas at identity. If the user is driving the view
  // (auto-fit off), restore their last pan/zoom so toggling a filter doesn't yank
  // them back; otherwise leave identity and let the settle handler fit the layout.
  if (app.graphAutoFit === false && app.graphTransform) {
    sel.call(app.graphZoom.transform, app.graphTransform);
  }

  canvas.addEventListener('mousemove', (event) => {
    const found = pointerNode(event);
    hoverNodeId = found ? found.id : null;
    syncHighlight();
    const tooltip = document.getElementById('graphTooltip');
    if (!tooltip) return;
    const rect = canvas.getBoundingClientRect();
    const showTooltip = (html) => {
      tooltip.innerHTML = html;
      tooltip.classList.remove('hidden');
      tooltip.style.left = `${event.clientX - rect.left + 15}px`;
      tooltip.style.top = `${event.clientY - rect.top - 10}px`;
    };
    if (found) {
      const isExternal = !found.isCluster && found.data?.external;
      const isVirtual = !found.isCluster && found.data?.virtual;
      const meta = found.isCluster
        ? `${found.clusterKind} cluster · ${found.memberCount} items`
        : isExternal
          ? `external · ${found.data?.type || found.type}`
          : isVirtual
            ? `online scan · ${found.data?.type || found.type}`
            : found.data?.type || found.type;
      const hint = found.isCluster
        ? 'double-click to expand'
        : isExternal && found.data?.locationHint
          ? `defined in ${found.data.locationHint}`
          : isVirtual
            ? 'found by online scan, not in the SBOM'
            : `${connCount.get(found.id) || 0} connections`;
      showTooltip(
        `<div class="font-semibold text-white">${escapeHtml(found.name)}</div>` +
          `<div class="text-slate-400 text-xs">${escapeHtml(meta)}</div>` +
          `<div class="text-xs mt-1">${escapeHtml(hint)}</div>`
      );
      return;
    }
    // No node under the pointer: fall back to hovering an edge (surfaces the "via snippet" hint).
    const edge = edgeAtCanvas(event.clientX - rect.left, event.clientY - rect.top);
    if (edge) {
      showTooltip(edgeTooltipHtml(edge));
    } else {
      tooltip.classList.add('hidden');
    }
  });

  canvas.addEventListener('mouseleave', () => {
    hoverNodeId = null;
    syncHighlight();
    document.getElementById('graphTooltip')?.classList.add('hidden');
  });

  // Click selects and pins hover-style focus (suppressed by d3.drag after a real drag).
  canvas.addEventListener('click', (event) => {
    const found = pointerNode(event);
    if (!found) {
      selectedNodeId = null;
      app.graphSelectedNodeId = null;
      syncHighlight();
      app._scheduleNavPush();
      return;
    }
    selectedNodeId = found.id;
    app.graphSelectedNodeId = found.id;
    syncHighlight();
    if (found.isCluster) {
      app.detailElement = found.data && !found.data.placeholder ? found.data : null;
    } else {
      app.detailElement = found.data;
    }
    app._scheduleNavPush();
  });

  // Double-click drills into a collapsed cluster.
  canvas.addEventListener('dblclick', (event) => {
    const found = pointerNode(event);
    if (found && found.isCluster) {
      app.expandedClusters.add(found.clusterKey);
      app.renderGraph();
    }
  });

  // Expose the search recompute so the controls bar can update the overlay
  // without rebuilding the graph, and apply any active query to the fresh build.
  app.graphRecomputeSearch = recomputeSearch;
  // A pure redraw (no re-layout) so visual-only toggles like icon mode can flip
  // a flag and repaint the settled canvas instead of restarting the simulation.
  app.graphRedraw = queueDraw;
  // Frame the whole (visible) layout in the viewport: the "reset zoom" control
  // fits the graph rather than snapping to a 1:1 identity view that leaves most
  // of a spread-out layout off-screen. Skips search-hidden nodes so a focused
  // search reframes to the matches.
  app.graphFitView = (duration = 500) => {
    const pts = renderNodes.filter((d) => !nodeSearchStyle(d.id).hidden);
    if (!pts.length) return;
    // Fitting (the "reset zoom" control) opts back into auto-fit on rebuilds.
    app.graphAutoFit = true;
    let minX = Infinity;
    let minY = Infinity;
    let maxX = -Infinity;
    let maxY = -Infinity;
    for (const d of pts) {
      const r = radiusFor(d);
      if (d.x - r < minX) minX = d.x - r;
      if (d.y - r < minY) minY = d.y - r;
      if (d.x + r > maxX) maxX = d.x + r;
      if (d.y + r > maxY) maxY = d.y + r;
    }
    const bw = Math.max(maxX - minX, 1);
    const bh = Math.max(maxY - minY, 1);
    const cx = (minX + maxX) / 2;
    const cy = (minY + maxY) / 2;
    const [minK, maxK] = app.graphZoom.scaleExtent();
    // 0.9 keeps a small margin; cap at 1 so a tiny graph stays 1:1 rather than
    // ballooning to fill the canvas.
    const k = Math.max(minK, Math.min(maxK, 1, 0.9 * Math.min(width / bw, height / bh)));
    const t = d3.zoomIdentity.translate(width / 2 - k * cx, height / 2 - k * cy).scale(k);
    const target = duration
      ? app.graphCanvasSel.transition().duration(duration)
      : app.graphCanvasSel;
    target.call(app.graphZoom.transform, t);
  };
  // Re-fold the heat index onto the settled layout and repaint, so switching heat
  // mode never restarts the force simulation.
  app.graphRecomputeHeat = () => {
    buildHeat();
    queueDraw();
  };
  // Re-fold the main-artifact contribution set onto the settled layout and
  // repaint, so toggling the focus lens or changing the artifact never rebuilds.
  app.graphRecomputeFocus = recomputeFocus;
  recomputeSearch();
  recomputeFocus();
  setFlow();

  // Lets nav-history restoration (browser back/forward) re-pin a node's
  // highlight on the already-rendered canvas without a full graph rebuild.
  app.graphSyncSelection = (id) => {
    selectedNodeId = renderById.has(id) ? id : null;
    app.graphSelectedNodeId = selectedNodeId;
    syncHighlight();
  };

  app.graphSim = sim;
  app.graphCanvasSel = sel;
  app.graphSvg = null;
}

export function resetGraphZoom(app) {
  if (app.graphFitView) app.graphFitView();
  else if (app.graphCanvasSel && app.graphZoom) {
    app.graphCanvasSel.transition().duration(500).call(app.graphZoom.transform, d3.zoomIdentity);
  }
}
