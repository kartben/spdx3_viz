import {
  getRelationshipColor,
  getNodeType,
  getNodeTypeColor,
  cleanName,
  dirPrefix
} from './utils.js';

const INPUT_LAYOUT_LINKS_PER_BUILD = 8;
// Above this many underlying nodes we refuse to render a flat graph even if the
// user turned aggregation off — a multi-thousand-node hairball is unusable and
// hammers the machine. We force-collapse and surface a hint instead.
const MAX_FLAT_NODES = 2000;
// Labels are expensive and become noise when zoomed out; only draw them past
// this zoom level, and cap how many we draw per frame.
const LABEL_ZOOM_THRESHOLD = 1.1;
const MAX_LABELS = 400;
// World-space padding for viewport culling so nodes/edges near the edge of the
// screen still draw.
const CULL_PAD = 80;
// Relationship types drawn with a dotted stroke instead of a solid line.
const DASH_REL_TYPES = new Set(['usesTool']);
// Relationship types drawn with an arrowhead at their "head" end. hasInput
// points at the build (the source), hasOutput points at the output file (the
// target), so the pair reads as inputs → build → outputs.
const ARROW_REL_TYPES = new Set(['hasInput', 'hasOutput']);
// Arrowhead dimensions in screen pixels (divided by the zoom factor to stay a
// constant on-screen size). Kept deliberately small/light.
const ARROW_LEN = 7;
const ARROW_HALF_WIDTH = 3;
// Hover "flow" animation: when a node with directed edges is hovered, dashes
// march along those edges in the flow direction (into the build for inputs, out
// to the file for outputs). Dash/gap are screen pixels; SPEED is screen px per
// frame.
const FLOW_DASH = 5;
const FLOW_GAP = 12;
const FLOW_PERIOD = FLOW_DASH + FLOW_GAP;
const FLOW_SPEED = 0.3;

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

  let type = 'ExternalReference';
  if (role === 'source' && buildRelationshipTypes.has(rel.relationshipType)) {
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

export function renderGraph(app) {
  const container = document.getElementById('graphContainer');
  if (!container) return;

  // Drop any previous canvas/svg but keep the tooltip element.
  container.querySelectorAll('svg, canvas').forEach((el) => el.remove());
  if (app.graphSim) app.graphSim.stop();
  if (app.graphFlowRAF) {
    cancelAnimationFrame(app.graphFlowRAF); // stop a hover-flow loop from the old canvas
    app.graphFlowRAF = 0;
  }

  const width = container.clientWidth;
  const height = container.clientHeight;
  if (!width || !height || !globalThis.d3) return;

  const activeNodeTypes = new Set(
    app.graphFilters.filter((f) => !f.isRel && f.active).map((f) => f.key)
  );
  const activeRelTypes = new Set(
    app.graphFilters.filter((f) => f.isRel && f.active).map((f) => f.key)
  );

  /* ----------------------------------------------------------------------
     1. Underlying nodes (one per SPDX element that passes the type filters)
     ---------------------------------------------------------------------- */
  const uNodeIds = new Set();
  const uNodes = [];
  const uNodeById = new Map();

  const addNode = (spdxId, rel = null, role = 'target') => {
    if (!spdxId) return null;
    if (uNodeIds.has(spdxId)) return uNodeById.get(spdxId);

    const el = app.elementMap.get(spdxId) || placeholderFor(spdxId, rel || {}, role);
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
  app.tools.forEach((t) => addNode(t.spdxId));
  app.buildConfigs.forEach((c) => addNode(c.spdxId));
  (app.builds || []).forEach((b) => addNode(b.spdxId));
  if (!app.builds?.length && app.buildInfo) addNode(app.buildInfo.spdxId);

  /* ----------------------------------------------------------------------
     2. Underlying links
     ---------------------------------------------------------------------- */
  const uLinks = [];
  app.relationships.forEach((rel) => {
    if (rel.relationshipType === 'hasConcludedLicense') return;
    if (!activeRelTypes.has(rel.relationshipType)) return;

    const sourceNode = addNode(rel.from, rel, 'source');
    asTargets(rel.to).forEach((target) => {
      const targetNode = addNode(target, rel, 'target');
      if (!sourceNode || !targetNode) return;
      uLinks.push({ sourceId: rel.from, targetId: target, type: rel.relationshipType });
    });
  });

  /* ----------------------------------------------------------------------
     3. Hierarchical clustering
        Group files into their parent package, else their directory; group
        build steps into their root build; everything else is its own node.
     ---------------------------------------------------------------------- */
  let aggregate = app.graphAggregate;
  app.graphTruncated = false;
  if (!aggregate && uNodes.length > MAX_FLAT_NODES) {
    aggregate = true;
    app.graphTruncated = true;
  }
  const expanded = app.expandedClusters instanceof Set ? app.expandedClusters : new Set();

  const clusterKeyFor = (node) => {
    if (!aggregate) return 'self:' + node.id;
    if (node.type === 'package') return 'pkg:' + node.id;
    if (node.type === 'file') {
      // Only collapse into a parent that is an actual package. SBOMs (e.g. the
      // Linux kernel) often use a pseudo-root *file* like `$(src_tree)` as the
      // `contains` parent of every file — clustering on that would collapse the
      // whole tree into one node, so we fall through to directory grouping.
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

  /* ----------------------------------------------------------------------
     4. Render nodes + map every underlying id to its render id
     ---------------------------------------------------------------------- */
  const renderById = new Map();
  const renderNodes = [];
  const renderKeyOf = new Map(); // underlying id -> render node id

  clusters.forEach((c) => {
    const collapsed =
      aggregate && c.members.length > 1 && c.kind !== 'self' && !expanded.has(c.key);

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

  /* ----------------------------------------------------------------------
     5. Remap links onto render nodes, drop self-loops, dedupe, weight
     ---------------------------------------------------------------------- */
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

  // Live readout for the controls bar.
  app.graphNodeCount = renderNodes.length;
  app.graphEdgeCount = links.length;

  /* ----------------------------------------------------------------------
     6. Canvas (edges + nodes + labels on one surface)
     ---------------------------------------------------------------------- */
  const canvas = document.createElement('canvas');
  canvas.className = 'graph-canvas';
  container.appendChild(canvas);

  const dpr = globalThis.devicePixelRatio || 1;
  canvas.width = width * dpr;
  canvas.height = height * dpr;
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;
  const ctx = canvas.getContext('2d');

  const radiusFor = (d) =>
    d.isCluster
      ? Math.max(9, Math.min(30, 7 + Math.sqrt(d.memberCount) * 1.6))
      : Math.max(5, Math.min(16, 4 + Math.sqrt(connCount.get(d.id) || 0) * 1.2));

  const strokeFor = (d) => d3.color(getNodeTypeColor(d.type)).brighter(0.5);
  // Draw bigger nodes' labels first so the MAX_LABELS cap keeps the useful ones.
  const labelOrder = [...renderNodes].sort((a, b) => radiusFor(b) - radiusFor(a));

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

  // headAlpha lets the arrowheads stay opaque while the shaft is dimmed (used by
  // the hover flow, where the shaft fades behind the moving dashes but the heads
  // should remain crisp). Defaults to the shaft alpha.
  const drawLinkGroups = (groups, alpha, lineWidth, headAlpha = alpha) => {
    const k = currentTransform.k;
    // Arrowheads a constant on-screen size, growing only a touch on emphasised
    // (thicker) edges so they stay light.
    const headLen = (ARROW_LEN + lineWidth * k) / k;
    const headHalf = (ARROW_HALF_WIDTH + lineWidth * k * 0.6) / k;
    const dotPattern = [lineWidth, 4 / k]; // constant on-screen dotted pattern

    groups.forEach((group, color) => {
      ctx.strokeStyle = color;
      ctx.globalAlpha = alpha;
      ctx.lineWidth = lineWidth;

      // Solid shafts (plain + directed) batched into one path per colour.
      // Dashed edges and arrowheads are collected and drawn separately
      // afterwards — a single path can't mix dashes, and heads are filled.
      let dashed = null;
      let arrows = null;
      ctx.setLineDash([]);
      ctx.beginPath();
      group.forEach((link) => {
        const a = link.sourceNode;
        const b = link.targetNode;
        if (!a || !b || a.x == null || b.x == null) return;
        if (!nodeInView(a) && !nodeInView(b)) return; // viewport culling

        if (DASH_REL_TYPES.has(link.type)) {
          (dashed ||= []).push(a, b);
          return;
        }
        if (!ARROW_REL_TYPES.has(link.type)) {
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          return;
        }
        // hasInput's head sits on the build (source); hasOutput's on the file
        // (target). Shaft stops at the base of the head so they meet cleanly.
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

      if (dashed) {
        ctx.globalAlpha = alpha;
        ctx.setLineDash(dotPattern);
        ctx.beginPath();
        for (let i = 0; i < dashed.length; i += 2) {
          ctx.moveTo(dashed[i].x, dashed[i].y);
          ctx.lineTo(dashed[i + 1].x, dashed[i + 1].y);
        }
        ctx.stroke();
        ctx.setLineDash([]);
      }
    });
  };

  const drawNodes = () => {
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
      ctx.fillStyle = getNodeTypeColor(d.type);
      ctx.fill();
      ctx.lineWidth = (d.isCluster ? 2.5 : 1.5) / k;
      ctx.strokeStyle = d.isCluster ? 'rgba(255,255,255,0.85)' : strokeFor(d);
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
    });
    ctx.globalAlpha = 1;
  };

  // Screen-space label decluttering: labels are placed greedily in priority
  // order and any that would overlap one already drawn is skipped. This keeps
  // dense areas (e.g. lots of search hits packed together) readable without
  // re-laying out the graph and jolting node positions around as the user types.
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

    // Search hits always get a label — even zoomed out — so they're findable.
    if (searchActive) {
      for (const d of matchLabelList) {
        if (drawn >= MAX_LABELS) break;
        if (d.x == null) continue;
        if (drawLabel(d, true)) drawn++;
      }
    }

    // Remaining (non-match) labels only once zoomed in, mirroring the old
    // behaviour and respecting hover focus when not searching.
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

  // The hovered node's directed (hasInput/hasOutput) links, or null. Drives both
  // the flow animation and the dimmed base shaft under it.
  const highlightedDirectedLinks = () => {
    if (searchActive || !highlightedNodeId) return null;
    const hl = linksByNode.get(highlightedNodeId);
    if (!hl) return null;
    const directed = hl.filter((l) => ARROW_REL_TYPES.has(l.type));
    return directed.length ? directed : null;
  };

  // Marching dashes along the directed edges, animated by flowPhase. Each edge
  // is drawn tail → head so the dashes travel in the relationship's direction.
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

    if (searchActive) {
      // Links touching a match are emphasised; the rest stay faint. In focus
      // mode, links with a hidden endpoint were dropped during recompute.
      if (searchDimGroups) drawLinkGroups(searchDimGroups, 0.06, 0.7 / k);
      if (searchHotGroups) drawLinkGroups(searchHotGroups, 0.5, 1.4 / k);
    } else if (highlightedNodeId) {
      drawLinkGroups(groupedLinks, 0.04, 0.7 / k);
      const hl = linksByNode.get(highlightedNodeId) || [];
      const directed = highlightedDirectedLinks();
      if (directed) {
        // Non-directed edges stay bright/solid; directed edges get a dim base
        // shaft (with a faint head) so the animated flow on top reads as motion.
        const others = hl.filter((l) => !ARROW_REL_TYPES.has(l.type));
        if (others.length) drawLinkGroups(groupLinksByColor(others), 0.85, 1.6 / k);
        // Dim shaft, but keep the arrowheads opaque so direction stays clear.
        drawLinkGroups(groupLinksByColor(directed), 0.3, 1 / k, 1);
        drawFlowOverlay(directed, 1.8 / k);
      } else {
        drawLinkGroups(groupLinksByColor(hl), 0.85, 1.6 / k);
      }
    } else {
      drawLinkGroups(groupedLinks, 0.22, 0.85 / k);
    }
    drawNodes();

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

  // Self-perpetuating loop that advances the flow animation while a node with
  // directed edges is hovered; it stops itself once the hover no longer applies.
  // The handle lives on `app` so a graph rebuild can cancel a stale loop.
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

  /* ----------------------------------------------------------------------
     6b. Search overlay
         Driven by the controls bar via app.graphRecomputeSearch(). Recomputes
         the match/neighbour sets and link partitions, then redraws — it never
         rebuilds the graph or restarts the simulation, so typing doesn't
         re-layout the whole thing.
     ---------------------------------------------------------------------- */
  // Shared style objects (avoid per-node allocation in the draw loop).
  const SS_VISIBLE = { hidden: false, alpha: 1 };
  const SS_NEIGHBOR = { hidden: false, alpha: 0.4 };
  const SS_HIDDEN = { hidden: true, alpha: 0 };
  const SS_DIM = { hidden: false, alpha: 0.1 };

  let searchActive = false;
  let searchFocusMode = false; // 'focus' hides non-matches; 'dim' just fades them
  let matchSet = new Set(); // render-node ids whose underlying element matches
  let neighborSet = new Set(); // direct neighbours of matches (focus mode only)
  let matchLabelList = []; // matched render nodes, largest first, for labelling
  let searchDimGroups = null; // colour-grouped links not touching a match
  let searchHotGroups = null; // colour-grouped links touching a match
  const searchTextCache = new Map(); // underlying id -> { name, full|null }

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

  const nodeSearchStyle = (id) => {
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
      // Match on the underlying elements, then fold each hit up to its render
      // node so a collapsed cluster lights up when any member matches.
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

  /* ----------------------------------------------------------------------
     7. Force simulation (main thread; ticks redraw the canvas)
     ---------------------------------------------------------------------- */
  const sim = d3
    .forceSimulation(renderNodes)
    .force(
      'link',
      d3
        .forceLink(createLayoutLinks(links))
        .id((d) => d.id)
        .distance((d) => (d.type === 'hasInput' ? 85 : 60))
        .strength((d) => (d.type === 'hasInput' ? 0.05 : 0.18))
    )
    .force('charge', d3.forceManyBody().strength(-150))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force(
      'collision',
      d3.forceCollide().radius((d) => radiusFor(d) + 4)
    )
    .force('x', d3.forceX(width / 2).strength(0.045))
    .force('y', d3.forceY(height / 2).strength(0.045));

  sim.on('tick', queueDraw);

  /* ----------------------------------------------------------------------
     8. Interaction: zoom/pan, node drag, hover, click, double-click expand
        Hit-testing uses the simulation's quadtree via sim.find().
     ---------------------------------------------------------------------- */
  const nodeAtCanvas = (px, py) => {
    const wx = currentTransform.invertX(px);
    const wy = currentTransform.invertY(py);
    const found = sim.find(wx, wy, 40 / currentTransform.k);
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
      queueDraw();
    });

  const drag = d3
    .drag()
    .subject((event) => {
      const wx = currentTransform.invertX(event.x);
      const wy = currentTransform.invertY(event.y);
      const found = sim.find(wx, wy, 40 / currentTransform.k);
      if (!found || nodeSearchStyle(found.id).hidden) return null;
      const r = radiusFor(found);
      return (found.x - wx) ** 2 + (found.y - wy) ** 2 <= (r + 4) ** 2 ? found : null;
    })
    .on('start', (event) => {
      if (!event.subject) return;
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
      if (!event.active) sim.alphaTarget(0);
      event.subject.fx = null;
      event.subject.fy = null;
    });

  sel.call(app.graphZoom).on('dblclick.zoom', null);
  sel.call(drag);

  canvas.addEventListener('mousemove', (event) => {
    const found = pointerNode(event);
    hoverNodeId = found ? found.id : null;
    syncHighlight();
    const tooltip = document.getElementById('graphTooltip');
    if (!tooltip) return;
    if (found) {
      const rect = canvas.getBoundingClientRect();
      const meta = found.isCluster
        ? `${found.clusterKind} cluster · ${found.memberCount} items`
        : found.data?.type || found.type;
      const hint = found.isCluster
        ? 'double-click to expand'
        : `${connCount.get(found.id) || 0} connections`;
      tooltip.innerHTML =
        `<div class="font-semibold text-white">${escapeHtml(found.name)}</div>` +
        `<div class="text-slate-400 text-xs">${escapeHtml(meta)}</div>` +
        `<div class="text-xs mt-1">${escapeHtml(hint)}</div>`;
      tooltip.classList.remove('hidden');
      tooltip.style.left = `${event.clientX - rect.left + 15}px`;
      tooltip.style.top = `${event.clientY - rect.top - 10}px`;
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
  recomputeSearch();
  setFlow();

  app.graphSim = sim;
  app.graphCanvasSel = sel;
  app.graphSvg = null;
}

export function resetGraphZoom(app) {
  if (app.graphCanvasSel && app.graphZoom) {
    app.graphCanvasSel.transition().duration(500).call(app.graphZoom.transform, d3.zoomIdentity);
  }
}
