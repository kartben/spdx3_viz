import { getRelationshipColor, getNodeType, getNodeTypeColor, cleanName } from './utils.js';

const INPUT_LAYOUT_LINKS_PER_BUILD = 8;

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

export function renderGraph(app) {
  const container = document.getElementById('graphContainer');
  if (!container) return;

  container.querySelectorAll('svg, canvas').forEach((el) => el.remove());
  if (app.graphSim) app.graphSim.stop();

  const width = container.clientWidth;
  const height = container.clientHeight;
  if (!width || !height || !globalThis.d3) return;

  const activeNodeTypes = new Set(
    app.graphFilters.filter((f) => !f.isRel && f.active).map((f) => f.key)
  );
  const activeRelTypes = new Set(
    app.graphFilters.filter((f) => f.isRel && f.active).map((f) => f.key)
  );

  const nodeIds = new Set();
  const nodes = [];
  const nodeById = new Map();

  const addNode = (spdxId, rel = null, role = 'target') => {
    if (!spdxId) return null;
    if (nodeIds.has(spdxId)) return nodeById.get(spdxId);

    const el = app.elementMap.get(spdxId) || placeholderFor(spdxId, rel || {}, role);
    const type = getNodeType(el);
    if (!activeNodeTypes.has(type)) return null;

    const node = {
      id: spdxId,
      name: el.name || cleanName(spdxId),
      type,
      data: el
    };
    nodeIds.add(spdxId);
    nodeById.set(spdxId, node);
    nodes.push(node);
    return node;
  };

  app.packages.forEach((p) => addNode(p.spdxId));
  app.files.forEach((f) => addNode(f.spdxId));
  app.tools.forEach((t) => addNode(t.spdxId));
  app.buildConfigs.forEach((c) => addNode(c.spdxId));
  (app.builds || []).forEach((b) => addNode(b.spdxId));
  if (!app.builds?.length && app.buildInfo) addNode(app.buildInfo.spdxId);

  const links = [];
  app.relationships.forEach((rel) => {
    if (rel.relationshipType === 'hasConcludedLicense') return;
    if (!activeRelTypes.has(rel.relationshipType)) return;

    const sourceNode = addNode(rel.from, rel, 'source');
    asTargets(rel.to).forEach((target) => {
      const targetNode = addNode(target, rel, 'target');
      if (!sourceNode || !targetNode) return;
      links.push({
        sourceId: rel.from,
        targetId: target,
        sourceNode,
        targetNode,
        type: rel.relationshipType,
        color: getRelationshipColor(rel.relationshipType)
      });
    });
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

  const canvas = document.createElement('canvas');
  canvas.className = 'graph-edge-canvas';
  container.appendChild(canvas);

  const dpr = globalThis.devicePixelRatio || 1;
  canvas.width = width * dpr;
  canvas.height = height * dpr;
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;

  const ctx = canvas.getContext('2d');
  const groupedLinks = groupLinksByColor(links);
  let currentTransform = d3.zoomIdentity;
  let highlightedNodeId = null;
  let drawFrame = 0;

  const drawLinkList = (linkList, alpha, lineWidth) => {
    const grouped = groupLinksByColor(linkList);
    grouped.forEach((group, color) => {
      ctx.beginPath();
      ctx.strokeStyle = color;
      ctx.globalAlpha = alpha;
      ctx.lineWidth = lineWidth;
      group.forEach((link) => {
        if (
          link.sourceNode.x == null ||
          link.sourceNode.y == null ||
          link.targetNode.x == null ||
          link.targetNode.y == null
        ) {
          return;
        }
        ctx.moveTo(link.sourceNode.x, link.sourceNode.y);
        ctx.lineTo(link.targetNode.x, link.targetNode.y);
      });
      ctx.stroke();
    });
  };

  const drawGroupedLinks = (groups, alpha, lineWidth) => {
    groups.forEach((group, color) => {
      ctx.beginPath();
      ctx.strokeStyle = color;
      ctx.globalAlpha = alpha;
      ctx.lineWidth = lineWidth;
      group.forEach((link) => {
        if (
          link.sourceNode.x == null ||
          link.sourceNode.y == null ||
          link.targetNode.x == null ||
          link.targetNode.y == null
        ) {
          return;
        }
        ctx.moveTo(link.sourceNode.x, link.sourceNode.y);
        ctx.lineTo(link.targetNode.x, link.targetNode.y);
      });
      ctx.stroke();
    });
  };

  const drawCanvas = () => {
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);
    ctx.save();
    ctx.translate(currentTransform.x, currentTransform.y);
    ctx.scale(currentTransform.k, currentTransform.k);
    ctx.lineCap = 'round';

    if (highlightedNodeId) {
      drawGroupedLinks(groupedLinks, 0.035, 0.7);
      drawLinkList(linksByNode.get(highlightedNodeId) || [], 0.75, 1.3);
    } else {
      drawGroupedLinks(groupedLinks, 0.22, 0.85);
    }

    ctx.restore();
    ctx.globalAlpha = 1;
  };

  const queueDraw = () => {
    if (drawFrame) return;
    drawFrame = requestAnimationFrame(() => {
      drawFrame = 0;
      drawCanvas();
    });
  };

  const svg = d3
    .select(container)
    .append('svg')
    .attr('class', 'graph-node-layer')
    .attr('width', width)
    .attr('height', height);

  const g = svg.append('g');
  app.graphZoom = d3
    .zoom()
    .scaleExtent([0.05, 8])
    .on('zoom', (event) => {
      currentTransform = event.transform;
      g.attr('transform', currentTransform);
      queueDraw();
    });
  svg.call(app.graphZoom);

  let sim;
  const radiusFor = (d) => Math.max(5, Math.min(16, 4 + Math.sqrt(connCount.get(d.id) || 0) * 1.2));

  const node = g
    .append('g')
    .selectAll('circle')
    .data(nodes)
    .enter()
    .append('circle')
    .attr('class', 'node')
    .attr('r', radiusFor)
    .attr('fill', (d) => getNodeTypeColor(d.type))
    .attr('stroke', (d) => d3.color(getNodeTypeColor(d.type)).brighter(0.5))
    .attr('stroke-width', 1.5)
    .call(
      d3
        .drag()
        .on('start', (event, d) => {
          if (!event.active) sim.alphaTarget(0.3).restart();
          d.fx = d.x;
          d.fy = d.y;
        })
        .on('drag', (event, d) => {
          d.fx = event.x;
          d.fy = event.y;
          queueDraw();
        })
        .on('end', (event, d) => {
          if (!event.active) sim.alphaTarget(0);
          d.fx = null;
          d.fy = null;
        })
    );

  const label = g
    .append('g')
    .selectAll('text')
    .data(nodes)
    .enter()
    .append('text')
    .text((d) => d.name)
    .attr('font-size', (d) => (d.type === 'tool' || d.type === 'build' ? 10 : 9))
    .attr('fill', '#94a3b8')
    .attr('dx', (d) => radiusFor(d) + 3)
    .attr('dy', 3);

  node.on('mouseover', (event, d) => {
    highlightedNodeId = d.id;
    const connected = connectedIndex.get(d.id) || new Set([d.id]);

    node.classed('dimmed', (n) => !connected.has(n.id));
    label.classed('dimmed', (n) => !connected.has(n.id));
    queueDraw();

    const tooltip = document.getElementById('graphTooltip');
    if (!tooltip) return;
    tooltip.innerHTML = `<div class="font-semibold text-white">${d.name}</div><div class="text-slate-400 text-xs">${d.data.type}</div><div class="text-xs mt-1">${connCount.get(d.id) || 0} connections</div>`;
    tooltip.classList.remove('hidden');
    tooltip.style.left = `${event.offsetX + 15}px`;
    tooltip.style.top = `${event.offsetY - 10}px`;
  });

  node.on('mouseout', () => {
    highlightedNodeId = null;
    node.classed('dimmed', false);
    label.classed('dimmed', false);
    queueDraw();
    document.getElementById('graphTooltip')?.classList.add('hidden');
  });

  node.on('click', (_event, d) => {
    app.detailElement = d.data;
  });

  sim = d3
    .forceSimulation(nodes)
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

  sim.on('tick', () => {
    node.attr('cx', (d) => d.x).attr('cy', (d) => d.y);
    label.attr('x', (d) => d.x).attr('y', (d) => d.y);
    queueDraw();
  });

  queueDraw();
  app.graphSim = sim;
  app.graphSvg = svg;
}

export function resetGraphZoom(app) {
  if (app.graphSvg && app.graphZoom) {
    app.graphSvg.transition().duration(500).call(app.graphZoom.transform, d3.zoomIdentity);
  }
}
