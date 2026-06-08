import { getRelationshipColor, getNodeType, getNodeTypeColor, cleanName } from './utils.js';

export function renderGraph(app) {
  const container = document.getElementById('graphContainer');
  if (!container) return;

  container.querySelectorAll('svg').forEach((s) => s.remove());
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
  const addNode = (spdxId) => {
    if (nodeIds.has(spdxId)) return;
    const el = app.elementMap.get(spdxId);
    if (!el) return;
    const type = getNodeType(el);
    if (!activeNodeTypes.has(type)) return;
    nodeIds.add(spdxId);
    nodes.push({ id: spdxId, name: cleanName(spdxId), type, data: el });
  };

  app.packages.forEach((p) => addNode(p.spdxId));
  app.files.forEach((f) => addNode(f.spdxId));
  app.tools.forEach((t) => addNode(t.spdxId));
  app.buildConfigs.forEach((c) => addNode(c.spdxId));
  if (app.buildInfo) addNode(app.buildInfo.spdxId);

  const links = [];
  app.relationships.forEach((rel) => {
    if (rel.relationshipType === 'hasConcludedLicense') return;
    if (!activeRelTypes.has(rel.relationshipType)) return;
    const targets = Array.isArray(rel.to) ? rel.to : [rel.to];
    targets.forEach((target) => {
      if (nodeIds.has(rel.from) && nodeIds.has(target)) {
        links.push({ source: rel.from, target, type: rel.relationshipType });
      }
    });
  });

  const connCount = new Map();
  links.forEach((link) => {
    connCount.set(link.source, (connCount.get(link.source) || 0) + 1);
    connCount.set(link.target, (connCount.get(link.target) || 0) + 1);
  });

  const svg = d3.select(container).append('svg').attr('width', width).attr('height', height);
  const defs = svg.append('defs');
  [...new Set(app.edgeColors.map((edge) => edge.color))].forEach((color) => {
    defs
      .append('marker')
      .attr('id', `arrow-${color.replace('#', '')}`)
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 20)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-4L10,0L0,4')
      .attr('fill', color)
      .attr('opacity', 0.6);
  });

  const g = svg.append('g');
  app.graphZoom = d3
    .zoom()
    .scaleExtent([0.05, 8])
    .on('zoom', (event) => g.attr('transform', event.transform));
  svg.call(app.graphZoom);

  const link = g
    .append('g')
    .selectAll('line')
    .data(links)
    .enter()
    .append('line')
    .attr('class', 'link')
    .attr('stroke', (d) => getRelationshipColor(d.type))
    .attr('stroke-opacity', 0.35)
    .attr('stroke-width', 1.2)
    .attr('marker-end', (d) => `url(#arrow-${getRelationshipColor(d.type).replace('#', '')})`);

  let sim;
  const node = g
    .append('g')
    .selectAll('circle')
    .data(nodes)
    .enter()
    .append('circle')
    .attr('class', 'node')
    .attr('r', (d) => Math.max(5, Math.min(16, 4 + (connCount.get(d.id) || 0) * 0.8)))
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
    .attr('dx', (d) => Math.max(7, 4 + (connCount.get(d.id) || 0) * 0.8) + 3)
    .attr('dy', 3);

  node.on('mouseover', (event, d) => {
    const connected = new Set([d.id]);
    links.forEach((linkData) => {
      const source = typeof linkData.source === 'object' ? linkData.source.id : linkData.source;
      const target = typeof linkData.target === 'object' ? linkData.target.id : linkData.target;
      if (source === d.id) connected.add(target);
      if (target === d.id) connected.add(source);
    });

    node.classed('dimmed', (n) => !connected.has(n.id));
    link.classed('dimmed', (linkData) => {
      const source = typeof linkData.source === 'object' ? linkData.source.id : linkData.source;
      const target = typeof linkData.target === 'object' ? linkData.target.id : linkData.target;
      return source !== d.id && target !== d.id;
    });
    label.classed('dimmed', (n) => !connected.has(n.id));

    const tooltip = document.getElementById('graphTooltip');
    if (!tooltip) return;
    tooltip.innerHTML = `<div class="font-semibold text-white">${d.name}</div><div class="text-slate-400 text-xs">${d.data.type}</div><div class="text-xs mt-1">${connCount.get(d.id) || 0} connections</div>`;
    tooltip.classList.remove('hidden');
    tooltip.style.left = `${event.offsetX + 15}px`;
    tooltip.style.top = `${event.offsetY - 10}px`;
  });

  node.on('mouseout', () => {
    node.classed('dimmed', false);
    link.classed('dimmed', false);
    label.classed('dimmed', false);
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
        .forceLink(links)
        .id((d) => d.id)
        .distance(60)
    )
    .force('charge', d3.forceManyBody().strength(-180))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force(
      'collision',
      d3.forceCollide().radius((d) => Math.max(7, 4 + (connCount.get(d.id) || 0) * 0.8) + 4)
    )
    .force('x', d3.forceX(width / 2).strength(0.05))
    .force('y', d3.forceY(height / 2).strength(0.05));

  sim.on('tick', () => {
    link
      .attr('x1', (d) => d.source.x)
      .attr('y1', (d) => d.source.y)
      .attr('x2', (d) => d.target.x)
      .attr('y2', (d) => d.target.y);
    node.attr('cx', (d) => d.x).attr('cy', (d) => d.y);
    label.attr('x', (d) => d.x).attr('y', (d) => d.y);
  });

  app.graphSim = sim;
  app.graphSvg = svg;
}

export function resetGraphZoom(app) {
  if (app.graphSvg && app.graphZoom) {
    app.graphSvg.transition().duration(500).call(app.graphZoom.transform, d3.zoomIdentity);
  }
}
