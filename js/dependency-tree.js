import { DEPTH_COLORS } from './config.js';
import { cleanName } from './utils.js';

export function renderDependencyTree(app) {
  const container = document.getElementById('depTreeContainer');
  if (!container) return;
  container.querySelectorAll('svg').forEach((s) => s.remove());
  app._treeRoot = null;
  app._treeUpdate = null;

  const width = container.clientWidth;
  const height = container.clientHeight;
  if (!width || !height || !app.treeRoot || !globalThis.d3) return;

  const visited = new Set();
  const buildTree = (spdxId, depth) => {
    if (visited.has(spdxId) || depth > app.treeDepth) {
      return { name: cleanName(spdxId), id: spdxId, children: [], circular: visited.has(spdxId) };
    }
    visited.add(spdxId);
    const deps = app.depsOf(spdxId) || [];
    const children = deps.map((dep) => buildTree(dep, depth + 1));
    visited.delete(spdxId);
    return { name: cleanName(spdxId), id: spdxId, children };
  };

  const root = d3.hierarchy(buildTree(app.treeRoot, 0));
  root.x0 = height / 2;
  root.y0 = 0;

  const treeLayout = d3.tree().nodeSize([22, 180]);
  const svg = d3.select(container).append('svg').attr('width', width).attr('height', height);
  const gRoot = svg.append('g').attr('transform', `translate(80, ${height / 2})`);
  const zoom = d3
    .zoom()
    .scaleExtent([0.1, 5])
    .on('zoom', (event) => gRoot.attr('transform', event.transform));
  svg.call(zoom);

  const update = (source) => {
    const treeData = treeLayout(root);
    const nodes = treeData.descendants();
    const links = treeData.links();

    const node = gRoot.selectAll('g.node').data(nodes, (d) => `${d.data.id}-${d.depth}`);
    const nodeEnter = node
      .enter()
      .append('g')
      .attr('class', 'node')
      .attr('transform', `translate(${source.y0 || 0},${source.x0 || 0})`)
      .on('click', (_event, d) => {
        if (d.children) {
          d._children = d.children;
          d.children = null;
        } else {
          d.children = d._children;
          d._children = null;
        }
        update(d);
      });

    nodeEnter
      .append('circle')
      .attr('r', 5)
      .attr('fill', (d) =>
        d._children ? depthColor(d.depth) : d.children ? depthColor(d.depth) : '#1e293b'
      )
      .attr('stroke', (d) => depthColor(d.depth))
      .attr('stroke-width', 2);

    nodeEnter
      .append('text')
      .attr('dy', '.35em')
      .attr('x', (d) => (d.children || d._children ? -10 : 10))
      .attr('text-anchor', (d) => (d.children || d._children ? 'end' : 'start'))
      .text((d) => d.data.name)
      .attr('fill', (d) => (d.data.circular ? '#ef4444' : '#cbd5e1'))
      .attr('font-size', 11);

    const nodeUpdate = nodeEnter.merge(node);
    nodeUpdate
      .transition()
      .duration(300)
      .attr('transform', (d) => `translate(${d.y},${d.x})`);

    nodeUpdate
      .select('circle')
      .attr('fill', (d) =>
        d._children ? depthColor(d.depth) : d.children ? depthColor(d.depth) : '#1e293b'
      )
      .attr('stroke', (d) => depthColor(d.depth));

    node
      .exit()
      .transition()
      .duration(200)
      .attr('transform', `translate(${source.y},${source.x})`)
      .remove();

    const link = gRoot
      .selectAll('path.link')
      .data(links, (d) => `${d.target.data.id}-${d.target.depth}`);
    const linkEnter = link
      .enter()
      .insert('path', 'g')
      .attr('class', 'link')
      .attr('stroke', (d) => depthColor(d.source.depth))
      .attr('d', () => {
        const origin = { x: source.x0 || 0, y: source.y0 || 0 };
        return diagonal(origin, origin);
      });

    linkEnter
      .merge(link)
      .transition()
      .duration(300)
      .attr('d', (d) => diagonal(d.source, d.target))
      .attr('stroke', (d) => depthColor(d.source.depth));

    link
      .exit()
      .transition()
      .duration(200)
      .attr('d', () => {
        const origin = { x: source.x, y: source.y };
        return diagonal(origin, origin);
      })
      .remove();

    nodes.forEach((d) => {
      d.x0 = d.x;
      d.y0 = d.y;
    });
  };

  collapseAfterDepth(root, 2);
  update(root);

  app._treeRoot = root;
  app._treeUpdate = update;
}

export function expandAllTree(app) {
  if (!app._treeRoot || !app._treeUpdate) return;
  const expandAll = (node) => {
    if (node._children) {
      node.children = node._children;
      node._children = null;
    }
    if (node.children) node.children.forEach(expandAll);
  };
  expandAll(app._treeRoot);
  app._treeUpdate(app._treeRoot);
}

export function collapseAllTree(app) {
  if (!app._treeRoot || !app._treeUpdate) return;
  const collapseAll = (node) => {
    if (node.children) {
      node.children.forEach(collapseAll);
      if (node.depth > 0) {
        node._children = node.children;
        node.children = null;
      }
    }
  };
  collapseAll(app._treeRoot);
  app._treeUpdate(app._treeRoot);
}

function diagonal(source, target) {
  return `M ${source.y} ${source.x} C ${(source.y + target.y) / 2} ${source.x}, ${(source.y + target.y) / 2} ${target.x}, ${target.y} ${target.x}`;
}

function collapseAfterDepth(node, maxDepth) {
  if (node.children && node.depth >= maxDepth) {
    node._children = node.children;
    node.children = null;
  }
  if (node.children) node.children.forEach((child) => collapseAfterDepth(child, maxDepth));
  if (node._children) node._children.forEach((child) => collapseAfterDepth(child, maxDepth));
}

function depthColor(depth) {
  return DEPTH_COLORS[depth % DEPTH_COLORS.length];
}
