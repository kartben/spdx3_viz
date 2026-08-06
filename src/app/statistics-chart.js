/* The Statistics tab's donut chart renderer. Split from statistics.js and
   loaded on demand (see renderRelationshipChart) so d3 stays out of the entry
   chunk: the mixin itself is imported at startup, but only opening the
   Statistics view pays for the chart code. */

import { select } from 'd3-selection';
import { pie as d3pie, arc as d3arc } from 'd3-shape';
// Side-effect import: grafts .transition() onto selections.
import 'd3-transition';

const countFmt = new Intl.NumberFormat();

function shortLabel(label, max = 20) {
  if (typeof label !== 'string') return '';
  return label.length > max ? `${label.slice(0, max - 3)}...` : label;
}

export function renderDonutChart({
  host,
  rows,
  total,
  centerLabel,
  centerColor,
  ariaLabel,
  defaultHint,
  hoverHint,
  titleForRow,
  onClick
}) {
  host.replaceChildren();
  if (!total || !rows.length) return;

  const rect = host.getBoundingClientRect();
  const width = Math.max(280, Math.round(rect.width || host.clientWidth || 420));
  const height = Math.max(280, Math.round(rect.height || host.clientHeight || 288));
  const radius = Math.min(width, height) * 0.42;
  const innerRadius = radius * 0.62;
  const cx = width / 2;
  const cy = height / 2;

  const svg = select(host)
    .append('svg')
    .attr('viewBox', `0 0 ${width} ${height}`)
    .attr('role', 'img')
    .attr('aria-label', ariaLabel)
    .style('width', '100%')
    .style('height', '100%');

  const filterId = `statsDonutGlow-${host.id || 'chart'}`;
  const defs = svg.append('defs');
  defs
    .append('filter')
    .attr('id', filterId)
    .append('feDropShadow')
    .attr('dx', 0)
    .attr('dy', 0)
    .attr('stdDeviation', 2.6)
    .attr('flood-color', '#020617')
    .attr('flood-opacity', 0.55);

  const g = svg.append('g').attr('transform', `translate(${cx},${cy})`);
  g.append('circle')
    .attr('r', innerRadius - 4)
    .attr('fill', '#0f172a')
    .attr('opacity', 0.72)
    .attr('stroke', centerColor)
    .attr('stroke-width', 1.5)
    .attr('stroke-opacity', 0.55);

  const title = g
    .append('text')
    .attr('text-anchor', 'middle')
    .attr('y', -14)
    .attr('fill', '#f8fafc')
    .attr('font-size', 15)
    .attr('font-weight', 700);
  const count = g
    .append('text')
    .attr('text-anchor', 'middle')
    .attr('y', 10)
    .attr('fill', '#e2e8f0')
    .attr('font-size', 22)
    .attr('font-weight', 800);
  const hint = g
    .append('text')
    .attr('text-anchor', 'middle')
    .attr('y', 30)
    .attr('fill', '#94a3b8')
    .attr('font-size', 11);

  const setCenter = (row = null) => {
    title.text(shortLabel(row?.label || centerLabel));
    count.text(countFmt.format(row?.count || total));
    hint.text(row ? hoverHint(row) : defaultHint);
  };
  setCenter();

  const pie = d3pie()
    .value((d) => d.count)
    .sort(null)
    .padAngle(0.012);
  const arc = d3arc().innerRadius(innerRadius).outerRadius(radius).cornerRadius(5);
  const hoverArc = d3arc()
    .innerRadius(innerRadius - 1)
    .outerRadius(radius + 7)
    .cornerRadius(6);

  const path = g
    .selectAll('path')
    .data(pie(rows))
    .join('path')
    .attr('d', arc)
    .attr('fill', (d) => d.data.color)
    .attr('stroke', '#1e293b')
    .attr('stroke-width', 2)
    .attr('opacity', 0.92)
    .attr('filter', `url(#${filterId})`)
    .style('cursor', onClick ? 'pointer' : 'default')
    .on('mouseenter', function (_event, d) {
      select(this).transition().duration(140).attr('d', hoverArc).attr('opacity', 1);
      setCenter(d.data);
    })
    .on('mouseleave', function () {
      select(this).transition().duration(140).attr('d', arc).attr('opacity', 0.92);
      setCenter();
    });

  if (onClick) path.on('click', (_event, d) => onClick(d.data));

  path.append('title').text((d) => titleForRow(d.data));
}
