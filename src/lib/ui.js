// Tiny DOM helpers shared by popup, scan report and options pages.
// Everything is built with textContent — page titles, URLs and metadata are untrusted.
import { CATEGORY_LABEL } from './findings.js';
import { LEVEL_META } from './verdict.js';

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : String(c));
  }
  return el;
}

const SVG_NS = 'http://www.w3.org/2000/svg';
function svg(tag, attrs) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}

export function levelColor(level) {
  return (LEVEL_META[level] || LEVEL_META.unknown).color;
}

/** Circular gauge showing 0..100 */
export function gauge(value, level, { size = 88, caption = 'risk' } = {}) {
  const r = size / 2 - 7;
  const c = 2 * Math.PI * r;
  const root = svg('svg', { width: size, height: size, viewBox: `0 0 ${size} ${size}`, class: 'gauge', role: 'img', 'aria-label': `${caption} ${value}` });
  root.append(svg('circle', { cx: size / 2, cy: size / 2, r, fill: 'none', stroke: 'var(--track)', 'stroke-width': 7 }));
  root.append(svg('circle', {
    cx: size / 2, cy: size / 2, r, fill: 'none', stroke: levelColor(level), 'stroke-width': 7, 'stroke-linecap': 'round',
    'stroke-dasharray': `${(c * Math.max(0, Math.min(100, value))) / 100} ${c}`, transform: `rotate(-90 ${size / 2} ${size / 2})`,
  }));
  const t = svg('text', { x: '50%', y: '47%', 'text-anchor': 'middle', 'dominant-baseline': 'middle', class: 'gauge-value' });
  t.textContent = level === 'unknown' && !value ? '–' : String(Math.round(value));
  const cap = svg('text', { x: '50%', y: '68%', 'text-anchor': 'middle', class: 'gauge-caption' });
  cap.textContent = caption;
  root.append(t, cap);
  return root;
}

export function levelPill(level, text) {
  const meta = LEVEL_META[level] || LEVEL_META.unknown;
  return h('span', { class: `pill pill-${level}` }, text || meta.label);
}

export function severityChip(sev) {
  return h('span', { class: `sev sev-${sev}` }, sev);
}

/** Findings grouped by category. */
export function renderFindings(findings, { includeInfo = true } = {}) {
  const list = includeInfo ? findings : findings.filter((f) => f.weight > 0);
  if (!list.length) return h('p', { class: 'muted empty' }, 'No issues found.');
  const groups = {};
  for (const f of list) (groups[f.category] ||= []).push(f);
  const order = ['reputation', 'links', 'qr', 'text', 'domain', 'content', 'connection', 'url'];
  return h('div', { class: 'findings' },
    order.filter((c) => groups[c]).map((cat) =>
      h('div', { class: 'finding-group' },
        h('div', { class: 'group-title' }, CATEGORY_LABEL[cat] || cat),
        groups[cat].map((f) =>
          h('div', { class: `finding sev-border-${f.severity}` },
            h('div', { class: 'finding-head' }, severityChip(f.severity), h('span', { class: 'finding-title' }, f.title)),
            f.detail ? h('div', { class: 'finding-detail' }, f.detail) : null)))));
}

export function renderReputation(checks = []) {
  if (!checks.length) return h('p', { class: 'muted small' }, 'No reputation sources enabled — add them in Settings.');
  return h('div', { class: 'rep-list' }, checks.map((c) =>
    h('div', { class: `rep rep-${c.status}` },
      h('span', { class: 'rep-dot' }),
      h('span', { class: 'rep-src' }, c.source),
      h('span', { class: 'rep-status' }, c.status === 'listed' ? 'LISTED' : c.status === 'clean' ? 'not listed' : `error: ${c.error || 'unavailable'}`))));
}

export function timeAgo(ts) {
  const s = Math.round((Date.now() - ts) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  if (s < 7 * 86400) return `${Math.floor(s / 86400)}d ago`;
  return new Date(ts).toLocaleDateString();
}

export function truncateMiddle(s, n = 60) {
  if (!s || s.length <= n) return s || '';
  const half = Math.floor((n - 1) / 2);
  return `${s.slice(0, half)}…${s.slice(-half)}`;
}

export function fmtBytes(n) {
  if (n == null) return '';
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 ** 2).toFixed(1)} MB`;
}

export function fmtTime(sec) {
  if (!Number.isFinite(sec)) return '–';
  const m = Math.floor(sec / 60);
  const s = Math.floor(sec % 60);
  return `${m}:${String(s).padStart(2, '0')}`;
}
