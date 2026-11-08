import { ext, send } from '../lib/ext.js';
import { h, gauge, levelPill, renderFindings, renderReputation, timeAgo, truncateMiddle, levelColor } from '../lib/ui.js';
import { LEVEL_META } from '../lib/verdict.js';
import { getSettings } from '../lib/storage.js';
import { providerConfigured } from '../lib/ai-detect.js';

const $ = (sel) => document.querySelector(sel);
const scanPage = (params) => ext.runtime.getURL(`scan/scan.html?${new URLSearchParams(params)}`);
const openTab = (url) => ext.tabs.create({ url }).then(() => window.close());

let currentTab = null;
let currentResult = null;

// ------------------------------------------------------------------
// Tabs
// ------------------------------------------------------------------
document.querySelectorAll('.tabs button').forEach((btn) =>
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tabs button').forEach((b) => b.classList.toggle('active', b === btn));
    document.querySelectorAll('.tab-panel').forEach((p) => p.classList.toggle('hidden', p.id !== `tab-${btn.dataset.tab}`));
    if (btn.dataset.tab === 'history') loadHistory();
  }));

$('#open-settings').addEventListener('click', () => ext.runtime.openOptionsPage().then(() => window.close()));

// ------------------------------------------------------------------
// This page
// ------------------------------------------------------------------
function renderVerdict(r) {
  const card = $('#verdict');
  card.className = `card verdict ${r.level}`;
  card.replaceChildren(
    gauge(r.score, r.level),
    h('div', { class: 'verdict-info' },
      levelPill(r.level, r.level === 'safe' && r.trusted ? 'Trusted' : undefined),
      h('div', { class: 'verdict-host' }, r.unicodeHost || r.host || truncateMiddle(r.url, 50)),
      r.unicodeHost && r.unicodeHost !== r.host ? h('div', { class: 'small mono muted' }, `punycode: ${r.host}`) : null,
      h('div', { class: 'verdict-reason' }, r.reason),
      r.officialBrand ? h('div', { class: 'small', style: { color: 'var(--safe)', marginTop: '4px' } }, `✓ Official ${r.officialBrand} domain`) : null,
      !r.hasPage && r.level !== 'unknown' ? h('div', { class: 'small muted' }, 'URL checks only — page content not analyzed yet.') : null,
    ),
  );
  $('#findings').replaceChildren(r.findings?.length ? renderFindings(r.findings) : h('p', { class: 'muted empty' }, r.level === 'unknown' ? '' : 'No issues found.'));
  $('#reputation').replaceChildren(renderReputation(r.reputation));
  if (r.connection && !r.connection.certAvailable && r.connection.https) {
    $('#reputation').append(h('p', { class: 'muted small' }, 'Certificate details are only readable in Firefox (browser API limitation). Enable "Certificate Transparency lookup" in Settings for domain-age checks.'));
  }
  const trustBtn = $('#trust');
  trustBtn.textContent = r.trusted ? 'Untrust site' : 'Trust site';
  trustBtn.disabled = r.level === 'unknown' || !r.registrable;
}

async function loadCurrent() {
  [currentTab] = await ext.tabs.query({ active: true, currentWindow: true });
  if (!currentTab?.url || !/^https?:/.test(currentTab.url)) {
    renderVerdict({ level: 'unknown', score: 0, url: currentTab?.url || '', host: 'Browser page', reason: 'Internal browser pages are not scanned.', findings: [] });
    $('#rescan').disabled = true;
    $('#full-report').disabled = true;
    $('#media-details').classList.add('hidden');
    return;
  }
  try {
    currentResult = await send({ type: 'getTabVerdict', tabId: currentTab.id, url: currentTab.url });
    renderVerdict(currentResult);
  } catch (e) {
    $('#verdict').replaceChildren(h('span', { class: 'error' }, e.message));
  }
}

$('#rescan').addEventListener('click', async () => {
  $('#verdict').replaceChildren(h('div', { class: 'row' }, h('span', { class: 'spinner' }), h('span', { class: 'muted' }, 'Re-scanning…')));
  try {
    await ext.tabs.sendMessage(currentTab.id, { type: 'rescanPage' }).catch(() => {});
    currentResult = await send({ type: 'rescanTab', tabId: currentTab.id, url: currentTab.url });
    renderVerdict(currentResult);
  } catch (e) {
    $('#verdict').replaceChildren(h('span', { class: 'error' }, e.message));
  }
});

$('#trust').addEventListener('click', async () => {
  if (!currentResult?.registrable) return;
  if (currentResult.trusted) await send({ type: 'untrustSite', domain: currentResult.registrable });
  else await send({ type: 'trustSite', domain: currentResult.registrable, tabId: currentTab.id });
  currentResult = await send({ type: 'rescanTab', tabId: currentTab.id, url: currentTab.url });
  renderVerdict(currentResult);
});

$('#full-report').addEventListener('click', () => openTab(scanPage({ mode: 'url', url: currentTab.url })));

// ------------------------------------------------------------------
// Report phishing
// ------------------------------------------------------------------
const REPORT = {
  gsb: (u) => ({ open: `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(u)}` }),
  microsoft: () => ({ open: 'https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site-guest', copy: true }),
  netcraft: () => ({ open: 'https://report.netcraft.com/report', copy: true }),
  apwg: (u) => ({ open: `mailto:reportphishing@apwg.org?subject=${encodeURIComponent('Phishing site report')}&body=${encodeURIComponent(`Phishing URL (defanged): ${defang(u)}\n\nReported with CyberDetector.`)}` }),
  india: () => ({ open: 'https://cybercrime.gov.in/', copy: true }),
  copy: () => ({ copy: true, defanged: true }),
};
const defang = (u) => u.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
document.querySelector('.report-links')?.addEventListener('click', async (e) => {
  const b = e.target.closest('button[data-report]');
  if (!b || !currentTab?.url) return;
  const r = REPORT[b.dataset.report](currentTab.url);
  if (r.copy) {
    await navigator.clipboard.writeText(r.defanged ? defang(currentTab.url) : currentTab.url).catch(() => {});
    $('#report-status').textContent = '✓ URL copied — paste it into the report form.';
  }
  if (r.open) ext.tabs.create({ url: r.open });
});

// ------------------------------------------------------------------
// Live deepfake check (video calls)
// ------------------------------------------------------------------
async function liveCheck(action) {
  const res = await ext.tabs.sendMessage(currentTab.id, { type: 'liveCheck', action }, { frameId: 0 });
  if (!res?.ok) throw new Error(res?.error || 'No response from the page — reload it and try again');
  return res.data;
}
function paintLive(running) {
  const b = $('#live-btn');
  b.classList.toggle('on', running);
  b.textContent = running ? '■ Stop live deepfake check' : '🎙 Start live deepfake check on this call';
}
$('#live-btn').addEventListener('click', async () => {
  try {
    const st = await liveCheck('status');
    paintLive((await liveCheck(st.running ? 'stop' : 'start')).running);
    $('#live-note').textContent = 'The meter appears at the bottom-left of the call page.';
  } catch (e) {
    $('#live-note').textContent = `⚠ ${e.message}`;
  }
});

// ------------------------------------------------------------------
// Media extractor
// ------------------------------------------------------------------
let mediaItems = [];
let mediaFilter = 'all';
const MEDIA_ICON = { image: '🖼', video: '🎞', audio: '🎵' };

async function collectMedia() {
  const ask = () => ext.tabs.sendMessage(currentTab.id, { type: 'collectMedia' });
  let res;
  try {
    res = await ask();
  } catch {
    // Content script missing (tab opened before install) — inject and retry.
    await ext.scripting.executeScript({ target: { tabId: currentTab.id }, files: ['content/content.js'] });
    res = await ask();
  }
  return res?.data || [];
}

function renderMedia() {
  const list = mediaItems.filter((m) => mediaFilter === 'all' || m.type === mediaFilter);
  $('#media-count').textContent = `(${mediaItems.length})`;
  if (!list.length) {
    $('#media-list').replaceChildren(h('p', { class: 'muted empty small' }, 'No media found.'));
    return;
  }
  $('#media-list').replaceChildren(...list.map((m) => {
    const thumb = m.type === 'image' && !m.src.startsWith('blob:')
      ? h('img', { class: 'media-thumb', src: m.src, alt: '', loading: 'lazy', referrerpolicy: 'no-referrer' })
      : h('div', { class: 'media-thumb' }, MEDIA_ICON[m.type]);
    const dims = m.width && m.height ? `${m.width}×${m.height}` : m.duration ? `${Math.round(m.duration)}s` : '';
    return h('div', { class: 'media-item' },
      thumb,
      h('div', { class: 'media-meta' },
        h('div', {}, `${m.type}${dims ? ' · ' + dims : ''}${m.alt ? ' · ' + m.alt : ''}`),
        h('div', { class: 'src', title: m.src }, m.src.startsWith('data:') ? 'inline data' : m.src)),
      h('button', {
        disabled: m.src.startsWith('blob:'),
        title: m.src.startsWith('blob:') ? 'Streamed media cannot be fetched — download and upload it instead' : 'Scan for AI/deepfake',
        onclick: () => openTab(scanPage({ mode: 'media', src: m.src, type: m.type, page: currentTab.url, tab: currentTab.id })),
      }, 'Scan'));
  }));
}

$('#media-details').addEventListener('toggle', async (e) => {
  if (!e.target.open || mediaItems.length) return;
  $('#media-list').replaceChildren(h('span', { class: 'spinner' }));
  try {
    mediaItems = await collectMedia();
    renderMedia();
  } catch (err) {
    $('#media-list').replaceChildren(h('p', { class: 'error small' }, `Could not read page media: ${err.message}`));
  }
});

$('#media-filters').addEventListener('click', (e) => {
  const b = e.target.closest('.chip');
  if (!b) return;
  mediaFilter = b.dataset.filter;
  document.querySelectorAll('#media-filters .chip').forEach((c) => c.classList.toggle('active', c === b));
  renderMedia();
});

// ------------------------------------------------------------------
// Manual scanners
// ------------------------------------------------------------------
$('#url-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = $('#url-input').value.trim();
  if (!url) return;
  const out = $('#url-result');
  out.replaceChildren(h('div', { class: 'row', style: { marginTop: '10px' } }, h('span', { class: 'spinner' }), h('span', { class: 'muted' }, 'Analyzing…')));
  try {
    const r = await send({ type: 'scanUrl', url });
    out.replaceChildren(h('div', { class: 'url-result' },
      h('div', { class: 'result-head' },
        gauge(r.score, r.level, { size: 64 }),
        h('div', { class: 'grow' },
          levelPill(r.level),
          h('div', { class: 'verdict-host' }, r.unicodeHost),
          r.expansion ? h('div', { class: 'small muted break' }, `Expands to: ${r.expansion.final}`) : null,
          h('div', { class: 'verdict-reason' }, r.reason))),
      renderFindings(r.findings, { includeInfo: false }),
      renderReputation(r.reputation),
      h('button', { onclick: () => openTab(scanPage({ mode: 'url', url: r.input })) }, 'Open full report')));
  } catch (err) {
    out.replaceChildren(h('p', { class: 'error' }, err.message));
  }
});

// Firefox closes the popup when a file picker opens, so uploads happen in the report page.
$('#upload-media').addEventListener('click', () => openTab(scanPage({ mode: 'upload' })));

$('#media-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const src = $('#media-input').value.trim();
  if (!src) return;
  openTab(scanPage({ mode: 'media', src, type: $('#media-type').value }));
});

// ------------------------------------------------------------------
// History
// ------------------------------------------------------------------
let historyFilter = 'all';

async function loadHistory() {
  const items = (await send({ type: 'getHistory' })).filter((i) => historyFilter === 'all' || i.type === historyFilter);
  const list = $('#history-list');
  if (!items.length) {
    list.replaceChildren(h('p', { class: 'muted empty' }, 'No scans yet.'));
    return;
  }
  list.replaceChildren(...items.map((i) => {
    const icon = i.type === 'media' ? MEDIA_ICON[i.mediaType] || '🖼' : i.type === 'url' ? '🔗' : '🌐';
    const scoreText = i.type === 'media' ? `${Math.round((i.probability ?? 0) * 100)}% AI` : `${i.score}/100`;
    return h('div', { class: 'history-item', onclick: () => openTab(scanPage({ mode: 'history', id: i.id })) },
      h('span', { class: 'dot', style: { background: levelColor(i.level) } }),
      h('div', { class: 'body' },
        h('div', { class: 'target', title: i.target }, `${icon} ${i.target}`),
        h('div', { class: 'sub' }, `${(LEVEL_META[i.level] || LEVEL_META.unknown).label} · ${i.summary || ''} · ${timeAgo(i.ts)}`)),
      h('span', { class: 'score' }, scoreText));
  }));
}

$('#history-filters').addEventListener('click', (e) => {
  const b = e.target.closest('.chip');
  if (!b) return;
  historyFilter = b.dataset.filter;
  document.querySelectorAll('#history-filters .chip').forEach((c) => c.classList.toggle('active', c === b));
  loadHistory();
});

$('#clear-history').addEventListener('click', async () => {
  if (!confirm('Delete all scan history?')) return;
  await send({ type: 'clearHistory' });
  loadHistory();
});

// ------------------------------------------------------------------
(async () => {
  await loadCurrent();
  const s = await getSettings();
  const web = /^https?:/.test(currentTab?.url || '');
  if (web && s.reportButtons) $('#report-details').classList.remove('hidden');
  if (web && s.liveCallCheck && ['local', 'custom'].includes(s.aiProvider)) {
    $('#live-row').classList.remove('hidden');
    liveCheck('status').then((r) => paintLive(r.running)).catch(() => {});
  }
  $('#ai-status').replaceChildren(providerConfigured(s)
    ? h('span', { style: { color: 'var(--safe)' } }, `✓ AI detection: ${s.aiProvider}`)
    : h('span', { class: 'muted' }, 'No AI-detection API configured — results use metadata & forensic heuristics only. ', h('a', { href: '#', onclick: (e) => { e.preventDefault(); ext.runtime.openOptionsPage(); } }, 'Configure')));
})();
