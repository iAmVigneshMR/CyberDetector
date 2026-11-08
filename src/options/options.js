import { ext, send, requestDataConsent } from '../lib/ext.js';
import { getSettings, saveSettings } from '../lib/storage.js';
import { h, timeAgo } from '../lib/ui.js';
import { localHealth } from '../lib/ai-detect.js';
import { auditList } from '../lib/ext-audit.js';

const $ = (s) => document.querySelector(s);
let savedTimer;

function flashSaved() {
  $('#saved').classList.add('show');
  clearTimeout(savedTimer);
  savedTimer = setTimeout(() => $('#saved').classList.remove('show'), 1200);
}

// Settings that send data to third parties → Firefox data-collection category.
const CONSENT = {
  gsbKey: (v) => (v ? 'browsingActivity' : null),
  usePhishTank: (v) => (v ? 'browsingActivity' : null),
  ctLookup: (v) => (v ? 'browsingActivity' : null),
  rdapLookup: (v) => (v ? 'browsingActivity' : null),
  aiProvider: (v) => (v !== 'none' && v !== 'local' ? 'websiteContent' : null),
};

// Settings that need an optional browser permission (requested when switched on).
const PERMS = { downloadGuard: ['downloads'] };

function showProvider(p) {
  document.querySelectorAll('.provider').forEach((el) => el.classList.toggle('active', el.dataset.provider === p));
}

async function init() {
  const s = await getSettings();

  for (const el of document.querySelectorAll('[data-key]')) {
    const key = el.dataset.key;
    if (el.type === 'checkbox') el.checked = !!s[key];
    else el.value = s[key] ?? '';
    const event = el.type === 'checkbox' || el.tagName === 'SELECT' ? 'change' : 'input';
    el.addEventListener(event, async () => {
      let value = el.type === 'checkbox' ? el.checked : el.value.trim();
      // Must be the first await: browsers only allow permission prompts inside the user gesture.
      if (PERMS[key] && value === true) {
        const granted = await ext.permissions.request({ permissions: PERMS[key] }).catch(() => false);
        if (!granted) {
          alert('The browser permission was not granted, so this option stays off.');
          el.checked = false;
          return;
        }
      }
      const category = CONSENT[key]?.(value);
      if (category && !(await requestDataConsent(category))) {
        alert('CyberDetector needs your permission to share this data with the selected service. The option was not enabled.');
        if (el.type === 'checkbox') el.checked = false;
        else el.value = key === 'aiProvider' ? 'none' : '';
        value = el.type === 'checkbox' ? false : el.value;
      }
      if (el.dataset.type === 'number') {
        value = Math.max(1, Math.min(500, parseInt(value, 10) || 50));
      }
      await saveSettings({ [key]: value });
      if (key === 'aiProvider') showProvider(value);
      flashSaved();
    });
  }
  showProvider(s.aiProvider);
  renderTrusted(s.trustedDomains);
  renderFeed();
}

function renderTrusted(list) {
  $('#trusted').replaceChildren(...(list.length ? list : []).map((d) =>
    h('li', {}, h('span', { class: 'mono' }, d), h('button', {
      class: 'ghost danger small',
      onclick: async () => {
        await send({ type: 'untrustSite', domain: d });
        renderTrusted((await getSettings()).trustedDomains);
      },
    }, 'Remove'))));
  if (!list.length) $('#trusted').append(h('li', { class: 'muted small' }, 'No trusted sites.'));
}

$('#trust-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  let d = $('#trust-input').value.trim().toLowerCase();
  if (!d) return;
  try {
    d = new URL(d.includes('://') ? d : `https://${d}`).hostname.replace(/^www\./, '');
  } catch {
    return;
  }
  await send({ type: 'trustSite', domain: d });
  $('#trust-input').value = '';
  renderTrusted((await getSettings()).trustedDomains);
});

async function renderFeed(status) {
  status ??= await send({ type: 'feedStatus' }).catch(() => null);
  $('#feed-status').textContent = status ? `${status.count.toLocaleString()} phishing URLs · updated ${timeAgo(status.updated)}.` : 'Not downloaded yet.';
}

$('#refresh-feed').addEventListener('click', async (e) => {
  e.target.disabled = true;
  $('#feed-status').textContent = 'Downloading…';
  try {
    renderFeed(await send({ type: 'refreshFeeds' }));
  } catch (err) {
    $('#feed-status').textContent = `Update failed: ${err.message}`;
  } finally {
    e.target.disabled = false;
  }
});

$('#export-history').addEventListener('click', async () => {
  const history = await send({ type: 'getHistory' });
  const blob = new Blob([JSON.stringify(history, null, 2)], { type: 'application/json' });
  const a = h('a', { href: URL.createObjectURL(blob), download: `cyberdetector-history-${new Date().toISOString().slice(0, 10)}.json` });
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
});

$('#clear-history').addEventListener('click', async () => {
  if (!confirm('Delete all scan history?')) return;
  await send({ type: 'clearHistory' });
  flashSaved();
});

$('#test-local').addEventListener('click', async () => {
  const out = $('#local-status');
  out.textContent = 'Connecting…';
  out.className = 'hint';
  try {
    const r = await localHealth(await getSettings());
    out.textContent = `✓ Connected — models: ${Object.values(r.models).join(', ')}${r.ffmpeg ? '' : ' (ffmpeg missing: video/audio disabled)'}`;
    out.className = 'hint ok-text';
  } catch (e) {
    out.textContent = `✕ ${/401|token/i.test(e.message) ? 'Wrong token' : 'Not reachable — start the server (see instructions above)'}: ${e.message}`;
    out.className = 'hint error';
  }
});

// ---------------- Protected passwords ----------------
async function renderPasswords() {
  const list = await send({ type: 'pwList' });
  $('#pw-list').replaceChildren(...list.map((p) =>
    h('li', {}, h('span', {}, h('b', {}, p.label), h('span', { class: 'muted small' }, `  ·  ${p.domains.join(', ')}`)),
      h('button', { class: 'ghost danger small', onclick: async () => { await send({ type: 'pwRemove', id: p.id }); renderPasswords(); } }, 'Remove'))));
  if (!list.length) $('#pw-list').append(h('li', { class: 'muted small' }, 'No protected passwords yet.'));
}
$('#pw-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const status = $('#pw-status');
  status.className = 'hint';
  status.textContent = 'Hashing…';
  try {
    const r = await send({ type: 'pwAdd', label: $('#pw-label').value, password: $('#pw-value').value, domains: $('#pw-domains').value.split(/[\s,]+/) });
    $('#pw-value').value = '';
    $('#pw-label').value = '';
    $('#pw-domains').value = '';
    status.textContent = `✓ "${r.label}" is protected on ${r.domains.join(', ')}`;
    status.className = 'hint ok-text';
    renderPasswords();
  } catch (err) {
    status.textContent = `✕ ${err.message}`;
    status.className = 'hint error';
  }
});

// ---------------- Extension auditor ----------------
$('#run-audit').addEventListener('click', async () => {
  const out = $('#audit');
  const granted = await ext.permissions.request({ permissions: ['management'] }).catch(() => false);
  if (!granted) {
    out.replaceChildren(h('p', { class: 'hint error' }, 'Permission not granted — the audit needs to list your installed extensions.'));
    return;
  }
  const items = auditList(await ext.management.getAll(), ext.runtime.id);
  if (!items.length) {
    out.replaceChildren(h('p', { class: 'hint' }, 'No other extensions installed.'));
    return;
  }
  out.replaceChildren(
    h('p', { class: 'hint' }, `${items.length} extension(s). ${items.filter((i) => i.level === 'danger').length} high-risk, ${items.filter((i) => i.level === 'warning').length} medium. High risk doesn't mean malicious — it means the extension could do a lot of damage if it were compromised.`),
    ...items.map((i) => h('div', { class: `audit-item ${i.level}` },
      h('div', { class: 'row' },
        h('b', { class: 'grow' }, `${i.name} `, h('span', { class: 'muted small' }, `v${i.version}${i.enabled ? '' : ' · disabled'}`)),
        h('span', { class: 'small' }, `risk ${i.score}`),
        i.enabled && i.mayDisable ? h('button', { class: 'small', onclick: async (e) => { await ext.management.setEnabled(i.id, false); e.target.textContent = 'Disabled'; e.target.disabled = true; } }, 'Disable') : null),
      i.reasons.length ? h('ul', {}, i.reasons.map((r) => h('li', {}, r))) : null)));
});
// Least privilege: give the "manage extensions" permission back when leaving Settings.
window.addEventListener('pagehide', () => { ext.permissions.remove({ permissions: ['management'] }).catch(() => {}); });

init();
renderPasswords();
