import { ext } from '../lib/ext.js';
import { analyze, analyzeManual, isTrusted } from '../lib/phishing.js';
import { expandUrl } from '../lib/shortener.js';
import { refreshOpenPhish, feedStatus } from '../lib/reputation.js';
import { summarizeSecurityInfo } from '../lib/connection.js';
import { LEVEL_META } from '../lib/verdict.js';
import { normalizeUrlInput, isLocalHost } from '../lib/domain.js';
import {
  getSettings, saveSettings, getHistory, addHistory, deleteHistory, clearHistory,
  sessionGet, sessionSet, sessionRemove, getProtectedPasswords, setProtectedPasswords,
} from '../lib/storage.js';
import { createRecord, checkTyped, protectedLengths } from '../lib/password-alert.js';
import { analyzeEmail } from '../lib/email-analyzer.js';
import { assessDownload } from '../lib/download-guard.js';
import { analyzeUrl } from '../lib/url-analyzer.js';
import { checkLookalike } from '../lib/typosquat.js';
import { computeVerdict } from '../lib/verdict.js';
import { isShortener } from '../lib/shortener.js';
import { detectAI } from '../lib/ai-detect.js';
import { parseHost } from '../lib/domain.js';

const isWeb = (url) => /^https?:\/\//i.test(url || '');

// ------------------------------------------------------------------
// Toolbar badge
// ------------------------------------------------------------------
async function setBadge(tabId, level, title) {
  const meta = LEVEL_META[level] || LEVEL_META.unknown;
  try {
    await ext.action.setBadgeText({ tabId, text: meta.badge });
    await ext.action.setBadgeBackgroundColor({ tabId, color: meta.color });
    ext.action.setBadgeTextColor?.({ tabId, color: '#ffffff' });
    await ext.action.setTitle({ tabId, title: `CyberDetector — ${meta.label}${title ? `: ${title}` : ''}` });
  } catch {
    /* tab closed */
  }
}

// ------------------------------------------------------------------
// Tab analysis
// ------------------------------------------------------------------
async function analyzeTab(tabId, url, page, { force = false } = {}) {
  const settings = await getSettings();
  if (!isWeb(url)) {
    await setBadge(tabId, 'unknown');
    return { url, level: 'unknown', score: 0, findings: [], reason: 'This page cannot be scanned' };
  }
  if (isLocalHost(new URL(url).hostname)) {
    await setBadge(tabId, 'unknown', 'local address');
    return { url, level: 'unknown', score: 0, findings: [], reason: 'Local / private network address — not scanned' };
  }
  if (!settings.autoScan && !force) {
    await setBadge(tabId, 'unknown', 'auto-scan is off');
    return { url, level: 'unknown', score: 0, findings: [], reason: 'Automatic scanning is disabled' };
  }

  const secEntry = await sessionGet(`sec:${tabId}`);
  const sec = secEntry && sameOrigin(secEntry.url, url) ? secEntry.info : null;
  const result = await analyze(url, settings, { page, sec });

  // A slower URL-only analysis must not overwrite a richer page analysis.
  // The read-compare-write runs under a per-tab lock so concurrent analyses can't interleave.
  const stored = await withTabLock(tabId, async () => {
    const existing = await sessionGet(`tab:${tabId}`);
    if (existing && existing.url === url && existing.hasPage && !result.hasPage) return existing;
    await sessionSet(`tab:${tabId}`, result);
    await setBadge(tabId, result.level, result.reason);
    return result;
  });
  if (stored !== result) return stored;

  if (settings.logFlagged && result.level !== 'safe' && result.hasPage) {
    await addHistory({
      type: 'page', source: 'auto', target: url, level: result.level, score: result.score,
      summary: result.reason, findings: result.findings.filter((f) => f.weight > 0).slice(0, 12),
    });
  }
  return result;
}

const tabLocks = new Map();
function withTabLock(tabId, fn) {
  const prev = tabLocks.get(tabId) || Promise.resolve();
  const next = prev.then(fn, fn);
  tabLocks.set(tabId, next.catch(() => {}));
  return next;
}

function sameOrigin(a, b) {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}

function bannerDecision(result, settings) {
  if (!settings.showBanner || result.trusted) return false;
  return result.level === 'danger' || (result.level === 'warning' && settings.bannerOnWarning);
}

// ------------------------------------------------------------------
// PhishTank rejects requests unless the User-Agent is "phishtank/<name>", and fetch()
// can't set User-Agent — so rewrite it for that one endpoint only.
// ------------------------------------------------------------------
async function setupHeaderRules() {
  await ext.declarativeNetRequest.updateSessionRules({
    removeRuleIds: [1],
    addRules: [{
      id: 1,
      priority: 1,
      action: { type: 'modifyHeaders', requestHeaders: [{ header: 'user-agent', operation: 'set', value: 'phishtank/cyberdetector-extension' }] },
      condition: { urlFilter: '|https://checkurl.phishtank.com/checkurl/', resourceTypes: ['xmlhttprequest', 'other'] },
    }],
  });
}
setupHeaderRules().catch(() => {});

// ------------------------------------------------------------------
// Firefox only: read TLS certificate details for top-level pages.
// ------------------------------------------------------------------
const browserNs = globalThis.browser;
if (browserNs?.webRequest?.getSecurityInfo) {
  browserNs.webRequest.onHeadersReceived.addListener(
    async (details) => {
      if (details.tabId < 0) return;
      try {
        const info = await browserNs.webRequest.getSecurityInfo(details.requestId, { certificateChain: false });
        await sessionSet(`sec:${details.tabId}`, { url: details.url, info: summarizeSecurityInfo(info) });
      } catch {
        /* ignore */
      }
    },
    { urls: ['https://*/*'], types: ['main_frame'] },
    ['blocking'],
  );
}

// ------------------------------------------------------------------
// Navigation events
// ------------------------------------------------------------------
ext.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (!changeInfo.url) return;
  if (!isWeb(changeInfo.url)) {
    setBadge(tabId, 'unknown');
    return;
  }
  // Quick URL-only verdict while the page loads; the content script refines it.
  analyzeTab(tabId, changeInfo.url, null).catch(() => {});
});

ext.tabs.onRemoved.addListener((tabId) => {
  sessionRemove([`tab:${tabId}`, `sec:${tabId}`, `page:${tabId}`]).catch(() => {});
});

// ------------------------------------------------------------------
// ClickFix: the clipboard hook must run in the PAGE world, so it is registered
// dynamically — only while the setting is on (nothing for pages to switch off).
// ------------------------------------------------------------------
const HOOK_ID = 'cd-clipboard-hook';
async function syncClipboardHook(settings) {
  try {
    await ext.scripting.unregisterContentScripts({ ids: [HOOK_ID] }).catch(() => {});
    if (!settings.clickfixGuard) return;
    await ext.scripting.registerContentScripts([{
      id: HOOK_ID,
      js: settings.clickfixWarnAnyCommand ? ['content/clipboard-warnany.js', 'content/clipboard-hook.js'] : ['content/clipboard-hook.js'],
      matches: ['http://*/*', 'https://*/*'],
      runAt: 'document_start',
      allFrames: true,
      world: 'MAIN',
      persistAcrossSessions: true,
    }]);
  } catch (e) {
    console.warn('CyberDetector: could not register clipboard hook', e);
  }
}

// ------------------------------------------------------------------
// Risky-download guard (optional "downloads" permission)
// ------------------------------------------------------------------
const handledDownloads = new Set();
let downloadsWired = false;
async function onDownload(item) {
  if (handledDownloads.has(item.id) || !item.filename || item.state === 'interrupted') return;
  const settings = await getSettings();
  if (!settings.downloadGuard) return;
  handledDownloads.add(item.id);
  let verdict = null;
  const [tab] = await ext.tabs.query({ active: true, lastFocusedWindow: true }).catch(() => []);
  if (tab?.id != null) verdict = await sessionGet(`tab:${tab.id}`);
  if (verdict && item.referrer && !sameOrigin(verdict.url, item.referrer)) verdict = null;
  const a = assessDownload(item, verdict);
  if (!a.risky) return;
  // Small files often finish before we can pause them — then we warn and offer to delete the file.
  const [now] = await ext.downloads.search({ id: item.id }).catch(() => []);
  const finished = (now || item).state === 'complete';
  if (!finished) await ext.downloads.pause(item.id).catch(() => {});
  const info = JSON.stringify({ name: a.name, reasons: a.reasons, url: item.finalUrl || item.url, finished });
  ext.tabs.create({ url: ext.runtime.getURL(`download/warning.html?id=${item.id}&info=${encodeURIComponent(info)}`) });
  addHistory({ type: 'page', source: 'auto', target: item.finalUrl || item.url, level: a.severity === 'high' ? 'danger' : 'warning', score: a.severity === 'high' ? 90 : 50, summary: `Risky download paused: ${a.name}`, findings: a.reasons.map((r) => ({ id: 'download', category: 'content', severity: a.severity, weight: 35, title: r })) }).catch(() => {});
}
async function wireDownloads() {
  if (downloadsWired || !ext.downloads?.onCreated) return;
  downloadsWired = true;
  ext.downloads.onCreated.addListener((item) => onDownload(item).catch(() => {}));
  ext.downloads.onChanged.addListener(async (delta) => {
    if (!delta.filename?.current) return;
    const [item] = await ext.downloads.search({ id: delta.id }).catch(() => []);
    if (item) onDownload(item).catch(() => {});
  });
}
wireDownloads();
ext.permissions.onAdded?.addListener(() => wireDownloads());

ext.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local' || !changes.settings) return;
  const o = changes.settings.oldValue || {};
  const n = changes.settings.newValue || {};
  if (o.clickfixGuard !== n.clickfixGuard || o.clickfixWarnAnyCommand !== n.clickfixWarnAnyCommand) getSettings().then(syncClipboardHook);
});

// ------------------------------------------------------------------
// Context menus
// ------------------------------------------------------------------
async function setupMenus() {
  await ext.contextMenus.removeAll();
  ext.contextMenus.create({ id: 'scan-media', title: 'Scan Media (deepfake / AI check)', contexts: ['image', 'video', 'audio'] });
  ext.contextMenus.create({ id: 'check-link', title: 'Check link for phishing', contexts: ['link'] });
  ext.contextMenus.create({ id: 'scan-page', title: 'Scan this page for phishing', contexts: ['page'] });
}

ext.contextMenus.onClicked.addListener(async (info, tab) => {
  const page = ext.runtime.getURL('scan/scan.html');
  const q = new URLSearchParams();
  if (info.menuItemId === 'scan-media') {
    q.set('mode', 'media');
    q.set('src', info.srcUrl || '');
    q.set('type', info.mediaType || 'image');
    if (info.pageUrl) q.set('page', info.pageUrl);
    if (tab?.id >= 0) q.set('tab', String(tab.id));
  } else if (info.menuItemId === 'check-link') {
    q.set('mode', 'url');
    q.set('url', info.linkUrl);
  } else if (info.menuItemId === 'scan-page') {
    q.set('mode', 'url');
    q.set('url', info.pageUrl);
  } else return;
  ext.tabs.create({ url: `${page}?${q}`, index: tab ? tab.index + 1 : undefined });
});

// ------------------------------------------------------------------
// Lifecycle
// ------------------------------------------------------------------
ext.runtime.onInstalled.addListener(async ({ reason }) => {
  await setupMenus();
  await syncClipboardHook(await getSettings());
  ext.alarms.create('feed-refresh', { periodInMinutes: 360 });
  refreshOpenPhish().catch(() => {});
  if (reason === 'install') {
    // Chrome doesn't inject content scripts into tabs that were already open.
    const tabs = await ext.tabs.query({ url: ['http://*/*', 'https://*/*'] });
    for (const t of tabs) {
      ext.scripting.executeScript({ target: { tabId: t.id }, files: ['content/content.js'] }).catch(() => {});
      ext.scripting.executeScript({ target: { tabId: t.id, allFrames: true }, files: ['content/guard.js'] }).catch(() => {});
    }
    ext.runtime.openOptionsPage();
  }
});

ext.runtime.onStartup.addListener(() => {
  setupMenus().catch(() => {});
  getSettings().then(syncClipboardHook).catch(() => {});
  refreshOpenPhish().catch(() => {});
});

ext.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'feed-refresh') refreshOpenPhish().catch(() => {});
});

// ------------------------------------------------------------------
// Messaging
// ------------------------------------------------------------------
const handlers = {
  async pageReport({ report }, sender) {
    const tabId = sender.tab?.id;
    if (tabId == null || sender.frameId !== 0) return null;
    await sessionSet(`page:${tabId}`, report);
    const settings = await getSettings();
    const result = await analyzeTab(tabId, report.url, report);
    return { ...result, showBanner: bannerDecision(result, settings) };
  },

  async getTabVerdict({ tabId, url }) {
    const cached = await sessionGet(`tab:${tabId}`);
    if (cached && cached.url === url) return cached;
    const page = await sessionGet(`page:${tabId}`);
    return analyzeTab(tabId, url, page?.url === url ? page : null);
  },

  async rescanTab({ tabId, url }) {
    await sessionRemove([`tab:${tabId}`, `rep:${url}`]);
    const page = await sessionGet(`page:${tabId}`);
    return analyzeTab(tabId, url, page?.url === url ? page : null, { force: true });
  },

  async scanUrl({ url, record = true }) {
    const href = normalizeUrlInput(url);
    const settings = await getSettings();
    const result = await analyzeManual(href, settings);
    if (record) {
      await addHistory({
        type: 'url', source: 'manual', target: href, level: result.level, score: result.score,
        summary: result.reason, findings: result.findings.slice(0, 20), finalUrl: result.expansion?.final,
      });
    }
    return result;
  },

  async expandUrl({ url }) {
    return expandUrl(normalizeUrlInput(url));
  },

  async trustSite({ domain, tabId }) {
    const s = await getSettings();
    if (!s.trustedDomains.includes(domain)) await saveSettings({ trustedDomains: [...s.trustedDomains, domain] });
    if (tabId != null) await sessionRemove(`tab:${tabId}`);
    return true;
  },

  async untrustSite({ domain }) {
    const s = await getSettings();
    await saveSettings({ trustedDomains: s.trustedDomains.filter((d) => d !== domain) });
    return true;
  },

  async isTrusted({ host }) {
    return isTrusted(host, await getSettings());
  },

  getHistory: () => getHistory(),
  addHistory: ({ entry }) => addHistory(entry),
  deleteHistory: ({ id }) => deleteHistory(id),
  clearHistory: () => clearHistory(),

  // ---- Advanced protections ----
  async forwardNotice({ notice }, sender) {
    if (sender.tab?.id == null) return false;
    await ext.tabs.sendMessage(sender.tab.id, { type: 'guardNotice', notice }, { frameId: 0 });
    return true;
  },

  async clickfixEvent({ event }, sender) {
    const tabId = sender.tab?.id;
    if (tabId != null) setBadge(tabId, 'danger', 'Blocked a ClickFix clipboard attack');
    await addHistory({
      type: 'page', source: 'auto', target: event.url || sender.url, level: 'danger', score: 95,
      summary: 'Blocked ClickFix clipboard attack',
      findings: [{ id: 'clickfix-blocked', category: 'content', severity: 'critical', weight: 70, title: 'Page tried to copy a malicious command', detail: `${event.reason}: ${event.text.slice(0, 200)}` }],
    });
    return true;
  },

  async pwLengths() {
    const s = await getSettings();
    return s.passwordAlert ? protectedLengths(await getProtectedPasswords()) : [];
  },
  async pwCheck({ value, host }) {
    const s = await getSettings();
    if (!s.passwordAlert || typeof value !== 'string' || !host) return null;
    return checkTyped(await getProtectedPasswords(), value, host);
  },
  async pwAllow({ id, host }) {
    const list = await getProtectedPasswords();
    const reg = parseHost(host).registrable;
    await setProtectedPasswords(list.map((r) => (r.id === id ? { ...r, domains: [...new Set([...r.domains, reg])] } : r)));
    return true;
  },
  async pwAdd({ label, password, domains }) {
    const rec = await createRecord(label, password, domains);
    await setProtectedPasswords([...(await getProtectedPasswords()), rec]);
    return { id: rec.id, label: rec.label, domains: rec.domains };
  },
  async pwList() {
    return (await getProtectedPasswords()).map(({ id, label, domains, created }) => ({ id, label, domains, created }));
  },
  async pwRemove({ id }) {
    await setProtectedPasswords((await getProtectedPasswords()).filter((r) => r.id !== id));
    return true;
  },

  async quickUrlCheck({ url }) {
    const s = await getSettings();
    const a = analyzeUrl(url);
    const lk = checkLookalike(a.parsed);
    const v = computeVerdict([...a.findings, ...lk.findings].filter((f) => f.id !== 'shortener'), { sensitivity: s.sensitivity, trusted: isTrusted(a.parsed.host, s) });
    return { level: v.level, reason: v.reason, shortener: isShortener(a.parsed.host) };
  },

  async analyzeEmail({ mail }) {
    return analyzeEmail(mail, await getSettings());
  },

  async liveChunk({ kind, b64 }) {
    const settings = await getSettings();
    if (!settings.liveCallCheck) throw new Error('Live call check is off in Settings');
    if (!['local', 'custom'].includes(settings.aiProvider)) throw new Error('Live check needs the Local detector (Settings → Deepfake detection)');
    const bin = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const blob = new Blob([bin], { type: kind === 'audio' ? 'audio/wav' : 'image/jpeg' });
    const r = await detectAI({ blob, src: '', mediaType: kind === 'audio' ? 'audio' : 'image', settings });
    return { score: r.score, provider: r.provider };
  },

  async downloadDecision({ id, keep }) {
    if (keep) await ext.downloads.resume(id);
    else {
      const [item] = await ext.downloads.search({ id }).catch(() => []);
      if (item?.state === 'complete') await ext.downloads.removeFile(id).catch(() => {});
      else await ext.downloads.cancel(id).catch(() => {});
      await ext.downloads.erase({ id }).catch(() => {});
    }
    return true;
  },

  refreshFeeds: () => refreshOpenPhish(true).then(() => feedStatus()),
  feedStatus: () => feedStatus(),
};

ext.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const fn = handlers[msg?.type];
  if (!fn) return false;
  // Only our own pages / content scripts can reach this listener (no externally_connectable).
  Promise.resolve()
    .then(() => fn(msg, sender))
    .then(
      (data) => sendResponse({ ok: true, data }),
      (err) => sendResponse({ ok: false, error: String(err?.message || err) }),
    );
  return true;
});
