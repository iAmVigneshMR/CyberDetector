import { ext, hasDataConsent } from './ext.js';
import { finding } from './findings.js';
import { officialBrandFor } from './brands.js';
import { sessionGet, sessionSet } from './storage.js';

// ------------------------------------------------------------------
// OpenPhish community feed — downloaded periodically and matched locally,
// so no browsing data leaves the browser.
// ------------------------------------------------------------------
// openphish.com/feed.txt now redirects to this GitHub copy (Community feed, updated every 12 h).
const OPENPHISH_FEEDS = [
  'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt',
  'https://openphish.com/feed.txt',
];
const FEED_MAX_AGE = 6 * 3600_000;

let feedCache = null; // { urls: Set, hosts: Set, updated }

function normalizeForMatch(href) {
  try {
    const u = new URL(href);
    return (u.hostname.replace(/^www\./, '') + u.pathname.replace(/\/+$/, '') + u.search).toLowerCase();
  } catch {
    return href.toLowerCase();
  }
}

export async function refreshOpenPhish(force = false) {
  const { openphish } = await ext.storage.local.get('openphish');
  if (!force && openphish && Date.now() - openphish.updated < FEED_MAX_AGE) return openphish;
  let lastErr;
  for (const src of OPENPHISH_FEEDS) {
    try {
      const res = await fetch(src, { credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(15000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const urls = (await res.text()).split('\n').map((s) => s.trim()).filter((s) => /^https?:\/\//.test(s));
      if (!urls.length) throw new Error('Empty feed');
      const data = { updated: Date.now(), source: src, urls };
      await ext.storage.local.set({ openphish: data });
      feedCache = null;
      return data;
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr || new Error('Feed unavailable');
}

async function loadFeed() {
  if (feedCache) return feedCache;
  let { openphish } = await ext.storage.local.get('openphish');
  if (!openphish) {
    try {
      openphish = await refreshOpenPhish(true);
    } catch {
      return null;
    }
  }
  const urls = new Set(openphish.urls.map(normalizeForMatch));
  const hosts = new Set();
  for (const raw of openphish.urls) {
    try {
      hosts.add(new URL(raw).hostname.replace(/^www\./, '').toLowerCase());
    } catch { /* ignore malformed lines */ }
  }
  feedCache = { urls, hosts, updated: openphish.updated, count: openphish.urls.length };
  return feedCache;
}

export async function feedStatus() {
  const { openphish } = await ext.storage.local.get('openphish');
  return openphish ? { updated: openphish.updated, count: openphish.urls.length, source: openphish.source } : null;
}

async function checkOpenPhish(href) {
  const feed = await loadFeed();
  if (!feed) return { source: 'OpenPhish', status: 'error', error: 'Feed not available' };
  const norm = normalizeForMatch(href);
  const noQuery = norm.split('?')[0];
  if (feed.urls.has(norm) || feed.urls.has(noQuery)) return { source: 'OpenPhish', status: 'listed', match: 'url' };
  const host = new URL(href).hostname.replace(/^www\./, '').toLowerCase();
  // Host-level matches are only meaningful when the host isn't a big shared service.
  if (feed.hosts.has(host) && !officialBrandFor(host)) return { source: 'OpenPhish', status: 'listed', match: 'host' };
  return { source: 'OpenPhish', status: 'clean' };
}

// ------------------------------------------------------------------
// Google Safe Browsing v4 Lookup API (requires an API key)
// ------------------------------------------------------------------
async function checkSafeBrowsing(href, key) {
  const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    signal: AbortSignal.timeout(6000),
    body: JSON.stringify({
      client: { clientId: 'cyberdetector-extension', clientVersion: ext.runtime.getManifest().version },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url: href }],
      },
    }),
  });
  if (!res.ok) throw new Error(`Safe Browsing HTTP ${res.status}`);
  const json = await res.json();
  if (json.matches?.length) {
    return { source: 'Google Safe Browsing', status: 'listed', threats: [...new Set(json.matches.map((m) => m.threatType))] };
  }
  return { source: 'Google Safe Browsing', status: 'clean' };
}

// ------------------------------------------------------------------
// PhishTank checkurl API (app key optional but strongly recommended)
// ------------------------------------------------------------------
async function checkPhishTank(href, key) {
  const body = new URLSearchParams({ url: href, format: 'json' });
  if (key) body.set('app_key', key);
  const res = await fetch('https://checkurl.phishtank.com/checkurl/', {
    method: 'POST',
    body,
    credentials: 'omit',
    signal: AbortSignal.timeout(6000),
  });
  if (!res.ok) throw new Error(`PhishTank HTTP ${res.status}`);
  const json = await res.json();
  const r = json.results || {};
  if (r.in_database && (r.valid === true || r.valid === 'true')) {
    return { source: 'PhishTank', status: 'listed', verified: r.verified, detail: r.phish_detail_page };
  }
  return { source: 'PhishTank', status: 'clean' };
}

/**
 * Query every enabled reputation source. Results are cached per URL for 30 minutes.
 * @returns {Promise<{checks: object[], findings: object[]}>}
 */
export async function checkReputation(href, settings) {
  const cacheKey = `rep:${href}`;
  const cached = await sessionGet(cacheKey);
  if (cached && Date.now() - cached.ts < 30 * 60_000) return cached.result;

  const jobs = [];
  if (settings.openPhish) jobs.push(checkOpenPhish(href));
  const share = (settings.gsbKey || settings.usePhishTank) && (await hasDataConsent('browsingActivity'));
  if (settings.gsbKey && share) jobs.push(checkSafeBrowsing(href, settings.gsbKey).catch((e) => ({ source: 'Google Safe Browsing', status: 'error', error: e.message })));
  if (settings.usePhishTank && share) jobs.push(checkPhishTank(href, settings.phishTankKey).catch((e) => ({ source: 'PhishTank', status: 'error', error: e.message })));

  const checks = await Promise.all(jobs);
  const findings = [];
  for (const c of checks) {
    if (c.status !== 'listed') continue;
    if (c.source === 'Google Safe Browsing') {
      findings.push(finding('gsb-listed', 'reputation', 'critical', 'Flagged by Google Safe Browsing', c.threats.join(', ').replace(/_/g, ' ').toLowerCase()));
    } else if (c.source === 'PhishTank') {
      findings.push(finding('phishtank-listed', 'reputation', 'critical', 'Listed as phishing on PhishTank', c.verified ? 'Verified by the community' : 'Reported, awaiting verification'));
    } else if (c.source === 'OpenPhish') {
      findings.push(c.match === 'url'
        ? finding('openphish-listed', 'reputation', 'critical', 'Listed in the OpenPhish phishing feed', 'This exact URL is a known phishing page.')
        : finding('openphish-host', 'reputation', 'high', 'Host appears in the OpenPhish phishing feed', 'Other phishing pages were reported on this host.'));
    }
  }
  const result = { checks, findings };
  await sessionSet(cacheKey, { ts: Date.now(), result });
  return result;
}

// ------------------------------------------------------------------
// Certificate Transparency — when was the first certificate for this
// domain issued? A proxy for domain age (opt-in, uses crt.sh).
// ------------------------------------------------------------------
export async function certificateFirstSeen(registrable) {
  if (!(await hasDataConsent('browsingActivity'))) return undefined;
  const key = `ct:${registrable}`;
  const { [key]: cached } = await ext.storage.local.get(key);
  if (cached && Date.now() - cached.ts < 24 * 3600_000) return cached.firstSeen;
  // crt.sh is frequently overloaded (502/503 HTML pages) — retry once.
  let rows;
  for (let attempt = 0; attempt < 2 && !rows; attempt++) {
    const res = await fetch(`https://crt.sh/?q=${encodeURIComponent(registrable)}&output=json`, {
      credentials: 'omit',
      signal: AbortSignal.timeout(12000),
    });
    if (res.ok && (res.headers.get('content-type') || '').includes('json')) rows = await res.json();
    else if (attempt === 1) throw new Error(`crt.sh HTTP ${res.status}`);
  }
  let first = null;
  for (const r of rows) {
    const t = Date.parse(r.not_before + 'Z');
    if (!Number.isNaN(t) && (first === null || t < first)) first = t;
  }
  await ext.storage.local.set({ [key]: { ts: Date.now(), firstSeen: first } });
  return first;
}
