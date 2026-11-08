import { ext } from './ext.js';

export const DEFAULT_SETTINGS = {
  // Protection
  autoScan: true,
  showBanner: true,
  bannerOnWarning: true,
  logFlagged: true,
  sensitivity: 'balanced', // relaxed | balanced | strict

  // Reputation sources
  openPhish: true, // local feed, no browsing data leaves the browser
  gsbKey: '', // Google Safe Browsing v4 Lookup API key
  usePhishTank: false,
  phishTankKey: '',
  ctLookup: false, // crt.sh certificate-transparency "domain first seen" lookup

  // Deepfake / AI-media detection
  aiProvider: 'none', // none | local | sightengine | hive | custom
  localEndpoint: 'http://127.0.0.1:8765/detect',
  localToken: '',
  sightengineUser: '',
  sightengineSecret: '',
  hiveKey: '',
  customEndpoint: '',
  customToken: '',
  mediaSendMode: 'upload', // upload | url
  maxMediaMB: 50,
  // Embedded content in scanned media (all local except the link checks, which use the reputation settings above)
  scanQr: true,
  scanOcr: true,
  checkEmbeddedLinks: true,

  // Advanced protections (each can be switched off in Settings)
  clickfixGuard: true, // block "paste this into Win+R" clipboard attacks
  clickfixWarnAnyCommand: false, // also warn when a page copies any terminal command
  passwordAlert: true, // warn when a protected password is typed on the wrong site
  aitmDetect: true, // cloned Microsoft/Google/Okta login pages (reverse-proxy phishing kits)
  bitbDetect: true, // fake in-page "browser popup" login windows
  deviceCodeWarn: true, // warnings on device-code login pages
  oauthConsentWarn: true, // highlight risky permissions on OAuth consent screens
  liveCallCheck: true, // live deepfake meter for browser video calls (local/custom detector)
  rdapLookup: false, // domain registration date via RDAP (sends suspicious domains to the registry)
  linkHover: 'risky', // off | risky | always
  downloadGuard: false, // needs the "downloads" permission, requested when enabled
  webmailScan: true, // Gmail / Outlook web: sender, link and attachment checks
  reportButtons: true, // "Report phishing" buttons in the popup

  trustedDomains: [],
};

export async function getSettings() {
  const { settings } = await ext.storage.local.get('settings');
  return { ...DEFAULT_SETTINGS, ...(settings || {}) };
}

export async function saveSettings(patch) {
  const current = await getSettings();
  const next = { ...current, ...patch };
  await ext.storage.local.set({ settings: next });
  return next;
}

// ---------- Protected passwords (password-reuse alarm) ----------
// Kept under their own key (not in settings) so the hashes are never broadcast to content scripts.
export async function getProtectedPasswords() {
  const { protectedPasswords } = await ext.storage.local.get('protectedPasswords');
  return protectedPasswords || [];
}
export async function setProtectedPasswords(list) {
  await ext.storage.local.set({ protectedPasswords: list });
}

// ---------- Scan history ----------
const HISTORY_MAX = 200;

export async function getHistory() {
  const { history } = await ext.storage.local.get('history');
  return history || [];
}

export async function addHistory(entry) {
  const history = await getHistory();
  const item = { id: crypto.randomUUID(), ts: Date.now(), ...entry };
  // Collapse repeated automatic detections of the same URL within an hour.
  if (item.source === 'auto') {
    const dupe = history.find(
      (h) => h.source === 'auto' && h.target === item.target && item.ts - h.ts < 3600_000,
    );
    if (dupe) return dupe;
  }
  history.unshift(item);
  await ext.storage.local.set({ history: history.slice(0, HISTORY_MAX) });
  return item;
}

export async function deleteHistory(id) {
  const history = await getHistory();
  await ext.storage.local.set({ history: history.filter((h) => h.id !== id) });
}

export async function clearHistory() {
  await ext.storage.local.set({ history: [] });
}

// ---------- Per-session (tab) state ----------
export async function sessionGet(key) {
  const res = await ext.storage.session.get(key);
  return res[key];
}
export async function sessionSet(key, value) {
  await ext.storage.session.set({ [key]: value });
}
export async function sessionRemove(keys) {
  await ext.storage.session.remove(keys);
}
