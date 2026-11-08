// Audit the user's other installed extensions for risky permissions.
// Uses the optional "management" permission, requested only when the user runs the audit.

const PERM_RISK = {
  debugger: [4, 'Can control any tab like DevTools (read/modify everything)'],
  proxy: [3, 'Can route all your traffic through a proxy'],
  nativeMessaging: [3, 'Can talk to programs installed on your computer'],
  cookies: [3, 'Can read your login cookies (session hijacking)'],
  webRequest: [2, 'Can watch all network requests'],
  webRequestBlocking: [2, 'Can block or change network requests'],
  declarativeNetRequest: [1, 'Can block or redirect requests'],
  management: [2, 'Can disable or remove other extensions (including security tools)'],
  clipboardRead: [2, 'Can read your clipboard'],
  clipboardWrite: [1, 'Can change your clipboard'],
  history: [2, 'Can read your full browsing history'],
  privacy: [2, 'Can change browser privacy settings'],
  desktopCapture: [2, 'Can record your screen'],
  tabCapture: [2, 'Can record tab audio/video'],
  downloads: [1, 'Can start and open downloads'],
  scripting: [1, 'Can inject scripts into pages'],
  tabs: [1, 'Can see the URLs of all tabs'],
  webNavigation: [1, 'Can see every page you visit'],
  identity: [1, 'Can request sign-in tokens'],
  contentSettings: [1, 'Can change site permissions (camera, mic, pop-ups)'],
};
const ALL_SITES = /^(<all_urls>|\*:\/\/\*\/\*|https?:\/\/\*\/\*|\*:\/\/\*\/)$/;

export function scoreExtension(x, selfId) {
  if (x.id === selfId || x.type === 'theme') return null;
  const reasons = [];
  let score = 0;
  const perms = new Set([...(x.permissions || [])]);
  const hosts = x.hostPermissions || [];
  if (hosts.some((h) => ALL_SITES.test(h))) {
    score += 3;
    reasons.push('Can read and change data on ALL websites');
  } else if (hosts.length > 20) {
    score += 2;
    reasons.push(`Can read and change data on ${hosts.length} sites`);
  }
  for (const p of perms) {
    const r = PERM_RISK[p];
    if (r) { score += r[0]; reasons.push(r[1]); }
  }
  if (hosts.some((h) => ALL_SITES.test(h)) && perms.has('cookies')) { score += 2; reasons.push('All-site access + cookies = can steal logged-in sessions'); }
  if (x.installType === 'sideload') { score += 3; reasons.push('Installed by another program (sideloaded), not by you'); }
  else if (x.installType === 'development') reasons.push('Unpacked / developer-mode extension');
  else if (x.installType === 'other') { score += 1; reasons.push('Not installed from an official store'); }
  if (x.updateUrl && !/clients2\.google\.com|edge\.microsoft\.com|addons\.mozilla\.org/.test(x.updateUrl)) { score += 2; reasons.push(`Updates from a non-store server (${new URL(x.updateUrl).hostname})`); }
  const level = score >= 8 ? 'danger' : score >= 4 ? 'warning' : 'safe';
  return { id: x.id, name: x.name, version: x.version, enabled: x.enabled, installType: x.installType, score, level, reasons, mayDisable: x.mayDisable !== false };
}

export function auditList(all, selfId) {
  return all.map((x) => scoreExtension(x, selfId)).filter(Boolean).sort((a, b) => b.score - a.score);
}
