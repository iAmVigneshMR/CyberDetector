import { parseHost } from './domain.js';
import { finding } from './findings.js';
import { isShortener } from './shortener.js';

// TLDs with high abuse rates in phishing reports (Spamhaus / Interisle stats).
export const RISKY_TLDS = new Set([
  'zip', 'mov', 'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'icu', 'cyou', 'buzz', 'rest', 'quest', 'sbs',
  'cfd', 'click', 'link', 'country', 'kim', 'work', 'support', 'fit', 'loan', 'men', 'cam', 'monster', 'lol',
  'bond', 'pw', 'cc', 'su', 'ws', 'win', 'bid', 'date', 'review', 'party', 'trade', 'racing', 'download',
  'stream', 'accountant', 'cricket', 'science', 'faith', 'gdn', 'vip', 'shop', 'online', 'site', 'live', 'store',
]);

// Path-based shared services where anyone can publish a page or form.
const SHARED_PLATFORM_PATHS = [
  ['docs.google.com', /^\/forms\//], ['forms.gle', /./], ['sites.google.com', /./], ['storage.googleapis.com', /./],
  ['firebasestorage.googleapis.com', /./], ['forms.office.com', /./], ['drive.google.com', /./],
  ['dropbox.com', /^\/(s|scl)\//], ['1drv.ms', /./], ['ipfs.io', /^\/ipfs\//], ['cloudflare-ipfs.com', /./],
  ['jotform.com', /./], ['typeform.com', /./], ['canva.site', /./], ['wixsite.com', /./],
];

const URL_LURE_WORDS = /(login|log-in|signin|sign-in|verify|verification|secure|account|update|banking|confirm|wallet|webscr|authenticate|password|unlock|suspend|billing|invoice|recover|kyc)/gi;

function entropy(s) {
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  return Object.values(freq).reduce((h, n) => h - (n / s.length) * Math.log2(n / s.length), 0);
}

/**
 * Structural analysis of a URL (no network access).
 * @returns {{url: URL, parsed: object, findings: object[]}}
 */
export function analyzeUrl(href) {
  const u = new URL(href);
  const p = parseHost(u.hostname);
  const out = [];

  if (p.isIP) {
    out.push(finding('ip-host', 'url', 'high', 'Uses a raw IP address instead of a domain name', `Host: ${u.hostname}. Legitimate services almost never ask you to log in on a bare IP.`));
  }

  if (u.username || u.password) {
    out.push(finding('userinfo', 'url', 'high', 'Hidden destination using "@" in the URL',
      `Everything before "@" (${decodeURIComponent(u.username)}) is ignored — the real site is ${u.hostname}.`));
  }

  if (u.port && !['80', '443'].includes(u.port)) {
    out.push(finding('odd-port', 'url', 'medium', `Non-standard port :${u.port}`, 'Phishing kits are often served from ad-hoc servers on unusual ports.'));
  }

  // Long URLs are normal for SSO / tracking links, so this is weak evidence at best.
  const len = href.length;
  if (len > 400) out.push(finding('very-long-url', 'url', 'low', `Very long URL (${len} characters)`, 'Long URLs can push the real domain out of view.'));

  const depth = p.subdomain ? p.subdomain.split('.').length : 0;
  if (depth >= 4) out.push(finding('deep-subdomain', 'url', 'medium', `Unusually many subdomains (${depth})`, `Host: ${u.hostname}`));
  else if (depth === 3) out.push(finding('many-subdomains', 'url', 'low', 'Several nested subdomains', `Host: ${u.hostname}`));

  const hyphens = (p.label.match(/-/g) || []).length;
  if (hyphens >= 3) out.push(finding('many-hyphens', 'url', 'medium', `Domain name contains ${hyphens} hyphens`, p.registrable));
  else if (hyphens === 2) out.push(finding('hyphens', 'url', 'low', 'Domain name contains multiple hyphens', p.registrable));

  const tld = p.suffix.split('.').pop();
  if (!p.isIP && RISKY_TLDS.has(tld)) {
    out.push(finding('risky-tld', 'url', 'low', `High-abuse top-level domain ".${tld}"`, 'This TLD is disproportionately used for phishing. Not proof of malice on its own.'));
  }

  if (p.hostingPlatform) {
    out.push(finding('free-hosting', 'url', 'low', `Hosted on a free/shared platform (${p.hostingPlatform})`,
      'Anyone can publish here in minutes; brand logins on these hosts are a common phishing pattern.'));
  } else {
    const shared = SHARED_PLATFORM_PATHS.find(([h, re]) => (u.hostname === h || u.hostname.endsWith('.' + h)) && re.test(u.pathname));
    if (shared) out.push(finding('shared-platform', 'url', 'low', `User-published content on ${shared[0]}`, 'Forms and documents on shared platforms are frequently used to harvest credentials.'));
  }

  if (/^(xn--)?[a-z0-9-]+$/.test(p.label) && p.label.length >= 12) {
    const digits = (p.label.match(/\d/g) || []).length;
    if (entropy(p.label) > 3.7 && /[bcdfghjklmnpqrstvwxz]{5,}/.test(p.label)) {
      out.push(finding('random-domain', 'url', 'low', 'Random-looking domain name', `"${p.label}" resembles an auto-generated name.`));
    } else if (digits >= 5) {
      out.push(finding('digit-domain', 'url', 'low', 'Domain name contains many digits', p.label));
    }
  }

  // Lure words only matter in the HOSTNAME ("secure-login-verify.com"); in the path
  // (/login, /account/signin) they are on every legitimate login page.
  const pathAndQuery = decodeSafe(u.pathname + u.search);
  const hostPart = `${p.subdomain} ${p.label}`.toLowerCase();
  const hostLures = [...new Set(hostPart.match(URL_LURE_WORDS) || [])];
  if (!p.isIP && hostLures.length >= 2) out.push(finding('host-lure-words', 'url', 'medium', 'Credential-related words in the domain name', `${hostLures.join(', ')} in ${p.host}`));
  else if (!p.isIP && hostLures.length === 1 && !p.subdomain.split('.').includes(hostLures[0])) {
    // "login.example.com" is normal; "example-login.com" is not.
    out.push(finding('host-lure-word', 'url', 'low', 'Credential-related word in the domain name', `${hostLures[0]} in ${p.host}`));
  }

  const embedded = pathAndQuery.match(/(?:https?:\/\/|www\.)[^\s&#]+/i);
  if (embedded) {
    out.push(finding('embedded-url', 'url', 'info', 'Another URL embedded in the address (redirect parameter)', embedded[0].slice(0, 120)));
  }

  const encoded = (u.href.match(/%[0-9a-f]{2}/gi) || []).length;
  if (encoded > 15) out.push(finding('heavy-encoding', 'url', 'low', 'Heavily percent-encoded URL', `${encoded} encoded characters can hide the real content.`));

  if (u.protocol === 'data:' || u.protocol === 'blob:') {
    out.push(finding('data-url', 'url', 'high', 'Page loaded from a data:/blob: URL', 'Used to render phishing pages without any domain.'));
  }

  if (isShortener(u.hostname)) {
    out.push(finding('shortener', 'url', 'low', `Shortened link (${u.hostname})`, 'The final destination is hidden until the link is expanded.'));
  }

  return { url: u, parsed: p, findings: out };
}

function decodeSafe(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}
