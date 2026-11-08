import { toUnicode } from './punycode.js';

// Small subset of the Public Suffix List (ICANN multi-label suffixes).
// Good enough to find the registrable domain for the vast majority of sites
// without shipping the full 200 KB list.
const MULTI_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'ltd.uk', 'plc.uk', 'me.uk', 'net.uk', 'nhs.uk', 'police.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
  'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in', 'edu.in', 'res.in', 'firm.in', 'gen.in', 'ind.in', 'nic.in', 'bank.in', 'fin.in',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'co.nz', 'org.nz', 'net.nz', 'govt.nz',
  'co.za', 'org.za', 'gov.za',
  'com.mx', 'org.mx', 'gob.mx',
  'com.sg', 'edu.sg', 'gov.sg', 'com.my', 'com.ph', 'com.pk', 'com.ng', 'com.tr', 'com.tw', 'com.hk',
  'com.ar', 'com.co', 'com.vn', 'com.eg', 'com.sa', 'co.kr', 'or.kr', 'co.id', 'co.th', 'in.th',
  'co.il', 'ac.il', 'com.ua', 'com.bd', 'com.np', 'com.lk', 'co.ke', 'com.pe', 'com.ec',
]);

// Second-level labels that country registries commonly open for registration (xx.com.es, xx.org.et …).
const GENERIC_SLD = new Set(['com', 'net', 'org', 'co', 'gov', 'edu', 'ac', 'biz', 'gob', 'or', 'ne', 'go', 'mil', 'nom', 'ltd', 'plc', 'sch', 'gen', 'firm']);

// Platforms where every subdomain is a different, user-controlled site
// (PSL "private" section). Commonly abused to host phishing kits for free.
export const HOSTING_SUFFIXES = new Set([
  'github.io', 'gitlab.io', 'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev', 'web.app',
  'firebaseapp.com', 'herokuapp.com', 'glitch.me', 'repl.co', 'replit.app', 'replit.dev', 'onrender.com',
  'fly.dev', 'azurewebsites.net', 'blogspot.com', 'wordpress.com', 'wixsite.com', 'weebly.com',
  'square.site', 'webflow.io', '000webhostapp.com', 'ngrok-free.app', 'ngrok.io', 'ngrok.app',
  'trycloudflare.com', 'r2.dev', 'surge.sh', 'framer.app', 'framer.website', 'godaddysites.com',
  'mystrikingly.com', 'carrd.co', 'notion.site', 's3.amazonaws.com', 'appspot.com', 'cloudfront.net',
  'ipfs.io', 'dweb.link', 'translate.goog', 'lovable.app', 'bolt.host', 'webcindario.com', 'jimdosite.com',
  'yolasite.com',
]);

// Suffixes that only vetted organisations can register.
export const RESTRICTED_SUFFIXES = new Set(['bank.in', 'fin.in', 'gov.in', 'nic.in', 'gov', 'mil', 'edu', 'gov.uk', 'bank', 'gov.au']);

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function isIpHost(host) {
  return IPV4.test(host) || host.startsWith('[') || /^\d+$/.test(host) || /^0x[0-9a-f]+$/i.test(host);
}

/** localhost, private-network IPs and reserved dev TLDs — not useful (or noisy) to scan. */
export function isLocalHost(hostname) {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h === '::1' || /\.(localhost|local|test|internal|lan|home\.arpa)$/.test(h)) return true;
  const m = h.match(IPV4);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 127 || a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254) || a === 0;
}

/**
 * Split a hostname into its parts.
 * @returns {{host, unicodeHost, labels, suffix, registrable, label, unicodeLabel, subdomain, isIP, hostingPlatform}}
 */
export function parseHost(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  const unicodeHost = toUnicode(host);
  if (isIpHost(host)) {
    return { host, unicodeHost, labels: [host], suffix: '', registrable: host, label: host, unicodeLabel: host, subdomain: '', isIP: true, hostingPlatform: null };
  }
  const labels = host.split('.');
  let suffixLen = 1;
  let hostingPlatform = null;

  for (const hs of HOSTING_SUFFIXES) {
    if (host.endsWith('.' + hs)) {
      const n = hs.split('.').length;
      if (n > suffixLen) {
        suffixLen = n;
        hostingPlatform = hs;
      }
    }
  }
  if (!hostingPlatform && labels.length >= 3) {
    const last2 = labels.slice(-2).join('.');
    const [sld, tld] = labels.slice(-2);
    // Explicit list, plus the generic ccTLD pattern com.es / org.et / gov.ss / biz.id …
    if (MULTI_SUFFIXES.has(last2) || (tld.length === 2 && GENERIC_SLD.has(sld))) suffixLen = 2;
  }

  const suffix = labels.slice(-suffixLen).join('.');
  if (labels.length <= suffixLen) {
    return { host, unicodeHost, labels, suffix, registrable: host, label: labels[0], unicodeLabel: unicodeHost.split('.')[0], subdomain: '', isIP: false, hostingPlatform };
  }
  const label = labels[labels.length - suffixLen - 1];
  const registrable = `${label}.${suffix}`;
  const subdomain = labels.slice(0, labels.length - suffixLen - 1).join('.');
  const uLabels = unicodeHost.split('.');
  const unicodeLabel = uLabels[uLabels.length - suffixLen - 1] ?? label;
  return { host, unicodeHost, labels, suffix, registrable, label, unicodeLabel, subdomain, isIP: false, hostingPlatform };
}

export function normalizeUrlInput(input) {
  let s = String(input || '').trim();
  if (!s) throw new Error('Enter a URL');
  // Defang common obfuscation: hxxp://, example[.]com
  s = s.replace(/^hxxp/i, 'http').replace(/\[\.\]/g, '.').replace(/\(\.\)/g, '.');
  if (!/^[a-z][a-z0-9+.-]*:/i.test(s)) s = 'https://' + s;
  const u = new URL(s);
  if (!/^https?:$/.test(u.protocol)) throw new Error('Only http(s) URLs can be analyzed');
  return u.href;
}
