// Embedded-content analysis for scanned media: QR codes, text read from the
// image (OCR) and links hidden in metadata. Pure functions — the decoding itself
// (jsQR / Tesseract) lives in image-scan.js; this file turns the raw output into
// findings and a list of links to check with the phishing engine.
import { finding } from './findings.js';
import { computeVerdict } from './verdict.js';
import { BRANDS, brandMentions } from './brands.js';
import { RISKY_TLDS } from './url-analyzer.js';

// Same lists as content/content.js (content scripts can't import modules — keep them in sync),
// plus call-back / tech-support and crypto phrases that are typical of scam images.
export const KEYWORDS = {
  urgency: [
    'act now', 'immediately', 'urgent', 'within 24 hours', 'within 48 hours', 'expires today', 'final notice',
    'last warning', 'account suspended', 'account has been suspended', 'account will be locked', 'account locked',
    'account will be closed', 'account has been limited', 'unusual activity', 'unusual sign-in', 'suspicious activity',
    'unauthorized access', 'temporarily restricted', 'verify your account', 'confirm your identity', 'update your payment',
    'payment failed', 'payment declined', 'limited time', 'your password expires', 'mailbox is full', 'storage is full',
    'action required', 'immediate action', 'failure to comply', 'avoid suspension', 'deactivated',
  ],
  credential: [
    'enter your password', 'confirm your password', 're-enter your password', 'social security number', 'ssn',
    'date of birth', "mother's maiden name", 'card verification', 'cvv', 'atm pin', 'one-time password', 'otp',
    'verification code', 'billing information', 'kyc', 'pan card', 'aadhaar number', 'net banking', 'security question',
  ],
  reward: [
    'you have won', "you've won", 'congratulations', 'claim your prize', 'claim your reward', 'gift card', 'free iphone',
    'lottery', 'cash prize', 'selected winner', 'exclusive offer', 'tax refund', 'refund pending', 'unclaimed', 'airdrop',
    'double your', 'giveaway',
  ],
  threat: [
    'legal action', 'arrest warrant', 'police', 'penalty', 'lawsuit', 'court', 'debt collector', 'will be reported',
    'blocked permanently', 'permanently deleted',
  ],
  callback: [
    'call now', 'call us', 'call immediately', 'call this number', 'call the number', 'toll free', 'toll-free', 'helpline',
    'customer care', 'customer support', 'tech support', 'technical support', 'support team', 'contact support',
    'your computer is infected', 'virus detected', 'your computer has been locked', 'do not shut down', 'do not restart',
  ],
  quishing: ['scan the qr', 'scan this qr', 'scan the code', 'scan to verify', 'scan to login', 'scan to log in', 'scan to pay', 'scan to claim', 'scan qr code', 'scan the qr code'],
  seed: ['seed phrase', 'recovery phrase', 'secret recovery', 'mnemonic phrase', '12-word', '24-word', 'wallet phrase', 'private key'],
};

// "call Microsoft Support", "call our 24/7 helpdesk", "contact Norton technician at"
const CALL_PHRASE = /\b(?:call|dial|contact|ring|phone)\b[^.\n]{0,40}?\b(?:support|helpline|help ?desk|customer (?:care|service)|service desk|technicians?|department|agent)\b/i;

export function scanKeywords(text) {
  const lower = (text || '').toLowerCase();
  const out = {};
  for (const [cat, list] of Object.entries(KEYWORDS)) {
    out[cat] = list.filter((k) => (k.length <= 4 ? new RegExp(`\\b${k}\\b`).test(lower) : lower.includes(k)));
  }
  const call = CALL_PHRASE.exec(lower);
  if (call && !out.callback.some((k) => call[0].includes(k))) out.callback.push(call[0]);
  return out;
}

// ------------------------------------------------------------------
// Links
// ------------------------------------------------------------------
const COMMON_TLDS = new Set([
  'com', 'net', 'org', 'info', 'biz', 'io', 'co', 'app', 'dev', 'me', 'us', 'uk', 'in', 'de', 'fr', 'ru', 'cn', 'br', 'au',
  'ca', 'es', 'it', 'nl', 'jp', 'kr', 'id', 'ly', 'gl', 'to', 'tv', 'ai', 'gg', 'sh', 'eu', 'pl', 'ch', 'se', 'tr', 'vn',
  'pk', 'ng', 'za', 'mx', 'ar', 'gov', 'edu', 'mil', 'ms', 'is', 'st', 'at', 'be', 'cz', 'ro', 'ir', 'ph', 'my', 'sg', 'hk',
  'tw', 'ae', 'sa', 'bd', 'lk', 'np', 'ke', 'ua', 'kz', 'by', 'gle', 'page', 'bank', 'money', 'pay', 'help', 'network', 'tech',
  'cloud', 'web', 'website', 'host', 'space', 'email', 'digital', 'services', 'center', 'group', 'world', 'news', 'xxx',
  ...RISKY_TLDS,
]);

// Namespace / spec URLs that appear in metadata and are never interesting.
const BORING_HOSTS = /(^|\.)(ns\.adobe\.com|adobe\.com|w3\.org|purl\.org|iptc\.org|c2pa\.org|schema\.org|exif\.org|xmp\.org|ns\.google\.com|ns\.useplus\.org|apple\.com|creativecommons\.org|contentauthenticity\.org|contentcredentials\.org)$/i;

const SCHEME_URL = /\b(?:https?:\/\/|hxxps?:\/\/|www\.)[^\s<>"'`{}|\\^\]]+/gi;
// host.tld[/path] without a scheme — OCR text, QR plain text.
const BARE_DOMAIN = /(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?::\d{2,5})?(\/[^\s<>"'`]*)?(?![\w@-])/gi;

function clean(u) {
  return u.replace(/[.,;:!?)\]}'"»]+$/, '');
}

/**
 * Find links in free text.
 * @param {string} text
 * @param {{bareDomains?: boolean}} opts bareDomains: also accept "paypal-login.xyz/verify" (OCR / QR text)
 * @returns {string[]} normalized http(s) URLs, deduplicated, in order of appearance
 */
export function extractUrls(text, { bareDomains = false } = {}) {
  if (!text) return [];
  const s = String(text).replace(/\[\.\]|\(\.\)/g, '.');
  const found = [];
  for (const m of s.matchAll(SCHEME_URL)) found.push({ i: m.index, end: m.index + m[0].length, u: clean(m[0]) });
  if (bareDomains) {
    for (const m of s.matchAll(BARE_DOMAIN)) {
      if (found.some((f) => m.index >= f.i && m.index < f.end)) continue;
      const tld = m[2].toLowerCase();
      if (!COMMON_TLDS.has(tld)) continue;
      // "file.png", "v1.2", "e.g." style false positives
      if (/^\d+(\.\d+)+$/.test(m[1]) || /\.(png|jpe?g|gif|webp|pdf|docx?|xlsx?|exe|zip|js|txt)$/i.test(m[1]) && !m[3]) continue;
      found.push({ i: m.index, end: m.index + m[0].length, u: clean(m[0]) });
    }
  }
  const out = [];
  for (const { u } of found.sort((a, b) => a.i - b.i)) {
    const href = toHttpUrl(u);
    if (href && !out.includes(href)) out.push(href);
  }
  return out;
}

function toHttpUrl(raw) {
  let s = raw.replace(/^hxxp/i, 'http');
  if (!/^https?:\/\//i.test(s)) s = `https://${s}`;
  try {
    const u = new URL(s);
    if (!u.hostname.includes('.')) return null;
    return u.href;
  } catch {
    return null;
  }
}

export function isBoringHost(url) {
  try {
    return BORING_HOSTS.test(new URL(url).hostname);
  } catch {
    return true;
  }
}

// ------------------------------------------------------------------
// QR payloads
// ------------------------------------------------------------------
const CRYPTO_SCHEMES = /^(bitcoin|ethereum|litecoin|dogecoin|monero|solana|tron|bitcoincash|ripple|usdt|binance|bnb):/i;

/**
 * Classify a decoded QR / barcode payload.
 * @returns {{type: string, label: string, url?: string, detail?: string, raw: string}}
 */
export function parseQrPayload(raw) {
  const text = String(raw || '').trim();
  const lower = text.toLowerCase();
  if (/^(https?:\/\/|www\.)/i.test(text)) {
    const url = toHttpUrl(text.split(/\s/)[0]);
    if (url) return { type: 'url', label: 'Web link', url, raw: text };
  }
  if (lower.startsWith('wifi:')) {
    const ssid = /(?:^|;|:)S:((?:\\.|[^;])*)/i.exec(text.slice(5))?.[1]?.replace(/\\(.)/g, '$1') || '';
    const sec = /(?:^|;)T:([^;]*)/i.exec(text.slice(5))?.[1] || 'open';
    return { type: 'wifi', label: 'Wi-Fi network', detail: `Network "${ssid}" (${sec || 'open'})`, raw: '[Wi-Fi credentials hidden]' };
  }
  if (CRYPTO_SCHEMES.test(text)) {
    const [scheme, rest] = [text.split(':')[0].toLowerCase(), text.slice(text.indexOf(':') + 1)];
    const amount = /[?&](?:amount|value)=([^&]+)/i.exec(rest)?.[1];
    return { type: 'crypto', label: 'Crypto payment request', detail: `${scheme} address ${rest.split('?')[0]}${amount ? ` · amount ${decodeURIComponent(amount)}` : ''}`, raw: text };
  }
  if (lower.startsWith('otpauth:')) {
    let issuer = '';
    try { issuer = new URL(text).searchParams.get('issuer') || decodeURIComponent(new URL(text).pathname.slice(1)); } catch { /* ignore */ }
    return { type: 'otpauth', label: 'Two-factor (2FA) setup', detail: issuer ? `Account: ${issuer}` : '', raw: '[2FA secret hidden]' };
  }
  if (/^(tel|sms|smsto|mms|mmsto):/i.test(text)) {
    const num = text.replace(/^[a-z]+:/i, '').split(/[?:]/)[0];
    return { type: lower.startsWith('tel') ? 'tel' : 'sms', label: lower.startsWith('tel') ? 'Phone call' : 'Text message', detail: num, raw: text };
  }
  if (/^(mailto|matmsg):/i.test(text)) return { type: 'email', label: 'Email', detail: text.replace(/^mailto:/i, '').split('?')[0], raw: text };
  if (/^begin:vcard/i.test(text) || /^mecard:/i.test(text)) return { type: 'contact', label: 'Contact card', raw: text };
  if (/^(upi|paytm|phonepe|gpay):\/\//i.test(text)) {
    let detail = '';
    try { const u = new URL(text); detail = [u.searchParams.get('pn'), u.searchParams.get('pa'), u.searchParams.get('am') && `amount ${u.searchParams.get('am')}`].filter(Boolean).join(' · '); } catch { /* ignore */ }
    return { type: 'payment', label: 'UPI / payment request', detail, raw: text };
  }
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) return { type: 'app-link', label: 'App link', detail: text.split(':')[0], raw: text };
  const urls = extractUrls(text, { bareDomains: true });
  if (urls.length) return { type: 'url', label: 'Web link', url: urls[0], raw: text };
  return { type: 'text', label: 'Text', raw: text };
}

// ------------------------------------------------------------------
// Metadata links
// ------------------------------------------------------------------
/** Text fields of extractMetadata() output, as [source, value] pairs. */
export function metadataTextFields(meta) {
  const out = [];
  for (const [k, v] of Object.entries(meta?.exif || {})) if (typeof v === 'string') out.push([`EXIF ${k}`, v]);
  for (const [k, v] of Object.entries(meta?.xmpFields || {})) if (typeof v === 'string') out.push([`XMP ${k}`, v]);
  for (const [k, v] of Object.entries(meta?.text || {})) if (typeof v === 'string') out.push([`Embedded text: ${k}`, v]);
  return out;
}

/** Links hidden in metadata (explicit http(s)/www only — metadata is full of dotted identifiers). */
export function metadataLinks(meta) {
  const out = [];
  for (const [source, value] of metadataTextFields(meta)) {
    for (const url of extractUrls(value)) {
      if (!isBoringHost(url) && !out.some((l) => l.url === url)) out.push({ url, source });
    }
  }
  return out;
}

// ------------------------------------------------------------------
// OCR text
// ------------------------------------------------------------------
/** Drop OCR noise lines ("| ~ ee ;") that photos without text produce. */
export function cleanOcrText(text) {
  return String(text || '')
    .replace(/-\n(?=[a-z])/g, '')
    .split('\n')
    .map((l) => l.replace(/\s+/g, ' ').trim())
    .filter((l) => {
      const alnum = (l.match(/[\p{L}\p{N}]/gu) || []).length;
      const words = l.split(' ').filter((w) => /[\p{L}\p{N}]{2,}/u.test(w)).length;
      return l.length >= 3 && alnum / l.length >= 0.6 && words >= 1;
    })
    .join('\n');
}

const PHONE = /(?<![\w+])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?|\d{2,4}[\s.-])?\d{3,4}[\s.-]?\d{3,5}(?![\w])/g;
export function extractPhones(text) {
  const out = [];
  for (const m of String(text || '').matchAll(PHONE)) {
    const digits = m[0].replace(/\D/g, '');
    if (digits.length >= 8 && digits.length <= 15 && !/^(19|20)\d{6}$/.test(digits) && !out.includes(m[0].trim())) out.push(m[0].trim());
  }
  return out.slice(0, 5);
}

const WALLET = /\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|T[A-Za-z1-9]{33})\b/g;
export function extractWallets(text) {
  return [...new Set(String(text || '').match(WALLET) || [])].slice(0, 3);
}

function mentioned(text, name) {
  const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(^|[^\\p{L}\\p{N}])${esc}($|[^\\p{L}\\p{N}])`, 'iu').test(text);
}

export function brandsInText(text) {
  return BRANDS.filter((b) => brandMentions(b).some((n) => mentioned(text, n))).map((b) => b.name);
}

// ------------------------------------------------------------------
// Combined analysis
// ------------------------------------------------------------------
const LINK_SEVERITY = { danger: 'critical', warning: 'medium', safe: 'info', unknown: 'info' };
const LEVEL_RANK = { unknown: 0, safe: 1, warning: 2, danger: 3 };

/**
 * @param {object} input
 * @param {Array<{raw: string, format?: string}>} [input.qrCodes]  decoded codes
 * @param {{text: string, confidence: number}|null} [input.ocr]
 * @param {Array<{url: string, source: string}>} [input.metaLinks]
 * @param {Object<string, object>} [input.linkResults] url → scanUrl result ({level, score, reason}) or {error}
 * @param {string} [input.sensitivity]
 * @returns {{level, score, reason, findings, links, qr, text, phones, wallets, brands}}
 */
export function analyzeEmbeddedContent({ qrCodes = [], ocr = null, metaLinks = [], linkResults = {}, sensitivity = 'balanced' } = {}) {
  const findings = [];
  const links = []; // {url, source}
  const addLink = (url, source) => { if (url && !links.some((l) => l.url === url)) links.push({ url, source }); };

  // ---- QR codes ----
  const qr = qrCodes.map((c) => ({ ...parseQrPayload(c.raw), format: c.format || 'qr_code' }));
  for (const c of qr) {
    const name = c.format === 'qr_code' ? 'QR code' : `Barcode (${c.format})`;
    if (c.type === 'url') {
      addLink(c.url, name);
      if (c.url.startsWith('http://')) findings.push(finding('qr-http', 'qr', 'low', `${name} opens an unencrypted http:// link`, c.url));
    } else if (c.type === 'crypto') {
      findings.push(finding('qr-crypto', 'qr', 'medium', `${name} requests a cryptocurrency payment`, `${c.detail}. Crypto payments can't be reversed — "send crypto to receive more" offers are always scams.`));
    } else if (c.type === 'payment') {
      findings.push(finding('qr-payment', 'qr', 'low', `${name} starts a payment`, `${c.detail || c.raw}. Scanning a payment QR sends money — you never need to scan one to receive money.`));
    } else if (c.type === 'otpauth') {
      findings.push(finding('qr-otpauth', 'qr', 'low', `${name} adds a two-factor (2FA) account`, `${c.detail}. Only scan 2FA codes shown by the site you are setting up yourself.`));
    } else if (c.type === 'wifi') {
      findings.push(finding('qr-wifi', 'qr', 'info', `${name} joins a Wi-Fi network`, `${c.detail}. Rogue networks can intercept traffic — only join networks you recognise.`));
    } else if (c.type === 'tel' || c.type === 'sms') {
      findings.push(finding(`qr-${c.type}`, 'qr', 'low', `${name} ${c.type === 'tel' ? 'calls' : 'texts'} ${c.detail}`, 'Premium-rate and call-back scams use QR codes to dial numbers for you.'));
    } else if (c.type === 'app-link') {
      findings.push(finding('qr-app-link', 'qr', 'low', `${name} opens an app (${c.detail}://)`, c.raw.slice(0, 200)));
    } else {
      findings.push(finding(`qr-${c.type}`, 'qr', 'info', `${name}: ${c.label}`, c.raw.slice(0, 300)));
    }
  }

  // ---- Text in the image ----
  const text = cleanOcrText(ocr?.text);
  const qrText = qr.filter((c) => c.type === 'text').map((c) => c.raw).join('\n');
  const allText = [text, qrText].filter(Boolean).join('\n');
  const k = scanKeywords(allText);
  const phones = extractPhones(text);
  const wallets = extractWallets(allText);
  const brands = brandsInText(allText);
  for (const url of extractUrls(text, { bareDomains: true })) addLink(url, 'Text in image');

  if (allText) {
    const pressure = k.urgency.length + k.threat.length;
    const quote = (arr) => arr.slice(0, 6).map((s) => `"${s}"`).join(' · ');
    if (pressure >= 3) findings.push(finding('text-urgency-high', 'text', 'medium', 'Strong urgency / threat language in the image', quote([...k.urgency, ...k.threat])));
    else if (pressure >= 1) findings.push(finding('text-urgency', 'text', pressure >= 2 ? 'low' : 'info', 'Urgency / pressure language in the image', quote([...k.urgency, ...k.threat])));
    if (k.reward.length >= 2) findings.push(finding('text-reward', 'text', 'low', 'Prize / reward bait in the image', quote(k.reward)));
    if (k.credential.length) findings.push(finding('text-credential', 'text', k.credential.length >= 2 || pressure ? 'medium' : 'low', 'Image asks for passwords, codes or personal details', quote(k.credential)));
    if (k.seed.length) findings.push(finding('text-seed', 'text', 'high', 'Image mentions a wallet seed / recovery phrase or private key', `${quote(k.seed)}. No legitimate service ever asks for these.`));
    if (k.callback.length && (phones.length || pressure)) {
      findings.push(finding('text-callback', 'text', pressure || k.callback.length >= 2 ? 'high' : 'medium', 'Call-back / tech-support scam pattern',
        `${quote(k.callback)}${phones.length ? ` · number: ${phones.join(', ')}` : ''}. Scammers show fake alerts with a phone number so you call them.`));
    } else if (phones.length) {
      findings.push(finding('text-phone', 'text', 'info', 'Phone number in the image', phones.join(', ')));
    }
    if (wallets.length) {
      const bait = k.reward.length || /\b(send|double|giveaway|airdrop|bonus)\b/i.test(allText);
      findings.push(finding('text-wallet', 'text', bait ? 'high' : 'low', bait ? 'Crypto address combined with giveaway / "send to receive" text' : 'Crypto wallet address in the image', wallets.join(', ')));
    }
    if (k.quishing.length && (qr.length || pressure || k.credential.length)) {
      findings.push(finding('text-quishing', 'text', pressure || k.credential.length ? 'high' : 'medium', 'Asks you to scan a QR code to verify / log in / pay (quishing)',
        'QR phishing hides the real link so you can\'t inspect it before opening — and moves you to a phone without your desktop protections.'));
    }
    if (brands.length && (pressure || k.credential.length || k.quishing.length || k.reward.length)) {
      findings.push(finding('text-brand', 'text', 'medium', `Image presents itself as ${brands.slice(0, 2).join(' / ')} and pressures you to act`,
        `Check any link or number against ${brands[0]}'s official website instead of using the one in the image.`));
    } else if (brands.length) {
      findings.push(finding('text-brand-mention', 'text', 'info', `Mentions ${brands.slice(0, 3).join(', ')}`, ''));
    }
  }

  // ---- Metadata links ----
  for (const l of metaLinks) {
    addLink(l.url, l.source);
    findings.push(finding('meta-link', 'links', 'info', `Link hidden in metadata (${l.source})`, l.url));
  }

  // ---- Link verdicts from the phishing engine ----
  let worstLink = 'unknown';
  for (const l of links) {
    const r = linkResults[l.url];
    if (!r) continue;
    l.result = r;
    if (r.error) {
      findings.push(finding('link-error', 'links', 'info', `Could not check ${l.url}`, r.error));
      continue;
    }
    if (LEVEL_RANK[r.level] > LEVEL_RANK[worstLink]) worstLink = r.level;
    const sev = LINK_SEVERITY[r.level] || 'info';
    const what = r.level === 'danger' ? 'leads to a dangerous site' : r.level === 'warning' ? 'leads to a suspicious site' : 'checked — no phishing indicators';
    findings.push(finding(`link-${r.level}`, 'links', sev, `${l.source} ${what}`, `${l.url}${r.finalUrl && r.finalUrl !== l.url ? ` → ${r.finalUrl}` : ''}${r.level !== 'safe' && r.reason ? ` — ${r.reason}` : ''}`));
  }

  const v = computeVerdict(findings, { sensitivity });
  let level = v.level;
  if (LEVEL_RANK[worstLink] > LEVEL_RANK[level]) level = worstLink;
  const nothing = !qr.length && !allText && !links.length;
  if (nothing) level = 'unknown';
  const reason = nothing ? 'No QR codes, readable text or links found' : v.findings.find((f) => f.weight > 0)?.title || 'No scam indicators in embedded content';
  return { level, score: v.score, reason, findings: v.findings, links, qr, text, phones, wallets, brands, ocrConfidence: ocr?.confidence ?? null };
}
