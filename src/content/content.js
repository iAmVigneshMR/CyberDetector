// CyberDetector content script (classic script — content scripts can't be ES modules).
// Collects phishing signals from the page, extracts media, and renders the
// in-page warning banner / overlay inside a closed shadow root.
(() => {
  if (window.__cyberDetectorLoaded) return;
  window.__cyberDetectorLoaded = true;
  if (window.top !== window) return; // top frame only

  const ext = globalThis.browser ?? globalThis.chrome;

  // ---------------------------------------------------------------
  // Keyword lists (lowercase)
  // ---------------------------------------------------------------
  const KEYWORDS = {
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
  };

  const SHORTENERS = new Set(['bit.ly', 'bitly.com', 'j.mp', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'v.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 'bl.ink', 't.ly', 's.id', 'lnkd.in', 'shorte.st', 'adf.ly',
    'x.co', 'clck.ru', 'u.to', 'qrco.de', 'tiny.one', 'short.gy', 'surl.li', 'snip.ly', 'gg.gg', 'dub.sh', 'kutt.it', 'ouo.io']);

  const PAYMENT_SEL = [
    'input[autocomplete^="cc-"]', 'input[name*="card" i]', 'input[id*="card" i]', 'input[name*="cvv" i]', 'input[id*="cvv" i]',
    'input[name*="cvc" i]', 'input[id*="cvc" i]', 'input[placeholder*="card number" i]', 'input[name*="iban" i]',
    'input[name*="expir" i]', 'input[placeholder*="MM/YY" i]',
  ].join(',');
  const OTP_SEL = [
    'input[autocomplete="one-time-code"]', 'input[name*="otp" i]', 'input[id*="otp" i]', 'input[placeholder*="code" i]',
    'input[name*="2fa" i]', 'input[name*="mfa" i]', 'input[name*="verification" i]',
  ].join(',');

  const isVisible = (el) => {
    if (el.type === 'hidden') return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  };

  // ---------------------------------------------------------------
  // Page report
  // ---------------------------------------------------------------
  function collectForms() {
    const pw = [...document.querySelectorAll('input[type="password"]')].filter(isVisible);
    const pay = [...document.querySelectorAll(PAYMENT_SEL)].filter(isVisible);
    const otp = [...document.querySelectorAll(OTP_SEL)].filter((e) => isVisible(e) && e.type !== 'password');
    const sensitiveInputs = [...pw, ...pay, ...otp];
    const forms = new Set(sensitiveInputs.map((i) => i.form).filter(Boolean));

    const crossOriginActions = [];
    let insecureActions = 0;
    let mailtoOrScript = 0;
    for (const f of forms) {
      const raw = f.getAttribute('action');
      if (!raw) continue;
      const a = raw.trim().toLowerCase();
      if (a.startsWith('mailto:') || a.startsWith('javascript:')) { mailtoOrScript++; continue; }
      try {
        const u = new URL(raw, location.href);
        if (u.protocol === 'http:') insecureActions++;
        if (u.origin !== location.origin) crossOriginActions.push(u.hostname);
      } catch { /* ignore */ }
    }

    // Text around sensitive inputs (labels, headings, buttons) for brand impersonation checks.
    let formText = '';
    for (const input of sensitiveInputs.slice(0, 5)) {
      const box = input.form || input.closest('div,section,main') || input.parentElement;
      formText += ' ' + (box?.innerText || '').slice(0, 800) + ' ' + (input.placeholder || '');
    }

    return {
      counts: { password: pw.length, payment: pay.length, otp: otp.length, crossOriginActions, insecureActions, mailtoOrScript },
      formText: formText.slice(0, 4000),
    };
  }

  function scanKeywords(text) {
    const out = {};
    for (const [cat, list] of Object.entries(KEYWORDS)) {
      out[cat] = list.filter((k) => {
        if (k.length <= 4) return new RegExp(`\\b${k}\\b`).test(text);
        return text.includes(k);
      });
    }
    return out;
  }

  function collectLinks() {
    const anchors = document.querySelectorAll('a[href]');
    let nullLinks = 0;
    const shortLinks = new Set();
    for (const a of anchors) {
      const raw = a.getAttribute('href').trim();
      if (!raw || raw === '#' || /^javascript:\s*(void\(0\)|;)?\s*$/i.test(raw)) { nullLinks++; continue; }
      try {
        const u = new URL(raw, location.href);
        if (SHORTENERS.has(u.hostname.replace(/^www\./, ''))) shortLinks.add(u.href);
      } catch { /* ignore */ }
    }
    return { total: anchors.length, nullLinks, shortLinks: [...shortLinks].slice(0, 25) };
  }

  // ---------------------------------------------------------------
  // Advanced signals: AiTM login clones, browser-in-the-browser, ClickFix lures
  // ---------------------------------------------------------------
  const IDP_FINGERPRINTS = [
    { brand: 'Microsoft', dom: '#i0116, #i0118, input[name="loginfmt"], #idSIButton9, #lightbox, .ext-sign-in-box', res: /(aadcdn\.(msauth|msftauth)\.net|logincdn\.msauth\.net|aadcdn\.microsoftonline-p\.com|login\.live\.com\/Me\.htm)/i },
    { brand: 'Google', dom: '#identifierId, #identifierNext, #passwordNext, input[name="Passwd"]', res: /(ssl\.gstatic\.com\/accounts|accounts\.google\.com\/(_\/|ServiceLogin))/i },
    { brand: 'Okta', dom: '#okta-sign-in, #okta-signin-username, .okta-sign-in-header', res: /(ok\d+static\.oktacdn\.com|global\.oktacdn\.com)/i },
  ];
  function detectIdpClone() {
    let resources = [];
    try { resources = performance.getEntriesByType('resource').map((r) => r.name).slice(0, 400); } catch { /* ignore */ }
    for (const fp of IDP_FINGERPRINTS) {
      const evidence = [];
      const node = document.querySelector(fp.dom);
      if (node) evidence.push(`page structure (${node.id ? '#' + node.id : node.className || node.name})`);
      const res = resources.find((r) => fp.res.test(r));
      if (res) evidence.push(`loads ${new URL(res).hostname}`);
      if (evidence.length) return { brand: fp.brand, evidence };
    }
    return null;
  }

  const OFFICIAL_LOGIN_URL = /\bhttps?:\/\/(accounts\.google\.com|login\.microsoftonline\.com|login\.live\.com|appleid\.apple\.com|(www\.)?facebook\.com\/(login|dialog)|github\.com\/login|steamcommunity\.com\/openid|discord\.com\/(login|oauth2)|(www\.)?linkedin\.com\/(login|oauth)|x\.com\/i\/oauth2|api\.twitter\.com\/oauth)\S*/i;
  function detectBitB() {
    const candidates = [];
    const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(), i = 0; n && i < 4000; n = walker.nextNode(), i++) {
      if (OFFICIAL_LOGIN_URL.test(n.nodeValue) && !n.parentElement?.closest('a, script, style, code, pre')) candidates.push([n.parentElement, n.nodeValue.match(OFFICIAL_LOGIN_URL)[0]]);
    }
    for (const inp of document.querySelectorAll('input[readonly], input[disabled]')) {
      if (OFFICIAL_LOGIN_URL.test(inp.value)) candidates.push([inp, inp.value.match(OFFICIAL_LOGIN_URL)[0]]);
    }
    for (const [node, shownUrl] of candidates.slice(0, 20)) {
      let a = node;
      for (let d = 0; a && d < 8; d++, a = a.parentElement) {
        const pos = getComputedStyle(a).position;
        if (pos !== 'fixed' && pos !== 'absolute') continue;
        const r = a.getBoundingClientRect();
        if (r.width < 250 || r.height < 250) continue;
        const frame = a.querySelector('iframe');
        if (frame || a.querySelector('input[type="password"]')) {
          let frameHost = '';
          try { frameHost = frame ? new URL(frame.src, location.href).hostname : location.hostname; } catch { /* ignore */ }
          return { shownUrl: shownUrl.slice(0, 120), frameHost };
        }
      }
    }
    return null;
  }

  const RUN_KEYS = /(win(dows)?\s*(key|logo key)?\s*\+\s*r\b|⊞\s*\+?\s*r\b|press\s+(the\s+)?windows\s+(key|button)|run dialog|(press|then)\s+ctrl\s*\+\s*v|⌘\s*\+?\s*space.{0,40}terminal|open\s+(the\s+)?terminal.{0,60}(paste|cmd\s*\+\s*v))/i;
  const VERIFY_WORDS = /(verify you are (a )?human|i('| a)m not a robot|captcha|human verification|verification (steps|id|failed)|cloudflare|complete (the )?verification|prove you('| a)re human)/i;
  function detectClickFixLure(text) {
    const k = text.match(RUN_KEYS);
    const v = text.match(VERIFY_WORDS);
    return k && v ? [k[0], v[0]] : null;
  }

  function collectReport() {
    const bodyText = (document.body?.innerText || '').slice(0, 30000);
    const lower = bodyText.toLowerCase();
    const { counts, formText } = collectForms();
    const links = collectLinks();
    const logoAlts = [...document.querySelectorAll('img[alt]')]
      .filter((i) => /logo/i.test(i.alt + ' ' + i.className + ' ' + i.id))
      .map((i) => i.alt).filter(Boolean).slice(0, 8);
    const favicon = document.querySelector('link[rel~="icon"]')?.href || '';
    const seedPhrase = /(seed|recovery|secret|mnemonic)\s+(phrase|words)|12[- ]word|24[- ]word|private key/i.test(lower) &&
      (document.querySelectorAll('textarea').length > 0 || document.querySelectorAll('input[type="text"]').length >= 12);
    const mixedContent = location.protocol === 'https:'
      ? document.querySelectorAll('img[src^="http:"], script[src^="http:"], iframe[src^="http:"], link[href^="http:"][rel="stylesheet"]').length
      : 0;
    const disablesRightClick = !!document.body?.getAttribute('oncontextmenu')?.includes('return false');

    return {
      url: location.href,
      title: document.title.slice(0, 300),
      formText,
      logoAlts,
      favicon,
      forms: counts,
      keywords: scanKeywords(lower),
      links: { total: links.total, nullLinks: links.nullLinks },
      shortLinks: links.shortLinks,
      seedPhrase,
      mixedContent,
      disablesRightClick,
      idpClone: detectIdpClone(),
      bitb: detectBitB(),
      clickfixLure: detectClickFixLure(bodyText),
    };
  }

  let lastSignature = '';
  let lastLevel = null;

  async function report(force = false) {
    const r = collectReport();
    const sig = `${r.url}|${r.forms.password}|${r.forms.payment}|${r.forms.otp}|${r.seedPhrase}|${!!r.idpClone}|${!!r.bitb}|${!!r.clickfixLure}`;
    if (!force && sig === lastSignature) return;
    lastSignature = sig;
    try {
      const res = await ext.runtime.sendMessage({ type: 'pageReport', report: r });
      if (res?.ok && res.data) handleVerdict(res.data);
    } catch { /* extension reloaded */ }
  }

  // ---------------------------------------------------------------
  // Banner / overlay
  // ---------------------------------------------------------------
  const RANK = { safe: 0, unknown: 0, warning: 1, danger: 2 };
  let host = null;

  function dismissedKey() {
    return `cyberdetector-dismissed:${location.hostname}`;
  }

  function handleVerdict(v) {
    const escalated = RANK[v.level] > RANK[lastLevel ?? 'safe'];
    lastLevel = v.level;
    if (!v.showBanner) { removeBanner(); return; }
    let dismissed = null;
    try { dismissed = sessionStorage.getItem(dismissedKey()); } catch { /* sandboxed */ }
    if (dismissed && RANK[dismissed] >= RANK[v.level]) return;
    if (host && !escalated) return;
    showBanner(v);
  }

  let inertTarget = null;
  function removeBanner() {
    host?.remove();
    host = null;
    if (inertTarget) {
      inertTarget.inert = false;
      inertTarget = null;
    }
  }

  const el = (tag, attrs = {}, ...kids) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') n.className = v;
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v);
    }
    for (const k of kids) n.append(k);
    return n;
  };

  const BANNER_CSS = `
    :host { all: initial; }
    * { box-sizing: border-box; font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
    .bar { position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647; display: flex; gap: 12px; align-items: center;
      padding: 10px 16px; color: #fff; font-size: 14px; line-height: 1.4; box-shadow: 0 2px 12px rgba(0,0,0,.35); }
    .bar.warning { background: #b45309; }
    .bar.danger { background: #b91c1c; }
    .bar .msg { flex: 1; }
    .bar b { font-weight: 700; }
    .bar ul { margin: 4px 0 0; padding-left: 18px; font-size: 13px; opacity: .95; }
    button { font: 600 13px system-ui, sans-serif; border-radius: 6px; padding: 7px 12px; cursor: pointer; border: 1px solid rgba(255,255,255,.6);
      background: transparent; color: #fff; white-space: nowrap; }
    button.primary { background: #fff; color: #111; border-color: #fff; }
    .overlay { position: fixed; inset: 0; z-index: 2147483647; background: rgba(69,10,10,.96); color: #fff; display: flex;
      align-items: center; justify-content: center; padding: 24px; }
    .card { max-width: 560px; width: 100%; }
    .icon { font-size: 54px; line-height: 1; }
    h1 { font-size: 26px; margin: 12px 0 8px; }
    .host { font-family: ui-monospace, monospace; background: rgba(255,255,255,.12); padding: 2px 6px; border-radius: 4px; word-break: break-all; }
    .card ul { margin: 14px 0 22px; padding-left: 20px; font-size: 14px; line-height: 1.6; }
    .score { display: inline-block; margin-top: 6px; font-size: 13px; opacity: .85; }
    .actions { display: flex; gap: 10px; flex-wrap: wrap; }
    .link { background: none; border: none; text-decoration: underline; padding: 7px 4px; font-weight: 500; opacity: .85; }
  `;

  function showBanner(v) {
    removeBanner();
    host = el('cyberdetector-banner');
    const root = host.attachShadow({ mode: 'closed' });
    root.append(el('style', {}, BANNER_CSS));
    const reasons = v.findings.filter((f) => f.weight > 0).slice(0, 4);
    const list = el('ul', {}, ...reasons.map((f) => el('li', {}, f.title)));

    const dismiss = () => {
      try { sessionStorage.setItem(dismissedKey(), v.level); } catch { /* ignore */ }
      removeBanner();
    };
    const trust = async () => {
      if (!confirm(`Always trust ${v.registrable}? CyberDetector will stop warning about this site.`)) return;
      await ext.runtime.sendMessage({ type: 'trustSite', domain: v.registrable }).catch(() => {});
      removeBanner();
    };
    const leave = () => {
      if (history.length > 1) history.back();
      else location.replace('about:blank');
    };

    if (v.level === 'danger') {
      root.append(el('div', { class: 'overlay', role: 'alertdialog', 'aria-label': 'Phishing warning' },
        el('div', { class: 'card' },
          el('div', { class: 'icon' }, '⚠️'),
          el('h1', {}, 'Dangerous site — possible phishing'),
          el('div', {}, 'CyberDetector blocked ', el('span', { class: 'host' }, v.unicodeHost || location.hostname),
            ' because it shows strong signs of phishing. Do not enter passwords, codes or payment details.'),
          el('span', { class: 'score' }, `Risk score ${v.score}/100`),
          list,
          el('div', { class: 'actions' },
            el('button', { class: 'primary', onclick: leave }, '← Get me out of here'),
            el('button', { onclick: dismiss }, 'Continue anyway (not recommended)'),
            el('button', { class: 'link', onclick: trust }, 'I trust this site')),
        )));
    } else {
      root.append(el('div', { class: `bar ${v.level}`, role: 'alert' },
        el('div', { class: 'msg' }, el('b', {}, '⚠ CyberDetector: '), `This page looks suspicious (risk ${v.score}/100). Be careful entering personal information.`, list),
        el('button', { onclick: trust }, 'Trust site'),
        el('button', { class: 'primary', onclick: dismiss }, 'Dismiss')));
    }
    document.documentElement.append(host);
    if (v.level === 'danger') {
      // Block keyboard/mouse access to the phishing form underneath and start focus on the safe action.
      if (document.body && !document.body.inert) {
        inertTarget = document.body;
        inertTarget.inert = true;
      }
      root.querySelector('button.primary')?.focus();
    }
  }

  // ---------------------------------------------------------------
  // Media extraction + result markers
  // ---------------------------------------------------------------
  function collectMedia() {
    const items = [];
    const seen = new Set();
    const add = (src, type, extra = {}) => {
      if (!src || seen.has(src) || items.length >= 200) return;
      if (!/^(https?:|data:|blob:)/.test(src)) return;
      seen.add(src);
      items.push({ src, type, ...extra });
    };
    for (const img of document.images) {
      const w = img.naturalWidth, h = img.naturalHeight;
      if (img.complete && w && h && w < 80 && h < 80) continue; // icons / trackers
      add(img.currentSrc || img.src, 'image', { width: w, height: h, alt: (img.alt || '').slice(0, 80) });
    }
    for (const v of document.querySelectorAll('video')) {
      add(v.currentSrc || v.src || v.querySelector('source')?.src, 'video', { width: v.videoWidth, height: v.videoHeight, duration: Number.isFinite(v.duration) ? v.duration : null });
      if (v.poster) add(v.poster, 'image', { alt: 'video poster' });
    }
    for (const a of document.querySelectorAll('audio')) {
      add(a.currentSrc || a.src || a.querySelector('source')?.src, 'audio', { duration: Number.isFinite(a.duration) ? a.duration : null });
    }
    for (const m of document.querySelectorAll('meta[property="og:image"], meta[name="twitter:image"]')) add(m.content, 'image', { alt: 'social preview' });
    for (const m of document.querySelectorAll('meta[property="og:video"], meta[property="og:video:url"]')) add(m.content, 'video', { alt: 'social video' });
    for (const m of document.querySelectorAll('meta[property="og:audio"]')) add(m.content, 'audio');
    return items;
  }

  const markers = [];
  function markMedia(src, level, label) {
    const els = [...document.querySelectorAll('img, video, audio')].filter((m) => (m.currentSrc || m.src) === src || m.poster === src);
    const colors = { safe: '#16a34a', warning: '#d97706', danger: '#dc2626', unknown: '#64748b' };
    for (const target of els) {
      target.style.outline = `3px solid ${colors[level] || colors.unknown}`;
      target.style.outlineOffset = '-3px';
      const tag = el('cyberdetector-mark');
      const root = tag.attachShadow({ mode: 'closed' });
      root.append(el('style', {}, `:host{all:initial;position:absolute;z-index:2147483646;pointer-events:none}
        div{font:600 12px system-ui,sans-serif;color:#fff;padding:3px 8px;border-radius:0 0 6px 0;background:${colors[level] || colors.unknown};box-shadow:0 1px 4px rgba(0,0,0,.4)}`),
        el('div', {}, `🛡 ${label}`));
      document.documentElement.append(tag);
      markers.push({ tag, target });
    }
    positionMarkers();
  }
  function positionMarkers() {
    for (const { tag, target } of markers) {
      const r = target.getBoundingClientRect();
      tag.style.top = `${r.top + window.scrollY}px`;
      tag.style.left = `${r.left + window.scrollX}px`;
    }
  }
  window.addEventListener('resize', positionMarkers, { passive: true });

  // ---------------------------------------------------------------
  // Messages from popup / scan page
  // ---------------------------------------------------------------
  ext.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg?.type === 'collectMedia') {
      sendResponse({ ok: true, data: collectMedia() });
    } else if (msg?.type === 'markMedia') {
      markMedia(msg.src, msg.level, msg.label);
      sendResponse({ ok: true });
    } else if (msg?.type === 'rescanPage') {
      lastSignature = '';
      lastLevel = null;
      try { sessionStorage.removeItem(dismissedKey()); } catch { /* ignore */ }
      removeBanner();
      report(true);
      sendResponse({ ok: true });
    }
    return false;
  });

  // ---------------------------------------------------------------
  // Start: initial report + watch for login forms injected later (SPAs, modals)
  // ---------------------------------------------------------------
  report(true);
  let timer = null;
  let lastHref = location.href;
  new MutationObserver(() => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      if (location.href !== lastHref) {
        lastHref = location.href;
        lastLevel = null;
      }
      report();
    }, 1200);
  }).observe(document.documentElement, { childList: true, subtree: true });
})();
