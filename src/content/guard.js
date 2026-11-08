// CyberDetector "guard" content script (classic script, runs in every frame).
// Each feature is gated by its own setting:
//   clickfixGuard     — alerts when the page-world clipboard hook blocks a malicious command
//   passwordAlert     — protected password typed on the wrong site
//   deviceCodeWarn    — device-code login pages (microsoft.com/devicelogin, github.com/login/device …)
//   oauthConsentWarn  — risky permissions on OAuth consent screens
//   linkHover         — real destination of links on hover
//   webmailScan       — Gmail / Outlook web message checks
//   liveCallCheck     — live deepfake meter for browser video calls (started from the popup)
(() => {
  if (window.__cyberDetectorGuard) return;
  window.__cyberDetectorGuard = true;
  const ext = globalThis.browser ?? globalThis.chrome;
  const isTop = window.top === window;
  const send = (msg) => ext.runtime.sendMessage(msg).then((r) => (r?.ok ? r.data : Promise.reject(new Error(r?.error || 'no response'))));

  const DEFAULTS = { clickfixGuard: true, passwordAlert: true, deviceCodeWarn: true, oauthConsentWarn: true, linkHover: 'risky', webmailScan: true, liveCallCheck: true };
  let S = { ...DEFAULTS };

  // ===================================================================
  // Notice UI (shadow DOM, top frame only; iframes forward via background)
  // ===================================================================
  const COLORS = { danger: '#b91c1c', warning: '#b45309', info: '#1d4ed8', safe: '#15803d' };
  const CSS = `
    :host{all:initial}
    *{box-sizing:border-box;font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
    .n{position:fixed;right:16px;top:16px;z-index:2147483647;width:min(420px,calc(100vw - 32px));color:#fff;border-radius:10px;
       box-shadow:0 8px 30px rgba(0,0,0,.4);padding:14px 16px;font-size:14px;line-height:1.45}
    .n.full{inset:0;width:auto;border-radius:0;display:flex;align-items:center;justify-content:center;background:rgba(69,10,10,.97)!important}
    .n.full .inner{max-width:560px}
    h3{margin:0 0 6px;font-size:16px} .full h3{font-size:24px}
    p{margin:4px 0} ul{margin:6px 0 0;padding-left:18px;font-size:13px}
    code{font:12px ui-monospace,monospace;background:rgba(0,0,0,.25);padding:6px 8px;border-radius:6px;display:block;white-space:pre-wrap;word-break:break-all;max-height:110px;overflow:auto;margin-top:6px}
    .a{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
    button{font:600 13px system-ui,sans-serif;border-radius:6px;padding:6px 12px;cursor:pointer;border:1px solid rgba(255,255,255,.6);background:transparent;color:#fff}
    button.p{background:#fff;color:#111;border-color:#fff}
    .x{position:absolute;right:8px;top:6px;border:none;font-size:18px;padding:2px 6px}`;
  const shown = new Map();

  function el(tag, attrs = {}, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') n.className = v;
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v);
    }
    for (const k of kids.flat()) if (k != null) n.append(k);
    return n;
  }

  function showNotice(n) {
    if (!isTop) {
      ext.runtime.sendMessage({ type: 'forwardNotice', notice: n }).catch(() => {});
      return;
    }
    renderNotice(n);
  }

  function renderNotice(n) {
    const key = n.key || n.kind;
    shown.get(key)?.remove();
    const host = el('cyberdetector-notice');
    const root = host.attachShadow({ mode: 'closed' });
    const close = () => { host.remove(); shown.delete(key); if (n.full && document.body) document.body.inert = false; };
    const actions = (ACTIONS[n.kind] || (() => []))(n, close);
    const box = el('div', { class: `n${n.full ? ' full' : ''}`, role: 'alert', style: `background:${COLORS[n.level] || COLORS.info}` },
      el('div', { class: 'inner' },
        el('h3', {}, n.title),
        n.body ? el('p', {}, n.body) : null,
        n.code ? el('code', {}, n.code) : null,
        n.list?.length ? el('ul', {}, n.list.map((x) => el('li', {}, x))) : null,
        el('div', { class: 'a' }, actions.length ? actions : el('button', { class: 'p', onclick: close }, 'OK'))),
      n.full ? null : el('button', { class: 'x', 'aria-label': 'Close', onclick: close }, '×'));
    root.append(el('style', {}, CSS), box);
    document.documentElement.append(host);
    shown.set(key, host);
    if (n.full && document.body) { document.body.inert = true; root.querySelector('button.p')?.focus(); }
    if (n.timeout) setTimeout(close, n.timeout);
  }

  // Per-kind buttons (notices are plain data so they can be forwarded from iframes)
  const ACTIONS = {
    password: (n, close) => [
      el('button', { class: 'p', onclick: () => { close(); if (history.length > 1) history.back(); else location.replace('about:blank'); } }, '← Leave this site'),
      el('button', { onclick: async () => {
        if (!confirm(`Is ${n.data.host} really a legitimate place to use your "${n.data.label}" password?`)) return;
        await send({ type: 'pwAllow', id: n.data.id, host: n.data.host }).catch(() => {});
        unblockForms(); close();
      } }, 'This site is legitimate'),
    ],
    clickfix: (n, close) => [el('button', { class: 'p', onclick: close }, 'Got it — I won\'t paste anything')],
  };

  // ===================================================================
  // 1. ClickFix — events from the page-world clipboard hook
  // ===================================================================
  window.addEventListener('cyberdetector:clipboard', (e) => {
    if (!S.clickfixGuard) return;
    let d;
    try { d = JSON.parse(e.detail); } catch { return; }
    if (d.action === 'blocked') {
      showNotice({
        kind: 'clickfix', key: 'clickfix', level: 'danger', full: true,
        title: '⛔ Blocked a "paste and run" attack (ClickFix)',
        body: 'This page tried to put a hidden command on your clipboard. Pages that ask you to press Win+R, Ctrl+V or open Terminal to "verify you are human" are installing malware. CyberDetector replaced the command with a harmless warning.',
        code: d.text,
        list: [`Why: ${d.reason}`, 'Do not press Win+R, paste, or run anything this page tells you to.'],
      });
      ext.runtime.sendMessage({ type: 'clickfixEvent', event: d }).catch(() => {});
    } else if (d.action === 'warned') {
      showNotice({ kind: 'clickfix-warn', level: 'warning', title: 'This page copied a terminal command', body: 'Only run commands you understand and that come from a source you trust.', code: d.text, timeout: 15000 });
    }
  });

  // ===================================================================
  // 2. Password-reuse alarm
  // ===================================================================
  let pwLengths = [];
  let formsBlocked = false;
  const checked = new WeakMap();
  const blockSubmit = (e) => {
    if (!formsBlocked) return;
    e.preventDefault();
    e.stopImmediatePropagation();
  };
  function unblockForms() { formsBlocked = false; }

  async function onPasswordInput(e) {
    const t = e.target;
    if (!(t instanceof HTMLInputElement) || !/^(password|text|email|tel)$/i.test(t.type)) return;
    const v = t.value;
    if (!pwLengths.includes(v.length) || checked.get(t) === v) return;
    checked.set(t, v);
    let r;
    try { r = await send({ type: 'pwCheck', value: v, host: location.hostname }); } catch { return; }
    if (!r || r.allowed) return;
    t.value = '';
    t.dispatchEvent(new Event('input', { bubbles: true }));
    formsBlocked = true;
    showNotice({
      kind: 'password', key: 'password', level: 'danger', full: true, data: { id: r.id, label: r.label, host: location.hostname },
      title: `🔑 You just typed your "${r.label}" password on the wrong site`,
      body: `This password belongs to ${r.domains.join(', ')} — but this page is ${location.hostname}. If you didn't mean to share it here, this is probably phishing. The field was cleared and sending is blocked.`,
      list: ['If you already submitted it somewhere else, change this password now.', 'Turn on two-factor authentication — preferably a passkey or security key.'],
    });
  }

  // ===================================================================
  // 3. Device-code & OAuth-consent warnings (top frame of real IdP pages)
  // ===================================================================
  const DEVICE_PAGES = [
    /^https:\/\/(www\.)?microsoft\.com\/(?:[a-z]{2}-[a-z]{2}\/)?devicelogin/i,
    /^https:\/\/login\.microsoftonline\.com\/[^/]+\/oauth2\/(v2\.0\/)?deviceauth/i,
    /^https:\/\/login\.microsoft\.com\/device/i,
    /^https:\/\/(aka\.ms\/devicelogin)/i,
    /^https:\/\/github\.com\/login\/device/i,
    /^https:\/\/(www\.)?google\.com\/device/i,
    /^https:\/\/accounts\.google\.com\/o\/oauth2\/device/i,
    /^https:\/\/[^/]+\.awsapps\.com\/start\/?#\/device/i,
    /^https:\/\/device\.sso\.[a-z0-9-]+\.amazonaws\.com/i,
  ];
  const CONSENT_PAGE = /^https:\/\/(login\.microsoftonline\.com|login\.live\.com|accounts\.google\.com\/(signin\/oauth|o\/oauth2)|github\.com\/login\/oauth\/authorize|[^/]+\.okta\.com\/oauth2)/i;
  const CONSENT_TEXT = /(permissions requested|wants to access your google account|wants additional access|would like to:|authorize .+ to|this app would like to|accept these permissions|allow .+ to access)/i;
  const RISKY_SCOPES = [
    [/read,? (compose|write)?,? ?send,? and permanently delete all your email|read and write access to your mail|send mail as you|mail\.readwrite|mail\.send/i, 'Read, send or delete your email'],
    [/maintain access to data you have given it access to|offline access|have offline access/i, 'Keep access even after you sign out'],
    [/(see,? edit,? create,? and delete all of your google drive files|full access to your files|files\.readwrite\.all|read and write all files)/i, 'Read and change ALL your files'],
    [/(read and write (all )?(users'|your) (full )?profiles?|directory\.readwrite|access the directory as you)/i, 'Change your organisation directory'],
    [/(manage your contacts|contacts\.readwrite|see, edit, download, and permanently delete your contacts)/i, 'Change your contacts'],
    [/(read and write (your|all) calendars|calendars\.readwrite)/i, 'Change your calendar'],
    [/(full control|act on your behalf|access as you|user_impersonation)/i, 'Act fully as you'],
    [/(repo\b|full control of private repositories|admin:org|delete_repo)/i, 'Full control of your code repositories'],
  ];
  let consentShown = false;
  function checkIdpPages() {
    if (!isTop) return;
    const href = location.href;
    if (S.deviceCodeWarn && DEVICE_PAGES.some((re) => re.test(href)) && !shown.has('device')) {
      showNotice({
        kind: 'device', key: 'device', level: 'warning',
        title: '⚠ Device-code sign-in page',
        body: 'This is a real sign-in page, but attackers abuse it: they send you a code by email, chat or phone and ask you to "enter it here" — which signs THEM in to your account.',
        list: ['Only enter a code that YOU just got on your own TV, console, CLI tool or device.', 'If someone sent you this code or link, close this page.'],
      });
    }
    if (S.oauthConsentWarn && !consentShown && CONSENT_PAGE.test(href)) {
      const text = (document.body?.innerText || '').slice(0, 20000);
      if (!CONSENT_TEXT.test(text)) return;
      const risks = RISKY_SCOPES.filter(([re]) => re.test(text)).map(([, label]) => label);
      const unverified = /unverified|hasn't verified|not verified|google hasn.t verified/i.test(text);
      if (!risks.length && !unverified) return;
      consentShown = true;
      showNotice({
        kind: 'consent', key: 'consent', level: risks.length >= 2 || unverified ? 'danger' : 'warning',
        title: '⚠ An app is asking for access to your account',
        body: 'Consent phishing tricks you into granting a malicious app access — no password needed, and it survives password changes. Only accept if YOU just started connecting this app.',
        list: [...(unverified ? ['The publisher of this app is not verified'] : []), ...risks.map((r) => `Requests: ${r}`)],
      });
    }
  }

  // ===================================================================
  // 4. Link hover check
  // ===================================================================
  let tip = null;
  let tipRoot = null;
  let hoverTimer = null;
  const hostCache = new Map();
  function regOf(h) {
    const parts = h.replace(/^www\./, '').split('.');
    return parts.length > 2 && /^(co|com|org|net|gov|ac|edu)$/.test(parts[parts.length - 2]) ? parts.slice(-3).join('.') : parts.slice(-2).join('.');
  }
  function hideTip() { clearTimeout(hoverTimer); if (tip) tip.style.display = 'none'; }
  function ensureTip() {
    if (tip) return;
    tip = el('cyberdetector-tip');
    tipRoot = tip.attachShadow({ mode: 'closed' });
    tipRoot.append(el('style', {}, `:host{all:initial;position:fixed;z-index:2147483646;pointer-events:none}
      div{font:12px/1.4 system-ui,sans-serif;color:#fff;background:#1e293b;border-radius:6px;padding:6px 9px;max-width:420px;box-shadow:0 4px 16px rgba(0,0,0,.35);word-break:break-all}
      b{font-weight:700} .w{color:#fcd34d} .d{color:#fca5a5}`), el('div'));
    document.documentElement.append(tip);
  }
  async function onHover(e) {
    const a = e.target.closest?.('a[href]');
    if (!a) return;
    clearTimeout(hoverTimer);
    hoverTimer = setTimeout(async () => {
      let u;
      try { u = new URL(a.href); } catch { return; }
      if (!/^https?:$/.test(u.protocol) || u.hostname === location.hostname) return;
      const text = (a.innerText || '').trim();
      const shownDomain = text.match(/^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]|$)/i)?.[1];
      const mismatch = shownDomain && !/\s/.test(text) && regOf(shownDomain.toLowerCase()) !== regOf(u.hostname);
      let q = hostCache.get(u.hostname);
      if (!q) {
        q = send({ type: 'quickUrlCheck', url: u.href }).catch(() => null);
        hostCache.set(u.hostname, q);
      }
      const r = await q;
      const risky = mismatch || (r && r.level !== 'safe') || r?.shortener;
      if (S.linkHover === 'risky' && !risky) return;
      ensureTip();
      const box = tipRoot.querySelector('div');
      box.replaceChildren(
        'Opens ', el('b', {}, u.hostname),
        mismatch ? el('div', { class: 'd' }, `⚠ The link text shows "${shownDomain}" but it goes somewhere else`) : null,
        r?.shortener ? el('div', { class: 'w' }, '⚠ Shortened link — real destination hidden') : null,
        r && r.level !== 'safe' ? el('div', { class: r.level === 'danger' ? 'd' : 'w' }, `⚠ ${r.reason}`) : null);
      const rect = a.getBoundingClientRect();
      tip.style.display = 'block';
      tip.style.left = `${Math.max(8, Math.min(rect.left, innerWidth - 430))}px`;
      tip.style.top = `${rect.bottom + 6 > innerHeight - 60 ? rect.top - 60 : rect.bottom + 6}px`;
    }, 150);
  }

  // ===================================================================
  // 5. Webmail scanner (Gmail / Outlook web) — best effort, DOM varies
  // ===================================================================
  const doneMail = new WeakSet();
  function extractGmail() {
    const out = [];
    for (const msg of document.querySelectorAll('div.adn')) {
      if (doneMail.has(msg)) continue;
      const sender = msg.querySelector('span.gD[email]');
      const body = msg.querySelector('div.a3s');
      if (!sender || !body) continue;
      doneMail.add(msg);
      out.push({
        anchor: body,
        mail: {
          fromName: sender.getAttribute('name') || sender.textContent,
          fromEmail: sender.getAttribute('email'),
          subject: document.querySelector('h2.hP')?.textContent || '',
          links: [...body.querySelectorAll('a[href]')].map((a) => ({ text: a.innerText, href: a.href })),
          attachments: [...msg.querySelectorAll('span.aV3, div.aQH span[title]')].map((s) => s.textContent || s.title).filter(Boolean),
          bodyText: (body.innerText || '').slice(0, 5000),
        },
      });
    }
    return out;
  }
  function extractOutlook() {
    const body = document.querySelector('div[aria-label="Message body"], div[aria-label="Corps du message"], #UniqueMessageBody');
    if (!body || doneMail.has(body)) return [];
    const pane = body.closest('[role="main"], [aria-label*="Reading" i]') || document;
    const headerText = (pane.querySelector('[aria-label^="From" i], [title*="@"]')?.getAttribute('title') || pane.innerText || '').slice(0, 3000);
    const email = headerText.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i)?.[0] || '';
    const nameEl = pane.querySelector('[aria-label^="From" i] span, span[title*="@"]');
    doneMail.add(body);
    return [{
      anchor: body,
      mail: {
        fromName: (nameEl?.textContent || '').replace(/<[^>]*>/, '').trim(),
        fromEmail: email,
        subject: pane.querySelector('[role="heading"]')?.textContent || '',
        links: [...body.querySelectorAll('a[href]')].map((a) => ({ text: a.innerText, href: a.href })),
        attachments: [...pane.querySelectorAll('[role="attachment"] [title], div[title$=".zip" i], div[title$=".html" i]')].map((n) => n.getAttribute('title')).filter(Boolean),
        bodyText: (body.innerText || '').slice(0, 5000),
      },
    }];
  }
  async function scanMail() {
    const items = location.hostname === 'mail.google.com' ? extractGmail() : extractOutlook();
    for (const { anchor, mail } of items) {
      let v;
      try { v = await send({ type: 'analyzeEmail', mail }); } catch { continue; }
      const h = el('cyberdetector-mail');
      const root = h.attachShadow({ mode: 'closed' });
      const color = { safe: '#15803d', warning: '#b45309', danger: '#b91c1c' }[v.level] || '#334155';
      const top = v.findings.filter((f) => f.weight > 0).slice(0, 5);
      root.append(el('style', {}, `:host{all:initial;display:block;margin:0 0 10px}
        div{font:13px/1.45 system-ui,sans-serif;color:#fff;background:${color};border-radius:8px;padding:8px 12px}
        ul{margin:4px 0 0;padding-left:18px}`),
        el('div', {},
          el('b', {}, v.level === 'safe' ? '🛡 CyberDetector: no phishing signs found in this email' : `🛡 CyberDetector: ${v.level === 'danger' ? 'this email looks like phishing' : 'be careful with this email'} (risk ${v.score}/100)`),
          top.length ? el('ul', {}, top.map((f) => el('li', {}, `${f.title}${f.detail ? ` — ${f.detail}` : ''}`))) : null));
      anchor.prepend(h);
    }
  }

  // ===================================================================
  // 6. Live deepfake meter for browser calls
  // ===================================================================
  let live = null;
  function wavFromFloat32(samples, rate) {
    const buf = new ArrayBuffer(44 + samples.length * 2);
    const v = new DataView(buf);
    const w = (o, s) => { for (let i = 0; i < s.length; i++) v.setUint8(o + i, s.charCodeAt(i)); };
    w(0, 'RIFF'); v.setUint32(4, 36 + samples.length * 2, true); w(8, 'WAVE'); w(12, 'fmt ');
    v.setUint32(16, 16, true); v.setUint16(20, 1, true); v.setUint16(22, 1, true); v.setUint32(24, rate, true);
    v.setUint32(28, rate * 2, true); v.setUint16(32, 2, true); v.setUint16(34, 16, true); w(36, 'data'); v.setUint32(40, samples.length * 2, true);
    for (let i = 0; i < samples.length; i++) v.setInt16(44 + i * 2, Math.max(-1, Math.min(1, samples[i])) * 0x7fff, true);
    return buf;
  }
  const b64 = (buf) => {
    let s = '';
    const bytes = new Uint8Array(buf);
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(s);
  };
  function mediaStreams() {
    const streams = [];
    for (const m of document.querySelectorAll('audio, video')) {
      if (m.paused && !m.srcObject) continue;
      let s = m.srcObject instanceof MediaStream ? m.srcObject : null;
      if (!s) { try { s = m.captureStream ? m.captureStream() : m.mozCaptureStream ? m.mozCaptureStream() : null; } catch { s = null; } }
      if (s && s.getAudioTracks().length) streams.push(s);
    }
    return streams;
  }
  function biggestVideo() {
    return [...document.querySelectorAll('video')].filter((v) => !v.paused && v.videoWidth > 0)
      .sort((a, b) => b.videoWidth * b.videoHeight - a.videoWidth * a.videoHeight)[0];
  }
  function livePanel() {
    const host = el('cyberdetector-live');
    const root = host.attachShadow({ mode: 'closed' });
    root.append(el('style', {}, `:host{all:initial}
      .p{position:fixed;left:16px;bottom:16px;z-index:2147483647;width:270px;background:#0f172a;color:#e2e8f0;border-radius:10px;padding:12px;font:13px/1.4 system-ui,sans-serif;box-shadow:0 8px 30px rgba(0,0,0,.5)}
      h4{margin:0 0 8px;font-size:13px} .r{display:flex;justify-content:space-between;margin:3px 0} .v{font-weight:700}
      .bars{display:flex;gap:2px;align-items:flex-end;height:36px;margin-top:8px} .bars i{flex:1;background:#334155;min-height:2px}
      .s{font-size:11px;color:#94a3b8;margin-top:6px} button{margin-top:8px;font:600 12px system-ui;border-radius:6px;padding:5px 10px;border:1px solid #475569;background:#1e293b;color:#fff;cursor:pointer}`));
    const voice = el('span', { class: 'v' }, '…');
    const video = el('span', { class: 'v' }, '…');
    const bars = el('div', { class: 'bars' });
    const status = el('div', { class: 's' }, 'Listening to the call audio…');
    root.append(el('div', { class: 'p' },
      el('h4', {}, '🛡 Live deepfake check'),
      el('div', { class: 'r' }, 'Synthetic voice', voice),
      el('div', { class: 'r' }, 'AI-generated video', video),
      bars, status,
      el('button', { onclick: () => stopLive() }, 'Stop')));
    document.documentElement.append(host);
    const paint = (span, s) => { span.textContent = s == null ? '–' : `${Math.round(s * 100)}%`; span.style.color = s >= 0.7 ? '#f87171' : s >= 0.4 ? '#fbbf24' : '#4ade80'; };
    return {
      host,
      voice: (s) => {
        paint(voice, s);
        const bar = el('i');
        bar.style.height = `${Math.max(4, s * 100)}%`;
        bar.style.background = s >= 0.7 ? '#ef4444' : s >= 0.4 ? '#f59e0b' : '#22c55e';
        bars.append(bar);
        while (bars.children.length > 30) bars.firstChild.remove();
      },
      video: (s) => paint(video, s),
      status: (t) => { status.textContent = t; },
    };
  }
  async function startLive() {
    if (live) return { running: true };
    if (!S.liveCallCheck) throw new Error('Live call check is turned off in Settings');
    const streams = mediaStreams();
    if (!streams.length) throw new Error('No call audio found on this page yet — start the call first');
    const ctx = new AudioContext({ sampleRate: 16000 });
    const mix = ctx.createGain();
    for (const s of streams) ctx.createMediaStreamSource(s).connect(mix);
    const proc = ctx.createScriptProcessor(4096, 1, 1);
    const silent = ctx.createGain();
    silent.gain.value = 0;
    mix.connect(proc); proc.connect(silent); silent.connect(ctx.destination);
    let chunk = [];
    let len = 0;
    const panel = livePanel();
    live = { ctx, proc, panel, timer: null, busy: false };
    proc.onaudioprocess = (ev) => {
      const d = ev.inputBuffer.getChannelData(0);
      chunk.push(new Float32Array(d));
      len += d.length;
      if (len >= 16000 * 4) {
        const all = new Float32Array(len);
        let o = 0;
        for (const c of chunk) { all.set(c, o); o += c.length; }
        chunk = []; len = 0;
        let energy = 0;
        for (let i = 0; i < all.length; i += 16) energy += all[i] * all[i];
        if (energy / (all.length / 16) < 1e-6) { panel.status('Silence…'); return; }
        if (live.busy) return;
        live.busy = true;
        send({ type: 'liveChunk', kind: 'audio', b64: b64(wavFromFloat32(all, 16000)) })
          .then((r) => { panel.voice(r.score); panel.status(`Last check ${new Date().toLocaleTimeString()} · ${r.provider}`); })
          .catch((err) => panel.status(`⚠ ${err.message}`))
          .finally(() => { if (live) live.busy = false; });
      }
    };
    live.timer = setInterval(async () => {
      const v = biggestVideo();
      if (!v) return;
      try {
        const c = document.createElement('canvas');
        const scale = Math.min(1, 1024 / Math.max(v.videoWidth, v.videoHeight));
        c.width = Math.round(v.videoWidth * scale); c.height = Math.round(v.videoHeight * scale);
        c.getContext('2d').drawImage(v, 0, 0, c.width, c.height);
        const blob = await new Promise((r) => c.toBlob(r, 'image/jpeg', 0.9));
        const r = await send({ type: 'liveChunk', kind: 'image', b64: b64(await blob.arrayBuffer()) });
        panel.video(r.score);
      } catch { /* cross-origin video or detector error */ }
    }, 8000);
    return { running: true };
  }
  function stopLive() {
    if (!live) return { running: false };
    clearInterval(live.timer);
    live.proc.onaudioprocess = null;
    live.ctx.close().catch(() => {});
    live.panel.host.remove();
    live = null;
    return { running: false };
  }

  // ===================================================================
  // Wiring
  // ===================================================================
  ext.runtime.onMessage.addListener((msg, _s, sendResponse) => {
    if (msg?.type === 'guardNotice' && isTop) { renderNotice(msg.notice); sendResponse({ ok: true }); return false; }
    if (msg?.type === 'liveCheck' && isTop) {
      Promise.resolve()
        .then(() => (msg.action === 'stop' ? stopLive() : msg.action === 'status' ? { running: !!live } : startLive()))
        .then((data) => sendResponse({ ok: true, data }), (e) => sendResponse({ ok: false, error: e.message }));
      return true;
    }
    return false;
  });

  async function init() {
    const { settings } = await ext.storage.local.get('settings');
    S = { ...DEFAULTS, ...(settings || {}) };
    if (S.passwordAlert) {
      try { pwLengths = await send({ type: 'pwLengths' }); } catch { pwLengths = []; }
      if (pwLengths.length) {
        document.addEventListener('input', onPasswordInput, true);
        document.addEventListener('change', onPasswordInput, true);
        document.addEventListener('submit', blockSubmit, true);
        document.addEventListener('click', (e) => { if (formsBlocked && e.target.closest?.('button[type="submit"], input[type="submit"], button:not([type])')) blockSubmit(e); }, true);
      }
    }
    if (!isTop) return;
    if (S.linkHover !== 'off') {
      document.addEventListener('mouseover', onHover, { passive: true });
      document.addEventListener('mouseout', (e) => { if (e.target.closest?.('a[href]')) hideTip(); }, { passive: true });
      window.addEventListener('scroll', hideTip, { passive: true });
    }
    const isMail = /^(mail\.google\.com|outlook\.(live|office|office365)\.com)$/.test(location.hostname);
    let t = null;
    const tick = () => {
      clearTimeout(t);
      t = setTimeout(() => {
        checkIdpPages();
        if (isMail && S.webmailScan) scanMail();
      }, 700);
    };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', tick, { once: true }); else tick();
    new MutationObserver(tick).observe(document.documentElement, { childList: true, subtree: true });
  }
  ext.storage.onChanged?.addListener((changes, area) => {
    if (area === 'local' && changes.settings) S = { ...DEFAULTS, ...(changes.settings.newValue || {}) };
  });
  init();
})();
