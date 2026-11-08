import { ext, send, hasDataConsent } from '../lib/ext.js';
import { h, gauge, levelPill, renderFindings, renderReputation, truncateMiddle, fmtBytes, fmtTime, timeAgo, levelColor } from '../lib/ui.js';
import { getSettings } from '../lib/storage.js';
import { extractMetadata } from '../lib/media-metadata.js';
import { errorLevelAnalysis } from '../lib/ela.js';
import { detectAI, providerConfigured, isLocalProvider } from '../lib/ai-detect.js';
import { combineMediaScore } from '../lib/media-score.js';
import { analyzeEmbeddedContent, metadataLinks } from '../lib/image-text.js';
import { decodeQrCodes, recognizeText } from '../lib/image-scan.js';

const $ = (s) => document.querySelector(s);
const app = $('#app');
const params = new URLSearchParams(location.search);

$('#open-settings').addEventListener('click', () => ext.runtime.openOptionsPage());
$('#new-upload').addEventListener('click', () => { location.search = '?mode=upload'; });

const setTitle = (t) => { $('#mode-title').textContent = t; document.title = `CyberDetector — ${t}`; };
const card = (title, ...body) => h('section', { class: 'card' }, title ? h('h3', {}, title) : null, ...body);
const kv = (pairs) => {
  const rows = pairs.filter(([, v]) => v !== undefined && v !== null && v !== '');
  if (!rows.length) return h('p', { class: 'muted small' }, 'None found.');
  return h('dl', { class: 'kv' }, rows.flatMap(([k, v, long]) => [h('dt', {}, k), h('dd', { class: long ? 'long' : '' }, String(v))]));
};
const scoreColor = (s) => (s >= 0.7 ? 'var(--danger)' : s >= 0.4 ? 'var(--warning)' : 'var(--safe)');
const loading = (text) => app.replaceChildren(h('div', { class: 'loading' }, h('span', { class: 'spinner' }), text));
const fail = (msg) => app.replaceChildren(card('Something went wrong', h('p', { class: 'error' }, msg)));

// ==================================================================
// URL report
// ==================================================================
function renderUrlResult(r, { stored = false } = {}) {
  setTitle('URL report');
  const hero = h('section', { class: `card hero ${r.level}` },
    gauge(r.score, r.level, { size: 110 }),
    h('div', { class: 'grow' },
      levelPill(r.level),
      h('div', { class: 'hero-title' }, r.unicodeHost || r.target || ''),
      h('div', { class: 'hero-sub' }, r.reason || r.summary || ''),
      h('div', { class: 'mono muted small break', style: { marginTop: '6px' } }, r.input || r.url || r.target),
      stored ? h('div', { class: 'small muted' }, `Saved ${timeAgo(r.ts)} — `, h('a', { href: `?mode=url&url=${encodeURIComponent(r.target)}` }, 're-scan now')) : null));

  const right = [];
  if (r.reputation) right.push(card('Reputation / blacklists', renderReputation(r.reputation)));
  if (r.expansion) {
    right.push(card('Shortened URL expansion',
      h('div', { class: 'hops' }, r.expansion.hops.flatMap((hop, i) => [i ? h('div', { class: 'arrow' }, '↓ redirects to') : null, h('div', { class: 'hop mono' }, hop)])),
      r.expansion.error ? h('p', { class: 'error small' }, `Stopped: ${r.expansion.error}`) : null));
  }
  if (r.host) {
    const c = r.connection || {};
    const sec = c.sec;
    right.push(card('Domain & connection', kv([
      ['Host', r.host],
      ['Displayed as', r.unicodeHost !== r.host ? r.unicodeHost : ''],
      ['Registered domain', r.registrable],
      ['Official brand', r.officialBrand],
      ['HTTPS', c.https ? 'Yes' : 'No — unencrypted'],
      ['Certificate issuer', sec?.cert?.issuer],
      ['Certificate valid', sec?.cert ? `${new Date(sec.cert.validFrom).toLocaleDateString()} → ${new Date(sec.cert.validTo).toLocaleDateString()}` : ''],
      ['TLS', sec?.protocolVersion],
      ['First seen (CT logs)', c.firstSeenDays != null ? `${c.firstSeenDays} days ago` : ''],
    ]),
    c.https && !sec ? h('p', { class: 'muted small' }, 'Full certificate details are available in Firefox, or when the page is open in a tab. Chrome does not expose certificates to extensions.') : null));
  }
  right.push(h('p', { class: 'notice' }, 'Manual URL scans check the address, domain, reputation feeds and redirects without opening the page. Page content (login forms, brand impersonation, urgency language) is analyzed automatically when you visit it.'));

  app.replaceChildren(hero, h('div', { class: 'grid' },
    h('div', { class: 'col' }, card('Findings', renderFindings(r.findings || []))),
    h('div', { class: 'col' }, ...right)));
}

async function urlMode(url) {
  setTitle('URL report');
  loading(`Analyzing ${truncateMiddle(url, 80)}…`);
  try {
    renderUrlResult(await send({ type: 'scanUrl', url }));
  } catch (e) {
    fail(e.message);
  }
}

// ==================================================================
// Media scan
// ==================================================================
function stepsUI() {
  const el = h('div', { class: 'steps' });
  const add = (text) => {
    const s = h('div', { class: 'step' }, h('span', { class: 'spinner' }), h('span', {}, text));
    el.append(s);
    return {
      done: (t) => { s.className = 'step done'; s.firstChild.replaceWith(h('span', {}, '✓')); if (t) s.lastChild.textContent = t; },
      fail: (t) => { s.className = 'step fail'; s.firstChild.replaceWith(h('span', {}, '✕')); if (t) s.lastChild.textContent = t; },
      skip: (t) => { s.className = 'step'; s.firstChild.replaceWith(h('span', {}, '–')); if (t) s.lastChild.textContent = t; },
      text: (t) => { s.lastChild.textContent = t; },
    };
  };
  return { el, add };
}

async function fetchMedia(src, maxMB) {
  if (src.startsWith('blob:')) throw new Error('This media is streamed from a blob: URL and cannot be fetched by extensions. Download the file and use “Scan a file”.');
  const res = await fetch(src, { credentials: 'include', signal: AbortSignal.timeout(60000) });
  if (!res.ok) throw new Error(`Download failed: HTTP ${res.status}`);
  const len = Number(res.headers.get('content-length') || 0);
  if (len > maxMB * 1024 * 1024) throw new Error(`File is ${fmtBytes(len)} — over the ${maxMB} MB limit (change it in Settings).`);
  const blob = await res.blob();
  if (blob.size > maxMB * 1024 * 1024) throw new Error(`File is ${fmtBytes(blob.size)} — over the ${maxMB} MB limit.`);
  return blob;
}

async function mediaMode({ src, file, type, pageUrl, tabId }) {
  setTitle('Media scan');
  const settings = await getSettings();
  const steps = stepsUI();
  app.replaceChildren(card(file ? `Scanning ${file.name}` : 'Scanning media', h('div', { class: 'mono small muted break', style: { marginBottom: '10px' } }, src || ''), steps.el));

  let blob = file;
  const sFetch = steps.add(file ? 'Reading file' : 'Downloading media');
  try {
    if (!blob) blob = await fetchMedia(src, settings.maxMediaMB);
    sFetch.done(`${file ? 'Read' : 'Downloaded'} ${fmtBytes(blob.size)}`);
  } catch (e) {
    sFetch.fail(e.message);
    return;
  }

  const sMeta = steps.add('Inspecting EXIF / XMP / C2PA metadata');
  let bytes;
  try {
    bytes = new Uint8Array(await blob.arrayBuffer());
  } catch (e) {
    sMeta.fail(`Could not read the file: ${e.message}`);
    return;
  }
  const meta = await extractMetadata(bytes);
  const kind = meta.kind !== 'unknown' ? meta.kind : type || (blob.type.split('/')[0] || 'image');
  sMeta.done(`Metadata: ${meta.format}${meta.c2pa ? ' · C2PA manifest found' : ''}${meta.markers.length ? ` · ${meta.markers.length} provenance signal(s)` : ''}`);

  let ela = null;
  if (kind === 'image' && meta.format !== 'SVG') {
    const sEla = steps.add('Running error level analysis');
    try {
      ela = await errorLevelAnalysis(blob);
      sEla.done(`Error level analysis: ${ela.hotspots.length} hotspot(s)`);
    } catch (e) {
      sEla.fail(`Error level analysis unavailable: ${e.message}`);
    }
  }

  const embedded = await scanEmbedded({ blob, kind, meta, settings, steps });

  let ai = null;
  let aiError = null;
  if (providerConfigured(settings) && !isLocalProvider(settings) && !(await hasDataConsent('websiteContent'))) {
    aiError = 'Firefox data-sharing permission for website content was not granted — re-select the provider in Settings to allow it.';
  } else if (providerConfigured(settings)) {
    const sAi = steps.add(`Querying ${settings.aiProvider} AI-detection API`);
    try {
      ai = await detectAI({ blob, src, mediaType: kind, settings, duration: meta.duration });
      sAi.done(`${ai.provider}: ${(ai.score * 100).toFixed(0)}% synthetic`);
    } catch (e) {
      aiError = e.message;
      sAi.fail(`AI detection failed: ${e.message}`);
    }
  }

  const result = combineMediaScore(meta, ai, ela);
  const objectUrl = URL.createObjectURL(blob);
  renderMediaReport({ src, file, kind, blob, meta, ela, ai, aiError, result, objectUrl, settings, pageUrl, embedded });
  const embeddedWorse = embedded && LEVEL_RANK[embedded.level] > LEVEL_RANK[result.level] && LEVEL_RANK[embedded.level] >= LEVEL_RANK.warning;

  const target = file ? file.name : src.startsWith('data:') ? 'inline data image' : src;
  await send({
    type: 'addHistory',
    entry: {
      type: 'media', source: file ? 'upload' : 'context', mediaType: kind, target, pageUrl,
      level: embeddedWorse ? embedded.level : result.level, probability: result.probability, score: Math.round(result.probability * 100),
      summary: embeddedWorse ? `${embedded.reason} · ${result.verdict}` : result.verdict,
      details: {
        format: meta.format, size: blob.size, width: meta.width, height: meta.height, duration: meta.duration,
        confidence: result.confidence, basis: result.basis, signals: result.signals, markers: meta.markers,
        c2pa: meta.c2pa, exif: meta.exif, xmpFields: meta.xmpFields, gps: meta.gps,
        ai: ai ? { provider: ai.provider, score: ai.score, scores: ai.scores } : null, aiError,
        ela: ela ? ela.stats : null,
        embedded: embedded ? summarizeEmbedded(embedded) : null,
      },
    },
  }).catch(() => {});

  if (tabId && src) {
    const label = embeddedWorse
      ? `⚠ ${embedded.reason} · ${Math.round(result.probability * 100)}% AI`
      : `${Math.round(result.probability * 100)}% AI · ${result.verdict.split(' —')[0]}`;
    ext.tabs.sendMessage(Number(tabId), { type: 'markMedia', src, level: embeddedWorse ? embedded.level : result.level, label }).catch(() => {});
  }
}

// ---------------- Embedded content: QR codes, OCR text, metadata links ----------------
const LEVEL_RANK = { unknown: 0, safe: 1, warning: 2, danger: 3 };
const MAX_LINK_CHECKS = 8;

async function scanEmbedded({ blob, kind, meta, settings, steps }) {
  const decodable = kind === 'image' && meta.format !== 'SVG';
  const metaLinks = metadataLinks(meta);
  const wantQr = decodable && settings.scanQr;
  const wantOcr = decodable && settings.scanOcr;
  if (!wantQr && !wantOcr && !metaLinks.length) return null;

  const errors = [];
  let qrCodes = [];
  if (wantQr) {
    const s = steps.add('Looking for QR codes and barcodes');
    try {
      const r = await decodeQrCodes(blob);
      qrCodes = r.codes;
      s.done(r.codes.length ? `Found ${r.codes.length} QR/barcode(s)` : 'No QR codes found');
    } catch (e) {
      errors.push(`QR decoding failed: ${e.message}`);
      s.fail(`QR decoding unavailable: ${e.message}`);
    }
  }

  let ocr = null;
  if (wantOcr) {
    const s = steps.add('Reading text in the image (OCR)');
    try {
      ocr = await recognizeText(blob, {
        onProgress: (p, status) => s.text(`Reading text in the image (OCR) — ${status}${p ? ` ${Math.round(p * 100)}%` : ''}`),
      });
      const words = ocr.text.split(/\s+/).filter((w) => /[\p{L}\p{N}]{2,}/u.test(w)).length;
      s.done(words ? `Read ${words} word(s) of text (${ocr.confidence}% confidence)` : 'No readable text');
    } catch (e) {
      errors.push(`Text recognition failed: ${e.message}`);
      s.fail(`Text recognition unavailable: ${e.message}`);
    }
  }

  // First pass to collect links, then check them with the phishing engine.
  const linkResults = {};
  const pre = analyzeEmbeddedContent({ qrCodes, ocr, metaLinks, sensitivity: settings.sensitivity });
  if (pre.links.length && settings.checkEmbeddedLinks) {
    const toCheck = pre.links.slice(0, MAX_LINK_CHECKS);
    const s = steps.add(`Checking ${toCheck.length} link(s) found in the media for phishing`);
    await Promise.all(toCheck.map(async (l) => {
      try {
        const r = await send({ type: 'scanUrl', url: l.url, record: false });
        linkResults[l.url] = { level: r.level, score: r.score, reason: r.reason, finalUrl: r.expansion?.final };
      } catch (e) {
        linkResults[l.url] = { error: e.message };
      }
    }));
    const bad = Object.values(linkResults).filter((r) => r.level === 'danger' || r.level === 'warning').length;
    s.done(`Checked ${toCheck.length} link(s)${bad ? ` — ${bad} suspicious` : ' — no phishing indicators'}${pre.links.length > toCheck.length ? ` (${pre.links.length - toCheck.length} more not checked)` : ''}`);
  }

  const res = analyzeEmbeddedContent({ qrCodes, ocr, metaLinks, linkResults, sensitivity: settings.sensitivity });
  return { ...res, errors, ran: { qr: wantQr, ocr: wantOcr, links: settings.checkEmbeddedLinks } };
}

/** Compact copy for history (no secrets: Wi-Fi / 2FA payloads are already redacted by parseQrPayload). */
function summarizeEmbedded(e) {
  return {
    level: e.level, score: e.score, reason: e.reason, ran: e.ran, errors: e.errors, ocrConfidence: e.ocrConfidence,
    findings: e.findings.slice(0, 20),
    links: e.links.map((l) => ({ url: l.url, source: l.source, result: l.result })),
    qr: e.qr.map((c) => ({ type: c.type, label: c.label, detail: c.detail, url: c.url, format: c.format, raw: c.raw.slice(0, 500) })),
    text: e.text.slice(0, 2000),
  };
}

function embeddedCard(e) {
  const linkRow = (l) => {
    const r = l.result;
    return h('div', { class: 'emb-link' },
      r?.level ? levelPill(r.level) : h('span', { class: 'pill pill-unknown' }, r?.error ? 'error' : 'not checked'),
      h('div', { class: 'grow' },
        h('div', { class: 'mono small break' }, l.url),
        h('div', { class: 'small muted' }, l.source, r?.finalUrl && r.finalUrl !== l.url ? ` · redirects to ${r.finalUrl}` : '', r?.reason && r.level !== 'safe' ? ` · ${r.reason}` : '')),
      h('a', { class: 'small', href: `?${new URLSearchParams({ mode: 'url', url: l.url })}`, target: '_blank', title: 'Open the full URL report (does not visit the link)' }, 'Report'));
  };
  const ran = e.ran || {};
  const skipped = [!ran.qr && 'QR decoding', !ran.ocr && 'text recognition'].filter(Boolean);
  return card('Embedded content — QR codes, text & links',
    h('div', { class: 'row', style: { marginBottom: '8px' } }, levelPill(e.level, e.level === 'unknown' ? 'Nothing found' : undefined), h('span', { class: 'small' }, e.reason)),
    e.qr.length
      ? h('div', {}, h('h4', { class: 'small muted' }, 'QR CODES & BARCODES'),
          e.qr.map((c) => h('div', { class: 'emb-qr' }, h('b', {}, c.label), c.detail ? h('span', { class: 'small' }, ` — ${c.detail}`) : null,
            h('div', { class: 'mono small break muted' }, c.raw.slice(0, 500)))))
      : null,
    e.links.length
      ? h('div', { style: { marginTop: '10px' } }, h('h4', { class: 'small muted' }, 'LINKS'), e.links.map(linkRow),
          !ran.links ? h('p', { class: 'muted small' }, 'Link checking is turned off in Settings.') : null)
      : null,
    e.findings.length ? h('div', { style: { marginTop: '10px' } }, renderFindings(e.findings)) : null,
    e.text
      ? h('details', { style: { marginTop: '10px' } },
          h('summary', { class: 'small' }, `Text read from the image${e.ocrConfidence != null ? ` (${e.ocrConfidence}% OCR confidence)` : ''}`),
          h('pre', { class: 'ocr-text' }, e.text))
      : null,
    ...(e.errors || []).map((m) => h('p', { class: 'error small' }, m)),
    skipped.length && e.ran ? h('p', { class: 'muted small' }, `${skipped.join(' and ')} ${skipped.length > 1 ? 'are' : 'is'} off or not applicable to this file.`) : null,
    h('p', { class: 'notice', style: { marginTop: '8px' } }, 'QR codes and text are decoded on your device. Links are checked without opening them in your browser. OCR can misread stylised or low-resolution text.'));
}

// ---------------- Media report rendering ----------------
function probabilityCard(result, ai, aiError, { showConfigHint = false } = {}) {
  const pct = Math.round(result.probability * 100);
  return card('Synthetic probability',
    h('div', { class: 'prob' },
      gauge(pct, result.level, { size: 104, caption: 'AI %' }),
      h('div', { class: 'grow' },
        levelPill(result.level, result.verdict),
        h('div', { class: 'prob-bar' }, h('div', { style: { width: `${pct}%`, background: levelColor(result.level) } })),
        h('div', { class: 'row small' }, h('span', { class: `conf conf-${result.confidence}` }, `${result.confidence} confidence`), h('span', { class: 'muted' }, result.basis)),
        ai?.models ? h('div', { class: 'small muted', style: { marginTop: '4px' } }, `Models: ${ai.models.join(', ')}`) : null)),
    ai && Object.keys(ai.scores || {}).length
      ? h('div', { class: 'scores' }, Object.entries(ai.scores).map(([k, v]) =>
          h('div', { class: 'score-row' }, h('span', {}, k),
            h('div', { class: 'prob-bar' }, h('div', { style: { width: `${v * 100}%`, background: scoreColor(v) } })),
            h('span', { class: 'mono' }, `${(v * 100).toFixed(0)}%`))))
      : null,
    result.signals.length
      ? h('ul', { class: 'signals' }, result.signals.map((s) =>
          h('li', {}, h('span', { class: `eff ${s.effect === '+' ? 'plus' : s.effect === '-' ? 'minus' : 'pm'}` }, s.effect),
            h('span', {}, s.label, s.detail ? h('span', { class: 'muted' }, ` — ${s.detail}`) : null))))
      : null,
    aiError ? h('p', { class: 'error small' }, `AI detection API error: ${aiError}`) : null,
    showConfigHint
      ? h('p', { class: 'notice' }, 'No AI-detection model is configured, so this score relies on metadata and forensic heuristics and cannot confirm a deepfake. ',
          h('a', { href: '#', onclick: (e) => { e.preventDefault(); ext.runtime.openOptionsPage(); } }, 'Set up the free local detector'), ' (or Sightengine / Hive) for model-based detection.')
      : null);
}

function provenanceCard(meta) {
  const c = meta.c2pa;
  return card('Provenance — C2PA & AI markers',
    c
      ? h('div', {},
          h('p', {}, h('b', {}, c.remote ? 'Content Credentials (C2PA) manifest is stored remotely.' : 'Content Credentials (C2PA) manifest found.')),
          c.remote ? h('p', { class: 'small break' }, 'Manifest URL (not downloaded automatically): ', h('a', { href: c.remote, target: '_blank', rel: 'noopener noreferrer' }, c.remote)) : null,
          kv([
            ['Claim generator', c.claimGenerators.join(', ')],
            ['Actions', c.actions.join(', ')],
            ['Digital source type', c.digitalSourceTypes.join(', ')],
            ['Signer hints', c.signerHints.join(', ')],
            ['Has ingredients', c.hasIngredients ? 'Yes (composited from other assets)' : ''],
          ]),
          h('p', { class: 'notice', style: { marginTop: '8px' } }, 'The manifest signature is not cryptographically verified here. Verify it at ',
            h('a', { href: 'https://contentcredentials.org/verify', target: '_blank', rel: 'noopener' }, 'contentcredentials.org/verify'), '.'))
      : h('p', { class: 'muted small' }, 'No C2PA / Content Credentials manifest.'),
    meta.markers.length
      ? h('div', { style: { marginTop: '10px' } }, meta.markers.map((m) => h('div', { class: `marker ${m.kind}` }, m.label, h('div', { class: 'src' }, `${m.source} · ${m.strength}`))))
      : h('p', { class: 'muted small' }, 'No AI-generation or camera provenance markers in metadata.'),
    meta.metadataStripped ? h('p', { class: 'notice' }, 'This file carries no metadata. Social networks and messaging apps strip it routinely, so its absence is not evidence either way.') : null);
}

function metadataCard(meta, blob) {
  const ex = meta.exif;
  const fmtExp = (v) => (typeof v === 'number' && v > 0 && v < 1 ? `1/${Math.round(1 / v)} s` : v != null ? `${v} s` : '');
  const sections = [
    h('h4', { class: 'small muted' }, 'FILE'),
    kv([
      ['Format', meta.format], ['MIME type', blob.type], ['Size', fmtBytes(blob.size)],
      ['Dimensions', meta.width ? `${Math.round(meta.width)} × ${Math.round(meta.height)}` : ''],
      ['Duration', meta.duration ? fmtTime(meta.duration) : ''],
      ['Audio', meta.audio ? `${meta.audio.sampleRate} Hz · ${meta.audio.channels} ch · ${meta.audio.bitsPerSample}-bit` : ''],
      ['Progressive JPEG', meta.flags.progressive ? 'Yes' : ''], ['Photoshop data block', meta.flags.photoshopIRB ? 'Yes' : ''],
      ['Animated', meta.flags.animated ? 'Yes' : ''],
    ]),
  ];
  if (Object.keys(ex).length) {
    sections.push(h('h4', { class: 'small muted', style: { marginTop: '12px' } }, 'EXIF'), kv([
      ['Camera', [ex.Make, ex.Model].filter(Boolean).join(' ')], ['Lens', [ex.LensMake, ex.LensModel].filter(Boolean).join(' ')],
      ['Software', ex.Software], ['Taken', ex.DateTimeOriginal], ['Modified', ex.DateTime],
      ['Exposure', fmtExp(ex.ExposureTime)], ['Aperture', ex.FNumber ? `f/${(+ex.FNumber).toFixed(1)}` : ''], ['ISO', ex.ISO],
      ['Focal length', ex.FocalLength ? `${(+ex.FocalLength).toFixed(1)} mm` : ''], ['Artist', ex.Artist], ['Copyright', ex.Copyright],
      ['Description', ex.ImageDescription], ['User comment', ex.UserComment], ['Serial', ex.BodySerialNumber],
    ]));
  }
  if (meta.gps) {
    sections.push(h('p', { class: 'small', style: { color: 'var(--warning)' } },
      `⚠ Contains GPS location: ${meta.gps.lat}, ${meta.gps.lon} — `,
      h('a', { href: `https://www.openstreetmap.org/?mlat=${meta.gps.lat}&mlon=${meta.gps.lon}#map=15/${meta.gps.lat}/${meta.gps.lon}`, target: '_blank', rel: 'noopener' }, 'view map'),
      '. Strip location before sharing.'));
  }
  if (Object.keys(meta.xmpFields).length) {
    sections.push(h('h4', { class: 'small muted', style: { marginTop: '12px' } }, 'XMP'), kv(Object.entries(meta.xmpFields)));
  }
  if (Object.keys(meta.text).length) {
    sections.push(h('h4', { class: 'small muted', style: { marginTop: '12px' } }, 'EMBEDDED TEXT'), kv(Object.entries(meta.text).map(([k, v]) => [k, v, v.length > 80])));
  }
  if (meta.parseError) sections.push(h('p', { class: 'error small' }, `Parser warning: ${meta.parseError}`));
  return card('Metadata', ...sections);
}

function imageStage(objectUrl, ela, ai) {
  const img = h('img', { src: objectUrl, alt: 'Scanned image' });
  const stage = h('div', { class: 'stage' }, img);
  const controls = h('div', { class: 'controls' });
  const regions = [];

  if (ela) {
    const canvas = h('canvas', { class: 'heat', width: ela.width, height: ela.height });
    canvas.getContext('2d').putImageData(ela.heatmap, 0, 0);
    canvas.style.opacity = '0';
    stage.append(canvas);
    const opacity = h('input', { type: 'range', min: 0, max: 100, value: 70 });
    const toggle = h('input', { type: 'checkbox' });
    const update = () => { canvas.style.opacity = toggle.checked ? String(opacity.value / 100) : '0'; };
    toggle.addEventListener('change', update);
    opacity.addEventListener('input', () => { toggle.checked = true; update(); });
    controls.append(
      h('label', {}, toggle, 'ELA heatmap'),
      h('label', {}, 'Opacity', opacity),
      h('span', { class: 'legend' }, 'low', h('span', { class: 'ramp' }), 'high error'));
    for (const r of ela.hotspots) regions.push(['ela', r]);
  }
  for (const r of ai?.regions || []) regions.push(['ai', r]);

  const regionEls = regions.map(([kind, r]) => h('div', {
    class: `region ${kind}`,
    title: kind === 'ai' ? `AI region ${(r.score * 100).toFixed(0)}%` : 'Compression hotspot',
    style: { left: `${r.x * 100}%`, top: `${r.y * 100}%`, width: `${r.w * 100}%`, height: `${r.h * 100}%`, display: kind === 'ai' ? '' : 'none' },
  }));
  stage.append(...regionEls);
  if (ela?.hotspots.length) {
    const t = h('input', { type: 'checkbox' });
    t.addEventListener('change', () => regionEls.forEach((el) => { if (el.classList.contains('ela')) el.style.display = t.checked ? '' : 'none'; }));
    controls.append(h('label', {}, t, `Hotspots (${ela.hotspots.length})`));
  }
  if (ai?.regions?.length) {
    const t = h('input', { type: 'checkbox', checked: true });
    t.addEventListener('change', () => regionEls.forEach((el) => { if (el.classList.contains('ai')) el.style.display = t.checked ? '' : 'none'; }));
    controls.append(h('label', {}, t, `Manipulated regions (${ai.regions.length})`));
  }
  return [h('div', { class: 'stage-wrap' }, stage), controls];
}

function timelineStage(kind, objectUrl, ai) {
  const media = h(kind, { src: objectUrl, controls: true, preload: 'metadata' });
  const timeline = h('div', { class: 'timeline', title: 'Click to seek' });
  const tsList = h('div', { class: 'ts-list' });
  const note = h('p', { class: 'muted small' });
  const frames = ai?.frames || [];
  const wrap = h('div', {}, kind === 'video' ? h('div', { class: 'stage-wrap' }, h('div', { class: 'stage' }, media)) : media, timeline, tsList, note);

  if (!frames.length) {
    timeline.classList.add('hidden');
    note.textContent = ai
      ? `${ai.provider} returned a single score for the whole file (no per-segment data).`
      : 'Per-frame / per-segment timeline requires an AI-detection API that supports this media type (Sightengine or Hive for video, Hive or a custom endpoint for audio).';
    return wrap;
  }

  media.addEventListener('loadedmetadata', () => {
    const duration = media.duration;
    if (!Number.isFinite(duration) || duration <= 0) return;
    // Some APIs report positions in milliseconds.
    const maxT = Math.max(...frames.map((f) => f.time));
    const unit = ai.frameTimeUnit === 'auto' && maxT > duration * 1.5 ? 1000 : 1;
    const pts = frames.map((f) => ({ ...f, t: f.time / unit, e: f.end != null ? f.end / unit : null }));
    const slot = duration / pts.length;
    timeline.append(h('div', { class: 'threshold', style: { bottom: '50%' } }));
    for (const f of pts) {
      const width = f.e != null ? ((f.e - f.t) / duration) * 100 : (slot / duration) * 100;
      timeline.append(h('div', {
        class: 'bar',
        title: `${fmtTime(f.t)} — ${(f.score * 100).toFixed(0)}% synthetic`,
        style: { left: `${(f.t / duration) * 100}%`, width: `max(2px, calc(${width}% - 1px))`, height: `${Math.max(4, f.score * 100)}%`, background: scoreColor(f.score) },
      }));
    }
    const playhead = h('div', { class: 'playhead' });
    timeline.append(playhead);
    media.addEventListener('timeupdate', () => { playhead.style.left = `${(media.currentTime / duration) * 100}%`; });
    timeline.addEventListener('click', (e) => {
      const r = timeline.getBoundingClientRect();
      media.currentTime = ((e.clientX - r.left) / r.width) * duration;
    });

    // Merge consecutive suspicious frames into ranges.
    const ranges = [];
    for (const f of pts) {
      if (f.score < 0.5) continue;
      const last = ranges[ranges.length - 1];
      const end = f.e ?? f.t + slot;
      if (last && f.t - last.end <= slot * 1.5) { last.end = end; last.peak = Math.max(last.peak, f.score); } else ranges.push({ start: f.t, end, peak: f.score });
    }
    note.textContent = ranges.length ? 'Suspicious segments (click to jump):' : 'No segment scored above 50%.';
    tsList.replaceChildren(...ranges.map((r) => h('button', { onclick: () => { media.currentTime = r.start; media.play?.(); } },
      `${fmtTime(r.start)}–${fmtTime(r.end)} · ${(r.peak * 100).toFixed(0)}%`)));
  });
  return wrap;
}

function renderMediaReport({ src, file, kind, blob, meta, ela, ai, aiError, result, objectUrl, settings, pageUrl, embedded }) {
  const preview = kind === 'image' ? imageStage(objectUrl, ela, ai) : timelineStage(kind, objectUrl, ai);
  const left = [card(kind === 'image' ? 'Manipulation heatmap' : 'Detection timeline', ...[preview].flat())];
  if (ela) {
    left.push(card('Error level analysis',
      kv([['Mean error', ela.stats.mean], ['Std deviation', ela.stats.std], ['Block variation', ela.stats.blockStd], ['Hotspots', ela.hotspots.length], ['Downscaled for analysis', ela.downscaled ? 'Yes' : '']]),
      h('p', { class: 'notice', style: { marginTop: '8px' } },
        'ELA re-compresses the image and highlights areas that change differently. Edges and textures naturally glow; look for a uniform region (a face, an object) that is much brighter or darker than similar surroundings. ',
        meta.format !== 'JPEG' ? 'This is not a JPEG, so ELA is less meaningful.' : '')));
  }
  left.push(metadataCard(meta, blob));

  const hero = h('section', { class: `card hero ${result.level}` },
    h('div', { style: { fontSize: '40px' } }, { image: '🖼', video: '🎞', audio: '🎵' }[kind] || '📄'),
    h('div', { class: 'grow' },
      levelPill(result.level, result.verdict),
      embedded && LEVEL_RANK[embedded.level] >= LEVEL_RANK.warning ? h('span', { style: { marginLeft: '6px' } }, levelPill(embedded.level, `Embedded content: ${embedded.reason}`)) : null,
      h('div', { class: 'hero-title' }, file ? file.name : truncateMiddle(src, 90)),
      h('div', { class: 'hero-sub' }, `${meta.format} ${kind} · ${fmtBytes(blob.size)}${pageUrl ? ` · from ${new URL(pageUrl).hostname}` : ''}`)));

  app.replaceChildren(hero, h('div', { class: 'grid' },
    h('div', { class: 'col' }, ...left),
    h('div', { class: 'col' },
      embedded && LEVEL_RANK[embedded.level] >= LEVEL_RANK.warning ? embeddedCard(embedded) : null,
      probabilityCard(result, ai, aiError, { showConfigHint: !providerConfigured(settings) }),
      embedded && LEVEL_RANK[embedded.level] < LEVEL_RANK.warning ? embeddedCard(embedded) : null,
      provenanceCard(meta),
      h('p', { class: 'notice' }, 'No detector is perfect. Treat this as one piece of evidence: check the original source, look for the same media elsewhere (reverse image search), and be cautious with content designed to provoke strong emotions.'))));
}

// ==================================================================
// Upload
// ==================================================================
function uploadMode() {
  setTitle('Scan a file');
  const tpl = $('#upload-tpl').content.cloneNode(true);
  app.replaceChildren(tpl);
  const dz = $('#dropzone');
  const input = $('#file-input');
  const go = (file) => {
    if (!file) return;
    const type = file.type.split('/')[0];
    mediaMode({ file, type: ['image', 'video', 'audio'].includes(type) ? type : 'image' }).catch((e) => fail(`Could not scan ${file.name}: ${e.message}`));
  };
  input.addEventListener('change', () => go(input.files[0]));
  dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('drag'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag'));
  dz.addEventListener('drop', (e) => { e.preventDefault(); dz.classList.remove('drag'); go(e.dataTransfer.files[0]); });
  window.addEventListener('paste', (e) => go([...(e.clipboardData?.files || [])][0]), { once: true });
}

// ==================================================================
// History entry
// ==================================================================
async function historyMode(id) {
  const items = await send({ type: 'getHistory' });
  const item = items.find((i) => i.id === id);
  if (!item) return fail('This history entry no longer exists.');
  if (item.type !== 'media') {
    renderUrlResult({ ...item, reason: item.summary, url: item.target, input: item.target }, { stored: true });
    return;
  }
  setTitle('Saved media scan');
  const d = item.details || {};
  const result = { probability: item.probability ?? 0, level: item.level, verdict: item.summary, confidence: d.confidence || 'low', basis: d.basis || '', signals: d.signals || [] };
  const canRescan = /^https?:/.test(item.target);
  app.replaceChildren(
    h('section', { class: `card hero ${item.level}` },
      h('div', { class: 'grow' },
        levelPill(item.level, item.summary),
        h('div', { class: 'hero-title' }, truncateMiddle(item.target, 90)),
        h('div', { class: 'hero-sub' }, `${d.format || ''} ${item.mediaType} · ${fmtBytes(d.size)} · scanned ${timeAgo(item.ts)}`),
        canRescan ? h('a', { class: 'btn', style: { marginTop: '8px' }, href: `?${new URLSearchParams({ mode: 'media', src: item.target, type: item.mediaType })}` }, '↻ Re-scan') : null)),
    h('div', { class: 'grid' },
      h('div', { class: 'col' },
        probabilityCard(result, d.ai, d.aiError, { showConfigHint: !d.ai }),
        d.ela ? card('Error level analysis', kv([['Mean error', d.ela.mean], ['Std deviation', d.ela.std], ['Block variation', d.ela.blockStd]])) : null),
      h('div', { class: 'col' },
        d.embedded ? embeddedCard(d.embedded) : null,
        provenanceCard({ c2pa: d.c2pa, markers: d.markers || [], metadataStripped: false }),
        card('EXIF', kv(Object.entries(d.exif || {}))),
        h('p', { class: 'notice' }, 'The media itself is not stored in history — re-scan to view the heatmap or timeline.'))));
}

// ==================================================================
// Router
// ==================================================================
(async () => {
  try {
    switch (params.get('mode')) {
      case 'url': return await urlMode(params.get('url'));
      case 'media': return await mediaMode({ src: params.get('src'), type: params.get('type'), pageUrl: params.get('page'), tabId: params.get('tab') });
      case 'history': return await historyMode(params.get('id'));
      default: return uploadMode();
    }
  } catch (e) {
    fail(e.message || String(e));
  }
})();
