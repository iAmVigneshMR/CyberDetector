// AI-generated / deepfake detection via third-party APIs.
// Each adapter returns a normalised result:
//   { provider, score: 0..1, scores: {label: 0..1}, frames: [{time, score}], regions: [{x,y,w,h,score}], note }
//
// Endpoints and response fields follow each provider's public docs at the time of
// writing — if a provider changes its API, adjust the adapter here.

const extFor = (mime) => (mime.split('/')[1] || 'bin').replace('jpeg', 'jpg').replace('quicktime', 'mov').replace('mpeg', 'mp3').split(';')[0];

function fileName(blob, fallbackType) {
  return `media.${extFor(blob.type || fallbackType)}`;
}

async function asJson(res) {
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
  }
  if (!res.ok) throw new Error(json.error?.message || json.message || json.error || `HTTP ${res.status}`);
  return json;
}

// ------------------------------------------------------------------
// Sightengine — image & video (models: genai = AI-generated, deepfake = face swap)
// ------------------------------------------------------------------
async function sightengine({ blob, src, mediaType, settings, duration }) {
  if (!settings.sightengineUser || !settings.sightengineSecret) throw new Error('Sightengine API user/secret not configured');
  if (mediaType === 'audio') throw new Error('Sightengine does not analyse audio — choose Hive or a custom endpoint for audio.');
  const fd = new FormData();
  fd.set('models', 'genai,deepfake');
  fd.set('api_user', settings.sightengineUser);
  fd.set('api_secret', settings.sightengineSecret);
  const useUrl = settings.mediaSendMode === 'url' && /^https?:/.test(src || '');
  if (mediaType === 'video') {
    if (duration > 60) throw new Error(`Sightengine's synchronous video API only accepts clips under 60 s (this one is ${Math.round(duration)} s).`);
    if (useUrl) fd.set('stream_url', src); else fd.set('media', blob, fileName(blob, 'video/mp4'));
    const json = await asJson(await fetch('https://api.sightengine.com/1.0/video/check-sync.json', { method: 'POST', body: fd, signal: AbortSignal.timeout(120000) }));
    if (json.status !== 'success') throw new Error(json.error?.message || 'Sightengine error');
    const frames = (json.data?.frames || []).map((f) => ({
      time: f.info?.position ?? 0,
      score: Math.max(f.type?.ai_generated ?? 0, f.type?.deepfake ?? 0),
      ai: f.type?.ai_generated, deepfake: f.type?.deepfake,
    }));
    const peak = frames.reduce((m, f) => Math.max(m, f.score), 0);
    const avg = frames.reduce((m, f) => m + f.score, 0) / (frames.length || 1);
    return {
      provider: 'Sightengine', score: Math.max(avg, peak * 0.85),
      scores: { 'AI-generated (peak frame)': Math.max(...frames.map((f) => f.ai ?? 0), 0), 'Deepfake face (peak frame)': Math.max(...frames.map((f) => f.deepfake ?? 0), 0) },
      frames, frameTimeUnit: 'ms', regions: [], // info.position is in milliseconds
    };
  }
  let res;
  if (useUrl) {
    // Documented form for remote images: GET with query parameters.
    const q = new URLSearchParams({ url: src, models: 'genai,deepfake', api_user: settings.sightengineUser, api_secret: settings.sightengineSecret });
    res = await fetch(`https://api.sightengine.com/1.0/check.json?${q}`, { signal: AbortSignal.timeout(60000) });
  } else {
    fd.set('media', blob, fileName(blob, 'image/jpeg'));
    res = await fetch('https://api.sightengine.com/1.0/check.json', { method: 'POST', body: fd, signal: AbortSignal.timeout(60000) });
  }
  const json = await asJson(res);
  if (json.status !== 'success') throw new Error(json.error?.message || 'Sightengine error');
  const ai = json.type?.ai_generated ?? 0;
  const df = json.type?.deepfake ?? 0;
  return { provider: 'Sightengine', score: Math.max(ai, df), scores: { 'AI-generated': ai, 'Deepfake face': df }, frames: [], regions: [] };
}

// ------------------------------------------------------------------
// Hive — image, video, audio (AI-generated content detection)
// ------------------------------------------------------------------
// Documented classes: ai_generated / not_ai_generated, deepfake (yes_deepfake = legacy deepfake-only API).
const HIVE_POSITIVE = /^(ai_generated|deepfake|yes_deepfake)$/i;

async function hive({ blob, src, mediaType, settings }) {
  if (!settings.hiveKey) throw new Error('Hive API key not configured');
  const fd = new FormData();
  if (settings.mediaSendMode === 'url' && /^https?:/.test(src || '')) fd.set('url', src);
  else fd.set('media', blob, fileName(blob, mediaType === 'audio' ? 'audio/mpeg' : mediaType === 'video' ? 'video/mp4' : 'image/jpeg'));
  const json = await asJson(await fetch('https://api.thehive.ai/api/v2/task/sync', {
    method: 'POST',
    headers: { authorization: `token ${settings.hiveKey}`, accept: 'application/json' },
    body: fd,
    signal: AbortSignal.timeout(120000),
  }));
  const outputs = json.status?.[0]?.response?.output || [];
  if (!outputs.length) throw new Error('Hive returned no output');
  const frames = [];
  const best = {};
  for (const o of outputs) {
    let s = 0;
    for (const c of o.classes || []) {
      if (HIVE_POSITIVE.test(c.class)) s = Math.max(s, c.score);
      if (HIVE_POSITIVE.test(c.class) || /^(not_ai_generated|no_deepfake)$/.test(c.class)) continue;
      // Generator attribution classes (e.g. "midjourney", "dalle", "sora") — keep the strongest few.
      if (c.score > 0.2 && !/^(none|inconclusive|other_image_generators)/.test(c.class)) best[c.class] = Math.max(best[c.class] || 0, c.score);
    }
    frames.push({ time: o.time ?? 0, end: o.end_time, score: s }); // audio: 10 s chunks with end_time
  }
  const peak = Math.max(...frames.map((f) => f.score));
  const avg = frames.reduce((m, f) => m + f.score, 0) / frames.length;
  const top = Object.entries(best).sort((a, b) => b[1] - a[1]).slice(0, 4);
  return {
    provider: 'Hive',
    score: frames.length > 1 ? Math.max(avg, peak * 0.85) : peak,
    scores: { 'AI-generated / deepfake': peak, ...Object.fromEntries(top.map(([k, v]) => [`Source: ${k}`, v])) },
    frames: frames.length > 1 ? frames : [],
    frameTimeUnit: 's',
    regions: [],
  };
}

// ------------------------------------------------------------------
// Custom endpoint — your own model / proxy server.
// Request : multipart POST  file=<media>, mediaType=image|video|audio, sourceUrl=<url>
// Response: { score: 0..1, label?, scores?: {k: v}, frames?: [{time, score}],
//             segments?: [{start, end, score}], regions?: [{x, y, w, h, score}] (0..1 coords) }
// ------------------------------------------------------------------
async function custom({ blob, src, mediaType, settings, endpoint = settings.customEndpoint, token = settings.customToken, name = 'Custom endpoint' }) {
  if (!endpoint) throw new Error(`${name}: endpoint URL not configured`);
  const fd = new FormData();
  fd.set('file', blob, fileName(blob, 'application/octet-stream'));
  fd.set('mediaType', mediaType);
  if (src) fd.set('sourceUrl', src);
  const headers = token ? { authorization: `Bearer ${token}` } : {};
  let res;
  try {
    res = await fetch(endpoint, { method: 'POST', body: fd, headers, signal: AbortSignal.timeout(300000) });
  } catch (e) {
    throw new Error(name === 'Local detector' ? `Local detector not reachable at ${endpoint} — is the server running? (${e.message})` : e.message);
  }
  const json = await asJson(res);
  const segments = json.segments || [];
  const frames = json.frames || segments.map((s) => ({ time: s.start, end: s.end, score: s.score }));
  return {
    provider: name,
    models: json.models ? Object.values(json.models) : undefined,
    score: Number(json.score ?? json.probability ?? 0),
    scores: json.scores || (json.label ? { [json.label]: Number(json.score ?? 0) } : {}),
    frames,
    frameTimeUnit: 's',
    regions: json.regions || [],
  };
}

// Local open-source detector server (detector-server/ in this repo) — same contract as "custom".
const local = (args) => custom({ ...args, endpoint: args.settings.localEndpoint, token: args.settings.localToken, name: 'Local detector' });

const PROVIDERS = { local, sightengine, hive, custom };

/** Providers that keep media on this computer (no third-party data sharing). */
export const isLocalProvider = (settings) => settings.aiProvider === 'local';

/** Ping the local server's /health endpoint. */
export async function localHealth(settings) {
  const url = settings.localEndpoint.replace(/\/detect\/?$/, '') + '/health';
  const res = await fetch(url, { headers: { authorization: `Bearer ${settings.localToken}` }, signal: AbortSignal.timeout(5000) });
  return asJson(res);
}

export function providerConfigured(settings) {
  switch (settings.aiProvider) {
    case 'sightengine': return !!(settings.sightengineUser && settings.sightengineSecret);
    case 'hive': return !!settings.hiveKey;
    case 'custom': return !!settings.customEndpoint;
    case 'local': return !!(settings.localEndpoint && settings.localToken);
    default: return false;
  }
}

export async function detectAI(args) {
  const fn = PROVIDERS[args.settings.aiProvider];
  if (!fn) return null;
  const r = await fn(args);
  r.score = Math.min(1, Math.max(0, Number(r.score) || 0));
  return r;
}
