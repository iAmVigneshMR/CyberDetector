// Browser-side decoders for embedded image content. Everything runs locally:
//   QR / barcodes — native BarcodeDetector when available (ChromeOS, macOS, Android),
//                   otherwise the bundled jsQR decoder (QR only).
//   Text (OCR)    — bundled Tesseract.js (WASM) with English LSTM data; nothing is downloaded.
// The vendor/ files are copied from node_modules by scripts/build.mjs.

const vendor = (p) => new URL(`../vendor/${p}`, import.meta.url).href;

async function loadBitmap(blob) {
  return createImageBitmap(blob);
}

function pixels(bmp, maxSide) {
  const scale = Math.min(1, maxSide / Math.max(bmp.width, bmp.height));
  const w = Math.max(1, Math.round(bmp.width * scale));
  const h = Math.max(1, Math.round(bmp.height * scale));
  const c = new OffscreenCanvas(w, h);
  const ctx = c.getContext('2d', { willReadFrequently: true });
  ctx.fillStyle = '#fff'; // transparent PNG backgrounds → white, so dark modules stay dark
  ctx.fillRect(0, 0, w, h);
  ctx.drawImage(bmp, 0, 0, w, h);
  return ctx.getImageData(0, 0, w, h);
}

async function nativeDetector() {
  if (typeof globalThis.BarcodeDetector !== 'function') return null;
  try {
    const formats = await globalThis.BarcodeDetector.getSupportedFormats();
    if (!formats.includes('qr_code')) return null;
    return new globalThis.BarcodeDetector({ formats });
  } catch {
    return null;
  }
}

let jsQRPromise;
function loadJsQR() {
  // UMD bundle: attaches self.jsQR when no module system is present.
  jsQRPromise ||= import('../vendor/jsqr/jsQR.js').then(() => {
    if (typeof globalThis.jsQR !== 'function') throw new Error('QR decoder failed to load');
    return globalThis.jsQR;
  });
  return jsQRPromise;
}

/**
 * Decode QR codes (and other barcodes where the browser supports them).
 * jsQR finds one code per pass, so the image is also searched in overlapping tiles.
 * @param {Blob} blob
 * @returns {Promise<{codes: Array<{raw: string, format: string}>, engine: string}>}
 */
export async function decodeQrCodes(blob) {
  const bmp = await loadBitmap(blob);
  try {
    const native = await nativeDetector();
    if (native) {
      const found = await native.detect(bmp);
      const codes = dedupe(found.map((b) => ({ raw: b.rawValue, format: b.format })));
      return { codes, engine: 'BarcodeDetector' };
    }

    const jsQR = await loadJsQR();
    const codes = [];
    const tryDecode = (img) => {
      const r = jsQR(img.data, img.width, img.height, { inversionAttempts: 'attemptBoth' });
      if (r?.data) codes.push({ raw: r.data, format: 'qr_code' });
    };
    // Whole image at two scales (small codes need resolution; huge photos are slow and noisy).
    tryDecode(pixels(bmp, 1600));
    if (!codes.length && Math.max(bmp.width, bmp.height) > 900) tryDecode(pixels(bmp, 800));
    // 3×3 overlapping tiles: finds additional / small codes in posters and screenshots.
    if (Math.max(bmp.width, bmp.height) >= 600) {
      const full = pixels(bmp, 2400);
      const tw = Math.round(full.width / 2);
      const th = Math.round(full.height / 2);
      const c = new OffscreenCanvas(full.width, full.height);
      const ctx = c.getContext('2d', { willReadFrequently: true });
      ctx.putImageData(full, 0, 0);
      for (const fy of [0, 0.25, 0.5]) {
        for (const fx of [0, 0.25, 0.5]) {
          tryDecode(ctx.getImageData(Math.round(full.width * fx), Math.round(full.height * fy), tw, th));
        }
      }
    }
    return { codes: dedupe(codes), engine: 'jsQR' };
  } finally {
    bmp.close?.();
  }
}

function dedupe(codes) {
  const seen = new Set();
  return codes.filter((c) => c.raw && !seen.has(c.raw) && seen.add(c.raw)).slice(0, 10);
}

/**
 * Read text from an image with Tesseract (English).
 * @param {Blob} blob
 * @param {{onProgress?: (p: number, status: string) => void, timeoutMs?: number}} opts
 * @returns {Promise<{text: string, confidence: number}>}
 */
export async function recognizeText(blob, { onProgress, timeoutMs = 90000 } = {}) {
  const { default: Tesseract } = await import('../vendor/tesseract/tesseract.esm.min.js');
  const worker = await Tesseract.createWorker('eng', Tesseract.OEM.LSTM_ONLY, {
    workerPath: vendor('tesseract/worker.min.js'),
    corePath: vendor('tesseract/tesseract-core-simd-lstm.wasm.js'),
    langPath: vendor('tesseract/lang'),
    workerBlobURL: false, // blob: workers are blocked by the extension CSP
    gzip: true,
    cacheMethod: 'none', // data is bundled; no need to copy it into IndexedDB
    logger: (m) => onProgress?.(m.progress ?? 0, m.status || ''),
  });
  let timer;
  try {
    // Upscale small images: Tesseract needs ~20px+ glyphs. Large ones are capped for speed.
    const bmp = await loadBitmap(blob);
    const longest = Math.max(bmp.width, bmp.height);
    const target = longest < 1000 ? Math.min(2000, longest * 2) : Math.min(longest, 3000);
    const scale = target / longest;
    const c = new OffscreenCanvas(Math.round(bmp.width * scale), Math.round(bmp.height * scale));
    const ctx = c.getContext('2d');
    ctx.fillStyle = '#fff';
    ctx.fillRect(0, 0, c.width, c.height);
    ctx.imageSmoothingQuality = 'high';
    ctx.drawImage(bmp, 0, 0, c.width, c.height);
    bmp.close?.();
    const png = await c.convertToBlob({ type: 'image/png' });

    const job = worker.recognize(png);
    const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('text recognition timed out')), timeoutMs); });
    const { data } = await Promise.race([job, timeout]);
    return { text: data.text || '', confidence: Math.round(data.confidence ?? 0) };
  } finally {
    clearTimeout(timer);
    worker.terminate().catch(() => {});
  }
}
