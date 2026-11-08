// Error Level Analysis (ELA): re-save the image as JPEG at a known quality and
// measure how much each pixel changes. Regions pasted in or edited after the last
// save often recompress differently from the rest of the image and "light up".
// ELA is a forensic aid, not proof — always read it alongside other evidence.

// Compact "inferno"-like colour ramp, 0..255 → [r,g,b]
const RAMP = [
  [0, [0, 0, 4]], [40, [40, 11, 84]], [80, [101, 21, 110]], [120, [159, 42, 99]],
  [160, [212, 72, 66]], [200, [245, 125, 21]], [230, [250, 193, 39]], [255, [252, 255, 164]],
];
const LUT = new Uint8Array(256 * 3);
for (let v = 0; v < 256; v++) {
  let i = 0;
  while (i < RAMP.length - 2 && v > RAMP[i + 1][0]) i++;
  const [a, ca] = RAMP[i], [b, cb] = RAMP[i + 1];
  const t = (v - a) / (b - a || 1);
  for (let c = 0; c < 3; c++) LUT[v * 3 + c] = Math.round(ca[c] + (cb[c] - ca[c]) * t);
}

/**
 * @param {Blob} blob image
 * @param {{quality?: number, amplify?: number, maxDim?: number}} opts
 * @returns {Promise<{width, height, heatmap: ImageData, stats: object, hotspots: object[], downscaled: boolean}>}
 */
export async function errorLevelAnalysis(blob, { quality = 0.9, amplify = 20, maxDim = 3000 } = {}) {
  const bmp = await createImageBitmap(blob);
  const ratio = Math.min(1, maxDim / Math.max(bmp.width, bmp.height));
  const w = Math.max(1, Math.round(bmp.width * ratio));
  const h = Math.max(1, Math.round(bmp.height * ratio));

  const c1 = new OffscreenCanvas(w, h);
  const x1 = c1.getContext('2d', { willReadFrequently: true });
  x1.drawImage(bmp, 0, 0, w, h);
  bmp.close?.();
  const orig = x1.getImageData(0, 0, w, h).data;

  const jpeg = await c1.convertToBlob({ type: 'image/jpeg', quality });
  const bmp2 = await createImageBitmap(jpeg);
  const c2 = new OffscreenCanvas(w, h);
  const x2 = c2.getContext('2d', { willReadFrequently: true });
  x2.drawImage(bmp2, 0, 0);
  bmp2.close?.();
  const re = x2.getImageData(0, 0, w, h).data;

  const heat = new ImageData(w, h);
  const hd = heat.data;
  const diff = new Uint8Array(w * h);
  let sum = 0, sumSq = 0, max = 0;
  for (let p = 0, i = 0; p < w * h; p++, i += 4) {
    const d = Math.max(Math.abs(orig[i] - re[i]), Math.abs(orig[i + 1] - re[i + 1]), Math.abs(orig[i + 2] - re[i + 2]));
    diff[p] = d;
    sum += d;
    sumSq += d * d;
    if (d > max) max = d;
    const v = Math.min(255, d * amplify);
    hd[i] = LUT[v * 3];
    hd[i + 1] = LUT[v * 3 + 1];
    hd[i + 2] = LUT[v * 3 + 2];
    hd[i + 3] = v < 12 ? v * 8 : 235;
  }
  const n = w * h;
  const mean = sum / n;
  const std = Math.sqrt(Math.max(0, sumSq / n - mean * mean));

  // Block statistics → hotspots whose error level is far above the image average.
  const GRID = 16;
  const bw = Math.ceil(w / GRID), bh = Math.ceil(h / GRID);
  const blocks = [];
  for (let by = 0; by < GRID; by++) {
    for (let bx = 0; bx < GRID; bx++) {
      let s = 0, c = 0;
      for (let y = by * bh; y < Math.min(h, (by + 1) * bh); y++) {
        for (let x = bx * bw; x < Math.min(w, (bx + 1) * bw); x++) { s += diff[y * w + x]; c++; }
      }
      if (c) blocks.push({ bx, by, mean: s / c });
    }
  }
  const bMean = blocks.reduce((a, b) => a + b.mean, 0) / (blocks.length || 1);
  const bStd = Math.sqrt(blocks.reduce((a, b) => a + (b.mean - bMean) ** 2, 0) / (blocks.length || 1));
  const hotspots = blocks
    .filter((b) => bStd > 0.15 && b.mean > bMean + 2.5 * bStd && b.mean > 1.5)
    .sort((a, b) => b.mean - a.mean)
    .slice(0, 12)
    .map((b) => ({ x: b.bx / GRID, y: b.by / GRID, w: 1 / GRID, h: 1 / GRID, score: Math.min(1, (b.mean - bMean) / (bStd * 6 || 1)) }));

  return {
    width: w,
    height: h,
    heatmap: heat,
    downscaled: ratio < 1,
    stats: { mean: +mean.toFixed(2), std: +std.toFixed(2), max, blockStd: +bStd.toFixed(2), hotspotRatio: hotspots.length / (GRID * GRID) },
    hotspots,
  };
}
