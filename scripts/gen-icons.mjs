// Generates the shield toolbar icons as PNGs with no dependencies (zlib only).
// node scripts/gen-icons.mjs
import { deflateSync } from 'node:zlib';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const outDir = path.join(path.dirname(path.dirname(fileURLToPath(import.meta.url))), 'src', 'icons');

const CRC_TABLE = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
const crc32 = (buf) => {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
function png(size, rgba) {
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}

// Shape functions in unit coordinates (0..1).
function inShield(x, y) {
  const cx = 0.5;
  if (y < 0.08 || y > 0.94) return false;
  const top = 0.08 + 0.06 * Math.abs(x - cx) / 0.4; // slight notch at top centre
  if (y < top && Math.abs(x - cx) < 0.4) return false;
  if (y <= 0.55) return Math.abs(x - cx) <= 0.4;
  // tapered bottom (quadratic curve to a point)
  const t = (y - 0.55) / (0.94 - 0.55);
  const half = 0.4 * (1 - t * t);
  return Math.abs(x - cx) <= half;
}
function inEye(x, y) {
  // Almond-shaped "eye" with pupil: scanning / detection motif
  const cx = 0.5, cy = 0.46;
  const dx = (x - cx) / 0.27, dy = (y - cy) / 0.15;
  const almond = Math.abs(dy) <= (1 - dx * dx) && Math.abs(dx) <= 1;
  return almond;
}
const inPupil = (x, y) => (x - 0.5) ** 2 + (y - 0.46) ** 2 <= 0.085 ** 2;
const inGlint = (x, y) => (x - 0.53) ** 2 + (y - 0.43) ** 2 <= 0.025 ** 2;

function render(size) {
  const SS = 4; // supersampling
  const buf = Buffer.alloc(size * size * 4);
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let r = 0, g = 0, b = 0, a = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const x = (px + (sx + 0.5) / SS) / size;
          const y = (py + (sy + 0.5) / SS) / size;
          if (!inShield(x, y)) continue;
          let col;
          if (inGlint(x, y)) col = [255, 255, 255];
          else if (inPupil(x, y)) col = [11, 17, 32];
          else if (inEye(x, y)) col = [240, 249, 255];
          else {
            // vertical gradient sky-500 → blue-800
            const t = y;
            col = [Math.round(14 + (30 - 14) * t), Math.round(165 + (64 - 165) * t), Math.round(233 + (175 - 233) * t)];
          }
          r += col[0]; g += col[1]; b += col[2]; a += 255;
        }
      }
      const n = SS * SS;
      const covered = a / 255;
      const i = (py * size + px) * 4;
      if (covered) {
        buf[i] = Math.round(r / covered);
        buf[i + 1] = Math.round(g / covered);
        buf[i + 2] = Math.round(b / covered);
      }
      buf[i + 3] = Math.round(a / n);
    }
  }
  return png(size, buf);
}

for (const size of [16, 32, 48, 128]) {
  writeFileSync(path.join(outDir, `icon-${size}.png`), render(size));
  console.log(`✓ icon-${size}.png`);
}
