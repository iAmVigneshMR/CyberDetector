// Dependency-free metadata extraction for images, video and audio:
//   JPEG (EXIF, XMP, C2PA/JUMBF in APP11, Photoshop IRB), PNG (tEXt/iTXt/zTXt, eXIf, caBX),
//   WebP / WAV (RIFF chunks), ISO-BMFF (MP4/MOV/M4A/HEIC/AVIF incl. C2PA uuid box), MP3 (ID3v2).
// C2PA manifests are DETECTED and their claim generator / actions / digital source type are
// read, but signatures are NOT cryptographically verified (that requires the c2pa SDK).

const latin1 = new TextDecoder('latin1');
const utf8 = new TextDecoder('utf-8');
const ascii = (b, o, n) => latin1.decode(b.subarray(o, o + n));
const u16be = (b, o) => (b[o] << 8) | b[o + 1];
const u32be = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
const u32le = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;

function startsWith(b, str, off = 0) {
  for (let i = 0; i < str.length; i++) if (b[off + i] !== str.charCodeAt(i)) return false;
  return true;
}

function indexOfBytes(b, needle, from = 0, to = b.length) {
  const n0 = needle[0];
  outer: for (let i = from; i <= to - needle.length; i++) {
    if (b[i] !== n0) continue;
    for (let j = 1; j < needle.length; j++) if (b[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}
const bytesOf = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0));

async function inflate(data) {
  const ds = new DecompressionStream('deflate');
  const buf = await new Response(new Blob([data]).stream().pipeThrough(ds)).arrayBuffer();
  return new Uint8Array(buf);
}

// ------------------------------------------------------------------
// Format sniffing
// ------------------------------------------------------------------
export function sniffFormat(b) {
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return { format: 'JPEG', kind: 'image' };
  if (startsWith(b, '\x89PNG')) return { format: 'PNG', kind: 'image' };
  if (startsWith(b, 'GIF8')) return { format: 'GIF', kind: 'image' };
  if (startsWith(b, 'RIFF') && startsWith(b, 'WEBP', 8)) return { format: 'WebP', kind: 'image' };
  if (startsWith(b, 'RIFF') && startsWith(b, 'WAVE', 8)) return { format: 'WAV', kind: 'audio' };
  if (startsWith(b, 'RIFF') && startsWith(b, 'AVI ', 8)) return { format: 'AVI', kind: 'video' };
  if (startsWith(b, 'ftyp', 4)) {
    const brand = ascii(b, 8, 4);
    if (/^(heic|heix|mif1|msf1|hevc)/.test(brand)) return { format: 'HEIC', kind: 'image' };
    if (/^avi[fs]/.test(brand)) return { format: 'AVIF', kind: 'image' };
    if (/^(M4A |M4B |mp42)/.test(brand) && brand.startsWith('M4')) return { format: 'M4A', kind: 'audio' };
    return { format: brand.trim() === 'qt' ? 'MOV' : 'MP4', kind: 'video' };
  }
  if (b[0] === 0x1a && b[1] === 0x45 && b[2] === 0xdf && b[3] === 0xa3) return { format: 'WebM/MKV', kind: 'video' };
  if (startsWith(b, 'ID3') || (b[0] === 0xff && (b[1] & 0xe0) === 0xe0)) return { format: 'MP3', kind: 'audio' };
  if (startsWith(b, 'OggS')) return { format: 'Ogg', kind: 'audio' };
  if (startsWith(b, 'fLaC')) return { format: 'FLAC', kind: 'audio' };
  if (startsWith(b, '<?xml') || startsWith(b, '<svg')) return { format: 'SVG', kind: 'image' };
  if (startsWith(b, 'II*\0') || startsWith(b, 'MM\0*')) return { format: 'TIFF', kind: 'image' };
  return { format: 'Unknown', kind: 'unknown' };
}

// ------------------------------------------------------------------
// TIFF / EXIF
// ------------------------------------------------------------------
const IFD0_TAGS = {
  0x010e: 'ImageDescription', 0x010f: 'Make', 0x0110: 'Model', 0x0112: 'Orientation', 0x0131: 'Software',
  0x0132: 'DateTime', 0x013b: 'Artist', 0x8298: 'Copyright', 0xa002: 'PixelXDimension', 0xa003: 'PixelYDimension',
};
const EXIF_TAGS = {
  0x829a: 'ExposureTime', 0x829d: 'FNumber', 0x8827: 'ISO', 0x9003: 'DateTimeOriginal', 0x9004: 'DateTimeDigitized',
  0x9010: 'OffsetTime', 0x9209: 'Flash', 0x920a: 'FocalLength', 0x9286: 'UserComment', 0xa002: 'PixelXDimension',
  0xa003: 'PixelYDimension', 0xa420: 'ImageUniqueID', 0xa431: 'BodySerialNumber', 0xa433: 'LensMake', 0xa434: 'LensModel',
  0x9291: 'SubSecTimeOriginal', 0xa402: 'ExposureMode', 0xa403: 'WhiteBalance',
};
const GPS_TAGS = { 1: 'GPSLatitudeRef', 2: 'GPSLatitude', 3: 'GPSLongitudeRef', 4: 'GPSLongitude', 6: 'GPSAltitude' };
const TYPE_SIZE = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8 };

export function parseTIFF(t, out) {
  if (t.length < 8) return;
  const le = t[0] === 0x49;
  const u16 = (o) => (le ? t[o] | (t[o + 1] << 8) : (t[o] << 8) | t[o + 1]);
  const u32 = (o) => (le ? u32le(t, o) : u32be(t, o));
  const s32 = (o) => u32(o) | 0;
  if (u16(2) !== 42) return;

  const readValue = (type, count, off) => {
    switch (type) {
      case 2: return latin1.decode(t.subarray(off, off + count)).replace(/\0+$/, '').trim();
      case 3: return count === 1 ? u16(off) : Array.from({ length: Math.min(count, 16) }, (_, i) => u16(off + i * 2));
      case 4: return count === 1 ? u32(off) : Array.from({ length: Math.min(count, 16) }, (_, i) => u32(off + i * 4));
      case 5:
      case 10: {
        const vals = Array.from({ length: Math.min(count, 8) }, (_, i) => {
          const n = type === 5 ? u32(off + i * 8) : s32(off + i * 8);
          const d = type === 5 ? u32(off + i * 8 + 4) : s32(off + i * 8 + 4);
          return d ? n / d : 0;
        });
        return count === 1 ? vals[0] : vals;
      }
      case 7: {
        const raw = t.subarray(off, off + Math.min(count, 2048));
        if (startsWith(raw, 'ASCII\0\0\0')) return latin1.decode(raw.subarray(8)).replace(/\0+$/, '').trim();
        if (startsWith(raw, 'UNICODE\0')) return new TextDecoder(le ? 'utf-16le' : 'utf-16be').decode(raw.subarray(8)).replace(/\0+$/, '').trim();
        const s = latin1.decode(raw).replace(/\0+$/, '');
        return /^[\x20-\x7e]*$/.test(s) ? s.trim() : `(${count} bytes)`;
      }
      default: return undefined;
    }
  };

  const readIFD = (off, tags, target, depth = 0) => {
    if (depth > 3 || off < 8 || off + 2 > t.length) return;
    const n = u16(off);
    for (let k = 0; k < n && k < 512; k++) {
      const e = off + 2 + k * 12;
      if (e + 12 > t.length) break;
      const tag = u16(e), type = u16(e + 2), count = u32(e + 4);
      if (tag === 0x8769) { readIFD(u32(e + 8), EXIF_TAGS, target, depth + 1); continue; }
      if (tag === 0x8825) { out.gpsRaw = {}; readIFD(u32(e + 8), GPS_TAGS, out.gpsRaw, depth + 1); continue; }
      const name = tags[tag];
      if (!name) continue;
      const size = (TYPE_SIZE[type] || 1) * count;
      const valOff = size <= 4 ? e + 8 : u32(e + 8);
      if (valOff + size > t.length) continue;
      const v = readValue(type, count, valOff);
      if (v !== undefined && v !== '') target[name] = v;
    }
  };
  readIFD(u32(4), IFD0_TAGS, out.exif);

  const g = out.gpsRaw;
  if (g?.GPSLatitude && g?.GPSLongitude && Array.isArray(g.GPSLatitude)) {
    const dms = ([d, m, s]) => d + m / 60 + s / 3600;
    const lat = dms(g.GPSLatitude) * (g.GPSLatitudeRef === 'S' ? -1 : 1);
    const lon = dms(g.GPSLongitude) * (g.GPSLongitudeRef === 'W' ? -1 : 1);
    if (Number.isFinite(lat) && Number.isFinite(lon) && (lat || lon)) out.gps = { lat: +lat.toFixed(6), lon: +lon.toFixed(6) };
  }
  delete out.gpsRaw;
}

// ------------------------------------------------------------------
// C2PA / JUMBF
// ------------------------------------------------------------------
function cborTextAt(b, i) {
  // Read a CBOR text string (major type 3) starting at b[i].
  const h = b[i];
  if (h >= 0x60 && h <= 0x77) return utf8.decode(b.subarray(i + 1, i + 1 + (h - 0x60)));
  if (h === 0x78) return utf8.decode(b.subarray(i + 2, i + 2 + b[i + 1]));
  if (h === 0x79) return utf8.decode(b.subarray(i + 3, i + 3 + u16be(b, i + 1)));
  return null;
}

function cborValueAfterKey(b, key, limit = 6) {
  const results = [];
  const needle = bytesOf(key);
  let from = 0;
  while (results.length < limit) {
    const idx = indexOfBytes(b, needle, from);
    if (idx < 0) break;
    const v = cborTextAt(b, idx + needle.length);
    if (v && /^[\p{L}\p{N}\p{P}\p{Zs}\/._+()-]{2,200}$/u.test(v)) results.push(v);
    from = idx + needle.length;
  }
  return results;
}

// IPTC Digital Source Type vocabulary (longest first so "compositeWith…" wins over "composite").
const IPTC_SOURCE_TYPES = [
  'compositeWithTrainedAlgorithmicMedia', 'trainedAlgorithmicMedia', 'algorithmicallyEnhanced', 'algorithmicMedia',
  'compositeSynthetic', 'compositeCapture', 'composite', 'digitalCapture', 'digitalCreation', 'digitalArt', 'dataDrivenMedia',
  'minorHumanEdits', 'humanEdits', 'negativeFilm', 'positiveFilm', 'print', 'screenCapture', 'virtualRecording',
];
const SOURCE_TYPE_RE = new RegExp(`digitalsourcetype/(${IPTC_SOURCE_TYPES.join('|')})`, 'g');

export function sourceTypesIn(text) {
  return [...new Set([...text.matchAll(SOURCE_TYPE_RE)].map((m) => m[1]))];
}

export function parseC2PA(b) {
  const text = latin1.decode(b);
  // v1 claims: "claim_generator": "<text>"
  const generators = cborValueAfterKey(b, '\x6fclaim_generator');
  // v2 claims: "claim_generator_info": [{ "name": "<text>", ... }] — only read "name" right after that key.
  const infoKey = bytesOf('\x74claim_generator_info');
  for (let from = 0, idx; (idx = indexOfBytes(b, infoKey, from)) >= 0 && generators.length < 6; from = idx + infoKey.length) {
    const nameIdx = indexOfBytes(b, bytesOf('\x64name'), idx, Math.min(b.length, idx + 300));
    const v = nameIdx > 0 ? cborTextAt(b, nameIdx + 5) : null;
    if (v) generators.push(v);
  }
  const actions = [...new Set(text.match(/c2pa\.(?:created|edited|opened|placed|converted|cropped|drawing|filtered|color_adjustments|resized|transcoded|repackaged|published|removed|watermarked|unknown)/g) || [])];
  const issuers = [...new Set((text.match(/(?:Adobe|OpenAI|Google|Microsoft|Truepic|Leica|Sony|Nikon|Canon|Samsung|Qualcomm|BBC|Meta|Content Credentials)[\w .,-]{0,40}/g) || []).map((s) => s.trim()))].slice(0, 6);
  return {
    present: true,
    claimGenerators: [...new Set(generators)].slice(0, 6),
    actions,
    digitalSourceTypes: sourceTypesIn(text),
    signerHints: issuers,
    hasIngredients: /c2pa\.ingredient/.test(text),
    verified: false,
  };
}

// ------------------------------------------------------------------
// Format parsers
// ------------------------------------------------------------------
function parseJPEG(b, out) {
  let i = 2;
  const jumbf = [];
  while (i + 4 <= b.length) {
    if (b[i] !== 0xff) { i++; continue; }
    const marker = b[i + 1];
    if (marker === 0xff) { i++; continue; }
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { i += 2; continue; }
    if (marker === 0xda || marker === 0xd9) break;
    const len = u16be(b, i + 2);
    const seg = b.subarray(i + 4, i + 2 + len);
    if (marker === 0xe1) {
      if (startsWith(seg, 'Exif\0\0')) parseTIFF(seg.subarray(6), out);
      else if (startsWith(seg, 'http://ns.adobe.com/xap/1.0/\0')) out.xmp += utf8.decode(seg.subarray(29));
      else if (startsWith(seg, 'http://ns.adobe.com/xmp/extension/\0')) out.xmp += utf8.decode(seg.subarray(75));
    } else if (marker === 0xeb) {
      jumbf.push(seg);
    } else if (marker === 0xed && startsWith(seg, 'Photoshop 3.0')) {
      out.flags.photoshopIRB = true;
    } else if (marker === 0xfe) {
      out.text.Comment = latin1.decode(seg).slice(0, 500);
    } else if (marker === 0xc0 || marker === 0xc2) {
      out.height = u16be(seg, 1);
      out.width = u16be(seg, 3);
      out.flags.progressive = marker === 0xc2;
    } else if (marker === 0xdb) {
      out.flags.quantTables = (out.flags.quantTables || 0) + 1;
    }
    i += 2 + len;
  }
  if (jumbf.length) {
    const total = new Uint8Array(jumbf.reduce((n, s) => n + s.length, 0));
    let o = 0;
    for (const s of jumbf) { total.set(s, o); o += s.length; }
    if (indexOfBytes(total, bytesOf('c2pa')) >= 0) out.c2pa = parseC2PA(total);
  }
}

async function parsePNG(b, out) {
  let i = 8;
  while (i + 12 <= b.length) {
    const n = u32be(b, i);
    const type = ascii(b, i + 4, 4);
    const data = b.subarray(i + 8, i + 8 + n);
    if (type === 'IHDR') { out.width = u32be(data, 0); out.height = u32be(data, 4); }
    else if (type === 'tEXt') {
      const z = data.indexOf(0);
      out.text[latin1.decode(data.subarray(0, z))] = latin1.decode(data.subarray(z + 1)).slice(0, 20000);
    } else if (type === 'zTXt') {
      const z = data.indexOf(0);
      try { out.text[latin1.decode(data.subarray(0, z))] = latin1.decode(await inflate(data.subarray(z + 2))).slice(0, 20000); } catch { /* ignore */ }
    } else if (type === 'iTXt') {
      const z = data.indexOf(0);
      const key = latin1.decode(data.subarray(0, z));
      const compressed = data[z + 1] === 1;
      let p = z + 3;
      p = data.indexOf(0, p) + 1; // language tag
      p = data.indexOf(0, p) + 1; // translated keyword
      let body = data.subarray(p);
      try { if (compressed) body = await inflate(body); } catch { body = new Uint8Array(); }
      const val = utf8.decode(body);
      if (key === 'XML:com.adobe.xmp') out.xmp += val;
      else out.text[key] = val.slice(0, 20000);
    } else if (type === 'eXIf') parseTIFF(data, out);
    else if (type === 'caBX') out.c2pa = parseC2PA(data);
    else if (type === 'acTL') out.flags.animated = true;
    else if (type === 'IEND') break;
    i += 12 + n;
  }
}

function parseRIFF(b, out) {
  let i = 12;
  while (i + 8 <= b.length) {
    const id = ascii(b, i, 4);
    const size = u32le(b, i + 4);
    const data = b.subarray(i + 8, i + 8 + size);
    if (id === 'VP8X') { out.width = 1 + (data[4] | (data[5] << 8) | (data[6] << 16)); out.height = 1 + (data[7] | (data[8] << 8) | (data[9] << 16)); }
    else if (id === 'VP8 ' && data.length > 10) { out.width = (data[6] | (data[7] << 8)) & 0x3fff; out.height = (data[8] | (data[9] << 8)) & 0x3fff; }
    else if (id === 'VP8L' && data.length > 5) { const v = u32le(data, 1); out.width = (v & 0x3fff) + 1; out.height = ((v >> 14) & 0x3fff) + 1; }
    else if (id === 'EXIF') parseTIFF(startsWith(data, 'Exif\0\0') ? data.subarray(6) : data, out);
    else if (id === 'XMP ') out.xmp += utf8.decode(data);
    else if (id === 'C2PA') out.c2pa = parseC2PA(data);
    else if (id === 'fmt ' && data.length >= 16) { out.audio = { channels: data[2] | (data[3] << 8), sampleRate: u32le(data, 4), bitsPerSample: data[14] | (data[15] << 8) }; }
    else if (id === 'LIST' && startsWith(data, 'INFO')) {
      let j = 4;
      const INFO = { ISFT: 'Software', ICMT: 'Comment', INAM: 'Title', IART: 'Artist', ICRD: 'Created', IENG: 'Engineer' };
      while (j + 8 <= data.length) {
        const sid = ascii(data, j, 4), ssz = u32le(data, j + 4);
        const v = latin1.decode(data.subarray(j + 8, j + 8 + ssz)).replace(/\0+$/, '').trim();
        if (v) out.text[INFO[sid] || sid] = v;
        j += 8 + ssz + (ssz & 1);
      }
    }
    i += 8 + size + (size & 1);
  }
}

const C2PA_UUID = 'd8fec3d61b0e483c92975828877ec481';
const XMP_UUID = 'be7acfcb97a942e89c71999491e3afac';
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

function parseBMFF(b, out, start = 0, end = b.length, depth = 0) {
  let i = start;
  while (i + 8 <= end && depth < 6) {
    let size = u32be(b, i);
    const type = ascii(b, i + 4, 4);
    let header = 8;
    if (size === 1) { size = Number((BigInt(u32be(b, i + 8)) << 32n) | BigInt(u32be(b, i + 12))); header = 16; }
    else if (size === 0) size = end - i;
    if (size < header) break;
    const boxEnd = Math.min(i + size, end);
    if (type === 'ftyp') out.text.Brand = ascii(b, i + 8, 4).trim();
    else if (type === 'uuid') {
      const id = hex(b.subarray(i + header, i + header + 16));
      if (id === C2PA_UUID) out.c2pa = parseC2PA(b.subarray(i + header + 16, boxEnd));
      else if (id === XMP_UUID) out.xmp += utf8.decode(b.subarray(i + header + 16, boxEnd));
    } else if (['moov', 'udta', 'trak', 'mdia', 'minf', 'ilst'].includes(type)) {
      parseBMFF(b, out, i + header, boxEnd, depth + 1);
    } else if (type === 'meta') {
      parseBMFF(b, out, i + header + 4, boxEnd, depth + 1); // full box: version+flags
    } else if (type === 'mvhd') {
      const v = b[i + header];
      const ts = v === 1 ? u32be(b, i + header + 20) : u32be(b, i + header + 12);
      const dur = v === 1 ? u32be(b, i + header + 28) : u32be(b, i + header + 16);
      if (ts) out.duration = dur / ts;
    } else if (type === 'tkhd') {
      const v = b[i + header];
      const off = i + header + (v === 1 ? 88 : 76);
      const w = u32be(b, off) / 65536, h = u32be(b, off + 4) / 65536;
      if (w && h && !out.width) { out.width = w; out.height = h; }
    } else if (type.charCodeAt(0) === 0xa9 || type === 'desc' || type === 'cprt') {
      // iTunes-style metadata: ©too (encoder), ©swr, ©nam, ©cmt, ©day …
      const dataIdx = indexOfBytes(b, bytesOf('data'), i + header, boxEnd);
      if (dataIdx > 0) {
        const v = utf8.decode(b.subarray(dataIdx + 12, boxEnd)).replace(/\0+$/, '').trim();
        const names = { '\xa9too': 'Encoder', '\xa9swr': 'Software', '\xa9nam': 'Title', '\xa9cmt': 'Comment', '\xa9day': 'Date', '\xa9ART': 'Artist', '\xa9mak': 'Make', '\xa9mod': 'Model', '\xa9xyz': 'Location' };
        if (v) out.text[names[type] || type.replace('\xa9', '©')] = v.slice(0, 500);
      }
    }
    i += size;
  }
}

function parseID3(b, out) {
  if (!startsWith(b, 'ID3')) return;
  const ver = b[3];
  const syncsafe = (o) => (b[o] << 21) | (b[o + 1] << 14) | (b[o + 2] << 7) | b[o + 3];
  const end = 10 + syncsafe(6);
  let i = 10;
  const NAMES = { TSSE: 'Encoder settings', TENC: 'Encoded by', TIT2: 'Title', TPE1: 'Artist', TALB: 'Album', TYER: 'Year', TDRC: 'Recorded', TCON: 'Genre', TOOL: 'Tool' };
  const decode = (enc, d) => {
    if (enc === 0) return latin1.decode(d);
    if (enc === 1) return new TextDecoder('utf-16').decode(d);
    if (enc === 2) return new TextDecoder('utf-16be').decode(d);
    return utf8.decode(d);
  };
  while (i + 10 < end && i + 10 < b.length) {
    const id = ascii(b, i, 4);
    if (!/^[A-Z0-9]{4}$/.test(id)) break;
    const size = ver >= 4 ? syncsafe(i + 4) : u32be(b, i + 4);
    const d = b.subarray(i + 10, i + 10 + size);
    if (id[0] === 'T' && d.length > 1) {
      const val = decode(d[0], d.subarray(1)).replace(/\0/g, ' ').trim();
      if (id === 'TXXX') out.text[val.split(' ')[0] || 'TXXX'] = val;
      else if (val) out.text[NAMES[id] || id] = val.slice(0, 500);
    } else if (id === 'COMM' && d.length > 4) {
      out.text.Comment = decode(d[0], d.subarray(4)).replace(/\0/g, ' ').trim().slice(0, 500);
    }
    i += 10 + size;
  }
}

// ------------------------------------------------------------------
// XMP field extraction
// ------------------------------------------------------------------
function xmpValues(xmp, name) {
  const esc = name.replace(':', '\\:');
  const vals = [];
  for (const m of xmp.matchAll(new RegExp(`${esc}="([^"]*)"`, 'g'))) vals.push(m[1]);
  for (const m of xmp.matchAll(new RegExp(`<${esc}>([\\s\\S]*?)</${esc}>`, 'g'))) {
    const inner = m[1].replace(/<rdf:li[^>]*>([\s\S]*?)<\/rdf:li>/g, '$1 ').replace(/<[^>]+>/g, '').trim();
    if (inner) vals.push(inner);
  }
  return vals;
}

function extractXmpFields(xmp) {
  if (!xmp) return {};
  const fields = {};
  const want = {
    'xmp:CreatorTool': 'CreatorTool', 'Iptc4xmpExt:DigitalSourceType': 'DigitalSourceType', 'photoshop:Credit': 'Credit',
    'dc:creator': 'Creator', 'dc:description': 'Description', 'tiff:Make': 'Make', 'tiff:Model': 'Model',
    'xmp:CreateDate': 'CreateDate', 'xmp:ModifyDate': 'ModifyDate', 'photoshop:DateCreated': 'DateCreated',
    'plus:DataMining': 'DataMining',
  };
  for (const [k, label] of Object.entries(want)) {
    const v = xmpValues(xmp, k);
    if (v.length) fields[label] = [...new Set(v)].join('; ').slice(0, 400);
  }
  const agents = xmpValues(xmp, 'stEvt:softwareAgent');
  if (agents.length) fields.EditHistory = [...new Set(agents)].join(' → ').slice(0, 400);
  return fields;
}

// ------------------------------------------------------------------
// Provenance / AI marker evaluation
// ------------------------------------------------------------------
// Unambiguous generator names — safe to match even in free-text fields.
const AI_GENERATORS = [
  'Midjourney', 'DALL[-·· ]?E', 'OpenAI', 'ChatGPT', 'GPT-4o', 'Stable Diffusion', 'StableDiffusion', 'Stability AI',
  'stability\\.ai', 'SDXL', 'Adobe Firefly', 'Bing Image Creator', 'Microsoft Designer', 'Leonardo\\.?Ai', 'Ideogram', 'NovelAI',
  'ComfyUI', 'AUTOMATIC1111', 'sd-webui', 'InvokeAI', 'Fooocus', 'FLUX\\.1', 'black-forest-labs', 'HeyGen', 'Synthesia',
  'ElevenLabs', 'Resemble AI', 'Imagine with Meta', 'Craiyon', 'DreamStudio', 'NightCafe', 'Playground AI', 'Nano Banana',
  'Seedream', 'Qwen-Image', 'Google Imagen', 'Runway Gen-\\d', 'Luma Dream Machine',
];
// Short / dictionary-word names — only trusted in tool fields (Software, CreatorTool, C2PA generator…).
const AI_GENERATORS_TOOL_ONLY = [
  'Sora', 'Firefly', 'Imagen', 'Gemini', 'Google AI', 'Image Creator', 'Runway', 'Pika', 'Kling', 'Veo', 'Luma', 'Dream Machine',
  'D-ID', 'Resemble', 'Suno', 'Udio', 'Grok', 'xAI', 'Meta AI', 'Krea', 'Recraft', 'Hailuo', 'MiniMax', 'Hunyuan', 'Reve',
];
const genRe = (names) => new RegExp(`(^|[^A-Za-z])(${names.join('|')})(?=$|[^A-Za-z])`, 'i');
const AI_GEN_RE = genRe(AI_GENERATORS);
const AI_GEN_TOOL_RE = genRe([...AI_GENERATORS, ...AI_GENERATORS_TOOL_ONLY]);
const TOOL_FIELD = /Software|Make|Model|CreatorTool|edit history|claim generator|Encoder|Encoded by|Tool/;

const AI_EDIT_APPS = /\b(FaceApp|Reface|Remini|Lensa|Facetune|DeepFaceLab|FaceSwap|Deep ?Swap|Avatarify|Wombo|Generative Fill|Magic Eraser|Magic Editor|Object Eraser|Generative Erase|Photoroom|Topaz (Gigapixel|Photo AI))\b/i;
const EDIT_APPS = /\b(Adobe Photoshop|Photoshop|Lightroom|GIMP|Snapseed|PicsArt|Meitu|Canva|Pixelmator|Affinity Photo|Paint\.NET|Photopea|Luminar|Capture One|VSCO|Picsart|Fotor|InShot|CapCut|Premiere|After Effects|DaVinci Resolve|Final Cut)\b/i;

function evaluateMarkers(m) {
  const markers = [];
  const push = (kind, strength, label, source) => markers.push({ kind, strength, label, source });

  // 1. Digital source type (IPTC vocabulary, used by C2PA + XMP)
  const types = new Set([...sourceTypesIn(m.xmpFields.DigitalSourceType || ''), ...(m.c2pa?.digitalSourceTypes || [])]);
  const dsrc = m.c2pa?.digitalSourceTypes?.length ? 'C2PA' : 'XMP';
  if (types.has('compositeWithTrainedAlgorithmicMedia')) push('ai-edit', 'strong', 'Declared as edited with generative AI (compositeWithTrainedAlgorithmicMedia)', dsrc);
  else if (types.has('trainedAlgorithmicMedia')) push('ai', 'strong', 'Declared as AI-generated (IPTC digital source type: trainedAlgorithmicMedia)', dsrc);
  else if (types.has('compositeSynthetic')) push('ai-edit', 'medium', 'Declared as a composite including synthetic elements (compositeSynthetic)', dsrc);
  else if (['digitalCapture', 'negativeFilm', 'positiveFilm', 'print', 'compositeCapture'].some((t) => types.has(t))) {
    push('authentic', 'medium', `Declared as captured by a camera/scanner (${[...types].join(', ')})`, dsrc);
  }
  // Non-AI declarations: procedural graphics, digital art, screenshots, enhancement.
  for (const t of ['algorithmicMedia', 'digitalCreation', 'digitalArt', 'screenCapture', 'algorithmicallyEnhanced', 'dataDrivenMedia', 'virtualRecording']) {
    if (types.has(t)) push('info', 'weak', `Declared source type: ${t} (not AI-generated)`, dsrc);
  }

  // 2. Image-generator parameters embedded by local tools
  const t = m.text;
  if (t.parameters && /Steps:\s*\d+/.test(t.parameters) && /Sampler:/.test(t.parameters)) push('ai', 'strong', 'Stable Diffusion generation parameters embedded (prompt, sampler, seed)', 'PNG text: parameters');
  if (t.prompt && /"class_type"/.test(t.prompt)) push('ai', 'strong', 'ComfyUI workflow embedded', 'PNG text: prompt');
  if (t.workflow && /"nodes"/.test(t.workflow)) push('ai', 'strong', 'ComfyUI workflow embedded', 'PNG text: workflow');
  if (t['sd-metadata'] || t.invokeai_metadata || t.Dream) push('ai', 'strong', 'InvokeAI generation metadata embedded', 'PNG text');
  if (t.Software === 'NovelAI' || /NovelAI/.test(t.Source || '')) push('ai', 'strong', 'NovelAI generation metadata', 'PNG text');

  // 3. Named generators in metadata fields
  const fieldSources = [
    ['EXIF Software', m.exif.Software], ['EXIF Make', m.exif.Make], ['EXIF Model', m.exif.Model], ['EXIF Artist', m.exif.Artist],
    ['EXIF Description', m.exif.ImageDescription], ['EXIF UserComment', m.exif.UserComment],
    ['XMP CreatorTool', m.xmpFields.CreatorTool], ['XMP Credit', m.xmpFields.Credit], ['XMP edit history', m.xmpFields.EditHistory],
    ['XMP Description', m.xmpFields.Description], ['C2PA claim generator', m.c2pa?.claimGenerators.join(' ')],
    ...Object.entries(m.text).filter(([k]) => !['parameters', 'prompt', 'workflow'].includes(k)).map(([k, v]) => [`Text: ${k}`, v]),
  ];
  const seenGen = new Set();
  for (const [src, val] of fieldSources) {
    if (!val || typeof val !== 'string') continue;
    const g = val.match(TOOL_FIELD.test(src) ? AI_GEN_TOOL_RE : AI_GEN_RE);
    if (g && !seenGen.has(g[2].toLowerCase())) {
      seenGen.add(g[2].toLowerCase());
      push('ai', TOOL_FIELD.test(src) || /Credit/.test(src) ? 'strong' : 'medium', `AI generator named in metadata: "${g[2]}"`, src);
    }
    const ae = val.match(AI_EDIT_APPS);
    if (ae) push('ai-edit', 'medium', `Edited with an AI face/retouch tool: "${ae[1]}"`, src);
    const e = val.match(EDIT_APPS);
    if (e && !markers.some((x) => x.kind === 'edited' && x.label.includes(e[1]))) push('edited', 'weak', `Processed with editing software: "${e[1]}"`, src);
  }
  if (m.c2pa?.actions.includes('c2pa.edited')) push('edited', 'weak', 'C2PA records an edit action', 'C2PA');
  if (m.c2pa?.remote) push('info', 'weak', 'C2PA manifest stored remotely (linked from XMP, not downloaded)', 'XMP dcterms:provenance');
  else if (m.c2pa?.present && !markers.some((x) => x.source.includes('C2PA'))) push('info', 'weak', 'Content Credentials (C2PA) manifest present', 'C2PA');

  // 4. Camera evidence
  const ex = m.exif;
  if (ex.Make && ex.Model && (ex.ExposureTime || ex.FNumber || ex.ISO)) {
    push('authentic', 'weak', `Camera EXIF present: ${ex.Make} ${ex.Model}${ex.LensModel ? ` · ${ex.LensModel}` : ''}`, 'EXIF');
  }
  if (/\bLavf\d|\bLavc\d|ffmpeg/i.test(m.text.Encoder || '')) push('info', 'weak', `Re-encoded with FFmpeg (${m.text.Encoder})`, 'Container metadata');

  return markers;
}

/**
 * Extract metadata from raw bytes.
 * @param {Uint8Array} bytes
 */
export async function extractMetadata(bytes) {
  const { format, kind } = sniffFormat(bytes);
  const out = { format, kind, width: null, height: null, duration: null, exif: {}, gps: null, xmp: '', xmpFields: {}, text: {}, c2pa: null, flags: {}, audio: null };
  try {
    if (format === 'JPEG') parseJPEG(bytes, out);
    else if (format === 'PNG') await parsePNG(bytes, out);
    else if (format === 'WebP' || format === 'WAV' || format === 'AVI') parseRIFF(bytes, out);
    else if (['MP4', 'MOV', 'M4A', 'HEIC', 'AVIF'].includes(format)) parseBMFF(bytes, out);
    else if (format === 'MP3') parseID3(bytes, out);
    else if (format === 'GIF') { out.width = bytes[6] | (bytes[7] << 8); out.height = bytes[8] | (bytes[9] << 8); }
    else if (format === 'TIFF') parseTIFF(bytes, out);
  } catch (e) {
    out.parseError = String(e.message || e);
  }
  // Universal fallback: an XMP packet anywhere in the file.
  if (!out.xmp) {
    const idx = indexOfBytes(bytes, bytesOf('<x:xmpmeta'), 0, Math.min(bytes.length, 8 << 20));
    if (idx >= 0) {
      const endIdx = indexOfBytes(bytes, bytesOf('</x:xmpmeta>'), idx, Math.min(bytes.length, idx + (1 << 20)));
      if (endIdx > 0) out.xmp = utf8.decode(bytes.subarray(idx, endIdx + 12));
    }
  }
  out.xmpFields = extractXmpFields(out.xmp);
  const remote = out.xmp.match(/dcterms:provenance(?:="|>)\s*(https?:\/\/[^"<\s]+)/);
  if (!out.c2pa && remote) {
    out.c2pa = { present: true, remote: remote[1], claimGenerators: [], actions: [], digitalSourceTypes: [], signerHints: [], hasIngredients: false, verified: false };
  } else if (out.c2pa && remote) out.c2pa.remote = remote[1];
  out.markers = evaluateMarkers(out);
  out.hasCameraExif = !!(out.exif.Make && out.exif.Model);
  out.metadataStripped = !Object.keys(out.exif).length && !out.xmp && !Object.keys(out.text).length && !out.c2pa;
  return out;
}
