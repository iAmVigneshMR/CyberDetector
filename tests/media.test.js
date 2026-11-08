import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deflateSync } from 'node:zlib';
import { extractMetadata, sniffFormat } from '../src/lib/media-metadata.js';
import { combineMediaScore } from '../src/lib/media-score.js';

// ---------- tiny fixture builders ----------
const be32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const be16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };

function pngChunk(type, data) {
  return Buffer.concat([be32(data.length), Buffer.from(type), data, Buffer.alloc(4)]); // CRC ignored by parser
}
function png(chunks, w = 1024, h = 1024) {
  const ihdr = Buffer.concat([be32(w), be32(h), Buffer.from([8, 6, 0, 0, 0])]);
  return new Uint8Array(Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), pngChunk('IHDR', ihdr), ...chunks, pngChunk('IEND', Buffer.alloc(0))]));
}

// Big-endian TIFF with IFD0 {Make, Model, Software, ExifIFD→{ExposureTime, FNumber, ISO}}
function tiff({ make, model, software }) {
  const strings = [make + '\0', model + '\0', software + '\0'].map((s) => Buffer.from(s, 'latin1'));
  const ifd0Count = 4;
  const ifd0Size = 2 + ifd0Count * 12 + 4;
  const exifCount = 3;
  const exifSize = 2 + exifCount * 12 + 4;
  let dataOff = 8 + ifd0Size + exifSize;
  const data = [];
  const entry = (tag, type, count, valueOrOffset) => Buffer.concat([be16(tag), be16(type), be32(count), valueOrOffset]);
  const strEntry = (tag, buf) => {
    const off = dataOff;
    data.push(buf);
    dataOff += buf.length;
    return entry(tag, 2, buf.length, be32(off));
  };
  const ratEntry = (tag, n, d) => {
    const off = dataOff;
    const buf = Buffer.concat([be32(n), be32(d)]);
    data.push(buf);
    dataOff += 8;
    return entry(tag, 5, 1, be32(off));
  };
  const exifIfdOffset = 8 + ifd0Size;
  const ifd0 = Buffer.concat([be16(ifd0Count), strEntry(0x010f, strings[0]), strEntry(0x0110, strings[1]), strEntry(0x0131, strings[2]), entry(0x8769, 4, 1, be32(exifIfdOffset)), be32(0)]);
  const exif = Buffer.concat([be16(exifCount), ratEntry(0x829a, 1, 250), ratEntry(0x829d, 28, 10), entry(0x8827, 3, 1, Buffer.concat([be16(200), be16(0)])), be32(0)]);
  return Buffer.concat([Buffer.from('MM\0*'), be32(8), ifd0, exif, ...data]);
}

function jpeg(segments) {
  const segs = segments.map(([marker, payload]) => Buffer.concat([Buffer.from([0xff, marker]), be16(payload.length + 2), payload]));
  const sof = Buffer.concat([Buffer.from([0xff, 0xc0]), be16(17), Buffer.from([8]), be16(3000), be16(4000), Buffer.from([3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1])]);
  return new Uint8Array(Buffer.concat([Buffer.from([0xff, 0xd8]), ...segs, sof, Buffer.from([0xff, 0xda, 0, 2, 0xff, 0xd9])]));
}

test('format sniffing', () => {
  assert.equal(sniffFormat(png([])).format, 'PNG');
  assert.equal(sniffFormat(jpeg([])).format, 'JPEG');
  assert.equal(sniffFormat(new Uint8Array(Buffer.from('\0\0\0\x18ftypisom\0\0\0\0'))).format, 'MP4');
  assert.equal(sniffFormat(new Uint8Array(Buffer.from('ID3\x04\0\0\0\0\0\0'))).format, 'MP3');
});

test('camera JPEG: EXIF parsed and counted as authentic evidence', async () => {
  const bytes = jpeg([[0xe1, Buffer.concat([Buffer.from('Exif\0\0'), tiff({ make: 'Canon', model: 'Canon EOS R5', software: 'Firmware 1.8' })])]]);
  const m = await extractMetadata(bytes);
  assert.equal(m.exif.Make, 'Canon');
  assert.equal(m.exif.Model, 'Canon EOS R5');
  assert.equal(m.exif.ISO, 200);
  assert.ok(Math.abs(m.exif.ExposureTime - 0.004) < 1e-9);
  assert.equal(m.width, 4000);
  assert.ok(m.markers.some((x) => x.kind === 'authentic'));
  const s = combineMediaScore(m, null, null);
  assert.ok(s.probability < 0.3);
  assert.equal(s.confidence, 'low');
});

test('Stable Diffusion PNG parameters → declared AI', async () => {
  const text = Buffer.from('parameters\0a photo of a cat\nSteps: 30, Sampler: DPM++ 2M Karras, CFG scale: 7, Seed: 1234', 'latin1');
  const m = await extractMetadata(png([pngChunk('tEXt', text)]));
  assert.ok(m.markers.some((x) => x.kind === 'ai' && x.strength === 'strong'));
  const s = combineMediaScore(m, null, null);
  assert.equal(s.level, 'danger');
  assert.ok(s.probability >= 0.95);
});

test('compressed iTXt XMP with IPTC trainedAlgorithmicMedia', async () => {
  const xmp = '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description Iptc4xmpExt:DigitalSourceType="http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia" xmp:CreatorTool="Adobe Firefly"/></rdf:RDF></x:xmpmeta>';
  const itxt = Buffer.concat([Buffer.from('XML:com.adobe.xmp\0', 'latin1'), Buffer.from([1, 0]), Buffer.from('\0\0'), deflateSync(Buffer.from(xmp))]);
  const m = await extractMetadata(png([pngChunk('iTXt', itxt)]));
  assert.match(m.xmpFields.DigitalSourceType, /trainedAlgorithmicMedia/);
  assert.equal(m.xmpFields.CreatorTool, 'Adobe Firefly');
  assert.ok(m.markers.some((x) => x.kind === 'ai' && /trainedAlgorithmicMedia/.test(x.label)));
});

test('C2PA manifest in PNG caBX: claim generator + actions', async () => {
  const gen = 'ChatGPT/OpenAI c2pa-rs';
  const cbor = Buffer.concat([
    Buffer.from('jumb\0\0\0\0jumdc2pa\0'),
    Buffer.from([0x6f]), Buffer.from('claim_generator'), Buffer.from([0x60 + gen.length]), Buffer.from(gen),
    Buffer.from('c2pa.actions...c2pa.created...http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia'),
  ]);
  const m = await extractMetadata(png([pngChunk('caBX', cbor)]));
  assert.ok(m.c2pa?.present);
  assert.deepEqual(m.c2pa.claimGenerators, [gen]);
  assert.ok(m.c2pa.actions.includes('c2pa.created'));
  assert.ok(m.c2pa.digitalSourceTypes.includes('trainedAlgorithmicMedia'));
  assert.equal(combineMediaScore(m, null, null).level, 'danger');
});

test('API score drives probability; camera C2PA lowers it', async () => {
  const m = await extractMetadata(png([]));
  assert.equal(combineMediaScore(m, { provider: 'X', score: 0.92, scores: {} }, null).level, 'danger');
  assert.equal(combineMediaScore(m, { provider: 'X', score: 0.05, scores: {} }, null).level, 'safe');
});

test('free-text "runway" in description is not an AI marker', async () => {
  const text = Buffer.from('Description\0Model walking the runway at fashion week', 'latin1');
  const m = await extractMetadata(png([pngChunk('tEXt', text)]));
  assert.equal(m.markers.filter((x) => x.kind === 'ai').length, 0);
});

test('MP3 ID3 encoder tag naming an AI voice tool', async () => {
  const frame = (id, text) => { const d = Buffer.concat([Buffer.from([3]), Buffer.from(text)]); return Buffer.concat([Buffer.from(id), be32(d.length), Buffer.from([0, 0]), d]); };
  const frames = Buffer.concat([frame('TSSE', 'ElevenLabs v2'), frame('TIT2', 'Statement')]);
  const header = Buffer.concat([Buffer.from('ID3'), Buffer.from([3, 0, 0]), Buffer.from([0, 0, (frames.length >> 7) & 0x7f, frames.length & 0x7f])]);
  const m = await extractMetadata(new Uint8Array(Buffer.concat([header, frames])));
  assert.equal(m.text['Encoder settings'], 'ElevenLabs v2');
  assert.ok(m.markers.some((x) => x.kind === 'ai' && /ElevenLabs/.test(x.label)));
});

test('IPTC algorithmicMedia (procedural, non-AI) is not treated as AI; source type parsed exactly', async () => {
  const dst = (t) => Buffer.concat([Buffer.from('qdigitalSourceTypex?'), Buffer.from(`http://cv.iptc.org/newscodes/digitalsourcetype/${t}`), Buffer.from('rallActionsIncluded')]);
  const m1 = await extractMetadata(png([pngChunk('caBX', Buffer.concat([Buffer.from('jumbc2pa'), dst('algorithmicMedia')]))]));
  assert.deepEqual(m1.c2pa.digitalSourceTypes, ['algorithmicMedia']);
  assert.equal(m1.markers.filter((x) => x.kind === 'ai').length, 0);
  const m2 = await extractMetadata(png([pngChunk('caBX', Buffer.concat([Buffer.from('jumbc2pa'), dst('digitalCapture')]))]));
  assert.deepEqual(m2.c2pa.digitalSourceTypes, ['digitalCapture']);
  assert.ok(m2.markers.some((x) => x.kind === 'authentic'));
});

test('remote C2PA manifest referenced from XMP is reported', async () => {
  const xmp = '<x:xmpmeta><rdf:Description dcterms:provenance="https://cai-manifests.adobe.com/manifests/abc"/></x:xmpmeta>';
  const itxt = Buffer.concat([Buffer.from('XML:com.adobe.xmp\0', 'latin1'), Buffer.from([0, 0, 0, 0]), Buffer.from(xmp)]);
  const m = await extractMetadata(png([pngChunk('iTXt', itxt)]));
  assert.equal(m.c2pa?.remote, 'https://cai-manifests.adobe.com/manifests/abc');
});
