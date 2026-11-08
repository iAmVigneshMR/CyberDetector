// Build browser-specific bundles from src/:
//   dist/chrome   — MV3 service worker background
//   dist/firefox  — MV3 event-page background + gecko id + webRequest (TLS certificate inspection)
// Usage: node scripts/build.mjs [chrome|firefox] [--zip]
import { cp, rm, readFile, writeFile, mkdir, access } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const src = path.join(root, 'src');
const dist = path.join(root, 'dist');

const args = process.argv.slice(2);
const zip = args.includes('--zip');
const targets = args.filter((a) => !a.startsWith('--'));
const browsers = targets.length ? targets : ['chrome', 'firefox'];

// Third-party code bundled into the extension (no CDN: MV3 forbids remote code).
// Installed as devDependencies — run `npm install` first.
const nm = path.join(root, 'node_modules');
const VENDOR = [
  ['jsqr/dist/jsQR.js', 'jsqr/jsQR.js'],
  ['jsqr/LICENSE', 'jsqr/LICENSE'],
  ['tesseract.js/dist/tesseract.esm.min.js', 'tesseract/tesseract.esm.min.js'],
  ['tesseract.js/dist/worker.min.js', 'tesseract/worker.min.js'],
  ['tesseract.js/LICENSE.md', 'tesseract/LICENSE.md'],
  // SIMD build only: every supported browser (Chrome 91+, Firefox 140+) has WASM SIMD.
  ['tesseract.js-core/tesseract-core-simd-lstm.wasm.js', 'tesseract/tesseract-core-simd-lstm.wasm.js'],
  ['tesseract.js-core/LICENSE', 'tesseract/LICENSE-core'],
  // Integer-quantized "best" English LSTM model (~3 MB).
  ['@tesseract.js-data/eng/4.0.0_best_int/eng.traineddata.gz', 'tesseract/lang/eng.traineddata.gz'],
];
for (const [from] of VENDOR) {
  try {
    await access(path.join(nm, from));
  } catch {
    console.error(`✕ Missing node_modules/${from} — run \`npm install\` first.`);
    process.exit(1);
  }
}

const base = JSON.parse(await readFile(path.join(src, 'manifest.json'), 'utf8'));
const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
base.version = pkg.version;

const transforms = {
  chrome(m) {
    return m;
  },
  firefox(m) {
    m.background = { scripts: [m.background.service_worker], type: 'module' };
    // webRequest + blocking are required for webRequest.getSecurityInfo() (certificate details).
    m.permissions = [...m.permissions, 'webRequest', 'webRequestBlocking'];
    m.browser_specific_settings = {
      gecko: {
        id: 'cyberdetector@stupastechsolutions.dev',
        strict_min_version: '140.0',
        // Nothing leaves the browser by default (OpenPhish is matched locally).
        // URL / media sharing with third-party APIs is opt-in and requested at runtime.
        data_collection_permissions: {
          required: ['none'],
          optional: ['browsingActivity', 'websiteContent'],
        },
      },
      gecko_android: { strict_min_version: '142.0' },
    };
    return m;
  },
};

for (const browser of browsers) {
  if (!transforms[browser]) throw new Error(`Unknown target: ${browser}`);
  const out = path.join(dist, browser);
  await rm(out, { recursive: true, force: true });
  await mkdir(out, { recursive: true });
  await cp(src, out, { recursive: true, filter: (p) => !p.endsWith('manifest.json') || path.dirname(p) !== src });
  for (const [from, to] of VENDOR) {
    await mkdir(path.dirname(path.join(out, 'vendor', to)), { recursive: true });
    await cp(path.join(nm, from), path.join(out, 'vendor', to));
  }
  const manifest = transforms[browser](structuredClone(base));
  await writeFile(path.join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  console.log(`✓ built ${path.relative(root, out)}`);

  if (zip) {
    const file = path.join(dist, `cyberdetector-${browser}-${base.version}.zip`);
    await rm(file, { force: true });
    execFileSync('zip', ['-qr', '-X', file, '.'], { cwd: out });
    console.log(`  → ${path.relative(root, file)}`);
  }
}
