# CyberDetector — Phishing & Deepfake Shield

Manifest V3 browser extension for **Chrome** and **Firefox** that detects phishing pages and AI-generated / deepfake media. Plain JavaScript (ES modules), no bundler. The only third-party code is jsQR (QR decoding) and Tesseract.js (OCR), copied into the build from `node_modules`. Nothing is loaded from a CDN.

## Quick start

```bash
npm install            # once: fetches jsQR + Tesseract.js (bundled into the build)
npm run build          # → dist/chrome and dist/firefox
npm test               # unit tests for the detection logic (Node 20+)
npm run package        # → dist/cyberdetector-<browser>-<version>.zip
```

**Chrome / Edge / Brave:** `chrome://extensions` → enable *Developer mode* → *Load unpacked* → `dist/chrome`
**Firefox (140+):** `about:debugging#/runtime/this-firefox` → *Load Temporary Add-on* → `dist/firefox/manifest.json`
(or `npm run start:firefox`)

Edit files in `src/`, then re-run `npm run build` and reload the extension.

## Features

### Phishing detection (automatic on every page)
| Feature | Where | Notes |
|---|---|---|
| URL & domain structure analyzer | `lib/url-analyzer.js` | IP hosts, `user@host` tricks, odd ports, deep subdomains, risky TLDs, free hosting platforms, embedded redirects |
| Typosquat & lookalike checker | `lib/typosquat.js`, `lib/brands.js` | Homoglyphs (Cyrillic/Greek/digits), punycode mixed-script, keyboard typos, combosquats (`paypal-secure`), brand-in-subdomain (`paypal.com.evil.xyz`) against ~60 commonly impersonated brands |
| Shortened URL expander | `lib/shortener.js` | Follows HTTP, meta-refresh and JS redirects with cookies omitted |
| SSL/HTTPS validator | `lib/connection.js` | HTTP pages, insecure form targets, mixed content. **Firefox:** full certificate check (trust, expiry, mismatch, TLS version, certificate age). **Chrome** has no certificate API, so turn on the optional Certificate Transparency lookup there for domain age |
| Login/payment form detector | `content/content.js`, `lib/page-analyzer.js` | Password / card / OTP / seed-phrase fields, cross-domain form posts, brand impersonation (title, logo, favicon vs. domain) |
| Phishing keyword & urgency scanner | `content/content.js` | Urgency, threat, reward and credential-request phrases |
| Blacklist integration | `lib/reputation.js` | **OpenPhish** feed (on by default, matched locally). **Google Safe Browsing v4** and **PhishTank** (opt-in, need API keys) |

### Deepfake / AI-media detection
| Feature | Where | Notes |
|---|---|---|
| Right-click **Scan Media** | `background/background.js` | On images, video and audio. Also *Check link for phishing* and *Scan this page* |
| Media extractor | popup → *Media on this page* | Images, video, audio, posters, og:image / og:video |
| EXIF / XMP / C2PA inspector | `lib/media-metadata.js` | JPEG, PNG, WebP, HEIC/AVIF, MP4/MOV, WAV, MP3. Detects C2PA manifests (claim generator, actions, IPTC digital source type), Stable Diffusion / ComfyUI / InvokeAI parameters, and generator names. **C2PA signatures are not cryptographically verified** — the report links to contentcredentials.org/verify |
| AI-detection model | `lib/ai-detect.js`, `detector-server/` | **Local detector**: free, private open-source models on your machine (see [detector-server/README.md](detector-server/README.md)). Also **Sightengine**, **Hive**, or **your own endpoint** |
| Synthetic probability + confidence | `lib/media-score.js` | Combines the API score, provenance metadata and heuristics; labels confidence honestly (`low` = heuristics only) |
| QR code & barcode decoder | `lib/image-scan.js`, `lib/image-text.js` | Runs locally with jsQR, or the browser's `BarcodeDetector` where it supports QR. Classifies the payload (link, Wi-Fi, crypto / UPI payment, 2FA setup, phone / SMS). Wi-Fi passwords and 2FA secrets are redacted |
| Text in images (OCR) | `lib/image-scan.js`, `lib/image-text.js` | Runs locally with Tesseract.js (English, ~1–2 s per image). Flags urgency / threat language, call-back and tech-support scams with phone numbers, "scan the QR to verify" (quishing), brand impersonation, credential or seed-phrase requests, and crypto giveaway wallets |
| Links in media | `lib/image-text.js` | Links from QR codes, image text and metadata (EXIF / XMP / PNG text) are run through the phishing engine without being opened (up to 8 per scan) |
| Heatmap / timestamps | `lib/ela.js`, `scan/scan.js` | Images: local Error Level Analysis heatmap, compression hotspots, and API-provided regions. Video/audio: per-frame score timeline with clickable suspicious segments |

### Advanced protections (Settings → *Advanced protections*, each one can be switched off)
| Protection | Where | What it does | Default |
|---|---|---|---|
| ClickFix / clipboard attacks | `content/clipboard-hook.js` (page world), `content/guard.js` | Replaces malicious commands a page copies to your clipboard (hidden PowerShell, `mshta`, `iex`, `certutil`, DNS-lookup and fake-"✅ verification" tricks…) with a harmless warning. Generic commands are only blocked on pages that also show "Win+R / Ctrl+V / verify you are human" lures. The lure text itself is a **Danger** finding | on |
| Password-reuse alarm | `lib/password-alert.js`, `content/guard.js` | Register important passwords (stored as salted PBKDF2 hashes only). Typing one on any other site clears the field, blocks the form and shows a full-screen warning | on (add passwords in Settings) |
| AiTM login clones | `content/content.js`, `lib/page-analyzer.js` | Microsoft / Google / Okta sign-in page structure or CDN assets on a non-official domain (Tycoon 2FA, Evilginx-style kits) | on |
| Browser-in-the-browser | same | Official login URL drawn as text inside a floating in-page "window" containing a login frame | on |
| Device-code & consent phishing | `content/guard.js` | Warning on real device-code pages (microsoft.com/devicelogin, github.com/login/device…); risky-permission and unverified-app warnings on OAuth consent screens | on |
| Link hover check | `content/guard.js` | Shows the real destination; warns when link text shows a different domain, or the target looks risky / is shortened | risky links only |
| Webmail scanner | `content/guard.js`, `lib/email-analyzer.js` | Gmail / Outlook web: brand-spoofing senders, mismatched links, risky or disguised attachments, pressure language. Best-effort: depends on the webmail page structure | on |
| Risky-download guard | `lib/download-guard.js`, `download/` | Pauses (or, if already finished, flags) executables/archives/HTML with a second red flag: disguised extension, right-to-left trick, HTML smuggling, or a flagged page | off (asks for the *downloads* permission) |
| Domain age (RDAP) | `lib/rdap.js` | Official registry registration date for suspicious domains, login pages and manual scans | off (sends the domain to the registry) |
| Live call deepfake meter | `content/guard.js` | Popup button on video-call pages: streams 4-second audio chunks and video frames to the **Local detector**, shows a live meter | on (needs Local detector) |
| Extension auditor | `lib/ext-audit.js` | Lists your other extensions by risk (all-site access, cookies, proxy, sideloaded, off-store updates) with a Disable button | button (asks for *management*, released when you leave Settings) |
| Report phishing | popup | Google Safe Browsing (pre-filled), Microsoft, Netcraft, APWG e-mail, India's cybercrime.gov.in, defanged-URL copy | on |

### UI
- **Toolbar badge:** ✓ green (safe), ! amber (warning), ✕ red (danger).
- **Popup dashboard:** verdict and findings for the current page, reputation sources, page media list, manual URL and media scanner, history.
- **In-page warnings:** an amber bar for suspicious pages and a full-screen overlay for dangerous ones (closed shadow DOM, so the page can't restyle or remove them).
- **Report page** (`scan/scan.html`): full URL and media reports, file upload (drag-drop or paste).
- **Scan history:** last 200 entries, exportable as JSON.

## Custom detection endpoint contract

```
POST <your endpoint>     multipart/form-data: file, mediaType (image|video|audio), sourceUrl
Authorization: Bearer <token>   (optional)

200 → {
  "score": 0.93,                                   // 0..1 probability synthetic
  "scores":   { "face swap": 0.91 },               // optional breakdown
  "frames":   [{ "time": 1.5, "score": 0.8 }],     // optional, seconds (video/audio)
  "segments": [{ "start": 3, "end": 5.5, "score": 0.9 }],
  "regions":  [{ "x": 0.1, "y": 0.2, "w": 0.3, "h": 0.3, "score": 0.9 }]   // optional, 0..1 coords
}
```

## Privacy
- By default nothing leaves the browser except downloads of the OpenPhish feed.
- Safe Browsing, PhishTank, crt.sh and AI-detection APIs are opt-in. Firefox additionally asks for its data-collection consent (`browsingActivity` / `websiteContent`) when you turn one on.
- QR decoding and OCR run on your device. Links found in media are checked with the same sources as a manual URL scan (OpenPhish locally, plus Safe Browsing / PhishTank / crt.sh only if you enabled them). Shortened links are expanded with cookies omitted. You can turn each of these off in Settings → *Embedded content*.
- Advanced protections run locally. The exceptions: **RDAP** (off by default) sends suspicious domains to the domain registry, and the **live call meter** sends call audio/video only to *your own* Local detector or custom endpoint.
- Protected passwords are stored only as salted PBKDF2-SHA256 hashes (210,000 iterations) plus their length, under a separate storage key that is never sent to web pages.
- Optional permissions are requested only when needed: *downloads* when you enable the download guard, *management* when you run the extension auditor (released again when you leave Settings).
- Settings, API keys and history live in `storage.local` (never synced). Per-tab state lives in `storage.session`.

## Verification status (2026-11-08)
| Area | How it was tested | Result |
|---|---|---|
| Detection logic | `npm test`: 47 unit tests (incl. ClickFix classifier on real payload styles, email, downloads, password hashing, RDAP, auditor) | pass |
| Advanced protections | 26 attack simulations in Chrome: ClickFix (writeText + execCommand, docs page untouched), AiTM clone, BitB, password alarm, link hover, download guard, device-code warning on the real Microsoft page, RDAP, live call meter, auditor, report button; 5 checks in Firefox | 26 / 26 Chrome, 5 / 5 Firefox |
| False positives | 168 real legitimate sites in headless Chrome (56 login pages) | 0 / 162 flagged (6 didn't load) |
| Address-only detection | 300 live OpenPhish URLs (no page visit, blacklist excluded) | 30% flagged. Page content and blacklists catch the rest |
| UI and integrations | 28 automated browser checks in Chrome: overlay buttons, keyboard lock, popup, media list, upload, custom endpoint (regions, video/audio timelines), short-link expansion, PhishTank, crt.sh | 28 / 28 |
| Firefox 158 | Background, verdict, overlay, TLS certificate inspection, consent gating, media scan, popup | 12 / 13 (the 1 failure was a test-harness timing check) |
| C2PA | 31 files (official C2PA test files plus manifests signed with the C2PA SDK), compared with the official c2pa reader | 30 / 31 (remote manifest isn't downloaded, by design) |
| Local detector | 10 image + 4 audio models compared on held-out data; extension ↔ server tested end to end in Chrome (9 checks) | images: 85% / 65% caught on two test sets; audio: 71–97% (details in detector-server/README.md) |
| Sightengine / Hive / Safe Browsing | Request and response formats checked against current docs; invalid-key error paths tested live | **No successful scan with a real key yet** |

## Limitations
- Heuristics give risk signals, not proof. Tune with *Sensitivity* in Settings, and use *Trust site* for false positives.
- Without an AI-detection API, a deepfake whose metadata has been stripped cannot be reliably detected; the report says so.
- `blob:` (streamed) media can't be fetched by extensions. Download the file and use *Scan a file*.
- OCR is English only and misreads stylised, handwritten, rotated or very small text. jsQR finds QR codes only (not other barcodes), and the image is searched in tiles to find more than one. Embedded-content checks run on images, not video frames.
- Certificate details are Firefox-only (browser API limitation).
- The ClickFix hook runs in the page's own JavaScript. A page written specifically to defeat CyberDetector could get unhooked clipboard functions (e.g. from a fresh iframe), so it's defence in depth; the lure-text Danger finding is a second layer.
- Not tested end to end: the OAuth consent screen warning (needs a live consent flow), the webmail scanner on real Gmail/Outlook (unit-tested analyzer only), and HTML-smuggled blob downloads (headless Chrome doesn't create them; covered by unit tests).
- The bundled Tesseract OCR library contains `Function(...)` code paths, which `web-ext lint` reports. The extension's CSP forbids `eval`, so they can't run, but store reviewers may ask about them.
- The registrable-domain logic uses a small built-in subset of the Public Suffix List.
- Sightengine and Hive response formats follow their public docs; if a provider changes its API, adjust `lib/ai-detect.js`.

## Layout
```
src/
  manifest.json          base manifest (Chrome form; build adapts it for Firefox)
  background/            service worker / event page: tab analysis, badge, menus, messaging
  content/content.js     page signals (incl. AiTM / BitB / ClickFix-lure detection), media extraction, warning banner
  content/guard.js       advanced on-page protections: password alarm, device-code/consent warnings,
                         link hover, webmail scanner, live call meter, ClickFix alerts (all frames)
  content/clipboard-hook.js   ClickFix clipboard interception, registered into the PAGE world only while enabled
  lib/                   detection logic (pure ES modules; unit-tested in tests/), incl.
                         password-alert.js, email-analyzer.js, download-guard.js, rdap.js, ext-audit.js
  download/              "risky download" warning page
  popup/ scan/ options/  UI pages
detector-server/         free local AI/deepfake detector (Python), see its README
scripts/build.mjs        per-browser builds (+ --zip); copies vendor/ (jsQR, Tesseract) from node_modules
scripts/gen-icons.mjs    regenerates icons
```
