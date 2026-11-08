import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  extractUrls, parseQrPayload, metadataLinks, cleanOcrText, extractPhones, extractWallets, analyzeEmbeddedContent, scanKeywords,
} from '../src/lib/image-text.js';

test('extractUrls: explicit links, defanged links, trailing punctuation', () => {
  assert.deepEqual(extractUrls('Visit https://evil.xyz/login. Or hxxp://bad[.]top/a, or www.example.com!'),
    ['https://evil.xyz/login', 'http://bad.top/a', 'https://www.example.com/']);
});

test('extractUrls: bare domains only when asked, with TLD filtering', () => {
  const text = 'Go to paypal-secure-login.xyz/verify now. Version 1.2.3, file report.pdf, e.g. this.';
  assert.deepEqual(extractUrls(text), []);
  assert.deepEqual(extractUrls(text, { bareDomains: true }), ['https://paypal-secure-login.xyz/verify']);
  assert.deepEqual(extractUrls('email me at bob@corp.com', { bareDomains: true }), []);
});

test('parseQrPayload: url, wifi (redacted), crypto, otpauth, tel, upi, text', () => {
  assert.equal(parseQrPayload('https://bit.ly/abc').url, 'https://bit.ly/abc');
  const wifi = parseQrPayload('WIFI:T:WPA;S:Cafe Free;P:hunter2;;');
  assert.equal(wifi.type, 'wifi');
  assert.match(wifi.detail, /Cafe Free/);
  assert.doesNotMatch(wifi.raw, /hunter2/);
  const btc = parseQrPayload('bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh?amount=0.5');
  assert.equal(btc.type, 'crypto');
  assert.match(btc.detail, /amount 0\.5/);
  const otp = parseQrPayload('otpauth://totp/Acme:bob?secret=JBSWY3DPEHPK3PXP&issuer=Acme');
  assert.equal(otp.type, 'otpauth');
  assert.doesNotMatch(otp.raw, /JBSWY3/);
  assert.equal(parseQrPayload('tel:+18005551234').type, 'tel');
  assert.equal(parseQrPayload('upi://pay?pa=scam@upi&pn=Refund&am=5000').type, 'payment');
  assert.equal(parseQrPayload('Go to amaz0n-refund.top').url, 'https://amaz0n-refund.top/');
  assert.equal(parseQrPayload('hello world').type, 'text');
});

test('metadataLinks: finds hidden links, ignores XMP namespace URLs', () => {
  const meta = {
    exif: { UserComment: 'see https://phish.example.xyz/x', Software: 'GIMP' },
    xmpFields: { Rights: 'http://ns.adobe.com/xap/1.0/rights/', Description: 'www.w3.org thing' },
    text: { Comment: 'nothing here' },
  };
  assert.deepEqual(metadataLinks(meta), [{ url: 'https://phish.example.xyz/x', source: 'EXIF UserComment' }]);
});

test('cleanOcrText drops noise lines and joins hyphenated words', () => {
  assert.equal(cleanOcrText('| ~ ; .\nYour account has been sus-\npended\n=- _ -='), 'Your account has been suspended');
});

test('extractPhones / extractWallets', () => {
  assert.deepEqual(extractPhones('Call +1 (800) 555-1234 now. Ref 2024. Date 20240101'), ['+1 (800) 555-1234']);
  assert.deepEqual(extractWallets('send to 0x52908400098527886E0F7030069857D2E4169EE7 today'), ['0x52908400098527886E0F7030069857D2E4169EE7']);
});

test('scanKeywords: short keywords need word boundaries', () => {
  assert.deepEqual(scanKeywords('Enter the OTP sent to you').credential, ['otp']);
  assert.deepEqual(scanKeywords('A hotpot recipe').credential, []);
});

test('call-back phrasing variants are recognised', () => {
  assert.deepEqual(scanKeywords('Unusual activity. Please call Microsoft Support at 1-888-555-0199').callback, ['call microsoft support']);
  const r = analyzeEmbeddedContent({ ocr: { text: 'Your account has been suspended. Call our helpdesk: +1 (888) 555-0199', confidence: 90 } });
  assert.ok(r.findings.some((f) => f.id === 'text-callback' && f.severity === 'high'));
  assert.equal(scanKeywords('Call me maybe').callback.length, 0);
});

test('nothing embedded → unknown', () => {
  const r = analyzeEmbeddedContent({ qrCodes: [], ocr: { text: '  ~ |  ', confidence: 20 } });
  assert.equal(r.level, 'unknown');
  assert.equal(r.links.length, 0);
});

test('tech-support scam screenshot → danger', () => {
  const r = analyzeEmbeddedContent({
    ocr: { text: 'WARNING! Virus detected. Your computer has been locked.\nCall Microsoft Support immediately: +1 (888) 555-0199\nDo not shut down your computer', confidence: 88 },
  });
  assert.ok(r.findings.some((f) => f.id === 'text-callback' && f.severity === 'high'));
  assert.ok(r.findings.some((f) => f.id === 'text-brand'));
  assert.notEqual(r.level, 'safe');
});

test('quishing: QR link + urgent "scan to verify" text; link verdict escalates', () => {
  const url = 'https://micros0ft-verify.top/login';
  const input = {
    qrCodes: [{ raw: url }],
    ocr: { text: 'Microsoft 365: your password expires today. Scan the QR code to verify your account.', confidence: 90 },
  };
  const pre = analyzeEmbeddedContent(input);
  assert.deepEqual(pre.links.map((l) => l.url), [url]);
  assert.ok(pre.findings.some((f) => f.id === 'text-quishing'));

  const r = analyzeEmbeddedContent({ ...input, linkResults: { [url]: { level: 'danger', score: 90, reason: 'Lookalike of microsoft.com' } } });
  assert.equal(r.level, 'danger');
  assert.equal(r.links[0].result.level, 'danger');
  assert.ok(r.findings.some((f) => f.id === 'link-danger' && f.severity === 'critical'));
});

test('benign QR + safe link stays safe', () => {
  const r = analyzeEmbeddedContent({
    qrCodes: [{ raw: 'https://www.wikipedia.org/' }],
    linkResults: { 'https://www.wikipedia.org/': { level: 'safe', score: 0 } },
  });
  assert.equal(r.level, 'safe');
});

test('crypto giveaway text → high', () => {
  const r = analyzeEmbeddedContent({ ocr: { text: 'Elon giveaway! Send 0.1 BTC to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh and double your money', confidence: 80 } });
  assert.ok(r.findings.some((f) => f.id === 'text-wallet' && f.severity === 'high'));
  assert.notEqual(r.level, 'safe');
});
