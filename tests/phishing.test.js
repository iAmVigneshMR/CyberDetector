import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeUrl } from '../src/lib/url-analyzer.js';
import { checkLookalike, skeleton, editDistance } from '../src/lib/typosquat.js';
import { parseHost, normalizeUrlInput, isLocalHost } from '../src/lib/domain.js';
import { toUnicode } from '../src/lib/punycode.js';
import { analyzePage } from '../src/lib/page-analyzer.js';
import { computeVerdict } from '../src/lib/verdict.js';

const ids = (fs) => fs.map((f) => f.id);
const lookalike = (url) => checkLookalike(parseHost(new URL(url).hostname));
const verdictFor = (url, page = null) => {
  const { parsed, findings } = analyzeUrl(url);
  const lk = checkLookalike(parsed);
  const pre = [...findings, ...lk.findings];
  const pf = analyzePage(page, parsed, lk.officialBrand, pre.reduce((s, f) => s + f.weight, 0));
  return computeVerdict([...pre, ...pf]);
};

test('punycode decodes IDN labels', () => {
  assert.equal(toUnicode('xn--pple-43d.com'), 'аpple.com'); // Cyrillic а
  assert.equal(toUnicode('xn--mnchen-3ya.de'), 'münchen.de');
});

test('registrable domain extraction', () => {
  assert.equal(parseHost('login.paypal.com.evil.co.uk').registrable, 'evil.co.uk');
  assert.equal(parseHost('paypal-verify.web.app').registrable, 'paypal-verify.web.app');
  assert.equal(parseHost('paypal-verify.web.app').hostingPlatform, 'web.app');
  assert.equal(parseHost('192.168.1.10').isIP, true);
});

test('URL input normalisation (defang + scheme)', () => {
  assert.equal(normalizeUrlInput('hxxp://evil[.]com/login'), 'http://evil.com/login');
  assert.equal(normalizeUrlInput('example.com'), 'https://example.com/');
  assert.throws(() => normalizeUrlInput('javascript:alert(1)'));
});

test('official domains are recognised and not flagged', () => {
  for (const u of ['https://www.paypal.com/signin', 'https://accounts.google.com/', 'https://login.microsoftonline.com/', 'https://www.onlinesbi.sbi/']) {
    const r = lookalike(u);
    assert.ok(r.officialBrand, u);
    assert.deepEqual(ids(r.findings), ['official-domain'], u);
  }
});

test('typosquats and homoglyphs are caught', () => {
  assert.ok(ids(lookalike('https://paypa1.com').findings).includes('homoglyph'));
  assert.ok(ids(lookalike('https://rnicrosoft.com').findings).includes('homoglyph'));
  assert.ok(ids(lookalike('https://paypall.com').findings).includes('typosquat'));
  assert.ok(ids(lookalike('https://micorsoft.com').findings).includes('typosquat'));
  assert.ok(ids(lookalike('https://xn--pple-43d.com').findings).includes('idn-mixed-script') || ids(lookalike('https://xn--pple-43d.com').findings).includes('homoglyph'));
  assert.ok(ids(lookalike('https://paypal-secure-login.com').findings).includes('combosquat'));
  assert.ok(ids(lookalike('https://netflixbilling.net').findings).includes('combosquat'));
  assert.ok(ids(lookalike('https://paypal.com.account-check.xyz').findings).includes('brand-domain-in-subdomain'));
});

test('common legitimate domains are not typosquats', () => {
  for (const u of ['https://ample.com', 'https://apply.com', 'https://chasm.org', 'https://zoominfo.com', 'https://groups.io', 'https://github.blog', 'https://example.com', 'https://wikipedia.org']) {
    const sev = lookalike(u).findings.filter((f) => f.weight > 0);
    assert.equal(sev.length, 0, `${u}: ${ids(sev)}`);
  }
});

test('URL structure red flags', () => {
  assert.ok(ids(analyzeUrl('http://192.168.4.20/paypal/login').findings).includes('ip-host'));
  assert.ok(ids(analyzeUrl('https://www.google.com@evil.example/').findings).includes('userinfo'));
  assert.ok(ids(analyzeUrl('https://a.b.c.d.e.example.com/').findings).includes('deep-subdomain'));
  assert.ok(ids(analyzeUrl('https://bit.ly/abc').findings).includes('shortener'));
  assert.ok(ids(analyzeUrl('https://secure-account-update.xyz/').findings).includes('risky-tld'));
});

test('skeleton / edit distance helpers', () => {
  assert.equal(skeleton('pаypa1'), skeleton('paypal'));
  assert.equal(editDistance('paypal', 'paypla'), 1);
  assert.equal(editDistance('microsoft', 'micr0soft'), 1);
});

const page = (over = {}) => ({
  url: 'x', title: '', formText: '', logoAlts: [], favicon: '',
  forms: { password: 0, payment: 0, otp: 0, crossOriginActions: [], insecureActions: 0, mailtoOrScript: 0 },
  keywords: { urgency: [], credential: [], reward: [], threat: [] },
  links: { total: 0, nullLinks: 0 }, shortLinks: [], seedPhrase: false, mixedContent: 0, ...over,
});

test('verdicts: clean, warning and danger', () => {
  assert.equal(verdictFor('https://www.wikipedia.org/').level, 'safe');
  assert.equal(verdictFor('https://www.paypal.com/signin', page({ title: 'PayPal login', forms: { ...page().forms, password: 1 } })).level, 'safe');

  const fake = verdictFor('https://paypa1-secure.com/signin', page({
    title: 'Log in to your PayPal account',
    forms: { ...page().forms, password: 1, crossOriginActions: ['collector.ru'] },
    keywords: { urgency: ['account has been limited', 'verify your account', 'within 24 hours'], credential: [], reward: [], threat: [] },
  }));
  assert.equal(fake.level, 'danger', JSON.stringify(fake.findings.map((f) => f.id)));

  const brandImpersonation = verdictFor('https://secure-mail-portal.net/', page({ title: 'Sign in to Outlook', forms: { ...page().forms, password: 1 } }));
  assert.ok(brandImpersonation.findings.some((f) => f.id === 'brand-impersonation'));
  assert.notEqual(brandImpersonation.level, 'safe');
});

test('"Sign in with Google" buttons are not impersonation', () => {
  const r = verdictFor('https://some-saas.com/login', page({ title: 'Some SaaS — Log in', formText: 'Email Password Sign in with Google Continue with Apple', forms: { ...page().forms, password: 1 } }));
  assert.ok(!r.findings.some((f) => f.id.startsWith('brand-')), ids(r.findings).join());
  assert.equal(r.level, 'safe');
});

test('critical reputation hit forces danger', () => {
  const r = computeVerdict([{ id: 'gsb', category: 'reputation', severity: 'critical', weight: 70, title: 'x' }]);
  assert.equal(r.level, 'danger');
  assert.ok(r.score >= 90);
});

test('local / private addresses are recognised', () => {
  for (const h of ['localhost', '127.0.0.1', '192.168.1.5', '10.0.0.2', '172.20.1.1', 'app.localhost', 'printer.local', '[::1]']) assert.ok(isLocalHost(h), h);
  for (const h of ['8.8.8.8', '172.32.0.1', 'example.com', 'localhost.evil.com']) assert.ok(!isLocalHost(h), h);
});

test('generic ccTLD second-level suffixes (com.es, biz.id)', () => {
  assert.equal(parseHost('roblokx.com.es').registrable, 'roblokx.com.es');
  assert.equal(parseHost('shop.example.biz.id').registrable, 'example.biz.id');
  assert.ok(ids(lookalike('https://roblokx.com.es/charts').findings).includes('typosquat'));
});

test('misspelled brand buried in a longer name', () => {
  assert.ok(ids(lookalike('http://newsupdatedmicrosof.vercel.app/').findings).includes('typo-combo'));
  assert.equal(lookalike('https://finance-news.com').findings.filter((f) => f.weight > 0).length, 0); // not "binance"
});

test('normal SSO login URLs with redirect parameters are not suspicious', () => {
  const url = 'https://id.atlassian.com/login?application=bitbucket&continue=https%3A%2F%2Fbitbucket.org%2Faccount%2Fsignin%2F%3Fnext%3D%252F';
  assert.equal(verdictFor(url, page({ title: 'Log in to continue - Log in with Atlassian account', forms: { ...page().forms, password: 1 } })).level, 'safe');
  assert.equal(verdictFor('https://login.example.com/account/signin?verify=1&update=2').level, 'safe');
  assert.ok(ids(analyzeUrl('https://secure-login-verify.com/').findings).includes('host-lure-words'));
});

test('app-store badges are not brand impersonation', () => {
  const r = verdictFor('https://homes-site.com/', page({ title: 'Homes for sale', logoAlts: ['Get it on Google Play', 'Download on the App Store'], forms: { ...page().forms, password: 1 } }));
  assert.ok(!r.findings.some((f) => f.id.startsWith('brand-')), ids(r.findings).join());
});
