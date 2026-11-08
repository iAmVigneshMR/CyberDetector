// Orchestrates every phishing check for a URL (+ optional page report).
import { analyzeUrl } from './url-analyzer.js';
import { checkLookalike } from './typosquat.js';
import { analyzeConnection } from './connection.js';
import { analyzePage, advancedPageFindings } from './page-analyzer.js';
import { domainRegistered, ageFindings } from './rdap.js';
import { checkReputation, certificateFirstSeen } from './reputation.js';
import { expandUrl, isShortener } from './shortener.js';
import { computeVerdict } from './verdict.js';
import { finding } from './findings.js';

const PATH_SIGNALS = new Set(['very-long-url', 'embedded-url', 'heavy-encoding', 'shortener']);

export function isTrusted(host, settings) {
  return settings.trustedDomains.some((d) => host === d || host.endsWith('.' + d));
}

/**
 * Full analysis.
 * @param {string} href
 * @param {object} settings
 * @param {{page?: object, sec?: object, manual?: boolean}} opts
 */
export async function analyze(href, settings, { page = null, sec = null, manual = false } = {}) {
  const started = Date.now();
  const { url: u, parsed: p, findings: urlFindings } = analyzeUrl(href);
  const result = {
    url: href,
    host: p.host,
    unicodeHost: p.unicodeHost,
    registrable: p.registrable,
    hasPage: !!page,
    page: page ? summarizePage(page) : null,
    ts: Date.now(),
  };

  const trusted = isTrusted(p.host, settings);
  const { findings: domainFindings, officialBrand } = checkLookalike(p);
  result.officialBrand = officialBrand?.name || null;

  // "Suspicious domain" = evidence about WHO runs the site (domain/host signals), not path or query noise.
  const pre = [...urlFindings, ...domainFindings].filter((f) => !PATH_SIGNALS.has(f.id));
  const preRisk = pre.reduce((s, f) => s + f.weight, 0);

  const { findings: connFindings, summary: connection } = analyzeConnection(u, sec, page);
  result.connection = connection;

  const pageFindings = [...analyzePage(page, p, officialBrand, preRisk), ...advancedPageFindings(page, p, officialBrand, settings)];

  // Network checks run in parallel; none may block the verdict for long.
  const lookupWorthy = !officialBrand && !trusted && !p.isIP && (manual || preRisk >= 15 || page?.forms.password > 0);
  const [rep, ct, registered] = await Promise.all([
    checkReputation(href, settings).catch((e) => ({ checks: [{ source: 'Reputation', status: 'error', error: e.message }], findings: [] })),
    settings.ctLookup && !officialBrand && !trusted && !p.isIP && (manual || preRisk >= 15 || page?.forms.password > 0)
      ? certificateFirstSeen(p.registrable).catch(() => undefined)
      : Promise.resolve(undefined),
    settings.rdapLookup && lookupWorthy ? domainRegistered(p.registrable).catch(() => undefined) : Promise.resolve(undefined),
  ]);
  if (typeof registered === 'number') connection.registeredDays = Math.floor((Date.now() - registered) / 86400_000);
  result.reputation = rep.checks;

  const ctFindings = [];
  if (typeof ct === 'number') {
    const days = Math.floor((Date.now() - ct) / 86400_000);
    connection.firstSeenDays = days;
    if (days < 7) ctFindings.push(finding('new-domain', 'connection', 'high', `Domain first seen ${days} day(s) ago`, 'Its first TLS certificate is brand new (Certificate Transparency logs). Most phishing domains are used within days of registration.'));
    else if (days < 30) ctFindings.push(finding('young-domain', 'connection', 'medium', `Domain first seen ${days} days ago`, 'Young domain according to Certificate Transparency logs.'));
    else ctFindings.push(finding('domain-age', 'connection', 'info', `Domain first seen ${days} days ago`, 'Certificate Transparency logs'));
  }

  // Official brand domains: only reputation hits and broken TLS should raise alarms.
  let all = [...rep.findings, ...domainFindings, ...urlFindings, ...connFindings, ...ctFindings, ...ageFindings(registered), ...pageFindings];
  if (officialBrand) {
    all = all.map((f) => (['reputation', 'connection'].includes(f.category) || f.weight === 0 ? f : { ...f, severity: 'info', weight: 0 }));
  }

  Object.assign(result, computeVerdict(all, { sensitivity: settings.sensitivity, trusted }));
  result.trusted = trusted;
  result.elapsedMs = Date.now() - started;
  return result;
}

/** Manual scan: expands shortened links first and analyzes the destination. */
export async function analyzeManual(href, settings) {
  let expansion = null;
  let target = href;
  if (isShortener(new URL(href).hostname)) {
    expansion = await expandUrl(href);
    target = expansion.final;
  }
  const result = await analyze(target, settings, { manual: true });
  if (expansion) {
    result.expansion = expansion;
    result.findings.unshift(finding('expanded', 'url', 'info', 'Shortened link expanded', `${href} → ${expansion.final}${expansion.error ? ` (stopped: ${expansion.error})` : ''}`));
  }
  result.input = href;
  return result;
}

function summarizePage(page) {
  return {
    title: page.title,
    forms: page.forms,
    shortLinks: page.shortLinks,
    keywordCount: Object.values(page.keywords || {}).reduce((n, a) => n + a.length, 0),
  };
}
