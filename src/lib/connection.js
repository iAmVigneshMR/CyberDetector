import { finding } from './findings.js';

/**
 * Reduce Firefox's webRequest.getSecurityInfo() output to what we display.
 * (Chrome has no API for reading certificates.)
 */
export function summarizeSecurityInfo(info) {
  if (!info) return null;
  const cert = info.certificates?.[0];
  return {
    state: info.state, // secure | weak | broken | insecure
    protocolVersion: info.protocolVersion,
    cipherSuite: info.cipherSuite,
    hsts: info.hsts,
    isUntrusted: !!info.isUntrusted,
    isDomainMismatch: !!info.isDomainMismatch,
    isNotValidAtThisTime: !!info.isNotValidAtThisTime,
    isExtendedValidation: !!info.isExtendedValidation,
    weaknessReasons: info.weaknessReasons || [],
    errorMessage: info.errorMessage || '',
    cert: cert
      ? {
          subject: cert.subject,
          issuer: cert.issuer,
          validFrom: cert.validity?.start,
          validTo: cert.validity?.end,
          fingerprint: cert.fingerprint?.sha256,
          isBuiltInRoot: cert.isBuiltInRoot,
        }
      : null,
  };
}

function cn(dn) {
  return (dn || '').match(/CN=([^,]+)/)?.[1] || (dn || '').match(/O=([^,]+)/)?.[1] || dn || '';
}

/**
 * HTTPS / certificate checks.
 * @param {URL} u
 * @param {object|null} sec summarized security info (Firefox only)
 * @param {object|null} page content-script report
 */
export function analyzeConnection(u, sec, page) {
  const out = [];
  const summary = { https: u.protocol === 'https:', certAvailable: !!sec?.cert, sec };
  const sensitive = page && (page.forms.password > 0 || page.forms.payment > 0);

  if (u.protocol === 'http:') {
    out.push(sensitive
      ? finding('http-sensitive', 'connection', 'high', 'Login or payment form on an unencrypted (HTTP) page', 'Anything you type can be read or modified in transit.')
      : finding('http', 'connection', 'medium', 'Connection is not encrypted (HTTP)'));
  }

  if (page?.forms.insecureActions > 0) {
    out.push(finding('form-http-action', 'connection', 'high', 'Form sends data over unencrypted HTTP', `${page.forms.insecureActions} form(s) submit to an http:// address.`));
  }
  if (page?.mixedContent > 0 && u.protocol === 'https:') {
    out.push(finding('mixed-content', 'connection', 'low', 'Mixed content: some resources load over HTTP', `${page.mixedContent} insecure resource(s).`));
  }

  if (sec) {
    if (sec.isUntrusted) out.push(finding('cert-untrusted', 'connection', 'high', 'Certificate is not trusted', 'Self-signed or issued by an unknown authority.'));
    if (sec.isDomainMismatch) out.push(finding('cert-mismatch', 'connection', 'high', 'Certificate does not match this domain'));
    if (sec.isNotValidAtThisTime) out.push(finding('cert-expired', 'connection', 'high', 'Certificate is expired or not yet valid'));
    if (sec.state === 'broken') out.push(finding('tls-broken', 'connection', 'high', 'Broken TLS connection', sec.errorMessage));
    if (sec.state === 'weak' || /TLSv1(\.[01])?$/.test(sec.protocolVersion || '')) {
      out.push(finding('tls-weak', 'connection', 'medium', `Weak encryption (${sec.protocolVersion || 'weak cipher'})`, (sec.weaknessReasons || []).join(', ')));
    }
    if (sec.cert?.validFrom) {
      const ageDays = Math.floor((Date.now() - sec.cert.validFrom) / 86400_000);
      summary.certAgeDays = ageDays;
      if (ageDays <= 3) out.push(finding('cert-very-new', 'connection', 'low', `Certificate issued ${ageDays} day(s) ago`, 'Phishing sites usually obtain a fresh certificate right before a campaign. Legitimate sites also renew often, so this is a weak signal.'));
    }
    if (sec.cert) {
      out.push(finding('cert-info', 'connection', 'info', `Certificate issued by ${cn(sec.cert.issuer)}`, `Subject: ${cn(sec.cert.subject)}${sec.protocolVersion ? ` · ${sec.protocolVersion}` : ''}`));
    }
  }
  return { findings: out, summary };
}
