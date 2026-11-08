import { BRANDS, brandMentions } from './brands.js';
import { finding } from './findings.js';
import { parseHost } from './domain.js';

// "Sign in with Google" / "Continue with Apple" buttons are legitimate OAuth, not impersonation.
// App-store badges and embedded Google/Apple widgets mention brands without impersonating them.
const BADGE_PHRASE = /(get it on|download on|available on|download from)?\s*(google play|app store|apple store|google maps|google reviews?|google pay|apple pay|microsoft store)/gi;
const OAUTH_PHRASE = /(?:(?:sign|log)\s?(?:in|on|up)|continue|connect)\s+(?:with|using|via)\s+\S+(?:\s+(?:id|account|365|wallet))?/gi;

function mentioned(text, name) {
  const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(^|[^\\p{L}\\p{N}])${esc}($|[^\\p{L}\\p{N}])`, 'iu').test(text);
}

/**
 * Turn the content script's page report into findings.
 * @param {object} page report from content.js
 * @param {object} p parsed host
 * @param {object|null} officialBrand brand that owns this domain, if any
 * @param {number} urlRisk score already accumulated from URL/domain checks
 */
export function analyzePage(page, p, officialBrand, urlRisk) {
  const out = [];
  if (!page) return out;
  const { forms, keywords } = page;
  const hasLogin = forms.password > 0;
  const hasPayment = forms.payment > 0;
  const sensitive = hasLogin || hasPayment || forms.otp > 0;
  const suspiciousDomain = urlRisk >= 15;

  // ---- Forms ----
  if (hasLogin) {
    out.push(suspiciousDomain
      ? finding('login-suspicious', 'content', 'high', 'Password field on a suspicious domain', `${forms.password} password field(s) on ${p.registrable}.`)
      : finding('login-form', 'content', 'info', 'Page contains a login form', `${forms.password} password field(s).`));
  }
  if (hasPayment) {
    out.push(suspiciousDomain
      ? finding('payment-suspicious', 'content', 'high', 'Card/payment fields on a suspicious domain', `${forms.payment} payment field(s).`)
      : finding('payment-form', 'content', 'info', 'Page asks for card/payment details', `${forms.payment} payment field(s).`));
  }
  if (forms.otp > 0 && suspiciousDomain) {
    out.push(finding('otp-suspicious', 'content', 'medium', 'Asks for a one-time code (OTP/2FA) on a suspicious domain', 'Real-time phishing kits relay OTPs to bypass two-factor authentication.'));
  }
  if (sensitive && forms.crossOriginActions.length) {
    const targets = forms.crossOriginActions.map((a) => parseHost(a).registrable);
    const foreign = [...new Set(targets)].filter((t) => t !== p.registrable);
    if (foreign.length) {
      out.push(finding('cross-origin-form', 'content', 'medium', 'Sensitive form submits to a different domain', `Data is sent to: ${foreign.slice(0, 3).join(', ')}`));
    }
  }
  if (forms.mailtoOrScript > 0 && sensitive) {
    out.push(finding('form-odd-action', 'content', 'high', 'Login form posts to email/script handler', 'Phishing kits often email harvested credentials directly.'));
  }
  if (page.seedPhrase) {
    out.push(finding('seed-phrase', 'content', officialBrand ? 'low' : 'high', 'Page asks for a wallet recovery/seed phrase',
      'No legitimate service ever needs your recovery phrase. Entering it gives full control of your wallet.'));
  }

  // ---- Brand impersonation ----
  if (!officialBrand) {
    const strip = (s) => (s || '').replace(OAUTH_PHRASE, ' ').replace(BADGE_PHRASE, ' ');
    const strong = strip([page.title, ...(page.logoAlts || [])].join(' \n '));
    const formText = strip(page.formText);
    const faviconHost = page.favicon ? safeHost(page.favicon) : '';
    for (const brand of BRANDS) {
      const names = brandMentions(brand);
      const inStrong = names.some((n) => mentioned(strong, n));
      const inForm = names.some((n) => mentioned(formText, n));
      const favFromBrand = faviconHost && brand.domains.some((d) => faviconHost === d || faviconHost.endsWith('.' + d));
      if (!inStrong && !inForm && !favFromBrand) continue;
      // Brand's exact name on another TLD (google.fr, amazon.es) is often a legit country site.
      const brandLabel = brand.keywords.includes(p.label);
      if (sensitive && (inStrong || favFromBrand) && !brandLabel) {
        out.push(finding('brand-impersonation', 'content', 'high', `Looks like a ${brand.name} login, but this isn't a ${brand.name} domain`,
          `The page ${favFromBrand ? 'loads the ' + brand.name + ' icon' : 'presents itself as ' + brand.name} and asks for credentials on ${p.registrable}.`));
        break;
      } else if (sensitive && (inForm || brandLabel)) {
        out.push(finding('brand-in-form', 'content', 'medium', `Login form mentions ${brand.name}`, `Real ${brand.name} logins live on ${brand.domains[0]}, not ${p.registrable}.`));
        break;
      } else if (favFromBrand) {
        out.push(finding('brand-favicon', 'content', 'medium', `Uses the ${brand.name} icon on another domain`, faviconHost));
        break;
      }
    }
  }

  // ---- Language: urgency / pressure / reward ----
  const k = keywords || {};
  const urgency = k.urgency || [];
  const threat = k.threat || [];
  const reward = k.reward || [];
  const credential = k.credential || [];
  const pressure = urgency.length + threat.length;
  const scale = officialBrand ? 'info' : null;
  if (pressure >= 4) out.push(finding('urgency-high', 'content', scale || 'medium', 'Strong urgency / pressure language', [...urgency, ...threat].slice(0, 6).join(' · ')));
  else if (pressure >= 2) out.push(finding('urgency', 'content', scale || 'low', 'Urgency / pressure language', [...urgency, ...threat].slice(0, 6).join(' · ')));
  if (reward.length >= 2) out.push(finding('reward-bait', 'content', scale || 'low', 'Prize / reward bait language', reward.slice(0, 5).join(' · ')));
  if (credential.length >= 2 && sensitive) out.push(finding('credential-ask', 'content', scale || 'low', 'Asks to verify identity or account details', credential.slice(0, 5).join(' · ')));

  // ---- Structural signs of a cloned page ----
  const links = page.links || {};
  if (links.total >= 10 && links.nullLinks / links.total > 0.5) {
    out.push(finding('dead-links', 'content', officialBrand ? 'info' : 'low', 'Most links on the page go nowhere', `${links.nullLinks}/${links.total} links are "#" or empty — typical of copied login pages.`));
  }
  if (page.shortLinks?.length) {
    out.push(finding('short-links', 'content', 'info', `${page.shortLinks.length} shortened link(s) on this page`, page.shortLinks.slice(0, 3).join(', ')));
  }
  if (page.disablesRightClick && sensitive && !officialBrand) {
    out.push(finding('anti-inspect', 'content', 'low', 'Page blocks right-click / inspection', 'Phishing kits try to stop users from inspecting the page.'));
  }

  return out;
}

function safeHost(u) {
  try {
    return new URL(u).hostname.toLowerCase();
  } catch {
    return '';
  }
}

/**
 * Findings for the advanced protections (each gated by its own setting).
 * Official brand domains are skipped: their own login pages naturally match their fingerprints.
 */
export function advancedPageFindings(page, p, officialBrand, settings) {
  const out = [];
  if (!page) return out;
  if (settings.aitmDetect && page.idpClone && !officialBrand) {
    const { brand, evidence } = page.idpClone;
    // Okta tenants legitimately run on company custom domains, so Okta clones are only a medium signal.
    const sev = brand === 'Okta' ? 'medium' : 'high';
    out.push(finding('aitm-clone', 'content', sev, `Copy of the ${brand} sign-in page on ${p.registrable}`,
      `${evidence.join('; ')}. Real ${brand} sign-in never runs on this domain — this is how reverse-proxy ("adversary-in-the-middle") kits steal passwords AND 2FA codes.`));
  }
  if (settings.bitbDetect && page.bitb && !officialBrand) {
    out.push(finding('bitb', 'content', 'high', 'Fake browser pop-up window (browser-in-the-browser)',
      `The page draws a window showing "${page.bitb.shownUrl}", but it is part of ${p.registrable}${page.bitb.frameHost && page.bitb.frameHost !== p.host ? ` (content from ${page.bitb.frameHost})` : ''}. Real pop-ups can be dragged outside the browser window.`));
  }
  if (settings.clickfixGuard && page.clickfixLure) {
    out.push(finding('clickfix-lure', 'content', 'critical', 'Page tells you to paste and run a command ("ClickFix")',
      `Found "${page.clickfixLure[0]}" together with "${page.clickfixLure[1]}". Real CAPTCHAs never ask you to press Win+R or paste anything.`));
  }
  return out;
}
