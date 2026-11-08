// Analyse an email opened in Gmail / Outlook web (data extracted by content/guard.js).
import { BRANDS, officialBrandFor } from './brands.js';
import { parseHost } from './domain.js';
import { analyzeUrl } from './url-analyzer.js';
import { checkLookalike } from './typosquat.js';
import { isShortener } from './shortener.js';
import { finding } from './findings.js';
import { computeVerdict } from './verdict.js';

const FREE_MAIL = new Set(['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'yahoo.com', 'aol.com', 'icloud.com', 'proton.me', 'protonmail.com', 'gmx.com', 'mail.com', 'zoho.com', 'yandex.com', 'rediffmail.com']);
const RISKY_ATTACHMENT = /\.(exe|scr|com|pif|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|hta|msi|msix|lnk|iso|img|vhd|vhdx|jar|cpl|reg|chm|xll|one|svg|html?|shtml|zip\.exe|docm|xlsm|pptm)$/i;
const DOUBLE_EXT = /\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|js|hta|vbs|cmd|bat|lnk|html?)$/i;
const URGENCY = /(urgent|immediately|within 24 hours|account (has been )?(suspended|locked|limited)|verify your (account|identity)|unusual (sign-in|activity)|password (will )?expire|final notice|payment (failed|declined)|invoice attached|wire transfer|gift cards?)/gi;

function domainOf(email) {
  const m = String(email || '').toLowerCase().match(/@([a-z0-9.-]+\.[a-z]{2,})/);
  return m ? m[1] : '';
}

/**
 * @param {{fromName, fromEmail, replyTo, subject, links: {text, href}[], attachments: string[], bodyText}} mail
 */
export function analyzeEmail(mail, settings) {
  const out = [];
  const fromDomain = domainOf(mail.fromEmail);
  const fromReg = fromDomain ? parseHost(fromDomain).registrable : '';
  const name = String(mail.fromName || '');

  // 1. Display name claims a brand the address doesn't belong to
  for (const brand of BRANDS) {
    const names = [brand.name, ...(brand.mentions || [])].filter((n) => n.length >= 4);
    if (!names.some((n) => new RegExp(`\\b${n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(name))) continue;
    // The sender's domain must belong to the SAME brand (gmail.com is Google's, not PayPal's).
    if (fromDomain && officialBrandFor(fromDomain) !== brand) {
      out.push(finding('mail-brand-spoof', 'content', FREE_MAIL.has(fromReg) ? 'high' : 'medium',
        `Sender name says "${name}" but the address is ${mail.fromEmail}`,
        `Real ${brand.name} email comes from ${brand.domains.slice(0, 2).join(' / ')}.`));
    }
    break;
  }
  // 2. Display name contains a different email address ("support@paypal.com" <x@evil.io>)
  const nameEmail = name.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i);
  if (nameEmail && domainOf(nameEmail[0]) !== fromDomain) {
    out.push(finding('mail-name-email', 'content', 'high', 'Sender name contains a different email address', `Shown "${nameEmail[0]}", actually sent from ${mail.fromEmail}.`));
  }
  // 3. Sender domain is a lookalike
  if (fromDomain) {
    const lk = checkLookalike(parseHost(fromDomain)).findings.filter((f) => f.weight > 0);
    for (const f of lk) out.push({ ...f, id: `mail-${f.id}`, title: `Sender domain: ${f.title}` });
  }
  // 4. Reply-To goes elsewhere
  const replyDomain = domainOf(mail.replyTo);
  if (replyDomain && fromReg && parseHost(replyDomain).registrable !== fromReg) {
    out.push(finding('mail-reply-to', 'content', 'medium', 'Replies go to a different domain', `Reply-To: ${mail.replyTo}`));
  }

  // 5. Links: text shows one destination, href goes to another; risky link targets
  let mismatches = 0;
  const risky = [];
  for (const { text, href } of (mail.links || []).slice(0, 80)) {
    let u;
    try { u = new URL(href); } catch { continue; }
    if (!/^https?:$/.test(u.protocol)) continue;
    const shown = String(text || '').trim().match(/(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]|$)/i);
    if (shown && !/\s/.test(text.trim())) {
      const shownReg = parseHost(shown[1]).registrable;
      if (shownReg !== parseHost(u.hostname).registrable) {
        mismatches++;
        if (mismatches <= 3) out.push(finding('mail-link-mismatch', 'content', 'high', 'Link text shows a different address than where it goes', `Shows "${shown[1]}", opens ${u.hostname}`));
      }
    }
    const a = analyzeUrl(u.href);
    const lk = checkLookalike(a.parsed);
    const v = computeVerdict([...a.findings, ...lk.findings], { sensitivity: settings.sensitivity });
    if (v.level !== 'safe' || isShortener(u.hostname)) risky.push({ host: u.hostname, why: isShortener(u.hostname) ? 'shortened link' : v.reason, level: v.level });
  }
  if (risky.length) {
    const worst = risky.some((r) => r.level === 'danger') ? 'high' : risky.some((r) => r.level === 'warning') ? 'medium' : 'low';
    out.push(finding('mail-risky-links', 'url', worst, `${risky.length} suspicious link(s) in this email`, risky.slice(0, 4).map((r) => `${r.host} (${r.why})`).join(' · ')));
  }

  // 6. Attachments
  for (const att of (mail.attachments || []).slice(0, 20)) {
    if (DOUBLE_EXT.test(att)) out.push(finding('mail-double-ext', 'content', 'high', `Disguised attachment: ${att}`, 'A double file extension hides an executable or web page.'));
    else if (RISKY_ATTACHMENT.test(att)) out.push(finding('mail-risky-attachment', 'content', /\.(html?|svg|shtml)$/i.test(att) ? 'high' : 'medium', `Risky attachment type: ${att}`, /\.(html?|svg|shtml)$/i.test(att) ? 'HTML/SVG attachments are a common way to deliver fake login pages.' : 'This file type can run code on your computer.'));
  }

  // 7. Pressure language
  const urg = [...new Set(((mail.subject || '') + ' ' + (mail.bodyText || '')).toLowerCase().match(URGENCY) || [])];
  if (urg.length >= 2) out.push(finding('mail-urgency', 'content', 'low', 'Urgency / pressure language', urg.slice(0, 5).join(' · ')));

  const verdict = computeVerdict(out, { sensitivity: settings.sensitivity });
  return { ...verdict, fromDomain, linkCount: (mail.links || []).length };
}
