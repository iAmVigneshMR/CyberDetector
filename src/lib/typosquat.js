import { BRANDS, officialBrandFor } from './brands.js';
import { RESTRICTED_SUFFIXES } from './domain.js';
import { finding } from './findings.js';

// Unicode confusables (Cyrillic / Greek / misc) that render like Latin letters.
const CONFUSABLES = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ԁ': 'd',
  'ɡ': 'g', 'һ': 'h', 'ⅼ': 'l', 'ѕ': 's', 'ԛ': 'q', 'ԝ': 'w', 'ν': 'v', 'ο': 'o', 'α': 'a', 'ι': 'i',
  'κ': 'k', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'ӏ': 'l', 'ɩ': 'i', 'ꞵ': 'b', 'ʏ': 'y', 'ᴠ': 'v', 'ᴡ': 'w',
  'ı': 'i', 'ł': 'l', 'ø': 'o', 'ö': 'o', 'ó': 'o', 'ò': 'o', 'ô': 'o', 'õ': 'o', 'á': 'a', 'à': 'a',
  'â': 'a', 'ä': 'a', 'ã': 'a', 'å': 'a', 'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e', 'í': 'i', 'ì': 'i',
  'î': 'i', 'ï': 'i', 'ú': 'u', 'ù': 'u', 'û': 'u', 'ü': 'u', 'ç': 'c', 'ñ': 'n', 'ý': 'y', 'ş': 's',
  'ğ': 'g', 'ţ': 't', 'ș': 's', 'ț': 't', 'ė': 'e', 'ę': 'e', 'ą': 'a', 'ž': 'z', 'ś': 's', 'ć': 'c',
  // Digits / symbols used as letters
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g', '$': 's', '@': 'a', '|': 'l',
};

/** Collapse visually-similar characters so "paypa1" and "pаypal" (Cyrillic а) both become "paypal". */
export function skeleton(s) {
  let out = '';
  for (const ch of s.toLowerCase()) out += CONFUSABLES[ch] ?? ch;
  return out.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/i/g, 'l');
}

const QWERTY_ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm'];
function keyboardAdjacent(a, b) {
  for (let r = 0; r < QWERTY_ROWS.length; r++) {
    const i = QWERTY_ROWS[r].indexOf(a);
    if (i < 0) continue;
    for (let dr = -1; dr <= 1; dr++) {
      const row = QWERTY_ROWS[r + dr];
      if (!row) continue;
      for (let dc = -1; dc <= 1; dc++) if (row[i + dc] === b) return true;
    }
  }
  return false;
}

/** Optimal-string-alignment (Damerau) distance, early exit above `max`. */
export function editDistance(a, b, max = 3) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    let rowMin = Infinity;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      rowMin = Math.min(rowMin, d[i][j]);
    }
    if (rowMin > max) return max + 1;
  }
  return d[a.length][b.length];
}

/** Describe a single edit between two strings, or null if not exactly one edit. */
function singleEdit(candidate, target) {
  if (candidate.length === target.length) {
    const diffs = [];
    for (let i = 0; i < target.length; i++) if (candidate[i] !== target[i]) diffs.push(i);
    if (diffs.length === 1) return { kind: 'sub', from: target[diffs[0]], to: candidate[diffs[0]] };
    if (diffs.length === 2 && diffs[1] === diffs[0] + 1 && candidate[diffs[0]] === target[diffs[1]] && candidate[diffs[1]] === target[diffs[0]]) return { kind: 'swap' };
    return null;
  }
  const [long, short, kind] = candidate.length > target.length ? [candidate, target, 'ins'] : [target, candidate, 'del'];
  if (long.length - short.length !== 1) return null;
  for (let i = 0; i < long.length; i++) {
    if (long.slice(0, i) + long.slice(i + 1) === short) {
      const ch = long[i];
      const fatFinger = [long[i - 1], long[i + 1]].some((n) => n && keyboardAdjacent(ch, n));
      return { kind, ch, doubled: long[i - 1] === ch || long[i + 1] === ch, fatFinger };
    }
  }
  return null;
}

/** Substring of `label` (same first letter) within one edit of `kw`, e.g. "microsof" in "newsupdatedmicrosof". */
function fuzzyContains(label, kw) {
  for (let len = kw.length - 1; len <= kw.length + 1; len++) {
    for (let i = 0; i + len <= label.length; i++) {
      const sub = label.slice(i, i + len);
      if (sub === label || sub[0] !== kw[0]) continue;
      if (editDistance(sub, kw, 1) === 1) return sub;
    }
  }
  return null;
}

// Words commonly glued onto brand names in combosquatting domains.
const LURE_WORDS = ['login', 'logon', 'signin', 'sign-in', 'secure', 'security', 'verify', 'verification', 'account', 'support', 'update', 'auth', 'wallet', 'service', 'services', 'help', 'online', 'bank', 'billing', 'recovery', 'unlock', 'confirm', 'customer', 'refund', 'claim', 'reward', 'gift', 'alert', 'notice', 'id', 'access', 'portal', 'web', 'app', 'team', 'safe', 'center', 'centre', 'kyc', 'pay', 'payment', 'invoice', 'delivery', 'track', 'parcel'];

const SCRIPT_TESTS = [
  ['Latin', /\p{Script=Latin}/u],
  ['Cyrillic', /\p{Script=Cyrillic}/u],
  ['Greek', /\p{Script=Greek}/u],
  ['Armenian', /\p{Script=Armenian}/u],
  ['Han', /\p{Script=Han}/u],
  ['Arabic', /\p{Script=Arabic}/u],
];
function scriptsIn(s) {
  return SCRIPT_TESTS.filter(([, re]) => re.test(s)).map(([n]) => n);
}

const SEVERITY_ORDER = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/**
 * Lookalike / typosquat / combosquat / homograph analysis of a parsed host.
 * @returns {{findings: object[], officialBrand: object|null}}
 */
export function checkLookalike(p) {
  const findings = [];
  if (p.isIP) return { findings, officialBrand: null };

  const officialBrand = officialBrandFor(p.host);
  if (officialBrand) {
    findings.push(finding('official-domain', 'domain', 'info', `Official ${officialBrand.name} domain`, p.registrable));
    return { findings, officialBrand };
  }

  // --- IDN / homograph ---
  if (p.host.includes('xn--')) {
    const mixed = p.unicodeHost.split('.').filter((l) => scriptsIn(l).length > 1);
    if (mixed.length) {
      findings.push(finding('idn-mixed-script', 'domain', 'high', 'Mixed alphabets in domain (homograph attack)',
        `"${p.unicodeHost}" mixes ${scriptsIn(mixed[0]).join(' + ')} characters that can look identical to Latin letters.`));
    } else {
      findings.push(finding('idn', 'domain', 'low', 'Internationalised (punycode) domain', `${p.host} is displayed as "${p.unicodeHost}".`));
    }
  }

  if (RESTRICTED_SUFFIXES.has(p.suffix)) return { findings, officialBrand: null };

  const label = p.label;
  const uLabel = p.unicodeLabel;
  const labelSkel = skeleton(uLabel);
  const tokens = label.split(/[-_]+/).filter(Boolean);
  const best = new Map(); // brand name -> finding

  const consider = (brand, f) => {
    const prev = best.get(brand.name);
    if (!prev || SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[prev.severity]) best.set(brand.name, f);
  };

  for (const brand of BRANDS) {
    for (const kw of brand.keywords) {
      const kwSkel = skeleton(kw);
      if (label === kw) {
        consider(brand, finding('brand-other-tld', 'domain', 'medium', `"${kw}" brand name on a domain not in our official list`,
          `${p.registrable} may be a regional ${brand.name} site or an impostor — official: ${brand.domains.slice(0, 3).join(', ')}.`));
        continue;
      }
      if (kw.length >= 4 && labelSkel === kwSkel) {
        consider(brand, finding('homoglyph', 'domain', 'high', `Lookalike of ${brand.name} (character substitution)`,
          `"${uLabel}" imitates "${kw}" using similar-looking characters.`));
        continue;
      }
      if (kw.length >= 5) {
        const dist = editDistance(label, kw, 2);
        let typo = false;
        if (dist === 1) {
          const e = singleEdit(label, kw);
          if (kw.length >= 7) typo = true;
          else if (e && (e.kind === 'swap' || e.kind === 'del' || (e.kind === 'ins' && (e.doubled || e.fatFinger)) || (e.kind === 'sub' && keyboardAdjacent(e.from, e.to)))) typo = true;
        } else if (dist === 2 && kw.length >= 10) typo = true;
        if (typo) {
          consider(brand, finding('typosquat', 'domain', 'high', `Possible typosquat of ${brand.name}`,
            `"${label}" is ${dist} keystroke${dist > 1 ? 's' : ''} away from "${kw}".`));
          continue;
        }
      }
      if (kw.length >= 7 && !label.includes(kw)) {
        const near = fuzzyContains(label, kw);
        if (near) {
          consider(brand, finding('typo-combo', 'domain', 'low', `Near-spelling of "${kw}" inside the domain`,
            `"${near}" in ${p.registrable} is one character away from "${kw}".`));
          continue;
        }
      }
      if (kw.length >= 4) {
        const inTokens = tokens.includes(kw) && tokens.length > 1;
        const glued = label.includes(kw) && LURE_WORDS.some((w) => w.length >= 3 && label.replace(kw, '').includes(w));
        const skelGlued = kw.length >= 5 && !label.includes(kw) && labelSkel.includes(kwSkel);
        if (skelGlued) {
          consider(brand, finding('homoglyph-combo', 'domain', 'high', `Disguised ${brand.name} name inside domain`,
            `"${uLabel}" hides "${kw}" using lookalike characters.`));
        } else if (inTokens || glued) {
          consider(brand, finding('combosquat', 'domain', 'medium', `Brand name "${kw}" combined with other words`,
            `${p.registrable} is not owned by ${brand.name}; attackers often register names like "${kw}-login" or "${kw}secure".`));
        }
      }
    }

    // Brand inside the *subdomain* while the real domain is something else:
    //   paypal.com.account-verify.xyz  → real site is account-verify.xyz
    if (p.subdomain) {
      const officialInSub = brand.domains.find((d) => p.subdomain === d || p.subdomain.includes(d + '.') || p.subdomain.endsWith(d));
      if (officialInSub) {
        consider(brand, finding('brand-domain-in-subdomain', 'domain', 'high', `"${officialInSub}" appears in the subdomain`,
          `The real site is ${p.registrable}, not ${brand.name}. Text before the last dot-separated domain is controlled by the site owner.`));
      } else {
        const subTokens = p.subdomain.split(/[.\-_]+/);
        const kw = brand.keywords.find((k) => k.length >= 5 && subTokens.includes(k));
        if (kw) {
          consider(brand, finding('brand-in-subdomain', 'domain', 'medium', `"${kw}" used as a subdomain`,
            `${p.host} belongs to ${p.registrable}, not ${brand.name}.`));
        }
      }
    }
  }

  findings.push(...best.values());
  return { findings, officialBrand: null };
}
