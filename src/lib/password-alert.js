// Password-reuse alarm (like Google's "Password Alert").
// The user registers important passwords; we keep only salted PBKDF2-SHA256 hashes plus the
// length (so we only hash candidate input of the right length) and the domains where each
// password legitimately belongs. If one is typed anywhere else, the user is warned immediately —
// this works even when the phishing page itself was not recognised.
import { parseHost } from './domain.js';

const ITERATIONS = 210_000; // OWASP 2023+ recommendation for PBKDF2-HMAC-SHA256
const enc = new TextEncoder();
const hex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
const unhex = (s) => new Uint8Array(s.match(/../g).map((h) => parseInt(h, 16)));

async function pbkdf2(password, saltHex, iterations = ITERATIONS) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unhex(saltHex), iterations }, key, 256);
  return hex(bits);
}

/** Build a stored record. The plain password is never persisted. */
export async function createRecord(label, password, domains) {
  if (!password || password.length < 6) throw new Error('Use a password of at least 6 characters');
  const cleanDomains = domains
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean)
    .map((d) => {
      try {
        return parseHost(new URL(d.includes('://') ? d : `https://${d}`).hostname).registrable;
      } catch {
        return null;
      }
    })
    .filter(Boolean);
  if (!cleanDomains.length) throw new Error('Add at least one site where this password belongs (e.g. google.com)');
  const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
  return {
    id: crypto.randomUUID(),
    label: label.trim() || cleanDomains[0],
    salt,
    iterations: ITERATIONS,
    hash: await pbkdf2(password, salt),
    length: password.length,
    domains: [...new Set(cleanDomains)],
    created: Date.now(),
  };
}

/** Lengths of protected passwords — the only thing content scripts need to know. */
export function protectedLengths(records) {
  return [...new Set(records.map((r) => r.length))];
}

/**
 * Check a typed value against protected passwords.
 * @returns {Promise<null | {label, domains, allowed: boolean}>}
 */
export async function checkTyped(records, value, pageHost) {
  const candidates = records.filter((r) => r.length === value.length);
  if (!candidates.length) return null;
  const site = parseHost(pageHost).registrable;
  for (const r of candidates) {
    if ((await pbkdf2(value, r.salt, r.iterations)) === r.hash) {
      const allowed = r.domains.some((d) => site === d || pageHost === d || pageHost.endsWith('.' + d));
      return { id: r.id, label: r.label, domains: r.domains, allowed };
    }
  }
  return null;
}
