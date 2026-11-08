// Domain registration date via RDAP — the registries' official, free replacement for WHOIS.
// rdap.org redirects each query to the authoritative registry server for that TLD.
import { ext, hasDataConsent } from './ext.js';
import { finding } from './findings.js';

const CACHE_MS = 7 * 24 * 3600_000;

export function registrationDate(rdap) {
  const ev = (rdap?.events || []).find((e) => /^registration$/i.test(e.eventAction));
  const t = ev ? Date.parse(ev.eventDate) : NaN;
  return Number.isNaN(t) ? null : t;
}

/** @returns {Promise<number|null|undefined>} registration timestamp, null if unknown, undefined if skipped */
export async function domainRegistered(registrable) {
  if (!(await hasDataConsent('browsingActivity'))) return undefined;
  const key = `rdap:${registrable}`;
  const { [key]: cached } = await ext.storage.local.get(key);
  if (cached && Date.now() - cached.ts < CACHE_MS) return cached.registered;
  const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(registrable)}`, {
    credentials: 'omit',
    headers: { accept: 'application/rdap+json, application/json' },
    signal: AbortSignal.timeout(8000),
  });
  if (res.status === 404) {
    await ext.storage.local.set({ [key]: { ts: Date.now(), registered: null } });
    return null;
  }
  if (!res.ok) throw new Error(`RDAP HTTP ${res.status}`);
  const registered = registrationDate(await res.json());
  await ext.storage.local.set({ [key]: { ts: Date.now(), registered } });
  return registered;
}

export function ageFindings(registered) {
  if (typeof registered !== 'number') return [];
  const days = Math.floor((Date.now() - registered) / 86400_000);
  const when = new Date(registered).toISOString().slice(0, 10);
  if (days < 7) return [finding('rdap-new', 'domain', 'high', `Domain registered ${days} day(s) ago`, `Registered ${when} (RDAP). Most phishing domains are used within days of registration.`)];
  if (days < 30) return [finding('rdap-young', 'domain', 'medium', `Domain registered ${days} days ago`, `Registered ${when} (RDAP).`)];
  return [finding('rdap-age', 'domain', 'info', `Domain registered ${Math.floor(days / 365) ? `${(days / 365).toFixed(1)} years` : `${days} days`} ago`, `Registered ${when} (RDAP).`)];
}
