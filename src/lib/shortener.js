// URL shortener detection + expansion.
export const SHORTENERS = new Set([
  'bit.ly', 'bitly.com', 'j.mp', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'v.gd', 'buff.ly',
  'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 'bl.ink', 't.ly', 's.id', 'lnkd.in',
  'trib.al', 'shorte.st', 'adf.ly', 'bc.vc', 'x.co', 'soo.gd', 'clck.ru', 'u.to', 'tr.im', 'mcaf.ee',
  'db.tt', '1drv.ms', 'forms.gle', 'amzn.to', 'aka.ms', 'bit.do', 'qrco.de', 'tiny.one', 'shorturl.gg',
  'short.gy', 'surl.li', 'urlz.fr', 'snip.ly', 'cli.re', 'rotf.lol', 'tinu.be', 'l.ead.me', 'han.gl',
  'me2.do', 'linktr.ee', 'qr.link', 'shrtco.de', 'gg.gg', 'ln.run', 'dub.sh', 'go.link', 'shor.by',
  'zpr.io', 'kutt.it', 'ouo.io', 'tny.im', 'urlr.me', 'spoo.me', 'y2u.be',
]);

export function isShortener(hostname) {
  const h = hostname.toLowerCase().replace(/^www\./, '');
  return SHORTENERS.has(h);
}

const META_REFRESH = /<meta[^>]+http-equiv=["']?refresh["']?[^>]*content=["']?\s*\d+\s*;\s*url=([^"'>\s]+)/i;
const JS_REDIRECT = /(?:location\.(?:replace|assign)\(|location(?:\.href)?\s*=\s*)["'](https?:\/\/[^"']+)["']/i;

/**
 * Follow a shortened URL to its destination.
 * Requests are made without cookies so the shortener can't tie the lookup to you.
 * @returns {Promise<{original: string, final: string, hops: string[], error?: string}>}
 */
export async function expandUrl(url, maxHops = 6) {
  const hops = [url];
  let current = url;
  try {
    for (let i = 0; i < maxHops; i++) {
      const res = await fetch(current, {
        method: 'GET',
        redirect: 'follow',
        credentials: 'omit',
        cache: 'no-store',
        signal: AbortSignal.timeout(8000),
      });
      if (res.url && res.url !== current) {
        current = res.url;
        hops.push(current);
      }
      // Some shorteners (e.g. t.co for browsers) return an HTML/JS redirect instead of a 30x.
      const ctype = res.headers.get('content-type') || '';
      if (!ctype.includes('html')) break;
      const html = (await res.text()).slice(0, 65536);
      const m = html.match(META_REFRESH) || html.match(JS_REDIRECT);
      if (!m) break;
      const next = new URL(m[1].replace(/&amp;/g, '&'), current).href;
      if (next === current || hops.includes(next)) break;
      current = next;
      hops.push(current);
      if (!isShortener(new URL(current).hostname)) break;
    }
    return { original: url, final: current, hops };
  } catch (e) {
    return { original: url, final: current, hops, error: e.name === 'TimeoutError' ? 'Timed out' : String(e.message || e) };
  }
}
