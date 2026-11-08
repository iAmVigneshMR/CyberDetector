// Minimal RFC 3492 Punycode decoder — used to reveal the real characters
// behind internationalised (xn--) domain labels for homograph detection.
const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700;
const INITIAL_BIAS = 72, INITIAL_N = 128;

function adapt(delta, numPoints, firstTime) {
  delta = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > ((BASE - TMIN) * TMAX) >> 1) {
    delta = Math.floor(delta / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

function basicToDigit(cp) {
  if (cp >= 0x30 && cp < 0x3a) return 26 + (cp - 0x30);
  if (cp >= 0x41 && cp < 0x5b) return cp - 0x41;
  if (cp >= 0x61 && cp < 0x7b) return cp - 0x61;
  return BASE;
}

export function decode(input) {
  const output = [];
  let i = 0, n = INITIAL_N, bias = INITIAL_BIAS;
  let basic = input.lastIndexOf('-');
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j++) {
    if (input.charCodeAt(j) >= 0x80) throw new Error('not-basic');
    output.push(input.charCodeAt(j));
  }
  for (let index = basic > 0 ? basic + 1 : 0; index < input.length; ) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (index >= input.length) throw new Error('invalid-input');
      const digit = basicToDigit(input.charCodeAt(index++));
      if (digit >= BASE) throw new Error('invalid-input');
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    const out = output.length + 1;
    bias = adapt(i - oldi, out, oldi === 0);
    n += Math.floor(i / out);
    i %= out;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

export function toUnicode(host) {
  return host
    .split('.')
    .map((label) => {
      if (!label.startsWith('xn--')) return label;
      try {
        return decode(label.slice(4));
      } catch {
        return label;
      }
    })
    .join('.');
}
