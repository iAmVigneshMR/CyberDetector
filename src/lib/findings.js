// Shared finding model. Every check produces findings of this shape;
// verdict.js turns them into a score + Safe/Warning/Danger level.

export const SEVERITY_WEIGHT = {
  info: 0,
  low: 8,
  medium: 18,
  high: 35,
  critical: 70,
};

export const CATEGORY_LABEL = {
  reputation: 'Reputation / blacklists',
  domain: 'Domain & lookalikes',
  url: 'URL structure',
  connection: 'Connection & certificate',
  content: 'Page content & forms',
  qr: 'QR codes & barcodes',
  text: 'Text in the image',
  links: 'Links found in the media',
};

/**
 * @param {string} id stable identifier
 * @param {keyof CATEGORY_LABEL} category
 * @param {keyof SEVERITY_WEIGHT} severity
 * @param {string} title short human readable
 * @param {string} [detail]
 */
export function finding(id, category, severity, title, detail = '') {
  return { id, category, severity, weight: SEVERITY_WEIGHT[severity], title, detail };
}
