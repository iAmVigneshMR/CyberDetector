// Combine findings into a 0–100 risk score and a Safe / Warning / Danger level.

const THRESHOLDS = {
  relaxed: { warning: 35, danger: 75 },
  balanced: { warning: 25, danger: 60 },
  strict: { warning: 15, danger: 45 },
};

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
// Stop any single category from dominating (e.g. 6 weak URL signals).
const CATEGORY_CAP = { url: 45, domain: 70, connection: 60, content: 70, reputation: 100 };

export function computeVerdict(findings, { sensitivity = 'balanced', trusted = false } = {}) {
  const sorted = [...findings].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.weight - a.weight);
  if (trusted) {
    return { level: 'safe', score: 0, findings: sorted, reason: 'You marked this site as trusted' };
  }
  const byCat = {};
  for (const f of findings) byCat[f.category] = (byCat[f.category] || 0) + f.weight;
  let score = 0;
  for (const [cat, sum] of Object.entries(byCat)) score += Math.min(sum, CATEGORY_CAP[cat] ?? 60);
  score = Math.min(100, Math.round(score));

  const t = THRESHOLDS[sensitivity] || THRESHOLDS.balanced;
  let level = score >= t.danger ? 'danger' : score >= t.warning ? 'warning' : 'safe';
  if (findings.some((f) => f.severity === 'critical')) {
    level = 'danger';
    score = Math.max(score, 90);
  }
  const top = sorted.find((f) => f.weight > 0);
  return { level, score, findings: sorted, reason: top?.title || 'No phishing indicators found' };
}

export const LEVEL_META = {
  safe: { label: 'Safe', color: '#16a34a', badge: '✓' },
  warning: { label: 'Warning', color: '#d97706', badge: '!' },
  danger: { label: 'Danger', color: '#dc2626', badge: '✕' },
  unknown: { label: 'Not scanned', color: '#64748b', badge: '' },
};
