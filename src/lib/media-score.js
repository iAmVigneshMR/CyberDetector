// Combine API detection, provenance metadata and local heuristics into one
// "synthetic probability" with an honest confidence label.

const COMMON_AI_SIZES = new Set([
  '512x512', '768x768', '1024x1024', '1536x1536', '2048x2048', '1024x1792', '1792x1024', '1536x1024', '1024x1536',
  '832x1216', '1216x832', '896x1152', '1152x896', '768x1344', '1344x768', '640x1536', '1536x640', '1408x768', '768x1408',
  '1280x720', '720x1280', '1920x1080', '1080x1920',
]);

/**
 * @param {object} meta from extractMetadata
 * @param {object|null} ai from detectAI
 * @param {object|null} ela from errorLevelAnalysis
 */
export function combineMediaScore(meta, ai, ela) {
  const signals = [];
  const add = (label, effect, detail = '') => signals.push({ label, effect, detail });

  const markers = meta.markers || [];
  const strongAI = markers.find((m) => m.kind === 'ai' && m.strength === 'strong');
  const aiEdit = markers.find((m) => m.kind === 'ai-edit' && m.strength !== 'weak');
  const mediumAI = markers.find((m) => m.kind === 'ai' && m.strength === 'medium');
  const authentic = markers.find((m) => m.kind === 'authentic' && m.strength === 'medium');
  const camera = markers.find((m) => m.kind === 'authentic' && m.strength === 'weak');
  const edited = markers.find((m) => m.kind === 'edited');

  let p;
  let confidence;
  let basis;

  if (ai) {
    p = ai.score;
    confidence = 'high';
    basis = `${ai.provider} detection model`;
    add(`${ai.provider}: ${(ai.score * 100).toFixed(0)}% synthetic`, ai.score >= 0.5 ? '+' : '-');
  } else {
    // Heuristic prior without a detection model — deliberately conservative.
    p = 0.3;
    confidence = 'low';
    basis = 'metadata heuristics only (no detection API configured)';
    if (meta.kind === 'image') {
      if (camera) { p -= 0.15; add('Camera EXIF present', '-', camera.label); }
      else if (meta.metadataStripped) { p += 0.05; add('Metadata stripped', '±', 'Common on social media; weak evidence either way.'); }
      const size = `${meta.width}x${meta.height}`;
      if (COMMON_AI_SIZES.has(size) && !camera) { p += 0.1; add(`Dimensions ${size} match common AI generator output`, '+'); }
      if (ela && ela.hotspots.length >= 3 && meta.format === 'JPEG') { p += 0.05; add(`${ela.hotspots.length} ELA hotspots`, '+', 'Regions with inconsistent compression — possible local edits.'); }
    }
  }

  if (strongAI) {
    p = Math.max(p, 0.97);
    confidence = 'high';
    basis = ai ? `${basis} + provenance metadata` : 'provenance metadata';
    add(strongAI.label, '+', strongAI.source);
  } else if (aiEdit) {
    p = Math.max(p, 0.85);
    confidence = 'high';
    add(aiEdit.label, '+', aiEdit.source);
  } else if (mediumAI) {
    p = Math.max(p, 0.75);
    if (!ai) confidence = 'medium';
    add(mediumAI.label, '+', mediumAI.source);
  }
  if (authentic && !strongAI && !aiEdit) {
    p = ai ? p * 0.8 : Math.min(p, 0.1);
    if (!ai) confidence = 'medium';
    add(authentic.label, '-', `${authentic.source}${meta.c2pa ? ' (signature not verified)' : ''}`);
  }
  if (edited) add(edited.label, '±', 'Editing alone does not mean manipulation.');

  p = Math.min(1, Math.max(0, p));
  let level, verdict;
  if (p >= 0.7) { level = 'danger'; verdict = strongAI && !ai ? 'Declared AI-generated' : 'Likely AI-generated / manipulated'; }
  else if (p >= 0.4) { level = 'warning'; verdict = 'Possibly synthetic or manipulated'; }
  else if (confidence === 'low') { level = 'unknown'; verdict = 'Inconclusive — no strong signals'; }
  else { level = 'safe'; verdict = 'No signs of AI generation detected'; }

  return { probability: p, level, verdict, confidence, basis, signals };
}
