import sys, os, json, time, collections
import numpy as np, torch
from PIL import Image
from transformers import pipeline
torch.set_num_threads(int(os.environ.get("THREADS","16")))
d = sys.argv[1]; out = sys.argv[2]
meta = json.load(open(os.path.join(d, 'meta.json')))
AI_LABELS = {'artificial', 'ai', 'fake', 'ai-generated', 'dalle', 'sd', 'deepfake'}
MODELS = sys.argv[3].split(',')
def auc(y, s):
    order = np.argsort(s); y = np.array(y)[order]
    pos = y.sum(); neg = len(y) - pos
    ranks = np.arange(1, len(y) + 1)
    return (ranks[y == 1].sum() - pos * (pos + 1) / 2) / (pos * neg)
results = json.load(open(out)) if os.path.exists(out) else {}
imgs = []
for m in meta:
    im = Image.open(os.path.join(d, m['file'])); im.load(); imgs.append(im.convert('RGB'))
for model in MODELS:
    if model in results: continue
    t = time.time()
    try:
        clf = pipeline('image-classification', model=model, device='cpu')
    except Exception as e:
        results[model] = {'error': str(e)[:200]}; print(model, 'LOAD FAIL', e, flush=True); continue
    scores = []
    for i in range(0, len(imgs), 16):
        for preds in clf(imgs[i:i + 16], top_k=None):
            scores.append(sum(p['score'] for p in preds if p['label'].lower() in AI_LABELS))
    y = [1 if m['label'] == 'fake' else 0 for m in meta]
    s = np.array(scores)
    real_s = s[np.array(y) == 0]
    thr5 = float(np.quantile(real_s, 0.95))  # threshold giving 5% false positives on real
    per = collections.defaultdict(list)
    for m, sc in zip(meta, s):
        if m['label'] == 'fake': per[m['model']].append(sc >= thr5)
    results[model] = {
        'auc': round(float(auc(y, s)), 3),
        'acc@0.5': round(float(np.mean((s >= 0.5) == np.array(y))), 3),
        'fpr@0.5': round(float(np.mean(real_s >= 0.5)), 3),
        'tpr@0.5': round(float(np.mean(s[np.array(y) == 1] >= 0.5)), 3),
        'thr@fpr5': round(thr5, 3),
        'tpr@fpr5': round(float(np.mean(s[np.array(y) == 1] >= thr5)), 3),
        'per_generator@fpr5': {k: round(float(np.mean(v)), 2) for k, v in sorted(per.items())},
        'sec_per_img': round((time.time() - t) / len(imgs), 3),
        'scores': [round(float(x), 4) for x in s],
    }
    r = results[model]
    print(f"{model:55} AUC={r['auc']} acc@.5={r['acc@0.5']} FPR@.5={r['fpr@0.5']} TPR@.5={r['tpr@0.5']} TPR@FPR5%={r['tpr@fpr5']} ({r['sec_per_img']}s/img)", flush=True)
    json.dump(results, open(out, 'w'))
os._exit(0)
