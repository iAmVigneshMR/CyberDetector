import sys, os, json, time, subprocess
import numpy as np, torch
from transformers import pipeline
torch.set_num_threads(int(os.environ.get('THREADS', '8')))
sets = sys.argv[1].split(',')   # dirs with meta.json
out = sys.argv[2]; MODELS = sys.argv[3].split(',')
AI = {'fake', 'spoof', 'deepfake'}
def decode(p):
    r = subprocess.run(['ffmpeg', '-v', 'error', '-i', p, '-t', '600', '-ac', '1', '-ar', '16000', '-f', 'f32le', '-'], capture_output=True)
    return np.frombuffer(r.stdout, dtype=np.float32)
def auc(y, s):
    o = np.argsort(s); y = np.array(y)[o]; P = y.sum(); N = len(y) - P
    return (np.arange(1, len(y) + 1)[y == 1].sum() - P * (P + 1) / 2) / (P * N)
data = {}
for d in sets:
    meta = json.load(open(os.path.join(d, 'meta.json')))
    data[os.path.basename(d)] = [(decode(os.path.join(d, m['file'])), 1 if m['label'] == 'fake' else 0) for m in meta]
results = json.load(open(out)) if os.path.exists(out) else {}
for model in MODELS:
    if model in results: continue
    t = time.time()
    clf = pipeline('audio-classification', model=model, device='cpu')
    res = {}
    for name, items in data.items():
        scores = []
        for wav, _ in items:
            chunks = [wav[i:i + 64000] for i in range(0, len(wav), 64000)]
            chunks = [c for c in chunks if len(c) >= 8000] or [wav]
            preds = clf([{'raw': c, 'sampling_rate': 16000} for c in chunks], top_k=None)
            cs = [sum(p['score'] for p in pr if p['label'].lower() in AI) for pr in preds]
            a = np.array(cs); scores.append(float(max(a.mean(), np.quantile(a, 0.9) * 0.9)))
        y = [l for _, l in items]; s = np.array(scores); real = s[np.array(y) == 0]
        thr5 = float(np.quantile(real, 0.95)); thr20 = float(np.quantile(real, 0.80))
        res[name] = {'auc': round(float(auc(y, s)), 3), 'acc@0.5': round(float(np.mean((s >= 0.5) == np.array(y))), 3),
                     'fpr@0.5': round(float(np.mean(real >= 0.5)), 3), 'tpr@0.5': round(float(np.mean(s[np.array(y) == 1] >= 0.5)), 3),
                     'thr@fpr5': round(thr5, 4), 'thr@fpr20': round(thr20, 4), 'tpr@fpr5': round(float(np.mean(s[np.array(y) == 1] >= thr5)), 3),
                     'scores': [round(float(x), 4) for x in s]}
        r = res[name]
        print(f"{model:60} [{name}] AUC={r['auc']} acc@.5={r['acc@0.5']} FPR@.5={r['fpr@0.5']} TPR@.5={r['tpr@0.5']} TPR@FPR5%={r['tpr@fpr5']}", flush=True)
    res['sec'] = round(time.time() - t)
    results[model] = res
    json.dump(results, open(out, 'w'))
os._exit(0)
