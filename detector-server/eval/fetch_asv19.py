import sys, os, json, io, collections
from datasets import load_dataset
out = sys.argv[1]
ds = load_dataset('Bisher/ASVspoof_2019_LA', split='test', streaming=True).decode(False)
got = collections.Counter(); meta = []; first = None
for i, r in enumerate(ds):
    if first is None: first = {k: (type(v).__name__ if k == 'audio' else v) for k, v in r.items()}; print('row:', first, flush=True)
    lab = r.get('key') if 'key' in r else r.get('label')
    lab = {'bonafide': 'real', 'spoof': 'fake', 0: 'real', 1: 'fake'}.get(lab, lab)
    if got[lab] >= 150: 
        if got['real'] >= 150 and got['fake'] >= 150: break
        continue
    a = r['audio']; data = a['bytes']; name = f"{lab}-{i}.flac"
    open(os.path.join(out, name), 'wb').write(data)
    meta.append({'file': name, 'label': lab, 'system': r.get('system_id') or r.get('attack')}); got[lab] += 1
    if i > 40000: break
print(dict(got), flush=True)
json.dump(meta, open(os.path.join(out, 'meta.json'), 'w'), indent=1)
os._exit(0)
