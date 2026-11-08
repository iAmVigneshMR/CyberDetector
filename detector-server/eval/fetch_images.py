import sys, os, json, collections
from datasets import load_dataset
out = sys.argv[1]; os.makedirs(out, exist_ok=True)
meta = []; per = collections.Counter()
for shard in ['03', '07', '11']:
    ds = load_dataset('ComplexDataLab/OpenFake', data_files={'test': f'core/test-000{shard}-of-00013.parquet'}, split='test', streaming=True).decode(False)
    got = collections.Counter()
    for r in ds:
        lab = r['label']
        if got[lab] >= 100: 
            if all(got[l] >= 100 for l in ('real', 'fake')): break
            continue
        # cap any single generator so one model doesn't dominate
        if lab == 'fake' and per[r['model']] >= 25: continue
        data = r['image']['bytes']
        ext = 'png' if data[:4] == b'\x89PNG' else 'webp' if data[8:12] == b'WEBP' else 'jpg'
        name = f"{lab}-{r['image_sha256'][:16]}.{ext}"
        open(os.path.join(out, name), 'wb').write(data)
        meta.append({'file': name, 'label': lab, 'model': r['model'], 'release_date': r['release_date']})
        got[lab] += 1; per[r['model']] += 1
    print('shard', shard, dict(got), flush=True)
json.dump(meta, open(os.path.join(out, 'meta.json'), 'w'), indent=1)
print(len(meta), 'images;', collections.Counter(m['model'] for m in meta).most_common(40))
os._exit(0)
