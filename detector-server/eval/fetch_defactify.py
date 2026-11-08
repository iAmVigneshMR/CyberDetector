import sys, os, json, collections
from datasets import load_dataset
out = sys.argv[1]; meta = []; got = collections.Counter(); per = collections.Counter()
for shard in ['00001', '00004']:
    ds = load_dataset('Rajarshi-Roy-research/Defactify_Image_Dataset', data_files={'test': f'data/test-{shard}-of-00008.parquet'}, split='test', streaming=True).decode(False)
    local = collections.Counter()
    for r in ds:
        lab = 'real' if r['Label_A'] == 0 else 'fake'
        if local[lab] >= 75:
            if local['real'] >= 75 and local['fake'] >= 75: break
            continue
        data = r['Image']['bytes']; ext = 'png' if data[:4] == b'\x89PNG' else 'jpg'
        name = f"{lab}-{shard}-{sum(local.values())}.{ext}"
        open(os.path.join(out, name), 'wb').write(data)
        meta.append({'file': name, 'label': lab, 'model': f"src{r['Label_B']}"}); local[lab] += 1; per[r['Label_B']] += 1
    print(shard, dict(local), flush=True)
print('sources', dict(per), flush=True)
json.dump(meta, open(os.path.join(out, 'meta.json'), 'w'), indent=1)
os._exit(0)
