import sys, os, zipfile, csv, io, random, json
from huggingface_hub import HfFileSystem
out = sys.argv[1]
fs = HfFileSystem()
f = fs.open('datasets/mueller91/In-the-Wild/release_in_the_wild.zip', 'rb', block_size=2**20)
z = zipfile.ZipFile(f)
names = z.namelist()
metaname = [n for n in names if n.endswith('meta.csv')][0]
rows = list(csv.DictReader(io.StringIO(z.read(metaname).decode())))
print(len(names), 'entries;', rows[0])
random.seed(7)
by = {'spoof': [], 'bona-fide': []}
for r in rows: by.setdefault(r['label'], []).append(r)
print({k: len(v) for k, v in by.items()})
pick = random.sample(by['spoof'], 150) + random.sample(by['bona-fide'], 150)
prefix = metaname.rsplit('meta.csv', 1)[0]
meta = []
for r in pick:
    data = z.read(prefix + r['file'])
    open(os.path.join(out, r['file']), 'wb').write(data)
    meta.append({'file': r['file'], 'label': 'fake' if r['label'] == 'spoof' else 'real', 'speaker': r['speaker']})
json.dump(meta, open(os.path.join(out, 'meta.json'), 'w'), indent=1)
print('saved', len(meta), flush=True)
os._exit(0)
