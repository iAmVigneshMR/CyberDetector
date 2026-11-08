"""
CyberDetector local detection server — free, private, runs on your own machine.

Implements the extension's "custom endpoint" contract:
    POST /detect   multipart: file, mediaType (image|video|audio), sourceUrl
                   header:    Authorization: Bearer <token>
    → { score, scores, frames, regions, models, calibrated }
    GET  /health   → { ok, models, version }

Models and calibration live in models.json (chosen by evaluate.py on held-out data).
Only listens on 127.0.0.1; every request must carry the token in ~/.config/cyberdetector/token.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

import numpy as np
import torch
from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile
from PIL import Image
from transformers import pipeline

VERSION = '1.0.0'
HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / 'models.json').read_text())
TOKEN_FILE = Path(os.environ.get('CYBERDETECTOR_TOKEN_FILE', Path.home() / '.config' / 'cyberdetector' / 'token'))
MAX_UPLOAD = 300 * 1024 * 1024
MAX_VIDEO_FRAMES = 60
MAX_AUDIO_SECONDS = 600
FFMPEG = shutil.which('ffmpeg')

Image.MAX_IMAGE_PIXELS = 80_000_000  # refuse decompression bombs
torch.set_num_threads(max(1, (os.cpu_count() or 4) - 1))


# ----------------------------------------------------------------------------
# Token
# ----------------------------------------------------------------------------
def load_token() -> str:
    if env := os.environ.get('CYBERDETECTOR_TOKEN'):
        return env.strip()
    if TOKEN_FILE.exists():
        return TOKEN_FILE.read_text().strip()
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    tok = secrets.token_urlsafe(32)
    TOKEN_FILE.write_text(tok)
    TOKEN_FILE.chmod(0o600)
    return tok


# ----------------------------------------------------------------------------
# Models
# ----------------------------------------------------------------------------
class Detector:
    """Wraps a Hugging Face classifier and maps its raw output to a calibrated probability."""

    def __init__(self, spec: dict, task: str):
        self.id = spec['id']
        self.ai_labels = {l.lower() for l in spec['ai_labels']}
        self.cal = spec.get('calibration')  # {"t_warn": x, "t_danger": y}
        self.pipe = pipeline(task, model=self.id, device='cpu')
        self.lock = threading.Lock()

    def raw(self, inputs, **kw) -> list[float]:
        with self.lock, torch.inference_mode():
            out = self.pipe(inputs, top_k=None, **kw)
        if out and isinstance(out[0], dict):  # single input
            out = [out]
        return [float(sum(p['score'] for p in preds if p['label'].lower() in self.ai_labels)) for preds in out]

    def calibrate(self, s: float) -> float:
        """Piecewise-linear map so t_warn → 0.4 and t_danger → 0.7 (the extension's Warning/Danger lines)."""
        if not self.cal:
            return s
        tw, td = self.cal['t_warn'], self.cal['t_danger']
        if s <= tw:
            return 0.4 * s / tw if tw > 0 else 0.0
        if s <= td:
            return 0.4 + 0.3 * (s - tw) / (td - tw)
        return 0.7 + 0.3 * (s - td) / (1 - td) if td < 1 else 1.0


def load_models():
    print('Loading models (first run downloads them, ~1–2 GB)…', flush=True)
    m = {'image': Detector(CONFIG['image'], 'image-classification')}
    if CONFIG.get('audio'):
        m['audio'] = Detector(CONFIG['audio'], 'audio-classification')
    print('Models ready:', ', '.join(d.id for d in m.values()), flush=True)
    return m


# ----------------------------------------------------------------------------
# Media helpers (ffmpeg is invoked with argument lists, never a shell)
# ----------------------------------------------------------------------------
def ffprobe_duration(path: str) -> float | None:
    probe = shutil.which('ffprobe')
    if not probe:
        return None
    r = subprocess.run([probe, '-v', 'error', '-show_entries', 'format=duration', '-of', 'csv=p=0', path],
                       capture_output=True, text=True, timeout=30)
    try:
        return float(r.stdout.strip())
    except ValueError:
        return None


def decode_audio(path: str, sr: int = 16000) -> np.ndarray:
    if not FFMPEG:
        raise HTTPException(500, 'ffmpeg is required for audio/video analysis')
    r = subprocess.run([FFMPEG, '-v', 'error', '-i', path, '-t', str(MAX_AUDIO_SECONDS), '-vn', '-ac', '1', '-ar', str(sr),
                        '-f', 'f32le', '-'], capture_output=True, timeout=300)
    return np.frombuffer(r.stdout, dtype=np.float32)


def extract_frames(path: str, workdir: str, duration: float | None) -> list[tuple[float, Image.Image]]:
    if not FFMPEG:
        raise HTTPException(500, 'ffmpeg is required for video analysis')
    fps = 1.0 if not duration or duration <= MAX_VIDEO_FRAMES else MAX_VIDEO_FRAMES / duration
    subprocess.run([FFMPEG, '-v', 'error', '-i', path, '-vf', f'fps={fps:.5f}', '-frames:v', str(MAX_VIDEO_FRAMES),
                    os.path.join(workdir, 'f%04d.jpg')], capture_output=True, timeout=600)
    frames = []
    for i, name in enumerate(sorted(n for n in os.listdir(workdir) if n.startswith('f'))):
        with Image.open(os.path.join(workdir, name)) as im:
            frames.append((i / fps, im.convert('RGB')))
    return frames


def aggregate(scores: list[float]) -> float:
    """Whole-file score: robust to a few noisy frames but sensitive to a sustained fake segment."""
    if not scores:
        return 0.0
    a = np.array(scores)
    return float(max(a.mean(), np.quantile(a, 0.9) * 0.9))


# ----------------------------------------------------------------------------
# Analysis
# ----------------------------------------------------------------------------
def analyze_image(models, im: Image.Image) -> dict:
    det = models['image']
    im = im.convert('RGB')
    s = det.calibrate(det.raw([im])[0])
    # 3×3 tile scan → which regions look synthetic (coarse localisation for the heatmap view).
    # Only for images already judged suspicious: crops of real photos are out-of-distribution
    # for the model and would otherwise produce misleading boxes.
    regions = []
    w, h = im.size
    if s >= 0.4 and min(w, h) >= 384:
        tiles, boxes = [], []
        for ty in range(3):
            for tx in range(3):
                box = (tx * w // 3, ty * h // 3, (tx + 1) * w // 3, (ty + 1) * h // 3)
                tiles.append(im.crop(box)); boxes.append(box)
        for box, raw in zip(boxes, det.raw(tiles)):
            ts = det.calibrate(raw)
            if ts >= 0.7:
                regions.append({'x': box[0] / w, 'y': box[1] / h, 'w': (box[2] - box[0]) / w, 'h': (box[3] - box[1]) / h, 'score': round(ts, 3)})
    return {'score': s, 'scores': {'AI-generated image (local model)': s}, 'frames': [], 'regions': regions}


def analyze_audio_array(models, wav: np.ndarray, sr: int = 16000, win: float = 4.0) -> dict:
    det = models.get('audio')
    if det is None:
        raise HTTPException(400, 'No audio model configured')
    if len(wav) < sr // 2:
        raise HTTPException(400, 'Audio too short (needs at least 0.5 s)')
    step = int(win * sr)
    chunks = [wav[i:i + step] for i in range(0, len(wav), step)]
    chunks = [c for c in chunks if len(c) >= sr // 2]
    raws = det.raw([{'raw': c, 'sampling_rate': sr} for c in chunks])
    frames = [{'time': round(i * win, 2), 'end': round(min((i + 1) * win, len(wav) / sr), 2), 'score': round(det.calibrate(r), 4)} for i, r in enumerate(raws)]
    s = aggregate([f['score'] for f in frames])
    return {'score': s, 'scores': {'Synthetic voice (local model)': s}, 'frames': frames, 'regions': []}


def analyze_video(models, path: str) -> dict:
    duration = ffprobe_duration(path)
    with tempfile.TemporaryDirectory() as work:
        frames = extract_frames(path, work, duration)
        if not frames:
            raise HTTPException(400, 'Could not decode any video frames')
        det = models['image']
        raws = []
        for i in range(0, len(frames), 8):
            raws += det.raw([im for _, im in frames[i:i + 8]])
    out_frames = [{'time': round(t, 2), 'score': round(det.calibrate(r), 4)} for (t, _), r in zip(frames, raws)]
    visual = aggregate([f['score'] for f in out_frames])
    scores = {'AI-generated frames (local model)': visual}
    score = visual
    if 'audio' in models:
        wav = decode_audio(path)
        if len(wav) >= 16000:
            a = analyze_audio_array(models, wav)
            scores['Synthetic voice in soundtrack'] = a['score']
            score = max(visual, a['score'])
    return {'score': score, 'scores': scores, 'frames': out_frames, 'regions': []}


# ----------------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------------
def create_app(models, token: str) -> FastAPI:
    app = FastAPI(title='CyberDetector local detector', version=VERSION, docs_url=None, redoc_url=None)

    def auth(authorization: str | None):
        if not authorization or not secrets.compare_digest(authorization, f'Bearer {token}'):
            raise HTTPException(401, 'Missing or wrong token — copy it from ~/.config/cyberdetector/token into the extension settings')

    @app.get('/health')
    def health(authorization: str | None = Header(default=None)):
        auth(authorization)
        return {'ok': True, 'version': VERSION, 'models': {k: v.id for k, v in models.items()}, 'ffmpeg': bool(FFMPEG)}

    @app.post('/detect')
    async def detect(file: UploadFile = File(...), mediaType: str = Form('image'), sourceUrl: str = Form(''),
                     authorization: str | None = Header(default=None)):
        auth(authorization)
        data = await file.read(MAX_UPLOAD + 1)
        if len(data) > MAX_UPLOAD:
            raise HTTPException(413, 'File too large')
        if mediaType == 'image':
            try:
                with Image.open(io.BytesIO(data)) as im:
                    result = analyze_image(models, im)
            except (OSError, Image.DecompressionBombError) as e:
                raise HTTPException(400, f'Unreadable image: {e}')
        elif mediaType in ('video', 'audio'):
            with tempfile.NamedTemporaryFile(suffix='.' + (file.filename or 'x').rsplit('.', 1)[-1][:5]) as tmp:
                tmp.write(data); tmp.flush()
                result = analyze_video(models, tmp.name) if mediaType == 'video' else analyze_audio_array(models, decode_audio(tmp.name))
        else:
            raise HTTPException(400, 'mediaType must be image, video or audio')
        result['score'] = round(float(result['score']), 4)
        result['scores'] = {k: round(float(v), 4) for k, v in result['scores'].items()}
        result['models'] = {k: v.id for k, v in models.items()}
        result['calibrated'] = True
        return result

    return app


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--port', type=int, default=8765)
    ap.add_argument('--show-token', action='store_true', help='print the access token and exit')
    args = ap.parse_args()
    token = load_token()
    if args.show_token:
        print(token)
        return
    import uvicorn
    models = load_models()
    print(f'\nCyberDetector detector listening on http://127.0.0.1:{args.port}/detect')
    print(f'Access token: {token}\n(paste both into the extension: Settings → Deepfake detection → Local detector)\n', flush=True)
    # 127.0.0.1 only — never expose this server to the network.
    uvicorn.run(create_app(models, token), host='127.0.0.1', port=args.port, log_level='warning')


if __name__ == '__main__':
    main()
