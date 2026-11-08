#!/usr/bin/env bash
# One-time setup: Python virtualenv + CPU PyTorch + model download.
set -euo pipefail
cd "$(dirname "$0")"
command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }
command -v ffmpeg >/dev/null || echo "⚠ ffmpeg not found — images will work, video/audio need ffmpeg (sudo apt install ffmpeg)"
[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements.txt
echo "Downloading models (one time, ~1–2 GB)…"
.venv/bin/python -c "
import json; from transformers import pipeline
c = json.load(open('models.json'))
pipeline('image-classification', model=c['image']['id'])
if c.get('audio'): pipeline('audio-classification', model=c['audio']['id'])
print('Models cached.')"
echo "✓ Setup complete. Start the detector with ./run.sh"
