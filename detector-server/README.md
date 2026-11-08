# CyberDetector local detector

A free, private AI-media detector that runs on your own computer. The extension sends images, video and audio to `http://127.0.0.1:8765`, so nothing leaves your machine.

## Setup (once)
```bash
cd detector-server
./setup.sh        # creates .venv, installs CPU PyTorch, downloads models (~2 GB)
```
Requires Python 3.10+. Install **ffmpeg** for video and audio (`sudo apt install ffmpeg`). No GPU is needed.

## Run
```bash
./run.sh
```
The server prints an **access token**. In the extension, open **Settings → Deepfake & AI-media detection**, set *Detection provider* to **Local detector**, paste the token and click **Test connection**.
- The token is stored in `~/.config/cyberdetector/token`. Run `./run.sh --show-token` to print it again.
- The server only listens on `127.0.0.1` and rejects requests without the token, so websites you visit cannot use it.

## What it does
| Media | How |
|---|---|
| Image | Scores the whole image. If it is suspicious, also scores a 3×3 grid of tiles and returns the suspicious regions (boxes in the report) |
| Video | Scores 1 frame per second (up to 60 frames) for the timeline, and checks the soundtrack for a synthetic voice |
| Audio | Scores 4-second windows (up to 10 minutes) for the timeline |

Speed on a 16-core CPU: about 1 s per image (about 6 s when the tile scan runs), about 10 s for a 12-second video, and under 1 s per 4 s of audio.

## Measured accuracy (2026-11-08)
Model selection and calibration came from data the models were not tested on before. Scripts and raw results are in `eval/`.

**Images:** 10 open-source detectors were compared. `haywoodsloan/ai-image-detector-deploy` was best.

| Test set | Real photos | AI images | AUC | Caught at "Danger" | False "Danger" on real photos |
|---|---|---|---|---|---|
| OpenFake test split: 22 generators (GPT-Image 1.5/2, Midjourney 7, FLUX.2, Sora 2, Veo 3, Nano Banana Pro, Seedream 5…) | 300 (ImageNet, DOCCI) | 300 | 0.97 | **85%** | 1.3% |
| Defactify test split: SD 2.1, SDXL, SD 3, DALL·E 3, Midjourney 6 | 150 (COCO) | 150 | 0.91 | **65%** | 6.7% |

- Weak spots: FLUX.2-klein (36% caught) and Z-Image (68%).
- The runner-up models caught 41–67%. The most-downloaded detectors caught only 22–30%.
- Combining models did not help.

**Audio:** 4 detectors were compared. `Gustking/wav2vec2-large-xlsr-deepfake-audio-classification` was best.

| Test set | AUC | Caught at "Danger" (5% false alarms) |
|---|---|---|
| In-the-Wild: real deepfakes of 58 public figures, 300 clips | 0.94 | 71% |
| ASVspoof 2019 LA, 300 clips | 0.996 | 97% |
| Commercial TTS (ElevenLabs, Polly, Kokoro, Hume, Speechify), 60 fake clips | n/a | 75% (100% at "Warning") |

Another model (`mo-thecreator`) looked better on the first two sets, but caught **0%** of the unseen commercial-TTS voices. It was rejected as likely overfit.

## Honest limitations
- These are open-source research models. **Expect misses on brand-new generators, and some false alarms**, especially on heavily compressed or edited real photos.
- The training data of the chosen image model is undocumented, so it may have seen images similar to the OpenFake test set. The Defactify result (65%) is the more conservative figure.
- Face-swap deepfakes in video are only detected if the frames look AI-generated overall. No dedicated face-swap model is included.
- A "real" result is not proof of authenticity. Combine it with the metadata/C2PA checks and common sense.

## Changing models
Edit `models.json` (`id`, `ai_labels`, and `calibration` thresholds), then re-run `./setup.sh`. To recalibrate on your own data, put labelled files in a folder with a `meta.json` (`[{"file": "...", "label": "real|fake"}]`) and run `eval/eval_images.py` or `eval/eval_audio.py`. Set `t_danger` to the reported `thr@fpr5` and `t_warn` to a looser threshold.
