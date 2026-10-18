#!/usr/bin/env python3
"""Add speaker labels (diarization) to the per-recording meeting transcripts.

Where this fits in the recording pipeline
-----------------------------------------
The portal's meetings come from a gitignored working area produced by the
transcription/analysis tool:

    knowledge-base/recordings/<id>/
        audio/<file>.{wav,m4a,mp4}     raw audio for the recording
        transcript/transcript.txt      flat transcript ({text, segments:[...]})
        results/, frames/, manifest.json

This script sits *between* raw transcription and ingestion. For each recording
that has audio, it re-transcribes with speaker diarization enabled and writes a
non-destructive, labeled transcript next to the existing one:

    transcript/transcript.diarized.json   {text, segments:[{start,end,text,speaker}], ...}
    transcript/transcript.labeled.txt     human-readable "Speaker N: ..." turns

`scripts/gen-transcripts.py` then ingests transcripts into
knowledge/docs/sessions/transcripts/<id>.md. It prefers the diarized JSON when
present (segments carry a `speaker`), so re-running the ingest after diarizing
surfaces speaker turns to the chat agent and the Library — no other change
needed. Pipeline order:

    make diarize        # this script (optional, needs a provider + deps)
    make transcripts    # gen-transcripts.py — picks up diarized output if present

Config-driven, with safe empty defaults
----------------------------------------
The diarization backend is read from client.config.json -> "recordings":

    "recordings": {
      "diarization": {
        "module": "video_processor.providers.deepgram_provider",
        "class":  "DeepgramProvider",
        "model":  "",                      // optional, passed if the provider takes it
        "apiKeyEnv": "DEEPGRAM_API_KEY"    // documented; not validated here
      }
    }

Everything is optional. Provider module/class may also be overridden from the
environment (DIARIZE_PROVIDER_MODULE / DIARIZE_PROVIDER_CLASS / DIARIZE_MODEL).
A brand-new client with no recordings, no config, and no diarization library
installed gets a clean no-op (exit 0) — nothing to do, nothing breaks.

Usage:
    python3 scripts/diarize-transcripts.py [--only <id>] [--limit N] [--force]
"""
from __future__ import annotations

import argparse
import glob
import importlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REC = os.path.join(ROOT, "knowledge-base", "recordings")
CONFIG = os.path.join(ROOT, "client.config.json")

# Audio extensions, in preference order (best transcription source first).
AUDIO_EXTS = ("wav", "m4a", "mp4")
EXT_RANK = {f".{e}": i for i, e in enumerate(AUDIO_EXTS)}

# Default provider seam. Mirrors the proven setup but is fully overridable from
# config/env, so the template carries no hard dependency on any one backend.
DEFAULT_MODULE = "video_processor.providers.deepgram_provider"
DEFAULT_CLASS = "DeepgramProvider"


def diarize_config() -> dict:
    """Read the "recordings.diarization" block from client.config.json (all
    keys optional), then let environment variables override module/class/model."""
    cfg: dict = {}
    if os.path.isfile(CONFIG):
        with open(CONFIG, encoding="utf-8") as f:
            recordings = json.load(f).get("recordings", {}) or {}
        cfg = recordings.get("diarization", {}) or {}
    return {
        "module": os.environ.get("DIARIZE_PROVIDER_MODULE") or cfg.get("module") or DEFAULT_MODULE,
        "class": os.environ.get("DIARIZE_PROVIDER_CLASS") or cfg.get("class") or DEFAULT_CLASS,
        "model": os.environ.get("DIARIZE_MODEL") or cfg.get("model") or "",
    }


def load_provider(module_name: str, class_name: str):
    """Import and instantiate the configured diarization provider, or return
    None if the backend isn't installed (clean no-op for a fresh client)."""
    try:
        module = importlib.import_module(module_name)
    except ImportError:
        return None
    cls = getattr(module, class_name, None)
    if cls is None:
        return None
    try:
        return cls()
    except Exception as e:  # provider may require credentials/config to init
        print(f"provider {class_name} could not initialize: {e}", flush=True)
        return None


def pick_audio() -> dict:
    """One audio file per recording dir, preferring wav > m4a > mp4."""
    found: list[str] = []
    for ext in AUDIO_EXTS:
        found += glob.glob(os.path.join(REC, "*", "audio", f"*.{ext}"))
    by_dir: dict[str, str] = {}
    for a in sorted(found):
        rec_dir = os.path.dirname(os.path.dirname(a))
        cur = by_dir.get(rec_dir)
        if cur is None or EXT_RANK.get(os.path.splitext(a)[1], 99) < EXT_RANK.get(
            os.path.splitext(cur)[1], 99
        ):
            by_dir[rec_dir] = a
    return by_dir


def transcribe(provider, audio_path: str, model: str) -> dict:
    """Call the provider's transcribe_audio with diarization on. Pass `model`
    only when the provider accepts it, so simpler providers still work."""
    try:
        return provider.transcribe_audio(audio_path, diarize=True, model=model or None)
    except TypeError:
        return provider.transcribe_audio(audio_path, diarize=True)


def fmt_ts(sec) -> str:
    sec = int(float(sec or 0))
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def labeled_text(segments: list) -> str:
    """Render diarized segments as readable speaker turns, merging consecutive
    segments from the same speaker into one block."""
    lines: list[str] = []
    cur_speaker = None
    cur_start = None
    cur_text: list[str] = []

    def flush():
        if cur_text:
            who = cur_speaker or "Speaker"
            lines.append(f"[{fmt_ts(cur_start)}] {who}: {' '.join(cur_text).strip()}")

    for seg in segments:
        text = str(seg.get("text", "")).strip()
        if not text:
            continue
        speaker = seg.get("speaker") or None
        if speaker != cur_speaker:
            flush()
            cur_speaker, cur_start, cur_text = speaker, seg.get("start", 0), []
        cur_text.append(text)
    flush()
    return "\n\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Diarize per-recording transcripts.")
    ap.add_argument("--only", help="process a single recording id")
    ap.add_argument("--limit", type=int, default=0, help="process at most N recordings")
    ap.add_argument("--force", action="store_true", help="re-do already-diarized recordings")
    args = ap.parse_args()

    if not os.path.isdir(REC):
        print(f"no recordings working area at {REC} — nothing to diarize.", flush=True)
        return 0

    by_dir = pick_audio()
    if not by_dir:
        print(f"no audio files under {REC}/*/audio — nothing to diarize.", flush=True)
        return 0

    cfg = diarize_config()
    provider = load_provider(cfg["module"], cfg["class"])
    if provider is None:
        print(
            f"diarization backend '{cfg['module']}.{cfg['class']}' is unavailable "
            "(library not installed or failed to init) — skipping diarization.",
            flush=True,
        )
        return 0

    done = total = errors = 0
    for rec_dir, audio_path in sorted(by_dir.items()):
        rid = os.path.basename(rec_dir)
        if rid.startswith("video"):  # raw unanalyzed captures
            continue
        if args.only and rid != args.only:
            continue
        if args.limit and done >= args.limit:
            break

        out_json = os.path.join(rec_dir, "transcript", "transcript.diarized.json")
        if os.path.exists(out_json) and not args.force:
            print(f"skip (exists): {rid}", flush=True)
            continue

        total += 1
        print(f"[{total}] diarizing {rid} ...", flush=True)
        try:
            result = transcribe(provider, audio_path, cfg["model"])
            segments = result.get("segments") or []
            os.makedirs(os.path.dirname(out_json), exist_ok=True)
            with open(out_json, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "text": result.get("text", ""),
                        "segments": segments,
                        "provider": result.get("provider", ""),
                        "model": result.get("model", ""),
                        "duration": result.get("duration", 0),
                    },
                    f,
                    indent=2,
                )
            out_txt = os.path.join(rec_dir, "transcript", "transcript.labeled.txt")
            with open(out_txt, "w", encoding="utf-8") as f:
                f.write(labeled_text(segments) + "\n")

            speakers = sorted({s.get("speaker") for s in segments if s.get("speaker")})
            print(
                f"    -> {len(segments)} turns, {len(speakers)} speakers"
                + (f" ({', '.join(speakers)})" if speakers else ""),
                flush=True,
            )
            done += 1
        except Exception as e:  # one bad file shouldn't stop the batch
            errors += 1
            print(f"    ERROR {rid}: {e}", flush=True)

    print(f"\nDone: {done} diarized, {errors} errors.", flush=True)
    return 1 if errors and not done else 0


if __name__ == "__main__":
    sys.exit(main())
