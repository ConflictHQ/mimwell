#!/usr/bin/env python3
"""Fetch meeting audio/recordings from Google Drive into the gitignored working
area knowledge-base/recordings/, so they can be diarized and analyzed.

Scans the configured Drive folders for media (audio/video files, plus
Zoom-style subfolders that hold a small `audio*.m4a` next to the full video),
and downloads each recording's best audio track to:

    knowledge-base/recordings/<id>/audio/<id>.<ext>

<id> is derived from the Drive item name (slugified). Existing audio is left
untouched, so re-runs only pull what is missing. Nothing is ever deleted.

Source folders come from client.config.json under "recordings.driveFolders"
(a list of Drive folder IDs); folder IDs may also be passed as CLI arguments,
which override the config. With neither configured this is a clean no-op, so a
brand-new client with no Drive set up still runs without error.

Auth is the gws CLI (the same approach scripts/import-drive-docs.py uses for
Drive); it must be authenticated as the Drive owner. Run from anywhere:

    python3 scripts/fetch-drive-audio.py [folderId ...]
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(ROOT, "client.config.json")
REC = os.path.join(ROOT, "knowledge-base", "recordings")

AUDIO_EXTS = (".m4a", ".mp3", ".wav", ".aac", ".flac", ".ogg")
VIDEO_EXTS = (".mp4", ".m4v", ".mov", ".mkv", ".webm")
MEDIA_EXTS = AUDIO_EXTS + VIDEO_EXTS
LIST_FIELDS = "nextPageToken,files(id,name,mimeType,size)"


def load_folders(argv: list[str]) -> list[str]:
    """Drive folder IDs to scan: CLI args win, else recordings.driveFolders.

    Returns an empty list when neither is set so the script can no-op cleanly
    instead of crashing for a brand-new client.
    """
    args = [a for a in argv if a.strip()]
    if args:
        return args
    try:
        with open(CONFIG, encoding="utf-8") as fh:
            cfg = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    folders = cfg.get("recordings", {}).get("driveFolders", [])
    return [f for f in folders if isinstance(f, str) and f.strip()]


def gws_env() -> dict:
    """gws environment, mirroring import-drive-docs.py: drop the service-account
    credentials override so the user's authenticated CLI session is used."""
    return {k: v for k, v in os.environ.items()
            if k != "GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE"}


def children(folder_id: str) -> list[dict]:
    """Non-trashed direct children of a Drive folder (id, name, mimeType, size).

    Uses gws drive files list with --page-all so every page is returned.
    """
    params = {
        "q": f"'{folder_id}' in parents and trashed=false",
        "fields": LIST_FIELDS,
        "pageSize": 200,
        "supportsAllDrives": True,
        "includeItemsFromAllDrives": True,
    }
    r = subprocess.run(
        ["gws", "drive", "files", "list", "--params", json.dumps(params),
         "--page-all"],
        capture_output=True, text=True, env=gws_env(),
    )
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip()[:200] or "gws list failed")
    out: list[dict] = []
    for line in r.stdout.splitlines():       # --page-all emits one JSON page per line
        line = line.strip()
        if not line:
            continue
        out += json.loads(line).get("files", [])
    return out


def is_folder(item: dict) -> bool:
    return "folder" in item.get("mimeType", "")


def is_media(item: dict) -> bool:
    name = item.get("name", "").lower()
    mime = item.get("mimeType", "")
    return ("video" in mime or "audio" in mime
            or name.endswith(MEDIA_EXTS))


def slugify(name: str) -> str:
    """Stable, filesystem-safe id from a Drive item name (extension dropped)."""
    base = os.path.splitext(name)[0].lower()
    base = re.sub(r"[^a-z0-9]+", "-", base).strip("-")
    return base or "recording"


def pick_audio(item: dict) -> tuple[str | None, str | None]:
    """(file_id, suffix) of the best audio track for a Drive item.

    For a folder (e.g. a Zoom recording folder), prefer the largest audio file,
    else the largest video. For a loose file, use it directly.
    """
    if is_folder(item):
        kids = children(item["id"])
        audio = [k for k in kids
                 if "audio" in k.get("mimeType", "")
                 or k.get("name", "").lower().endswith(AUDIO_EXTS)]
        if audio:
            a = max(audio, key=lambda k: int(k.get("size") or 0))
            return a["id"], os.path.splitext(a["name"])[1].lower() or ".m4a"
        vids = [k for k in kids
                if "video" in k.get("mimeType", "")
                or k.get("name", "").lower().endswith(VIDEO_EXTS)]
        if vids:
            v = max(vids, key=lambda k: int(k.get("size") or 0))
            return v["id"], os.path.splitext(v["name"])[1].lower() or ".mp4"
        return None, None
    suffix = os.path.splitext(item.get("name", ""))[1].lower()
    if not suffix:
        suffix = ".mp4" if "video" in item.get("mimeType", "") else ".m4a"
    return item["id"], suffix


def download(file_id: str, dest: str) -> None:
    """Download a Drive file's binary content to dest via gws (-o for binary)."""
    params = {"fileId": file_id, "alt": "media", "supportsAllDrives": True}
    r = subprocess.run(
        ["gws", "drive", "files", "download", "--params", json.dumps(params),
         "-o", dest],
        capture_output=True, text=True, env=gws_env(),
    )
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip()[:200] or "gws download failed")


def has_local_audio(rec_id: str) -> bool:
    adir = os.path.join(REC, rec_id, "audio")
    if not os.path.isdir(adir):
        return False
    return any(f.lower().endswith(MEDIA_EXTS) for f in os.listdir(adir))


def main(argv: list[str]) -> None:
    folders = load_folders(argv)
    if not folders:
        print("No Drive folders configured (recordings.driveFolders / args) "
              "— nothing to fetch.")
        return

    catalog: list[dict] = []
    for fid in folders:
        try:
            catalog += children(fid)
        except RuntimeError as e:
            print(f"WARN: folder {fid}: {e}")

    items = [it for it in catalog if is_folder(it) or is_media(it)]
    if not items:
        print("No media found in the configured Drive folders.")
        return

    fetched = skipped = missed = 0
    seen: set[str] = set()
    for item in items:
        rec_id = slugify(item.get("name", ""))
        # de-dupe ids within a run (two items slugging the same)
        suffix_n, base = 1, rec_id
        while rec_id in seen:
            suffix_n += 1
            rec_id = f"{base}-{suffix_n}"
        seen.add(rec_id)

        if has_local_audio(rec_id):
            skipped += 1
            continue
        fid, suffix = pick_audio(item)
        if not fid:
            print(f"  MISS (no audio in '{item.get('name')}')")
            missed += 1
            continue
        adir = os.path.join(REC, rec_id, "audio")
        os.makedirs(adir, exist_ok=True)
        dest = os.path.join(adir, rec_id + suffix)
        print(f"  fetch {rec_id}  <-  {item.get('name')}{suffix}", flush=True)
        try:
            download(fid, dest)
            fetched += 1
        except RuntimeError as e:
            print(f"    ERROR {rec_id}: {e}")
            if os.path.exists(dest) and os.path.getsize(dest) == 0:
                os.remove(dest)
            missed += 1

    print(f"\nFetched {fetched}, skipped {skipped} (already local), "
          f"missed {missed}.")


if __name__ == "__main__":
    main(sys.argv[1:])
