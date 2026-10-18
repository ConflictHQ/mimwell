#!/usr/bin/env python3
"""Build app/sessions.json — the meetings catalog for the Intelligence gallery —
from the PlanOpticon working area (knowledge-base/recordings/, gitignored).

For each analyzed recording: title, date, duration, key points, action-item
count, and a link to the committed redacted analysis (knowledge/docs/sessions/).
Also copies one representative frame per session to app/thumbs/<id>.jpg so the
gallery has thumbnails without committing the full frame sets.

All client-specific inputs are optional and have safe empty-defaults, so this
runs cleanly for a brand-new client that has none of them yet:
  - Session label rules    -> client.config.json: sessions.labelRules /
                              sessions.defaultLabel (absent -> no labels).
  - Explicit per-session    -> knowledge/session-tags.json (absent -> derived
    labels                    from label rules).
  - Drive recording map     -> knowledge/session-recordings.json (absent ->
                              no drive_url).

Run from anywhere:  python3 scripts/gen-sessions.py
"""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REC = os.path.join(ROOT, "knowledge-base", "recordings")
SESS_DOCS = os.path.join(ROOT, "knowledge", "docs", "sessions")
THUMBS = os.path.join(ROOT, "app", "thumbs")
OUT = os.path.join(ROOT, "app", "sessions.json")

DATE_RE = re.compile(r"(20\d{2})[-.](\d{2})[-.](\d{2})")

# Label rules come from client.config.json so the script carries no client
# specifics. Each rule is {"label": str, "keywords": [str, ...]}; a session is
# tagged with the first matching rule's label (matched against folder + title,
# case-insensitive). With no rules and no defaultLabel, sessions get no labels.
CONFIG_PATH = os.path.join(ROOT, "client.config.json")
label_rules = []
default_label = ""
if os.path.isfile(CONFIG_PATH):
    sessions_cfg = json.load(open(CONFIG_PATH, encoding="utf-8")).get("sessions", {}) or {}
    label_rules = sessions_cfg.get("labelRules", []) or []
    default_label = sessions_cfg.get("defaultLabel", "") or ""


def classify(folder: str, title: str) -> list:
    hay = f"{folder} {title}".lower()
    for rule in label_rules:
        keywords = [k.lower() for k in rule.get("keywords", []) if k]
        if any(k in hay for k in keywords):
            return [rule.get("label", "")] if rule.get("label") else []
    return [default_label] if default_label else []


def session_date(folder: str, manifest: dict) -> str:
    m = DATE_RE.search(folder)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    p = (manifest.get("video", {}) or {}).get("processed_at", "")
    return p[:10] if p else ""


TAGS_PATH = os.path.join(ROOT, "knowledge", "session-tags.json")
explicit_tags = {}
if os.path.isfile(TAGS_PATH):
    explicit_tags = json.load(open(TAGS_PATH, encoding="utf-8")).get("tags", {})

REC_MAP_PATH = os.path.join(ROOT, "knowledge", "session-recordings.json")
drive_map = {}
if os.path.isfile(REC_MAP_PATH):
    drive_map = json.load(open(REC_MAP_PATH, encoding="utf-8")).get("recordings", {})

# Index agenda/notes files by their date so a recording can show the matching
# agenda for the same day (one meeting = agenda + recording when both exist).
AGENDA_DIR = os.path.join(ROOT, "knowledge", "docs", "agendas")
agenda_by_date = {}
for ap in glob.glob(os.path.join(AGENDA_DIR, "*.md")):
    d = os.path.basename(ap)[:-3]
    if DATE_RE.match(d):
        agenda_by_date[d] = f"knowledge/docs/agendas/{d}.md"


def item_text(x):
    if isinstance(x, str):
        return x
    if isinstance(x, dict):
        return x.get("point") or x.get("action") or x.get("task") or x.get("item") or x.get("description") or ""
    return ""


sessions = []
os.makedirs(THUMBS, exist_ok=True)

for mpath in sorted(glob.glob(os.path.join(REC, "*", "manifest.json"))):
    folder = os.path.basename(os.path.dirname(mpath))
    if folder.startswith("video"):  # raw unanalyzed captures
        continue
    manifest = json.load(open(mpath, encoding="utf-8"))
    video = manifest.get("video", {}) or {}
    title = video.get("title") or folder.replace("-", " ").title()
    dur = video.get("duration_seconds") or 0

    # Key points + action-item count come from the structured results files.
    kp_path = os.path.join(REC, folder, "results", "key_points.json")
    key_points = []
    if os.path.isfile(kp_path):
        for k in json.load(open(kp_path, encoding="utf-8")):
            pt = k.get("point") if isinstance(k, dict) else (k if isinstance(k, str) else None)
            if pt:
                key_points.append(pt)
    ai_path = os.path.join(REC, folder, "results", "action_items.json")
    raw_ai = json.load(open(ai_path, encoding="utf-8")) if os.path.isfile(ai_path) else []
    action_items = [t for t in (item_text(a) for a in raw_ai) if t]

    # Link to the committed redacted analysis + transcript if ingested.
    doc_rel = f"knowledge/docs/sessions/{folder}.md"
    has_doc = os.path.isfile(os.path.join(ROOT, doc_rel))
    tr_rel = f"knowledge/docs/sessions/transcripts/{folder}.md"
    has_tr = os.path.isfile(os.path.join(ROOT, tr_rel))
    sdate = session_date(folder, manifest)
    drive_id = drive_map.get(folder, "")

    # Copy one representative frame (~40% through) as the thumbnail.
    frames = sorted(glob.glob(os.path.join(REC, folder, "frames", "frame_*.jpg")))
    thumb = ""
    if frames:
        pick = frames[int(len(frames) * 0.4)]
        dst = os.path.join(THUMBS, f"{folder}.jpg")
        shutil.copyfile(pick, dst)
        # Resize down to a gallery thumbnail to keep the repo lean.
        subprocess.run(["sips", "--resampleWidth", "480", dst],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        thumb = f"app/thumbs/{folder}.jpg"

    labels = explicit_tags.get(folder) or classify(folder, title)
    sessions.append({
        "id": folder,
        "title": title,
        "labels": labels,
        "date": sdate,
        "duration_min": round(dur / 60) if dur else None,
        "key_points": key_points[:10],
        "action_items": action_items,
        "action_item_count": len(action_items),
        "frames": (manifest.get("stats", {}) or {}).get("frames_extracted", 0),
        "doc": doc_rel if has_doc else "",
        "transcript": tr_rel if has_tr else "",
        "agenda": agenda_by_date.get(sdate, ""),
        "drive_url": f"https://drive.google.com/file/d/{drive_id}/view" if drive_id else "",
        "thumb": thumb,
    })

sessions.sort(key=lambda s: s["date"], reverse=True)
json.dump({"count": len(sessions), "sessions": sessions},
          open(OUT, "w", encoding="utf-8"), indent=1)
print(f"Wrote {OUT}: {len(sessions)} sessions, "
      f"{sum(1 for s in sessions if s['thumb'])} thumbnails")
