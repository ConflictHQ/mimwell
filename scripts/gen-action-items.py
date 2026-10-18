#!/usr/bin/env python3
"""Aggregate per-meeting action items into app/action-items.json — the data for
the Action Items tracker page.

Reads each recording's results/action_items.json (gitignored working area),
attaches the meeting's id / title / date / labels, and emits one flat,
newest-first list. Also writes a committed knowledge/docs/action-items.md so the
chat agent can search them.

Client-specific values are never hardcoded:
  - The engagement name in the doc description is read from client.config.json
    ("client.name", falling back to "client.engagement"); absent → generic text.
  - Per-session labels come from knowledge/session-tags.json (optional;
    absent → no labels).

The PlanOpticon working area stays at knowledge-base/ (gitignored).

Run from anywhere:  python3 scripts/gen-action-items.py
"""
from __future__ import annotations

import glob
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REC = os.path.join(ROOT, "knowledge-base", "recordings")
CONFIG = os.path.join(ROOT, "client.config.json")
OUT_JSON = os.path.join(ROOT, "app", "action-items.json")
OUT_MD = os.path.join(ROOT, "knowledge", "docs", "action-items.md")
DATE_RE = re.compile(r"(20\d{2})[-.](\d{2})[-.](\d{2})")

# Engagement name for the doc description — read from config, never hardcoded.
# Through the owner seam (#206): brain.name, else the client.name alias.
client_name = ""
if os.path.isfile(CONFIG):
    raw = json.load(open(CONFIG, encoding="utf-8"))
    brain, client = raw.get("brain") or {}, raw.get("client") or {}
    client_name = brain.get("name") or client.get("name") or brain.get("purpose") or client.get("engagement") or ""

# Per-session labels (optional sibling data file). Absent → no labels.
tags = {}
tp = os.path.join(ROOT, "knowledge", "session-tags.json")
if os.path.isfile(tp):
    tags = json.load(open(tp, encoding="utf-8")).get("tags", {})


def item_fields(x):
    if isinstance(x, str):
        return {"text": x, "owner": "", "due": ""}
    if isinstance(x, dict):
        return {
            "text": x.get("action") or x.get("task") or x.get("item") or x.get("point") or x.get("description") or "",
            "owner": x.get("owner") or x.get("assignee") or x.get("who") or "",
            "due": x.get("due") or x.get("deadline") or x.get("when") or "",
        }
    return {"text": "", "owner": "", "due": ""}


def sdate(folder, manifest):
    m = DATE_RE.search(folder)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    return (manifest.get("video", {}) or {}).get("processed_at", "")[:10]


items = []
for ai_path in sorted(glob.glob(os.path.join(REC, "*", "results", "action_items.json"))):
    folder = os.path.basename(os.path.dirname(os.path.dirname(ai_path)))
    if folder.startswith("video"):
        continue
    mf = os.path.join(REC, folder, "manifest.json")
    manifest = json.load(open(mf, encoding="utf-8")) if os.path.isfile(mf) else {}
    title = (manifest.get("video", {}) or {}).get("title", folder)
    date = sdate(folder, manifest)
    labels = tags.get(folder, [])
    for a in json.load(open(ai_path, encoding="utf-8")):
        f = item_fields(a)
        if f["text"]:
            items.append({**f, "session": folder, "session_title": title, "date": date, "labels": labels})

items.sort(key=lambda x: x["date"], reverse=True)
json.dump({"count": len(items), "items": items}, open(OUT_JSON, "w", encoding="utf-8"), indent=1)

scope = f"{client_name} meeting recordings" if client_name else "meeting recordings"
lines = ['---', 'title: "Action Items"',
         f'description: "All action items extracted from {scope}, by meeting and date."',
         '---', '', '# Action Items', '']
cur = None
for it in items:
    if it["date"] != cur:
        cur = it["date"]
        lines.append(f"\n## {it['date']} — {it['session_title']}\n")
    suffix = f" _(owner: {it['owner']})_" if it["owner"] else ""
    lines.append(f"- {it['text']}{suffix}")
open(OUT_MD, "w", encoding="utf-8").write("\n".join(lines) + "\n")

print(f"Wrote {OUT_JSON} and {OUT_MD}: {len(items)} action items across "
      f"{len({i['session'] for i in items})} meetings")
