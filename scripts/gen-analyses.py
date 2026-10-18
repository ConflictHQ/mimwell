#!/usr/bin/env python3
"""Copy per-session analysis summaries into the indexed knowledge tree.

For each analyzed recording in the gitignored working area
(knowledge-base/recordings/<id>/results/analysis.md), write a PII-redacted copy
with frontmatter to knowledge/docs/sessions/<id>.md so the chat agent can search
and the Library/Intelligence pages can link to it.

Client-specific values hold no defaults baked into this script:

  - Email domains to KEEP unredacted come from client.config.json under
    "knowledge.keepEmailDomains" (a list). Absent/empty -> every email is
    redacted.
  - Optional per-session labels come from knowledge/session-tags.json
    ({"tags": {"<id>": ["label", ...]}}). Absent -> no labels.

Run from anywhere:  python3 scripts/gen-analyses.py
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
OUT = os.path.join(ROOT, "knowledge", "docs", "sessions")
DIAG_OUT = os.path.join(ROOT, "app", "diagrams")
CONFIG = os.path.join(ROOT, "client.config.json")
TAGS_PATH = os.path.join(ROOT, "knowledge", "session-tags.json")

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CRED = re.compile(r"(password|passwd|secret|api[_ ]?key|token)\s*[:=]\s*\S+", re.I)


def load_keep_domains() -> tuple[str, ...]:
    """Email domains left unredacted, from client.config.json (default none)."""
    if not os.path.isfile(CONFIG):
        return ()
    with open(CONFIG, encoding="utf-8") as f:
        knowledge = json.load(f).get("knowledge", {})
    return tuple(d.lower() for d in knowledge.get("keepEmailDomains", []))


KEEP_DOMAINS = load_keep_domains()


def redact(text: str) -> tuple[str, int]:
    n = [0]

    def email_sub(m):
        if KEEP_DOMAINS and m.group(0).lower().endswith(KEEP_DOMAINS):
            return m.group(0)
        n[0] += 1
        return "[email redacted]"

    def cred_sub(m):
        n[0] += 1
        return m.group(1) + ": [redacted]"

    return CRED.sub(cred_sub, EMAIL.sub(email_sub, text)), n[0]


tags = {}
if os.path.isfile(TAGS_PATH):
    tags = json.load(open(TAGS_PATH, encoding="utf-8")).get("tags", {})

os.makedirs(OUT, exist_ok=True)
written = total_redacted = 0
for apath in sorted(glob.glob(os.path.join(REC, "*", "results", "analysis.md"))):
    folder = os.path.basename(os.path.dirname(os.path.dirname(apath)))
    if folder.startswith("video"):  # unnamed/duplicate raw captures
        continue
    body, n = redact(open(apath, encoding="utf-8", errors="replace").read())
    total_redacted += n

    # Diagram screenshots live in the gitignored working area and are referenced
    # by relative path (diagrams/diagram_N.jpg) that won't resolve when served.
    # Copy them (resized) into app/diagrams/<folder>/ and rewrite the links to
    # absolute served paths. Drop links whose source image is missing.
    src_diag = os.path.join(REC, folder, "diagrams")

    def fix_img(m, _folder=folder, _src=src_diag):
        alt, path = m.group(1), m.group(2)
        fn = os.path.basename(path)
        srcfile = os.path.join(_src, fn)
        if "diagrams/" in path and os.path.isfile(srcfile):
            dstdir = os.path.join(DIAG_OUT, _folder)
            os.makedirs(dstdir, exist_ok=True)
            dst = os.path.join(dstdir, fn)
            shutil.copyfile(srcfile, dst)
            subprocess.run(["sips", "--resampleWidth", "900", dst],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            return f"![{alt}](/app/diagrams/{_folder}/{fn})"
        return f"_{alt or 'diagram'} (not captured)_" if "diagrams/" in path else m.group(0)

    body = re.sub(r"!\[([^\]]*)\]\(([^)]+)\)", fix_img, body)
    labels = ", ".join(tags.get(folder, []))
    fm = (
        "---\n"
        f'title: "Session: {folder}"\n'
        f'description: "PlanOpticon analysis of the {folder} meeting'
        f'{" (" + labels + ")" if labels else ""}."\n'
        "---\n\n"
    )
    open(os.path.join(OUT, f"{folder}.md"), "w", encoding="utf-8").write(fm + body)
    written += 1

print(f"Wrote {written} session analyses to {OUT} ({total_redacted} redactions)")
