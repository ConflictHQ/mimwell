#!/usr/bin/env python3
"""Ingest meeting transcripts into the indexed knowledge tree so the chat agent
can search and quote them.

Copies each analyzed recording's transcript (knowledge-base/recordings/<id>/
transcript/, gitignored working area) to knowledge/docs/sessions/transcripts/
<id>.md with frontmatter, redacting personal emails and credential-shaped
strings. These land under knowledge/docs (a recursive knowledge source) so
gen-knowledge-pack indexes them automatically.

When scripts/diarize-transcripts.py has run, a recording also has
transcript/transcript.diarized.json (segments labeled with a `speaker`). This
script prefers that file and renders speaker turns; otherwise it falls back to
the flat transcript/transcript.txt.

Client-specific values are read from config / sibling data files with safe
empty-defaults, so a brand-new client with none of them set still runs cleanly:
  - email domains to keep unredacted -> client.config.json
    "knowledge.keepEmailDomains" (default: none -> all emails redacted)
  - per-session labels -> knowledge/session-tags.json (optional)

Run from anywhere:  python3 scripts/gen-transcripts.py
"""
from __future__ import annotations

import glob
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REC = os.path.join(ROOT, "knowledge-base", "recordings")
OUT = os.path.join(ROOT, "knowledge", "docs", "sessions", "transcripts")
CONFIG = os.path.join(ROOT, "client.config.json")
TAGS_PATH = os.path.join(ROOT, "knowledge", "session-tags.json")

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CRED = re.compile(r"(password|passwd|secret|api[_ ]?key|token)\s*[:=]\s*\S+", re.I)


def keep_domains() -> tuple[str, ...]:
    """Email domains left unredacted, from client.config.json
    "knowledge.keepEmailDomains". Absent/empty -> none (redact every email)."""
    if not os.path.isfile(CONFIG):
        return ()
    with open(CONFIG, encoding="utf-8") as f:
        knowledge = json.load(f).get("knowledge", {})
    return tuple(d.lower() for d in knowledge.get("keepEmailDomains", []))


KEEP_DOMAINS = keep_domains()


PARA_CHARS = 450  # soft cap before breaking a paragraph at the next sentence end
SEG_RE = re.compile(
    r'"start":\s*([0-9.]+)\s*,\s*"end":\s*[0-9.]+\s*,\s*"text":\s*"((?:[^"\\]|\\.)*)"', re.S
)
TEXT_RE = re.compile(r'"text"\s*:\s*"((?:[^"\\]|\\.)*)"', re.S)


def fmt_ts(sec: float) -> str:
    sec = int(sec or 0)
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def _unescape(s: str) -> str:
    try:
        return json.loads('"' + s + '"')
    except (json.JSONDecodeError, ValueError):
        return s


def paragraph_text(text: str) -> str:
    """Group a run-on transcript string into readable ~PARA_CHARS paragraphs,
    breaking only at sentence boundaries."""
    text = re.sub(r"\s+", " ", text).strip()
    paras: list[str] = []
    cur = ""
    for sentence in re.split(r"(?<=[.?!])\s+", text):
        cur = (cur + " " + sentence).strip()
        if len(cur) >= PARA_CHARS:
            paras.append(cur)
            cur = ""
    if cur:
        paras.append(cur)
    return "\n\n".join(paras)


def stamped_paragraphs(segments: list[tuple[float, str]]) -> str:
    """Group timestamped (start, text) segments into paragraphs, each prefixed
    with the start time of its first segment."""
    paras: list[tuple[float, str]] = []
    cur: list[str] = []
    cur_start = None
    for start, t in segments:
        if cur_start is None:
            cur_start = start
        cur.append(t)
        joined = " ".join(cur)
        if len(joined) >= PARA_CHARS and joined.rstrip()[-1:] in ".?!":
            paras.append((cur_start, joined))
            cur, cur_start = [], None
    if cur:
        paras.append((cur_start or 0, " ".join(cur)))
    return "\n\n".join(f"**[{fmt_ts(st)}]** {txt}" for st, txt in paras)


def diarized_turns(raw: str) -> str:
    """Render transcript.diarized.json ({segments:[{start,text,speaker}]}) as
    timestamped speaker turns, merging consecutive segments from one speaker.
    Returns "" if the file isn't a diarized dump with speaker labels so callers
    can fall back to the flat transcript."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return ""
    if not isinstance(data, dict):
        return ""
    segments = data.get("segments") or []
    if not any(s.get("speaker") for s in segments if isinstance(s, dict)):
        return ""

    turns: list[tuple[float, str, str]] = []
    speaker = start = None
    buf: list[str] = []
    for s in segments:
        if not isinstance(s, dict):
            continue
        t = str(s.get("text", "")).strip()
        if not t:
            continue
        who = s.get("speaker") or "Speaker"
        if who != speaker:
            if buf:
                turns.append((start or 0, speaker or "Speaker", " ".join(buf)))
            speaker, start, buf = who, float(s.get("start", 0) or 0), []
        buf.append(t)
    if buf:
        turns.append((start or 0, speaker or "Speaker", " ".join(buf)))
    return "\n\n".join(f"**[{fmt_ts(st)}] {who}:** {txt}" for st, who, txt in turns)


def format_transcript(raw: str) -> str:
    """Turn the raw Whisper JSON ({text, segments:[{start,end,text}]}) into a
    readable transcript. Many of these dumps are truncated mid-`segments`, so we
    parse tolerantly: use timestamped segments only when they cover ~all of the
    (always-complete) flat `text`; otherwise fall back to sentence-grouped
    paragraphs of that text. Returns raw unchanged if it isn't a transcript dump."""
    text = None
    segments: list[tuple[float, str]] = []
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            return raw
        text = data.get("text")
        segments = [
            (float(s.get("start", 0) or 0), str(s.get("text", "")).strip())
            for s in (data.get("segments") or [])
            if str(s.get("text", "")).strip()
        ]
    except (json.JSONDecodeError, ValueError):
        # Truncated/invalid JSON — salvage the complete `text` and any whole segments.
        m = TEXT_RE.search(raw)
        if not m:
            return raw
        text = _unescape(m.group(1))
        segments = [(float(st), _unescape(tx).strip()) for st, tx in SEG_RE.findall(raw)]
        segments = [(st, t) for st, t in segments if t]

    if not text and not segments:
        return raw

    seg_chars = sum(len(t) for _, t in segments)
    if segments and (not text or seg_chars >= 0.9 * len(text)):
        return stamped_paragraphs(segments)
    return paragraph_text(text or "")


def redact(text: str) -> tuple[str, int]:
    hits = [0]

    def email_sub(m):
        e = m.group(0)
        if KEEP_DOMAINS and e.lower().endswith(KEEP_DOMAINS):
            return e
        hits[0] += 1
        return "[email redacted]"

    def cred_sub(m):
        hits[0] += 1
        return m.group(1) + ": [redacted]"

    text = EMAIL.sub(email_sub, text)
    text = CRED.sub(cred_sub, text)
    return text, hits[0]


tags = {}
if os.path.isfile(TAGS_PATH):
    tags = json.load(open(TAGS_PATH, encoding="utf-8")).get("tags", {})

os.makedirs(OUT, exist_ok=True)
written = total_redacted = 0
for tdir in sorted(glob.glob(os.path.join(REC, "*", "transcript"))):
    folder = os.path.basename(os.path.dirname(tdir))
    if folder.startswith("video"):
        continue
    # Prefer the diarized transcript (speaker turns); fall back to the flat one.
    diarized = os.path.join(tdir, "transcript.diarized.json")
    flat = os.path.join(tdir, "transcript.txt")
    body = ""
    if os.path.isfile(diarized):
        raw = open(diarized, encoding="utf-8", errors="replace").read().strip()
        body = diarized_turns(raw) if raw else ""
    if not body:
        if not os.path.isfile(flat):
            continue
        raw = open(flat, encoding="utf-8", errors="replace").read().strip()
        if not raw:
            continue
        body = format_transcript(raw)
    body, n = redact(body)
    total_redacted += n
    labels = ", ".join(tags.get(folder, []))
    fm = (
        "---\n"
        f'title: "Transcript: {folder}"\n'
        f'description: "Full verbatim transcript of the {folder} meeting recording'
        f'{" (" + labels + ")" if labels else ""}. Searchable source for exact quotes and details."\n'
        "---\n\n"
        f"# Transcript — {folder}\n\n"
    )
    open(os.path.join(OUT, f"{folder}.md"), "w", encoding="utf-8").write(fm + body + "\n")
    written += 1

print(f"Wrote {written} transcripts to {OUT} ({total_redacted} redactions)")
