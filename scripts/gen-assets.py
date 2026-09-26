#!/usr/bin/env python3
"""Walk the knowledge base for NON-markdown files and emit app/assets.json — the
media / assets index rendered by /assets/ (issue #45).

This is the non-markdown counterpart of the knowledge-pack: markdown already has
the flat pack (#39) and the categorized docs-manifest (#46); BINARIES (video,
images, pdf, docx, xlsx, csv, audio, …) had no home. assets.json is the single
index of every non-markdown upload — completeness is the point: anything added
shows up automatically, nothing is orphaned. The #6 coverage gate asserts every
non-md file appears here, exactly once.

Two surfaces, one index entry
-----------------------------
Session media (the `frames` filmstrip and `video_url` on each session in
app/sessions.json) is indexed HERE exactly once and tagged with its `session`
id, so the assets page and the session page both LINK to the same entry — no
duplication. Only filesystem walking emits filesystem entries; session-only URLs
(off-repo video) become source="session" entries.

Config (which dirs to walk, which filenames to skip) is read from
client.config.json under the "knowledge" key — this script hardcodes nothing
about a particular client. An empty knowledge base produces a valid empty index.

Classification (`kind`) drives which viewer the page opens:
  video/image -> media viewer (#41) · pdf/doc/sheet -> document viewer (#44) ·
  audio -> inline player · other -> download.

Run from anywhere:  python3 scripts/gen-assets.py
"""
from __future__ import annotations

import datetime as dt
import json
import mimetypes
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "app" / "assets.json"
CONFIG = ROOT / "client.config.json"
SESSIONS = ROOT / "app" / "sessions.json"

# Extension -> kind. Everything not listed (and not markdown) is "other".
KIND_BY_EXT: dict[str, str] = {
    # video
    "mp4": "video", "webm": "video", "mov": "video", "m4v": "video", "mkv": "video", "avi": "video",
    # image
    "png": "image", "jpg": "image", "jpeg": "image", "gif": "image", "webp": "image",
    "svg": "image", "bmp": "image", "avif": "image", "heic": "image",
    # pdf
    "pdf": "pdf",
    # documents
    "doc": "doc", "docx": "doc", "rtf": "doc", "odt": "doc", "pptx": "doc", "ppt": "doc", "key": "doc",
    # spreadsheets
    "xls": "sheet", "xlsx": "sheet", "csv": "sheet", "tsv": "sheet", "ods": "sheet",
    # audio
    "mp3": "audio", "wav": "audio", "m4a": "audio", "aac": "audio", "ogg": "audio", "flac": "audio",
}

# Non-markdown extensions that are config/data plumbing, not "uploads" — never
# surfaced to the assets page (and so never demanded by the coverage gate).
SKIP_EXTS = {
    "json", "py", "pyc", "lock", "toml", "cfg", "ini", "yml", "yaml",
    "gitkeep", "gitignore", "gitattributes", "db", "sqlite", "sqlite3",
    "html", "css", "js", "mjs", "map", "txt", "sh", "mk", "log",
}


def _knowledge() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8")).get("knowledge", {})


def _sources() -> list[tuple[str, bool]]:
    return [(s["path"], s.get("recursive", False)) for s in _knowledge().get("sources", [])]


def _skip_names() -> set[str]:
    return {n.lower() for n in _knowledge().get("skipNames", [])}


def ext_of(name: str) -> str:
    _, dot, ext = name.rpartition(".")
    return ext.lower() if dot else ""


def kind_of(ext: str) -> str:
    return KIND_BY_EXT.get(ext, "other")


def is_indexable(name: str, skip_names: set[str]) -> bool:
    if name.startswith("."):
        return False
    if name.lower() in skip_names:
        return False
    ext = ext_of(name)
    if not ext or ext == "md":
        return False
    return ext not in SKIP_EXTS


def fs_entry(rel: str) -> dict:
    """Build a filesystem asset entry for a repo-relative path."""
    full = ROOT / rel
    name = full.name
    ext = ext_of(name)
    mime, _ = mimetypes.guess_type(name)
    try:
        stat = full.stat()
        size = stat.st_size
        date = dt.date.fromtimestamp(stat.st_mtime).isoformat()
    except OSError:
        size, date = 0, dt.date.today().isoformat()
    entry = {
        "path": rel,
        "name": name,
        "kind": kind_of(ext),
        "ext": ext,
        "type": ext,
        "size": size,
        "date": date,
        "source": "filesystem",
    }
    if mime:
        entry["mime"] = mime
    return entry


def walk_filesystem(skip_names: set[str]) -> dict[str, dict]:
    """rel-path -> entry for every indexable non-markdown file under the
    configured knowledge sources."""
    out: dict[str, dict] = {}
    for src, recursive in _sources():
        base = ROOT / src
        if not base.is_dir():
            continue
        if recursive:
            walker = (Path(dp) / fn for dp, _, fns in os.walk(base) for fn in fns)
        else:
            walker = (base / fn for fn in os.listdir(base))
        for f in walker:
            if not f.is_file() or not is_indexable(f.name, skip_names):
                continue
            rel = f.relative_to(ROOT).as_posix()
            out.setdefault(rel, fs_entry(rel))
    return out


def _media_path(ref: str) -> str:
    """Normalize a session media reference for use as an index path/key."""
    return ref[1:] if ref.startswith("/") else ref


def session_media(by_path: dict[str, dict]) -> list[dict]:
    """Index each session's media (frames + video) exactly once. A reference that
    resolves to a file ALREADY found on the filesystem is annotated with its
    session in place (one entry, two surfaces); an off-repo URL becomes a
    source='session' entry. Plain external player URLs (youtube/drive/…) carry no
    file to index and are left to the session page's own embed."""
    if not SESSIONS.exists():
        return []
    try:
        data = json.loads(SESSIONS.read_text(encoding="utf-8"))
    except ValueError:
        return []

    extra: list[dict] = []
    seen_urls: set[str] = set()
    for s in data.get("sessions", []) or []:
        sid = s.get("id", "")
        sdate = s.get("date", "")
        refs: list[str] = list(s.get("frames", []) or [])
        if s.get("video_url"):
            refs.append(s["video_url"])
        for ref in refs:
            ref = (ref or "").strip()
            if not ref:
                continue
            # On-repo file already indexed from the filesystem: tag it once.
            key = _media_path(ref)
            if key in by_path:
                by_path[key].setdefault("session", sid)
                continue
            # Off-repo http(s) media with a real file extension -> session entry.
            if ref.startswith(("http://", "https://")):
                name = ref.rstrip("/").split("/")[-1].split("?")[0]
                ext = ext_of(name)
                if not ext or ext == "md" or ext in SKIP_EXTS:
                    continue  # external player URL, not a downloadable asset
                if ref in seen_urls:
                    continue
                seen_urls.add(ref)
                entry = {
                    "path": ref,
                    "name": name or sid,
                    "kind": kind_of(ext),
                    "ext": ext,
                    "type": ext,
                    "size": 0,
                    "date": sdate or dt.date.today().isoformat(),
                    "session": sid,
                    "source": "session",
                }
                mime, _ = mimetypes.guess_type(name)
                if mime:
                    entry["mime"] = mime
                extra.append(entry)
    return extra


def main() -> int:
    skip_names = _skip_names()
    by_path = walk_filesystem(skip_names)
    extra = session_media(by_path)
    assets = sorted(by_path.values(), key=lambda a: a["path"]) + sorted(extra, key=lambda a: a["path"])

    # Stable `generated` stamp: only bump when the asset set actually changed, so
    # the drift gate (#6) stays quiet on a no-op rebuild.
    prev = {}
    if OUT.exists():
        try:
            prev = json.loads(OUT.read_text(encoding="utf-8"))
        except ValueError:
            prev = {}
    generated = (prev.get("generated")
                 if prev.get("assets") == assets and prev.get("generated")
                 else dt.date.today().isoformat())
    payload = {
        "generated": generated,
        "count": len(assets),
        "assets": assets,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {OUT} ({len(assets)} asset(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
