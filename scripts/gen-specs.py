#!/usr/bin/env python3
"""Walk specs/ and emit specs/manifest.json — the index the Plan page renders.

The project plan is authored as a tree of markdown files with frontmatter
(see specs/README.md). Levels are expressed by the folder tree; numeric
prefixes (01-, 02-, …) order siblings and are stripped from the generated id.
A container folder declares itself with a 00-*.md file (the phase / epic /
feature node); other files and sub-folders are its children.

This script carries no client specifics — everything comes from the markdown
files under specs/. With an empty or missing tree it writes an empty manifest
so the page renders a clean empty state.

Only simple frontmatter is parsed (stdlib only, no PyYAML): scalar
`key: value` and inline `[a, b]` lists. All fields are optional and fall back
to safe defaults.

Run from anywhere:  python3 scripts/gen-specs.py
"""

from __future__ import annotations

import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPECS = os.path.join(ROOT, "specs")
OUT = os.path.join(SPECS, "manifest.json")

# Depth (number of path segments below specs/) -> inferred node type, used when
# a file's frontmatter omits `type`.
DEPTH_TYPE = {1: "phase", 2: "epic", 3: "feature"}
TYPE_ORDER = {"phase": 0, "epic": 1, "feature": 2, "story": 3}

PREFIX_RE = re.compile(r"^\d+[-_]")
FM_RE = re.compile(r"^---\n(.*?)\n---", re.S)
LIST_KEYS = {"labels", "depends_on", "references", "implemented_in"}
# Markdown files under specs/ that are docs, not plan nodes.
SKIP_FILES = {"readme.md", "story-standard.md"}


def strip_prefix(name: str) -> str:
    """Drop a leading numeric ordering prefix: '01-example' -> 'example'."""
    return PREFIX_RE.sub("", name)


def is_declarer(name: str) -> bool:
    """A folder declares itself with a '00-*.md' (or bare '00.md') file."""
    return bool(re.match(r"^0+([-_].*)?\.md$", name))


def sort_key(name: str) -> tuple:
    """Order siblings by numeric prefix first, then name."""
    m = re.match(r"^(\d+)", name)
    return (int(m.group(1)) if m else 9999, name.lower())


def parse_frontmatter(text: str) -> dict:
    """Parse the leading --- block. Supports `key: value` and `key: [a, b]`."""
    meta = {}
    m = FM_RE.match(text)
    if not m:
        return meta
    for line in m.group(1).splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip()
        if val.startswith("[") and val.endswith("]"):
            inner = val[1:-1].strip()
            meta[key] = [v.strip().strip("\"'") for v in inner.split(",") if v.strip()]
        else:
            val = val.strip("\"'")
            meta[key] = [v.strip() for v in val.split(",") if v.strip()] if key in LIST_KEYS and val else val
    return meta


def first_heading(text: str) -> str:
    body = FM_RE.sub("", text, count=1)
    h = re.search(r"^#\s+(.+)$", body, re.M)
    return h.group(1).strip() if h else ""


def node_id(rel_segments: list) -> str:
    """Path id from specs/, prefixes stripped. A trailing '00-*' declarer
    collapses onto its folder (the folder *is* the node)."""
    segs = list(rel_segments)
    if segs and is_declarer(segs[-1]):
        segs = segs[:-1]
    segs = [strip_prefix(s) for s in segs]
    return "/".join(s[:-3] if s.endswith(".md") else s for s in segs)


def read_md(path: str) -> tuple:
    text = open(path, encoding="utf-8", errors="replace").read()
    return parse_frontmatter(text), first_heading(text)


def collect():
    """Walk specs/, returning one manifest entry per markdown node."""
    items = []
    if not os.path.isdir(SPECS):
        return items

    def walk(abs_dir: str, rel_parts: list, depth: int):
        try:
            entries = os.listdir(abs_dir)
        except OSError:
            return
        files = sorted((e for e in entries if e.endswith(".md") and e.lower() not in SKIP_FILES), key=sort_key)
        dirs = sorted((e for e in entries
                       if os.path.isdir(os.path.join(abs_dir, e)) and not e.startswith(".")), key=sort_key)

        # The folder's declarer (00-*.md) defines this container node.
        declarer = next((f for f in files if is_declarer(f)), None)
        if declarer and rel_parts:
            add_entry(os.path.join(abs_dir, declarer), rel_parts + [declarer], depth, is_declarer=True)

        # Leaf markdown files (anything that isn't the declarer) are children.
        for f in files:
            if f == declarer:
                continue
            add_entry(os.path.join(abs_dir, f), rel_parts + [f], depth + 1, is_declarer=False)

        # Recurse into sub-folders.
        for d in dirs:
            walk(os.path.join(abs_dir, d), rel_parts + [d], depth + 1)

    def add_entry(abs_path, rel_segments, depth, is_declarer):
        meta, heading = read_md(abs_path)
        nid = node_id(rel_segments)
        inferred = DEPTH_TYPE.get(depth, "story") if is_declarer else "story"
        title = meta.get("title") or heading or strip_prefix(os.path.basename(abs_path))[:-3]
        rel_path = os.path.relpath(abs_path, ROOT).replace(os.sep, "/")
        parent = nid.rsplit("/", 1)[0] if "/" in nid else ""
        items.append({
            "id": nid,
            "title": title,
            "type": meta.get("type") or inferred,
            "status": meta.get("status") or "planned",
            "priority": meta.get("priority") or "",
            "labels": meta.get("labels") if isinstance(meta.get("labels"), list) else ([meta["labels"]] if meta.get("labels") else []),
            "date": meta.get("date") or "",
            "depends_on": meta.get("depends_on") if isinstance(meta.get("depends_on"), list) else ([meta["depends_on"]] if meta.get("depends_on") else []),
            "references": meta.get("references") if isinstance(meta.get("references"), list) else ([meta["references"]] if meta.get("references") else []),
            "implemented_in": meta.get("implemented_in") if isinstance(meta.get("implemented_in"), list) else ([meta["implemented_in"]] if meta.get("implemented_in") else []),
            "estimate": meta.get("estimate") or "",
            "owner": meta.get("owner") or "",
            "parent": parent,
            "depth": depth,
            "path": rel_path,
        })

    walk(SPECS, [], 0)
    return items


def main():
    items = collect()
    # Stable order: by id (which encodes the prefixed path), then by type rank.
    items.sort(key=lambda x: (x["id"], TYPE_ORDER.get(x["type"], 9)))
    os.makedirs(SPECS, exist_ok=True)
    payload = {"count": len(items), "items": items}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=1)
    phases = sum(1 for i in items if i["type"] == "phase")
    print(f"Wrote {OUT}: {len(items)} nodes across {phases} phase(s)")


if __name__ == "__main__":
    main()
