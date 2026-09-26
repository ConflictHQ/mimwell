#!/usr/bin/env python3
"""Walk the knowledge markdowns and emit app/knowledge-pack.json — the chat
agent's search index plus the link graph over the same corpus (issue #49).

Top-level keys (additive; every consumer of `items` is untouched):

  items:     [{path, title, summary}] — the flat search index the chat agent
             and the coverage gate read. Markdown items also carry `revision`,
             the sha256 of the document's bytes: the worker compares it with the
             optional D1 corpus index (#64) to tell an index that is behind git.
  backlinks: {path: [referrer, ...]} — incoming doc-to-doc links, from both
             [[wikilinks]] and relative markdown links between indexed docs.
             The reader renders these as "Referenced by".
  wikilinks: {name: path} — every [[name]] seen in the corpus, lowercased,
             resolved to the indexed doc it refers to (stem match; a name
             containing "/" also tries the literal path). On a stem collision
             the shallowest path wins, then lexicographic. The reader uses
             this map to turn [[name]] into links client-side.
  dangling:  [{ref, sources: [...]}] — links whose target is not in the index:
             the to-write queue (Obsidian's unresolved-link affordance).

Links inside fenced or inline code are ignored. A relative link whose target
exists on disk but is deliberately unindexed (skipNames) is neither a backlink
nor dangling. Self-links are dropped.

Client-specific values (which directories to index, which filenames to skip,
which JSON artifacts to register) are read from client.config.json under the
"knowledge" key — this script hardcodes nothing about a particular client.

Run from anywhere:  python3 scripts/gen-knowledge-pack.py
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "app" / "knowledge-pack.json"
CONFIG = ROOT / "client.config.json"

WIKILINK_RE = re.compile(r"\[\[([^\[\]]+?)\]\]")
MDLINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
CODE_RE = re.compile(r"```.*?```|`[^`\n]*`", re.S)


def extract(text: str, filename: str) -> tuple[str, str]:
    """Return (title, summary) from a markdown file's text."""
    title, summary = "", ""
    m = re.search(r"^---\n(.*?)\n---", text, re.S)
    if m:
        fm = m.group(1)
        t = re.search(r"^(?:title|name):\s*[\"']?(.*?)[\"']?\s*$", fm, re.M)
        d = re.search(r"^description:\s*[\"']?(.*?)[\"']?\s*$", fm, re.M)
        if t:
            title = t.group(1)
        if d:
            summary = d.group(1)
        text = text[m.end():]
    if not title:
        h = re.search(r"^#\s+(.+)$", text, re.M)
        title = h.group(1).strip() if h else filename
    if not summary:
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith(("#", "<!--", "|", "```", ">")):
                summary = line
                break
    return title, summary[:300]


def wikilink_names(text: str) -> list[str]:
    """[[name]] / [[name|alias]] / [[name#heading]] -> the bare target names."""
    names = []
    for inner in WIKILINK_RE.findall(text):
        target = inner.split("|")[0].split("#")[0].strip()
        if target:
            names.append(target)
    return names


def mdlink_hrefs(text: str) -> list[str]:
    """Relative markdown links whose target is a .md file (fragment stripped)."""
    hrefs = []
    for href in MDLINK_RE.findall(text):
        href = href.split("#")[0].split("?")[0]
        if not href or re.match(r"^[a-z][a-z0-9+.-]*:", href, re.I):
            continue  # http(s):, mailto:, etc.
        if href.lower().endswith(".md"):
            hrefs.append(href)
    return hrefs


def resolve_mdlink(href: str, src_dir: str) -> str:
    """Resolve a relative (or site-root) md href against the doc's directory."""
    if href.startswith("/"):
        return posixpath.normpath(href.lstrip("/"))
    return posixpath.normpath(posixpath.join(src_dir, href))


def build_wikilink_index(paths: list[str]) -> dict[str, str]:
    """Lower-cased filename stem -> indexed path (shallowest, then lexicographic)."""
    index: dict[str, str] = {}
    for p in sorted(paths, key=lambda p: (p.count("/"), p)):
        stem = posixpath.basename(p)[:-3].lower()  # strip .md
        index.setdefault(stem, p)
    return index


def main() -> int:
    knowledge = json.loads(CONFIG.read_text(encoding="utf-8"))["knowledge"]
    sources = [(s["path"], s["recursive"]) for s in knowledge["sources"]]
    skip_names = {n.lower() for n in knowledge["skipNames"]}
    json_docs = [(d["path"], d["title"]) for d in knowledge["jsonDocs"]]

    # ── Walk the sources: collect every indexable markdown + its text ──────────
    docs: dict[str, str] = {}  # rel path -> raw text
    revisions: dict[str, str] = {}  # rel path -> sha256 of the bytes
    for src, recursive in sources:
        base = ROOT / src
        if not base.is_dir():
            continue
        walker = base.rglob("*.md") if recursive else base.glob("*.md")
        for full in walker:
            if not full.is_file() or full.name.lower() in skip_names:
                continue
            rel = full.relative_to(ROOT).as_posix()
            docs[rel] = full.read_text(encoding="utf-8", errors="replace")
            revisions[rel] = hashlib.sha256(full.read_bytes()).hexdigest()

    items = []
    for rel, text in docs.items():
        title, summary = extract(text, posixpath.basename(rel))
        items.append({"path": rel, "title": title, "summary": summary, "revision": revisions[rel]})
    for path, title in json_docs:
        if (ROOT / path).is_file():
            items.append({"path": path, "title": title,
                          "summary": "Versioned JSON data file — read directly for current values."})
    items.sort(key=lambda x: x["path"])

    # ── Link graph over the same corpus (#49) ──────────────────────────────────
    stem_index = build_wikilink_index(list(docs))
    backlinks: dict[str, set[str]] = {}
    wikilinks: dict[str, str] = {}
    dangling: dict[str, set[str]] = {}

    def link(src: str, target: str) -> None:
        if target != src:
            backlinks.setdefault(target, set()).add(src)

    for src, text in sorted(docs.items()):
        body = CODE_RE.sub("", text)
        src_dir = posixpath.dirname(src)
        for name in wikilink_names(body):
            key = name.lower()
            resolved = stem_index.get(key)
            if not resolved and "/" in key:
                literal = posixpath.normpath(key if key.endswith(".md") else key + ".md")
                resolved = literal if literal in docs else None
            if resolved:
                wikilinks[key] = resolved
                link(src, resolved)
            else:
                dangling.setdefault(name, set()).add(src)
        for href in mdlink_hrefs(body):
            target = resolve_mdlink(href, src_dir)
            if target in docs:
                link(src, target)
            # a target that escapes the repo root is always dangling: the portal can
            # never serve it, and resolving it against the local filesystem would make
            # the pack differ between a working clone and a clean CI checkout
            elif target.startswith("../") or not (ROOT / target).is_file():  # exists-but-unindexed: ignore
                dangling.setdefault(href, set()).add(src)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "generated_for": "portal-chat-agent",
        "count": len(items),
        "items": items,
        "backlinks": {k: sorted(v) for k, v in sorted(backlinks.items())},
        "wikilinks": dict(sorted(wikilinks.items())),
        "dangling": [{"ref": ref, "sources": sorted(srcs)}
                     for ref, srcs in sorted(dangling.items())],
    }, indent=1), encoding="utf-8")
    print(f"Wrote {OUT} ({len(items)} entries, "
          f"{sum(len(v) for v in backlinks.values())} links, {len(dangling)} dangling)")
    if dangling:
        print("Dangling (to-write queue):")
        for ref, srcs in sorted(dangling.items()):
            print(f"  {ref} <- {', '.join(sorted(srcs))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
