#!/usr/bin/env python3
"""Walk the knowledge markdowns and emit app/docs-manifest.json — the categorized
document library rendered by /library/ (issue #46, generalized from an earlier
docs-manifest pattern).

The manifest is the markdown counterpart of the knowledge-pack: where the pack is
a FLAT search index, this organizes the same docs into a curated hierarchy of
  sections -> (optional) groups -> docs
each carrying id / label / description / count. The library page keeps the flat
search on top and adds this browse structure underneath.

Curation lives in the data, not the code
-----------------------------------------
Section/group PLACEMENT carries product meaning, so the generator preserves the
existing manifest across regens (the file IS the curation surface — drop a doc
into a section by hand and a rebuild keeps it there). It then:
  - validates every curated path still exists (drops missing ones with a warning);
  - corrects each section/group count from what actually remains;
  - appends any newly-discovered, not-yet-placed markdown to a single DEFAULT
    catch-all section so nothing is silently lost;
  - dedupes so a doc appears in EXACTLY ONE place (the #6 coverage gate enforces
    exactly-one-index across knowledge-pack / docs-manifest / assets).

Unlike the original it generalizes, NO section ids are hardcoded — the template ships a
generic empty seed (one default "Documents" bucket). Real engagements curate
sections into the file directly; those survive every rebuild.

Config (which dirs to index, which filenames to skip) is read from
client.config.json under the "knowledge" key — this script hardcodes nothing
about a particular client.

Run from anywhere:  python3 scripts/gen-docs-manifest.py
"""
from __future__ import annotations

import datetime as dt
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "app" / "docs-manifest.json"
CONFIG = ROOT / "client.config.json"

# The catch-all section newly-discovered docs land in. Generic, not client-
# specific; a real engagement may rename it in the data file and the rename
# survives (placement is preserved by path).
DEFAULT_SECTION_ID = "documents"
DEFAULT_SECTION_LABEL = "Documents"
DEFAULT_SECTION_DESCRIPTION = "Knowledge-base documents not yet filed into a category."


def _knowledge() -> dict:
    return json.loads(CONFIG.read_text(encoding="utf-8")).get("knowledge", {})


def _sources() -> list[tuple[str, bool]]:
    return [(s["path"], s.get("recursive", False)) for s in _knowledge().get("sources", [])]


def _skip_names() -> set[str]:
    return {n.lower() for n in _knowledge().get("skipNames", [])}


def load_existing() -> dict:
    if not OUT.exists():
        return {"sections": []}
    try:
        return json.loads(OUT.read_text(encoding="utf-8"))
    except ValueError:
        return {"sections": []}


def flatten_docs(manifest: dict) -> dict[str, dict]:
    """Path -> curated doc entry, across every section and group. Carries the
    curated title/updated so a rebuild keeps hand-set metadata."""
    out: dict[str, dict] = {}
    for section in manifest.get("sections", []) or []:
        for item in section.get("docs", []) or []:
            out[item["path"]] = item
        for group in section.get("groups", []) or []:
            for item in group.get("docs", []) or []:
                out[item["path"]] = item
    return out


def git_date(rel: str) -> str:
    try:
        result = subprocess.check_output(
            ["git", "log", "-1", "--format=%as", "--", rel],
            cwd=ROOT, text=True, stderr=subprocess.DEVNULL,
        ).strip()
        return result or dt.date.today().isoformat()
    except (subprocess.CalledProcessError, OSError):
        return dt.date.today().isoformat()


def titleize(rel: str) -> str:
    stem = Path(rel).stem
    return re.sub(r"\s+", " ", stem.replace("-", " ").replace("_", " ")).strip().title()


def doc_title(rel: str) -> str:
    """Prefer the markdown's frontmatter title / first H1, else a titleized stem."""
    try:
        text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return titleize(rel)
    m = re.search(r"^---\n(.*?)\n---", text, re.S)
    if m:
        t = re.search(r"^(?:title|name):\s*[\"']?(.*?)[\"']?\s*$", m.group(1), re.M)
        if t and t.group(1).strip():
            return t.group(1).strip()
        text = text[m.end():]
    h = re.search(r"^#\s+(.+)$", text, re.M)
    if h:
        return h.group(1).strip()
    return titleize(rel)


WORDS_PER_MINUTE = 200


def reading_minutes(rel: str) -> int:
    """Word count / 200wpm (frontmatter stripped), rounded up to a whole minute,
    minimum 1. Recomputed every run from the file's current content — unlike
    title/updated this is never hand-curated, so nothing here reads `existing`."""
    try:
        text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 1
    m = re.match(r"^---\n.*?\n---\n?", text, re.S)
    if m:
        text = text[m.end():]
    words = len(text.split())
    return max(1, -(-words // WORDS_PER_MINUTE))  # ceil division, stdlib-only


def make_doc(rel: str, existing: dict[str, dict], title: str | None = None) -> dict | None:
    """Build a doc entry, carrying curated metadata. Returns None (with a
    warning) when the curated path has vanished from disk."""
    old = existing.get(rel, {})
    if not (ROOT / rel).exists():
        print(f"WARNING: dropping missing docs-manifest path: {rel}")
        return None
    return {
        "title": title or old.get("title") or doc_title(rel),
        "path": rel,
        "updated": old.get("updated") or git_date(rel),
        "reading_time": reading_minutes(rel),
    }


def discover_markdown() -> list[str]:
    """Repo-relative paths of every indexable markdown under knowledge.sources."""
    skip = _skip_names()
    found: set[str] = set()
    for src, recursive in _sources():
        base = ROOT / src
        if not base.is_dir():
            continue
        walker = base.rglob("*.md") if recursive else base.glob("*.md")
        for f in walker:
            if not f.is_file() or f.name.lower() in skip:
                continue
            found.add(f.relative_to(ROOT).as_posix())
    return sorted(found)


def rebuild_section(seed: dict, existing: dict[str, dict]) -> dict:
    """Rebuild one curated section: keep its id/label/description, revalidate
    each curated doc, and recompute counts. Groups are preserved when present."""
    out: dict = {
        "id": seed["id"],
        "label": seed.get("label", titleize(seed["id"])),
    }
    if seed.get("description"):
        out["description"] = seed["description"]
    if seed.get("default"):
        out["default"] = True

    if seed.get("groups"):
        groups = []
        for group in seed["groups"]:
            docs = [d for item in group.get("docs", []) or []
                    if (d := make_doc(item["path"], existing, item.get("title"))) is not None]
            g: dict = {}
            if group.get("id"):
                g["id"] = group["id"]
            g["label"] = group.get("label", "")
            if group.get("description"):
                g["description"] = group["description"]
            g["docs"] = docs
            groups.append(g)
        out["groups"] = groups
        out["count"] = sum(len(g["docs"]) for g in groups)
    else:
        docs = [d for item in seed.get("docs", []) or []
                if (d := make_doc(item["path"], existing, item.get("title"))) is not None]
        out["docs"] = docs
        out["count"] = len(docs)
    return out


def default_section_seed(current: dict) -> dict:
    """The catch-all section seed: reuse the curated one (preserving any rename)
    if the manifest already marks a default/`DEFAULT_SECTION_ID` section, else a
    fresh generic bucket."""
    for section in current.get("sections", []) or []:
        if section.get("default") or section.get("id") == DEFAULT_SECTION_ID:
            seed = dict(section)
            seed["default"] = True
            return seed
    return {
        "id": DEFAULT_SECTION_ID,
        "label": DEFAULT_SECTION_LABEL,
        "description": DEFAULT_SECTION_DESCRIPTION,
        "default": True,
        "docs": [],
    }


def main() -> int:
    current = load_existing()
    existing = flatten_docs(current)

    # 1) Rebuild each curated, non-default section in place (placement preserved).
    sections: list[dict] = []
    for section in current.get("sections", []) or []:
        if section.get("default") or section.get("id") == DEFAULT_SECTION_ID:
            continue  # the default bucket is rebuilt last, once it has its extras
        sections.append(rebuild_section(section, existing))

    # 2) Newly-discovered markdown not placed in any curated section -> default.
    placed = {item["path"] for item in existing.values()}
    discovered = discover_markdown()
    default_seed = default_section_seed(current)
    default_docs = list(default_seed.get("docs", []) or [])
    placed_default = {d["path"] for d in default_docs}
    for rel in discovered:
        if rel not in placed and rel not in placed_default:
            default_docs.append({"path": rel})
            placed_default.add(rel)
    default_seed["docs"] = default_docs
    sections.append(rebuild_section(default_seed, existing))

    # 3) A doc appears at most once across the whole manifest — drop later dupes
    #    (a curated doc filed under two groups) and recompute counts.
    seen: set[str] = set()

    def dedupe_docs(docs: list[dict]) -> list[dict]:
        out = []
        for d in docs:
            if d["path"] in seen:
                continue
            seen.add(d["path"])
            out.append(d)
        return out

    for section in sections:
        if "groups" in section:
            for group in section["groups"]:
                group["docs"] = dedupe_docs(group["docs"])
            section["count"] = sum(len(g["docs"]) for g in section["groups"])
        else:
            section["docs"] = dedupe_docs(section["docs"])
            section["count"] = len(section["docs"])

    # Stable `generated` stamp: only bump when the sections actually changed, so
    # the drift gate (#6) stays quiet on a no-op rebuild.
    generated = (current.get("generated")
                 if current.get("sections") == sections and current.get("generated")
                 else dt.date.today().isoformat())
    payload = {"generated": generated, "sections": sections}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    total = sum(s["count"] for s in sections)
    print(f"Wrote {OUT} ({total} docs across {len(sections)} section(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
