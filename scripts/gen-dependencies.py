#!/usr/bin/env python3
"""Derive the dependency graph from the plan and emit app/dependencies.json.

The Plan page is authored as a tree of markdown files with frontmatter
(see specs/README.md); scripts/gen-specs.py indexes them into specs/manifest.json.
Each item may carry a `depends_on` list of node ids — "this node can't start
until those are done". This script reads that manifest and projects those
relationships into a small graph the Dependencies page renders:

    { "nodes": [{id, title, type, status}], "edges": [{from, to}] }

An edge {from: A, to: B} means "A depends on B".

This script carries no client specifics — everything comes from the manifest.
With a missing/empty manifest (or no declared dependencies) it still writes a
well-formed file so the page renders a clean empty state.

Run from anywhere:  python3 scripts/gen-dependencies.py
"""

from __future__ import annotations

import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(ROOT, "specs", "manifest.json")
OUT = os.path.join(ROOT, "app", "dependencies.json")


def load_items() -> list:
    """Read the manifest items list. Missing/invalid -> empty list."""
    try:
        with open(MANIFEST, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    items = data.get("items") if isinstance(data, dict) else None
    return items if isinstance(items, list) else []


def build(items: list) -> dict:
    """Project manifest items into {nodes, edges} from each `depends_on`.

    Only nodes that participate in at least one dependency edge are emitted —
    the graph stays focused on actual relationships rather than the whole plan.
    Edges to ids absent from the manifest are kept (the target node is still
    emitted with a placeholder title/status of "unknown") so a typo'd or
    external dependency is visible rather than silently dropped.
    """
    by_id = {it.get("id"): it for it in items if isinstance(it, dict) and it.get("id")}

    edges = []
    seen_edges = set()
    used = set()
    for it in items:
        if not isinstance(it, dict):
            continue
        src = it.get("id")
        if not src:
            continue
        deps = it.get("depends_on") or []
        if not isinstance(deps, list):
            deps = [deps]
        for dep in deps:
            dep = str(dep).strip()
            if not dep or dep == src:
                continue
            key = (src, dep)
            if key in seen_edges:
                continue
            seen_edges.add(key)
            edges.append({"from": src, "to": dep})
            used.add(src)
            used.add(dep)

    nodes = []
    for nid in sorted(used):
        it = by_id.get(nid)
        if it:
            nodes.append({
                "id": nid,
                "title": it.get("title") or nid,
                "type": it.get("type") or "story",
                "status": it.get("status") or "planned",
            })
        else:
            # Referenced as a dependency but not present in the manifest.
            nodes.append({
                "id": nid,
                "title": nid,
                "type": "unknown",
                "status": "unknown",
            })

    return {"nodes": nodes, "edges": edges}


def main():
    graph = build(load_items())
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(graph, f, indent=1)
    print(f"Wrote {OUT}: {len(graph['nodes'])} node(s), {len(graph['edges'])} edge(s)")


if __name__ == "__main__":
    main()
