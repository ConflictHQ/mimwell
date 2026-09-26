#!/usr/bin/env python3
"""Build the portal knowledge graph from the enriched PlanOpticon graph.

The build *algorithm* is client-agnostic; every client-specific value is read
from data files (client.config.json or sibling JSON) with safe empty-defaults,
so this runs cleanly for a brand-new engagement that has none of them yet.

Input
-----
  knowledge-base/knowledge_graph_enriched.json   local PlanOpticon working area
      (produced by the enrichment step — gitignored, not committed). If it is
      absent a fresh scaffold may initialize empty outputs. An existing populated
      projection is preserved and the command fails. Refresh jobs use
      --require-source so missing input cannot be reported as successful refresh.

Output
------
  app/knowledge_graph.json   {nodes: [{id,name,type,sessions,descriptions}],
                              edges: [{source,target,type}]}
  app/kg-references.json     {refs: {entity: [{title, href}]}}  from wiki_refs

Configuration (client.config.json, all optional)
------------------------------------------------
  knowledge.wikiDir   relative path to the wiki directory whose pages back the
                      entity references (default: "knowledge/wiki"). A node's
                      wiki_refs only become references if the matching page file
                      actually exists under this directory.

Run from anywhere:  python3 scripts/build-kg.py
"""
from __future__ import annotations

import argparse
import json
import copy
from pathlib import Path

from kg_evidence import edge_claims, merge_claims
from kg_identity import guard_records, identity, portable_props

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "knowledge-base" / "knowledge_graph_enriched.json"
OUT_KG = ROOT / "app" / "knowledge_graph.json"
OUT_REFS = ROOT / "app" / "kg-references.json"
CONFIG = ROOT / "client.config.json"

DEFAULT_WIKI_DIR = "knowledge/wiki"

# The single source of truth for the KG's format version (#25). Bumping the KG
# format is a two-step move: change this, then register a migration in
# migrate-kg.py FROM the old value (which imports KG_FORMAT from here, the same
# way migrate-brain.py imports BRAIN_VERSION from gen-brain.py — one owner, so
# generator and migrator can never disagree on "current").
KG_FORMAT = "conflict-kg/v1"


def load_wiki_dir(root=ROOT):
    """Resolve the wiki directory from client.config.json with a safe default."""
    try:
        cfg = json.loads((root / "client.config.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        cfg = {}
    rel = cfg.get("knowledge", {}).get("wikiDir") or DEFAULT_WIKI_DIR
    return root / rel, rel


def build(src_nodes, src_rels, wiki_dir, wiki_rel):
    guard_records(src_nodes, src_rels)
    nodes, refs = [], {}
    id_map = {}
    explicit_ids = set()
    for n in src_nodes:
        explicit = identity(n, "node")
        name = n.get("name", "") if explicit else n.get("name", "").strip()
        if not name:
            if explicit:
                raise ValueError("identified graph node requires a display name")
            continue
        sessions = sorted(
            {o.get("recording") for o in n.get("occurrences", n.get("props", {}).get("occurrences", []))
             if o.get("recording")}
        )
        descriptions = []
        if n.get("canonical_definition"):
            descriptions.append(n["canonical_definition"])
        descriptions += [d for d in n.get("descriptions", []) if d and d not in descriptions]
        nid = explicit or name
        if n.get("id") is not None:
            id_map[n["id"]] = nid
        if explicit in explicit_ids:
            continue
        if explicit:
            explicit_ids.add(explicit)
        node = {"id": nid, "name": name, "type": n.get("type", "concept")}
        props = portable_props(n, ("id", "name", "type", "sessions", "descriptions"))
        if props:
            node["props"] = props
        if explicit:
            for field in ("sessions", "descriptions"):
                if field in n and field in node["props"]:
                    raise ValueError(f"graph property collides with props: {field}")
        if explicit and "sessions" in n:
            node["sessions"] = copy.deepcopy(n["sessions"])
        elif sessions:
            node["sessions"] = sessions
        if explicit and "descriptions" in n:
            node["descriptions"] = copy.deepcopy(n["descriptions"])
        elif descriptions:
            node["descriptions"] = descriptions
        nodes.append(node)

        wiki_refs = []
        for ref in n.get("wiki_refs", []):
            page = ref[:-3] if ref.endswith(".md") else ref
            fname = page.replace(" ", "-") + ".md"
            if (wiki_dir / fname).is_file():
                wiki_refs.append({
                    "title": f"{page.replace('-', ' ')} (wiki)",
                    "href": "/app/reader.html?f=" + f"{wiki_rel}/{fname}",
                })
        if wiki_refs:
            refs[nid] = wiki_refs

    ids = {n["id"] for n in nodes}
    if len(ids) != len(nodes):
        raise ValueError("graph compilation produced duplicate node IDs")
    seen, edges = {}, []
    for e in src_rels:
        explicit = identity(e, "edge")
        s = id_map.get(e.get("source"), e.get("source"))
        t = id_map.get(e.get("target"), e.get("target"))
        rel = e.get("type", "")
        if s not in ids or t not in ids:
            if explicit:
                raise ValueError("identified relationship has a missing endpoint")
            continue
        if s == t and not explicit:
            continue
        key = ("record", explicit) if explicit else ("triple", s, t, rel)
        retained = e if explicit else edge_claims(e)
        edge = {"source": s, "target": t, "type": rel}
        props = portable_props(retained, ("source", "target", "type"))
        if props:
            edge["props"] = props
        if key in seen:
            if not explicit:
                merge_claims(seen[key], edge)
            continue
        seen[key] = edge
        edges.append(edge)

    return nodes, edges, refs


def build_files(root, *, require_source=False):
    root = Path(root)
    src = root / "knowledge-base/knowledge_graph_enriched.json"
    out_kg, out_refs = root / "app/knowledge_graph.json", root / "app/kg-references.json"
    wiki_dir, wiki_rel = load_wiki_dir(root)

    if src.exists():
        g = json.loads(src.read_text(encoding="utf-8"))
        if not isinstance(g, dict) or "nodes" not in g:
            raise ValueError("enriched graph must be an object with a nodes array")
        src_nodes = g["nodes"]
        src_rels = g.get("relationships", g.get("edges", []))
        if any(not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows)
               for rows in (src_nodes, src_rels)):
            raise ValueError("enriched graph nodes and relationships must be arrays of objects")
    else:
        if require_source:
            raise ValueError("required enriched graph input is missing; projections were preserved")
        # Missing inputs and an intentionally empty valid input are different.
        # Never turn lost local working data into a successful destructive refresh.
        for path, empty in ((out_kg, {"nodes": [], "edges": []}), (out_refs, {"refs": {}})):
            if path.exists():
                old = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(old, dict) or any(old.get(field) != value for field, value in empty.items()):
                    raise ValueError("enriched graph input is missing; existing projection was preserved")
        print("Enriched graph input is absent; initializing empty outputs (not a freshness proof).")
        src_nodes, src_rels = [], []

    nodes, edges, refs = build(src_nodes, src_rels, wiki_dir, wiki_rel)

    out_kg.parent.mkdir(parents=True, exist_ok=True)
    out_kg.write_text(
        # The canonical interchange format (docs/primitives/knowledge-engine.md
        # § "The knowledge graph"): edges reference node ids. KG_FORMAT is the
        # one place this version lives — migrate-kg.py imports it.
        json.dumps({"format": KG_FORMAT, "nodes": nodes, "edges": edges}),
        encoding="utf-8",
    )
    out_refs.write_text(
        json.dumps({"refs": refs}, indent=1), encoding="utf-8"
    )
    print(f"Wrote {out_kg}: {len(nodes)} nodes, {len(edges)} edges")
    print(f"Wrote {out_refs}: {len(refs)} entities with wiki references")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--require-source", action="store_true",
                        help="Fail on missing input, including empty/bootstrap projections")
    args = parser.parse_args(argv)
    try:
        build_files(args.root, require_source=args.require_source)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"KG refresh failed: {exc}\n")


if __name__ == "__main__":
    main()
