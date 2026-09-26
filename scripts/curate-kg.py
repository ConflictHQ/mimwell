#!/usr/bin/env python3
"""Knowledge Graph Curation — merge duplicates, remove noise, fix types.

The curation *algorithm* is client-agnostic; the *rules* it applies live in a
data file (default knowledge/curation.json) so a new engagement curates its own
graph without editing this script.

Rules file schema
------------------
{
  "merges": {
    "Canonical Name": ["alias 1", "alias 2"]   # aliases collapse into canonical
  },
  "typeFixes": {
    "Entity Name": "correct-type",             # override the node's type
    "Other Entity": null                        # null => drop the entity
  },
  "drops": ["entity to remove", ...]            # entity names to remove outright
}

Semantics (mirrors the source curation this was ported from):
- merges: build an alias -> canonical lookup. Every node/edge name is resolved
  through it. Nodes that resolve to the same canonical are merged into one, and
  their "descriptions" lists are unioned (order-preserving, de-duplicated).
- drops: a node is removed if its raw name OR its resolved canonical name is in
  drops (case-insensitive on the raw name, exact on the canonical).
- typeFixes: keyed by canonical name. A string value replaces the node "type";
  a null value drops the node entirely (same as listing it in drops).
- edges: endpoints are resolved through the alias map; an edge is dropped if
  either endpoint is no longer a node, if it is a self-loop, or if an identical
  (source, target, type) triple was already kept.

CLI
---
  python3 scripts/curate-kg.py [--in app/knowledge_graph.json]
                               [--out app/knowledge_graph.json]
                               [--rules knowledge/curation.json]

In-place curation (in == out) is the default; the graph is regenerable.
"""

import argparse
import json
import copy
from collections import Counter
from pathlib import Path

from kg_evidence import edge_claims, merge_claims
from kg_identity import guard_records, identity

ROOT = Path(__file__).resolve().parent.parent


def load_rules(path):
    with open(path) as f:
        rules = json.load(f)
    merge = rules.get("merges", {})
    type_fixes = rules.get("typeFixes", {})
    remove = set(rules.get("drops", []))
    return merge, type_fixes, remove


def curate(kg, merge, type_fixes, remove):
    nodes = copy.deepcopy(kg.get("nodes", kg.get("entities", [])))
    edges = copy.deepcopy(kg.get("edges", kg.get("relationships", [])))
    guard_records(nodes, edges)

    # ── Build alias → canonical lookup ──────────────────────────────────────
    alias_to_canonical = {}
    for canonical, aliases in merge.items():
        alias_to_canonical[canonical.lower()] = canonical
        for alias in aliases:
            alias_to_canonical[alias.lower()] = canonical

    def resolve(name):
        return alias_to_canonical.get(name.lower(), name)

    remove_lower = {r.lower() for r in remove}

    # ── Filter and remap nodes ──────────────────────────────────────────────
    seen_canonical = {}
    clean_nodes = []
    id_map = {}

    for n in nodes:
        explicit = identity(n, "node")
        name = n.get("name", "")
        rule_key = explicit or name

        # Remove noise
        if rule_key in remove or (not explicit and name.lower() in remove_lower):
            continue

        # Resolve to canonical
        canonical = name if explicit else resolve(name)

        # Remove noise after resolution
        if not explicit and canonical in remove:
            continue

        # Type fix
        node_type = n.get("type", "concept")
        type_key = explicit or canonical
        if type_key in type_fixes:
            fixed = type_fixes[type_key]
            if fixed is None:
                continue
            node_type = fixed

        key = ("record", explicit) if explicit else ("name", canonical)
        if key not in seen_canonical:
            merged_node = dict(n)
            merged_node["name"] = canonical
            if not explicit and merged_node.get("id") == name:
                merged_node["id"] = canonical
            merged_node["type"] = node_type
            # Collect descriptions from all aliases
            if not explicit or "descriptions" in n:
                merged_node["descriptions"] = n.get("descriptions", [])
            seen_canonical[key] = merged_node
            clean_nodes.append(merged_node)
        else:
            # Merge descriptions
            existing = seen_canonical[key]
            for d in n.get("descriptions", []):
                if d and d not in existing.get("descriptions", []):
                    existing.setdefault("descriptions", []).append(d)
            if not explicit:
                merge_claims(existing, n)
        if n.get("id") is not None:
            id_map[n["id"]] = seen_canonical[key].get("id", canonical)

    # ── Remap and deduplicate edges ─────────────────────────────────────────
    clean_node_ids = {n.get("id", n["name"]) for n in clean_nodes}
    original_node_ids = {n.get("id", n["name"]) for n in nodes}
    seen_edges = {}
    clean_edges = []

    for e in edges:
        explicit = identity(e, "edge")
        if explicit and (e["source"] not in original_node_ids or e["target"] not in original_node_ids):
            raise ValueError("identified relationship has a missing endpoint before curation")
        def endpoint(raw):
            return id_map.get(raw, raw if raw in original_node_ids else resolve(raw))
        src = endpoint(e.get("source", ""))
        tgt = endpoint(e.get("target", ""))
        rel = e.get("type", e.get("relationship_type", ""))

        # Drop if either endpoint was removed
        if src not in clean_node_ids or tgt not in clean_node_ids:
            continue

        # Drop self-loops
        if src == tgt and not explicit:
            continue

        key = ("record", explicit) if explicit else ("triple", src, tgt, rel)
        if not explicit:
            e = edge_claims(e)
        if key in seen_edges:
            if not explicit:
                merge_claims(seen_edges[key], e)
            continue

        retained = {**e, "source": src, "target": tgt}
        seen_edges[key] = retained
        clean_edges.append(retained)

    guard_records(clean_nodes, clean_edges)
    return nodes, edges, clean_nodes, clean_edges


def main():
    parser = argparse.ArgumentParser(description="Curate the knowledge graph from data-driven rules.")
    parser.add_argument("--in", dest="src", default="app/knowledge_graph.json",
                        help="input graph json (default: app/knowledge_graph.json)")
    parser.add_argument("--out", dest="out", default="app/knowledge_graph.json",
                        help="output graph json (default: app/knowledge_graph.json)")
    parser.add_argument("--rules", dest="rules", default="knowledge/curation.json",
                        help="curation rules json (default: knowledge/curation.json)")
    args = parser.parse_args()

    src = Path(args.src)
    out = Path(args.out)
    rules_path = Path(args.rules)
    if not src.is_absolute():
        src = ROOT / src
    if not out.is_absolute():
        out = ROOT / out
    if not rules_path.is_absolute():
        rules_path = ROOT / rules_path

    merge, type_fixes, remove = load_rules(rules_path)

    with open(src) as f:
        kg = json.load(f)

    nodes, edges, clean_nodes, clean_edges = curate(kg, merge, type_fixes, remove)

    # ── Write output ────────────────────────────────────────────────────────
    out_kg = {"nodes": clean_nodes, "edges": clean_edges}
    if "format" in kg:
        out_kg["format"] = kg["format"]
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        json.dump(out_kg, f, indent=2)

    print(f"Input:  {len(nodes)} nodes, {len(edges)} edges")
    print(f"Output: {len(clean_nodes)} nodes, {len(clean_edges)} edges")
    print(f"Merged: {len(nodes) - len(clean_nodes)} nodes removed/merged, "
          f"{len(edges) - len(clean_edges)} edges dropped/deduped")

    # Breakdown by type
    type_counts = Counter(n["type"] for n in clean_nodes)
    for t, c in sorted(type_counts.items()):
        print(f"  {t}: {c}")


if __name__ == "__main__":
    main()
