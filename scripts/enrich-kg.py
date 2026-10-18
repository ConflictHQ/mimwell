#!/usr/bin/env python3
"""Enrich the merged knowledge graph before it is built into the portal.

Pipeline position:
  merge-kg.py   -> knowledge-base/knowledge_graph.json           (raw, per-recording merge)
  enrich-kg.py  -> knowledge-base/knowledge_graph_enriched.json  (this script)
  build-kg.py   -> app/knowledge_graph.json                      (served artifact)

Enrichment is the one knowledge-graph step that is inherently client-specific:
transcripts spell the same person/company/system many ways ("Sam", "Sam O.",
"Samira"), and roles/titles only a human knows. Rather than hardcode those
maps in engine code, this generic stub reads them from `knowledge/enrichment.json`
(a hand-maintained source file). With no enrichment file present it is a clean
pass-through, so the pipeline works out of the box for a fresh engagement.

enrichment.json shape (all keys optional):
  {
    "aliases": { "Sam": "Samira Okonkwo", ... },        # name -> canonical name
    "roles":   { "Samira Okonkwo": "VP of Operations", ... },  # canonical -> role
    "drop_types": ["filler"],                            # node types to remove
    "relations": { "uses data from": "uses", "provides data to": "provides" }
                                                           # free verb -> canonical (#57)
  }

Edge relation canonicalization (#57): LLM extraction produces near-synonym
verbs unconstrained ("uses data from" / "consumes" / "reads from" all meaning
roughly the same thing). brain-schema.json's declared edge vocabulary is the
canonical set (the same vocabulary the compiled brain's own edges draw from —
one declared ontology, not a second parallel list). For each edge: the
`relations` map above is tried first (an explicit per-engagement mapping);
whatever survives that is checked against the canonical set; anything still
outside it is rewritten to `"other"` with the ORIGINAL verb preserved as
`raw_type` (never silently dropped — an audit trail plus, per #57, the
explicit escape hatch itself: an `other` count trending up over time is the
signal the vocabulary is missing a real relation, not that extraction is
noisy).

Output uses the current mimwell-kg/v1 graph identifier.
"""
import json
import copy
import sys
from pathlib import Path

from kg_evidence import edge_claims, merge_claims
from kg_identity import guard_records, identity

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "knowledge-base" / "knowledge_graph.json"
DST = ROOT / "knowledge-base" / "knowledge_graph_enriched.json"
RULES = ROOT / "knowledge" / "enrichment.json"
BRAIN_SCHEMA = ROOT / "brain-schema.json"

OTHER = "other"


def canonical_relations() -> set:
    """The declared edge vocabulary (brain-schema.json's `edges`) — the same
    list the compiled brain draws from. Missing/malformed file -> empty set,
    the fail-safe default: with no declared vocabulary every edge type is
    "not canonical", which routes everything to `other` rather than silently
    accepting anything (a KG this enrichment ran hard-fails obviously instead
    of quietly canonicalizing nothing)."""
    try:
        schema = json.loads(BRAIN_SCHEMA.read_text(encoding="utf-8"))
        return {e["id"] for e in schema.get("edges", []) if isinstance(e, dict) and e.get("id")}
    except (OSError, ValueError):
        return set()


def enrich(graph: dict, rules: dict, canonical: set) -> tuple[dict, int]:
    """Pure transform: merged graph + enrichment rules + the declared relation
    vocabulary -> the enriched graph, plus the count of edges that fell to
    `other`. No file I/O — main() is the thin wrapper around this."""
    if not isinstance(graph, dict) or "nodes" not in graph:
        raise ValueError("merged graph must contain a nodes array")
    nodes = copy.deepcopy(graph["nodes"])
    edges = copy.deepcopy(graph.get("edges", graph.get("relationships", [])))
    if (not isinstance(nodes, list) or not all(isinstance(n, dict) for n in nodes)
            or not isinstance(edges, list) or not all(isinstance(e, dict) for e in edges)):
        raise ValueError("merged nodes and relationships must be arrays of objects")
    guard_records(nodes, edges)
    aliases = rules.get("aliases", {})
    roles = rules.get("roles", {})
    drop_types = set(rules.get("drop_types", []))
    relation_map = rules.get("relations", {})
    if not isinstance(relation_map, dict):
        relation_map = {}

    # Canonicalize node names, then merge nodes that collapse to the same name.
    id_map = {}      # original id -> surviving id
    by_name = {}      # canonical name -> surviving node
    out_nodes = []
    for n in nodes:
        explicit = identity(n, "node")
        if not explicit and n.get("type") in drop_types:
            continue
        name = n.get("name") if explicit else aliases.get(n.get("name"), n.get("name"))
        key = ("record", explicit) if explicit else ("name", n.get("type"), name)
        if key in by_name:
            survivor = by_name[key]
            id_map[n["id"]] = survivor["id"]
            if explicit:
                for occurrence in n.get("occurrences", []):
                    if occurrence not in survivor.setdefault("occurrences", []):
                        survivor["occurrences"].append(occurrence)
            else:
                merge_claims(survivor, n)
        else:
            n = dict(n)
            n["name"] = name
            if not explicit and name in roles:
                n.setdefault("props", {})["role"] = roles[name]
            by_name[key] = n
            id_map[n["id"]] = n["id"]
            out_nodes.append(n)

    # Remap edges to surviving node ids, canonicalize the relation, dedupe on
    # the POST-canonicalization signature (two raw verbs mapping onto the same
    # canonical relation between the same pair collapse to one edge).
    seen = {}
    out_edges = []
    other_count = 0
    for e in edges:
        explicit = identity(e, "edge")
        s = id_map.get(e.get("source"))
        t = id_map.get(e.get("target"))
        if s is None or t is None:
            if explicit:
                raise ValueError("identified relationship has a missing or filtered endpoint")
            continue
        raw_type = e.get("type")
        mapped = relation_map.get(raw_type, raw_type)
        if explicit:
            rel_type = raw_type  # source semantics require explicit adapter reconciliation
        elif mapped in canonical:
            rel_type = mapped
        else:
            rel_type = OTHER
            other_count += 1
        sig = ("record", explicit) if explicit else ("triple", s, t, rel_type)
        if not explicit:
            e = edge_claims(e)
        if sig in seen:
            if not explicit:
                merge_claims(seen[sig], e)
            continue
        e = dict(e)
        seen[sig] = e
        e["source"], e["target"] = s, t
        if not explicit and rel_type == OTHER and raw_type is not None:
            e["type"] = OTHER
            e["raw_type"] = raw_type
        else:
            e["type"] = rel_type
        out_edges.append(e)

    return {"format": "mimwell-kg/v1", "nodes": out_nodes, "edges": out_edges}, other_count


def main():
    if not SRC.exists():
        raise ValueError(f"required merged graph is missing at {SRC}; existing outputs were preserved")

    graph = json.loads(SRC.read_text())
    rules = json.loads(RULES.read_text()) if RULES.exists() else {}
    if not rules:
        print(f"No {RULES.relative_to(ROOT)}; passing the merged graph through unchanged.")

    out, other_count = enrich(graph, rules, canonical_relations())

    DST.write_text(json.dumps(out, indent=2))
    print(f"Enriched graph: {len(out['nodes'])} nodes, {len(out['edges'])} edges -> "
          f"{DST.relative_to(ROOT)}"
          + (f" ({other_count} edge(s) fell to '{OTHER}' — see raw_type; "
             "a rising count means the vocabulary is missing a relation)"
             if other_count else ""))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        print(f"enrich-kg: {exc}", file=sys.stderr)
        sys.exit(1)
