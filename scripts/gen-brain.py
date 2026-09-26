#!/usr/bin/env python3
"""Federate the template's structured JSON sources into one brain graph.

The portal already emits a dozen structured artifacts (decisions, open
questions, action items, RAID, roadmap, deliverables, user stories,
stakeholders, glossary, sessions, dependencies, the spec manifest, the
build-readiness navigator, and the knowledge graph). Each holds one slice of the
engagement. This script is the federated compiler: it reads those sources and
projects them into one uniform property graph at app/brain.json so a single
index can be searched and walked.

No new data — it only RELOCATES and RELATES what already exists, stamping every
node with the source file it came from (provenance). The brain is a compiled
artifact: never hand-edit app/brain.json, regenerate it from the sources.

Architecture — a registry of thin adapters, one per source:

    @adapter
    def decisions(root): -> (nodes, edges)

Adapters are REGISTERED, not hardcoded: adding a new source = writing one
adapter and decorating it. Each adapter opens its source file under ROOT,
tolerates a missing or empty file (returns an empty graph rather than
crashing), and emits nodes + edges in the uniform envelope. Scheduled refreshes
set BRAIN_REFRESH_STRICT=1: malformed/unreadable present sources and adapter/linker
failures then stop compilation before either output is written. Missing optional
sources remain supported; this is not a complete source inventory.

A second, smaller registry runs AFTER the adapters:

    @linker
    def references(root, nodes): -> edges

A linker emits JOIN EDGES (#60) — relations whose endpoints are nodes some other
adapter produced, so they can only be computed once the node set is resolved.
Same tolerance contract as an adapter: a missing source yields no edges.

Schema contract (schemas/brain-node.schema.json + brain-edge.schema.json):
    node: { id, kind(required), title?, text?, source?, durability?, derived?,
            status?, owner?, labels?[], data?{} }
    edge: { source(required), target(required), rel?, class?, data?{} }
Each source maps to a FIRST-CLASS `kind` from the taxonomy (Memory, Decision,
OpenQuestion, ActionItem, Session, Spec, Risk, Deliverable, Roadmap, Story,
Stakeholder, Dependency, Term, Concept) — the kind itself is the discriminator,
so no `data.subkind` is needed. Concept is reserved for derived KG nodes
(`derived=True`), which are projected from sessions rather than authored as a
source artifact. Every node carries a `durability` (durable-logic for the facts
that persist — decisions, specs, memory, terms; point-in-time for the dated
records — sessions, action items, questions, risks, roadmap, deliverables,
stories, stakeholders, dependencies); the richer per-node fields go inside
`data`, which the schema permits as a free-form object. The output is the
{meta, nodes, edges} envelope (schemas/brain-envelope.schema.json): nodes and
edges conform to brain-node/brain-edge (app/brain.json#/nodes, #/edges), and a
`meta` block self-describes the format — `meta.version` (BRAIN_VERSION) is the
authoritative schema version a stale brain is migrated against (#25, via
scripts/migrate-brain.py + `make migrate-brain`).

Determinism: meta is a fixed, derived object (version + generator + recomputed
counts — no timestamps or env), nodes are sorted by id, edges by (source,
target, rel), and the file is written with indent=1 — a stable, diff-friendly,
round-trippable shape.

Alongside the brain, main() emits a sub-kilobyte stats sidecar at
app/brain-meta.json (version, generator, node/edge totals, per-kind and
per-source counts — the source breakdown is the provenance rollup, #57). Portal
pages and gates read the sidecar instead of downloading and parsing the whole
multi-megabyte brain just to show counts, and it stays available when the brain
is served from a non-static store. Same determinism contract as the brain
itself: derived entirely from the graph, no timestamps (git history, not a
wall-clock stamp, is where "when" lives — a clock stamp would dirty the drift
gate on every run).

Run from anywhere:  python3 scripts/gen-brain.py
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
from pathlib import Path

from config import settings  # noqa: F401  (Phase-0 frozen config singleton)
import build_plan
from ontology import load_registry
from principals import principal_id
from record_sources import deliverable_identity, deliverable_source_paths, record_slug
from tracker_refresh import strict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "app", "brain.json")
META_OUT = os.path.join(ROOT, "app", "brain-meta.json")


def _join_edge_rels() -> list:
    """The declared join-edge vocabulary (#60) from brain-schema.json's
    contract.joinEdges — rels whose target crosses into another realm by
    design (implemented_in -> code) and so will never resolve to a brain node.
    Read from the real repo's brain-schema.json (a generic, non-client file,
    same as every other schema this compiler reads) regardless of which `root`
    a given adapter call was passed — synthetic test fixtures never carry
    their own copy, same as check-brain.py's twin of this helper. Missing/
    malformed file -> empty list, the fail-safe default (nothing exempted)."""
    try:
        with open(os.path.join(ROOT, "brain-schema.json"), encoding="utf-8") as stream:
            schema = json.load(stream)
        rels = schema.get("contract", {}).get("joinEdges")
        return rels if isinstance(rels, list) else []
    except (OSError, ValueError):
        return []

# Authoritative brain-envelope schema version (#25). Stamped into meta.version so
# brain.json self-describes its format; scripts/migrate-brain.py upgrades any
# brain whose meta.version is older than this. Bump it (and register a migration)
# whenever the envelope/node/edge format changes incompatibly.
BRAIN_VERSION = "1"
GENERATOR = "gen-brain"


# ----------------------------------------------------------------------------
# Adapter registry
# ----------------------------------------------------------------------------
#
# ADAPTERS holds every source this compiler can federate. Each adapter is a
# `(root) -> (nodes, edges)` callable registered by the @adapter decorator; which
# of them run for a brain is its profile's `generators.brain` declaration
# (scripts/build_plan.py, #202), so a new adapter is also named in the profile
# layer that owns its records.

ADAPTERS = []
LINKERS = []


def adapter(fn):
    """Register a source adapter. Decorated fns run in registration order."""
    ADAPTERS.append(fn)
    return fn


def linker(fn):
    """Register a join-edge linker `(root, nodes) -> edges` (#60).

    Linkers run after every adapter, over the canonicalized node set, because a
    join edge is only emittable once both of its endpoints are known to exist.
    """
    LINKERS.append(fn)
    return fn


def _load(root: str, *parts: str):
    """Missing optional sources are empty; strict refresh rejects invalid reads."""
    required = strict()
    path = os.path.join(root, *parts)

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"Duplicate source key: {key}")
            result[key] = value
        return result

    def constant(value):
        raise ValueError(f"Nonfinite source value: {value}")

    try:
        with open(path, encoding="utf-8-sig") as f:
            value = json.load(f, **({"object_pairs_hook": pairs, "parse_constant": constant} if required else {}))
        if required and not isinstance(value, dict):
            raise ValueError("Brain source must be a JSON object")
        return value
    except FileNotFoundError:
        return None  # Optional source not installed; no completeness claim.
    except (OSError, ValueError):
        if required:
            raise
        return None


def _rows(data, key: str, *, item_type=dict) -> list:
    """Optional collections may be absent; declared invalid arrays must not vanish."""
    required = strict()
    if data is None:
        return []
    if not isinstance(data, dict):
        if required:
            raise ValueError("Brain source must be a JSON object")
        return []
    rows = data.get(key, [])
    if required and (not isinstance(rows, list) or any(not isinstance(row, item_type) for row in rows)):
        raise ValueError(f"Brain source {key} must be an array of {item_type.__name__} values")
    return rows if isinstance(rows, list) else []


def _slug(text: str) -> str:
    """Stable id fragment from free text."""
    return record_slug(text)


def _node(nid, kind, *, title=None, text=None, source=None, durability=None,
          derived=None, status=None, owner=None, labels=None, data=None):
    """Build a schema-conforming node (only non-empty optional keys are set).

    Provenance/durability fields ride at the top level: `derived` marks a node
    projected FROM other nodes rather than a first-class source row; `durability`
    classifies how long the fact holds (durable-logic / point-in-time); `status`
    and `owner` are surfaced from the source row when present. `derived` is only
    set when True (a False would be noise — absence already means "not derived")."""
    n = {"id": nid, "kind": kind}
    if title:
        n["title"] = title
    if text:
        n["text"] = text
    if source:
        n["source"] = source
    if durability:
        n["durability"] = durability
    if derived:
        n["derived"] = True
    if status:
        n["status"] = status
    if owner:
        n["owner"] = owner
    if labels:
        n["labels"] = [str(x) for x in labels]
    if data:
        n["data"] = data
    return n


# Durability per kind — how long a fact of this kind holds. The durable-logic
# kinds encode standing truth (a decision, a spec, a memory, a glossary term);
# the point-in-time kinds are dated records of a moment (a session, an action,
# an open question, a risk, the roadmap-as-of-now). Concept (derived KG) is
# left durability-less — its lifetime tracks the sessions it was distilled from.
_DURABILITY = {
    "Decision": "durable-logic",
    "Spec": "durable-logic",
    "Memory": "durable-logic",
    "Term": "durable-logic",
    "Session": "point-in-time",
    "ActionItem": "point-in-time",
    "OpenQuestion": "point-in-time",
    "Risk": "point-in-time",
    "Roadmap": "point-in-time",
    "Deliverable": "point-in-time",
    "Story": "point-in-time",
    "Stakeholder": "point-in-time",
    "Dependency": "point-in-time",
    # Source-inventory kinds (#13). A data source's shape — its tables/columns —
    # is standing structural truth, so Source/Entity/Field are durable-logic.
    "Source": "durable-logic",
    "Entity": "durable-logic",
    "Field": "durable-logic",
    # Artifact-pattern kinds (#14). A tracked artifact (and the catalog that
    # indexes it) is a standing deliverable, so Artifact/Catalog are
    # durable-logic.
    "Artifact": "durable-logic",
    "Catalog": "durable-logic",
    # Register entries (W1.4): an organization is a standing fact.
    "Organization": "durable-logic",
    "Person": "durable-logic",
}


# ----------------------------------------------------------------------------
# Adapters — one per source. Every adapter but `memory` reads a structured JSON
# artifact; `memory` crawls the hand-written memory markdown (issues #3, #9).
# ----------------------------------------------------------------------------


@adapter
def decisions(root):
    src = "app/decisions.json"
    nodes, edges = [], []
    for i, d in enumerate(_rows(_load(root, "app", "decisions.json"), "decisions")):
        if not isinstance(d, dict) or not d.get("title"):
            continue
        nid = "decision:" + _slug(d["title"])
        nodes.append(_node(
            nid, "Decision",
            title=d.get("title"),
            text=d.get("decision"),
            source=src,
            durability=_DURABILITY.get("Decision"),
            labels=d.get("labels"),
            data={k: d[k] for k in ("date", "session") if d.get(k)},
        ))
        if d.get("session"):
            edges.append({"source": nid, "target": "session:" + str(d["session"]),
                          "rel": "decided_in"})
    return nodes, edges


@adapter
def open_questions(root):
    src = "app/open-questions.json"
    nodes, edges = [], []
    for d in _rows(_load(root, "app", "open-questions.json"), "questions"):
        if not isinstance(d, dict) or not d.get("question"):
            continue
        nid = "question:" + _slug(d["question"])
        nodes.append(_node(
            nid, "OpenQuestion",
            title=d.get("question"),
            text=d.get("context"),
            source=src,
            durability=_DURABILITY.get("OpenQuestion"),
            status=d.get("status"),
            labels=d.get("labels"),
            data={k: d[k] for k in ("date", "session") if d.get(k)},
        ))
        if d.get("session"):
            edges.append({"source": nid, "target": "session:" + str(d["session"]),
                          "rel": "raised_in"})
    return nodes, edges


@adapter
def action_items(root):
    src = "app/action-items.json"
    nodes, edges = [], []
    for i, d in enumerate(_rows(_load(root, "app", "action-items.json"), "items")):
        if not isinstance(d, dict) or not d.get("text"):
            continue
        nid = "action:%d:%s" % (i, _slug(d["text"])[:40])
        nodes.append(_node(
            nid, "ActionItem",
            text=d.get("text"),
            source=src,
            durability=_DURABILITY.get("ActionItem"),
            owner=d.get("owner"),
            labels=d.get("labels"),
            data={k: d[k] for k in ("date", "session", "session_title")
                  if d.get(k)},
        ))
        if d.get("session"):
            edges.append({"source": nid, "target": "session:" + str(d["session"]),
                          "rel": "raised_in"})
    return nodes, edges


@adapter
def sessions(root):
    src = "app/sessions.json"
    nodes = []
    for d in _rows(_load(root, "app", "sessions.json"), "sessions"):
        if not isinstance(d, dict) or not d.get("id"):
            continue
        nodes.append(_node(
            "session:" + str(d["id"]), "Session",
            title=d.get("title"),
            text=d.get("summary"),
            source=src,
            durability=_DURABILITY.get("Session"),
            labels=d.get("labels"),
            data={k: d[k] for k in ("date", "duration_min") if d.get(k)},
        ))
    return nodes, []


@adapter
def specs(root):
    """Plan manifest -> Spec/Story nodes with the authored plan edges.

    The spec tree is the top-down decomposition (phase > epic > feature >
    story, see specs/STORY-STANDARD.md). A leaf `type: story` row becomes a
    first-class `Story` node; the containers above it (phase/epic/feature,
    declared by a `00-*.md`) stay `Spec` workstream nodes. Authored edges ride
    through verbatim: `child_of` (tree) and `depends_on` (story frontmatter).
    `references:` frontmatter -> `derives_from` provenance edges are the
    `record_links` LINKER's job, not this adapter's — resolving a reference to
    a decision vs. an open-question (#55) needs the settled node set, which an
    adapter does not have yet (see `record_links`)."""
    src = "specs/manifest.json"
    nodes, edges = [], []
    for d in _rows(_load(root, "specs", "manifest.json"), "items"):
        if not isinstance(d, dict) or not d.get("id"):
            continue
        nid = "spec:" + str(d["id"])
        kind = "Story" if d.get("type") == "story" else "Spec"
        nodes.append(_node(
            nid, kind,
            title=d.get("title"),
            source=src,
            durability=_DURABILITY.get(kind),
            status=d.get("status"),
            labels=d.get("labels"),
            data={k: d[k] for k in ("type", "priority", "estimate", "path")
                  if d.get(k)},
        ))
        parent = d.get("parent")
        if parent:
            edges.append({"source": nid, "target": "spec:" + str(parent),
                          "rel": "child_of"})
        for dep in (d.get("depends_on") or []):
            if dep:
                edges.append({"source": nid, "target": "spec:" + str(dep),
                              "rel": "depends_on"})
        for target in (d.get("implemented_in") or []):
            if target:
                # #60 slice 2: a join edge into the code realm. The target is a
                # realm-qualified address (repo-relative path, optionally
                # #symbol), NEVER a brain node id — the code realm is never
                # compiled into the brain, so this edge's target intentionally
                # will not resolve against `ids` the way every other edge's
                # does. check-brain.py's INTEGRITY gate exempts join-edge rels
                # (brain-schema.json's `contract.joinEdges`) from that check.
                edges.append({"source": nid, "target": str(target),
                              "rel": "implemented_in"})
    return nodes, edges


@adapter
def knowledge_graph(root):
    """conflict-kg/v1 nodes -> Concept; KG edges carried through verbatim.

    Multi-valued provenance (#57, item 1 — scoped to Concept nodes, the one
    kind that already carries this data): build-kg.py already aggregates
    which recording sessions mention each entity into a `sessions` list
    (merge-kg.py tags every occurrence with its recording folder;
    build-kg.py dedupes+sorts them). That data reaches here unused — the
    generic `extra` passthrough below already carries it into
    `data.sessions` as bare folder names, but never as brain-schema-shaped
    addresses a consumer (or a future evidence-list viewer) could resolve.
    `data["sources"]` adds that: the same list, addressed as `session:<id>`
    — which resolves directly, since sessions() below stamps a session
    node's id from that exact same folder name. Purely additive: the
    single `source` stamp every node already carries is unchanged, and a
    KG node with no `sessions` data (or none at all) gets no `sources`
    field, not an empty one."""
    src = "app/knowledge_graph.json"
    data = _load(root, "app", "knowledge_graph.json")
    nodes, edges = [], []
    for d in _rows(data, "nodes"):
        if not isinstance(d, dict) or not d.get("id"):
            continue
        nid = "kg:" + str(d["id"])
        extra = {k: v for k, v in d.items()
                 if k not in ("id", "label", "title", "name", "type")}
        extra["subkind"] = "kg"
        if d.get("type"):
            extra.setdefault("kg_type", d["type"])
        sessions_field = d.get("sessions")
        if isinstance(sessions_field, list) and sessions_field:
            extra["sources"] = sorted({"session:" + str(s) for s in sessions_field if s})
        nodes.append(_node(
            nid, "Concept",
            title=d.get("label") or d.get("title") or d.get("name"),
            source=src,
            derived=True,
            data=extra,
        ))
    for e in _rows(data, "edges"):
        if not isinstance(e, dict):
            continue
        s = e.get("source") or e.get("from") or e.get("src")
        t = e.get("target") or e.get("to") or e.get("dst")
        if not s or not t:
            continue
        edge = {"source": "kg:" + str(s), "target": "kg:" + str(t)}
        rel = e.get("rel") or e.get("type") or e.get("label")
        if rel:
            edge["rel"] = str(rel)
        claims = {k: v for k, v in e.items()
                  if k not in ("source", "target", "from", "to", "src", "dst", "rel", "type", "label")}
        if claims:
            edge["data"] = claims
        edges.append(edge)
    return nodes, edges


@adapter
def glossary(root):
    src = "app/glossary.json"
    nodes = []
    for d in _rows(_load(root, "app", "glossary.json"), "terms"):
        if not isinstance(d, dict) or not d.get("term"):
            continue
        nodes.append(_node(
            "term:" + _slug(d["term"]), "Term",
            title=d.get("term"),
            text=d.get("definition"),
            source=src,
            durability=_DURABILITY.get("Term"),
            data={k: d[k] for k in ("aliases", "related") if d.get(k)},
        ))
    return nodes, []


@adapter
def raid(root):
    """Risks/Assumptions/Issues/Dependencies -> Risk; the R/A/I/D classification
    (the source `type`) is preserved as data.category."""
    src = "app/raid.json"
    nodes = []
    for i, d in enumerate(_rows(_load(root, "app", "raid.json"), "items")):
        if not isinstance(d, dict) or not d.get("title"):
            continue
        data = {k: d[k] for k in ("severity", "mitigation") if d.get(k)}
        if d.get("type"):
            data["category"] = d["type"]
        nodes.append(_node(
            "raid:%d:%s" % (i, _slug(d["title"])[:40]), "Risk",
            title=d.get("title"),
            text=d.get("detail"),
            source=src,
            durability=_DURABILITY.get("Risk"),
            status=d.get("status"),
            owner=d.get("owner"),
            labels=d.get("labels"),
            data=data,
        ))
    return nodes, []


@adapter
def roadmap(root):
    src = "app/roadmap.json"
    nodes = []
    for d in _rows(_load(root, "app", "roadmap.json"), "tracks"):
        if not isinstance(d, dict) or not d.get("product"):
            continue
        nodes.append(_node(
            "track:" + _slug(d["product"]), "Roadmap",
            title=d.get("product"),
            text=d.get("summary") or d.get("tagline"),
            source=src,
            durability=_DURABILITY.get("Roadmap"),
            data={k: d[k] for k in ("tagline",) if d.get(k)},
        ))
    return nodes, []


@adapter
def deliverables(root):
    src = "app/deliverables.json"
    nodes, edges = [], []
    for d in _rows(_load(root, "app", "deliverables.json"), "deliverables"):
        if not isinstance(d, dict) or not (d.get("title") or d.get("id")):
            continue
        nid = deliverable_identity(d)
        data = {k: d[k] for k in ("phase", "category", "type", "date") if d.get(k)}
        paths = deliverable_source_paths(d)
        if paths:
            data["sourcePaths"] = paths
        nodes.append(_node(
            nid, "Deliverable",
            title=d.get("title"),
            text=d.get("summary"),
            source=src,
            durability=_DURABILITY.get("Deliverable"),
            status=d.get("status"),
            owner=d.get("owner"),
            labels=d.get("tags"),
            data=data,
        ))
        for st in (d.get("stories") or []):
            edges.append({"source": nid, "target": "story:" + str(st),
                          "rel": "relates_to"})
        for ss in (d.get("sessions") or []):
            edges.append({"source": nid, "target": "session:" + str(ss),
                          "rel": "relates_to"})
        for sp in (d.get("specs") or []):
            edges.append({"source": nid, "target": "spec:" + str(sp),
                          "rel": "relates_to"})
    return nodes, edges


@adapter
def user_stories(root):
    src = "app/user-stories.json"
    nodes, edges = [], []
    for d in _rows(_load(root, "app", "user-stories.json"), "stories"):
        if not isinstance(d, dict) or not (d.get("id") or d.get("title")):
            continue
        sid = d.get("id") or _slug(d.get("title"))
        nid = "story:" + str(sid)
        nodes.append(_node(
            nid, "Story",
            title=d.get("title"),
            text=d.get("i_want"),
            source=src,
            durability=_DURABILITY.get("Story"),
            status=d.get("status"),
            labels=d.get("labels"),
            data={k: d[k] for k in ("as_a", "i_want", "so_that", "acceptance",
                                    "epic") if d.get(k)},
        ))
        if d.get("deliverable"):
            edges.append({"source": nid,
                          "target": "deliverable:" + str(d["deliverable"]),
                          "rel": "relates_to"})
        for ss in (d.get("sessions") or []):
            edges.append({"source": nid, "target": "session:" + str(ss),
                          "rel": "relates_to"})
    return nodes, edges


@adapter
def people(root):
    """Person register (app/people.json) -> Person nodes `person:<slug>` (#212).

    Registered before `stakeholders` on purpose: both use the `person:<slug>`
    convention, and when a stakeholder row names a register entry the register
    node is the one identity (first writer wins in canonicalize). Only the bound
    principal is compiled; the host-side identities (Access emails, consumer
    actors) stay in the register, read at the host boundary by principals.py."""
    src = "app/people.json"
    nodes = []
    for d in _rows(_load(root, "app", "people.json"), "people"):
        if not isinstance(d, dict) or not d.get("name"):
            continue
        data = {k: d[k] for k in ("aliases", "scope_id", "provenance") if d.get(k)}
        principal = d.get("principal")
        if isinstance(principal, dict) and principal.get("issuer") and principal.get("subject"):
            data["principal"] = principal_id(principal["issuer"], principal["subject"])
        nodes.append(_node(
            "person:" + _slug(d["name"]), "Person",
            title=d.get("name"),
            text=d.get("notes"),
            source=src,
            durability=_DURABILITY.get("Person"),
            labels=d.get("labels"),
            data=data or None,
        ))
    return nodes, []


@adapter
def stakeholders(root):
    src = "app/stakeholders.json"
    nodes = []
    for d in _rows(_load(root, "app", "stakeholders.json"), "people"):
        if not isinstance(d, dict) or not d.get("name"):
            continue
        nodes.append(_node(
            "person:" + _slug(d["name"]), "Stakeholder",
            title=d.get("name"),
            text=d.get("notes"),
            source=src,
            durability=_DURABILITY.get("Stakeholder"),
            data={k: d[k] for k in ("role", "org", "email") if d.get(k)},
        ))
    return nodes, []


@adapter
def organizations(root):
    """Organization register (app/organizations.json) -> Organization nodes,
    plus `affiliated_with` edges from stakeholders whose `org` names an entry
    (by name or alias). Buildout W1.4: the register is the scope-level entity
    table that lets two brains name the same company without merging data —
    identity across brains resolves to these nodes via app/equivalences.json.

    A stakeholder `org` matching no register entry emits nothing (same
    tolerance as ownership_links: a free-text org is not a compile failure)."""
    src = "app/organizations.json"
    nodes, edges = [], []
    by_name = {}
    for d in _rows(_load(root, "app", "organizations.json"), "organizations"):
        if not isinstance(d, dict) or not d.get("name"):
            continue
        oid = "org:" + _slug(d["name"])
        data = {k: d[k] for k in ("kind", "domain", "scope_id", "aliases") if d.get(k)}
        nodes.append(_node(
            oid, "Organization",
            title=d.get("name"),
            text=d.get("notes"),
            source=src,
            durability="durable-logic",
            labels=d.get("labels"),
            data=data or None,
        ))
        by_name[_slug(d["name"])] = oid
        for alias in (d.get("aliases") or []):
            by_name.setdefault(_slug(alias), oid)
    for d in _rows(_load(root, "app", "stakeholders.json"), "people"):
        if not isinstance(d, dict) or not d.get("name") or not d.get("org"):
            continue
        oid = by_name.get(_slug(d["org"]))
        if oid:
            edges.append({"source": "person:" + _slug(d["name"]), "target": oid,
                          "rel": "affiliated_with"})
    return nodes, edges


@adapter
def equivalences(root):
    """Accepted identity across brains (app/equivalences.json) -> same_as /
    facet_of / aligns_with edges carrying confidence, asserter and evidence in
    `data`. Buildout W1.4: this file is the CANON record of what a curator
    accepted from app/proposals.json. No nodes are emitted — an equivalence
    whose endpoints do not both exist is dropped by canonicalize(), exactly
    like any other dangling edge, so a stale acceptance never breaks
    integrity. Cross-brain endpoints (`<repo>/<kind>:<id>`) resolve only in a
    federated brain; in a single-repo compile they are held until
    aggregate-brains folds the other side in."""
    edges = []
    for d in _rows(_load(root, "app", "equivalences.json"), "equivalences"):
        if not isinstance(d, dict) or not d.get("source") or not d.get("target"):
            continue
        rel = d.get("rel") or "same_as"
        if rel not in ("same_as", "facet_of", "aligns_with"):
            continue
        data = {k: d[k] for k in ("confidence", "asserted_by", "evidence", "date") if d.get(k) is not None}
        edge = {"source": str(d["source"]), "target": str(d["target"]), "rel": rel, "class": "semantic"}
        if data:
            edge["data"] = data
        edges.append(edge)
    return [], edges


@adapter
def dependencies(root):
    """Plan dependency graph (app/dependencies.json) -> Concept nodes + edges."""
    src = "app/dependencies.json"
    data = _load(root, "app", "dependencies.json")
    nodes, edges = [], []
    for d in _rows(data, "nodes"):
        if not isinstance(d, dict) or not d.get("id"):
            continue
        nodes.append(_node(
            "dep:" + str(d["id"]), "Dependency",
            title=d.get("title"),
            source=src,
            durability=_DURABILITY.get("Dependency"),
            status=d.get("status"),
            data={k: d[k] for k in ("type",) if d.get(k)},
        ))
    for e in _rows(data, "edges"):
        if not isinstance(e, dict) or not e.get("from") or not e.get("to"):
            continue
        edges.append({"source": "dep:" + str(e["from"]),
                      "target": "dep:" + str(e["to"]),
                      "rel": "depends_on"})
    return nodes, edges


@adapter
def source_inventory(root):
    """Source inventory (app/sources.json, from scripts/ingest_sources.py) ->
    Source / Entity / Field nodes with the structural + provenance edges (#13).

    The pluggable source-ingestion module inventories every data source
    (source -> entity -> field, each with status/owner/provenance). This adapter
    projects that inventory into the brain: a `Source` node per source, an
    `Entity` per table/resource, a `Field` per column/property — wired with
    `has_entity`/`has_field` STRUCTURAL edges (source contains entity contains
    field) and `sourced_by` PROVENANCE edges back to the extractor input each
    node was read from (generalizing an earlier field-catalog generator's resolved_to ->
    edge idea). Empty inventory ({sources:[]}) -> no nodes, so the empty-state
    brain is unchanged."""
    src = "app/sources.json"
    data = _load(root, "app", "sources.json")
    nodes, edges = [], []
    for s in _rows(data, "sources"):
        if not isinstance(s, dict) or not s.get("id"):
            continue
        sid = "source:" + _slug(s["id"])
        nodes.append(_node(
            sid, "Source",
            title=s.get("title") or s.get("id"),
            source=src,
            durability=_DURABILITY.get("Source"),
            status=s.get("status"),
            owner=s.get("owner"),
            data={k: s[k] for k in ("kind", "provenance") if s.get(k)},
        ))
        for ent in (s.get("entities") or []):
            if not isinstance(ent, dict) or not ent.get("name"):
                continue
            eid = "%s:entity:%s" % (sid, _slug(ent["name"]))
            nodes.append(_node(
                eid, "Entity",
                title=ent.get("title") or ent.get("name"),
                source=src,
                durability=_DURABILITY.get("Entity"),
                status=ent.get("status"),
                owner=ent.get("owner"),
                data={"name": ent["name"]},
            ))
            edges.append({"source": sid, "target": eid, "rel": "has_entity",
                          "class": "structural"})
            for fld in (ent.get("fields") or []):
                if not isinstance(fld, dict) or not fld.get("name"):
                    continue
                fid = "%s:field:%s" % (eid, _slug(fld["name"]))
                fdata = {k: fld[k] for k in ("name", "type", "nullable", "is_pk")
                         if fld.get(k) is not None}
                nodes.append(_node(
                    fid, "Field",
                    title=fld.get("name"),
                    source=src,
                    durability=_DURABILITY.get("Field"),
                    status=fld.get("status"),
                    data=fdata,
                ))
                edges.append({"source": eid, "target": fid, "rel": "has_field",
                              "class": "structural"})
    return nodes, edges


@adapter
def artifacts(root):
    """Artifact catalog (analysis/artifacts/catalog.json) -> Catalog / Artifact
    nodes with the catalog membership + session-provenance edges (#14).

    The artifact pattern (docs/primitives/artifact-pattern.md) is the generic
    escape hatch for a bespoke deliverable — a golden record, an identity
    strategy, a timeline, an integration catalog — that does not fit a
    first-class authoring tool: a catalog stub + canonical data JSON + an
    index.html render. This adapter projects the manifest into the brain: one
    `Catalog` node for the manifest, one `Artifact` node per stub, wired with
    `in_catalog` edges (artifact belongs to the catalog) and `relates_to`
    PROVENANCE edges to each session the artifact was distilled from
    (generalizing the earlier stubs' `source_sessions`). A reference to an absent
    session emits no edge, so the empty-state stays connected. An empty manifest
    ({artifacts:[]}) -> no Artifact nodes, so the empty-state brain is
    unchanged."""
    src = "analysis/artifacts/catalog.json"
    data = _load(root, "analysis", "artifacts", "catalog.json")
    rows = _rows(data, "artifacts")
    if not rows:
        return [], []
    nodes, edges = [], []
    nodes.append(_node(
        "catalog:artifacts", "Catalog",
        title="Artifacts",
        text="Manifest of standalone analysis artifacts.",
        source=src,
        durability=_DURABILITY.get("Catalog"),
        data={"count": len(rows)},
    ))
    for a in rows:
        if not isinstance(a, dict) or not a.get("id"):
            continue
        nid = "artifact:" + _slug(a["id"])
        nodes.append(_node(
            nid, "Artifact",
            title=a.get("title") or a.get("id"),
            text=a.get("description"),
            source=src,
            durability=_DURABILITY.get("Artifact"),
            data={k: a[k] for k in ("id", "icon", "href", "updated", "type",
                                    "source_sessions") if a.get(k)},
        ))
        edges.append({"source": nid, "target": "catalog:artifacts",
                      "rel": "in_catalog"})
        for ss in (a.get("source_sessions") or []):
            if ss:
                edges.append({"source": nid, "target": "session:" + str(ss),
                              "rel": "relates_to"})
    return nodes, edges


# Build-readiness navigator source + the two relations its projection contributes
# (#23). `blocked_by` is the UNSATISFIED subset of `depends_on` — a strictly
# stronger statement than the authored dependency edge, since it is scored
# against current status — and `critical_path` marks the consecutive links of the
# heaviest chain, so the path is walkable rather than only readable on a page.
BUILD_READINESS = ("app", "build-readiness.json")
BLOCKED_BY_REL = "blocked_by"
CRITICAL_PATH_REL = "critical_path"


@adapter
def build_readiness(root):
    """Build-readiness navigator (app/build-readiness.json) -> next-action
    `ActionItem` nodes + `blocked_by` / `critical_path` work-graph edges (#23).

    scripts/gen-build-readiness.py already DERIVES the answer to "what do I build
    next" (unblocked set, estimate-weighted critical path, per-story readiness
    with blocking reasons, ranked next actions), but it lands in a portal-only
    artifact. Without this adapter the compiled brain carries the plan and its
    `depends_on` edges yet none of the scoring, so an agent asking the brain
    "what should I work on?" / "what is blocking X?" gets nothing.

    Modeling — the kinds are the taxonomy's, nothing is invented:
      next action   a ranked recommendation is a dispatchable unit of work, which
                    is exactly the declared `action-item` kind
                    (brain-schema.json) -> `ActionItem`. `derived` marks it as
                    computed from the plan rather than authored, and it still
                    carries the artifact as `source` (provenance is mandatory;
                    check-brain.py resolves the path).
      readiness     a readiness SCORE is not an entity — it is a computed
                    attribute of a spec/story node the brain already holds. No
                    declared kind models it, and projecting one node per story
                    would duplicate the whole plan, so the scoring rides as edges
                    over the existing nodes instead:
                      spec:X -blocked_by->    spec:B   one per unsatisfied dep
                      spec:A -critical_path-> spec:B   consecutive chain links
                    Both point the way the work does (dependent -> dependency),
                    matching the `depends_on` edges the specs adapter emits.

    Tolerance: a missing, empty, or malformed artifact yields ([], []) — the
    empty-state template and the pinned golden fixture (neither has a
    build-readiness.json) are unaffected. Every id is projected onto the spec
    address space without checking it exists; canonicalize() drops an edge whose
    endpoints are not both real nodes, so a readiness file naming a story the
    manifest no longer carries can never break the integrity gate. Ordering is
    the artifact's own (already fully sorted/ranked by its generator), so the
    projection is deterministic.
    """
    src = "app/build-readiness.json"
    data = _load(root, *BUILD_READINESS)
    if not isinstance(data, dict):
        return [], []
    nodes, edges = [], []

    # Ranked recommendations -> ActionItem. `rank` is the artifact's own order
    # (1 = pick this up first), so the brain preserves the ranking a page shows.
    for rank, a in enumerate(_rows(data, "next_actions"), start=1):
        if not isinstance(a, dict) or not a.get("id"):
            continue
        sid = str(a["id"])
        reasons = [str(r) for r in (a.get("reasons") or []) if r]
        item = {"story": sid, "rank": rank,
                "on_critical_path": bool(a.get("on_critical_path"))}
        for k in ("priority", "estimate"):
            if a.get(k):
                item[k] = a[k]
        if a.get("points") is not None:  # 0 points is a real value, not absence
            item["points"] = a["points"]
        item["reasons"] = reasons
        nodes.append(_node(
            "next-action:" + sid, "ActionItem",
            title=a.get("title") or sid,
            text="Ready to build" + (": " + "; ".join(reasons) if reasons else ""),
            source=src,
            durability=_DURABILITY.get("ActionItem"),
            derived=True,
            status="ready",
            data=item,
        ))
        edges.append({"source": "next-action:" + sid, "target": "spec:" + sid,
                      "rel": "relates_to"})

    # Per-story scoring -> the "why is this blocked" edges.
    for r in _rows(data, "readiness"):
        if not isinstance(r, dict) or not r.get("id"):
            continue
        rid = "spec:" + str(r["id"])
        blockers = r.get("blocked_by")
        for b in (blockers if isinstance(blockers, list) else []):
            bid = b.get("id") if isinstance(b, dict) else b
            if bid:
                edges.append({"source": rid, "target": "spec:" + str(bid),
                              "rel": BLOCKED_BY_REL})

    # Critical path -> consecutive links of the chain (top-down: the dependent
    # first, its dependencies after).
    cp = data.get("critical_path")
    chain = cp.get("chain") if isinstance(cp, dict) else None
    chain_ids = [str(c["id"]) for c in chain
                 if isinstance(c, dict) and c.get("id")] if isinstance(chain, list) else []
    for a_id, b_id in zip(chain_ids, chain_ids[1:]):
        if a_id != b_id:
            edges.append({"source": "spec:" + a_id, "target": "spec:" + b_id,
                          "rel": CRITICAL_PATH_REL})

    return nodes, edges


# ----------------------------------------------------------------------------
# Memory — the one markdown-crawl adapter (issues #3, #9)
# ----------------------------------------------------------------------------
#
# Everything above federates a generated JSON artifact. Memory is the exception:
# it is hand-written prose that never had a structured surface, so without a
# crawl the durable facts a human curates stay invisible to the brain (they were
# only ever indexed, separately, into app/knowledge-pack.json).

# The memory directory is CONFIG-DRIVEN, not baked: it is whichever
# knowledge.sources entry in client.config.json is named `memory`. That covers
# both layouts the template supports — memory nested under knowledge/ and memory
# at the repo root — and an instance that renames or moves it only edits config.
# The fallbacks apply when a root has no config at all (a partial install, or the
# pinned golden fixture, which has no memory dir either way).
MEMORY_DIR_NAME = "memory"
MEMORY_FALLBACK_DIRS = (("knowledge/memory", False), ("memory", False))

# Category vocabulary for typed memory (#9). Declared here so the taxonomy has
# one home; NOT enforced — an unknown category rides through as authored rather
# than being dropped, because the adapter must never lose a memory file over a
# vocabulary quibble.
MEMORY_TYPES = ("reference", "decision", "question", "process")

# Typed frontmatter is OPTIONAL. A file that declares `metadata.type` (or a
# top-level `type`) records that category; a file with no frontmatter at all is
# still indexed under this default, so an engagement migrates its memory
# incrementally instead of having to convert every file before the adapter is
# useful.
MEMORY_DEFAULT_TYPE = "reference"

# Same cap the knowledge pack puts on a summary: the brain stores a handle on a
# memory file, not its body — the file itself is the durable copy.
MEMORY_TEXT_CHARS = 300

_H1_RE = re.compile(r"^#\s+(.+)$", re.M)


def _read_text(path: str) -> str:
    """Read a markdown file. Missing/unreadable -> "" (never raises)."""
    try:
        # utf-8-sig for the same reason _load uses it: a BOM must not blank a file.
        with open(path, encoding="utf-8-sig", errors="replace") as f:
            return f.read()
    except OSError:
        if strict():
            raise
        return ""


def _frontmatter(text: str) -> tuple[dict, str]:
    """Split a markdown doc into (frontmatter fields, body).

    A deliberately tiny line parser rather than a YAML dependency — the pipeline
    is stdlib-only. It reads top-level `key: value` scalars plus ONE level of
    nesting (`metadata:` followed by indented keys), which is the whole memory
    convention. Anything richer is ignored rather than fatal: a malformed
    frontmatter block must never be able to sink the compile or drop the file.
    """
    if not text.startswith("---"):
        return {}, text
    lines = text.splitlines()
    end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if end is None:
        return {}, text  # unterminated block: treat the whole file as body
    fields: dict = {}
    block = None  # the nested key currently being filled, e.g. "metadata"
    for raw in lines[1:end]:
        if not raw.strip() or raw.lstrip().startswith("#") or ":" not in raw:
            continue
        key, _, value = raw.partition(":")
        name, value = key.strip(), value.strip().strip("\"'")
        if raw[:1].isspace():  # indented -> belongs to the open block
            if block:
                fields.setdefault(block, {})[name] = value
            continue
        block = None if value else name
        if value:
            fields[name] = value
    return fields, "\n".join(lines[end + 1:])


def _first_prose(body: str) -> str:
    """The first line of real prose — skipping headings, tables, quotes, code,
    and HTML comments. The fallback summary when frontmatter declares none."""
    for line in body.splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "<!--", "|", "```", ">", "---")):
            return line
    return ""


def _knowledge_cfg(root: str) -> dict:
    """The `knowledge` block of client.config.json under `root` (or {}).

    Read from the root the adapter was handed, not from the settings singleton:
    an adapter is a pure `(root) -> graph` function, so it must resolve its
    sources relative to that root (tests and the golden fixture pass their own).
    """
    cfg = _load(root, "client.config.json")
    knowledge = cfg.get("knowledge") if isinstance(cfg, dict) else None
    return knowledge if isinstance(knowledge, dict) else {}


def _memory_dirs(knowledge: dict, root: str) -> list[tuple[str, bool]]:
    """Resolve the memory source dir(s) under `root` as (rel path, recursive).

    Config first (knowledge.sources entries whose final path segment is
    `memory`), falling back to the conventional locations when the config is
    absent or declares none. Only directories that actually exist are returned,
    so a root without memory yields an empty list and the adapter is a no-op.
    """
    declared: list[tuple[str, bool]] = []
    for s in _rows(knowledge, "sources"):
        path = s.get("path") if isinstance(s, dict) else None
        if isinstance(path, str) and path.strip("/").split("/")[-1] == MEMORY_DIR_NAME:
            declared.append((path.strip("/"), bool(s.get("recursive"))))
    out = []
    for rel, recursive in (declared or list(MEMORY_FALLBACK_DIRS)):
        if os.path.isdir(os.path.join(root, *rel.split("/"))):
            out.append((rel, recursive))
    return out


def _memory_files(root: str, rel_dir: str, recursive: bool) -> list[str]:
    """Every markdown file under a memory dir, as repo-relative posix paths, in
    sorted order — the deterministic crawl the node ordering depends on."""
    base = os.path.join(root, *rel_dir.split("/"))
    found = []
    if recursive:
        def onerror(error):
            if strict():
                raise error

        for dirpath, dirnames, filenames in os.walk(base, onerror=onerror):
            dirnames.sort()
            for name in sorted(filenames):
                found.append(os.path.join(dirpath, name))
    else:
        for name in sorted(os.listdir(base)):
            found.append(os.path.join(base, name))
    rels = []
    for full in found:
        if not full.lower().endswith(".md") or not os.path.isfile(full):
            continue
        rels.append(os.path.relpath(full, root).replace(os.sep, "/"))
    return sorted(rels)


@adapter
def memory(root):
    """Hand-written memory markdown -> `Memory` nodes (#3 · B2, #9).

    The `Memory` kind is durable-logic: the curated always-true facts of the
    engagement. One node per file, so the brain gains a searchable, walkable
    handle on each memory doc while the markdown stays the editable original.

    Contract:
      id          `memory:<repo-relative path minus .md>` — derived from the
                  path, so it is stable across runs and collision-free by
                  construction (two files cannot share a path).
      title       frontmatter `title`/`name`, else the first H1, else the
                  filename — the same precedence gen-knowledge-pack.py uses, so
                  a doc reads identically in the brain and in the search index.
      text        frontmatter `description`, else the first prose line.
      source      the file's own path — provenance is per-file and mandatory
                  (scripts/check-brain.py resolves it against ROOT).
      data.type   the memory category (#9), from `metadata.type` or a top-level
                  `type`, defaulting to MEMORY_DEFAULT_TYPE. Typed frontmatter
                  is honored but OPTIONAL: an untyped file is still indexed, so
                  nothing has to be migrated for the adapter to be useful.

    Files the knowledge config skips (knowledge.skipNames — README.md and the
    agent primers) are skipped here too, so the brain and the search index cover
    exactly the same corpus. No memory dir -> no nodes, so the empty-state and
    the pinned golden fixture are unaffected. No edges: a memory file relates to
    the rest of the graph through its prose, not through an authored link.

    `knowledge.excludeFromBrain` (optional list of repo-relative globs) keeps a
    file OUT of the compiled brain while leaving it in place for whatever else
    reads it. This matters because app/brain.json is a SERVED artifact: on a
    host that scopes some documents to a subset of readers, compiling those
    documents' titles and summaries into the brain would publish them to
    everyone. An engagement running per-document access control should point
    this at the same paths it protects (until the access seam is part of the
    engine itself). Empty by default — nothing is excluded unless asked.
    """
    knowledge = _knowledge_cfg(root)
    skip = {str(n).lower() for n in _rows(knowledge, "skipNames", item_type=str)}
    excluded = [str(g) for g in _rows(knowledge, "excludeFromBrain", item_type=str)]
    nodes = []
    for rel_dir, recursive in _memory_dirs(knowledge, root):
        for rel in _memory_files(root, rel_dir, recursive):
            name = rel.rsplit("/", 1)[-1]
            if name.lower() in skip:
                continue
            if any(fnmatch.fnmatch(rel, g) for g in excluded):
                continue
            fields, body = _frontmatter(_read_text(os.path.join(root, *rel.split("/"))))
            meta = fields.get("metadata") if isinstance(fields.get("metadata"), dict) else {}
            title = fields.get("title") or fields.get("name")
            if not title:
                h1 = _H1_RE.search(body)
                title = h1.group(1).strip() if h1 else name
            text = fields.get("description") or _first_prose(body)
            nodes.append(_node(
                "memory:" + rel[:-3], "Memory",
                title=title,
                text=text[:MEMORY_TEXT_CHARS],
                source=rel,
                durability=_DURABILITY.get("Memory"),
                status=fields.get("status"),
                owner=fields.get("owner"),
                data={"type": meta.get("type") or fields.get("type")
                      or MEMORY_DEFAULT_TYPE, "path": rel},
            ))
    return nodes, []


# ----------------------------------------------------------------------------
# Linkers — join edges over the resolved node set (#60)
# ----------------------------------------------------------------------------

# The committed doc link graph (#49). gen-knowledge-pack.py walks the knowledge
# markdowns and records, under `backlinks`, every INCOMING doc-to-doc link
# ({target path: [referrer path, ...]}) from [[wikilinks]] and relative markdown
# links. It is the only place the engine knows which document cites which.
KNOWLEDGE_PACK = ("app", "knowledge-pack.json")

# The schema's declared doc-to-doc relation (brain-schema.json#/edges).
REFERENCES_REL = "references"


def _path_index(nodes: list) -> dict:
    """repo-relative doc path -> brain node id, over the PATH-IDENTIFIED nodes.

    A node is path-identified when it carries `data.path` — the convention the
    contract calls the `path` id rule (brain-schema.json#/contract/idConventions):
    the file IS the identity. Memory notes and spec nodes qualify today; any
    future markdown adapter that stamps `data.path` joins the index for free,
    with no edit here. Nodes are walked in id order and the first writer wins, so
    two nodes claiming one path resolve deterministically.
    """
    index: dict = {}
    for n in sorted(nodes, key=lambda n: n["id"]):
        data = n.get("data")
        path = data.get("path") if isinstance(data, dict) else None
        if isinstance(path, str) and path:
            index.setdefault(path, n["id"])
    return index


@linker
def references(root, nodes):
    """Doc link graph (#49) -> first-class `references` edges (#60, slice 1).

    The link graph already ships in app/knowledge-pack.json, but it is keyed by
    file path, so a brain traversal cannot walk doc to doc. This linker projects
    it onto the brain's own addresses: for each backlink `target <- referrer`, an
    edge `referrer -> target` with rel `references`, oriented so the edge points
    the way the prose does (the citing doc references the cited one).

    Rules:
      - BOTH endpoints must resolve to a real brain node via `data.path`. A link
        to a document that has no node (a knowledge doc, an unindexed file) emits
        nothing rather than a dangling edge — check-brain.py's INTEGRITY gate
        rejects edges to non-existent nodes, and a compiled brain must never be
        the thing that breaks it.
      - `knowledge.excludeFromBrain` is honored on BOTH ends. The exclusion
        exists because app/brain.json is SERVED: a document held out of the brain
        must not reappear as the endpoint of an edge, which would leak both its
        existence and its path.
      - No pack (a partial install, or the pinned golden fixture) -> no edges, so
        the compile never depends on the pack having been generated first.

    Ordering and dedup are canonicalize()'s job — several links between the same
    pair collapse to one edge.
    """
    pack = _load(root, *KNOWLEDGE_PACK)
    backlinks = pack.get("backlinks") if isinstance(pack, dict) else None
    if not isinstance(backlinks, dict):
        return []
    excluded = [str(g) for g in _rows(_knowledge_cfg(root), "excludeFromBrain", item_type=str)]
    index = _path_index(nodes)

    def node_for(path):
        if not isinstance(path, str) or any(fnmatch.fnmatch(path, g) for g in excluded):
            return None
        return index.get(path)

    edges = []
    for target, referrers in backlinks.items():
        tid = node_for(target)
        if not tid or not isinstance(referrers, list):
            continue
        for ref in referrers:
            sid = node_for(ref)
            if sid and sid != tid:  # two paths on one node is not a self-link
                edges.append({"source": sid, "target": tid, "rel": REFERENCES_REL})
    return edges


DERIVES_FROM_REL = "derives_from"


@linker
def record_links(root, nodes):
    """A spec's `references:` frontmatter -> `derives_from` provenance edges
    (#55 slice-1 prerequisite: generalizes what used to be hardcoded into the
    `specs` adapter as decision-only).

    A LINKER, not part of the `specs` adapter, for the same reason `references`
    is one: resolving a citation needs the settled node set. `references:
    ["Pick Alpha"]` on a story must become an edge to whichever record actually
    exists under that title — a Decision or an OpenQuestion — not a blind
    `decision:<slug>` guess that canonicalize() silently drops when nothing by
    that slug exists (which is exactly what happened before this: a story
    citing an open question by title compiled a dangling edge that vanished
    with no signal). Decision wins on a same-slug collision (rare — titles are
    free text) since it was the original, documented behavior.

    Tolerance: a reference matching neither emits nothing (same posture as
    `references()` and the prior hardcoded version) — a citation to a record
    that got renamed or removed is not a compile failure.
    """
    specs_data = _rows(_load(root, "specs", "manifest.json"), "items")
    if not specs_data:
        return []
    ids = {n["id"] for n in nodes}
    edges = []
    for d in specs_data:
        if not isinstance(d, dict) or not d.get("id"):
            continue
        nid = "spec:" + str(d["id"])
        for ref in (d.get("references") or []):
            if not ref:
                continue
            decision_id = "decision:" + _slug(ref)
            question_id = "question:" + _slug(ref)
            if decision_id in ids:
                edges.append({"source": nid, "target": decision_id, "rel": DERIVES_FROM_REL})
            elif question_id in ids:
                edges.append({"source": nid, "target": question_id, "rel": DERIVES_FROM_REL})
    return edges


OWNS_REL = "owns"


@linker
def ownership_links(root, nodes):
    """A decision's or story's `owner:` field -> an `owns` edge from the
    owning stakeholder (#55 slice-1 prerequisite: brain-schema.json already
    declares `owns`, but nothing populated it before this — no schema
    carried an owner-name field to emit it from).

    A LINKER, same reason `record_links`/`references` are: resolving
    "does this owner name match a real Stakeholder" needs the settled node
    set. `owner: "Samira Okonkwo"` becomes `person:samira-okonkwo -> owns ->
    <the decision/story>` only when that stakeholder actually exists as a
    node — matching `stakeholders()`'s own id convention (`"person:" +
    _slug(name)`) exactly, not a guessed prefix.

    Tolerance: an owner name matching no stakeholder emits nothing — a typo
    or a departed stakeholder is not a compile failure, same posture every
    other linker in this file holds to.
    """
    ids = {n["id"] for n in nodes}
    edges = []

    for d in _rows(_load(root, "app", "decisions.json"), "decisions"):
        if not isinstance(d, dict) or not d.get("title") or not d.get("owner"):
            continue
        owner_id = "person:" + _slug(d["owner"])
        if owner_id in ids:
            edges.append({"source": owner_id, "target": "decision:" + _slug(d["title"]),
                          "rel": OWNS_REL})

    for d in _rows(_load(root, "specs", "manifest.json"), "items"):
        if not isinstance(d, dict) or not d.get("id") or not d.get("owner"):
            continue
        owner_id = "person:" + _slug(d["owner"])
        if owner_id in ids:
            edges.append({"source": owner_id, "target": "spec:" + str(d["id"]),
                          "rel": OWNS_REL})

    return edges


# ----------------------------------------------------------------------------
# Compile
# ----------------------------------------------------------------------------


def _meta(nodes: list, edges: list) -> dict:
    """The self-describing envelope header. DETERMINISTIC — version + generator
    are fixed constants and counts are recomputed from the graph, so no timestamp
    or env leaks in (the golden + drift gates compare bytes every run)."""
    return {
        "version": BRAIN_VERSION,
        "generator": GENERATOR,
        "counts": {"nodes": len(nodes), "edges": len(edges)},
    }


def canonicalize(nodes: list, edges: list, join_relations=None) -> tuple[list, list]:
    """The single deterministic ordering contract for a brain graph: nodes
    first-writer-wins by id then sorted; edges sorted by (source, target, rel),
    deduped on that key, and any edge whose SOURCE does not resolve to a node
    dropped (a dangling reference never breaks integrity — same posture as
    aggregate-brains.py). The TARGET is held to the same rule with one
    declared exception: a join edge (#60, brain-schema.json's
    contract.joinEdges — e.g. `implemented_in`) crosses into a realm that is
    never compiled into the brain, so its target will never resolve to a node
    by design; that is the feature, not a dangling reference, and is kept
    rather than dropped. check-brain.py's RECONCILE gate asserts this exact
    shape, so build() AND migrate-brain._restamp() both route through here to
    guarantee they can never drift."""
    nodes_by_id = {}
    for n in nodes:
        nodes_by_id.setdefault(n["id"], n)  # first writer wins, stable
    out_nodes = sorted(nodes_by_id.values(), key=lambda n: n["id"])

    join_edge_rels = set(_join_edge_rels() if join_relations is None else join_relations)
    seen = set()
    uniq_edges = []
    for e in sorted(edges, key=lambda e: (e["source"], e["target"], e.get("rel", ""))):
        if e["source"] not in nodes_by_id:
            continue
        if e["target"] not in nodes_by_id and e.get("rel") not in join_edge_rels:
            continue
        key = (e["source"], e["target"], e.get("rel", ""))
        if key in seen:
            continue
        seen.add(key)
        uniq_edges.append(e)
    return out_nodes, uniq_edges


def sidecar(graph: dict) -> dict:
    """The stats sidecar (app/brain-meta.json) derived from a compiled graph.

    Extends the envelope's meta with per-kind and per-source count rollups (the
    source breakdown is the provenance view, #57) so portal pages can render
    brain statistics from a sub-kilobyte fetch instead of the full brain.
    DETERMINISTIC like _meta(): everything is recomputed from the graph, keys
    are sorted, and there is no timestamp — the sidecar is drift-gated alongside
    the brain, so a wall-clock stamp would make every regeneration dirty.
    """
    by_kind: dict[str, int] = {}
    by_source: dict[str, int] = {}
    for n in graph["nodes"]:
        by_kind[n["kind"]] = by_kind.get(n["kind"], 0) + 1
        src = n.get("source") or "(none)"
        by_source[src] = by_source.get(src, 0) + 1
    return {
        "version": BRAIN_VERSION,
        "generator": GENERATOR,
        "counts": {
            "nodes": len(graph["nodes"]),
            "edges": len(graph["edges"]),
            "by_kind": dict(sorted(by_kind.items())),
            "by_source": dict(sorted(by_source.items())),
        },
    }


def projections(root: str, authority) -> tuple[list, list]:
    """The projections adapter (#228): an adopted store authority compiles from
    its receipted delivered projections, never by re-reading source JSON. Only
    `projections: committed` has files to ingest; `live` commits nothing delivered,
    since the context service reads the authority at request time (#229), so the
    compiled brain holds only regenerable sources."""
    mode = (authority or {}).get("projections")
    if mode == "live":
        return [], []
    if mode != "committed":
        raise ValueError(
            f"record authority adopted with projections={mode!r}: gen-brain compiles only "
            "`projections: committed` (receipted app/projections/<consumer>.json); `projections: live` "
            "is read from the authority at request time. See docs/design/adr-authority-per-brain-kind.md")
    from projection_receipts import load
    nodes, edges = [], []
    for consumer, payload, _receipt in load(root, authority["binding"]):
        source = f"app/projections/{consumer}.json"
        nodes.extend({"source": source, **node} for node in payload["graph"]["nodes"])
        edges.extend(payload["graph"]["edges"])
    return nodes, edges


def _scope_address(declared: dict):
    """The compiling brain's scope address (`<level>:<id>`), resolved as
    gen-manifest reports it: config scope, id defaulting to client.slug. Stamped
    on every compiled node (buildout W1.2, #204); None when no id resolves."""
    scope = declared.get("scope") or {}
    sid = scope.get("id") or (declared.get("client") or {}).get("slug") or ""
    return f"{scope.get('level') or 'project'}:{sid}" if sid else None


def build(root: str) -> dict:
    """Run every registered adapter, then every linker, into one deterministic
    graph. Two passes because a linker's edges are only emittable against a
    resolved node set: canonicalize() first to settle the nodes, run the linkers
    over them, then canonicalize again (it is idempotent) to order and dedup the
    combined edge list."""
    declared = _load(root, "client.config.json") or {}
    nodes = []
    edges = []
    if "authority" in (declared.get("brain") or {}):
        # Delivered projections come first so first-writer-wins in canonicalize()
        # makes the authority, not a stale source JSON, own every record it holds.
        nodes, edges = projections(root, declared["brain"]["authority"])
    registry = load_registry(root)
    skipped = build_plan.skipped_adapters(Path(root))
    for fn in ADAPTERS:
        if fn.__name__ in skipped:
            continue
        try:
            ns, es = fn(root)
        except Exception:
            if registry is not None or strict():
                raise
            # An adapter must never sink the whole build — skip a bad source.
            ns, es = [], []
        nodes.extend(ns)
        edges.extend(es)

    from source_adapters import compile_selected
    nodes.extend(compile_selected(root, registry, frontmatter=_frontmatter, first_prose=_first_prose))

    if registry is not None:
        nodes.extend(registry.compile_extensions(Path(root)))
        if 'decision.revision' in registry.kinds:
            from decision_lineage import compile_edges as compile_decision_edges
            edges.extend(compile_decision_edges(root, registry, nodes))
        registry.validate_records(nodes, edges)
    join_relations = registry.joins if registry is not None else None
    nodes, edges = canonicalize(nodes, edges, join_relations)
    for fn in LINKERS:
        try:
            edges.extend(fn(root, nodes))
        except Exception:
            if registry is not None or strict():
                raise
            # Same posture as an adapter: a bad join source loses its edges, not
            # the build.
            pass

    if registry is not None:
        registry.validate_records(nodes, edges)
    nodes, uniq_edges = canonicalize(nodes, edges, join_relations)
    scope = _scope_address(declared)
    if scope:
        for n in nodes:
            n.setdefault("scope", scope)
    from evidence import compile_evidence
    compile_evidence(root, nodes, uniq_edges)
    graph = {"meta": _meta(nodes, uniq_edges), "nodes": nodes, "edges": uniq_edges}
    if registry is not None:
        graph["meta"]["ontology"] = registry.binding()
        registry.validate_graph(graph, require_binding=True)
    return graph


def main():
    graph = build(ROOT)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(graph, f, indent=1)
    print(f"Wrote {OUT}: {len(graph['nodes'])} node(s), "
          f"{len(graph['edges'])} edge(s) from {len(ADAPTERS)} adapter(s) "
          f"+ {len(LINKERS)} linker(s)")
    meta = sidecar(graph)
    with open(META_OUT, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=1)
    print(f"Wrote {META_OUT}: stats sidecar "
          f"({len(meta['counts']['by_kind'])} kind(s), "
          f"{len(meta['counts']['by_source'])} source(s))")


if __name__ == "__main__":
    main()
