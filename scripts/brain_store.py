#!/usr/bin/env python3
"""Store-agnostic accessor over the compiled brain — one interface, two backends.

Record authority is independent of this compiled-graph encoding. Adopted
structured source records use knowledge_store.py; this module remains a projection
reader and cannot authorize canonical mutations.

Consumers (the kb skill #8, the brain viewer #5, the integrity gates #6, the
KG-traversal parity tests #22) must not care WHICH store is canonical. They
import this module and call a uniform API; the backend is selected once from
`settings.brain.store` (client.config.json -> "json" by default):

    from brain_store import get_node, search, neighbors, path, subgraph

    get_node(id)              -> node | None
    search(text)              -> [node]
    neighbors(id, dir, type?) -> [node]      dir in {"in", "out", "both"}
    path(a, b)                -> [id] | None  (deterministic shortest path)
    subgraph(ids)             -> {"nodes": [...], "edges": [...]}
    hybrid_search(text)       -> [node]      (#27 — lexical + vector + graph,
                                              additive; gated by semantic_search)
    stats()                   -> meta dict    (app/brain-meta.json sidecar —
                                              counts without loading the brain)

DETERMINISTIC ORDERING is part of the contract. Every multi-result is stably
sorted by node id (edges in subgraph by (source, target, rel); `path` returns the
deterministic shortest path — BFS that breaks ties by exploring neighbours in
sorted-id order). This exactness is what lets the #22 parity tests assert that
the JSON and SQLite backends return byte-identical results for the same input,
and what makes downstream output diff cleanly in git.

HYBRID RETRIEVAL (#27, additive/opt-in). `search()` is unchanged — a pure
lexical substring match with the hard byte-identical JSON<->SQLite parity contract
(#22). `hybrid_search()` is a NEW, separate verb that fuses three signals and is
gated behind features.semantic_search:
  1. lexical    — the existing search() hits (exact-substring recall);
  2. vector     — cosine similarity over the embedding index that embed-brain.py
                  builds (app/brain.vec.json), surfacing nodes that are ABOUT the
                  query even with no shared token;
  3. graph      — one hop of graph-expansion off the top lexical+vector hits, so a
                  highly-relevant node's neighbours are pulled into the result.
Scores from the three signals are combined and results are stably sorted by
(-score, id) — deterministic tie-breaks, same as every other verb. When
features.semantic_search is OFF, or the index is missing/empty, hybrid_search
falls back to exactly search()'s lexical result, so the default contract is
untouched and #22 stays green.

Backends (pluggable, selected from settings.brain.store):
  - "json"  : load app/brain.json once, build in-memory out/in adjacency maps.
              Zero-setup, fine for small/medium brains. neighbors/path/subgraph
              walk the in-memory maps.
  - "sqlite": open app/brain.db; get_node is an indexed lookup; search is a
              deterministic substring match (LIKE over the precomputed
              `search_text` column) that returns byte-identical results to the
              JSON backend; neighbors/path run as RECURSIVE-CTE traversals so a
              large brain is never fully loaded into memory.
  - "d1"    : the EDGE store (#37, feature-gated by features.brain_d1). Same
              interface, run AT THE EDGE inside worker.js against the env.DB D1
              binding; the SQL is defined once here (_D1_SQL) and the worker
              mirrors it, so D1 answers byte-identically to json/sqlite. In a
              Python process there is no D1 binding, so backend() reads the
              JSON brain the D1 projection is exported from; _D1Backend is used
              only with an injected D1-shaped handle. Only the worker serves D1,
              and only when brain.store=='d1' AND features.brain_d1.
              Do NOT route around the accessor — edge/D1 queries go THROUGH it.

Schema (schemas/brain-node.schema.json + brain-edge.schema.json): a node is
{id, kind, title?, text?, source?, labels?, data?}; an edge is
{source, target, rel?}. Adjacency is built on the edge `source`/`target`/`rel`
field names actually emitted by gen-brain.py (#3) — never the issue-body
src/dst/type names.

Empty-state safe: with no nodes every method returns empty/None cleanly.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections import deque
from typing import Any

from config import settings
from sql_dialect import D1Dialect, SQLiteDialect

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BRAIN_JSON = os.path.join(ROOT, "app", "brain.json")
BRAIN_META = os.path.join(ROOT, "app", "brain-meta.json")
BRAIN_DB = os.path.join(ROOT, "app", "brain.db")

_DIRS = ("in", "out", "both")

# The fields search() matches over, in order. This is the SINGLE definition of
# the search haystack: both backends (and the SQLite `search_text` column that
# brain-sqlite.py precomputes) build from this exact list so search() returns
# byte-identical results regardless of backend. search() semantics are a hard
# parity contract (#4 audit / #22 parity test): a case-insensitive SUBSTRING
# match across these fields, results stably sorted by id.
_SEARCH_FIELDS = ("id", "title", "text", "kind")


def edge_sort_key(edge: dict) -> tuple:
    """Order complete relationship rows without collapsing distinct evidence.

    Endpoint/relation triples are traversal coordinates, not record identities.
    The full payload breaks ties deterministically; exact repeated rows survive.
    """
    return (edge["source"], edge["target"], edge.get("rel") or "",
            json.dumps(edge, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False))


def search_haystack(node: dict) -> str:
    """The lowercased text search() matches a query substring against. Joining
    `_SEARCH_FIELDS` with a space and lowercasing is the WHOLE contract — keep
    this the only place it is built so the JSON backend, the SQLite backend, and
    the precomputed `search_text` column can never drift apart."""
    return " ".join(str(node.get(k, "")) for k in _SEARCH_FIELDS).lower()


def search_fingerprint(node: dict) -> str:
    """Bind a vector to the exact normalized text used by both retrieval paths."""
    return hashlib.sha256(search_haystack(node).encode("utf-8")).hexdigest()


# ----------------------------------------------------------------------------
# Backend interface
# ----------------------------------------------------------------------------


class _Backend:
    """Uniform read API. Subclasses implement the five accessor verbs."""

    def get_node(self, nid: str) -> dict | None:
        raise NotImplementedError

    def search(self, text: str) -> list[dict]:
        raise NotImplementedError

    def neighbors(self, nid: str, direction: str = "both",
                  type: str | None = None) -> list[dict]:
        raise NotImplementedError

    def path(self, a: str, b: str) -> list[str] | None:
        raise NotImplementedError

    def subgraph(self, ids: list[str]) -> dict:
        raise NotImplementedError


# ----------------------------------------------------------------------------
# JSON backend — load once, in-memory adjacency maps
# ----------------------------------------------------------------------------


class _JsonBackend(_Backend):
    def __init__(self, path: str = BRAIN_JSON):
        self._nodes: dict[str, dict] = {}
        self._out: dict[str, list[dict]] = {}
        self._in: dict[str, list[dict]] = {}
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = {"nodes": [], "edges": []}
        for n in data.get("nodes") or []:
            if isinstance(n, dict) and n.get("id"):
                self._nodes[n["id"]] = n
        for e in data.get("edges") or []:
            if not isinstance(e, dict):
                continue
            s, t = e.get("source"), e.get("target")
            if not s or not t:
                continue
            self._out.setdefault(s, []).append(e)
            self._in.setdefault(t, []).append(e)

    def get_node(self, nid: str) -> dict | None:
        return self._nodes.get(nid)

    def search(self, text: str) -> list[dict]:
        q = (text or "").strip().lower()
        if not q:
            return []
        hits = [n for n in self._nodes.values() if q in search_haystack(n)]
        return sorted(hits, key=lambda n: n["id"])

    def neighbors(self, nid: str, direction: str = "both",
                  type: str | None = None) -> list[dict]:
        if direction not in _DIRS:
            raise ValueError(f"dir must be one of {_DIRS}, got {direction!r}")
        out_ids, in_ids = set(), set()
        if direction in ("out", "both"):
            for e in self._out.get(nid, []):
                if type is None or e.get("rel") == type:
                    out_ids.add(e["target"])
        if direction in ("in", "both"):
            for e in self._in.get(nid, []):
                if type is None or e.get("rel") == type:
                    in_ids.add(e["source"])
        ids = out_ids | in_ids
        nodes = [self._nodes[i] for i in ids if i in self._nodes]
        return sorted(nodes, key=lambda n: n["id"])

    def path(self, a: str, b: str) -> list[str] | None:
        if a not in self._nodes or b not in self._nodes:
            return None
        if a == b:
            return [a]
        # BFS over undirected adjacency; deterministic via sorted-id expansion.
        prev: dict[str, str] = {a: a}
        q = deque([a])
        while q:
            cur = q.popleft()
            nbrs = set()
            for e in self._out.get(cur, []):
                nbrs.add(e["target"])
            for e in self._in.get(cur, []):
                nbrs.add(e["source"])
            for nxt in sorted(nbrs):
                if nxt in prev or nxt not in self._nodes:
                    continue
                prev[nxt] = cur
                if nxt == b:
                    return _trace(prev, a, b)
                q.append(nxt)
        return None

    def subgraph(self, ids: list[str]) -> dict:
        want = set(ids)
        nodes = sorted((self._nodes[i] for i in want if i in self._nodes),
                       key=lambda n: n["id"])
        edges = []
        for s in want:
            for e in self._out.get(s, []):
                if e["target"] in want:
                    edges.append(e)
        edges.sort(key=edge_sort_key)
        return {"nodes": nodes, "edges": edges}


def _trace(prev: dict[str, str], a: str, b: str) -> list[str]:
    out = [b]
    while out[-1] != a:
        out.append(prev[out[-1]])
    out.reverse()
    return out


# ----------------------------------------------------------------------------
# SQLite backend — indexed lookups + recursive-CTE traversals
# ----------------------------------------------------------------------------


class _SqliteBackend(_Backend):
    def __init__(self, path: str = BRAIN_DB, dialect: SQLiteDialect | None = None):
        # Read-only; tolerant of a missing db (empty result set, never raises).
        # Pass an authority's dialect to read a projection in the same database
        # over the authority's own connection.
        self._dialect = dialect or SQLiteDialect.open(path, authority=False)
        self._conn = self._dialect.db

    def _node_from_row(self, row: sqlite3.Row | None) -> dict | None:
        if row is None:
            return None
        return json.loads(row["json"])

    def get_node(self, nid: str) -> dict | None:
        try:
            cur = self._dialect.execute("SELECT json FROM node WHERE id = ?", (nid,))
        except sqlite3.Error:
            return None
        return self._node_from_row(cur.fetchone())

    def search(self, text: str) -> list[dict]:
        # Hard parity contract: byte-identical to the JSON backend. We match the
        # SAME lowercased substring (search_haystack) against the precomputed,
        # already-lowercased `search_text` column with LIKE '%q%'. The query is
        # lowercased here and its LIKE metacharacters (% _ \) are escaped so the
        # match is a literal substring — exactly Python's `in`. ORDER BY id gives
        # the same stable-by-id ordering. (The node_fts table is retained for
        # future use but is deliberately NOT on the search() path: raw FTS5
        # exact-token matching does not agree with substring search.)
        q = (text or "").strip().lower()
        if not q:
            return []
        pattern = "%" + _like_escape(q) + "%"
        try:
            cur = self._dialect.execute(
                "SELECT json FROM node WHERE search_text LIKE ? ESCAPE '\\' "
                "ORDER BY id", (pattern,))
            rows = cur.fetchall()
        except sqlite3.Error:
            return []
        return [json.loads(r["json"]) for r in rows]

    def neighbors(self, nid: str, direction: str = "both",
                  type: str | None = None) -> list[dict]:
        if direction not in _DIRS:
            raise ValueError(f"dir must be one of {_DIRS}, got {direction!r}")
        ids: set[str] = set()
        type_clause = " AND type = ?" if type is not None else ""
        params_out = (nid,) + ((type,) if type is not None else ())
        if direction in ("out", "both"):
            cur = self._dialect.execute(
                "SELECT dst AS nb FROM edge WHERE src = ?" + type_clause, params_out)
            ids.update(r["nb"] for r in cur.fetchall())
        if direction in ("in", "both"):
            cur = self._dialect.execute(
                "SELECT src AS nb FROM edge WHERE dst = ?" + type_clause, params_out)
            ids.update(r["nb"] for r in cur.fetchall())
        if not ids:
            return []
        placeholders = self._dialect.placeholders(len(ids))
        cur = self._dialect.execute(
            f"SELECT json FROM node WHERE id IN ({placeholders}) ORDER BY id",
            tuple(ids))
        return [json.loads(r["json"]) for r in cur.fetchall()]

    def path(self, a: str, b: str) -> list[str] | None:
        if self.get_node(a) is None or self.get_node(b) is None:
            return None
        if a == b:
            return [a]
        # BFS over the undirected adjacency, one frontier query per node —
        # sorted-id expansion mirrors the JSON backend exactly, so the first
        # arrival at `b` is the same deterministic shortest path. (This
        # replaced a recursive-CTE simple-path enumeration that went
        # exponential once federation made the graph hub-dense — the anchor
        # nodes create diamonds, and enumerating every simple path through
        # them never terminates in practice.)
        prev: dict[str, str] = {a: a}
        q = deque([a])
        try:
            while q:
                cur_id = q.popleft()
                rows = self._dialect.execute(
                    "SELECT dst AS n FROM edge WHERE src = ? "
                    "UNION SELECT src AS n FROM edge WHERE dst = ?",
                    (cur_id, cur_id)).fetchall()
                for nxt in sorted(r["n"] for r in rows):
                    if nxt in prev or self.get_node(nxt) is None:
                        continue
                    prev[nxt] = cur_id
                    if nxt == b:
                        return _trace(prev, a, b)
                    q.append(nxt)
        except sqlite3.Error:
            return None
        return None

    def subgraph(self, ids: list[str]) -> dict:
        want = list(dict.fromkeys(ids))
        if not want:
            return {"nodes": [], "edges": []}
        ph = self._dialect.placeholders(len(want))
        cur = self._dialect.execute(
            f"SELECT json FROM node WHERE id IN ({ph}) ORDER BY id", tuple(want))
        nodes = [json.loads(r["json"]) for r in cur.fetchall()]
        cur = self._dialect.execute(
            f"SELECT json FROM edge WHERE src IN ({ph}) AND dst IN ({ph}) "
            "ORDER BY src, dst, coalesce(type,'')", tuple(want) + tuple(want))
        edges = [json.loads(r["json"]) for r in cur.fetchall()]
        edges.sort(key=edge_sort_key)
        return {"nodes": nodes, "edges": edges}


def _like_escape(text: str) -> str:
    """Escape SQL LIKE metacharacters so the pattern matches them literally
    (a query of "50%" or "a_b" is a substring, not a wildcard) — paired with
    `ESCAPE '\\'` in the LIKE clause. This makes LIKE behave exactly like
    Python's substring `in`, which is what search() parity requires."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# ----------------------------------------------------------------------------
# D1 backend — edge store (#37), feature-gated by features.brain_d1
# ----------------------------------------------------------------------------
#
# D1 serving happens AT THE EDGE inside the Cloudflare Worker (worker.js), where
# the worker holds the live `env.DB` D1 binding and runs the SQL below against
# it. This module is the Python side of the SAME store-agnostic accessor; in a
# Python process there is no D1 binding, so `_D1Backend()` has no handle and
# every verb raises a pointed error rather than silently mis-serving.
#
# The two halves do NOT drift because the SQL is defined ONCE here, as a
# string-keyed contract (_D1_SQL), and the worker mirrors these exact statements
# — get_node/search are indexed SELECTs (search() uses the precomputed,
# already-lowercased `search_text` column with LIKE '%q%', so D1 returns
# byte-identical results to the JSON/SQLite backends; node_fts/FTS5 is NOT on the
# search path, matching _SqliteBackend); neighbors/path/subgraph mirror the
# _SqliteBackend recursive-CTE traversals. The deterministic ordering contract
# (nodes by id; edges by src,dst,coalesce(type,'')) is baked into the ORDER BYs.
#
# A D1 binding is a JS object; a Python caller that DOES want to drive D1 (e.g. a
# future test harness over a `wrangler d1 execute` shim) can inject any handle
# exposing `.prepare(sql).bind(*params).all()` -> {"results": [ {col: val} ]} —
# the same shape Cloudflare's D1 client returns. Absent a handle this is inert.

# The single source of the D1 read SQL. worker.js mirrors these statements verbatim
# against env.DB so the edge store answers identically to the local stores. The
# `path` query is the recursive-CTE BFS from _SqliteBackend (US x1f trail), kept
# in lockstep so a path() at the edge returns the same deterministic shortest path.
_D1_SQL = {
    "get_node": "SELECT json FROM node WHERE id = ?",
    "search": (
        "SELECT json FROM node WHERE search_text LIKE ? ESCAPE '\\' ORDER BY id"
    ),
    "neighbors_out": "SELECT dst AS nb FROM edge WHERE src = ?{type}",
    "neighbors_in": "SELECT src AS nb FROM edge WHERE dst = ?{type}",
    "nodes_in": "SELECT json FROM node WHERE id IN ({ph}) ORDER BY id",
    "path_frontier": (
        "SELECT dst AS n FROM edge WHERE src = ? "
        "UNION SELECT src AS n FROM edge WHERE dst = ?"
    ),
    "subgraph_edges": (
        "SELECT json FROM edge WHERE src IN ({ph}) AND dst IN ({ph}) "
        "ORDER BY src, dst, coalesce(type,'')"
    ),
}


class _D1Backend(_Backend):
    """The store-agnostic accessor over a Cloudflare D1 binding. The real queries
    run at the edge in worker.js against env.DB; in-process Python has no binding,
    so the verbs raise a pointed error unless a D1-shaped handle is injected.

    A handle (if supplied) must expose Cloudflare's D1 client shape:
    `handle.prepare(sql).bind(*params).all()` returning {"results": [{col: val}]}.
    """

    _MSG = ("d1 serving happens at the edge (worker.js); the in-process Python d1 "
            "backend has no D1 binding. Reads in Python use store=json|sqlite; the "
            "edge serves d1 via env.DB. (#37)")

    def __init__(self, handle: Any = None):
        self._dialect = None if handle is None else D1Dialect(handle)

    def _require(self) -> D1Dialect:
        if self._dialect is None:
            raise NotImplementedError(self._MSG)
        return self._dialect

    def _rows(self, sql: str, params: tuple) -> list[dict]:
        return self._require().rows(sql, params)

    def get_node(self, nid: str) -> dict | None:
        rows = self._rows(_D1_SQL["get_node"], (nid,))
        return json.loads(rows[0]["json"]) if rows else None

    def search(self, text: str) -> list[dict]:
        q = (text or "").strip().lower()
        if not q:
            return []
        pattern = "%" + _like_escape(q) + "%"
        return [json.loads(r["json"]) for r in self._rows(_D1_SQL["search"], (pattern,))]

    def neighbors(self, nid: str, direction: str = "both",
                  type: str | None = None) -> list[dict]:
        if direction not in _DIRS:
            raise ValueError(f"dir must be one of {_DIRS}, got {direction!r}")
        self._require()
        type_clause = " AND type = ?" if type is not None else ""
        params = (nid,) + ((type,) if type is not None else ())
        ids: set[str] = set()
        if direction in ("out", "both"):
            sql = _D1_SQL["neighbors_out"].format(type=type_clause)
            ids.update(r["nb"] for r in self._rows(sql, params))
        if direction in ("in", "both"):
            sql = _D1_SQL["neighbors_in"].format(type=type_clause)
            ids.update(r["nb"] for r in self._rows(sql, params))
        if not ids:
            return []
        ph = D1Dialect.placeholders(len(ids))
        sql = _D1_SQL["nodes_in"].format(ph=ph)
        return [json.loads(r["json"]) for r in self._rows(sql, tuple(ids))]

    def path(self, a: str, b: str) -> list[str] | None:
        if self.get_node(a) is None or self.get_node(b) is None:
            return None
        if a == b:
            return [a]
        # Same BFS as the JSON/SQLite backends (sorted-id expansion, one
        # frontier query per visited node) — bounded by node count, unlike the
        # simple-path CTE it replaced, which went exponential on hub-dense
        # federated graphs.
        prev: dict[str, str] = {a: a}
        q = deque([a])
        while q:
            cur_id = q.popleft()
            rows = self._rows(_D1_SQL["path_frontier"], (cur_id, cur_id))
            for nxt in sorted(r["n"] for r in rows):
                if nxt in prev or self.get_node(nxt) is None:
                    continue
                prev[nxt] = cur_id
                if nxt == b:
                    return _trace(prev, a, b)
                q.append(nxt)
        return None

    def subgraph(self, ids: list[str]) -> dict:
        want = list(dict.fromkeys(ids))
        if not want:
            return {"nodes": [], "edges": []}
        ph = D1Dialect.placeholders(len(want))
        nodes = [json.loads(r["json"])
                 for r in self._rows(_D1_SQL["nodes_in"].format(ph=ph), tuple(want))]
        sql = _D1_SQL["subgraph_edges"].format(ph=ph)
        edges = [json.loads(r["json"])
                 for r in self._rows(sql, tuple(want) + tuple(want))]
        edges.sort(key=edge_sort_key)
        return {"nodes": nodes, "edges": edges}


# ----------------------------------------------------------------------------
# Backend selection — one place, driven by settings.brain.store
# ----------------------------------------------------------------------------

_BACKENDS = {"json": _JsonBackend, "sqlite": _SqliteBackend}

_backend: _Backend | None = None


def _store() -> str:
    """Canonical store from config. 'both' is reconciled (JSON==SQLite) by
    brain-sqlite.py sync/check, so reads default to the JSON backend. 'd1' is a
    serving mode (#37): the worker reads the D1 projection of app/brain.json at
    the edge, and in-process Python (no D1 binding) reads that same JSON, with the
    flag on or off, so local gates and generators keep working."""
    store = settings.brain.store
    if store in ("both", "d1"):
        return "json"
    return store


def backend() -> _Backend:
    """The selected backend singleton (built lazily on first access)."""
    global _backend
    if _backend is None:
        store = _store()
        cls = _BACKENDS.get(store, _JsonBackend)
        _backend = cls()
    return _backend


def reset() -> None:
    """Drop the cached backend (TESTS ONLY — e.g. after config.reinit() or a
    rebuild of the underlying store)."""
    global _backend, _vec_index, _embed_mod
    _backend = None
    _vec_index = None
    _embed_mod = None


# ----------------------------------------------------------------------------
# Module-level accessor API (the contract consumers import)
# ----------------------------------------------------------------------------


def get_node(id: str) -> dict | None:
    return backend().get_node(id)


def search(text: str) -> list[dict]:
    return backend().search(text)


def neighbors(id: str, dir: str = "both", type: str | None = None) -> list[dict]:
    return backend().neighbors(id, dir, type)


def path(a: str, b: str) -> list[str] | None:
    return backend().path(a, b)


def subgraph(ids: list[str]) -> dict:
    return backend().subgraph(list(ids))


def stats(meta_path: str = BRAIN_META, brain_path: str = BRAIN_JSON) -> dict:
    """Compiled-brain stats from the app/brain-meta.json sidecar (gen-brain.py).

    Store-agnostic on purpose: the sidecar is a sub-kilobyte static file, so
    consumers (portal counts, gates) read totals and per-kind/per-source
    rollups without loading the multi-megabyte brain — and it keeps answering
    when the canonical store is one (sqlite/d1, #37) where app/brain.json is
    not the served artifact. Falls back to brain.json's own meta block when the
    sidecar is absent (an older compile); {} when neither is readable
    (empty-state safe, matching the rest of the accessor). The path parameters
    exist for tests only — production callers use the defaults.
    """
    for path in (meta_path, brain_path):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        meta = data if path == meta_path else data.get("meta")
        if isinstance(meta, dict) and isinstance(meta.get("counts"), dict):
            return meta
    return {}


# ----------------------------------------------------------------------------
# Hybrid retrieval (#27) — lexical + vector + graph-expansion, opt-in
# ----------------------------------------------------------------------------
#
# Additive and backend-agnostic: it composes the existing accessor verbs
# (search/get_node/neighbors) plus the vector index that embed-brain.py builds,
# so it works identically over the JSON and SQLite backends and never touches the
# pure-lexical search() parity contract. Gated by features.semantic_search; with
# the flag off (or no index) it returns exactly search()'s lexical result.

import math  # noqa: E402  (kept local to the hybrid section)

# Weights for fusing the three signals into one score. Lexical (exact substring)
# is weighted highest as the precision anchor; vector adds semantic recall; a
# graph-neighbour gets a small constant credit so expansion never outranks a
# direct hit. Deterministic: identical inputs -> identical scores -> identical
# (-score, id) ordering.
_W_LEXICAL = 1.0
_W_VECTOR = 0.6
_W_GRAPH = 0.25

# How many top seeds get graph-expanded. Bounded so expansion stays cheap and the
# result never balloons; deterministic because seeds are pre-sorted by (-score, id).
_GRAPH_SEED_LIMIT = 10

# Lazy, cached vector index (embed-brain.py's app/brain.vec.json). None until
# first hybrid call; (idx_or_False) so a missing index is cached as a miss.
_vec_index: Any = None

# embed-brain.py is hyphenated, so it cannot be imported by name. Load it once by
# file path (the same importlib trick the tests use for the dashed CLI scripts).
_embed_mod: Any = None


def _embed_module() -> Any:
    """Import scripts/embed-brain.py by file path (cached), or None if absent.
    Keeps brain_store dependency-free when semantic search is unused."""
    global _embed_mod
    if _embed_mod is None:
        import importlib.util
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "embed-brain.py")
        try:
            spec = importlib.util.spec_from_file_location("embed_brain", path)
            mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
        except (OSError, ImportError, AttributeError):
            _embed_mod = False
        else:
            _embed_mod = mod
    return _embed_mod or None


def _semantic_on() -> bool:
    return bool(settings.features.semantic_search)


def _index() -> dict | None:
    """Load the embedding index once (lazily); cache a miss as False so an absent
    index is not re-read every call. Empty/missing -> lexical-only fallback."""
    global _vec_index
    if _vec_index is None:
        mod = _embed_module()
        _vec_index = (mod.load_index() or False) if mod else False
    return _vec_index or None


def _query_vector(text: str) -> tuple[list[float], list[str]] | None:
    """Embed the query with the SAME embedder the index was built with, so the
    query and the indexed nodes live in one space. Returns (vector, node_ids) or
    None when there is no usable index."""
    idx = _index()
    if not idx or not idx.get("vectors"):
        return None
    mod = _embed_module()
    if mod is None:
        return None
    embedder = mod.get_embedder()
    if idx["embedder"] != {"id": embedder.id, "dim": embedder.dim}:
        return None
    try:
        vectors = embedder.embed([text])
    except (ValueError, OverflowError):
        return None
    if not mod.valid_vectors(vectors, 1, embedder.dim):
        return None
    return vectors[0], idx["node_ids"]


def _vector_scores(text: str) -> dict[str, float]:
    """Cosine similarity of the query against every indexed node vector. Vectors
    are stored L2-normalized, so cosine is a plain dot product. Empty when there
    is no index (clean lexical fallback)."""
    got = _query_vector(text)
    if got is None:
        return {}
    qvec, node_ids = got
    idx = _index() or {}
    scores: dict[str, float] = {}
    for nid, vec, source_hash in zip(node_ids, idx["vectors"], idx["node_text_sha256"]):
        node = get_node(nid)
        if node is None or search_fingerprint(node) != source_hash:
            continue
        dot = math.fsum(a * b for a, b in zip(qvec, vec))
        if dot > 0:
            scores[nid] = dot
    return scores


def hybrid_search(text: str, limit: int = 0) -> list[dict]:
    """Fuse lexical + vector + one-hop graph-expansion into one ranked result.

    - features.semantic_search OFF or no/empty index  -> exactly search() (lexical
      contract preserved, #22 stays green).
    - otherwise: union of lexical hits and vector-similar nodes, then expand one
      hop off the top seeds; score each node by a weighted sum of its signals and
      return nodes stably sorted by (-score, id). `limit` (0 = all) caps results.
    """
    q = (text or "").strip()
    if not q:
        return []

    lexical = search(q)  # the existing, unchanged lexical contract
    if not _semantic_on():
        return lexical[:limit] if limit else lexical

    vscores = _vector_scores(q.lower())
    if not vscores:
        # No usable index -> behave exactly like lexical search.
        return lexical[:limit] if limit else lexical

    # --- fuse: lexical + vector ----------------------------------------------
    score: dict[str, float] = {}
    for n in lexical:
        score[n["id"]] = score.get(n["id"], 0.0) + _W_LEXICAL
    for nid, s in vscores.items():
        score[nid] = score.get(nid, 0.0) + _W_VECTOR * s

    # --- graph-expansion: one hop off the strongest seeds --------------------
    # Expand the current top hits so a highly-relevant node's neighbours surface
    # too. A neighbour gets a small constant credit (never outranks a direct hit).
    seeds = sorted(score, key=lambda i: (-score[i], i))
    for sid in seeds[: _GRAPH_SEED_LIMIT]:
        for nbr in neighbors(sid, "both"):
            nid = nbr["id"]
            if nid not in score:
                score[nid] = _W_GRAPH

    # --- materialize + deterministic ranking ---------------------------------
    ranked_ids = sorted(score, key=lambda i: (-score[i], i))
    results = [get_node(i) for i in ranked_ids]
    results = [n for n in results if n is not None]
    return results[:limit] if limit else results


def reset_index() -> None:
    """Drop the cached vector index (TESTS ONLY / after an embed rebuild)."""
    global _vec_index
    _vec_index = None
