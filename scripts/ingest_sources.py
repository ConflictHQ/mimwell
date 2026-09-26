#!/usr/bin/env python3
"""Pluggable source-ingestion module -> app/sources.json (issue #13).

Any engagement that touches data has SOURCES — databases, APIs, product
catalogs, schema files. This module inventories them into one common shape so
the brain can reason about *what data exists, where it lives, and how far the
audit has got* — without baking any one technology in.

The shape is uniform across every source kind:

    source  (a system of record: a database, an API, a catalog, a schema)
      └─ entity  (a table / resource / type)
           └─ field  (a column / property / attribute)

Every level carries optional status / owner / provenance, so the inventory
records not just structure but standing: where a thing was extracted from
(`provenance`), who owns it, and how far along the audit is (`status`).

Architecture — a registry of EXTRACTOR ADAPTERS, one per input technology,
mirroring gen-brain.py's @adapter pattern:

    @extractor("sql-ddl")
    def sql_ddl(root): -> [source-dict, ...]

Adapters are REGISTERED, not hardcoded: adding support for a new source kind is
one decorated function. Each extractor discovers its inputs under ROOT (a
configured directory of dumps / schema files), tolerates *no inputs present*
(returns [] rather than crashing), and emits source-dicts in the common
envelope. The ONE reference adapter shipped here is `sql-ddl` — a generalized,
vendor-scrubbed CREATE TABLE parser. The rest (`api-schema`, `json-schema`,
`csv-headers`, `catalog`) are registered SEAMS: thin, dependency-free stubs that
declare the interface and return [] until an engagement needs them.

Inputs live under `sources/` (override per-extractor via config). NOTHING client
is shipped — only a tiny synthetic example DDL fixture under
sources/examples/ for the docs/tests, and the committed empty-state
app/sources.json is `{"sources": []}` so a fresh template builds clean.

Gating: this is an optional subsystem. It runs only when enabled via
`generators.sources` (a per-generator toggle) — disabled, the whole module is a
clean no-op (writes the empty envelope, emits no brain nodes), so a project that
inventories no sources carries nothing.

Determinism: sources sorted by id, entities by name, fields by name; written
with indent=1 — a stable, diff-friendly shape (matches gen-brain.py).

Run from anywhere:  python3 scripts/ingest_sources.py
"""
from __future__ import annotations

import json
import os
import re

from config import settings

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "app", "sources.json")

# Where extractors look for their inputs by default. An engagement points this
# at its dumps / schema dir via generators.sources (see _input_dir).
DEFAULT_INPUT_DIR = "sources"


# ----------------------------------------------------------------------------
# Extractor registry
# ----------------------------------------------------------------------------
#
# EXTRACTORS is the source of truth for what gets inventoried. Each extractor is
# a `(root) -> [source-dict]` callable registered under a stable name by the
# @extractor decorator, so adding a source technology is a one-function change.

EXTRACTORS: dict[str, callable] = {}


def extractor(name: str):
    """Register a source extractor under `name`. Each decorated fn is
    `(root) -> list[source-dict]` and must tolerate no inputs (return [])."""
    def register(fn):
        EXTRACTORS[name] = fn
        return fn
    return register


def _generator_opts() -> dict:
    """The `generators.sources` config value, normalized to an options dict.

    A bare `true`/absent -> defaults (every extractor on, default input dir);
    `false` -> {} with the module disabled by the caller; an object -> its keys.
    """
    val = settings.generators.get("sources", True)
    if isinstance(val, dict):
        return dict(val)
    return {}


def _enabled() -> bool:
    """Whether source-ingestion runs at all (generators.sources truthiness)."""
    return bool(settings.generators.get("sources", True))


def _input_dir() -> str:
    """Absolute path to the input directory (config override or the default)."""
    rel = _generator_opts().get("input_dir", DEFAULT_INPUT_DIR)
    return os.path.join(ROOT, rel)


def _provenance(name: str, path: str, locator: str | None = None) -> dict:
    """A provenance stamp: which extractor read which input path (repo-relative)."""
    rel = os.path.relpath(path, ROOT)
    prov = {"extractor": name, "path": rel}
    if locator:
        prov["locator"] = locator
    return prov


# ----------------------------------------------------------------------------
# Reference adapter: sql-ddl
# ----------------------------------------------------------------------------
#
# A generalized RDBMS CREATE TABLE parser. Ported from a SQL-Server-specific
# parser and SCRUBBED of vendor assumptions where practical: brackets are
# optional (T-SQL `[name]`, but plain identifiers and double-quoted names parse
# too), CLUSTERED/NONCLUSTERED on a PK constraint are tolerated but optional, and
# nothing requires a `USE [db]` / `-- Server:` header. It reads any *.sql/*.ddl
# dump under <input_dir>/ddl/ as one source-per-file.

# A column line: identifier, then a type (with optional (...) args), then an
# optional rest (nullability / defaults / inline comment). The rest is optional
# so a bare `status VARCHAR(32),` parses, not just `... NOT NULL`.
_COL_RE = re.compile(
    r'^\s*[\[`"]?(?P<name>\w+)[\]`"]?\s+'
    r'(?P<type>\w+(?:\s*\([^)]*\))?)\s*(?P<rest>.*)$'
)
# Table-level constraint / DDL keyword lines (matched as a leading WORD, not a
# prefix — a column named `created_at` must NOT be eaten by `CREATE`).
_SKIP_KEYWORDS = frozenset((
    "CONSTRAINT", "PRIMARY", "FOREIGN", "INDEX", "UNIQUE", "CHECK", "KEY",
    "CREATE", "GO", "USE", "ALTER", "SET", "WITH",
))
_CREATE_RE = re.compile(
    r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?'
    r'(?:[\[`"]?(?P<schema>\w+)[\]`"]?\.)?[\[`"]?(?P<table>\w+)[\]`"]?\s*\(',
    re.I,
)
_PK_CONSTRAINT_RE = re.compile(
    r'PRIMARY\s+KEY\s*(?:CLUSTERED|NONCLUSTERED)?\s*\(([^)]*)\)', re.I)


def _ddl_columns(body: str) -> list[dict]:
    """Parse the inside of a CREATE TABLE (...) block into field dicts."""
    fields: list[dict] = []
    pk_from_constraint: set[str] = set()
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("--") or line.startswith("/*"):
            continue
        pk_con = _PK_CONSTRAINT_RE.search(line)
        if pk_con:
            for c in pk_con.group(1).split(","):
                pk_from_constraint.add(re.sub(r'[\[\]`"\s]', "", c).lower())
            continue
        first_word = re.match(r'[\[`"]?(\w+)', line)
        if first_word and first_word.group(1).upper() in _SKIP_KEYWORDS:
            continue
        if line.startswith(")"):
            continue
        m = _COL_RE.match(line)
        if not m:
            continue
        rest = m.group("rest")
        comment = ""
        if "--" in rest:
            rest, comment = rest.split("--", 1)
            comment = comment.strip()
        nullable = "NOT NULL" not in rest.upper()
        is_pk = bool(re.search(r"\bPK\b", comment)) or "PRIMARY KEY" in rest.upper()
        fields.append({
            "name": m.group("name"),
            "type": re.sub(r"\s+", "", m.group("type")).upper(),
            "nullable": nullable,
            "is_pk": is_pk,
        })
    for f in fields:
        if f["name"].lower() in pk_from_constraint:
            f["is_pk"] = True
    return fields


def _ddl_tables(text: str) -> list[dict]:
    """Extract every CREATE TABLE in a dump as an entity-dict (name + fields)."""
    entities: list[dict] = []
    for m in _CREATE_RE.finditer(text):
        # walk to the matching ")" that closes this CREATE TABLE
        start = m.end()
        depth, i = 1, start
        while i < len(text) and depth:
            ch = text[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            i += 1
        body = text[start:i - 1]
        schema = m.group("schema")
        name = m.group("table")
        full = f"{schema}.{name}" if schema else name
        entities.append({"name": full, "fields": _ddl_columns(body)})
    return entities


@extractor("sql-ddl")
def sql_ddl(root: str) -> list[dict]:
    """Parse RDBMS DDL dumps under <input_dir>/ddl/*.{sql,ddl} -> one source per
    file (source.kind='database', entity-per-table, field-per-column). The file
    stem is the source id; each table is an entity, each column a field with
    type / nullability / PK carried through. No inputs -> []."""
    ddl_dir = os.path.join(_input_dir(), "ddl")
    sources: list[dict] = []
    if not os.path.isdir(ddl_dir):
        return sources
    for fname in sorted(os.listdir(ddl_dir)):
        if not fname.lower().endswith((".sql", ".ddl")):
            continue
        path = os.path.join(ddl_dir, fname)
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        stem = os.path.splitext(fname)[0]
        prov = _provenance("sql-ddl", path)
        entities = []
        for ent in _ddl_tables(text):
            ent["provenance"] = prov
            entities.append(ent)
        sources.append({
            "id": stem,
            "kind": "database",
            "title": stem,
            "provenance": prov,
            "entities": entities,
        })
    return sources


# ----------------------------------------------------------------------------
# Registered seams — pluggable stubs, no heavy deps. Each declares the interface
# and returns [] until an engagement implements it (or installs an optional
# parser). They are real registry entries so the catalog of supported kinds is
# discoverable; none pulls in a dependency the template doesn't already carry.
# ----------------------------------------------------------------------------


@extractor("api-schema")
def api_schema(root: str) -> list[dict]:
    """SEAM: OpenAPI / GraphQL schema -> entities (resources/types) + fields.

    Read schema docs under <input_dir>/api/ and project each resource/type into
    a source/entity/field. Stubbed (returns []) — wire it to a stdlib JSON/YAML
    walk over the spec's components/schemas when an engagement needs it."""
    return []


@extractor("json-schema")
def json_schema(root: str) -> list[dict]:
    """SEAM: JSON Schema files -> one entity per schema, properties -> fields.

    Walk <input_dir>/json-schema/*.json and read each schema's `properties`
    (type from the property's `type`, nullable from `required`). Stubbed."""
    return []


@extractor("csv-headers")
def csv_headers(root: str) -> list[dict]:
    """SEAM: CSV/TSV header rows -> one entity per file, columns -> fields.

    Read the header line of each <input_dir>/csv/*.csv with the stdlib `csv`
    module; every column becomes a field (type unknown). Stubbed."""
    return []


@extractor("catalog")
def catalog(root: str) -> list[dict]:
    """SEAM: product / ecommerce catalog -> entities (product types) + fields
    (attributes). Read a catalog export under <input_dir>/catalog/ and project
    its product types + attribute schema. Stubbed."""
    return []


# ----------------------------------------------------------------------------
# Compile
# ----------------------------------------------------------------------------


def _norm_source(src: dict) -> dict:
    """Deterministically order a source-dict: entities by name, fields by name,
    and drop empty optional collections so the shape stays minimal."""
    entities = []
    for ent in sorted(src.get("entities", []), key=lambda e: e.get("name", "")):
        fields = sorted(ent.get("fields", []), key=lambda f: f.get("name", ""))
        out_ent = {k: v for k, v in ent.items() if k != "fields"}
        if fields:
            out_ent["fields"] = fields
        entities.append(out_ent)
    out = {k: v for k, v in src.items() if k != "entities"}
    if entities:
        out["entities"] = entities
    return out


def build(root: str) -> dict:
    """Run every registered extractor and merge into one deterministic
    inventory. Disabled (generators.sources falsy) -> the empty envelope."""
    sources: list[dict] = []
    if _enabled():
        for name in sorted(EXTRACTORS):
            try:
                produced = EXTRACTORS[name](root) or []
            except Exception:
                # An extractor must never sink the whole build — skip a bad input.
                produced = []
            sources.extend(produced)

    by_id: dict[str, dict] = {}
    for src in sources:
        if not isinstance(src, dict) or not src.get("id"):
            continue
        by_id.setdefault(src["id"], _norm_source(src))  # first writer wins

    ordered = [by_id[k] for k in sorted(by_id)]
    n_entities = sum(len(s.get("entities", [])) for s in ordered)
    n_fields = sum(len(e.get("fields", []))
                   for s in ordered for e in s.get("entities", []))
    return {
        "version": 1,
        "generated_by": "scripts/ingest_sources.py",
        "counts": {"sources": len(ordered), "entities": n_entities,
                   "fields": n_fields},
        "sources": ordered,
    }


def main() -> None:
    inventory = build(ROOT)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(inventory, f, indent=1)
    c = inventory["counts"]
    print(f"Wrote {OUT}: {c['sources']} source(s), {c['entities']} entit(ies), "
          f"{c['fields']} field(s) from {len(EXTRACTORS)} extractor(s)")


if __name__ == "__main__":
    main()
