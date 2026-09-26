#!/usr/bin/env python3
"""Compile app/kinds.json — the page descriptors the generic kind renderer reads.

Frontend pass 1 (buildout W1.5, scoped up from #54 slice 2): a portal page is a
VIEW over a declared kind, not a hand-written shell. The ontology
(brain-schema.json) says which kinds exist and which artifact + page each has;
the artifact's JSON Schema (schemas/<artifact>.schema.json) says which fields a
record carries. Neither says how to DISPLAY a record. This script derives that:

    kind  +  artifact schema  ->  { records key, fields, display roles }

and writes it as app/kinds.json for app/kind-page.js to consume at runtime, so
deleting a field from the schema removes it from the rendered page with zero
HTML/JS edits — the acceptance test for the whole pass.

Display roles are inferred from field NAMES by a fixed table (title-ish,
body-ish, date, labels, status, owner, session, link). Inference is
deterministic and documented; an artifact schema may override any role by
declaring `x-kb-display` on the field:

    "severity": { "type": "string", "x-kb-display": "status" }

A kind whose artifact is not a records-list (roadmap tracks, the plan manifest)
gets `renderable: false` with a reason — those stay bespoke until pass 2 and
the manifest of what is and is not schema-rendered is itself part of the
output, so the boundary is declared rather than discovered.

Stdlib only. Deterministic (in the generated-clean drift gate).
Run from anywhere:  python3 scripts/gen-kinds.py
"""
from __future__ import annotations

import json
import os
from collections import OrderedDict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA = os.path.join(ROOT, "brain-schema.json")
SCHEMAS = os.path.join(ROOT, "schemas")
OUT = os.path.join(ROOT, "app", "kinds.json")

# Field name -> display role. First match wins; order inside each role matters
# only for choosing the ONE field that fills a single-slot role (title, body,
# date). Multi-slot roles (meta) take every match.
ROLE_BY_NAME = OrderedDict([
    ("title",   ("title", "name", "term", "question", "text", "product")),
    ("body",    ("decision", "definition", "detail", "context", "summary", "description", "notes")),
    ("date",    ("date", "updated", "created")),
    ("labels",  ("labels", "tags", "aliases")),
    ("status",  ("status", "severity", "type")),
    ("owner",   ("owner",)),
    ("session", ("session",)),
    ("link",    ("link", "doc", "email")),
])
SINGLE = ("title", "body", "date", "session", "link")

# Artifact path -> schema file, when the two do not share a basename.
SCHEMA_FOR = {
    "app/open-questions.json": "open-questions.schema.json",
    "app/user-stories.json": "user-stories.schema.json",
}


def _resolve(schema: dict, node: dict) -> dict:
    """Follow a local $ref (#/definitions/x) to its target."""
    while isinstance(node, dict) and "$ref" in node:
        cur: dict = schema
        for part in node["$ref"].split("/")[1:]:
            cur = cur[part]
        node = cur
    return node


def _artifact_schema(artifact: str) -> dict | None:
    name = SCHEMA_FOR.get(artifact) or os.path.basename(artifact).replace(".json", ".schema.json")
    path = os.path.join(SCHEMAS, name)
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _records(schema: dict) -> tuple[str | None, dict]:
    """(records key, item properties) — the first array-of-objects property at
    the artifact's top level. None when the artifact is not a records list."""
    props = schema.get("properties", {}) if schema.get("type") == "object" else {}
    for key, node in props.items():
        if key.startswith("$"):
            continue
        node = _resolve(schema, node)
        if node.get("type") == "array":
            items = _resolve(schema, node.get("items", {}))
            if items.get("type") == "object" and items.get("properties"):
                return key, items["properties"]
    return None, {}


def _nested(props: dict, schema: dict) -> bool:
    """True when a record carries two or more array-of-object properties — a
    tree (roadmap tracks -> phases/modules/items), which the flat list renderer
    would flatten into nonsense. One nested list (a story's acceptance criteria)
    renders fine as a sub-list."""
    n = 0
    for node in props.values():
        node = _resolve(schema, node)
        if node.get("type") == "array":
            items = _resolve(schema, node.get("items", {}))
            if items.get("type") == "object":
                n += 1
    return n >= 2


def _nested_lists(props: dict, schema: dict, depth: int) -> list[OrderedDict]:
    """Descriptors for the array-of-object properties in `props` (#76): each
    gets its own records key, fields and display roles, computed the same way
    a flat renderable kind's are — so a tree kind's nested lists are DECLARED,
    not merely known unrenderable. `depth` bounds recursion (one further level
    covers roadmap's phase/module -> item shape); a $ref cycle cannot loop
    forever because `depth` reaches zero regardless of property names."""
    out = []
    for name, node in props.items():
        node = _resolve(schema, node)
        if node.get("type") != "array":
            continue
        items = _resolve(schema, node.get("items", {}))
        if items.get("type") != "object" or not items.get("properties"):
            continue
        fields = _fields(items["properties"], schema)
        desc = OrderedDict([("name", name), ("fields", fields), ("display", _roles(fields))])
        if depth > 0:
            sub = _nested_lists(items["properties"], schema, depth - 1)
            if sub:
                desc["nested"] = sub
        out.append(desc)
    return out


def _fields(props: dict, schema: dict) -> list[OrderedDict]:
    out = []
    for name, node in props.items():
        node = _resolve(schema, node)
        t = node.get("type")
        f = OrderedDict([("name", name), ("type", t if isinstance(t, str) else (t[0] if isinstance(t, list) and t else "string"))])
        if "enum" in node:
            f["enum"] = list(node["enum"])
        if f["type"] == "array":
            items = _resolve(schema, node.get("items", {}))
            f["items"] = items.get("type", "string")
        if "x-kb-display" in node:
            f["role"] = node["x-kb-display"]
        out.append(f)
    return out


def _roles(fields: list[OrderedDict]) -> OrderedDict:
    """Assign display roles. Explicit x-kb-display wins; then the name table.
    Single-slot roles take the first match in table order; `meta` collects
    every remaining scalar field so nothing declared is silently dropped."""
    roles: OrderedDict = OrderedDict((r, [] if r not in SINGLE else None) for r in ROLE_BY_NAME)
    roles["meta"] = []
    taken: set[str] = set()
    for f in fields:
        if f.get("role") and f["role"] in roles:
            r = f["role"]
            if r in SINGLE:
                if roles[r] is None:
                    roles[r] = f["name"]
                    taken.add(f["name"])
            else:
                roles[r].append(f["name"])
                taken.add(f["name"])
    for role, names in ROLE_BY_NAME.items():
        for name in names:
            for f in fields:
                if f["name"] != name or f["name"] in taken:
                    continue
                if role in SINGLE:
                    if roles[role] is None:
                        roles[role] = f["name"]
                        taken.add(f["name"])
                elif role in ("labels",) and f["type"] != "array":
                    continue
                else:
                    roles[role].append(f["name"])
                    taken.add(f["name"])
    for f in fields:
        if f["name"] not in taken and f["type"] in ("string", "number", "integer", "boolean") and not f["name"].startswith("$"):
            roles["meta"].append(f["name"])
    return roles


def build(schema_path: str = SCHEMA) -> OrderedDict:
    with open(schema_path, encoding="utf-8") as f:
        ontology = json.load(f, object_pairs_hook=OrderedDict)
    kinds = []
    for k in ontology.get("kinds", []):
        artifact = k.get("artifact")
        entry = OrderedDict([
            ("id", k["id"]), ("title", k.get("title", k["id"])),
            ("description", k.get("description", "")),
            ("class", k.get("class")), ("mutability", k.get("mutability")),
            ("source", k.get("source")), ("page", k.get("page")),
            ("artifact", artifact),
        ])
        if not artifact or not artifact.endswith(".json"):
            entry["renderable"] = False
            entry["reason"] = "no JSON artifact (markdown storage or mirror)"
            kinds.append(entry)
            continue
        aschema = _artifact_schema(artifact)
        if aschema is None:
            entry["renderable"] = False
            entry["reason"] = "no artifact schema under schemas/"
            kinds.append(entry)
            continue
        # The artifact schema's own writability declaration (#38). The Worker
        # and the in-portal editor combine it with `mutability` (anchor kinds are
        # never writable) instead of keeping a parallel list of editable types.
        entry["editable"] = (aschema.get("x-conflict") or {}).get("editable") is True
        key, props = _records(aschema)
        if key is None:
            entry["renderable"] = False
            entry["reason"] = "artifact is not a records list (bespoke page until pass 2)"
            kinds.append(entry)
            continue
        if _nested(props, aschema):
            entry["renderable"] = False
            entry["records"] = key
            entry["reason"] = "records carry nested object lists (a tree, not a list; bespoke page until pass 2)"
            # The record stays bespoke (a flat list would flatten the tree into
            # nonsense), but its shape is still declared: top-level fields plus
            # a descriptor per nested list (#76), so a page that chooses to stay
            # custom can still read field/display info instead of hardcoding it.
            fields = _fields(props, aschema)
            entry["fields"] = fields
            entry["display"] = _roles(fields)
            entry["nested"] = _nested_lists(props, aschema, depth=1)
            kinds.append(entry)
            continue
        fields = _fields(props, aschema)
        entry["renderable"] = True
        entry["records"] = key
        entry["fields"] = fields
        entry["display"] = _roles(fields)
        kinds.append(entry)
    return OrderedDict([
        ("format", "kinds/v1"),
        ("generator", "gen-kinds"),
        ("$comment", "GENERATED by scripts/gen-kinds.py from brain-schema.json + schemas/*.schema.json — page descriptors for app/kind-page.js. Edit the ontology or the artifact schema, never this file."),
        ("kinds", kinds),
    ])


def main() -> int:
    data = build()
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, ensure_ascii=False)
        f.write("\n")
    n = sum(1 for k in data["kinds"] if k.get("renderable"))
    print(f"Wrote app/kinds.json ({n}/{len(data['kinds'])} kinds schema-renderable).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
