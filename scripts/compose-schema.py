#!/usr/bin/env python3
"""Compose brain-schema.json from profile overlays (#54 slice 5, redesigned).

The original slice-5 design had `profile` name ONE file to load. The fleet
showed why that is not enough before it was built: the company brain needed the
engagement kinds PLUS six more, and got them by forking the whole file. Profiles
therefore compose as BASE + ORDERED OVERLAYS:

    profiles/core.json         the envelope + kinds/edges every brain has
    profiles/engagement.json   the plan DAG and delivery records
    profiles/data.json         catalogued sources, artifacts, collections
    profiles/<more>.json       agent, company, build — land with their workstreams

and the composition is declared in client.config.json:

    "profile": { "base": "core", "overlays": ["engagement", "data"] }

Integrate, don't refactor: the composed result is WRITTEN TO brain-schema.json,
so the seven scripts that read that file keep reading it unchanged. The file
becomes a generated artifact whenever a composition is declared; it stays a
hand-maintained file for an instance that declares no overlays (empty
`profile.overlays` -> this script is a no-op, byte-for-byte backward compatible).

Merge rules — strict, because a silent last-wins is how forks start:
  - kind ids and edge ids must be UNIQUE across base + overlays; a collision is
    a hard error naming both overlays;
  - only the base may carry the envelope (version / contract / classes); an
    overlay declaring one is an error;
  - contextRecipes merge by key with the same uniqueness rule, except `default`:
    the base sets a purpose-neutral one and at most ONE overlay may refine it
    (engagement's plan-DAG traversal, #204); a second refinement is an error.
    The recipes' `$comment` is last-writer-wins, so the overlay refining
    `default` can describe it;
  - each layer declares the id convention of ITS OWN kinds under `idConventions`
    (rule -> [kind ids]); the composer merges them into the base contract's
    `contract.idConventions[rule].kinds`, and every composed kind must end up
    under exactly one rule — the ontology gate would reject it later anyway,
    so the composer fails first and names the layer;
  - order is preserved: base kinds first, then each overlay in declared order;
  - an overlay may carry `patches` — {kind id: {field: value}} applied LAST to
    kinds declared by EARLIER layers, restricted to the presentation/bridge
    fields (node, idPrefixes, page, artifact, storage, description). This is how an
    instance whose compiler emits more than the template's (a forked gen-brain
    compiling Doc nodes) states that truth without forking the schema, and how
    an overlay refines a purpose-neutral core description with its own meaning
    (#204). idPrefixes disambiguates kinds sharing a compiled node; the registry
    validates prefix syntax and uniqueness. class, mutability, source and the id convention are never
    patchable — those are the contract;
  - `edgePatches` — {edge id: {"description": ...}} — does the same for edges
    declared by other layers; only the description is patchable.

The composed file records its lineage in a `composition` block and keeps the
legacy single-string `profile` (= the last overlay, or the base) so
check-brain-schema.py's envelope check and gen-manifest's skew reporting keep
working across instances that have and have not migrated.

Gate: `--check` recomposes in memory and fails if brain-schema.json differs.

Run from anywhere:  python3 scripts/compose-schema.py [--check]
"""
from __future__ import annotations

import json
import re
import os
import sys
from collections import OrderedDict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROFILES = os.path.join(ROOT, "profiles")
OUT = os.path.join(ROOT, "brain-schema.json")

ENVELOPE_KEYS = ("version", "contract", "classes")
PATCHABLE = ("node", "idPrefixes", "page", "artifact", "storage", "description")
EDGE_PATCHABLE = ("description",)


class CompositionError(SystemExit):
    def __init__(self, msg: str):
        super().__init__(f"compose-schema: {msg}")


def _load_overlay(name: str) -> OrderedDict:
    path = os.path.join(PROFILES, f"{name}.json")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f, object_pairs_hook=OrderedDict)
    except FileNotFoundError:
        raise CompositionError(f"no such profile overlay: profiles/{name}.json")
    except json.JSONDecodeError as e:
        raise CompositionError(f"profiles/{name}.json is not valid JSON: {e}")
    if data.get("overlay") != name:
        raise CompositionError(
            f"profiles/{name}.json declares overlay={data.get('overlay')!r}, expected {name!r}")
    return data


def declared() -> tuple[str, list[str]]:
    """(base, overlays) from config. Empty overlays = no composition declared."""
    from config import settings
    prof = settings.profile
    return prof.get("base", "core"), list(prof.get("overlays", ()) or ())


def compose(base: str, overlays: list[str]) -> OrderedDict:
    layers = [(base, _load_overlay(base))] + [(o, _load_overlay(o)) for o in overlays]

    kinds: "OrderedDict[str, tuple[str, OrderedDict]]" = OrderedDict()
    edges: "OrderedDict[str, tuple[str, OrderedDict]]" = OrderedDict()
    recipes: OrderedDict = OrderedDict()
    terms: OrderedDict = OrderedDict()
    default_refined_by = None

    for i, (name, layer) in enumerate(layers):
        is_base = i == 0
        if not is_base and "registry" in layer:
            raise CompositionError(f"overlay {name!r} cannot replace the registry contract")
        if layers[0][1].get("registry") and not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)", str(layer.get("revision", ""))):
            raise CompositionError(f"overlay {name!r} needs an exact semantic revision")
        for key in ENVELOPE_KEYS:
            if not is_base and key in layer:
                raise CompositionError(
                    f"overlay {name!r} declares envelope key {key!r}; only the base may")
        for k in layer.get("kinds", []):
            kid = k.get("id")
            if not kid:
                raise CompositionError(f"overlay {name!r}: kind without id")
            if kid in kinds:
                raise CompositionError(
                    f"kind {kid!r} declared by both {kinds[kid][0]!r} and {name!r}")
            kinds[kid] = (name, k)
        for e in layer.get("edges", []):
            eid = e.get("id")
            if not eid:
                raise CompositionError(f"overlay {name!r}: edge without id")
            if eid in edges:
                raise CompositionError(
                    f"edge {eid!r} declared by both {edges[eid][0]!r} and {name!r}")
            edges[eid] = (name, e)
        for term in layer.get("taxonomy", []):
            tid = term.get("id")
            if not tid or tid in terms:
                raise CompositionError(f"overlay {name!r}: missing or duplicate taxonomy id {tid!r}")
            terms[tid] = term
        for rk, rv in layer.get("contextRecipes", OrderedDict()).items():
            if rk == "$comment":
                recipes[rk] = rv  # a later layer's note refines the base's; key order stays
                continue
            if rk == "default" and not is_base:
                if default_refined_by:
                    raise CompositionError(
                        f"contextRecipes.default refined by both {default_refined_by!r} and {name!r}")
                default_refined_by = name
            if rk in recipes and rk != "default":
                raise CompositionError(f"contextRecipe {rk!r} declared twice ({name!r})")
            recipes[rk] = rv

    base_layer = layers[0][1]
    for key in ENVELOPE_KEYS:
        if key not in base_layer:
            raise CompositionError(f"base {base!r} lacks envelope key {key!r}")

    # id conventions: rule -> ordered kind ids, merged across layers.
    contract = json.loads(json.dumps(base_layer["contract"]), object_pairs_hook=OrderedDict)
    for name, layer in layers[1:]:
        for relation in layer.get("joinEdges", []):
            if relation not in edges or relation in contract.get("joinEdges", []):
                raise CompositionError(f"overlay {name!r}: unknown or duplicate join edge {relation!r}")
            contract.setdefault("joinEdges", []).append(relation)
    conventions = contract.setdefault("idConventions", OrderedDict())
    for rule in conventions.values():
        rule["kinds"] = []
    assigned: dict[str, tuple[str, str]] = {}
    for name, layer in layers:
        for rule, kids in layer.get("idConventions", OrderedDict()).items():
            if rule not in conventions:
                raise CompositionError(
                    f"overlay {name!r} uses unknown id convention {rule!r} "
                    f"(base declares {sorted(conventions)})")
            for kid in kids:
                if kid not in kinds:
                    raise CompositionError(
                        f"overlay {name!r}: idConventions.{rule} names undeclared kind {kid!r}")
                if kid in assigned:
                    raise CompositionError(
                        f"kind {kid!r} given an id convention by both {assigned[kid][0]!r} "
                        f"({assigned[kid][1]}) and {name!r} ({rule})")
                assigned[kid] = (name, rule)
                conventions[rule]["kinds"].append(kid)
    # patches: presentation/bridge fields only, onto kinds from earlier layers
    for name, layer in layers[1:]:
        for kid, fields in (layer.get("patches") or {}).items():
            if kid not in kinds:
                raise CompositionError(f"overlay {name!r} patches undeclared kind {kid!r}")
            if kinds[kid][0] == name:
                raise CompositionError(f"overlay {name!r} patches its own kind {kid!r}; declare it directly")
            bad = sorted(set(fields) - set(PATCHABLE))
            if bad:
                raise CompositionError(
                    f"overlay {name!r} patches {kid!r}.{bad} — only {list(PATCHABLE)} are patchable")
            owner, k = kinds[kid]
            k = OrderedDict(k)
            k.update(fields)
            kinds[kid] = (owner, k)
        for eid, fields in (layer.get("edgePatches") or {}).items():
            if eid not in edges:
                raise CompositionError(f"overlay {name!r} patches undeclared edge {eid!r}")
            if edges[eid][0] == name:
                raise CompositionError(f"overlay {name!r} patches its own edge {eid!r}; declare it directly")
            bad = sorted(set(fields) - set(EDGE_PATCHABLE))
            if bad:
                raise CompositionError(
                    f"overlay {name!r} patches edge {eid!r}.{bad} — only {list(EDGE_PATCHABLE)} is patchable")
            owner, e = edges[eid]
            e = OrderedDict(e)
            e.update(fields)
            edges[eid] = (owner, e)

    missing = [kid for kid in kinds if kid not in assigned]
    if missing:
        raise CompositionError(
            f"kinds without an id convention: {missing} — declare them under "
            f"idConventions in the overlay that owns them")

    out = OrderedDict()
    out["$comment"] = (
        "GENERATED by scripts/compose-schema.py from profiles/ — edit the overlays, "
        "not this file. " + base_layer.get("$comment", "")
    )
    out["version"] = base_layer["version"]
    out["profile"] = overlays[-1] if overlays else base
    out["composition"] = OrderedDict([("base", base), ("overlays", list(overlays))])
    out["contract"] = contract
    out["classes"] = base_layer["classes"]
    out["kinds"] = [k for _, k in kinds.values()]
    out["edges"] = [e for _, e in edges.values()]
    out["contextRecipes"] = recipes
    if base_layer.get("registry"):
        out["registry"] = OrderedDict(base_layer["registry"])
        out["registry"]["layers"] = OrderedDict((name, layer["revision"]) for name, layer in layers)
        out["taxonomy"] = list(terms.values())
        from ontology import OntologyError, Registry
        try:
            Registry(out)
        except OntologyError as exc:
            raise CompositionError(str(exc)) from exc
    return out


def _dump(obj: OrderedDict) -> str:
    return json.dumps(obj, indent=1, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    check = "--check" in argv
    base, overlays = declared()
    if not overlays:
        print("compose-schema: no profile.overlays declared — brain-schema.json is hand-maintained; nothing to do.")
        return 0
    composed = _dump(compose(base, overlays))
    if check:
        try:
            with open(OUT, encoding="utf-8") as f:
                current = f.read()
        except FileNotFoundError:
            current = ""
        if current != composed:
            print(f"compose-schema: FAIL — brain-schema.json differs from {base} + {' + '.join(overlays)}; run `make schema`.")
            return 1
        print(f"compose-schema: OK — brain-schema.json == {base} + {' + '.join(overlays)}.")
        return 0
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(composed)
    n = json.loads(composed)
    print(f"Wrote brain-schema.json ({base} + {' + '.join(overlays)}: {len(n['kinds'])} kinds, {len(n['edges'])} edges).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
