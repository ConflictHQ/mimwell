#!/usr/bin/env python3
"""Compile app/brain-manifest.json — the brain's self-description.

`client.config.json` is INPUT (what an operator declared); this artifact is the
generated statement of what the instance currently IS. It exists so that a
parent brain, a query router, an agent, or `doctor` can reason about an instance
WITHOUT reading its tree — and so that a fleet sitting at three different engine
generations becomes legible before anything is upgraded.

Eight blocks, each answering one question a caller actually has:

  identity    who is this, and what namespace do its addresses take upward
  scope       where it sits on the spine (federation/company/domain/project/
              workspace/person/agent), its parent, its peers
  profile     which ontology it composes (base + ordered overlays) and which
              supergraph contract version it emits
  engine      generation markers — envelope version, schema present, gate count,
              template sync baseline
  inventory   what is POPULATED, not what is declared; the unpopulated list is
              the coverage gap a parent needs before it federates
  projections which resolutions it can answer at, and how far each has fallen
              behind canon
  substrate   how it is stored and deployed, and whether it has outgrown its tier
  policy      what it will publish upward and what never leaves this scope
  surfaces    how a caller reaches it

Index lag (projections[].lag_commits) is COMMITS touching canon since the commit
that last touched the projection artifact. Canon paths are derived from
brain-schema.json rather than hardcoded: a kind whose `source` is markdown or
fill-in contributes its `storage`/`artifact` path; generated kinds are outputs,
not canon. Where git cannot answer, lag is null (fail-quiet, mirroring
gen-staleness.py).

DETERMINISM NOTE: `generated` and every `lag_commits` are git/clock derived and
therefore per-commit volatile, so this artifact is deliberately kept OUT of the
Makefile generated-artifact drift gate — the same carve-out activity.json (#18)
and staleness.json (#29) get. Its NON-volatile subset is gated instead, by
scripts/check-manifest.py, which regenerates and diffs.

Stdlib only. Run from anywhere:  python3 scripts/gen-manifest.py
"""
from __future__ import annotations

import datetime
import json
import os
import subprocess

from config import settings

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "app", "brain-manifest.json")
SCHEMA = os.path.join(ROOT, "brain-schema.json")
BRAIN_META = os.path.join(ROOT, "app", "brain-meta.json")
GATES = os.path.join(ROOT, "gates.json")
SYNC_STAMP = os.path.join(ROOT, "app", ".template-sync.json")

# Resolution -> (artifact path, config predicate). The declared projection table:
# which resolutions the engine knows how to answer at, and which config turns each
# on. `enabled` is what the instance asked for; `present` is what is on disk.
# The two disagreeing is the interesting case, and the reason both are reported.
PROJECTIONS = (
    ("exact", "app/brain.json", lambda s: True),
    ("lexical", "app/knowledge-pack.json", lambda s: True),
    ("relational", "app/knowledge_graph.json", lambda s: True),
    ("temporal", "activity.json", lambda s: True),
    ("indexed", "app/brain.db", lambda s: s.brain.get("store", "json") in ("sqlite", "both", "d1")),
    ("semantic", "app/brain.vec.json", lambda s: bool(s.features.get("semantic_search", False))),
)

# Substrate tier implied by the configured store — reported for visibility only.
# Graduation (below) does NOT key off this: brain.store (the compiled read-store
# setting: json/sqlite/both/d1) and brain.authority (the canonical-record
# authority: files/sqlite/postgres/mysql) are independent settings
# (docs/practices/store-selection.md, "Compiled read store vs authority cell").
# Pointing an authority-graduation command at brain.store was #215's follow-up
# bug: a scaffolded brain.store=json engagement has no adopted authority to
# cut over from, so `cutover` fails with "brain.authority is not configured"
# regardless of what brain.store says.
_TIER_BY_STORE = {"json": "files", "sqlite": "indexed", "both": "indexed", "d1": "edge-db"}

# Graduation is advisory, not silent (#215): when the instance has outgrown
# graduate_at_nodes, the manifest names a concrete next step and a priced cell
# from the hosting/cost model, instead of only warning.
_HOSTING_DOC = "docs/practices/hosting-models.md"
_D1_DOC = "docs/practices/store-selection.md#serving-from-d1"

# The AUTHORITY graduation ladder: files -> sqlite -> a SQL store, priced in
# _HOSTING_DOC's "Graduation pricing" table and proven cross-driver by #227
# (`knowledge-store.py cutover --to <brain.stores id>`, any driver to any
# other). With no brain.authority configured, the authority is `files` but
# still UN-ADOPTED (docs/primitives/knowledge-stores.md#adopt-a-local-instance):
# there is nothing to export from, so `cutover` cannot be the first command —
# adoption is. D1 is never a rung here (ADR #198 decision 1): it graduates
# independently, reported separately below via `make brain-d1-push`.
_AUTHORITY_NEXT = {"files": "sqlite", "sqlite": "sql"}
_AUTHORITY_CELL = {
    "sqlite": "authority=sqlite, blobs=fs, vectors=local, graph=edges-table",
    "sql": "authority=postgres|mysql, blobs=fs, vectors=local, graph=edges-table",
}
_ADOPT_FIRST = (
    "brain.authority is not configured, so there is nothing to cut over from; "
    "adopt an authority first (docs/primitives/knowledge-stores.md#adopt-a-local-instance), "
    "then python3 scripts/knowledge-store.py init <import.json>"
)


def _adopted_authority_driver(s) -> str | None:
    """files / sqlite / postgres / mysql: the driver of the adopted
    brain.authority, or None when this process cannot tell (a secret-only dsn,
    or the named env var unset here — never guessed). With no brain.authority
    the authority is `files`, un-adopted (docs/practices/store-selection.md).

    Mirrors authority_class() in scripts/knowledge_store.py without importing
    it: that module needs jsonschema and other packages this stdlib-only
    generator does not otherwise depend on (see the module docstring).
    """
    authority = s.brain.get("authority")
    if not authority:
        return "files"
    store_id = authority.get("store")
    stores = {store.get("id"): store for store in (s.brain.get("stores") or ())}
    dsn = (stores.get(store_id) or {}).get("dsn") or {}
    if "env" not in dsn:
        return None
    value = os.environ.get(dsn["env"])
    if not value:
        return None
    if "://" not in value:
        return "files" if value.endswith(".json") else "sqlite"
    scheme = value.split("://", 1)[0]
    if scheme in ("postgres", "postgresql"):
        return "postgres"
    if scheme == "mysql":
        return "mysql"
    return None


def _load(path: str) -> dict:
    """Read a JSON file, or {} when it is absent/unreadable (fail-quiet: a
    missing artifact is a legitimate state — an older generation, or an empty
    engagement — and must read as a reported condition, not a crash)."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def template_sync(stamp: dict) -> str | None:
    """The engine commit the last template sync recorded (#52), in the string
    form the manifest schema declares. template-update.py records `upstream` as
    an object ({remote, requestedRef, commit}, #92); an older stamp carries the
    commit string itself. Anything else reads as no recorded baseline (#362)."""
    upstream = stamp.get("upstream") if isinstance(stamp, dict) else None
    if isinstance(upstream, dict):
        upstream = upstream.get("commit")
    return upstream if isinstance(upstream, str) and upstream else None


def _git(*args: str) -> str | None:
    """Run a git command at ROOT; None when git is unavailable or the command
    fails (no repo, shallow clone, not installed)."""
    try:
        out = subprocess.run(
            ("git", "-C", ROOT) + args,
            capture_output=True, text=True, check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return out.stdout.strip()


def canon_paths(schema: dict) -> list[str]:
    """Repo-relative paths that hold CANON, derived from the ontology rather
    than hardcoded.

    A kind whose declared `source` is markdown or fill-in is authored here, so
    its storage directory / JSON artifact is canon. `generated` and `mirrored`
    kinds are outputs and external mirrors respectively — neither is a source of
    truth, and counting them as canon would make every regeneration look like a
    canon change and every projection permanently stale.
    """
    paths: set[str] = {"client.config.json", "brain-schema.json"}
    for kind in schema.get("kinds", []):
        if kind.get("source") not in ("markdown", "fill-in"):
            continue
        storage = kind.get("storage")
        for item in (storage if isinstance(storage, list) else [storage]):
            if item:
                paths.add(item)
        if kind.get("artifact"):
            paths.add(kind["artifact"])
    return sorted(p for p in paths if os.path.exists(os.path.join(ROOT, p)))


def lag_commits(artifact: str, canon: list[str]) -> int | None:
    """Commits touching canon since the commit that last touched `artifact`.

    The freshness metric that matters for a derived projection is not its age
    but its LAG: how much canon has moved that it has not seen. Null whenever
    git cannot answer — an undeterminable lag is reported as unknown, never as
    zero (claiming fresh on no evidence is the one wrong answer here).
    """
    if not canon:
        return None
    last = _git("log", "-1", "--format=%H", "--", artifact)
    if not last:
        return None
    out = _git("rev-list", "--count", f"{last}..HEAD", "--", *canon)
    if out is None or not out.isdigit():
        return None
    return int(out)


def _scope(schema: dict) -> dict:
    """The scope facet. Declared in config; defaults keep a brand-new engagement
    valid — an instance that declares nothing is a project-scope root named for
    its slug, which is what a fresh engagement portal actually is."""
    declared = settings.scope
    slug = settings.get("client", "slug", default="") or ""
    return {
        "level": declared.get("level", "project"),
        "id": declared.get("id", "") or slug,
        "parent": declared.get("parent", None),
        "peers": sorted(declared.get("peers", ()) or ()),
    }


def _profile(schema: dict) -> dict:
    """Profile composition. The composed brain-schema.json records its own
    lineage (`composition`, written by compose-schema.py) and that wins; config
    is the fallback for an instance whose schema is still hand-maintained, and
    an instance declaring nothing at all composes `core` + its legacy
    single-string profile — so the manifest reports a composition for every
    instance, migrated or not, and the skew stays visible rather than absent."""
    declared = schema.get("profile")
    composition = schema.get("composition") or {}
    cfg = settings.profile
    base = composition.get("base") or cfg.get("base", "core")
    overlays = list(composition.get("overlays") or cfg.get("overlays", ()) or ())
    if not overlays and declared:
        overlays = [declared]
    return {
        "base": base,
        "overlays": overlays,
        "declared": declared if isinstance(declared, str) else None,
        "schema_version": schema.get("version", 0),
        "contract_version": str(schema.get("contract", {}).get("version", "0")),
    }


def _inventory(schema: dict, meta: dict) -> dict:
    """Populated vs declared. `by_kind` comes from the compiled brain's own meta
    header (gen-brain owns those counts; recomputing them here would be a second,
    drifting source). A declared kind is populated when any of the compiled node
    kinds it declares via `node` has a count; a kind with `node: null` lives in
    the pack or a mirror only and is never compiled, so it can only ever read as
    unpopulated here — which is the honest answer, not a bug."""
    counts = dict(meta.get("counts", {}).get("by_kind", {}))
    declared = schema.get("kinds", [])
    populated: set[str] = set()
    for kind in declared:
        node = kind.get("node")
        nodes = node if isinstance(node, list) else [node]
        if any(counts.get(n, 0) > 0 for n in nodes if n):
            populated.add(kind["id"])
    return {
        "nodes": int(meta.get("counts", {}).get("nodes", 0)),
        "edges": int(meta.get("counts", {}).get("edges", 0)),
        "kinds_declared": len(declared),
        "kinds_populated": len(populated),
        "by_kind": dict(sorted(counts.items())),
        "unpopulated": sorted({k["id"] for k in declared} - populated),
    }


def _substrate(nodes: int) -> dict:
    """Storage + deployment tier, and whether the instance has outgrown it.

    Graduation is ADVISORY. The threshold (brain.graduate_at_nodes) has been in
    the config since the store abstraction landed but nothing ever read it; this
    is what reads it. Blobs and vectors graduate INDEPENDENTLY of the node store
    — a small corpus with heavy semantic search graduates vectors first, and a
    corpus of recordings graduates blobs first — so each is declared separately
    rather than inferred from the tier.

    `needed` fires purely on node count vs threshold. Two independent
    recommendations follow when it does: the AUTHORITY ladder (`to`/`next_cell`/
    `action`, keyed on the adopted brain.authority, never on brain.store — see
    `_adopted_authority_driver`) and the D1 projection (`d1`, keyed on nothing but
    the node count, since it graduates independently of authority — ADR #198).
    """
    store = settings.brain.get("store", "json")
    tier = _TIER_BY_STORE.get(store, "files")
    threshold = int(settings.brain.get("graduate_at_nodes", 20000))
    needed = bool(threshold) and nodes > threshold
    driver = _adopted_authority_driver(settings)
    next_driver = _AUTHORITY_NEXT.get(driver) if needed else None
    if next_driver == "sql":
        target = "postgres|mysql"
    else:
        target = next_driver
    action = None
    if next_driver:
        action = _ADOPT_FIRST if driver == "files" else (
            f"python3 scripts/knowledge-store.py cutover --to <{target} brain.stores id>"
        )
    deploy = settings.deploy
    return {
        "tier": tier,
        "store": store,
        "blobs": settings.brain.get("blobs", "git"),
        "vectors": (
            "none" if not settings.features.get("semantic_search", False)
            else settings.semantic.get("substrate", "local")
        ),
        "graduation": {
            "needed": needed,
            "threshold_nodes": threshold,
            "current_nodes": nodes,
            "authority": driver,
            "to": next_driver,
            "reason": (
                f"{nodes} nodes exceeds graduate_at_nodes={threshold}; see {_HOSTING_DOC} "
                f"for the graduation options at this scale (adopted authority: {driver or 'unknown'})"
            ) if needed else None,
            "doc": _HOSTING_DOC,
            "next_cell": _AUTHORITY_CELL.get(next_driver),
            "action": action,
            "d1": {
                "doc": _D1_DOC,
                "action": "make brain-d1-push  # after setting brain.store: d1 and features.brain_d1; never an authority (ADR #198)",
            } if needed else None,
        },
        "deploy": {
            "target": deploy.get("target", "cloudflare-worker"),
            "persistence": sorted(deploy.get("persistence", ()) or ()) or ["none"],
            "replicas": deploy.get("replicas", None),
        },
    }


def _policy(schema: dict) -> dict:
    """The publish-upward contract. Defaults are CLOSED: an instance that has
    declared nothing publishes nothing, because the failure mode here is a
    company brain quietly inhaling an engagement's confidential fragments, and
    that must require an explicit act."""
    fed = settings.federation
    declared_kinds = {k["id"] for k in schema.get("kinds", [])}
    publishes = sorted(set(fed.get("publishes", ()) or ()) & declared_kinds)
    withholds = sorted(set(fed.get("withholds", ()) or ()) & declared_kinds)
    return {
        "access_gate": os.path.exists(os.path.join(ROOT, "access.js")),
        "publishes": publishes,
        "withholds": withholds or sorted(declared_kinds - set(publishes)),
    }


def build() -> dict:
    schema = _load(SCHEMA)
    meta = _load(BRAIN_META)
    gates = _load(GATES)
    canon = canon_paths(schema)
    inventory = _inventory(schema, meta)

    projections = []
    for resolution, artifact, enabled_for in PROJECTIONS:
        present = os.path.exists(os.path.join(ROOT, artifact))
        projections.append({
            "resolution": resolution,
            "artifact": artifact,
            "enabled": bool(enabled_for(settings)),
            "present": present,
            "lag_commits": lag_commits(artifact, canon) if present else None,
        })
    projections.sort(key=lambda p: p["resolution"])

    manifest = {
        "manifest": "brain-manifest/v1",
        "generator": "gen-manifest",
        "generated": datetime.date.today().isoformat(),
        "identity": {
            "id": settings.get("client", "slug", default="") or "",
            "name": settings.get("brain", "name", default="") or "",
            "engagement": settings.get("client", "engagement", default="") or "",
            "domain": settings.get("client", "domain", default="") or "",
        },
        "scope": _scope(schema),
        "profile": _profile(schema),
        "engine": {
            "brain_version": str(meta["version"]) if meta.get("version") is not None else None,
            "schema_present": bool(schema),
            "gates": len(gates.get("gates", [])),
            "template_sync": template_sync(_load(SYNC_STAMP)),
        },
        "inventory": inventory,
        "projections": projections,
        "substrate": _substrate(inventory["nodes"]),
        "policy": _policy(schema),
        "surfaces": {
            "portal": settings.get("client", "domain", default=None) or None,
            "chat": "/api/chat",
            "store": settings.brain.get("store", "json"),
            "template": settings.portal.get("template", "engagement"),
            "features": sorted(
                k for k, v in dict(settings.features.raw()).items()
                if v is True and not k.startswith("$")
            ),
        },
        "federation": {"children": sorted(settings.federation.get("children", ()) or ())},
    }
    return manifest


def main() -> int:
    manifest = build()
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1)
        f.write("\n")
    scope = manifest["scope"]
    inv = manifest["inventory"]
    print(
        f"Wrote {os.path.relpath(OUT, ROOT)} "
        f"({scope['level']}:{scope['id'] or '—'}, "
        f"{inv['kinds_populated']}/{inv['kinds_declared']} kinds populated, "
        f"substrate {manifest['substrate']['tier']})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
