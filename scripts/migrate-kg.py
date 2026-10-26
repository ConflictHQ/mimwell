#!/usr/bin/env python3
"""Migrate the extracted knowledge graph to the current format version (#25).

The KG self-describes its format with `format: "mimwell-kg/vN"`
(build-kg.py stamps KG_FORMAT). This mirrors scripts/migrate-brain.py's
framework exactly — same registry shape, same v1-empty-registry baseline, same
downgrade policy — applied to the KG envelope instead of the brain. Read
migrate-brain.py's module docstring for the full rationale; this file states
only what differs.

Differs from migrate-brain.py
------------------------------
The KG's version lives in a STRING (`"mimwell-kg/v1"`), not a bare integer, so
version comparison/increment here parses the trailing digits rather than
comparing ints directly. A KG with no `format` key (a legacy/hand-built file
predating the stamp) is treated as `_EARLIEST` ("conflict-kg/v1"), same
earliest-version fallback migrate-brain.py applies to a header-less brain.

v1 baseline
-----------
Ships with an EMPTY registry, matching the brain's v1 baseline — `migrate` is
an identity no-op that restamps `format` to the current value. The scaffold
below is the template for the first real KG migration; copy it, register it,
bump KG_VERSION in build-kg.py, add a fixture to tests/test_migrate_kg.py.

CLI
---
    python3 scripts/migrate-kg.py app/knowledge_graph.json          # exact preview
    python3 scripts/migrate-kg.py app/knowledge_graph.json -o out   # NEW private staged file
    python3 scripts/migrate-kg.py app/knowledge_graph.json --stdout # to stdout
    python3 scripts/migrate-kg.py --check app/knowledge_graph.json  # 0 if current, 2 if stale
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from copy import deepcopy

from operator_json_migration import (
    MigrationError, add_operator_arguments, decode, differences, operator_action,
    preview, report_preview, rewrite_root, sha256, snapshot, write_private_new,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KG = os.path.join(ROOT, "app", "knowledge_graph.json")


def _load_build_kg():
    """Load build-kg.py by file path (its hyphenated name is not importable) —
    the single source of truth for KG_FORMAT, mirroring migrate-brain.py's
    _load_gen_brain(). One owner, so the generator and this migrator can never
    disagree on what "current" means."""
    spec = importlib.util.spec_from_file_location(
        "build_kg", os.path.join(ROOT, "scripts", "build-kg.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_BUILD = _load_build_kg()
CURRENT_FORMAT = _BUILD.KG_FORMAT

_EARLIEST = "conflict-kg/v1"

_VERSION_RE = re.compile(r"^(?:conflict|mimwell)-kg/v(\d+)$")


def _version_num(fmt: str) -> int:
    m = _VERSION_RE.match(fmt)
    if not m:
        raise ValueError(f"unrecognized KG format string: {fmt!r} (expected conflict-kg/vN)")
    return int(m.group(1))


# ----------------------------------------------------------------------------
# Migration registry — ordered vN -> vN+1 transforms
# ----------------------------------------------------------------------------
#
# MIGRATIONS maps a FROM-format string to the transform that upgrades a KG at
# that format to the next one. Empty at v1 — register the first transform the
# day KG_VERSION becomes "conflict-kg/v2".

MIGRATIONS: dict[str, callable] = {}


def migration(from_format: str):
    """Register a `(envelope) -> envelope` transform that upgrades a KG FROM
    `from_format` to the next format. Decorated fns run in chained order."""
    def deco(fn):
        MIGRATIONS[str(from_format)] = fn
        return fn
    return deco


# --- EXAMPLE migration scaffold (NOT registered) ----------------------------
#
# Template for the first real KG migration — copy it, register with
# @migration("conflict-kg/v1"), bump CURRENT_FORMAT/KG_VERSION, add a fixture
# to tests/test_migrate_kg.py. Left unregistered so v1 stays an identity no-op.
#
# REVERSIBLE? Yes — drop the added `confidence` field to go back to v1.
def _example_v1_to_v2(env: dict) -> dict:
    """EXAMPLE (unregistered): a v1 -> v2 transform backfilling a default
    `confidence` on every edge. Pure: returns a new envelope."""
    edges = []
    for e in env.get("edges") or []:
        m = dict(e)
        m.setdefault("confidence", 1.0)
        edges.append(m)
    return {"nodes": list(env.get("nodes") or []), "edges": edges}


# ----------------------------------------------------------------------------
# Migrate
# ----------------------------------------------------------------------------


def _format_of(env: dict) -> str:
    """The KG's declared format, or `_EARLIEST` for a header-less/legacy KG."""
    fmt = env.get("format")
    return "conflict-kg/v1" if fmt == "calliope-kg/v1" else str(fmt) if fmt else _EARLIEST


def _restamp(env: dict) -> dict:
    """Re-emit the envelope in build-kg.py's exact {format, nodes, edges}
    shape at CURRENT_FORMAT. No sort/dedupe pass is imposed here — the KG
    pipeline's own merge/enrich/curate stages own canonicalization; a no-op
    migration therefore preserves node/edge ORDER exactly. The reviewed operator
    renderer below changes only the root marker's original byte token."""
    result = deepcopy(env)
    result.update(format=CURRENT_FORMAT, nodes=list(env.get("nodes") or []), edges=list(env.get("edges") or []))
    return result


def needs_migration(env: dict) -> bool:
    """True iff the KG's format is behind CURRENT_FORMAT."""
    return _format_of(env) != CURRENT_FORMAT


def migrate(env: dict) -> dict:
    """Upgrade a KG envelope to CURRENT_FORMAT by applying each registered
    vN -> vN+1 transform in order, then restamp the format string.

    Raises ValueError if the KG is NEWER than the tooling, or if the chain
    stalls (a gap in the registry) before reaching the current format."""
    fmt = _format_of(env)
    # The legacy v1 envelope has the same shape. Changing only its identifier
    # is an explicit, lossless migration; reads never rewrite stored files.
    if fmt == "conflict-kg/v1" and CURRENT_FORMAT == "mimwell-kg/v1":
        return _restamp(env)
    if _version_num(fmt) > _version_num(CURRENT_FORMAT):
        raise ValueError(
            f"KG format={fmt!r} is NEWER than this tooling's format "
            f"{CURRENT_FORMAT!r}; upgrade the template (downgrades are not "
            "auto-applied — see migrate-brain.py's downgrade policy, which "
            "this file mirrors).")
    guard = 0
    while fmt != CURRENT_FORMAT:
        transform = MIGRATIONS.get(fmt)
        if transform is None:
            raise ValueError(
                f"no migration registered FROM format {fmt!r} (cannot reach "
                f"{CURRENT_FORMAT!r}) — register one with @migration({fmt!r}).")
        env = transform(env)
        fmt = f"conflict-kg/v{_version_num(fmt) + 1}"
        guard += 1
        if guard > 999:  # impossible-loop guard
            raise ValueError("migration chain did not converge")
    return _restamp(env)


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------


def _serialize(env: dict) -> str:
    """The exact app/knowledge_graph.json byte shape build-kg.py emits."""
    return json.dumps(env, allow_nan=False)


def _operator_transform(env, kind=None):
    if (kind not in (None, "kg") or not isinstance(env, dict)
            or "format" in env and env["format"] not in (
                "conflict-kg/v1", "calliope-kg/v1", CURRENT_FORMAT)
            or not isinstance(env.get("nodes"), list) or not isinstance(env.get("edges"), list)
            or any(not isinstance(item, dict) for group in ("nodes", "edges") for item in env[group])
            or any(key in env for key in ("sha256", "checksum", "signature", "signatures", "journal"))):
        raise MigrationError("select an owned KG envelope, not history or an integrity-bound archive")
    updated = migrate(env)
    return updated, differences(env, updated), "kg"


def _operator_bytes(env, raw, kind):
    if kind != "kg":
        raise MigrationError("unsupported KG render scope")
    original = decode(raw)
    before, after = dict(original), dict(env)
    before.pop("format", None)
    after.pop("format", None)
    if before != after:
        raise MigrationError("content-version transforms need a separately reviewed lossless operator adapter")
    output = rewrite_root(raw, replace=("format", CURRENT_FORMAT))
    if decode(output) != env:
        raise MigrationError("KG-only output differs from its exact preview")
    return output


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Migrate the extracted KG envelope to the current format.")
    ap.add_argument("path", nargs="?",
                    help="KG JSON to migrate (default app/knowledge_graph.json)")
    ap.add_argument("-o", "--out", help="write the migrated KG here "
                    "(must be a new file in an owned private directory)")
    ap.add_argument("--stdout", action="store_true",
                    help="print the migrated KG to stdout (no file written)")
    ap.add_argument("--check", action="store_true",
                    help="report only: exit 0 if already current, 2 if a "
                         "migration is needed (writes nothing)")
    add_operator_arguments(ap)
    args = ap.parse_args(argv)
    try:
        action = any((args.apply, args.apply_plan, args.resume, args.restore_preimages))
        if action and any((args.path, args.out, args.stdout, args.check)) and not args.apply:
            raise MigrationError("apply/recovery selects only paths from its exact reviewed plan")
        result = operator_action(args, tool="mimwell-kg-operator/v1", convert=_operator_transform,
                                 serialize=_operator_bytes, tool_files=[__file__, _BUILD.__file__])
        if result is not None:
            print(json.dumps(result, indent=2, allow_nan=False))
            return 0
        if sum(bool(value) for value in (args.out, args.stdout, args.check, args.plan)) > 1:
            raise MigrationError("choose preview plan, check, stdout or a new staged output")
        path = args.path or KG
        if args.out or args.stdout or args.check:
            observed, raw = snapshot(path)
            migrated, changes, _ = _operator_transform(decode(raw))
            if args.check:
                print(f"{'stale' if changes else 'ok'}: {observed['path']}; input SHA-256 {observed['sha256']}")
                return 2 if changes else 0
            output = _operator_bytes(migrated, raw, "kg")
            if args.stdout:
                print(output.decode("utf-8"))
            else:
                write_private_new(args.out, output)
                print(json.dumps({"stagedOutput": str(args.out), "sourceWrites": 0,
                                  "inputSha256": observed["sha256"], "outputSha256": sha256(output)},
                                 indent=2))
            return 0
        plan = preview([path], tool="mimwell-kg-operator/v1", transform=_operator_transform,
                       serialize=_operator_bytes, tool_files=[__file__, _BUILD.__file__])
        print(json.dumps(report_preview(plan, args.plan), indent=2, allow_nan=False))
        return 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"migrate-kg: {exc}; retain any existing recovery directory", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
