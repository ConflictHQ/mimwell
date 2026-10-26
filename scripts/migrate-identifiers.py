#!/usr/bin/env python3
"""Preview explicit owned JSON identifiers; apply only an exact reviewed plan.

Supported scopes are a JSON Schema's ROOT extension annotation and a KG
envelope's ROOT format marker. Nested knowledge, examples, defaults, signed
archives and native journals are not recursively rewritten. Reader aliases,
tokens and existing historical artifacts remain unchanged.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import sys

from operator_json_migration import (
    MigrationError, add_operator_arguments, decode, operator_action, preview, report_preview, rewrite_root,
)


OLD_KG = "conflict-kg/v1"
NEW_KG = "mimwell-kg/v1"
TOOL = "mimwell-owned-identifiers/v1"
KINDS = ("auto", "schema-root", "kg")


def transform(value, kind=None):
    """Change only the reviewed artifact scope, never arbitrary nested keys."""
    kind = kind or "auto"
    if not isinstance(value, dict):
        raise MigrationError("selected identifier artifact must be an object")
    if kind == "auto":
        if value.get("format") in (OLD_KG, NEW_KG, "calliope-kg/v1"):
            kind = "kg"
        elif isinstance(value.get("$schema"), str):
            kind = "schema-root"
        else:
            raise MigrationError("declare --kind schema-root or --kind kg; no arbitrary JSON inference")
    result = deepcopy(value)
    if any(key in value for key in ("sha256", "checksum", "signature", "signatures", "journal")):
        raise MigrationError("integrity-bound archives/history require their own verified workflow")
    if kind == "schema-root":
        envelope = value.get("format")
        if (isinstance(envelope, str) and envelope.startswith("brain-exchange/")
                or value.get("kind") == "calliope.brain" or "journal" in value):
            raise MigrationError("archives and native journals require their own verified workflow")
        if "x-conflict" not in value:
            return result, [], kind
        if "x-mimwell" in value:
            raise MigrationError("schema extension collision: both x-conflict and x-mimwell exist")
        if not isinstance(value["x-conflict"], dict):
            raise MigrationError("schema root extension must be an object")
        result = {("x-mimwell" if key == "x-conflict" else key): item
                  for key, item in result.items()}
        return result, [{"pointer": "/x-conflict", "replacement": "/x-mimwell"}], kind
    if kind == "kg":
        if ("format" in value and value["format"] not in (OLD_KG, NEW_KG, "calliope-kg/v1")
                or not isinstance(value.get("nodes"), list) or not isinstance(value.get("edges"), list)
                or any(not isinstance(item, dict) for group in ("nodes", "edges") for item in value[group])):
            raise MigrationError("selected KG needs a supported envelope with node/edge object arrays")
        if value.get("format") == NEW_KG:
            return result, [], kind
        result["format"] = NEW_KG
        return result, [{"pointer": "/format", "from": value.get("format"), "to": NEW_KG}], kind
    raise MigrationError("unsupported owned identifier migration kind")


def render(value, raw, kind):
    if kind == "schema-root":
        output = rewrite_root(raw, rename=("x-conflict", "x-mimwell"))
    elif kind == "kg":
        output = rewrite_root(raw, replace=("format", NEW_KG))
    else:
        raise MigrationError("unsupported identifier render scope")
    if decode(output) != value:
        raise MigrationError("identifier-only output differs from its exact preview")
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, help="explicit owned current JSON artifacts")
    parser.add_argument("--kind", choices=KINDS, default="auto", help="scope of selected owned formats")
    add_operator_arguments(parser)
    args = parser.parse_args(argv)

    def convert(value, kind=None):
        return transform(value, kind or args.kind)

    try:
        action = any((args.apply, args.apply_plan, args.resume, args.restore_preimages))
        if action and args.paths and not args.apply:
            raise MigrationError("apply/recovery uses only the exact plan's selected paths")
        result = operator_action(args, tool=TOOL, convert=convert, serialize=render,
                                 tool_files=[__file__])
        if result is None:
            plan = preview(args.paths, tool=TOOL, transform=convert, serialize=render, tool_files=[__file__])
            result = report_preview(plan, args.plan)
        print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
        return 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"migrate-identifiers: {exc}; retain any existing recovery directory", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
