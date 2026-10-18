#!/usr/bin/env python3
"""Push the compiled brain into Cloudflare D1 (#37) — the deploy-side sync.

Gated, idempotent, deterministic. Emits app/brain.d1.sql from the canonical brain
(brain-sqlite.py d1-export) and loads it into the D1 database bound as `DB` via
`wrangler d1 execute`. D1 serves the COMPILED, READ-ONLY brain at the edge; it is
a projection of app/brain.json, never an authority.

PRECONDITION — the same rule worker.js uses to read D1: features.brain_d1 AND
brain.store == "d1". With the flag off nothing is pushed and the worker serves
JSON-in-memory (brain.store "d1" alone is a clean fallback). With the flag on and
any other store the config is inconsistent — the worker would never read the
database this pushes — so the precondition fails (exit 1).

When canon is a store cell (brain.authority adopted), D1 materializes only from a
receipted projection (#232): the receipts must verify and app/brain.json must hold
what they deliver; `projections: live` has none and fails (receipted_projections).

    brain-d1-deploy.py            precondition, export, `wrangler d1 execute --remote`
    brain-d1-deploy.py --check    precondition and receipts only; prints true|false (serve from D1)
    brain-d1-deploy.py --export   precondition, then export only (a deployment workflow
                                  can run the pinned wrangler itself)

No secrets/account ids here: the database is resolved from the `DB` binding in
wrangler.toml ([[d1_databases]] — enabled per-engagement, database_id untracked).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

# brain-sqlite.py is hyphenated; load it by path like the tests/CLI do.
import importlib.util

from config import settings
from knowledge_store import StoreError, adopted_authority

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_brain_sqlite():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "brain-sqlite.py")
    spec = importlib.util.spec_from_file_location("brain_sqlite", path)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def precondition(features_d1: bool, store: str) -> tuple[bool, str]:
    """(serve from D1?, message). Raises SystemExit(1) on an inconsistent config."""
    if not features_d1:
        return False, (f"features.brain_d1 is off (brain.store={store!r}) — nothing to "
                       "push; the worker serves app/brain.json in memory.")
    if store != "d1":
        print(f"brain-d1-deploy: features.brain_d1 is on but brain.store is {store!r}; "
              "the worker reads D1 only when brain.store is 'd1'. Set brain.store to "
              "'d1' or turn the feature off.", file=sys.stderr)
        raise SystemExit(1)
    return True, "features.brain_d1 on and brain.store='d1' — serving from D1."


def _refuse(message: str):
    print(f"brain-d1-deploy: {message}", file=sys.stderr)
    raise SystemExit(1)


def receipted_projections(root: str) -> list[dict]:
    """The receipts a D1 load materializes from when canon is a store cell (#232).

    Canon in `files` (no brain.authority): [] — app/brain.json compiles from git.
    Canon in a store: app/brain.json must be compiled from receipted delivered
    projections (`projections: committed`, gen-brain's projections adapter), every
    receipt must verify (projection_receipts.load), and every projected node must be
    in app/brain.json as delivered, or the load would ship a brain older than its
    receipts. `projections: live` commits nothing to materialize, so it is refused:
    the Worker proxies the context service instead (#229). Raises SystemExit(1).
    """
    with open(os.path.join(root, "client.config.json"), encoding="utf-8") as stream:
        raw = json.load(stream)
    try:
        authority = adopted_authority(raw)
    except StoreError as exc:
        _refuse(str(exc))
    if not authority:
        return []
    mode = authority.get("projections")
    if mode != "committed":
        _refuse(f"canon is a store cell with projections={mode!r}; D1 materializes only from a receipted "
                "projection (projections: committed). Under projections: live the Worker proxies the "
                "context service; turn features.brain_d1 off.")
    from projection_receipts import ProjectionError, load
    try:
        delivered = load(root, authority["binding"])
    except (ProjectionError, ValueError, OSError, KeyError) as exc:
        _refuse(f"receipted projection check failed: {exc}")
    if not delivered:
        _refuse("canon is a store cell but app/projections/ holds no receipted projection to materialize")
    with open(os.path.join(root, "app", "brain.json"), encoding="utf-8") as stream:
        compiled = {node["id"]: node for node in json.load(stream)["nodes"]}
    for consumer, payload, _receipt in delivered:
        for node in payload["graph"]["nodes"]:
            held = compiled.get(node["id"])
            if held is None or any(held.get(key) != value for key, value in node.items()):
                _refuse(f"app/brain.json does not hold {consumer}'s receipted node {node['id']} as delivered; "
                        "run make build")
    return [{"consumer": consumer, **receipt} for consumer, _payload, receipt in delivered]


def main(argv: list[str]) -> int:
    mode = argv[0] if argv else ""
    if mode not in ("", "--check", "--export"):
        print(__doc__, file=sys.stderr)
        return 2
    serve, message = precondition(bool(settings.features.brain_d1), settings.brain.store)
    print(f"brain-d1-deploy: {message}", file=sys.stderr)
    if serve:
        for receipt in receipted_projections(ROOT):
            print(f"brain-d1-deploy: materializing from {receipt['consumer']} at sequence "
                  f"{receipt['sequence']} (sha256 {receipt['sha256']})", file=sys.stderr)
    if mode == "--check":
        print("true" if serve else "false")
        return 0
    if not serve:
        return 0

    brain_sqlite = _load_brain_sqlite()
    out = brain_sqlite.d1_export()
    rel = os.path.relpath(out, ROOT)
    print(f"brain-d1-deploy: emitted {rel}", file=sys.stderr)
    if mode == "--export":
        return 0

    cmd = ["npx", "wrangler", "d1", "execute", "DB", "--remote", f"--file={rel}"]
    print("brain-d1-deploy: " + " ".join(cmd), file=sys.stderr)
    try:
        return subprocess.call(cmd, cwd=ROOT)
    except FileNotFoundError:
        print("brain-d1-deploy: wrangler not found — install it or run the deploy "
              "in CI where wrangler is available.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
