#!/usr/bin/env python3
"""Verify committed delivered projections by receipt, not byte-compare (#228).

Applies only to a brain whose client.config.json adopts `brain.authority` with
`projections: committed`; every other brain passes trivially. Fails when a
projection's sha256 differs from its receipt, when a receipt's binding differs
from the adopted contract binding, or, when the authority is reachable, when the
receipt claims a sequence beyond the authority's current delivery preview.

The authority DSN is `--dsn`, else $BRAIN_AUTHORITY_DSN, else the adopted
`brain.authority.store` resolved through `brain.stores[].dsn` when that names an
existing file (the sqlite cell). Without one the sequence check is reported as
skipped and outbox lag as unknown.

Scheduled refresh jobs pass `--fail-on-lag` (#81): publication then requires
every receipt to be proven current. An authority whose outbox is ahead of a
receipt fails (stale), and so does a run with no reachable authority (unknown),
matching the stale/unknown convention in docs/primitives/projection-freshness.md.
The DSN is a local SQLite path, so the job must run on a host that holds the
authority file; a hosted runner's checkout never does (`_internal/` is ignored).

Run from the brain root:  python3 scripts/check-projection-receipts.py
"""
import argparse
import json
import os
from pathlib import Path
import sys

from knowledge_store import StoreError, adopted_authority, resolve_store_dsn
from projection_freshness import observe_delivered
from projection_receipts import ProjectionError

ROOT = Path(__file__).resolve().parents[1]


def dsn(root, settings, authority, explicit):
    value = explicit or os.environ.get("BRAIN_AUTHORITY_DSN")
    if value:
        return Path(value)
    try:
        adopted = root / resolve_store_dsn(settings, authority["store"])
    except StoreError:
        return None
    return adopted if adopted.is_file() else None


def check(root, explicit_dsn=None, fail_on_lag=False):
    config = json.loads((root / "client.config.json").read_text())
    authority = (config.get("brain") or {}).get("authority")
    if not authority or authority.get("projections") != "committed":
        return {"applies": False, "errors": [], "projections": []}
    store = None
    try:
        adopted_authority(config)
        path = dsn(root, config, authority, explicit_dsn)
        if path is not None:
            from knowledge_store import SQLiteAuthority
            store = SQLiteAuthority(path, expected_binding=authority["binding"])
        observed = observe_delivered(root, authority["binding"], store)
    except (ProjectionError, ValueError, OSError, KeyError, TypeError) as exc:
        return {"applies": True, "errors": [str(exc)], "projections": []}
    finally:
        if store is not None:
            store.close()
    errors = [f"{p['consumer']}: receipt sequence {p['sequence']} is ahead of the authority head {p['head']}"
              for p in observed if p["state"] == "invalid"]
    if fail_on_lag:
        errors += [f"{p['consumer']}: outbox lag {p['lag']} (receipt sequence {p['sequence']}, authority head "
                   f"{p['head']}); redeliver the projection before publishing"
                   for p in observed if p["state"] == "stale"]
        errors += [f"{p['consumer']}: outbox lag unknown (no authority DSN on this host); a scheduled refresh "
                   f"cannot publish a projection it has not proven current"
                   for p in observed if p["state"] == "unknown"]
    return {"applies": True, "sequenceChecked": path is not None,
            "errors": errors, "projections": observed}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--dsn", help="authority location (sqlite path) for the sequence check")
    parser.add_argument("--json", action="store_true", help="print the full report")
    parser.add_argument("--fail-on-lag", action="store_true",
                        help="also fail unless every receipt is proven current: stale or unknown lag fails (scheduled refresh)")
    args = parser.parse_args(argv)
    report = check(args.root, args.dsn, args.fail_on_lag)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    if not report["applies"]:
        print("OK: check-projection-receipts — no committed projections declared")
        return 0
    for error in report["errors"]:
        print(f"ERROR: {error}", file=sys.stderr)
    if report["errors"]:
        return 1
    if not report["sequenceChecked"]:
        print("SKIP: no authority DSN available; sequence check not run, outbox lag unknown")
    for p in report["projections"]:
        print(f"  {p['consumer']}: sequence={p['sequence']} head={p['head']} lag={p['lag']} ({p['reason']})")
    print(f"OK: check-projection-receipts — {len(report['projections'])} receipted projection(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
