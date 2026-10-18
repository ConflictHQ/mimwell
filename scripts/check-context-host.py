#!/usr/bin/env python3
"""Operator check for a context host configuration (#443).

The context HTTP endpoint answers every failure with an empty body, so it never
leaks paths, pins or records across the network boundary. That leaves an
operator setting up a host locally with no way to see which rule failed. This
command loads the same snapshot the endpoint would serve, in-process, and prints
the reason when it cannot:

    python3 scripts/check-context-host.py --root . --host-config <file> --actor <id>

Exit 0 when the snapshot loads, 1 with the failing rule otherwise. It is a
local diagnostic: never expose its output over the network.
"""
import argparse
import datetime as dt
from pathlib import Path
import sys

from context_host import load_snapshot


def explain(exc):
    lines, seen = [], set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        lines.append(f"  {type(exc).__name__}: {exc}" if str(exc) else f"  {type(exc).__name__}")
        exc = exc.__cause__ or exc.__context__
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--host-config", required=True)
    parser.add_argument("--actor", required=True, help="The identity to authorize, as the host would")
    parser.add_argument("--now", help="Authorization time; defaults to current UTC")
    args = parser.parse_args(argv)
    now = args.now or dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    try:
        snapshot = load_snapshot(args.root, args.host_config, actor=args.actor, now=now)
    except Exception as exc:  # noqa: BLE001 - the point is to report any refusal
        print("check-context-host: the endpoint would refuse this configuration", file=sys.stderr)
        print(explain(exc), file=sys.stderr)
        return 1
    revision = getattr(snapshot, "revision", None)
    print(f"check-context-host: ok{f' (revision {revision})' if revision else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
