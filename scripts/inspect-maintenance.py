#!/usr/bin/env python3
"""Inspect semantic maintenance findings through the pinned context host (#78)."""
import argparse
import datetime as dt
from functools import partial
import os
from pathlib import Path
import sys

from context_bundle import encode
from context_host import load_snapshot, read_json
from semantic_maintenance import inspect
from maintenance_audit import audit, operation


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--host-config", required=True)
    parser.add_argument("--actor", required=True, help="Trusted local operator identity, never a producer/request field")
    parser.add_argument("--now", help="Trusted authorization time for reproducible proofs")
    parser.add_argument("--request", type=Path, required=True, help="Existing bounded-context request")
    parser.add_argument("--max-findings", type=int, default=100)
    parser.add_argument("--max-bytes", type=int, default=262144)
    parser.add_argument("--output", type=Path, help="New private report file; stdout by default")
    args = parser.parse_args(argv)
    now = args.now or dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    try:
        if args.root.is_symlink():
            raise ValueError("Symlinked root")
        with audit(args.root) as journal:
            log = partial(operation, journal)

            try:
                snapshot = load_snapshot(args.root, args.host_config, actor=args.actor, now=now)
                query = read_json(args.request)
            except (ValueError, OSError, KeyError, TypeError):
                log("maintenance.rejected", "semantic-maintenance", "context", {"reason": "host-input-unavailable"})
                raise
            result = inspect(snapshot, query, max_findings=args.max_findings, max_bytes=args.max_bytes, log=log)
            raw = encode(result)
            try:
                if args.output:
                    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(descriptor, "wb") as output:
                        output.write(raw)
                else:
                    sys.stdout.buffer.write(raw)
            except OSError:
                log("maintenance.delivery-rejected", "semantic-maintenance", "report", {"reason": "output-unavailable"})
                raise
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f"inspect-maintenance: unavailable or invalid input ({type(exc).__name__})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
