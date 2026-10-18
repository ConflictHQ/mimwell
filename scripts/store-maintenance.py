#!/usr/bin/env python3
"""Run a host-authorized store/cache report or native maintenance operation."""
import argparse
import os
from pathlib import Path
import sqlite3
import sys

from knowledge_store import StoreError
from store_maintenance import MaintenanceError, execute, load_host


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--host-config", default="_internal/store-maintenance.json")
    commands = parser.add_subparsers(dest="operation", required=True)
    for name in ("store.inspect", "cache.maintain", "migration.report"):
        commands.add_parser(name)
    capture = commands.add_parser("snapshot.capture")
    capture.add_argument("--output", type=Path, required=True,
                         help="new snapshot directory under an operator-private parent")
    recover = commands.add_parser("snapshot.restore")
    recover.add_argument("--snapshot", type=Path, required=True)
    recover.add_argument("--output", type=Path, required=True,
                         help="new isolated repository under an operator-private parent")
    args = parser.parse_args(argv)
    try:
        def identity():
            host = load_host(args.root, args.host_config)
            return host["raw"]["principalsByUid"].get(str(os.geteuid()))

        request_args = {key: str(getattr(args, key)) for key in ("output", "snapshot")
                        if hasattr(args, key)}
        result = execute(args.root, args.host_config,
                         {"format": "store-maintenance-request/v1", "operation": args.operation,
                          "arguments": request_args}, authorize=identity)
        sys.stdout.buffer.write(result)
        return 0
    except (MaintenanceError, OSError, StoreError, sqlite3.Error, ValueError, KeyError, TypeError) as exc:
        print(f"store-maintenance: unavailable or invalid operation ({type(exc).__name__})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
