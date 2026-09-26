#!/usr/bin/env python3
"""Run a shared knowledge operation as the host-mapped local principal."""

import argparse
import os
from pathlib import Path
import sys

from context_host import read_json
from knowledge_operations import load_host, run


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--host-config", default="_internal/knowledge-operations.json")
    parser.add_argument("--request", required=True, type=Path)
    args = parser.parse_args(argv)
    try:

        def identity():
            host = load_host(args.root, args.host_config)
            return host["principalsByUid"].get(str(os.geteuid()))

        actor = identity()
        if not actor:
            raise ValueError("Local principal unavailable")
        sys.stdout.buffer.write(
            run(args.root, args.host_config, read_json(args.request), actor=actor, authorize=identity)
        )
        return 0
    except (ValueError, OSError, KeyError, TypeError):
        print("knowledge-operations: unavailable or invalid input", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
