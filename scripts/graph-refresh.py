#!/usr/bin/env python3
"""Refresh the local KG pipeline with a source receipt, or inspect it read-only."""
import argparse
import json
from pathlib import Path
import subprocess

from projection_freshness import observe, refresh


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--check', action='store_true', help='Read-only JSON; exits 2 for stale/unknown')
    args = parser.parse_args()
    if args.check:
        report = observe(args.root)
        print(json.dumps(report, sort_keys=True))
        return 0 if report['state'] == 'current' else 2
    try:
        refresh(args.root)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f'Graph refresh failed; receipt not advanced: {exc}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
