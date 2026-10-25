#!/usr/bin/env python3
"""Prepare a new private Registry source proposal; never adopt or write the brain."""
import argparse
import json
from pathlib import Path
import sys

from context_host import decode
from ontology_source_proposal import MAX_INTENT, _stable, prepare, write_proposal


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--layer', required=True)
    parser.add_argument('--intent', required=True, type=Path)
    parser.add_argument('--next-revision', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        raw, _ = _stable(args.intent, MAX_INTENT)
        report, candidate, patch = prepare(args.root, args.layer, decode(raw), args.next_revision)
        summary = write_proposal(args.root, args.output, report, candidate, patch)
        print(json.dumps(summary, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, RecursionError) as exc:
        print('ontology-source-proposal: refused; source was not written; any partial new output is retained: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
