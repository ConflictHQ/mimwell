#!/usr/bin/env python3
"""Propose an explicit learned correction through the existing protected writer."""
import argparse
from pathlib import Path
import sys

from context_host import decode
from knowledge_operations import MAX_REQUEST_BYTES
from learned_proposals import propose


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--host-config', default='_internal/knowledge-operations.json')
    parser.add_argument('--input', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        with args.input.open('rb') as stream:
            raw = stream.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError('Input exceeds its limit')
        result = propose(args.root, args.host_config, decode(raw))
        sys.stdout.buffer.write(result)
        return 0
    except (ValueError, OSError, KeyError, TypeError, RecursionError):
        print('learned-change: unavailable or invalid proposal', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
