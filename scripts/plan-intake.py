#!/usr/bin/env python3
"""Plan a bounded batch of intake proposals through current pinned host policy (#132)."""
import argparse
import datetime as dt
from functools import partial
import os
from pathlib import Path
import sys

from context_bundle import encode
from context_host import read_json
from intake_host import load_planner
from maintenance_audit import audit, operation


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--host-config', required=True)
    parser.add_argument('--actor', required=True, help='Trusted operator identity, never forwarded from request/model input')
    parser.add_argument('--now', help='Trusted authorization time; defaults to current UTC')
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--output', type=Path, help='New private file; stdout by default')
    args = parser.parse_args(argv)
    now = args.now or dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')
    try:
        if args.root.is_symlink():
            raise ValueError('Symlinked root')
        with audit(args.root) as journal:
            log = partial(operation, journal)
            planner = load_planner(args.root, args.host_config, actor=args.actor, now=now, log=log)
            result = planner.plan(read_json(args.request))
            raw = encode(result)
            if args.output:
                descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, 'wb') as output:
                    output.write(raw)
            else:
                sys.stdout.buffer.write(raw)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f'plan-intake: invalid or unavailable input ({type(exc).__name__})', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
