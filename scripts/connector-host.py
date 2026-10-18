#!/usr/bin/env python3
"""Inspect and run the local registered connector-export host."""
import argparse
from pathlib import Path
import sys

from context_bundle import encode
from connector_host import ConnectorHost


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--host-config', default='_internal/knowledge-operations.json')
    parser.add_argument('--authority', default='selected')
    parser.add_argument('--namespace')
    parser.add_argument('--export')
    parser.add_argument('--stdin', action='store_true', help='Observe bytes matching the independently pinned export')
    parser.add_argument('--dead-letters', action='store_true')
    parser.add_argument('--replay-line', type=int)
    args = parser.parse_args(argv)
    if args.stdin and (not args.export or not args.namespace or args.dead_letters or args.replay_line is not None):
        parser.error('--stdin requires only --namespace and --export')
    host = ConnectorHost(args.root, args.host_config, args.authority)
    try:
        if args.dead_letters:
            result = {'format': 'connector-dead-letters/v1', 'items': host.dead_letters()}
        elif args.replay_line is not None:
            if not args.namespace or not args.export:
                parser.error('--replay-line requires --namespace and --export')
            result = host.replay_dead_letter(args.namespace, args.export, args.replay_line)
        elif args.stdin:
            result = host.import_stdin(args.namespace, args.export, sys.stdin.buffer)
        elif args.export:
            if not args.namespace:
                parser.error('--export requires --namespace')
            result = host.import_export(args.namespace, args.export)
        else:
            result = host.capability_report(args.namespace)
        sys.stdout.buffer.write(encode(result) + b'\n')
        return 0
    except (ValueError, OSError) as exc:
        sys.stderr.write('connector-host: ' + str(exc) + '\n')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
