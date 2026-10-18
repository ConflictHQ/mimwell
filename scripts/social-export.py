#!/usr/bin/env python3
"""Normalize an operator-selected local social export to connector-event/v1."""
import argparse
import json
import sys

from social_export_adapters import (CAPABILITIES, MAX_ARCHIVE_BYTES, MAX_MAPPING_BYTES,
                                    SocialExportError, load_mapping, normalize, read_stable_file)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capabilities', action='store_true', help='print the versioned capability matrix')
    parser.add_argument('--platform', choices=tuple(CAPABILITIES['adapters']))
    parser.add_argument('--namespace', help='operator-selected registered namespace')
    parser.add_argument('--member', help='exact selected ZIP member path')
    parser.add_argument('--mapping', help='local inert operator-json-map/v1 file for bridge profiles')
    parser.add_argument('input', nargs='?', help='operator-selected ZIP or JSON snapshot')
    args = parser.parse_args()
    if args.capabilities:
        print(json.dumps(CAPABILITIES, ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    if not args.platform or not args.namespace or not args.input:
        parser.error('--platform, --namespace, and input are required')
    try:
        raw = read_stable_file(args.input, MAX_ARCHIVE_BYTES)
        mapping = load_mapping(read_stable_file(args.mapping, MAX_MAPPING_BYTES), args.platform) if args.mapping else None
        for line in normalize(args.platform, raw, args.namespace, member=args.member, mapping=mapping):
            sys.stdout.buffer.write(line)
    except (OSError, SocialExportError) as exc:
        print(f'social export refused: {exc}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
