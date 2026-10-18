#!/usr/bin/env python3
"""Normalize one documented local platform export to connector-event/v1 JSONL."""
import argparse
import json
import os
import stat
import sys

from platform_export_adapters import (CAPABILITIES, MAX_ARCHIVE_BYTES, ExportAdapterError,
                                      normalize)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capabilities", action="store_true",
                        help="print the versioned offline adapter capability matrix")
    parser.add_argument("--platform", choices=("slack", "teams", "zoom", "discord"))
    parser.add_argument("--namespace", help="operator-selected namespace: export:<platform>/<source>")
    parser.add_argument("input", nargs="?", help="operator-selected ZIP or saved JSON response")
    args = parser.parse_args()
    if args.capabilities:
        print(json.dumps(CAPABILITIES, ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    if not args.platform or not args.namespace or not args.input:
        parser.error("--platform, --namespace, and input are required")
    try:
        descriptor = os.open(args.input, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_ARCHIVE_BYTES:
                raise ExportAdapterError("Selected export must be a bounded regular file")
            raw = source.read(MAX_ARCHIVE_BYTES + 1)
        if len(raw) > MAX_ARCHIVE_BYTES:
            raise ExportAdapterError("Selected export exceeds the source-byte bound")
        for line in normalize(args.platform, raw, args.namespace):
            sys.stdout.buffer.write(line)
    except (OSError, ExportAdapterError) as exc:
        print(f"platform export refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
