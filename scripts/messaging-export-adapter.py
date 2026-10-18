#!/usr/bin/env python3
"""Convert selected messaging exports into connector-event/v1 JSONL snapshots.

This tool never registers a host snapshot or performs network/platform access.
"""
import argparse
import sys

from intake_capture import CaptureError, read_stable
from messaging_export_adapters import (ExportAdapterError, MAX_SOURCE_BYTES,
                                       parse_signal_bridge, parse_telegram_json,
                                       parse_whatsapp_text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='source_kind', required=True)
    whatsapp = sub.add_parser('whatsapp', help='convert a profiled WhatsApp chat text export')
    telegram = sub.add_parser('telegram', help='convert one Telegram Desktop JSON chat export')
    signal = sub.add_parser('signal-bridge', help='convert an operator-produced Signal bridge manifest')
    for command in (whatsapp, telegram, signal):
        command.add_argument('--root', required=True, help='absolute selected export directory; no symlink traversal')
        command.add_argument('--source', required=True, help='relative source file path below --root')
        command.add_argument('--namespace', required=True, help='operator-selected registered connector namespace')
        command.add_argument('--observed-at', help='optional explicit RFC 3339 observation time; omitted means unknown')
    whatsapp.add_argument('--profile', required=True, choices=('android-en-US', 'ios-en-US'))
    whatsapp.add_argument('--timezone', required=True, help='explicit IANA timezone for local export timestamps')
    telegram.add_argument('--timezone', help='IANA timezone required only when source JSON dates are local/naive')
    args = parser.parse_args(argv)
    try:
        raw, _ = read_stable(args.root, args.source, MAX_SOURCE_BYTES)
        if args.source_kind == 'whatsapp':
            output = parse_whatsapp_text(raw, namespace=args.namespace, profile=args.profile,
                                         timezone_name=args.timezone, observed_at=args.observed_at)
        elif args.source_kind == 'telegram':
            output = parse_telegram_json(raw, namespace=args.namespace, timezone_name=args.timezone,
                                         observed_at=args.observed_at)
        else:
            output = parse_signal_bridge(raw, namespace=args.namespace, observed_at=args.observed_at)
    except (ExportAdapterError, CaptureError, OSError, ValueError) as exc:
        print(f'messaging-export-adapter: {exc}', file=sys.stderr)
        return 2
    # Nothing is written until the entire bounded source has parsed and validated.
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
