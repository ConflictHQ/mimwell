#!/usr/bin/env python3
"""Validate every installed app against its adopted recipe/authority."""
import argparse
import datetime as dt
from pathlib import Path
from brain_apps import check_all

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        apps = check_all(args.root, dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'))
        print(f'OK: brain-apps: {sum(app.get("enabled", True) for app in apps)} enabled, {sum(not app.get("enabled", True) for app in apps)} disabled draft(s)')
    except (ValueError, OSError, KeyError) as exc:
        parser.exit(1, str(exc) + '\n')

if __name__ == '__main__':
    main()
