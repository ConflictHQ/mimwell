#!/usr/bin/env python3
"""Preview or run file-brain generation in a private job clone; stdout is JSON."""
import argparse
import json
import signal

from host_rebuild import run_job


def main(argv=None):
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--output", help="new job directory under an existing operator-private parent")
    parser.add_argument("--mode", choices=("build", "ingest"), default="build")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--pass-env", action="append", default=[], metavar="NAME")
    parser.add_argument("--recordings", help="explicit input recording directory, copied only in ingest mode")
    args = parser.parse_args(argv)
    code, summary = run_job(args.root, args.output, mode=args.mode, execute=args.execute,
                            timeout=args.timeout, pass_env=args.pass_env, recordings=args.recordings)
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
