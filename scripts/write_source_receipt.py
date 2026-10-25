#!/usr/bin/env python3
"""Write the optional portal image's host-attested graph receipt."""

from __future__ import annotations

import argparse

import source_receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--validate-source-commit", action="store_true")
    parser.add_argument("source_commit", nargs="?")
    parser.add_argument("graph", nargs="?")
    parser.add_argument("output", nargs="?")
    parser.add_argument("--artifact-root")
    parser.add_argument("--artifact-output")
    args = parser.parse_args()
    if args.validate_source_commit:
        if (args.source_commit is None or args.graph is not None or args.output is not None
                or args.artifact_root is not None or args.artifact_output is not None):
            parser.error("--validate-source-commit takes exactly one source commit")
        try:
            source_receipt.validate_source_commit(args.source_commit)
        except ValueError as exc:
            parser.error(str(exc))
        return 0
    if args.source_commit is None or args.graph is None or args.output is None:
        parser.error("source_commit, graph and output are required")
    if bool(args.artifact_root) != bool(args.artifact_output):
        parser.error("--artifact-root and --artifact-output must be supplied together")
    if args.source_commit == "":
        return 0
    graph_raw = source_receipt._read_graph(args.graph)
    receipt = source_receipt.create_receipt_from_bytes(args.source_commit, graph_raw)
    manifest = None
    if args.artifact_output:
        import source_artifact_manifest

        manifest = source_artifact_manifest.create_manifest(args.source_commit, graph_raw, args.artifact_root)
    source_receipt.write_receipt_bytes(args.output, receipt)
    if manifest is not None:
        source_artifact_manifest.write_manifest(args.artifact_output, manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
