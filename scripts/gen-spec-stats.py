#!/usr/bin/env python3
"""Generate specs/stats.json — the live spec stats as a committed artifact, for
/specs/stats.html (#32).

scripts/spec-stats.py already computes this (critical path via `longest`, the
gate walk via `gated`, the id-subtree filter via `under`/`stories_under`) and
prints it to stdout; that CLI stays the `make spec-stats` terminal command,
unchanged. This wrapper imports its computation instead of duplicating it, and
writes the same numbers as JSON. The committed artifact always reports the
WHOLE plan (no id-prefix scoping — a checked-in artifact represents the plan
for every viewer, not one CLI invocation's slice); `--gate PREFIX` is honored
exactly like the CLI's own flag, defaulting to unconfigured (no gate split)
when omitted, same as `make spec-stats` prints no gate section without one.

Usage:
  python3 scripts/gen-spec-stats.py [--gate PREFIX]

Run from anywhere.
"""
from __future__ import annotations

import collections
import importlib.util
import json
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "specs" / "stats.json"
SPEC_STATS = ROOT / "scripts" / "spec-stats.py"


def _spec_stats():
    """Load spec-stats.py for its computation (hyphenated name -> not `import`able)."""
    spec = importlib.util.spec_from_file_location("spec_stats", SPEC_STATS)
    if not spec or not spec.loader:
        raise SystemExit(f"cannot load {SPEC_STATS}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build(ss, gate: str | None = None) -> dict:
    nodes = ss.ITEMS
    stories = ss.stories_under(None)

    size_counts = collections.Counter(s.get("estimate") for s in stories)
    unsized = size_counts.pop("", 0) + size_counts.pop(None, 0)

    by_feature: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for s in stories:
        feat = s["id"].rsplit("/", 1)[0] if "/" in s["id"] else s["id"]
        by_feature[feat][s.get("estimate") or "(unsized)"] += 1
    size_by_feature = [
        {"id": fid, "label": fid.rsplit("/", 1)[-1] if "/" in fid else fid,
         "counts": dict(by_feature[fid])}
        for fid in sorted(by_feature)
    ]

    cp_len, cp_ids = max((ss.longest(s["id"]) for s in stories), key=lambda t: t[0]) if stories else (0, [])
    critical_path = [
        {"id": nid, "title": ss.BY[nid].get("title", nid), "estimate": ss.BY[nid].get("estimate") or None}
        for nid in cp_ids if nid in ss.BY
    ]

    gate_split = None
    if gate:
        gated_count = sum(ss.gated(s["id"], gate) for s in stories)
        gate_split = {"pre_gate": len(stories) - gated_count, "gated": gated_count}

    low = sum(ss.POINTS.get(s.get("estimate"), (0, 0))[0] for s in stories)
    high = sum(ss.POINTS.get(s.get("estimate"), (0, 0))[1] for s in stories)

    return {
        "counts": dict(collections.Counter(i["type"] for i in nodes)),
        "stories": {
            "total": len(stories),
            "by_status": dict(collections.Counter(s["status"] for s in stories)),
        },
        "size_distribution": {
            "order": ss.ORDER,
            "counts": dict(size_counts),
            "unsized": unsized,
        },
        "size_by_feature": size_by_feature,
        "gate": gate,
        "gate_split": gate_split,
        "critical_path": {"length": cp_len, "nodes": critical_path},
        "effort_bounds": {"low": round(low, 2), "high": round(high, 2), "unit": ss.UNIT},
    }


def main(argv: list[str] | None = None) -> int:
    ss = _spec_stats()
    _, gate = ss._parse_args(sys.argv[1:] if argv is None else argv)
    core = build(ss, gate)
    prev = json.loads(OUT.read_text(encoding="utf-8")) if OUT.exists() else {}
    prev_core = {k: v for k, v in prev.items() if k != "generated"}
    generated = prev.get("generated") if prev_core == core else date.today().isoformat()

    payload = {"generated": generated, **core}
    OUT.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {OUT.relative_to(ROOT)}: {core['stories']['total']} stories, "
          f"critical path {core['critical_path']['length']} node(s), "
          f"{core['effort_bounds']['low']}-{core['effort_bounds']['high']} {core['effort_bounds']['unit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
