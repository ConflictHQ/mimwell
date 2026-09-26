#!/usr/bin/env python3
"""Live spec stats — counts, size distribution, optional gate split, critical
path, and low/high relative-effort bounds, computed from specs/manifest.json.

Counts are data-driven by design: nothing here is stored in the specs, because
stored counts go stale the moment the tree changes. Run this for the live CLI
report; scripts/gen-spec-stats.py imports the computation below (under/gated/
longest/stories_under) to write the same numbers to specs/stats.json for
/specs/stats.html — that JSON always runs with no prefix/gate scoping (a
checked-in artifact reports the whole plan), so `make spec-stats-json` and this
CLI can report different numbers for the same tree; the CLI's prefix/gate flags
are read-only, ad hoc filters and were never meant to be committed.

T-shirt sizes score RELATIVE EFFORT + COMPLEXITY, not time. The low/high band
per size comes from specs/estimate-bands.json (one scale, shared with
gen-estimates.py) — never inlined here; convert to calendar time only at the
end, with an explicit velocity assumption.

The bands file is a POINTER registered from the center: its absolute path comes
from the config barrel (settings.estimation.bands).

Usage:
  python3 scripts/spec-stats.py [id-prefix] [--gate PREFIX]

  id-prefix   restrict to stories under this slash-id subtree (default: all)
  --gate      a dependency-prefix that marks a "gate"; stories that depend
              (transitively) on it are reported as gated. Off by default.

Read-only — prints to stdout, writes nothing.
"""
from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import settings  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ITEMS = json.loads((ROOT / "specs" / "manifest.json").read_text(encoding="utf-8"))["items"]
BY = {i["id"]: i for i in ITEMS}
ALL = set(BY)

BANDCFG = json.loads(Path(settings.estimation.bands).read_text(encoding="utf-8"))
BANDS = BANDCFG["bands"]
UNIT = BANDCFG.get("unit", "engineer-days")
# Render sizes in band order (the order they appear in estimate-bands.json).
ORDER = list(BANDS.keys())
# low/high band per size, sourced from the single scale.
POINTS = {k: (v["low"], v["high"]) for k, v in BANDS.items()}


def _parse_args(argv):
    prefix, gate = None, None
    rest = list(argv)
    while rest:
        a = rest.pop(0)
        if a == "--gate":
            gate = rest.pop(0) if rest else None
        elif prefix is None:
            prefix = a
    return prefix, gate


def under(nid: str, prefix: str | None) -> bool:
    """True if a node id is the prefix root or sits under it (slash subtree).
    `prefix=None` (the default scope) matches every node."""
    return prefix is None or nid == prefix or nid.startswith(prefix + "/")


def stories_under(prefix: str | None = None) -> list[dict]:
    """Every story node under `prefix` (default: the whole tree)."""
    return [i for i in ITEMS if i["type"] == "story" and under(i["id"], prefix)]


_g: dict[tuple[str, str], bool] = {}


def gated(nid: str, gate: str | None, stk: tuple = ()) -> bool:
    """True if `nid` depends (transitively) on `gate` or a node under it.
    `gate=None` means no gate is configured — nothing is gated."""
    if gate is None:
        return False
    key = (nid, gate)
    if key in _g:
        return _g[key]
    if nid in stk:
        return False
    ds = [d for d in (BY.get(nid, {}).get("depends_on") or []) if d in ALL]
    r = any(d == gate or d.startswith(gate + "/") for d in ds) or any(gated(d, gate, stk + (nid,)) for d in ds)
    _g[key] = r
    return r


_lp: dict[str, tuple[int, list[str]]] = {}


def longest(nid: str, stk: tuple = ()) -> tuple[int, list[str]]:
    """The longest dependency chain ending at `nid`: (chain length, node ids)."""
    if nid in _lp:
        return _lp[nid]
    if nid in stk:
        return (0, [])
    ds = [d for d in (BY.get(nid, {}).get("depends_on") or []) if d in ALL]
    if not ds:
        r = (1, [nid])
    else:
        s = max((longest(d, stk + (nid,)) for d in ds), key=lambda t: t[0])
        r = (s[0] + 1, s[1] + [nid])
    _lp[nid] = r
    return r


def bar(n, total, width=24):
    return "█" * round(width * n / total) if total else ""


def main(argv: list[str] | None = None) -> int:
    prefix, gate = _parse_args(sys.argv[1:] if argv is None else argv)
    nodes = [i for i in ITEMS if under(i["id"], prefix)]
    stories = stories_under(prefix)

    scope = prefix if prefix else "all stories"
    print(f"SPEC STATS  ::  {scope}")
    print(f"nodes: {len(nodes)}  ({', '.join(f'{k} {v}' for k, v in collections.Counter(i['type'] for i in nodes).items())})")

    print("\nstories by status:")
    for k, v in collections.Counter(s["status"] for s in stories).items():
        print(f"  {k:12s} {v}")

    sizes = collections.Counter(s.get("estimate") for s in stories)
    print("\nstories by size (relative effort/complexity):")
    for s in ORDER:
        if sizes.get(s):
            print(f"  {s:5s} {sizes[s]:3d}  {bar(sizes[s], len(stories))}")
    unsized = sizes.get("") + sizes.get(None) if (sizes.get("") or sizes.get(None)) else 0
    if unsized:
        print(f"  {'(unsized)':5s} {unsized:3d}  {bar(unsized, len(stories))}")

    print("\nsize by feature:")
    fb = collections.defaultdict(collections.Counter)
    for s in stories:
        feat = s["id"].rsplit("/", 1)[0] if "/" in s["id"] else s["id"]
        fb[feat][s.get("estimate") or "(unsized)"] += 1
    for fid in sorted(fb):
        keys = ORDER + ["(unsized)"]
        dist = " ".join(f"{k}:{fb[fid][k]}" for k in keys if fb[fid][k])
        label = fid.rsplit("/", 1)[-1] if "/" in fid else fid
        print(f"  {label:28s} {dist}")

    if gate:
        g = sum(gated(s["id"], gate) for s in stories)
        print(f"\ngate split (gate: {gate}):")
        print(f"  pre-gate (startable now)   {len(stories) - g}")
        print(f"  gated                      {g}")

    cp = max((longest(s["id"]) for s in stories), key=lambda t: t[0]) if stories else (0, [])
    print(f"\ncritical path (deepest dependency chain, {cp[0]} nodes):")
    for n in cp[1]:
        print(f"  -> {n}  [{BY[n].get('estimate') or '-'}]" if n in BY else f"  -> {n}")

    lo = sum(POINTS.get(s.get("estimate"), (0, 0))[0] for s in stories)
    hi = sum(POINTS.get(s.get("estimate"), (0, 0))[1] for s in stories)
    print(f"\nrelative effort bounds ({UNIT}):")
    print(f"  total: {lo:.1f}–{hi:.1f} {UNIT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
