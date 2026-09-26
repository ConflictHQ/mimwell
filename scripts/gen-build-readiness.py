#!/usr/bin/env python3
"""Derive "what do I build next" and emit app/build-readiness.json.

The data already exists — the plan (specs/manifest.json), its dependency graph
(app/dependencies.json), and the effort estimates (specs/estimates.json, #12).
This script computes the *answer*: which stories are buildable now, the longest
estimate-weighted dependency chain, a readiness score per story (with blocking
reasons), and a ranked recommendation of what to pick up.

Everything is DERIVED — no hand-maintained data:

  unblocked     stories whose every `depends_on` target is done -> buildable now
  critical_path the longest dependency chain, weighted by estimate points
  readiness     per story: blocked | ready | in-progress | done + why-blocked
  next_actions  ranked: unblocked x on-critical-path x priority

Ids are the template's SLASH scheme (phase-one/example-epic/...); the parent
chain is the single `parent` field and dependencies are the `depends_on` list
(see specs/manifest.json + scripts/gen-specs.py). Estimate band -> points comes
from the bands table pointed to by client.config.json estimation.bands, resolved
through the config barrel (scripts/config.py) — this script hardcodes no path
to it.

Ships empty-state: with no declared dependencies it still writes a well-formed
file so the page renders cleanly. Output is fully sorted/deterministic so the
drift gate (portal-generated-clean) stays green.

Run from anywhere:  python3 scripts/gen-build-readiness.py
"""
from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import settings  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "specs" / "manifest.json"
DEPENDENCIES = ROOT / "app" / "dependencies.json"
ESTIMATES = ROOT / "specs" / "estimates.json"
BANDS = settings.estimation.bands
OUT = ROOT / "app" / "build-readiness.json"

# Priority -> sort weight (higher = pick up sooner) for next-action ranking.
PRIORITY_RANK = {"high": 3, "medium": 2, "low": 1, "": 0}

# Status that counts a dependency as satisfied.
DONE = "done"


def _load(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def main():
    manifest = _load(MANIFEST)
    items = manifest.get("items") if isinstance(manifest, dict) else None
    items = items if isinstance(items, list) else []
    by_id = {it["id"]: it for it in items if isinstance(it, dict) and it.get("id")}

    bands = (_load(Path(BANDS)) or {}).get("bands", {}) if BANDS else {}

    # Per-story estimate points, keyed by id (from estimates.json #12, falling
    # back to the band table directly). Containers carry no size -> 0 points.
    est = _load(ESTIMATES)
    points_by_id: dict[str, float] = {}
    for a in est.get("activities", []) if isinstance(est, dict) else []:
        if isinstance(a, dict) and a.get("id") and a.get("points") is not None:
            points_by_id[a["id"]] = a["points"]

    def points_of(nid: str) -> float:
        if nid in points_by_id:
            return points_by_id[nid]
        size = (by_id.get(nid) or {}).get("estimate")
        band = bands.get(size) if size else None
        return band.get("points", 0) if band else 0

    def deps_of(nid: str) -> list[str]:
        raw = (by_id.get(nid) or {}).get("depends_on") or []
        if not isinstance(raw, list):
            raw = [raw]
        return [str(d).strip() for d in raw if str(d).strip() and str(d).strip() != nid]

    def status_of(nid: str) -> str:
        it = by_id.get(nid)
        return it.get("status") or "planned" if it else "unknown"

    def title_of(nid: str) -> str:
        it = by_id.get(nid)
        return (it.get("title") if it else None) or nid

    stories = sorted(
        (it for it in items if isinstance(it, dict) and it.get("type") == "story" and it.get("id")),
        key=lambda it: it["id"],
    )

    # ── Readiness scoring ────────────────────────────────────────────────────
    # done       -> shipped
    # in-progress-> being built
    # ready      -> every dependency is done (or it has none); buildable now
    # blocked    -> at least one dependency is not done (the blocking reasons)
    readiness = []
    unblocked = []
    for it in stories:
        nid = it["id"]
        st = it.get("status") or "planned"
        deps = deps_of(nid)
        blocking = [
            {"id": d, "title": title_of(d), "status": status_of(d)}
            for d in sorted(deps)
            if status_of(d) != DONE
        ]
        if st == DONE:
            score = "done"
        elif st == "in-progress":
            score = "in-progress"
        elif not blocking:
            score = "ready"
        else:
            score = "blocked"
        row = {
            "id": nid,
            "title": it.get("title") or nid,
            "status": st,
            "priority": it.get("priority") or "",
            "readiness": score,
            "estimate": it.get("estimate") or "",
            "points": points_of(nid),
            "depends_on": sorted(deps),
            "blocked_by": blocking,
        }
        readiness.append(row)
        if score == "ready":
            unblocked.append(nid)

    # ── Critical path ────────────────────────────────────────────────────────
    # Longest dependency chain weighted by estimate points: the cost of a chain
    # is the sum of the band points of its nodes. Memoized DFS over depends_on,
    # cycle-guarded. Computed across every plan node (containers contribute 0)
    # so a chain story -> epic -> phase still surfaces.
    memo: dict[str, tuple[float, list[str]]] = {}

    def heaviest(nid: str, stack: tuple[str, ...] = ()) -> tuple[float, list[str]]:
        if nid in memo:
            return memo[nid]
        if nid in stack:  # cycle: stop without counting this node again
            return (0.0, [])
        own = points_of(nid)
        deps = [d for d in deps_of(nid) if d in by_id]
        if not deps:
            best = (own, [nid])
        else:
            sub = max((heaviest(d, stack + (nid,)) for d in deps), key=lambda t: t[0])
            best = (own + sub[0], [nid] + sub[1])
        memo[nid] = best
        return best

    # Prefer the heavier chain; break ties on a longer chain, then on the chain
    # ids so the choice is deterministic for the drift gate.
    cp_points, cp_ids = 0.0, []
    cp_key = (0.0, 0, [])
    for nid in sorted(by_id):
        pts, chain = heaviest(nid)
        key = (pts, len(chain), chain)
        if key > cp_key:
            cp_key, cp_points, cp_ids = key, pts, chain

    # The chain reads top-down: the dependent first, its dependencies after. A
    # node is "on the critical path" if it appears anywhere in that chain.
    on_cp = set(cp_ids)
    critical_path = {
        "points": round(cp_points, 2),
        "length": len(cp_ids),
        "chain": [
            {
                "id": nid,
                "title": title_of(nid),
                "type": (by_id.get(nid) or {}).get("type") or "unknown",
                "status": status_of(nid),
                "estimate": (by_id.get(nid) or {}).get("estimate") or "",
                "points": points_of(nid),
            }
            for nid in cp_ids
        ],
    }

    # ── Next actions ─────────────────────────────────────────────────────────
    # Rank the unblocked (ready) set: on the critical path first, then higher
    # priority, then heavier (more points), then id. The reasons make the
    # recommendation self-explaining on the page / in the brain.
    next_actions = []
    for r in (r for r in readiness if r["readiness"] == "ready"):
        on = r["id"] in on_cp
        reasons = []
        if on:
            reasons.append("on the critical path")
        if r["priority"]:
            reasons.append(f"{r['priority']} priority")
        reasons.append("all dependencies done" if r["depends_on"] else "no dependencies")
        next_actions.append({
            "id": r["id"],
            "title": r["title"],
            "priority": r["priority"],
            "estimate": r["estimate"],
            "points": r["points"],
            "on_critical_path": on,
            "reasons": reasons,
        })
    # Rank: critical-path first, then priority, then heavier; id as the final
    # deterministic tiebreak (sort is stable, so id-sort first then key-sort).
    next_actions.sort(key=lambda a: a["id"])
    next_actions.sort(
        key=lambda a: (a["on_critical_path"], PRIORITY_RANK.get(a["priority"], 0), a["points"]),
        reverse=True,
    )

    counts = {
        "stories": len(stories),
        "done": sum(1 for r in readiness if r["readiness"] == "done"),
        "in_progress": sum(1 for r in readiness if r["readiness"] == "in-progress"),
        "ready": sum(1 for r in readiness if r["readiness"] == "ready"),
        "blocked": sum(1 for r in readiness if r["readiness"] == "blocked"),
    }

    core = {
        "counts": counts,
        "unblocked": sorted(unblocked),
        "critical_path": critical_path,
        "next_actions": next_actions,
        "readiness": readiness,
    }

    # Stabilize generated_at when the derived core is unchanged so the drift
    # gate sees byte-identical output across runs.
    prev = _load(OUT)
    generated = date.today().isoformat()
    if all(prev.get(k) == v for k, v in core.items()):
        generated = prev.get("meta", {}).get("generated_at", generated)

    out = {
        "meta": {
            "version": 1,
            "generated_at": generated,
            "generator": "scripts/gen-build-readiness.py",
            "sources": [
                "specs/manifest.json",
                "app/dependencies.json",
                "specs/estimates.json",
            ],
        },
        **core,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(
        f"Wrote {OUT.relative_to(ROOT)}: {counts['stories']} stories "
        f"({counts['ready']} ready, {counts['blocked']} blocked, "
        f"{counts['in_progress']} in-progress, {counts['done']} done); "
        f"critical path {critical_path['length']} node(s), "
        f"{critical_path['points']} points; {len(next_actions)} next action(s)"
    )


if __name__ == "__main__":
    main()
