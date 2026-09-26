#!/usr/bin/env python3
"""Staleness / review-cadence sweep over the compiled brain (issue #29).

An ADVISORY report — not a hard gate — that flags brain content needing
re-confirmation so decisions and open questions don't silently rot. It READS the
compiled brain (app/brain.json); it never edits the brain envelope or its schema
(owned by #25). Two signals per node:

  1. durability  — stamped by gen-brain.py (_DURABILITY): durable-logic for the
                   facts that persist (decisions, specs, memory, terms);
                   point-in-time for the dated records (sessions, actions,
                   questions, risks, …).
  2. last-touched — the date the node's `source` file was last touched, from git
                   history (mirrors gen-activity.py's `git log` approach).

Three rules, each with a config-driven window (DAYS) read through the central
settings singleton (settings.staleness.*):

  point-in-time-stale     a point-in-time node whose source hasn't been touched
                          within point_in_time_window_days
  open-question-lingering an OpenQuestion (status open) lingering past
                          open_question_window_days
  decision-unconfirmed    a Decision not re-confirmed (source untouched) within
                          decision_cadence_days

A window of 0 (or absent) disables that rule. The sweep is gated by
features.staleness: OFF -> it no-ops and emits an empty, quiet report (so a
brand-new/empty-state engagement adds nothing). On the empty-state template
nothing is stale, so the report is empty either way.

Output: app/staleness.json (schemas/staleness.schema.json). DETERMINISM NOTE:
last-touched is git-derived and therefore per-commit-volatile, so this artifact
is deliberately kept OUT of the Makefile generated-artifact drift gate — the same
carve-out activity.json gets (#18). Re-run via `make staleness`.

Stdlib only; reference date is overridable via STALENESS_AS_OF=YYYY-MM-DD (used
by tests for hermetic, date-independent assertions).

Run from anywhere:  python3 scripts/gen-staleness.py
"""
from __future__ import annotations

import datetime
import json
import os
import subprocess

from config import settings

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BRAIN = os.path.join(ROOT, "app", "brain.json")
OUT = os.path.join(ROOT, "app", "staleness.json")


def _as_of() -> datetime.date:
    """Reference date for the sweep. STALENESS_AS_OF overrides today (tests)."""
    env = os.environ.get("STALENESS_AS_OF")
    if env:
        return datetime.date.fromisoformat(env)
    return datetime.date.today()


def _last_touched(source: str, cache: dict[str, str | None]) -> str | None:
    """ISO date a node's source file was last touched, from git history.

    Mirrors gen-activity.py's `git log` approach. Memoized per source path.
    Returns None when the source is empty, untracked, or git is unavailable —
    an undeterminable last-touched is simply not flagged (fail-quiet)."""
    if not source:
        return None
    if source in cache:
        return cache[source]
    result: str | None = None
    try:
        out = subprocess.check_output(
            ["git", "log", "-1", "--format=%as", "--", source],
            cwd=ROOT, text=True, stderr=subprocess.DEVNULL,
        ).strip()
        result = out or None
    except (OSError, subprocess.CalledProcessError):
        result = None
    cache[source] = result
    return result


def _days_between(earlier: str, later: datetime.date) -> int | None:
    """Whole days from an ISO date string to `later`. None on a bad date."""
    try:
        d = datetime.date.fromisoformat(earlier)
    except ValueError:
        return None
    return (later - d).days


def sweep(brain: dict, windows: dict[str, int], as_of: datetime.date,
          last_touched=None) -> list[dict]:
    """Pure sweep: flag nodes per the three rules. `last_touched(source)->iso|None`
    is injected (default: git history) so tests can drive it hermetically.

    A window of 0/absent disables its rule. Output is deterministic — sorted by
    (id, reason)."""
    if last_touched is None:
        cache: dict[str, str | None] = {}
        last_touched = lambda src: _last_touched(src, cache)  # noqa: E731

    pit_window = int(windows.get("point_in_time_window_days") or 0)
    oq_window = int(windows.get("open_question_window_days") or 0)
    dec_window = int(windows.get("decision_cadence_days") or 0)

    flagged: list[dict] = []
    for node in brain.get("nodes", []):
        if not isinstance(node, dict):
            continue
        nid = node.get("id")
        if not nid:
            continue
        kind = node.get("kind")
        durability = node.get("durability")
        source = node.get("source") or ""
        touched = last_touched(source)
        stale = _days_between(touched, as_of) if touched else None

        def emit(reason: str, window: int) -> None:
            flagged.append({
                "id": nid,
                "kind": kind,
                "title": node.get("title"),
                "durability": durability,
                "source": source or None,
                "reason": reason,
                "window_days": window,
                "last_touched": touched,
                "days_stale": stale if stale is not None else 0,
            })

        # Each rule only fires when its window is enabled AND we could date the
        # node AND it is past the threshold.
        if stale is None:
            continue

        if kind == "OpenQuestion" and oq_window and stale > oq_window:
            status = node.get("status")
            if status is None or status == "open":
                emit("open-question-lingering", oq_window)
        elif kind == "Decision" and dec_window and stale > dec_window:
            emit("decision-unconfirmed", dec_window)
        elif durability == "point-in-time" and pit_window and stale > pit_window:
            emit("point-in-time-stale", pit_window)

    flagged.sort(key=lambda f: (f["id"], f["reason"]))
    return flagged


def build() -> dict:
    """Compute the full report dict from the live brain + central config."""
    enabled = bool(settings.features.staleness)
    windows = {
        "point_in_time_window_days":
            int(settings.staleness.point_in_time_window_days),
        "open_question_window_days":
            int(settings.staleness.open_question_window_days),
        "decision_cadence_days":
            int(settings.staleness.decision_cadence_days),
    }
    as_of = _as_of()

    flagged: list[dict] = []
    if enabled:
        try:
            with open(BRAIN, encoding="utf-8") as f:
                brain = json.load(f)
        except (OSError, ValueError):
            brain = {"nodes": [], "edges": []}
        flagged = sweep(brain, windows, as_of)

    counts: dict[str, int] = {}
    for f in flagged:
        counts[f["reason"]] = counts.get(f["reason"], 0) + 1

    return {
        "generated_by": "scripts/gen-staleness.py",
        "enabled": enabled,
        "as_of": as_of.isoformat(),
        "windows": windows,
        "counts": counts,
        "flagged": flagged,
    }


def main() -> int:
    report = build()
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=1)
        f.write("\n")
    n = len(report["flagged"])
    state = "disabled" if not report["enabled"] else f"{n} flagged"
    print(f"Wrote {os.path.relpath(OUT, ROOT)} ({state}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
