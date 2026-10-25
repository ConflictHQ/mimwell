#!/usr/bin/env python3
"""Living Blueprint honesty gate over app/machine.json (#69).

JSON Schema (schemas/machine.schema.json, run by validate-schemas.py) proves the
file is well-formed; this gate proves it is HONEST — the invariants that make
overclaiming a validation error instead of a review comment. Pattern doc:
docs/patterns/living-blueprint.md; invariant table:
docs/design/living-blueprint-spec.md.

  V1  every id reference resolves (connections, unlockedBy, products,
      demonstrates, beat targets, per-view group memberships, phases)
  V2  scenario playability is DERIVED and reported (a scenario whose beats touch
      unbuilt machinery is legal data — roadmap scripting — but renders locked;
      the page refuses to play it and lists the blockers). Notes, not errors.
  V2a verb/target type agreement (travel->connection, card->component|capability,
      wait->no target, ...)
  V3  capability status claims vs the built-set today: `solves` needs ALL
      unlockedBy built; while ZERO are built the card is locked and status is
      ignored entirely (V3c — the chip is suppressed, so no claim to check)
  V3b a non-`solves` status carries a statusNote saying what is partial
  V4  delivery dates fall inside their declared phase window (delivery-kind
      phases only; reference/unnumbered phases have no window)
  V5  `built` carries >=1 evidence ref; decision refs resolve against
      app/decisions.json ids when that file carries ids
  V6  a pii:true connection terminates on handlesPii components at BOTH ends
  V7  exec-language lint: no denied token in any exec-facing string. Denylist =
      every word >=4 chars in any realName (components + internals), MINUS every
      word in any officialName, minus stopwords — the component inventory itself
      is the denylist, so it cannot drift.

A missing app/machine.json is a clean skip (a fork may not have adopted the
blueprint); an unparseable one is an error.

Run from repo root:  python3 scripts/check-machine.py [path/to/machine.json]
Exit 1 on violations; playability notes go to stdout either way.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Verb -> the kind(s) of id its target must name. None = no target allowed;
# "optional-anchor" = target optional, any addressable kind.
BEAT_TARGET_KINDS: dict[str, tuple[str, ...] | None] = {
    "arrive": ("component",),
    "travel": ("connection",),
    "process": ("component",),
    "split": ("component",),
    "merge": ("component",),
    "hold": ("component",),
    "divert": ("component",),
    "flag": ("component", "connection"),
    "emit": ("component",),
    "deliver": ("component",),
    "camera": ("component", "connection"),
    "card": ("component", "capability"),
    "caption": ("component", "connection", "capability"),
    "wait": None,
}

# Common function words that may legitimately appear inside a realName without
# poisoning exec copy (>=4 chars only; shorter tokens never enter the denylist).
STOPWORDS = frozenset("""
    with from into onto upon over under above below about across through during
    before after between within without against along behind beyond toward
    towards that this then than when where which while your their them they
    have been being will only also some such each other more most less least
    very much many
""".split())

TOKEN_RE = re.compile(r"[a-z0-9]+")


def tokens(text: str) -> set[str]:
    return set(TOKEN_RE.findall((text or "").lower()))


def parse_date(s: str) -> date:
    return date(*map(int, s.split("-")))


class Machine:
    """Index + derived state over a parsed machine.json."""

    def __init__(self, data: dict):
        self.data = data
        self.components = {c["id"]: c for c in data.get("components", [])}
        self.connections = {c["id"]: c for c in data.get("connections", [])}
        self.capabilities = {c["id"]: c for c in data.get("capabilities", [])}
        self.products = {p["id"]: p for p in data.get("products", [])}
        self.scenarios = {s["id"]: s for s in data.get("scenarios", [])}
        self.views = data.get("views", {})
        self.phases = {p["id"]: p for p in data.get("timeline", {}).get("phases", [])}

    def kind_of(self, ref: str) -> str | None:
        if ref in self.components:
            return "component"
        if ref in self.connections:
            return "connection"
        if ref in self.capabilities:
            return "capability"
        return None

    def phase_kind(self, phase_id: str) -> str:
        return self.phases.get(phase_id, {}).get("kind", "delivery")

    def component_state(self, comp: dict, at: date) -> str:
        """built | in-progress | ghosted at a timeline position (pure function
        of delivery dates — the same derivation the page renders)."""
        if comp.get("existing"):
            return "built"
        delivery = comp.get("delivery", {})
        if self.phase_kind(delivery.get("phase", "")) == "reference":
            return "ghosted"  # reference machinery never colorizes
        status = delivery.get("status")
        if status == "built" and "date" in delivery and parse_date(delivery["date"]) <= at:
            return "built"
        started = delivery.get("started")
        if started and parse_date(started) <= at:
            return "in-progress"
        return "ghosted"

    def connection_state(self, conn: dict, at: date) -> str:
        """Explicit delivery override wins; else derived from the endpoints:
        built iff both endpoints built, otherwise the least-advanced state."""
        delivery = conn.get("delivery")
        if delivery is not None:
            if delivery.get("status") == "built" and "date" in delivery:
                return "built" if parse_date(delivery["date"]) <= at else "ghosted"
            started = delivery.get("started")
            if started and parse_date(started) <= at:
                return "in-progress"
            return "ghosted"
        ends = [self.components.get(conn.get("from")), self.components.get(conn.get("to"))]
        if any(e is None for e in ends):
            return "ghosted"  # dangling — V1 reports it; never claim flow
        states = [self.component_state(e, at) for e in ends]
        if all(s == "built" for s in states):
            return "built"
        return "in-progress" if "in-progress" in states else "ghosted"

    def capability_unlocked(self, cap: dict, at: date) -> bool:
        return all(
            cid in self.components and self.component_state(self.components[cid], at) == "built"
            for cid in cap.get("unlockedBy", [])
        )

    def beat_blockers(self, scenario: dict, at: date) -> list[str]:
        """Ids blocking playability at `at` (empty = playable)."""
        blocking: list[str] = []
        for beat in scenario.get("beats", []):
            target = beat.get("target")
            if not target:
                continue
            kind = self.kind_of(target)
            ok = (
                kind == "component" and self.component_state(self.components[target], at) == "built"
                or kind == "connection" and self.connection_state(self.connections[target], at) == "built"
                or kind == "capability" and self.capability_unlocked(self.capabilities[target], at)
            )
            if not ok and target not in blocking:
                blocking.append(target)
        return blocking


def exec_fields(data: dict):
    """Yield (label, text) for every exec-facing string V7 lints."""
    for comp in data.get("components", []):
        cid = comp["id"]
        for field in ("metaphorName", "execCopy", "valueLine"):
            if comp.get(field):
                yield f"component {cid}.{field}", comp[field]
    for conn in data.get("connections", []):
        if conn.get("label"):
            yield f"connection {conn['id']}.label", conn["label"]
    for cap in data.get("capabilities", []):
        for field in ("name", "body", "valueLine", "problem", "statusNote"):
            if cap.get(field):
                yield f"capability {cap['id']}.{field}", cap[field]
    for prod in data.get("products", []):
        if prod.get("execCopy"):
            yield f"product {prod['id']}.execCopy", prod["execCopy"]
    for scen in data.get("scenarios", []):
        sid = scen["id"]
        for field in ("title", "execIntro"):
            if scen.get(field):
                yield f"scenario {sid}.{field}", scen[field]
        for beat in scen.get("beats", []):
            for field in ("payload", "execNote"):
                if beat.get(field):
                    yield f"scenario {sid} beat {beat.get('beat')}.{field}", beat[field]
    for ms in data.get("timeline", {}).get("milestones", []):
        if ms.get("label"):
            yield f"milestone {ms['id']}.label", ms["label"]


def check(data: dict, decisions_ids: set[str] | None = None, today: date | None = None):
    """Return (errors, notes). decisions_ids: known decision ids, or None when
    app/decisions.json is absent or carries none (pattern-check only then)."""
    m = Machine(data)
    today = today or date.today()
    errors: list[str] = []
    notes: list[str] = []

    # ── V1: referential integrity ────────────────────────────────────────────
    for conn in m.connections.values():
        for end in ("from", "to"):
            if conn[end] not in m.components:
                errors.append(f"V1 connection {conn['id']}.{end}: unknown component {conn[end]!r}")
    for cap in m.capabilities.values():
        for cid in cap.get("unlockedBy", []):
            if cid not in m.components:
                errors.append(f"V1 capability {cap['id']}.unlockedBy: unknown component {cid!r}")
        for pid in cap.get("products", []):
            if pid not in m.products:
                errors.append(f"V1 capability {cap['id']}.products: unknown product {pid!r}")
    for scen in m.scenarios.values():
        for kid in scen.get("demonstrates", []):
            if kid not in m.capabilities:
                errors.append(f"V1 scenario {scen['id']}.demonstrates: unknown capability {kid!r}")
    for comp in m.components.values():
        for view_id, group_id in comp.get("views", {}).items():
            view = m.views.get(view_id)
            if view is None:
                errors.append(f"V1 component {comp['id']}.views: unknown view {view_id!r}")
            elif group_id not in {g["id"] for g in view.get("groups", [])}:
                errors.append(
                    f"V1 component {comp['id']}.views.{view_id}: unknown group {group_id!r}")
    for owner, delivery in _deliveries(m):
        for key in ("phase", "activationPhase"):
            pid = delivery.get(key)
            if pid is not None and pid not in m.phases:
                errors.append(f"V1 {owner}.delivery.{key}: unknown phase {pid!r}")

    # ── V2a: verb/target agreement (V2 playability derives below) ────────────
    for scen in m.scenarios.values():
        for beat in scen.get("beats", []):
            verb, target = beat.get("action"), beat.get("target")
            allowed = BEAT_TARGET_KINDS.get(verb)
            label = f"scenario {scen['id']} beat {beat.get('beat')}"
            if allowed is None:
                if target is not None:
                    errors.append(f"V2a {label}: {verb!r} takes no target")
                continue
            if target is None:
                if verb != "caption":  # caption's anchor is optional
                    errors.append(f"V2a {label}: {verb!r} requires a target")
                continue
            kind = m.kind_of(target)
            if kind is None:
                errors.append(f"V1 {label}: unknown target {target!r}")
            elif kind not in allowed:
                errors.append(
                    f"V2a {label}: {verb!r} targets a {kind}; must be one of {'/'.join(allowed)}")

    # ── V2: playability, reported not enforced ────────────────────────────────
    for scen in m.scenarios.values():
        blockers = m.beat_blockers(scen, today)
        if blockers:
            notes.append(
                f"V2 scenario {scen['id']} is LOCKED today (renders with blockers listed): "
                + ", ".join(blockers))

    # ── V3 / V3b / V3c: status claims vs the built-set ───────────────────────
    for cap in m.capabilities.values():
        built = [
            cid for cid in cap.get("unlockedBy", [])
            if cid in m.components and m.component_state(m.components[cid], today) == "built"
        ]
        status = cap.get("status")
        if status and status != "solves" and not cap.get("statusNote"):
            errors.append(f"V3b capability {cap['id']}: status {status!r} requires a statusNote")
        if not built:
            continue  # V3c: card locked, status suppressed — nothing to claim
        if status == "solves" and len(built) != len(cap.get("unlockedBy", [])):
            missing = [c for c in cap.get("unlockedBy", []) if c not in built]
            errors.append(
                f"V3 capability {cap['id']}: claims 'solves' with unbuilt components: "
                + ", ".join(missing))

    # ── V4: dates inside the declared phase window ────────────────────────────
    for owner, delivery in _deliveries(m):
        phase = m.phases.get(delivery.get("phase", ""))
        if phase is None or phase.get("kind", "delivery") != "delivery":
            continue
        start = parse_date(phase["start"]) if phase.get("start") else None
        end = parse_date(phase["end"]) if phase.get("end") else None
        for field in ("date", "started"):
            if field not in delivery:
                continue
            d = parse_date(delivery[field])
            if (start and d < start) or (end and d > end):
                errors.append(
                    f"V4 {owner}.delivery.{field} {delivery[field]} falls outside phase "
                    f"{phase['id']!r} window {phase.get('start')}..{phase.get('end', 'open')}")

    # ── V5: built is a traceable fact ─────────────────────────────────────────
    for owner, delivery in _deliveries(m):
        if delivery.get("status") != "built":
            continue
        evidence = delivery.get("evidence", [])
        if not evidence:
            errors.append(f"V5 {owner}: built without evidence")
        for ev in evidence:
            if ev.get("type") == "decision" and decisions_ids is not None \
                    and ev.get("ref") not in decisions_ids:
                errors.append(
                    f"V5 {owner}: decision evidence {ev.get('ref')!r} not found in "
                    "app/decisions.json ids")

    # ── V6: the drawing agrees with the privacy architecture ─────────────────
    for conn in m.connections.values():
        if not conn.get("pii"):
            continue
        for end in ("from", "to"):
            comp = m.components.get(conn[end])
            if comp is not None and not comp.get("handlesPii"):
                errors.append(
                    f"V6 connection {conn['id']}: pii flow terminates on {conn[end]!r} "
                    "which does not declare handlesPii")

    # ── V7: exec-language lint ────────────────────────────────────────────────
    official: set[str] = set()
    real: set[str] = set()
    for comp in m.components.values():
        official |= tokens(comp.get("officialName", ""))
        real |= tokens(comp.get("realName", ""))
        for part in comp.get("internals", []):
            official |= tokens(part.get("officialName", ""))
            real |= tokens(part.get("realName", ""))
    denied = {t for t in real if len(t) >= 4} - official - STOPWORDS
    for label, text in exec_fields(data):
        hits = sorted(tokens(text) & denied)
        if hits:
            errors.append(f"V7 {label}: implementation naming in exec copy: {', '.join(hits)}")

    return errors, notes


def _deliveries(m: Machine):
    """Yield (owner-label, delivery-dict) for every explicit delivery block."""
    for comp in m.components.values():
        yield f"component {comp['id']}", comp.get("delivery", {})
    for conn in m.connections.values():
        if conn.get("delivery"):
            yield f"connection {conn['id']}", conn["delivery"]


def load_decision_ids(root: Path) -> set[str] | None:
    path = root / "app" / "decisions.json"
    if not path.is_file():
        return None
    try:
        items = json.loads(path.read_text(encoding="utf-8")).get("decisions", [])
    except (OSError, ValueError):
        return None
    ids = {d["id"] for d in items if isinstance(d, dict) and d.get("id")}
    return ids or None  # no ids adopted -> pattern-check only


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else ROOT / "app" / "machine.json"
    if not path.is_file():
        print(f"check-machine: {path} absent — skipped (blueprint not adopted)")
        return 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        print(f"check-machine: {path} is not valid JSON: {exc}", file=sys.stderr)
        return 1
    errors, notes = check(data, decisions_ids=load_decision_ids(ROOT))
    for note in notes:
        print(f"note: {note}")
    if errors:
        print(f"check-machine: {len(errors)} violation(s) in {path}:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print(f"check-machine: OK ({path})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
