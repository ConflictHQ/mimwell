"""Source-record identity for graph pipeline inputs and portable props (#82).

Identity is a source claim, never a grant or an accepted equivalence. Legacy
extraction records without this opt-in retain their name-based curation.
"""
from __future__ import annotations

import copy
import hashlib
import json

FIELD = "recordIdentity"
FORMAT = "kg-record/v1"


def stable_id(kind: str, origin: str, record: str) -> str:
    if kind not in ("node", "edge"):
        raise ValueError("record identity kind must be node or edge")
    for value in (origin, record):
        if not isinstance(value, str) or not value.strip():
            raise ValueError("record identity needs nonempty origin and record strings")
        try:
            encoded = value.encode("utf-8")
        except UnicodeError as exc:
            raise ValueError("record identity requires Unicode scalar strings") from exc
        if len(encoded) > 2048 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("record identity exceeds bounds or contains controls")
    # A string-only array has the same bytes in JCS and this compact encoder.
    data = json.dumps([FORMAT, kind, origin, record], ensure_ascii=False, separators=(",", ":"))
    return f"kg-{kind}-" + hashlib.sha256(data.encode("utf-8")).hexdigest()


def identity(value: dict, kind: str) -> str | None:
    props = value.get("props", {})
    if not isinstance(props, dict):
        raise ValueError("graph props must be an object")
    if FIELD not in props:
        return None
    claim = props[FIELD]
    if not isinstance(claim, dict) or set(claim) != {"format", "origin", "record"} or claim["format"] != FORMAT:
        raise ValueError("invalid kg-record/v1 identity claim")
    expected = stable_id(kind, claim["origin"], claim["record"])
    actual = value.get("id") if kind == "node" else props.get("id")
    if actual != expected:
        raise ValueError("graph record ID differs from its source identity")
    fields = ("name", "type") if kind == "node" else ("source", "target", "type")
    if any(not isinstance(value.get(key), str) or not value[key].strip() for key in fields):
        raise ValueError("identified graph record has missing or invalid structural fields")
    return expected


def claim(kind: str, origin: str, record: str) -> dict:
    """Properties an adapter may add after retaining any conflicting source props."""
    stable_id(kind, origin, record)
    return {"format": FORMAT, "origin": origin, "record": record}


def guard_records(nodes: list, edges: list) -> None:
    """Fail closed on contradictory identities, including before filtering.

    Repeated observations may add occurrences; all other source claims must
    agree. A successor revision requires adapter reconciliation first.
    """
    for kind, records in (("node", nodes), ("edge", edges)):
        seen = {}
        protected = set()
        for record in records:
            explicit = identity(record, kind)
            key = record.get("id") if kind == "node" else record.get("props", {}).get("id")
            if not isinstance(key, str):
                continue
            comparable = json.dumps({k: v for k, v in record.items() if k != "occurrences"},
                                    sort_keys=True, allow_nan=False, separators=(",", ":"))
            if key in seen and (explicit or key in protected) and seen[key] != comparable:
                raise ValueError(f"conflicting graph record identity: {key}")
            seen[key] = comparable
            if explicit:
                protected.add(key)


def portable_props(record: dict, structural: tuple[str, ...]) -> dict:
    """Retain source metadata without ambiguous top-level/props collisions."""
    props = copy.deepcopy(record.get("props", {}))
    for key, value in record.items():
        if key not in (*structural, "props"):
            if key in props:
                raise ValueError(f"graph property collides with props: {key}")
            props[key] = copy.deepcopy(value)
    return props
