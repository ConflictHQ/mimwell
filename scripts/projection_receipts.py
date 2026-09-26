"""Committed delivered projections and their receipts (#228).

Under `projections: committed` (docs/design/adr-authority-per-brain-kind.md) a
store authority delivers `app/projections/<consumer>.json` and writes
`app/projections/<consumer>.receipt.json` = {authority, binding, sequence,
sha256, deliveredAt} beside it. CI cannot regenerate these from git, so it
verifies the receipt instead of byte-comparing.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

DIRECTORY = "app/projections"
RECEIPT_KEYS = {"authority", "binding", "sequence", "sha256", "deliveredAt"}
CONSUMER = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


class ProjectionError(ValueError):
    pass


def paths(root, consumer):
    if not isinstance(consumer, str) or not CONSUMER.fullmatch(consumer):
        raise ProjectionError(f"invalid projection consumer: {consumer!r}")
    base = Path(root) / DIRECTORY
    return base / f"{consumer}.json", base / f"{consumer}.receipt.json"


def receipt_for(raw):
    payload = json.loads(raw)
    return {
        "authority": payload["authority"],
        "binding": payload["contract"],
        "sequence": payload["sequence"],
        "sha256": hashlib.sha256(raw).hexdigest(),
        "deliveredAt": payload["observedAt"],
    }


def write_receipt(root, consumer):
    """Receipt the projection file as it is on disk (the sink may keep a newer copy)."""
    projection, receipt = paths(root, consumer)
    value = receipt_for(projection.read_bytes())
    fd, temporary = tempfile.mkstemp(prefix=".receipt-", dir=receipt.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
        os.replace(temporary, receipt)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return value


def load(root, binding):
    """Every committed projection with its verified receipt, sorted by consumer.

    Fails when a projection lacks a receipt (or the reverse), when the artifact
    sha256 differs from the receipt, or when the receipt binding differs from the
    adopted contract binding.
    """
    base = Path(root) / DIRECTORY
    if not base.is_dir():
        return []
    names = sorted(p.name for p in base.iterdir() if p.suffix == ".json")
    receipts = {n[: -len(".receipt.json")] for n in names if n.endswith(".receipt.json")}
    projections = {n[: -len(".json")] for n in names if not n.endswith(".receipt.json")}
    if receipts != projections:
        raise ProjectionError(f"projection without receipt or receipt without projection: {sorted(receipts ^ projections)}")
    result = []
    for consumer in sorted(projections):
        projection, receipt_path = paths(root, consumer)
        receipt = json.loads(receipt_path.read_text())
        if not isinstance(receipt, dict) or set(receipt) != RECEIPT_KEYS:
            raise ProjectionError(f"{consumer}: receipt must carry exactly {sorted(RECEIPT_KEYS)}")
        raw = projection.read_bytes()
        if hashlib.sha256(raw).hexdigest() != receipt["sha256"]:
            raise ProjectionError(f"{consumer}: projection sha256 differs from its receipt")
        if receipt["binding"] != binding:
            raise ProjectionError(f"{consumer}: receipt binding differs from the adopted contract binding")
        if receipt_for(raw) != receipt:
            raise ProjectionError(f"{consumer}: receipt does not describe its projection")
        result.append((consumer, json.loads(raw), receipt))
    return result
