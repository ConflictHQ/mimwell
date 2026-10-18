"""Explicit public deployment facts for the container's status document (#522).

The declaration is operator supplied. It is never an authority-health measurement.
No database, source documents, connection values or credentials are inspected.
"""
from __future__ import annotations

from copy import deepcopy
import datetime as dt
import os
import re
import stat

from context_host import decode
from knowledge_operations import private_path

MAX_DECLARATION_BYTES = 4096
STATUS_PATH = "/.well-known/mimwell.json"
READ_CAPABILITIES = ("search_records", "read_record", "list_definitions", "resolve_metric", "run_metric")


def _time(value):
    if value is None:
        return
    if not isinstance(value, str) or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})", value):
        raise ValueError("Public status time requires an ISO timestamp with timezone")
    dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate(value):
    """Validate a deliberately public declaration, refusing extra fields wholesale."""
    if not isinstance(value, dict) or value.get("format") != "mimwell-public-status/v1":
        raise ValueError("Invalid public status declaration")
    if value.keys() - {"format", "edition", "compiled_at", "revision", "last_ingest", "substrate"}:
        raise ValueError("Unknown public status declaration field")
    edition = value.get("edition")
    if edition is not None and (not isinstance(edition, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._/@+:-]{0,127}", edition)):
        raise ValueError("Public edition requires a bounded release reference")
    revision = value.get("revision")
    if revision is not None and (not isinstance(revision, str) or not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", revision)):
        raise ValueError("Public revision requires a full Git commit ID")
    _time(value.get("compiled_at"))
    ingest = value.get("last_ingest")
    if ingest is not None:
        if not isinstance(ingest, dict) or set(ingest) != {"at", "status"}:
            raise ValueError("Invalid public ingestion declaration")
        if ingest["at"] is None or ingest["status"] not in ("ok", "failed", "running"):
            raise ValueError("Invalid public ingestion outcome")
        _time(ingest["at"])
    substrate = value.get("substrate")
    if substrate is not None:
        from knowledge_store import AXES

        if not isinstance(substrate, dict) or substrate.keys() - {*AXES, "graduation_needed"}:
            raise ValueError("Invalid public substrate declaration")
        for axis, choices in AXES.items():
            if substrate.get(axis) is not None and substrate[axis] not in choices:
                raise ValueError("Invalid public substrate driver")
        if substrate.get("graduation_needed") is not None and type(substrate["graduation_needed"]) is not bool:
            raise ValueError("Invalid public substrate graduation declaration")
    return deepcopy(value)


def load(root, relative):
    """Read a bounded regular private operator file once at host startup."""
    if not relative:
        return None
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Public status requires a real operator root")
    path = private_path(root, relative)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_mode & 0o077 or before.st_nlink != 1):
            raise ValueError("Public status requires an operator-owned private regular file")
        raw = stream.read(MAX_DECLARATION_BYTES + 1)
        after = os.fstat(stream.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if len(raw) > MAX_DECLARATION_BYTES or any(getattr(before, k) != getattr(after, k) for k in fields):
        raise ValueError("Public status declaration is oversized or changed")
    # Revalidate the private path after reading; a cooperating operator updates
    # it atomically and restarts the host. Mount-owner races are outside this pilot.
    current = private_path(root, relative).stat()
    if any(getattr(after, k) != getattr(current, k) for k in fields):
        raise ValueError("Public status declaration changed")
    return validate(decode(raw))


def document(engine, declaration=None, *, records=None):
    value = validate(declaration) if declaration is not None else {}
    # Version strings come from a release manifest, never arbitrary manifest data.
    version = engine if isinstance(engine, str) and re.fullmatch(r"[0-9][A-Za-z0-9.+-]{0,63}", engine) else None
    substrate = value.get("substrate") or {}
    return {"contract": "1", "engine": version, "edition": value.get("edition"),
            "compiled_at": value.get("compiled_at"), "revision": value.get("revision"),
            "records": records, "records_basis": "anonymous-projection" if records is not None else "unknown",
            "substrate": {axis: substrate.get(axis) for axis in
                          ("authority", "blobs", "vectors", "graph", "graduation_needed")},
            "last_ingest": value.get("last_ingest"),
            "metadata_source": "operator-declared" if declaration is not None else "unknown",
            "mcp": {"path": "/mcp", "tools": list(READ_CAPABILITIES), "tools_basis": "server-capabilities"}}
