"""Host-attested source and compiled-graph receipt for the portal container.

The receipt records a host-supplied immutable source commit and the exact
``app/brain.json`` bytes that the runtime loads. It does not prove Git object
identity or that every build-context file came from that commit.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat

FORMAT = "mimwell-source-receipt/v1"
MAX_GRAPH_BYTES = 64 * 1024 * 1024
MAX_RECEIPT_BYTES = 1024
MAX_JSON_DEPTH = 128
MAX_INTEGER_DIGITS = 128
_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _decode_json(raw: bytes):
    """Strict, bounded stdlib-only JSON parsing for the build-stage helper."""
    if len(raw) > MAX_GRAPH_BYTES:
        raise ValueError("Compiled graph exceeds its receipt size limit")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate compiled graph JSON key")
            result[key] = value
        return result

    def nonfinite(_value):
        raise ValueError("Nonfinite compiled graph JSON number")

    def parse_float(value):
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError("Overflowing compiled graph JSON number")
        return parsed

    def parse_int(value):
        if len(value.lstrip("-")) > MAX_INTEGER_DIGITS:
            raise ValueError("Oversized compiled graph JSON integer")
        return int(value)

    try:
        text = raw.decode("utf-8")
        graph = json.loads(
            text, object_pairs_hook=pairs, parse_constant=nonfinite, parse_float=parse_float, parse_int=parse_int
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid compiled graph JSON") from exc

    pending = [(graph, 0)]
    while pending:
        value, depth = pending.pop()
        if depth > MAX_JSON_DEPTH:
            raise ValueError("Compiled graph JSON exceeds its nesting limit")
        if isinstance(value, dict):
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)
    return graph


def _read_graph(path: os.PathLike | str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_GRAPH_BYTES:
            raise ValueError("Compiled graph must be a bounded regular file")
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, MAX_GRAPH_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_GRAPH_BYTES:
                raise ValueError("Compiled graph exceeds its receipt size limit")
        after = os.fstat(fd)
        if _identity(before) != _identity(after) or total != before.st_size:
            raise ValueError("Compiled graph changed while making its receipt")
    finally:
        os.close(fd)
    raw = b"".join(chunks)
    graph = _decode_json(raw)
    if not isinstance(graph, dict):
        raise ValueError("Compiled graph must be a JSON object")
    return raw


def _identity(info):
    return tuple(
        getattr(info, key)
        for key in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    )


def validate_source_commit(source_commit: str) -> None:
    """Validate the optional host-attested source identity without file effects."""
    if source_commit == "":
        return
    if not isinstance(source_commit, str) or not _COMMIT.fullmatch(source_commit):
        raise ValueError("ASTROLIFT_SOURCE_COMMIT must be a full lowercase Git SHA")


def create_receipt(source_commit: str, graph_path: os.PathLike | str) -> bytes | None:
    """Create canonical receipt bytes; empty source input means legacy build."""
    validate_source_commit(source_commit)
    if source_commit == "":
        return None
    return create_receipt_from_bytes(source_commit, _read_graph(graph_path))


def create_receipt_from_bytes(source_commit: str, graph_raw: bytes) -> bytes:
    """Create a receipt from bytes already read and parsed by the build caller."""
    validate_source_commit(source_commit)
    if source_commit == "":
        raise ValueError("A source commit is required to create a receipt")
    if not isinstance(graph_raw, bytes) or len(graph_raw) > MAX_GRAPH_BYTES:
        raise ValueError("Compiled graph exceeds its receipt size limit")
    graph = _decode_json(graph_raw)
    if not isinstance(graph, dict):
        raise ValueError("Compiled graph must be a JSON object")
    receipt = {
        "format": FORMAT,
        "sourceCommit": source_commit,
        "graphSha256": hashlib.sha256(graph_raw).hexdigest(),
    }
    encoded = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise ValueError("Source receipt exceeds its size limit")
    return encoded


def write_receipt(source_commit: str, graph_path: os.PathLike | str, output_path: os.PathLike | str) -> bool:
    """Write a new read-only build receipt, or leave no receipt for legacy builds."""
    encoded = create_receipt(source_commit, graph_path)
    if encoded is None:
        return False
    write_receipt_bytes(output_path, encoded)
    return True


def write_receipt_bytes(output_path: os.PathLike | str, encoded: bytes) -> None:
    """Write already-validated canonical receipt bytes once, exclusively."""
    if not isinstance(encoded, bytes) or len(encoded) > MAX_RECEIPT_BYTES:
        raise ValueError("Source receipt exceeds its size limit")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(output_path, flags, 0o444)
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write creating source receipt")
            view = view[written:]
        os.fchmod(fd, 0o444)
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            os.unlink(output_path)
        except OSError:
            pass
        raise
    else:
        os.close(fd)


def load_receipt(path: os.PathLike | str, graph_bytes: bytes | None, *, owner_uid: int = 0) -> dict | None:
    """Load and verify an optional root-owned immutable receipt against loaded graph bytes."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError("Source receipt cannot be safely opened") from exc
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner_uid
            or stat.S_IMODE(before.st_mode) != 0o444
            or before.st_nlink != 1
            or before.st_size > MAX_RECEIPT_BYTES
        ):
            raise ValueError("Source receipt must be a bounded root-owned read-only regular file")
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, min(4096, MAX_RECEIPT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_RECEIPT_BYTES:
                raise ValueError("Source receipt exceeds its size limit")
        raw = b"".join(chunks)
        after = os.fstat(fd)
        if _identity(before) != _identity(after) or len(raw) != before.st_size:
            raise ValueError("Source receipt changed or exceeds its size limit")
    finally:
        os.close(fd)
    try:
        current = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise ValueError("Source receipt path changed") from exc
    if _identity(after) != _identity(current):
        raise ValueError("Source receipt path changed")
    receipt = _decode_json(raw)
    if (
        not isinstance(receipt, dict)
        or set(receipt) != {"format", "sourceCommit", "graphSha256"}
        or receipt.get("format") != FORMAT
        or not isinstance(receipt.get("sourceCommit"), str)
        or not _COMMIT.fullmatch(receipt["sourceCommit"])
        or not isinstance(receipt.get("graphSha256"), str)
        or not _SHA256.fullmatch(receipt["graphSha256"])
    ):
        raise ValueError("Invalid source receipt")
    if not isinstance(graph_bytes, bytes) or hashlib.sha256(graph_bytes).hexdigest() != receipt["graphSha256"]:
        raise ValueError("Source receipt does not match the loaded compiled graph")
    return {"sourceCommit": receipt["sourceCommit"], "graphSha256": receipt["graphSha256"]}
