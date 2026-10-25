"""Fresh-process file reader for admitted snapshot capture.

This worker must stay standard-library-only and must not import or use SQLite.
Its purpose is to keep raw source-file descriptor closes in a process that holds
no SQLite connections. Callers reject SQLite bytes as ordinary copy sources,
while the selected authority is read through SQLite APIs.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys


MAX_REQUEST_BYTES = 16 * 1024
MAX_CHUNK_BYTES = 64 * 1024


def _same(left, right):
    return (left.st_dev, left.st_ino, left.st_mode, left.st_uid, left.st_nlink,
            left.st_size, left.st_mtime_ns, left.st_ctime_ns) == (
            right.st_dev, right.st_ino, right.st_mode, right.st_uid, right.st_nlink,
            right.st_size, right.st_mtime_ns, right.st_ctime_ns)


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short worker output")
        view = view[written:]


def _response(value):
    _write_all(1, json.dumps(value, sort_keys=True, separators=(",", ":"),
                             allow_nan=False).encode("ascii") + b"\n")


def _open_parent(path):
    parent_fd = os.open(path.anchor or "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parent.parts[1:]:
            child_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child_fd
        return parent_fd
    except BaseException:
        os.close(parent_fd)
        raise


def _open_source(path_text, limit):
    if (not isinstance(path_text, str) or not path_text or len(path_text) > 4096
            or "\x00" in path_text or not Path(path_text).is_absolute()
            or type(limit) is not int or not 0 <= limit <= 512 * 1024 * 1024):
        raise ValueError("invalid-request")
    path = Path(path_text)
    if ".." in path.parts:
        raise ValueError("invalid-request")
    parent_fd = _open_parent(path)
    descriptor = None
    try:
        named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(named.st_mode) or named.st_size > limit:
            raise ValueError("source-refused")
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=parent_fd)
        opened = os.fstat(descriptor)
        if not _same(named, opened):
            raise ValueError("source-changed")
        return path, parent_fd, descriptor, opened
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)
        raise


def _verify(path, parent_fd, descriptor, identity, size):
    opened = os.fstat(descriptor)
    named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
    current_parent_fd = _open_parent(path)
    try:
        original_parent = os.fstat(parent_fd)
        current_parent = os.fstat(current_parent_fd)
        if ((original_parent.st_dev, original_parent.st_ino)
                != (current_parent.st_dev, current_parent.st_ino)
                or size != identity.st_size or not _same(identity, opened)
                or not _same(identity, named)):
            raise ValueError("source-changed")
    finally:
        os.close(current_parent_fd)


def _describe(request):
    path, parent_fd, descriptor, identity = _open_source(request.get("path"), request.get("limit"))
    digest = hashlib.sha256()
    size = 0
    prefix = bytearray()
    try:
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, identity.st_size - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > identity.st_size:
                raise ValueError("source-changed")
            if len(prefix) < 16:
                prefix.extend(chunk[:16 - len(prefix)])
            digest.update(chunk)
        _verify(path, parent_fd, descriptor, identity, size)
        return {"ok": True, "bytes": size, "sha256": digest.hexdigest(),
                "mode": stat.S_IMODE(identity.st_mode),
                "sqlite": bytes(prefix) == b"SQLite format 3\x00"}
    finally:
        os.close(descriptor)
        os.close(parent_fd)


def _stream(request):
    path, parent_fd, descriptor, identity = _open_source(request.get("path"), request.get("limit"))
    size = 0
    digest = hashlib.sha256()
    prefix = bytearray()
    header_written = False
    try:
        _response({"ok": True, "bytes": identity.st_size,
                   "mode": stat.S_IMODE(identity.st_mode)})
        header_written = True
        while True:
            chunk = os.read(descriptor, min(MAX_CHUNK_BYTES, identity.st_size - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > identity.st_size:
                raise ValueError("source-changed")
            if len(prefix) < 16:
                prefix.extend(chunk[:16 - len(prefix)])
            digest.update(chunk)
            _write_all(1, chunk)
        _verify(path, parent_fd, descriptor, identity, size)
        _response({"ok": True, "bytes": size, "sha256": digest.hexdigest(),
                   "mode": stat.S_IMODE(identity.st_mode),
                   "sqlite": bytes(prefix) == b"SQLite format 3\x00"})
    except BaseException:
        # Once streaming starts, the parent consumes an exact byte count. A
        # JSON error trailer would be indistinguishable from source bytes, so
        # terminate the worker and let the parent observe bounded EOF instead.
        if header_written:
            return False
        raise
    finally:
        os.close(descriptor)
        os.close(parent_fd)


def main():
    while True:
        raw = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
        if not raw:
            return 0
        if len(raw) > MAX_REQUEST_BYTES or not raw.endswith(b"\n"):
            _response({"ok": False, "reason": "invalid-request"})
            return 2
        try:
            request = json.loads(raw.decode("ascii", "strict"))
        except (UnicodeDecodeError, ValueError):
            _response({"ok": False, "reason": "invalid-request"})
            return 2
        if request == {"op": "stop"}:
            return 0
        try:
            if not isinstance(request, dict) or set(request) != {"op", "path", "limit"}:
                raise ValueError("invalid-request")
            if request["op"] == "describe":
                _response(_describe(request))
            elif request["op"] == "stream":
                if _stream(request) is False:
                    return 2
            else:
                raise ValueError("invalid-request")
        except BaseException as exc:
            _response({"ok": False, "reason": "source-refused" if isinstance(exc, ValueError)
                       else "source-read-failed"})


if __name__ == "__main__":
    raise SystemExit(main())
