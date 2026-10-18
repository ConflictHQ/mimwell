"""Private, bounded session state for the Studio App MCP host.

The JSON-RPC client keeps only opaque random handles. Packages and attachment
chunks stay in this owner-private directory; callers never choose its path.
Aborting or expiring a session stops further I/O but does not remove immutable
native proposals or blobs that may already have been written.
"""
from __future__ import annotations

import fcntl
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time

from context_bundle import encode
from sql_dialect import StoreError

MAX_FRAME_BYTES = 64 * 1024
MAX_SESSION_BYTES = 33 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_SESSIONS = 32
MAX_ACTOR_SESSIONS = 4
SESSION_TTL_SECONDS = 30 * 60
SESSION_TOMBSTONE_SECONDS = 24 * 60 * 60
MAX_CHUNK_BYTES = 32 * 1024
MAX_UPLOAD_BYTES = 16 * 1024 * 1024
_HANDLE = re.compile(r"^[0-9a-f]{64}$")


def compact_response(value):
    """Serialize a response before a caller can treat a mutation as acknowledged."""
    try:
        raw = encode(value)
    except (TypeError, ValueError) as exc:
        raise StoreError("Studio App response is not serializable") from exc
    if len(raw) > MAX_FRAME_BYTES:
        raise StoreError("Studio App response exceeds the MCP frame limit")
    return raw


class SessionStore:
    """Atomic bounded session files under a host-selected private directory."""

    def __init__(self, directory, *, clock=time.time, max_total_bytes=MAX_TOTAL_BYTES,
                 max_sessions=MAX_SESSIONS, max_actor_sessions=MAX_ACTOR_SESSIONS,
                 ttl_seconds=SESSION_TTL_SECONDS):
        # Resolve platform-managed aliases (for example macOS /var) once, then
        # pin and validate the canonical private directory path.
        self.directory = Path(directory).resolve()
        self.clock = clock
        self.max_total_bytes = max_total_bytes
        self.max_sessions = max_sessions
        self.max_actor_sessions = max_actor_sessions
        self.ttl_seconds = ttl_seconds
        if any(type(value) is not int or value <= 0 for value in
               (max_total_bytes, max_sessions, max_actor_sessions, ttl_seconds)):
            raise ValueError("Invalid Studio App session limits")
        self._prepare_directory()

    def _prepare_directory(self):
        parent = self.directory.parent
        # The session directory and its host-owned parent are checked before
        # creation. Existing paths are never chmodded into looking private.
        if any(part.is_symlink() for part in (self.directory, *self.directory.parents)):
            raise StoreError("Studio App session directory cannot contain symlinks")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent_info = parent.lstat()
        if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.geteuid()
                or parent_info.st_mode & 0o077):
            raise StoreError("Studio App session parent must be owner-private")
        info = self.directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077):
            raise StoreError("Studio App session directory must be owner-private")
        dirfd = self._open_directory()
        try:
            try:
                descriptor = os.open(".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW |
                                     os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=dirfd)
            except OSError as exc:
                raise StoreError("Studio App session lock is unsafe") from exc
            try:
                self._validate_fd(descriptor, ".lock", dirfd, max_bytes=0)
            finally:
                os.close(descriptor)
        finally:
            os.close(dirfd)

    def _open_directory(self):
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        fd = None
        try:
            fd = os.open(self.directory, flags)
            info = os.fstat(fd)
            named = os.stat(self.directory, follow_symlinks=False)
        except OSError as exc:
            if fd is not None:
                os.close(fd)
            raise StoreError("Studio App session directory is unavailable") from exc
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077
                or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
            os.close(fd)
            raise StoreError("Studio App session directory changed or is unsafe")
        return fd

    def _validate_directory_fd(self, fd):
        try:
            info = os.fstat(fd)
            named = os.stat(self.directory, follow_symlinks=False)
        except OSError as exc:
            raise StoreError("Studio App session directory changed") from exc
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077
                or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
            raise StoreError("Studio App session directory changed or is unsafe")

    @staticmethod
    def _validate_fd(fd, name, dirfd, *, max_bytes):
        info = os.fstat(fd)
        try:
            named = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
        except OSError as exc:
            raise StoreError("Studio App session file changed") from exc
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077
                or info.st_nlink != 1 or info.st_size > max_bytes
                or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
            raise StoreError("Studio App session file is unsafe or exceeds its limit")
        return info

    def _locked(self):
        class Lock:
            def __init__(inner, owner):
                inner.owner = owner
                inner.fd = None
            def __enter__(inner):
                inner.dirfd = inner.owner._open_directory()
                try:
                    inner.fd = os.open(".lock", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK |
                                       getattr(os, "O_CLOEXEC", 0), dir_fd=inner.dirfd)
                    inner.owner._validate_fd(inner.fd, ".lock", inner.dirfd, max_bytes=0)
                except Exception as exc:
                    if inner.fd is not None:
                        os.close(inner.fd)
                        inner.fd = None
                    os.close(inner.dirfd)
                    inner.dirfd = None
                    raise StoreError("Studio App session lock is unsafe") from exc
                deadline = time.monotonic() + 0.25
                while True:
                    try:
                        fcntl.flock(inner.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        try:
                            inner.owner._validate_fd(inner.fd, ".lock", inner.dirfd, max_bytes=0)
                        except Exception:
                            fcntl.flock(inner.fd, fcntl.LOCK_UN)
                            os.close(inner.fd)
                            inner.fd = None
                            os.close(inner.dirfd)
                            inner.dirfd = None
                            raise
                        return inner
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            os.close(inner.fd)
                            inner.fd = None
                            os.close(inner.dirfd)
                            raise StoreError("Studio App session host is busy")
                        time.sleep(0.005)
            def __exit__(inner, *_):
                if inner.fd is not None:
                    fcntl.flock(inner.fd, fcntl.LOCK_UN)
                    os.close(inner.fd)
                if getattr(inner, "dirfd", None) is not None:
                    os.close(inner.dirfd)
        return Lock(self)

    def _path(self, handle):
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
            raise StoreError("Studio App session handle is invalid")
        return self.directory / (handle + ".json")

    def _read(self, path, dirfd=None):
        name = path.name
        own_dirfd = dirfd is None
        dirfd = self._open_directory() if own_dirfd else dirfd
        try:
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                             getattr(os, "O_CLOEXEC", 0), dir_fd=dirfd)
            except OSError as exc:
                raise StoreError("Studio App session is unavailable") from exc
            try:
                info = self._validate_fd(fd, name, dirfd, max_bytes=MAX_SESSION_BYTES)
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    raw = stream.read(MAX_SESSION_BYTES + 1)
                after = os.fstat(fd)
                named = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
                stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                if (tuple(getattr(info, field) for field in stable_fields)
                        != tuple(getattr(after, field) for field in stable_fields)
                        or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                            != (named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns, named.st_ctime_ns)):
                    raise StoreError("Studio App session changed during read")
            finally:
                os.close(fd)
        finally:
            if own_dirfd:
                os.close(dirfd)
        if len(raw) > MAX_SESSION_BYTES:
            raise StoreError("Studio App session exceeds its limit")
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get("format") != "studio-app-session/v1":
            raise StoreError("Studio App session is malformed")
        return value

    def _write(self, path, value, dirfd=None):
        raw = encode(value)
        if len(raw) > MAX_SESSION_BYTES:
            raise StoreError("Studio App session exceeds its limit")
        own_dirfd = dirfd is None
        dirfd = self._open_directory() if own_dirfd else dirfd
        temporary = ".session-" + secrets.token_hex(16)
        try:
            try:
                existing = os.stat(path.name, dir_fd=dirfd, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            if existing is not None and (not stat.S_ISREG(existing.st_mode)
                    or existing.st_uid != os.geteuid() or existing.st_mode & 0o077
                    or existing.st_nlink != 1):
                raise StoreError("Studio App session target is unsafe")
            descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW |
                                 getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=dirfd)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path.name, src_dir_fd=dirfd, dst_dir_fd=dirfd)
            os.fsync(dirfd)
        finally:
            try:
                os.unlink(temporary, dir_fd=dirfd)
            except FileNotFoundError:
                pass
            if own_dirfd:
                os.close(dirfd)

    def _inventory(self, dirfd):
        rows, total = [], 0
        with os.scandir(dirfd) as entries:
            names = [entry.name for entry in entries
                     if re.fullmatch(r"[0-9a-f]{64}\.json", entry.name)]
        for name in names:
            path = self.directory / name
            value = self._read(path, dirfd=dirfd)
            now = self.clock()
            if value.get("state") == "active" and value.get("expires", 0) <= now:
                value["state"] = "expired"
                value["payload"] = {"summary": "expired; proposals or immutable blobs already written may remain"}
                value["retireAfter"] = value["expires"] + SESSION_TOMBSTONE_SECONDS
                self._write(path, value, dirfd=dirfd)
            if value.get("state") in ("expired", "aborted"):
                retire_after = value.get("retireAfter", value.get("expires", 0) + SESSION_TOMBSTONE_SECONDS)
                if type(retire_after) in (int, float) and retire_after <= now:
                    os.unlink(name, dir_fd=dirfd)
                    continue
            size = os.stat(name, dir_fd=dirfd, follow_symlinks=False).st_size
            total += size
            rows.append((name, value, size))
        if total > self.max_total_bytes or len(rows) > self.max_sessions:
            raise StoreError("Studio App session host exceeds its configured capacity")
        return rows, total

    def create(self, actor, payload):
        if not isinstance(actor, str) or not actor.strip() or len(actor) > 256:
            raise StoreError("Studio App host identity is unavailable")
        value = {"format": "studio-app-session/v1", "actor": actor,
                 "created": self.clock(), "expires": self.clock() + self.ttl_seconds,
                 "state": "active", "payload": payload}
        raw = encode(value)
        if len(raw) > MAX_SESSION_BYTES:
            raise StoreError("Studio App session exceeds its limit")
        with self._locked() as lock:
            rows, total = self._inventory(lock.dirfd)
            active_actor = sum(1 for _, row, _ in rows if row.get("actor") == actor
                               and row.get("state") == "active" and row.get("expires", 0) > self.clock())
            if len(rows) >= self.max_sessions or active_actor >= self.max_actor_sessions:
                raise StoreError("Studio App session count limit reached")
            if total + len(raw) > self.max_total_bytes:
                raise StoreError("Studio App session storage limit reached")
            handle = secrets.token_hex(32)
            self._write(self._path(handle), value, dirfd=lock.dirfd)
        return handle

    def get(self, handle, actor):
        path = self._path(handle)
        with self._locked() as lock:
            value = self._read(path, dirfd=lock.dirfd)
            if value.get("actor") != actor:
                raise StoreError("Studio App session is unavailable")
            if value.get("expires", 0) <= self.clock() and value.get("state") == "active":
                value["state"] = "expired"
                self._write(path, value, dirfd=lock.dirfd)
            if value.get("state") != "active":
                raise StoreError("Studio App session is expired or aborted")
            return value

    def update(self, handle, actor, update, *, guard=None, identity_check=None):
        return self.mutate(handle, actor, update, guard=guard, identity_check=identity_check)

    def mutate(self, handle, actor, update, *, guard=None, identity_check=None):
        """Run a bounded session mutation under one host lock and persist it atomically."""
        path = self._path(handle)
        with self._locked() as lock:
            value = self._read(path, dirfd=lock.dirfd)
            if value.get("actor") != actor:
                raise StoreError("Studio App session is unavailable")
            if value.get("expires", 0) <= self.clock() and value.get("state") == "active":
                value["state"] = "expired"
                self._write(path, value, dirfd=lock.dirfd)
            if value.get("state") != "active":
                raise StoreError("Studio App session is expired or aborted")
            if (identity_check is not None and identity_check() != actor
                    or guard is not None and (not callable(guard) or not guard(value))):
                raise StoreError("Studio App session authorization changed")
            replacement = update(value)
            if not isinstance(replacement, dict):
                raise StoreError("Studio App session update is invalid")
            if (replacement.get("state") not in ("active", "aborted", "expired")
                    or replacement.get("state") == "active" and replacement.get("expires", 0) <= self.clock()
                    or identity_check is not None and identity_check() != actor
                    or guard is not None and (not callable(guard) or not guard(replacement))):
                raise StoreError("Studio App session authorization or expiry changed during update")
            raw = encode(replacement)
            if len(raw) > MAX_SESSION_BYTES:
                raise StoreError("Studio App session exceeds its limit")
            rows, total = self._inventory(lock.dirfd)
            old_size = next((size for item, _, size in rows if item == path.name), 0)
            if total - old_size + len(raw) > self.max_total_bytes:
                raise StoreError("Studio App session storage limit reached")
            self._write(path, replacement, dirfd=lock.dirfd)
            return replacement

    def run_effect(self, handle, actor, effect_key, callback):
        """Serialize a native side effect and persist an outcome-unknown intent first.

        A process crash after the intent is durable never causes an automatic
        retry. The host must reconcile the exact native request or leave the
        session unavailable for operator recovery.
        """
        def operation(value, mark_intent):
            mark_intent(effect_key, {})
            return callback(value)
        return self.run_operation(handle, actor, operation)

    def run_operation(self, handle, actor, callback, *, identity_check=None):
        """Serialize session work; persist an outcome-unknown marker only at first effect."""
        path = self._path(handle)
        if not callable(callback):
            raise StoreError("Studio App session operation is invalid")
        with self._locked() as lock:
            value = self._read(path, dirfd=lock.dirfd)
            if value.get("actor") != actor or value.get("state") != "active" or value.get("expires", 0) <= self.clock():
                raise StoreError("Studio App session is expired or unavailable")
            payload = value.get("payload")
            if not isinstance(payload, dict):
                raise StoreError("Studio App session is malformed")
            if payload.get("effectIntent"):
                raise StoreError("Studio App prior native outcome is unknown; reconcile before retry")
            _, current_total = self._inventory(lock.dirfd)
            intent_key = {"value": None}

            def mark_intent(key, details):
                if not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key):
                    raise StoreError("Studio App effect key is invalid")
                completed = payload.get("completedEffects", [])
                if key in completed:
                    raise StoreError("Studio App native effect was already completed; inspect status")
                if intent_key["value"] is not None:
                    if intent_key["value"] != key:
                        raise StoreError("Studio App operation attempted multiple native effects")
                    return
                if not isinstance(details, dict) or len(encode(details)) > 1024:
                    raise StoreError("Studio App effect intent details exceed their limit")
                payload["effectIntent"] = {**details, "key": key, "state": "outcome-unknown",
                    "effect": "native proposal or immutable blob write may have occurred",
                    "recovery": "inspect the exact native request in the registered destination before retry"}
                raw = encode(value)
                if len(raw) > MAX_SESSION_BYTES or current_total + len(raw) > self.max_total_bytes:
                    payload.pop("effectIntent", None)
                    raise StoreError("Studio App session capacity cannot reserve the pending effect")
                self._write(path, value, dirfd=lock.dirfd)
                intent_key["value"] = key

            replacement = callback(value, mark_intent)
            if not isinstance(replacement, dict) or not isinstance(replacement.get("payload"), dict):
                raise StoreError("Studio App session operation result is invalid")
            if (replacement.get("state") != "active" or replacement.get("actor") != actor
                    or replacement.get("expires", 0) <= self.clock()
                    or identity_check is not None and (not callable(identity_check) or identity_check() != actor)):
                raise StoreError("Studio App session identity or expiry changed during operation")
            result_payload = replacement["payload"]
            if intent_key["value"] is not None:
                result_payload.pop("effectIntent", None)
                completed = result_payload.setdefault("completedEffects", [])
                if not isinstance(completed, list) or len(completed) >= 256:
                    raise StoreError("Studio App effect history exceeds its limit")
                completed.append(intent_key["value"])
            raw = encode(replacement)
            if len(raw) > MAX_SESSION_BYTES:
                raise StoreError("Studio App session exceeds its limit")
            _, total = self._inventory(lock.dirfd)
            if total + len(raw) > self.max_total_bytes:
                raise StoreError("Studio App session storage limit reached")
            self._validate_directory_fd(lock.dirfd)
            self._write(path, replacement, dirfd=lock.dirfd)
            self._validate_directory_fd(lock.dirfd)
            return replacement

    def abort(self, handle, actor):
        response = {"handle": handle, "state": "aborted"}
        compact_response(response)
        def mark(value):
            value["state"] = "aborted"
            value["payload"] = {"summary": "aborted; previously written proposals or blobs may remain"}
            value["retireAfter"] = self.clock() + SESSION_TOMBSTONE_SECONDS
            return value
        self.update(handle, actor, mark)
        return response

    def begin_upload(self, handle, actor, attachment_id, *, size, sha256, guard=None, identity_check=None):
        if (not isinstance(attachment_id, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", attachment_id)
                or type(size) is not int or not 0 <= size <= MAX_UPLOAD_BYTES
                or not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256)):
            raise StoreError("Studio App attachment declaration is invalid")
        response = {"attachment": attachment_id, "nextChunk": 0, "maxChunkBytes": MAX_CHUNK_BYTES}
        compact_response(response)
        def add(value):
            payload = value.get("payload")
            if not isinstance(payload, dict):
                raise StoreError("Studio App session does not accept attachments")
            uploads = payload.setdefault("uploads", {})
            if attachment_id in uploads:
                raise StoreError("Studio App attachment was already declared")
            total = sum(item.get("size", 0) for item in uploads.values() if isinstance(item, dict))
            if len(uploads) >= 8 or total + size > MAX_UPLOAD_BYTES:
                raise StoreError("Studio App attachment total exceeds its limit")
            uploads[attachment_id] = {"size": size, "sha256": sha256, "nextChunk": 0,
                                      "bytes": 0, "chunks": [], "complete": False}
            return value
        self.update(handle, actor, add, guard=guard, identity_check=identity_check)
        return response

    def write_chunk(self, handle, actor, attachment_id, *, index, data, guard=None, identity_check=None):
        if (type(index) is not int or index < 0 or not isinstance(data, str)
                or len(data) > ((MAX_CHUNK_BYTES + 2) // 3) * 4):
            raise StoreError("Studio App attachment chunk is invalid")
        try:
            raw = base64.b64decode(data, validate=True)
        except (ValueError, TypeError) as exc:
            raise StoreError("Studio App attachment chunk is invalid") from exc
        if not 1 <= len(raw) <= MAX_CHUNK_BYTES:
            raise StoreError("Studio App attachment chunk exceeds its limit")
        response = {"attachment": attachment_id, "acceptedChunk": index, "acceptedBytes": len(raw)}
        compact_response(response)
        def add(value):
            payload = value.get("payload", {})
            upload = payload.get("uploads", {}).get(attachment_id)
            if not isinstance(upload, dict) or upload.get("complete"):
                raise StoreError("Studio App attachment upload is unavailable")
            if index != upload.get("nextChunk"):
                raise StoreError("Studio App attachment chunks must be unique and in order")
            if index >= (MAX_UPLOAD_BYTES + MAX_CHUNK_BYTES - 1) // MAX_CHUNK_BYTES:
                raise StoreError("Studio App attachment chunk count exceeds its limit")
            if upload.get("bytes", 0) + len(raw) > upload.get("size", -1):
                raise StoreError("Studio App attachment exceeds its declared size")
            upload["chunks"].append(data)
            upload["bytes"] += len(raw)
            upload["nextChunk"] += 1
            return value
        self.update(handle, actor, add, guard=guard, identity_check=identity_check)
        return response

    def finish_upload(self, handle, actor, attachment_id, *, guard=None, identity_check=None):
        result = {}
        response = {"attachment": attachment_id, "complete": True}
        compact_response(response)
        def finish(value):
            upload = value.get("payload", {}).get("uploads", {}).get(attachment_id)
            if not isinstance(upload, dict):
                raise StoreError("Studio App attachment upload is unavailable")
            try:
                raw = (base64.b64decode(upload["content"], validate=True) if upload.get("complete")
                       else b"".join(base64.b64decode(chunk, validate=True) for chunk in upload["chunks"]))
            except (ValueError, TypeError) as exc:
                raise StoreError("Studio App attachment upload is corrupt") from exc
            if (len(raw) != upload["size"] or hashlib.sha256(raw).hexdigest() != upload["sha256"]):
                raise StoreError("Studio App attachment bytes differ from their declaration")
            if not upload.get("complete"):
                upload["complete"] = True
                upload["content"] = base64.b64encode(raw).decode("ascii")
                del upload["chunks"]
            result.update({"bytes": raw, "sha256": upload["sha256"]})
            return value
        self.update(handle, actor, finish, guard=guard, identity_check=identity_check)
        return response, result["bytes"]
