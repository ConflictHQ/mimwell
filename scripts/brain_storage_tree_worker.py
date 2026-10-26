"""Isolated, standard-library-only walker for admitted storage trees.

This file is invoked as a fresh Python process by brain_storage_admission. It
must stay independent of SQLite and project modules: closing a raw descriptor
for a SQLite inode in the process holding its connection can cancel that
process's POSIX advisory locks.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import stat
import sys
import time


class HostRegistrationError(ValueError):
    """The canonical closed Studio App transport registration is invalid."""


def validate_host_registration(value):
    """Pure canonical host metadata validation, shared with RegisteredHost."""
    if (not isinstance(value, dict) or set(value) != {"format", "principals", "aliases"}
            or value.get("format") != "studio-app-mcp-host/v1"
            or not isinstance(value["principals"], dict) or not isinstance(value["aliases"], dict)
            or not 1 <= len(value["aliases"]) <= 64 or len(value["principals"]) > 256):
        raise HostRegistrationError("Studio App host registration is invalid")
    for digest, actor in value["principals"].items():
        if (not isinstance(digest, str) or len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)
                or not isinstance(actor, str) or not actor.strip() or len(actor) > 256):
            raise HostRegistrationError("Studio App host principal registration is invalid")
    for alias, entry in value["aliases"].items():
        if (not isinstance(alias, str) or not alias.isidentifier() or len(alias) > 64
                or not isinstance(entry, dict)
                or set(entry) - {"root", "authority", "binding", "grants", "nativeActors", "blobProtected"}
                or not {"root", "authority", "binding", "grants", "nativeActors"}.issubset(entry)
                or not isinstance(entry["root"], str) or not Path(entry["root"]).is_absolute()
                or not isinstance(entry["authority"], str)
                or not isinstance(entry["binding"], str) or len(entry["binding"]) != 64
                or not isinstance(entry["grants"], dict) or not isinstance(entry["nativeActors"], dict)
                or "blobProtected" in entry and type(entry["blobProtected"]) is not bool):
            raise HostRegistrationError("Studio App host alias registration is invalid")
        for actor, grants in entry["grants"].items():
            native_actor = entry["nativeActors"].get(actor)
            if (actor not in value["principals"].values() or not isinstance(native_actor, str)
                    or not native_actor.strip() or len(native_actor) > 256 or not isinstance(grants, list)
                    or len(grants) != len(set(grants))
                    or any(grant not in ("read", "propose") for grant in grants)):
                raise HostRegistrationError("Studio App host alias grant is invalid")
        if set(entry["nativeActors"]) != set(entry["grants"]):
            raise HostRegistrationError("Studio App native actor mappings must match explicit alias grants")
    return value


class InventoryError(Exception):
    pass


_LAST_USED = {"files": 0, "pathBytes": 0, "contentBytes": 0}


def _fingerprint(value):
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def stable_tree(path, *, max_files, max_total, limits, deadline, only_files=None, header_only=False,
                private_exclusions=None):
    """Count and hash one stable tree using no-follow, descriptor-relative IO."""
    if (type(max_files) is not int or max_files < 1 or type(max_total) is not int or max_total < 0
            or not isinstance(limits, dict)
            or set(limits) != {"files", "pathBytes", "contentBytes"}
            or any(type(value) is not int or value < 0 for value in limits.values())
            or not isinstance(deadline, (int, float)) or not math.isfinite(deadline)):
        raise InventoryError("Registered storage inventory bounds are invalid")
    if only_files is not None and (not isinstance(only_files, list) or not 1 <= len(only_files) <= 64
            or any(not isinstance(name, str) or not name or name in (".", "..")
                   or "/" in name or "\\" in name or "\x00" in name for name in only_files)
            or len(set(only_files)) != len(only_files)):
        raise InventoryError("Registered storage inventory bounds are invalid")
    if type(header_only) is not bool or header_only and only_files is None:
        raise InventoryError("Registered storage inventory bounds are invalid")
    if private_exclusions is not None and (
            not isinstance(private_exclusions, list) or len(private_exclusions) > 128
            or only_files is not None or header_only
            or any(not isinstance(name, str) or not name or name.startswith("/") or "\\" in name
                   or "\x00" in name or any(part in ("", ".", "..") for part in name.split("/"))
                   for name in private_exclusions)):
        raise InventoryError("Registered storage inventory bounds are invalid")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise InventoryError("Safe registered storage inventory is unavailable on this platform")
    root = Path(path)
    try:
        root_named = root.lstat()
    except OSError:
        raise InventoryError("A registered storage root is unavailable or unsafe") from None
    if not stat.S_ISDIR(root_named.st_mode):
        raise InventoryError("A registered storage root is unavailable or unsafe")

    no_write = stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID
    global _LAST_USED
    used = {key: 0 for key in limits}
    _LAST_USED = used

    def check_time():
        if time.monotonic() >= deadline:
            raise InventoryError("Storage inspection exceeded its time budget")

    def add(key, amount):
        check_time()
        if type(amount) is not int or amount < 0:
            raise InventoryError("Storage inspection budget input is invalid")
        total_used = used[key] + amount
        if total_used > limits[key]:
            raise InventoryError("Storage inspection exceeded its bounded inventory")
        used[key] = total_used

    def same_entry(left, right):
        return (left.st_dev, left.st_ino, left.st_mode, left.st_uid, left.st_nlink,
                left.st_size, left.st_mtime_ns, left.st_ctime_ns) == (
                right.st_dev, right.st_ino, right.st_mode, right.st_uid, right.st_nlink,
                right.st_size, right.st_mtime_ns, right.st_ctime_ns)

    def validate_directory(info):
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & no_write):
            raise InventoryError("A registered storage directory is unsafe")

    def open_flags(directory=False):
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        if directory:
            flags |= os.O_DIRECTORY
        else:
            flags |= getattr(os, "O_NONBLOCK", 0)
        return flags

    total = 0
    files = 0
    entries = 0
    basis = []

    def walk(directory_fd, relative):
        nonlocal total, files, entries
        check_time()
        if private_exclusions is not None and len(Path(relative).parts) > 32:
            raise InventoryError("Storage inspection exceeded its bounded inventory")
        before_dir = os.fstat(directory_fd)
        validate_directory(before_dir)
        try:
            with os.scandir(directory_fd) as iterator:
                names = []
                for entry in iterator:
                    entries += 1
                    if entries > max_files:
                        raise InventoryError("Registered storage inventory exceeds its bound")
                    add("files", 1)
                    if len(entry.name.encode("utf-8", "surrogateescape")) > 255:
                        raise InventoryError("A registered storage path is unsafe")
                    names.append(entry.name)
        except OSError:
            raise InventoryError("A registered storage directory changed while measuring") from None
        names.sort()
        for name in names:
            check_time()
            if only_files is not None and not relative and name not in only_files:
                continue
            rel = f"{relative}/{name}" if relative else name
            if private_exclusions is not None and rel in private_exclusions:
                continue
            encoded_rel = os.fsencode(rel)
            if len(encoded_rel) > 4096:
                raise InventoryError("A registered storage path exceeds its bound")
            add("pathBytes", len(encoded_rel))
            try:
                named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError:
                raise InventoryError("A registered storage entry changed while measuring") from None
            if stat.S_ISDIR(named.st_mode):
                if only_files is not None:
                    raise InventoryError("A registered storage file is unsafe")
                validate_directory(named)
                try:
                    child_fd = os.open(name, open_flags(directory=True), dir_fd=directory_fd)
                except OSError:
                    raise InventoryError("A registered storage directory is unsafe") from None
                try:
                    opened = os.fstat(child_fd)
                    if not same_entry(named, opened):
                        raise InventoryError("A registered storage directory changed while opening")
                    walk(child_fd, rel)
                    after = os.fstat(child_fd)
                    current_name = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if not same_entry(opened, after) or not same_entry(after, current_name):
                        raise InventoryError("A registered storage directory changed while measuring")
                finally:
                    os.close(child_fd)
                continue

            if (not stat.S_ISREG(named.st_mode) or named.st_nlink != 1
                    or named.st_uid != os.geteuid() or named.st_mode & no_write):
                raise InventoryError("A registered storage file is unsafe")
            if private_exclusions is not None and rel != "studio-apps-host.json" and named.st_size:
                raise InventoryError("Unregistered private retained content requires an explicit retained root")
            host_configuration = private_exclusions is not None and rel == "studio-apps-host.json"
            if host_configuration and named.st_mode & 0o077:
                raise InventoryError("Studio App host registration is invalid")
            read_limit = min(named.st_size, 16) if header_only else named.st_size
            if read_limit > max_total - total:
                raise InventoryError("Registered storage inventory exceeds its bound")
            try:
                file_fd = os.open(name, open_flags(), dir_fd=directory_fd)
            except OSError:
                raise InventoryError("A registered storage file is unsafe") from None
            try:
                opened = os.fstat(file_fd)
                if not same_entry(named, opened):
                    raise InventoryError("A registered storage file changed while opening")
                digest = hashlib.sha256()
                size = 0
                prefix = b""
                host_bytes = bytearray() if host_configuration else None
                while True:
                    check_time()
                    if header_only and size == read_limit:
                        break
                    chunk = os.read(file_fd, min(1024 * 1024, read_limit - size + (0 if header_only else 1)))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > read_limit or size > max_total - total:
                        raise InventoryError("A registered storage file changed while measuring")
                    if header_only:
                        prefix += chunk
                    if host_bytes is not None:
                        host_bytes.extend(chunk)
                    add("contentBytes", len(chunk))
                    digest.update(chunk)
                after = os.fstat(file_fd)
                current_name = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (size != read_limit or not same_entry(opened, after)
                        or not same_entry(after, current_name)):
                    raise InventoryError("A registered storage file changed while measuring")
                if header_only and (prefix == b"SQLite format 3\x00" or prefix.lstrip().startswith(b"{")):
                    raise InventoryError("Native sidecar contains standalone authority content")
                if host_bytes is not None:
                    try:
                        validate_host_registration(json.loads(host_bytes))
                    except (ValueError, UnicodeError, TypeError, RecursionError):
                        raise InventoryError("Studio App host registration is invalid") from None
            except OSError:
                raise InventoryError("A registered storage file is unavailable") from None
            finally:
                os.close(file_fd)
            total += size
            files += 1
            try:
                rel.encode("utf-8")
                basis_path = rel
            except UnicodeEncodeError:
                basis_path = {"filesystemBytesHex": encoded_rel.hex()}
            basis.append((basis_path, size, digest.hexdigest()))

        after_dir = os.fstat(directory_fd)
        if not same_entry(before_dir, after_dir):
            raise InventoryError("A registered storage directory changed while measuring")
        try:
            with os.scandir(directory_fd) as iterator:
                after_names = []
                for entry in iterator:
                    if len(after_names) >= len(names):
                        raise InventoryError("A registered storage directory changed while measuring")
                    after_names.append(entry.name)
                after_names.sort()
        except OSError:
            raise InventoryError("A registered storage directory changed while measuring") from None
        if names != after_names:
            raise InventoryError("A registered storage directory changed while measuring")

    try:
        root_fd = os.open(root, open_flags(directory=True))
    except OSError:
        raise InventoryError("A registered storage root is unavailable or unsafe") from None
    try:
        root_opened = os.fstat(root_fd)
        validate_directory(root_opened)
        if not same_entry(root_named, root_opened):
            raise InventoryError("A registered storage root changed while opening")
        walk(root_fd, "")
        root_after = os.fstat(root_fd)
        root_named_after = root.lstat()
        if not same_entry(root_opened, root_after) or not same_entry(root_after, root_named_after):
            raise InventoryError("A registered storage root changed while measuring")
    except OSError:
        raise InventoryError("A registered storage root changed while measuring") from None
    finally:
        os.close(root_fd)
    check_time()
    return {"ok": True, "total": total, "basis": _fingerprint(basis), "files": files,
            "used": used, "workerPid": os.getpid()}


def _request():
    raw = sys.stdin.buffer.read(16 * 1024 + 1)
    if len(raw) > 16 * 1024:
        raise InventoryError("Storage inventory request exceeded its bound")
    try:
        request = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise InventoryError("Storage inventory request is invalid") from None
    if (not isinstance(request, dict)
            or set(request) not in ({"path", "maxFiles", "maxTotal", "limits", "deadline"},
                                   {"path", "maxFiles", "maxTotal", "limits", "deadline", "onlyFiles"},
                                   {"path", "maxFiles", "maxTotal", "limits", "deadline", "onlyFiles", "headerOnly"},
                                   {"path", "maxFiles", "maxTotal", "limits", "deadline", "privateExclusions"})
            or not isinstance(request["path"], str)):
        raise InventoryError("Storage inventory request is invalid")
    return request


def main(*, _owner_deadline=None):
    try:
        if sys.argv[1:] != ["--worker-v1"]:
            raise InventoryError("Storage inventory worker invocation is invalid")
        request = _request()
        if _owner_deadline is not None and request["deadline"] != _owner_deadline:
            raise InventoryError("Storage inventory owner deadline differs from its request")
        result = stable_tree(request["path"], max_files=request["maxFiles"],
                             max_total=request["maxTotal"], limits=request["limits"],
                             deadline=request["deadline"], only_files=request.get("onlyFiles"),
                             header_only=request.get("headerOnly", False),
                             private_exclusions=request.get("privateExclusions"))
        status = 0
    except InventoryError as exc:
        result = {"ok": False, "error": str(exc), "used": dict(_LAST_USED),
                  "workerPid": os.getpid()}
        status = 2
    except BaseException:
        result = {"ok": False, "error": "Registered storage inventory failed safely",
                  "used": dict(_LAST_USED), "workerPid": os.getpid()}
        status = 2
    raw = json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(raw) > 4096:
        raw = b'{"error":"Storage inventory result exceeded its bound","ok":false}'
        status = 2
    sys.stdout.buffer.write(raw + b"\n")
    sys.stdout.buffer.flush()
    return status


class _OwnerLifetime:
    """Internal deadline/EOF monitor for this one live session leader only."""

    def __init__(self, descriptor, deadline):
        # Lazy Unix-only imports preserve the legacy private worker entry point.
        import fcntl
        import select
        import signal
        import threading

        self.pid = os.getpid()
        if (os.getpgrp() != self.pid or os.getsid(0) != self.pid
                or type(descriptor) is not int or not 3 <= descriptor <= 2**31 - 1
                or type(deadline) is not float or not math.isfinite(deadline)):
            raise InventoryError("Storage inventory owner monitor is unavailable")
        info = os.fstat(descriptor)
        if (not stat.S_ISFIFO(info.st_mode)
                or fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY):
            raise InventoryError("Storage inventory owner monitor is unavailable")
        os.set_inheritable(descriptor, False)
        os.set_blocking(descriptor, False)
        self.owner_fd, self.deadline = descriptor, deadline
        self.select, self.signal = select.select, signal.SIGKILL
        self.stop_read = self.stop_write = None
        self.stopping = False
        self.thread = None
        try:
            self.stop_read, self.stop_write = os.pipe()
            os.set_blocking(self.stop_read, False)
            os.set_blocking(self.stop_write, False)
            self.thread = threading.Thread(target=self._watch, name="inventory-owner-lifetime")
        except BaseException:
            self._close_descriptors()
            raise

    def _stop_own_group(self):
        # This executing session leader pins its own group ID; it never signals
        # a saved parent PID or an observed/unowned numeric process identity.
        import signal

        try:
            os.killpg(self.pid, self.signal)
        except BaseException:
            # A denied signal cannot be translated into a successful result.
            os._exit(125)
        # A successful self-group SIGKILL may still be pending on another
        # thread. Do not race it with a normal _exit from this monitor thread.
        # SIGKILL is uncatchable; interrupted waits cannot resume inventory.
        while True:
            signal.pause()

    def _watch(self):
        try:
            while True:
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    self._stop_own_group()
                try:
                    ready, _, _ = self.select([self.owner_fd, self.stop_read], [], [], remaining)
                except InterruptedError:
                    continue
                if self.owner_fd in ready:
                    # Sole owner never writes: EOF or unexpected data both stop.
                    os.read(self.owner_fd, 1)
                    self._stop_own_group()
                if self.stop_read in ready:
                    os.read(self.stop_read, 1)
                    if self.stopping:
                        return
                    self._stop_own_group()
        except BaseException:
            self._stop_own_group()

    def start(self):
        self.thread.start()

    def _close_descriptors(self):
        for name in ("owner_fd", "stop_read", "stop_write"):
            descriptor = getattr(self, name, None)
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, name, None)

    def close(self):
        try:
            if self.thread is not None and self.thread.ident is not None:
                self.stopping = True
                try:
                    os.write(self.stop_write, b"S")
                except OSError:
                    self._stop_own_group()
                try:
                    self.thread.join(timeout=1.0)
                except BaseException:
                    self._stop_own_group()
                if self.thread.is_alive():
                    self._stop_own_group()
        finally:
            # Never close a descriptor while the monitor might still select it.
            self._close_descriptors()


def _run():
    arguments = sys.argv[1:]
    if arguments == ["--worker-v1"]:
        # Retain the legacy direct/private CLI contract without an implicit
        # owner claim. Canonical production launches always provide the guard.
        return main()
    if (len(arguments) != 5 or arguments[0] != "--owner-fd"
            or arguments[2] != "--deadline" or arguments[4] != "--worker-v1"):
        return main()
    monitor = None
    original_argv = sys.argv
    try:
        fd_text, deadline_text = arguments[1], arguments[3]
        if (not fd_text.isascii() or not fd_text.isdecimal() or len(fd_text) > 10
                or len(deadline_text) > 64):
            return 125
        monitor = _OwnerLifetime(int(fd_text), float(deadline_text))
        monitor.start()
        # Start monitoring BEFORE the original bounded request read. Keep its
        # legacy parser/result protocol and bind both deadlines to one value.
        sys.argv = [original_argv[0], "--worker-v1"]
        return main(_owner_deadline=monitor.deadline)
    except (InventoryError, OSError, ValueError, OverflowError):
        return 125
    finally:
        sys.argv = original_argv
        if monitor is not None:
            monitor.close()


if __name__ == "__main__":
    raise SystemExit(_run())
