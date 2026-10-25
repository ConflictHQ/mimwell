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


class InventoryError(Exception):
    pass


_LAST_USED = {"files": 0, "pathBytes": 0, "contentBytes": 0}


def _fingerprint(value):
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def stable_tree(path, *, max_files, max_total, limits, deadline):
    """Count and hash one stable tree using no-follow, descriptor-relative IO."""
    if (type(max_files) is not int or max_files < 1 or type(max_total) is not int or max_total < 0
            or not isinstance(limits, dict)
            or set(limits) != {"files", "pathBytes", "contentBytes"}
            or any(type(value) is not int or value < 0 for value in limits.values())
            or not isinstance(deadline, (int, float)) or not math.isfinite(deadline)):
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
            rel = f"{relative}/{name}" if relative else name
            encoded_rel = os.fsencode(rel)
            if len(encoded_rel) > 4096:
                raise InventoryError("A registered storage path exceeds its bound")
            add("pathBytes", len(encoded_rel))
            try:
                named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError:
                raise InventoryError("A registered storage entry changed while measuring") from None
            if stat.S_ISDIR(named.st_mode):
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
            if named.st_size > max_total - total:
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
                while True:
                    check_time()
                    chunk = os.read(file_fd, min(1024 * 1024, named.st_size - size + 1))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > named.st_size or size > max_total - total:
                        raise InventoryError("A registered storage file changed while measuring")
                    add("contentBytes", len(chunk))
                    digest.update(chunk)
                after = os.fstat(file_fd)
                current_name = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (size != named.st_size or not same_entry(opened, after)
                        or not same_entry(after, current_name)):
                    raise InventoryError("A registered storage file changed while measuring")
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
            or set(request) != {"path", "maxFiles", "maxTotal", "limits", "deadline"}
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
                             deadline=request["deadline"])
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
