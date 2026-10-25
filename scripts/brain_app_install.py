"""Owner-mediated installation of one reviewed, disabled App bundle.

This module deliberately has no MCP entrypoint. A host may expose these
operations only through its authenticated local owner-admin boundary: applying
a preview confirms the exact source commit and bundle digest. It does not
enroll, enable, or grant the App.
"""

from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import unicodedata
import ctypes

from brain_apps import bundle_digest, check_app
from brain_storage_admission import (
    AdmissionLedger,
    InventoryBudget,
    StoreError,
    _bounded_git_output,
    _open_directory_chain,
    _selected_authority_path,
    fingerprint,
    inventory,
    load_registration,
)
from knowledge_store import blob_store_for, adopted_authority

MAX_APP_BYTES = 64 * 1024 * 1024
MAX_APP_FILES = 10_000
MAX_APP_PATH_BYTES = 4096
MAX_APP_DEPTH = 32
MAX_GIT_INDEX_BYTES = 8 * 1024 * 1024
MAX_GIT_INDEX_ENTRIES = 200_000
MAX_GIT_INDEX_PATH_BYTES = 4096
MAX_OPERATION_SECONDS = 120.0
_APP_ID = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_SHA = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})\Z")


def _identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _directory_identity(info):
    # Directory link count and timestamps change as entries are staged.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid)


def _stable_identity(info):
    """Fields a same-filesystem rename must preserve for the pinned index inode."""
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink, info.st_size, info.st_mtime_ns)


def _git(root, *arguments, budget, index_file=None):
    # Plumbing only: hooks are never part of this host-mediated operation.
    command = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "commit.gpgsign=false",
        "-C",
        str(root),
        *arguments,
    ]
    if arguments and arguments[0] == "diff":
        subcommand = command.index("diff", command.index("-C") + 2)
        command[subcommand + 1 : subcommand + 1] = ["--no-ext-diff", "--no-textconv"]
    return _bounded_git_output(command, budget, git_index_file=str(index_file) if index_file else None)


def _git_input(root, data, *arguments, budget, index_file=None):
    """Pass already-verified bytes to a bounded Git plumbing command."""
    return _bounded_git_output(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "commit.gpgsign=false",
            "-C",
            str(root),
            *arguments,
        ],
        budget,
        stdin_bytes=data,
        git_index_file=str(index_file) if index_file else None,
    )


def _git_text(root, *arguments, budget, index_file=None):
    try:
        value = _git(root, *arguments, budget=budget, index_file=index_file).decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise StoreError("App install Git metadata is malformed") from exc
    return value


def _repo_state(root, budget):
    top = Path(_git_text(root, "rev-parse", "--show-toplevel", budget=budget)).resolve(strict=True)
    if top != root:
        raise StoreError("App install target is not the selected brain repository root")
    head = _git_text(root, "rev-parse", "--verify", "HEAD^{commit}", budget=budget)
    if not _SHA.fullmatch(head):
        raise StoreError("App install target HEAD is unavailable")
    branch = _git_text(root, "symbolic-ref", "-q", "HEAD", budget=budget)
    if not branch.startswith("refs/heads/"):
        raise StoreError("App install requires an owner-selected local branch")
    object_format = _git_text(root, "rev-parse", "--show-object-format=storage", budget=budget)
    if object_format not in ("sha1", "sha256"):
        raise StoreError("App install target object format is unsupported")
    commit_identity = _git_commit_identity(root, budget)
    status = _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all", budget=budget)
    if status:
        raise StoreError("App install requires a clean target worktree and index")
    index_name = _git_text(root, "rev-parse", "--path-format=absolute", "--git-path", "index", budget=budget)
    index = Path(index_name)
    info, index_bytes = _read_index(index)
    _validate_index(index_bytes, object_format)
    index_parent_fd = _open_directory_chain(index.parent)
    try:
        index_parent_identity = _identity(os.fstat(index_parent_fd))
    finally:
        os.close(index_parent_fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
        or info.st_size > MAX_GIT_INDEX_BYTES
    ):
        raise StoreError("App install target index is unsafe or exceeds its bound")
    if _index_lock_exists(index):
        raise StoreError("App install target index is locked")
    _require_supported_index_extensions(root, budget)
    index_entries = _git(root, "ls-files", "--stage", "-z", budget=budget)
    return {
        "head": head,
        "branch": branch,
        "objectFormat": object_format,
        "indexBytes": info.st_size,
        "indexPath": index,
        "indexIdentity": _identity(info),
        "indexParentIdentity": index_parent_identity,
        "indexSha256": hashlib.sha256(index_bytes).hexdigest(),
        "indexEntriesSha256": hashlib.sha256(index_entries).hexdigest(),
        "commitIdentitySha256": fingerprint(commit_identity),
    }


def _git_commit_identity(root, budget):
    """Resolve and pin the effective repository-local author and committer."""
    raw = _git(root, "config", "--local", "--no-includes", "--null", "--list", budget=budget)
    if len(raw) > 1024 * 1024:
        raise StoreError("App install Git configuration exceeds its bound")
    configured = {}
    for row in raw.split(b"\0"):
        if not row:
            continue
        key, separator, value = row.partition(b"\n")
        if not separator:
            raise StoreError("App install Git identity configuration is malformed")
        configured.setdefault(key.lower(), []).append(value)

    def one(key):
        values = configured.get(key.encode("ascii"), [])
        if len(values) > 1:
            raise StoreError("App install requires one repository-local Git identity value")
        return values[0] if values else None

    selected = []
    for specific, fallback in (
        ("author.name", "user.name"),
        ("author.email", "user.email"),
        ("committer.name", "user.name"),
        ("committer.email", "user.email"),
    ):
        value = one(specific)
        if value is None:
            value = one(fallback)
        try:
            decoded = value.decode("utf-8") if value is not None else ""
        except UnicodeDecodeError as exc:
            raise StoreError("App install requires a valid repository-local Git identity") from exc
        if not decoded or len(value) > 256 or any(character in decoded for character in "\r\n\x00"):
            raise StoreError("App install requires a valid repository-local Git identity")
        selected.append(decoded)
    return tuple(selected)


def _read_index(index):
    parent_fd = None
    try:
        parent_fd = _open_directory_chain(index.parent)
        parent_info = os.fstat(parent_fd)
        named_parent = index.parent.lstat()
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != os.geteuid()
            or parent_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
            or (parent_info.st_dev, parent_info.st_ino) != (named_parent.st_dev, named_parent.st_ino)
        ):
            raise StoreError("App install target index directory is unsafe")
        return _read_index_at(parent_fd, index.name)
    except OSError as exc:
        raise StoreError("App install target index is unavailable") from exc
    finally:
        if parent_fd is not None:
            os.close(parent_fd)


def _read_index_at(parent_fd, name):
    fd = None
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
            or before.st_size > MAX_GIT_INDEX_BYTES
        ):
            raise StoreError("App install target index is unsafe or exceeds its bound")
        fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        opened = os.fstat(fd)
        if _identity(opened) != _identity(before):
            raise StoreError("App install target index changed while opening")
        chunks = []
        remaining = MAX_GIT_INDEX_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if len(data) != before.st_size or _identity(after) != _identity(opened) or _identity(named) != _identity(after):
            raise StoreError("App install target index changed while reading")
        return after, data
    except OSError as exc:
        raise StoreError("App install target index is unavailable or unsafe") from exc
    finally:
        if fd is not None:
            os.close(fd)


def _validate_index(data, object_format):
    digest_size = 20 if object_format == "sha1" else 32
    if len(data) < 12 + digest_size or data[:4] != b"DIRC":
        raise StoreError("App install target index format is invalid")
    version = int.from_bytes(data[4:8], "big")
    count = int.from_bytes(data[8:12], "big")
    hasher = hashlib.sha1() if object_format == "sha1" else hashlib.sha256()
    hasher.update(data[:-digest_size])
    if version not in (2, 3, 4) or count > MAX_GIT_INDEX_ENTRIES or hasher.digest() != data[-digest_size:]:
        raise StoreError("App install target index format or checksum is unsupported")


def _require_supported_index_extensions(root, budget):
    config = _git(root, "config", "--local", "--no-includes", "--null", "--list", budget=budget)
    if len(config) > 1024 * 1024:
        raise StoreError("App install Git configuration exceeds its bound")
    for row in config.split(b"\0"):
        if not row:
            continue
        key, separator, value = row.partition(b"\n")
        if not separator:
            raise StoreError("App install Git configuration is malformed")
        normalized = key.lower()
        truthy = value.strip().lower() in (b"true", b"yes", b"on", b"1")
        if truthy and normalized in (b"core.splitindex", b"core.untrackedcache", b"index.sparse"):
            raise StoreError("App install does not support split, sparse, or untracked-cache Git indexes")
    common = Path(_git_text(root, "rev-parse", "--path-format=absolute", "--git-common-dir", budget=budget))
    common_fd = _open_directory_chain(common)
    try:
        with os.scandir(common_fd) as entries:
            for number, entry in enumerate(entries, 1):
                if number > MAX_GIT_INDEX_ENTRIES:
                    raise StoreError("App install Git metadata inventory exceeds its bound")
                if entry.name.startswith("sharedindex."):
                    raise StoreError("App install does not support split Git indexes")
    except OSError as exc:
        raise StoreError("App install Git metadata is unavailable") from exc
    finally:
        os.close(common_fd)


def _index_lock_exists(index):
    parent_fd = _open_directory_chain(index.parent)
    try:
        try:
            os.stat("index.lock", dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True
    except OSError as exc:
        raise StoreError("App install target index lock state is unavailable") from exc
    finally:
        os.close(parent_fd)


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise StoreError("App install could not write complete Git index data")
        view = view[count:]


def _acquire_index_lock(index, preview, operation):
    """Serialize cooperative Git index writers and prepare a private candidate index."""
    parent_fd = lock_fd = private_fd = None
    lock_name = index.name + ".lock"
    private_name = f".brain-app-install-index-{operation}"
    try:
        parent_fd = _open_directory_chain(index.parent)
        parent_info = os.fstat(parent_fd)
        named_parent = index.parent.lstat()
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != os.geteuid()
            or parent_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
            or (parent_info.st_dev, parent_info.st_ino) != (named_parent.st_dev, named_parent.st_ino)
            or hashlib.sha256(repr(_identity(parent_info)).encode()).hexdigest()
            != preview["targetIndexParentIdentitySha256"]
        ):
            raise StoreError("App install Git index directory changed after review")
        original_info, original_bytes = _read_index_at(parent_fd, index.name)
        _validate_index(original_bytes, preview["targetObjectFormat"])
        if (
            hashlib.sha256(os.fsencode(index)).hexdigest() != preview["targetIndexPathSha256"]
            or hashlib.sha256(repr(_identity(original_info)).encode()).hexdigest()
            != preview["targetIndexIdentitySha256"]
            or hashlib.sha256(original_bytes).hexdigest() != preview["targetIndexSha256"]
        ):
            raise StoreError("App install target index changed after review")
        lock_fd = os.open(
            lock_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent_fd,
        )
        os.fchmod(lock_fd, 0o600)
        lock_marker = f"brain-app-install/v1 {operation}\n".encode("ascii")
        _write_all(lock_fd, lock_marker)
        os.fsync(lock_fd)
        lock_identity = _identity(os.fstat(lock_fd))
        named_lock = os.stat(lock_name, dir_fd=parent_fd, follow_symlinks=False)
        if _identity(named_lock) != lock_identity:
            raise StoreError("App install Git index lock changed while opening")
        private_fd = os.open(
            private_name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent_fd,
        )
        os.fchmod(private_fd, 0o600)
        _write_all(private_fd, original_bytes)
        os.fsync(private_fd)
        private_identity = _identity(os.fstat(private_fd))
        named_private = os.stat(private_name, dir_fd=parent_fd, follow_symlinks=False)
        if _identity(named_private) != private_identity:
            raise StoreError("App install private Git index changed while opening")
        # Git update-index atomically replaces this pathname. Do not retain an
        # unlinked copy of the initial index while its own index.lock exists.
        os.close(private_fd)
        private_fd = None
        os.fsync(parent_fd)
        return {
            "path": index,
            "parentFd": parent_fd,
            "parentIdentity": _identity(parent_info),
            "lockName": lock_name,
            "lockFd": lock_fd,
            "lockIdentity": lock_identity,
            "privateName": private_name,
            "privateFd": None,
            "privateIdentity": private_identity,
            "privatePath": index.parent / private_name,
            "published": False,
        }
    except BaseException as exc:
        # Do not remove a lock or candidate index once created: an interrupted
        # operation is reconciled from its durable ledger row and named residue.
        for descriptor in (private_fd, lock_fd, parent_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if isinstance(exc, OSError):
            raise StoreError("App install Git index lock or candidate is unavailable") from exc
        raise


def _verify_held_index_lock(index_state):
    parent_fd = index_state["parentFd"]
    parent_info = os.fstat(parent_fd)
    named_parent = index_state["path"].parent.lstat()
    lock_info = os.fstat(index_state["lockFd"])
    named_lock = os.stat(index_state["lockName"], dir_fd=parent_fd, follow_symlinks=False)
    if (
        (parent_info.st_dev, parent_info.st_ino) != index_state["parentIdentity"][:2]
        or (named_parent.st_dev, named_parent.st_ino) != index_state["parentIdentity"][:2]
        or _identity(lock_info) != index_state["lockIdentity"]
        or _identity(named_lock) != index_state["lockIdentity"]
    ):
        raise StoreError("App install Git index lock changed during operation")


def _verify_original_index(index_state, preview):
    _verify_held_index_lock(index_state)
    info, data = _read_index_at(index_state["parentFd"], index_state["path"].name)
    if (
        hashlib.sha256(repr(_identity(info)).encode()).hexdigest() != preview["targetIndexIdentitySha256"]
        or hashlib.sha256(data).hexdigest() != preview["targetIndexSha256"]
    ):
        raise StoreError("App install target Git index changed during operation")
    return info, data


def _read_candidate_index(index_state, object_format):
    _verify_held_index_lock(index_state)
    info, data = _read_index_at(index_state["parentFd"], index_state["privateName"])
    _validate_index(data, object_format)
    index_state["privateIdentity"] = _identity(info)
    return info, data


def _publish_candidate_index(index_state, preview, maximum_bytes):
    parent_fd = index_state["parentFd"]
    _verify_original_index(index_state, preview)
    candidate_info, candidate_bytes = _read_candidate_index(index_state, preview["targetObjectFormat"])
    if candidate_info.st_size > maximum_bytes:
        raise StoreError("App install target index exceeded its preflight bound")
    _verify_held_index_lock(index_state)
    named_candidate = os.stat(index_state["privateName"], dir_fd=parent_fd, follow_symlinks=False)
    if _identity(named_candidate) != _identity(candidate_info):
        raise StoreError("App install private Git index changed before publication")
    # Keep the exclusive lock sentinel in place while replacing the real index.
    # Cooperating Git processes will continue to refuse writes until ref CAS.
    os.replace(
        index_state["privateName"],
        index_state["path"].name,
        src_dir_fd=parent_fd,
        dst_dir_fd=parent_fd,
    )
    os.fsync(parent_fd)
    published_info, published_bytes = _read_index_at(parent_fd, index_state["path"].name)
    if (
        published_bytes != candidate_bytes
        or _stable_identity(published_info) != _stable_identity(named_candidate)
        or published_info.st_size > maximum_bytes
    ):
        raise StoreError("App install target index publication is uncertain")
    index_state["published"] = True
    index_state["publishedIdentity"] = _identity(published_info)
    index_state["publishedSha256"] = hashlib.sha256(published_bytes).hexdigest()


def _validate_index_entries(root, source, app_id, preview, budget, *, index_file, staged):
    raw = _git(root, "ls-files", "--stage", "-z", budget=budget, index_file=index_file)
    rows = raw.split(b"\0")
    if rows and rows[-1] == b"":
        rows.pop()
    elif raw:
        raise StoreError("App install target index inventory is malformed")
    baseline = []
    additions = {}
    prefix = f"apps/{app_id}/".encode("utf-8")
    expected = {}
    if staged:
        for relative, body in source["files"].items():
            path = prefix + relative.encode("utf-8")
            mode = b"100755" if source["entries"][relative]["executable"] else b"100644"
            oid = _git_blob_oid(body, preview["targetObjectFormat"]).encode("ascii")
            expected[path] = (mode, oid)
    seen = set()
    for row in rows:
        try:
            header, path = row.split(b"\t", 1)
            mode, oid, stage = header.split(b" ", 2)
        except ValueError as exc:
            raise StoreError("App install target index inventory is malformed") from exc
        if path in seen or stage != b"0" or mode not in (b"100644", b"100755", b"120000", b"160000"):
            raise StoreError("App install target index inventory is unsupported")
        if len(oid) != (40 if preview["targetObjectFormat"] == "sha1" else 64) or not re.fullmatch(rb"[a-f0-9]+", oid):
            raise StoreError("App install target index object id is malformed")
        seen.add(path)
        if path.startswith(prefix) or path == prefix[:-1]:
            additions[path] = (mode, oid)
        else:
            baseline.append(row)
    normalized_baseline = b"\0".join(baseline) + (b"\0" if baseline else b"")
    if hashlib.sha256(normalized_baseline).hexdigest() != preview["targetIndexEntriesSha256"]:
        raise StoreError("App install target index entries changed after review")
    if additions != expected:
        raise StoreError("App install target index entries differ from the reviewed bundle")


def _release_index_lock(index_state):
    _verify_held_index_lock(index_state)
    os.unlink(index_state["lockName"], dir_fd=index_state["parentFd"])
    os.fsync(index_state["parentFd"])


def _close_index_state(index_state):
    for key in ("privateFd", "lockFd", "parentFd"):
        descriptor = index_state.get(key)
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _assert_index_preview(root, preview, budget, *, index_state=None, index_file=None, candidate_staged=False):
    if index_state is not None:
        if index_state["published"]:
            _verify_held_index_lock(index_state)
            info, data = _read_index_at(index_state["parentFd"], index_state["path"].name)
            if (
                _identity(info) != index_state["publishedIdentity"]
                or hashlib.sha256(data).hexdigest() != index_state["publishedSha256"]
            ):
                raise StoreError("App install published Git index changed during operation")
            return
        _verify_original_index(index_state, preview)
        info, data = _read_candidate_index(index_state, preview["targetObjectFormat"])
        if not candidate_staged and (
            hashlib.sha256(data).hexdigest() != preview["targetIndexSha256"]
            or info.st_size != preview["targetIndexBytes"]
        ):
            raise StoreError("App install private Git index changed before staging")
        return
    name = _git_text(
        root, "rev-parse", "--path-format=absolute", "--git-path", "index", budget=budget, index_file=index_file
    )
    index = Path(name)
    info, data = _read_index(index)
    _validate_index(data, preview["targetObjectFormat"])
    if _index_lock_exists(index):
        raise StoreError("App install target index is locked")
    if (
        hashlib.sha256(os.fsencode(index)).hexdigest() != preview["targetIndexPathSha256"]
        or hashlib.sha256(repr(_identity(info)).encode()).hexdigest() != preview["targetIndexIdentitySha256"]
        or hashlib.sha256(data).hexdigest() != preview["targetIndexSha256"]
    ):
        raise StoreError("App install target index changed after review")


def _git_index_upper_bound(root, new_paths, object_format, existing_index_bytes, budget):
    """Bound a v2/v3-style index from the actual validated path inventory.

    Git can preserve or rebuild optional index extensions. The existing index
    size is therefore included as extension slack, along with a conservative
    cache-tree/extension allowance derived from every path prefix. If that
    bound exceeds the supported index ceiling, preview refuses before reserve
    or filesystem/Git write effects.
    """
    raw = _git(root, "ls-files", "--stage", "-z", budget=budget)
    paths = set()
    for row in raw.split(b"\0"):
        if not row:
            continue
        try:
            _entry, path = row.split(b"\t", 1)
        except ValueError as exc:
            raise StoreError("App install target index inventory is malformed") from exc
        if not path or len(path) > MAX_GIT_INDEX_PATH_BYTES:
            raise StoreError("App install target index path exceeds its bound")
        paths.add(path)
        if len(paths) > MAX_GIT_INDEX_ENTRIES:
            raise StoreError("App install target index entry count exceeds its bound")
    for value in new_paths:
        path = value.encode("utf-8")
        if not path or len(path) > MAX_GIT_INDEX_PATH_BYTES or path in paths:
            raise StoreError("App install target index path is invalid or already present")
        paths.add(path)
        if len(paths) > MAX_GIT_INDEX_ENTRIES:
            raise StoreError("App install target index entry count exceeds its bound")

    oid_bytes = 20 if object_format == "sha1" else 32
    entries_bytes = 0
    prefixes = set()
    for path in paths:
        # The extra two bytes cover the extended flags present in index v3.
        unaligned = 40 + oid_bytes + 2 + 2 + len(path) + 1
        entries_bytes += (unaligned + 7) & ~7
        for index, byte in enumerate(path):
            if byte == ord("/"):
                prefixes.add(path[:index])
    tree_extension_bytes = sum(len(prefix) + 1 + 8 + oid_bytes for prefix in prefixes)
    extension_slack = existing_index_bytes + tree_extension_bytes + len(paths) * 64 + 4096
    bound = 12 + oid_bytes + entries_bytes + extension_slack
    if bound > MAX_GIT_INDEX_BYTES:
        raise StoreError("App install derived Git index bound exceeds its supported limit")
    return bound


def _source_tree(source_root, app_id, source_commit, budget, *, allow_enabled=False, contract=None,
                 enforce_serving_bounds=False):
    if not _APP_ID.fullmatch(app_id) or not _SHA.fullmatch(source_commit):
        raise StoreError("App install source identity is invalid")
    root = Path(source_root).resolve(strict=True)
    top = Path(_git_text(root, "rev-parse", "--show-toplevel", budget=budget)).resolve(strict=True)
    if root != top:
        raise StoreError("App install source must be a Git worktree root")
    head = _git_text(root, "rev-parse", "--verify", "HEAD^{commit}", budget=budget)
    if head != source_commit:
        raise StoreError("Reviewed App source commit does not match its checkout")
    status = _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all", budget=budget)
    if status:
        raise StoreError("Reviewed App source checkout is not clean")
    object_format = _git_text(root, "rev-parse", "--show-object-format=storage", budget=budget)
    if object_format not in ("sha1", "sha256"):
        raise StoreError("Reviewed App source object format is unsupported")
    app_tree_path = f"apps/{app_id}"
    listing = _git(root, "ls-tree", "-r", "-z", "--full-tree", source_commit, "--", app_tree_path, budget=budget)
    entries = {}
    portable_paths = set()
    file_paths = set()
    directory_paths = set()
    total = 0
    for row in listing.split(b"\0"):
        if not row:
            continue
        try:
            metadata, raw_name = row.split(b"\t", 1)
            mode, kind, object_id = metadata.split(b" ", 2)
            name = raw_name.decode("utf-8")
            relative = name[len(app_tree_path) + 1 :] if name.startswith(app_tree_path + "/") else ""
        except (ValueError, UnicodeDecodeError) as exc:
            raise StoreError("Reviewed App source tree is malformed") from exc
        parts = Path(relative).parts
        if (
            not relative
            or len(raw_name) > MAX_APP_PATH_BYTES
            or Path(relative).is_absolute()
            or any(part in ("", ".", "..") or part.startswith(".") or part == "_internal" for part in parts)
            or "\\" in relative
            or "\x00" in relative
            or any(unicodedata.normalize("NFC", part) != part or part.endswith((".", " ")) for part in parts)
            or mode not in (b"100644", b"100755")
            or kind != b"blob"
            or len(object_id) != (40 if object_format == "sha1" else 64)
            or not re.fullmatch(rb"[a-f0-9]+", object_id)
            or relative in entries
        ):
            raise StoreError("Reviewed App source contains an unsupported path or file type")
        if enforce_serving_bounds:
            if len(parts) > MAX_APP_DEPTH:
                raise StoreError("Reviewed App source exceeds its serving depth bound")
            for depth in range(1, len(parts)):
                directory_paths.add("/".join(parts[:depth]))
            if len(entries) + 1 + len(directory_paths) > MAX_APP_FILES:
                raise StoreError("Reviewed App source exceeds its serving entry bound")
        folded = relative.casefold()
        if folded in portable_paths:
            raise StoreError("Reviewed App source has case-folding path collisions")
        portable_paths.add(folded)
        file_paths.add(relative)
        entries[relative] = {"objectId": object_id.decode("ascii"), "executable": mode == b"100755"}
        if len(entries) > MAX_APP_FILES:
            raise StoreError("Reviewed App source exceeds its file bound")
    if "app.json" not in entries:
        raise StoreError("Reviewed App source has no app.json")
    folded_files = {path.casefold() for path in file_paths}
    for file_path in file_paths:
        parent = Path(file_path).parent
        while str(parent) != ".":
            if str(parent).casefold() in folded_files:
                raise StoreError("Reviewed App source file path collides with a parent file")
            parent = parent.parent
    source_dir = root / app_tree_path
    if not source_dir.is_dir() or source_dir.is_symlink():
        raise StoreError("Reviewed App source directory is unavailable")
    data = {}
    for relative, row in sorted(entries.items()):
        raw = _read_committed_file(
            source_dir, relative, row["objectId"], object_format, row["executable"], remaining=MAX_APP_BYTES - total
        )
        total += len(raw)
        data[relative] = raw
    _require_clean_source(root, source_commit, budget)
    digest = _bundle_digest(data, entries)
    try:
        manifest = json.loads(data["app.json"])
    except (ValueError, UnicodeDecodeError) as exc:
        raise StoreError("Reviewed App manifest is malformed") from exc
    enabled = manifest.get("enabled", True) if isinstance(manifest, dict) else None
    if (
        not isinstance(manifest, dict)
        or manifest.get("id") != app_id
        or manifest.get("slug") != app_id
        or not isinstance(manifest.get("grant"), dict)
        or enabled not in (True, False)
        or (enabled is False and (
            manifest["grant"].get("read") != [] or manifest["grant"].get("owned") not in ([], {})
        ))
        or (enabled is True and not allow_enabled)
    ):
        raise StoreError("Reviewed App bundle is not an allowed committed draft or reviewed bundle")
    try:
        check_app(
            source_dir,
            contract if enabled else None,
            datetime.now(timezone.utc).isoformat(),
            allow_draft=True,
            verified_files=data,
        )
    except ValueError as exc:
        raise StoreError("Reviewed App bundle fails the installed host contract") from exc
    return {
        "root": root,
        "sourceCommit": source_commit,
        "objectFormat": object_format,
        "files": data,
        "entries": entries,
        "bundleBytes": total,
        "bundleSha256": digest,
        "manifest": manifest,
    }


def _paths_overlap(left, right):
    return left == right or left in right.parents or right in left.parents


def _private_destination_parent(path):
    path = Path(path)
    if not path.is_absolute() or path.name in ("", ".", ".."):
        raise StoreError("App staging destination must be an absolute new directory")
    parent = path.parent
    if parent.resolve(strict=True) != parent:
        raise StoreError("App staging parent must be canonical")
    descriptor = _open_directory_chain(parent)
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o777 != 0o700
        or info.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_IWGRP | stat.S_IWOTH)
    ):
        os.close(descriptor)
        raise StoreError("App staging parent must be a private operator-owned directory")
    return path, descriptor, _directory_identity(info)


def _create_private_bundle_root(parent_fd, parent_identity, root_name):
    root_fd = apps_fd = None
    try:
        parent_before = os.fstat(parent_fd)
        if _directory_identity(parent_before) != parent_identity:
            raise StoreError("App staging parent changed before output creation")
        os.mkdir(root_name, mode=0o700, dir_fd=parent_fd)
        root_fd = os.open(root_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        os.fchmod(root_fd, 0o700)
        root_info = os.fstat(root_fd)
        root_named = os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            (root_info.st_dev, root_info.st_ino) != (root_named.st_dev, root_named.st_ino)
            or root_info.st_uid != os.geteuid()
            or root_info.st_mode & 0o777 != 0o700
            or not stat.S_ISDIR(root_info.st_mode)
        ):
            raise StoreError("New App staging root could not be pinned privately")
        os.mkdir("apps", mode=0o700, dir_fd=root_fd)
        apps_fd = os.open("apps", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        os.fchmod(apps_fd, 0o700)
        apps_info = os.fstat(apps_fd)
        apps_named = os.stat("apps", dir_fd=root_fd, follow_symlinks=False)
        if (
            (apps_info.st_dev, apps_info.st_ino) != (apps_named.st_dev, apps_named.st_ino)
            or apps_info.st_uid != os.geteuid()
            or apps_info.st_mode & 0o777 != 0o700
            or not stat.S_ISDIR(apps_info.st_mode)
        ):
            raise StoreError("New App staging directory could not be pinned privately")
        os.fsync(apps_fd)
        os.fsync(root_fd)
        os.fsync(parent_fd)
        return root_fd, apps_fd, _directory_identity(root_info), _directory_identity(apps_info)
    except BaseException as exc:
        if apps_fd is not None:
            os.close(apps_fd)
        if root_fd is not None:
            os.close(root_fd)
        if isinstance(exc, OSError):
            raise StoreError("App staging root creation failed or is uncertain") from exc
        raise


def stage_committed_app_bundle(source_root, destination_root, published_root, app_id, source_commit,
                               expected_bundle_sha256, *, contract=None):
    """Copy one exact committed bundle into a new, private, unserved bundle root.

    The caller must select a destination root that is not mounted or configured
    by a serving host. This helper writes no grants, publication registry,
    enrollment, or activation state. The destination is outside the current
    aggregate storage-admission ledger; only the per-bundle limits below apply.
    """
    if not isinstance(expected_bundle_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}\Z", expected_bundle_sha256):
        raise StoreError("Reviewed App bundle digest is invalid")
    source_path = Path(source_root)
    if not source_path.is_absolute() or source_path.is_symlink() or source_path.resolve(strict=True) != source_path:
        raise StoreError("Reviewed App source root must be a canonical Git worktree")
    published_path = Path(published_root)
    if not published_path.is_absolute() or published_path.is_symlink() or published_path.resolve(strict=True) != published_path:
        raise StoreError("Published root must be a canonical existing directory")
    published_fd = _open_directory_chain(published_path)
    try:
        published_info = os.fstat(published_fd)
        if not stat.S_ISDIR(published_info.st_mode):
            raise StoreError("Published root is unavailable")
    finally:
        os.close(published_fd)

    output_path, parent_fd, parent_identity = _private_destination_parent(destination_root)
    source = None
    root_fd = apps_fd = stage_fd = app_fd = None
    try:
        if _paths_overlap(output_path, source_path) or _paths_overlap(output_path, published_path):
            raise StoreError("App staging output must be separate from source and published roots")
        budget = InventoryBudget(deadline_seconds=MAX_OPERATION_SECONDS)
        source = _source_tree(
            source_path, app_id, source_commit, budget,
            allow_enabled=True, contract=contract, enforce_serving_bounds=True,
        )
        if source["bundleSha256"] != expected_bundle_sha256:
            raise StoreError("Reviewed App bundle digest changed before staging")
        root_name = output_path.name
        root_fd, apps_fd, root_identity, apps_identity = _create_private_bundle_root(
            parent_fd, parent_identity, root_name
        )
        stage_name = ".brain-app-stage-" + secrets.token_hex(16)
        stage_fd, app_fd, stage_identity, app_identity = _install_files(
            apps_fd, stage_name, app_id, source["files"], source["entries"]
        )
        _publish_stage(apps_fd, stage_fd, app_fd, stage_name, app_id, stage_identity, app_identity)
        root_named = os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)
        apps_named = os.stat("apps", dir_fd=root_fd, follow_symlinks=False)
        if (
            _directory_identity(os.fstat(parent_fd)) != parent_identity
            or (root_named.st_dev, root_named.st_ino) != (root_identity[0], root_identity[1])
            or _directory_identity(os.fstat(root_fd)) != root_identity
            or (apps_named.st_dev, apps_named.st_ino) != (apps_identity[0], apps_identity[1])
            or _directory_identity(os.fstat(apps_fd)) != apps_identity
        ):
            raise StoreError("App staging destination changed after publication")
        from brain_apps import snapshot_bundle

        verified_files, verified_entries = snapshot_bundle(
            output_path,
            app_id,
            expected_root_identity=_identity(os.fstat(root_fd))[:5],
            expected_apps_identity=_identity(os.fstat(apps_fd))[:5],
        )
        normalized_entries = {path: {"executable": row["executable"]} for path, row in source["entries"].items()}
        if (
            verified_files != source["files"]
            or verified_entries != normalized_entries
            or _bundle_digest(verified_files, source["entries"]) != expected_bundle_sha256
        ):
            raise StoreError("App staging output differs from the reviewed source bundle")
        root_named = os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)
        apps_named = os.stat("apps", dir_fd=root_fd, follow_symlinks=False)
        if (
            (root_named.st_dev, root_named.st_ino) != root_identity[:2]
            or _directory_identity(os.fstat(root_fd)) != root_identity
            or (apps_named.st_dev, apps_named.st_ino) != apps_identity[:2]
            or _directory_identity(os.fstat(apps_fd)) != apps_identity
        ):
            raise StoreError("App staging destination changed during final verification")
        manifest = check_app(
            output_path / "apps" / app_id,
            contract,
            datetime.now(timezone.utc).isoformat(),
            allow_draft=True,
            verified_files=verified_files,
        )
        enabled = manifest.get("enabled", True)
        return {
            "format": "brain-app-private-staging-receipt/v1",
            "appId": app_id,
            "sourceRevision": source_commit,
            "bundleSha256": expected_bundle_sha256,
            "bundleBytes": source["bundleBytes"],
            "bundleFiles": len(source["files"]),
            "destinationRoot": str(output_path),
            "state": "prepared-unpublished-bundle" if enabled else "prepared-disabled-draft",
            "sourceManifestEnabled": bool(enabled),
            "grantsWritten": False,
            "registryWritten": False,
            "activation": False,
            "aggregateAdmissionCovered": False,
        }
    except OSError as exc:
        raise StoreError("App staging failed or publication state is uncertain") from exc
    finally:
        for descriptor in (app_fd, stage_fd, apps_fd, root_fd, parent_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _read_committed_file(root, relative, expected_oid, object_format, executable, *, remaining):
    parts = Path(relative).parts
    if not parts or type(remaining) is not int or remaining < 0:
        raise StoreError("Reviewed App source exceeds its byte bound")
    current = _open_directory_chain(root)
    try:
        for component in parts[:-1]:
            named = os.stat(component, dir_fd=current, follow_symlinks=False)
            if (
                not stat.S_ISDIR(named.st_mode)
                or named.st_uid != os.geteuid()
                or named.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
            ):
                raise StoreError("Reviewed App source path is unsafe")
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            try:
                opened = os.fstat(child)
                current_named = os.stat(component, dir_fd=current, follow_symlinks=False)
                if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino) or (
                    current_named.st_dev,
                    current_named.st_ino,
                ) != (opened.st_dev, opened.st_ino):
                    raise StoreError("Reviewed App source directory changed while opening")
            except BaseException:
                os.close(child)
                raise
            os.close(current)
            current = child
        name = parts[-1]
        before = os.stat(name, dir_fd=current, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
            or bool(before.st_mode & 0o111) != executable
            or before.st_size > remaining
        ):
            raise StoreError("Reviewed App source file is unsafe or exceeds its byte bound")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)
        try:
            opened = os.fstat(fd)
            if _identity(opened) != _identity(before):
                raise StoreError("Reviewed App source changed while opening")
            chunks = []
            left = min(remaining, before.st_size) + 1
            while left:
                chunk = os.read(fd, min(64 * 1024, left))
                if not chunk:
                    break
                chunks.append(chunk)
                left -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(fd)
            named_after = os.stat(name, dir_fd=current, follow_symlinks=False)
            if (
                len(raw) != before.st_size
                or _identity(opened) != _identity(after)
                or _identity(after) != _identity(named_after)
            ):
                raise StoreError("Reviewed App source changed while reading")
        finally:
            os.close(fd)
        header = b"blob " + str(len(raw)).encode("ascii") + b"\0"
        hasher = hashlib.sha1() if object_format == "sha1" else hashlib.sha256()
        hasher.update(header)
        hasher.update(raw)
        if hasher.hexdigest() != expected_oid:
            raise StoreError("Reviewed App source differs from its committed object")
        return raw
    except OSError as exc:
        raise StoreError("Reviewed App source is unavailable or unsafe") from exc
    finally:
        os.close(current)


def _require_clean_source(root, source_commit, budget):
    if _git_text(root, "rev-parse", "--verify", "HEAD^{commit}", budget=budget) != source_commit or _git(
        root, "status", "--porcelain=v1", "-z", "--untracked-files=all", budget=budget
    ):
        raise StoreError("Reviewed App source changed during installation")


def _bundle_digest(files, entries):
    return bundle_digest(files, entries)


def _git_blob_oid(raw, object_format):
    digest = hashlib.sha1() if object_format == "sha1" else hashlib.sha256()
    digest.update(b"blob " + str(len(raw)).encode("ascii") + b"\0")
    digest.update(raw)
    return digest.hexdigest()


def _protection_context(provider, *, root, alias, actor, store, registration):
    """Resolve real current host policy; a missing provider never means plaintext."""
    if not callable(provider):
        raise StoreError("App install requires the trusted host protection provider")
    try:
        supplied = provider(root=root, alias=alias, actor=actor, store=store, registration=registration)
        from brain_protection import ProtectionHost, assess, profile, requirements
        from knowledge_policy import fingerprint as policy_fingerprint

        if not isinstance(supplied, tuple) or len(supplied) != 4:
            raise StoreError("App install protection context is unavailable")
        host, raw_required, raw_selected, native_scope = supplied
        required = requirements(raw_required)
        selected = profile(raw_selected)
        expected_scope = {
            "format": "studio-app-protection-scope/v1",
            "nativeRecordBodies": False,
            "nativeHistory": False,
            "nativeMetadata": False,
        }
        if (
            not isinstance(host, ProtectionHost)
            or not isinstance(native_scope, dict)
            or native_scope != expected_scope
            or selected["mode"] != registration["protection"]["profile"]
            or policy_fingerprint(required) != registration["protection"]["requirementsSha256"]
            or required["opaqueMetadata"]
            or not required["plaintextCopies"]
            or not assess(required, selected, offline=True, operation="retain")["supported"]
        ):
            raise StoreError("App install protection context differs from the adopted policy")
        actor_identity = host.actor
        if not isinstance(actor_identity, str) or not actor_identity:
            raise StoreError("App install protection identity is unavailable")
        host.available(selected)
        if host.actor != actor_identity:
            raise StoreError("App install protection identity changed during review")
        return {
            "host": host,
            "required": required,
            "selected": selected,
            "nativeScope": dict(native_scope),
            "sha256": fingerprint(
                {
                    "providerActor": actor_identity,
                    "required": required,
                    "selected": selected,
                    "nativeScope": native_scope,
                }
            ),
        }
    except StoreError:
        raise
    except Exception as exc:
        # Provider exceptions and key failures can contain host-private details.
        raise StoreError("App install protection context is unavailable") from exc


def _target_context(root, store, *, budget, protection_provider, alias, actor):
    registration = load_registration(root, required=True)
    ledger = AdmissionLedger(root, registration)
    with ledger.readonly_snapshot(registration_sha256=fingerprint(registration), budget=budget):
        pass
    authority_path, config = _selected_authority_path(root, store, registration)
    authority = config.get("brain", {}).get("authority", {}) if isinstance(config.get("brain"), dict) else {}
    uid = str(os.geteuid())
    principals = authority.get("principalsByUid") if isinstance(authority, dict) else None
    operators = authority.get("operatorUids") if isinstance(authority, dict) else None
    if (
        not isinstance(principals, dict)
        or not isinstance(principals.get(uid), str)
        or not principals[uid]
        or principals[uid] != actor
        or not isinstance(operators, list)
        or uid not in operators
    ):
        raise StoreError("Current OS identity is not an owner operator for this brain")
    selected = adopted_authority(config)
    if (
        not isinstance(selected, dict)
        or selected.get("binding") != store.contract.binding
        or selected.get("store") != store.contract.authority
    ):
        raise StoreError("App install authority selection changed")
    protection = _protection_context(
        protection_provider, root=root, alias=alias, actor=actor, store=store, registration=registration
    )
    blob = blob_store_for(root, config, store.contract)
    if registration["blob"]["driver"] == "fs":
        if blob is None or not hasattr(blob, "root"):
            raise StoreError("App install blob route is unavailable")
        blob_root = Path(blob.root).absolute()
        blob_location = None
    else:
        blob_root = None
        blob_location = store.path
    current = _selected_authority_path(root, store, registration)
    if current[0] != authority_path or fingerprint(current[1]) != fingerprint(config):
        raise StoreError("App install selected authority changed")
    route = {
        "hostAlias": alias,
        "hostActorSha256": hashlib.sha256(actor.encode("utf-8")).hexdigest(),
        "configSha256": fingerprint(config),
        "registrationSha256": fingerprint(registration),
        "authorityPathSha256": hashlib.sha256(os.fsencode(authority_path)).hexdigest(),
        "authorityDevice": store.authority_file_identity[0],
        "authorityInode": store.authority_file_identity[1],
        "blobStore": registration["blob"]["store"],
        "blobDriver": registration["blob"]["driver"],
        "blobLocationSha256": registration["blob"]["locationSha256"],
        "protectionSha256": protection["sha256"],
        "blobPathSha256": None,
        "blobDevice": None,
        "blobInode": None,
    }
    if blob_root is not None:
        blob_fd = _open_directory_chain(blob_root)
        try:
            opened_blob = os.fstat(blob_fd)
            named_blob = blob_root.lstat()
            if (
                (opened_blob.st_dev, opened_blob.st_ino) != (named_blob.st_dev, named_blob.st_ino)
                or not stat.S_ISDIR(opened_blob.st_mode)
                or opened_blob.st_uid != os.geteuid()
                or opened_blob.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
            ):
                raise StoreError("App install blob route is unsafe")
            route["blobDevice"], route["blobInode"] = opened_blob.st_dev, opened_blob.st_ino
            route["blobPathSha256"] = hashlib.sha256(os.fsencode(blob_root.resolve(strict=True))).hexdigest()
        finally:
            os.close(blob_fd)
    else:
        route["blobPathSha256"] = hashlib.sha256(os.fsencode(str(Path(store.path).resolve(strict=True)))).hexdigest()

    def inventory_now():
        budget_now = InventoryBudget(deadline_seconds=20.0)
        before_path, before_config = _selected_authority_path(root, store, registration)
        if before_path != authority_path or fingerprint(before_config) != fingerprint(config):
            raise StoreError("App install authority route changed")
        measured = inventory(
            root, store, registration, blob_root=blob_root, blob_location=blob_location, budget=budget_now
        )
        after_path, after_config = _selected_authority_path(root, store, registration)
        if after_path != authority_path or fingerprint(after_config) != fingerprint(config):
            raise StoreError("App install authority route changed")
        return measured

    return registration, ledger, route, inventory_now


def _public_context(root, source, app_id, store, *, budget, protection_provider, alias, actor):
    state = _repo_state(root, budget)
    if Path(source["root"]).resolve(strict=True) == root:
        raise StoreError("App source and target brain must be separate worktrees")
    common_target = _git_text(root, "rev-parse", "--path-format=absolute", "--git-common-dir", budget=budget)
    common_source = _git_text(source["root"], "rev-parse", "--path-format=absolute", "--git-common-dir", budget=budget)
    if Path(common_target).resolve(strict=True) == Path(common_source).resolve(strict=True):
        raise StoreError("App source and target must use separate Git object stores")
    target = root / "apps" / app_id
    apps = root / "apps"
    try:
        apps_info = apps.lstat()
        target_info = target.lstat()
    except FileNotFoundError:
        target_info = None
        apps_info = apps.lstat()
    if (
        not stat.S_ISDIR(apps_info.st_mode)
        or stat.S_ISLNK(apps_info.st_mode)
        or apps_info.st_uid != os.geteuid()
        or apps_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
        or target_info is not None
    ):
        raise StoreError("App install target already exists or is unsafe")
    if _git(root, "rev-list", "--all", "--", f"apps/{app_id}", budget=budget):
        raise StoreError("App install refuses to replace a previously installed app id")
    registration, ledger, route, inventory_now = _target_context(
        root, store, budget=budget, protection_provider=protection_provider, alias=alias, actor=actor
    )
    inventory_value = inventory_now()
    index_bound = _git_index_upper_bound(
        root,
        (f"apps/{app_id}/{name}" for name in source["files"]),
        state["objectFormat"],
        state["indexBytes"],
        budget,
    )
    root_info = root.stat()
    apps_info = apps.lstat()
    index_lock_marker_bytes = len(b"brain-app-install/v1 ") + 64 + 1
    # During update-index, the old real index, its held lock sentinel, the
    # private current index and Git's private-index lock can coexist.
    index_peak = state["indexBytes"] + (2 * index_bound) + index_lock_marker_bytes
    return {
        "format": "brain-app-install-preview/v1",
        "brainId": registration["brainId"],
        "ownerUid": os.geteuid(),
        "appId": app_id,
        "sourceCommit": source["sourceCommit"],
        "sourceRoot": str(source["root"]),
        "targetRoot": str(root),
        "sourceObjectFormat": source["objectFormat"],
        "sourceRootSha256": hashlib.sha256(os.fsencode(source["root"])).hexdigest(),
        "bundleSha256": source["bundleSha256"],
        "bundleBytes": source["bundleBytes"],
        "bundleFiles": len(source["files"]),
        "targetRootSha256": hashlib.sha256(os.fsencode(root)).hexdigest(),
        "targetRootDevice": root_info.st_dev,
        "targetRootInode": root_info.st_ino,
        "appsDevice": apps_info.st_dev,
        "appsInode": apps_info.st_ino,
        "targetHead": state["head"],
        "targetBranch": state["branch"],
        "targetObjectFormat": state["objectFormat"],
        "targetIndexIdentitySha256": hashlib.sha256(repr(state["indexIdentity"]).encode()).hexdigest(),
        "targetIndexParentIdentitySha256": hashlib.sha256(repr(state["indexParentIdentity"]).encode()).hexdigest(),
        "targetIndexPathSha256": hashlib.sha256(os.fsencode(state["indexPath"])).hexdigest(),
        "targetIndexBytes": state["indexBytes"],
        "targetIndexSha256": state["indexSha256"],
        "targetIndexEntriesSha256": state["indexEntriesSha256"],
        "commitIdentitySha256": state["commitIdentitySha256"],
        "targetIndexBoundBytes": index_bound,
        "targetIndexPeakBytes": index_peak,
        "route": route,
        "inventoryBasisSha256": inventory_value["basisSha256"],
        "usedBytes": inventory_value["usedBytes"],
        "limitBytes": inventory_value["limitBytes"],
        "requiredPeakBytes": 2 * source["bundleBytes"] + index_peak,
        "installState": "disabled-draft",
        "grantsWritten": False,
        "activation": False,
        "ownership": "local-os-owner-confirmation",
    }


def preview_app_install(root, source_root, app_id, source_commit, store, *, protection_provider, alias, actor):
    root = Path(root).resolve(strict=True)
    budget = InventoryBudget(deadline_seconds=MAX_OPERATION_SECONDS)
    source = _source_tree(source_root, app_id, source_commit, budget)
    context = _public_context(
        root, source, app_id, store, budget=budget, protection_provider=protection_provider, alias=alias, actor=actor
    )
    context["previewSha256"] = fingerprint(context)
    return context


def _read_installed_digest(root, app_id, expected_files, expected_entries):
    return _read_committed_files(root / "apps" / app_id, expected_files, expected_entries)


def _open_pinned_apps(root, preview):
    apps = root / "apps"
    try:
        fd = _open_directory_chain(apps)
        opened = os.fstat(fd)
        named = apps.lstat()
        root_info = root.stat()
        if (
            (opened.st_dev, opened.st_ino) != (preview["appsDevice"], preview["appsInode"])
            or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
            or (root_info.st_dev, root_info.st_ino) != (preview["targetRootDevice"], preview["targetRootInode"])
            or not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
        ):
            os.close(fd)
            raise StoreError("App install repository route changed after review")
        return fd
    except OSError as exc:
        raise StoreError("App install repository route is unavailable") from exc


def _rename_noreplace(source_fd, source_name, target_fd, target_name):
    if any(
        not isinstance(value, str) or not value or "/" in value or "\0" in value for value in (source_name, target_name)
    ):
        raise StoreError("App install exclusive publication name is invalid")
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        function = getattr(libc, "renameatx_np", None)
        flag = 0x00000004  # RENAME_EXCL from the macOS SDK.
    elif sys.platform.startswith("linux"):
        function = getattr(libc, "renameat2", None)
        flag = 0x00000001  # RENAME_NOREPLACE from Linux UAPI headers.
    else:
        raise StoreError("Atomic no-replace App publication is unavailable on this platform")
    if function is None:
        raise StoreError("Atomic no-replace App publication is unavailable on this platform")
    function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    function.restype = ctypes.c_int
    result = function(source_fd, os.fsencode(source_name), target_fd, os.fsencode(target_name), flag)
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise StoreError("App install target appeared before exclusive publication")
    # ENOSYS/EINVAL/EOPNOTSUPP/ENOTSUP all refuse; there is no ordinary rename fallback.
    raise StoreError("Atomic no-replace App publication is unsupported or failed") from OSError(
        error, os.strerror(error)
    )


def _read_committed_files(
    directory, expected_files, expected_entries, *, parent_fd=None, directory_name=None, expected_identity=None
):
    actual = {}
    if parent_fd is None:
        root_fd = _open_directory_chain(directory)
        close_root = True
    else:
        if not isinstance(directory_name, str) or not directory_name or "/" in directory_name or "\0" in directory_name:
            raise StoreError("Installed App descriptor-relative directory name is invalid")
        try:
            before_root = os.stat(directory_name, dir_fd=parent_fd, follow_symlinks=False)
            root_fd = os.open(directory_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        except OSError as exc:
            raise StoreError("Installed App stage changed") from exc
        close_root = True
    try:
        root_info = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != os.geteuid()
            or root_info.st_mode & 0o777 != 0o755
            or (expected_identity is not None and (root_info.st_dev, root_info.st_ino) != expected_identity)
            or (
                parent_fd is not None
                and (root_info.st_dev, root_info.st_ino) != (before_root.st_dev, before_root.st_ino)
            )
        ):
            raise StoreError("Installed App stage changed")
        if parent_fd is not None:
            named_root = os.stat(directory_name, dir_fd=parent_fd, follow_symlinks=False)
            if (named_root.st_dev, named_root.st_ino) != (root_info.st_dev, root_info.st_ino):
                raise StoreError("Installed App stage changed")
        for relative, expected in sorted(expected_files.items()):
            parts = Path(relative).parts
            current = os.dup(root_fd)
            try:
                for component in parts[:-1]:
                    before_dir = os.stat(component, dir_fd=current, follow_symlinks=False)
                    if (
                        not stat.S_ISDIR(before_dir.st_mode)
                        or before_dir.st_uid != os.geteuid()
                        or before_dir.st_mode & 0o777 != 0o755
                        or before_dir.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
                    ):
                        raise StoreError("Installed App stage changed")
                    child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                    try:
                        opened_dir = os.fstat(child)
                        named_dir = os.stat(component, dir_fd=current, follow_symlinks=False)
                        if (opened_dir.st_dev, opened_dir.st_ino) != (before_dir.st_dev, before_dir.st_ino) or (
                            named_dir.st_dev,
                            named_dir.st_ino,
                        ) != (opened_dir.st_dev, opened_dir.st_ino):
                            raise StoreError("Installed App stage changed")
                    except BaseException:
                        os.close(child)
                        raise
                    os.close(current)
                    current = child
                name = parts[-1]
                before = os.stat(name, dir_fd=current, follow_symlinks=False)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_uid != os.geteuid()
                    or before.st_nlink != 1
                    or before.st_mode & 0o777 != (0o755 if expected_entries[relative]["executable"] else 0o644)
                    or before.st_size != len(expected)
                    or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
                ):
                    raise StoreError("Installed App stage changed")
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)
                try:
                    opened = os.fstat(fd)
                    if _identity(opened) != _identity(before):
                        raise StoreError("Installed App stage changed")
                    chunks = []
                    remaining = len(expected) + 1
                    while remaining:
                        chunk = os.read(fd, min(64 * 1024, remaining))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        remaining -= len(chunk)
                    raw = b"".join(chunks)
                    after = os.fstat(fd)
                    named = os.stat(name, dir_fd=current, follow_symlinks=False)
                    if (
                        len(raw) != len(expected)
                        or _identity(opened) != _identity(after)
                        or _identity(after) != _identity(named)
                        or raw != expected
                    ):
                        raise StoreError("Installed App stage changed")
                    actual[relative] = raw
                finally:
                    os.close(fd)
            finally:
                os.close(current)
    finally:
        if close_root:
            os.close(root_fd)
    if parent_fd is not None:
        named_root = os.stat(directory_name, dir_fd=parent_fd, follow_symlinks=False)
        if (named_root.st_dev, named_root.st_ino) != (root_info.st_dev, root_info.st_ino):
            raise StoreError("Installed App stage changed")
    if set(actual) != set(expected_entries):
        raise StoreError("Installed App file inventory changed")
    return actual


def apply_app_install(
    root, source_root, app_id, source_commit, store, *, expected_preview_sha256, protection_provider, alias, actor
):
    if not isinstance(expected_preview_sha256, str) or not _SHA.fullmatch(expected_preview_sha256):
        raise StoreError("App install preview confirmation is invalid")
    root = Path(root).resolve(strict=True)
    budget = InventoryBudget(deadline_seconds=MAX_OPERATION_SECONDS)
    source = _source_tree(source_root, app_id, source_commit, budget)
    preview = _public_context(
        root, source, app_id, store, budget=budget, protection_provider=protection_provider, alias=alias, actor=actor
    )
    preview["previewSha256"] = fingerprint(preview)
    if preview["previewSha256"] != expected_preview_sha256:
        raise StoreError("App install preview changed; review the current bundle and target again")
    registration, ledger, route, inventory_now = _target_context(
        root, store, budget=budget, protection_provider=protection_provider, alias=alias, actor=actor
    )
    if fingerprint(route) != fingerprint(preview["route"]):
        raise StoreError("App install route changed after review")
    index_name = _git_text(root, "rev-parse", "--path-format=absolute", "--git-path", "index", budget=budget)
    index_path = Path(index_name)
    commit_identity = _git_commit_identity(root, budget)
    if fingerprint(commit_identity) != preview["commitIdentitySha256"]:
        raise StoreError("App install repository-local Git identity changed after review")
    operation = secrets.token_hex(32)
    operation_key = f"brain-app-install:{operation}"
    index_lock_name = index_path.name + ".lock"
    private_index_name = f".brain-app-install-index-{operation}"
    details = {
        "operation": "brain-app.install",
        "operationId": operation,
        "appId": app_id,
        "sourceCommit": source_commit,
        "bundleSha256": source["bundleSha256"],
        "previewSha256": preview["previewSha256"],
        "targetHead": preview["targetHead"],
        "authorityBinding": store.contract.binding,
        "routeSha256": fingerprint(route),
        "requiredPeakBytes": preview["requiredPeakBytes"],
        "indexPathSha256": preview["targetIndexPathSha256"],
        "indexLockName": index_lock_name,
        "privateIndexName": private_index_name,
    }
    wrote = False
    index_state = None
    apps_fd = stage_fd = app_fd = None
    with ledger.effect(operation_key=operation_key, details=details, inventory_now=inventory_now) as reservation:
        try:
            if reservation.get("basisSha256") != preview["inventoryBasisSha256"] or preview[
                "requiredPeakBytes"
            ] > reservation.get("reservedBytes", -1):
                raise StoreError("App install reservation does not cover the reviewed bundle peak")
            wrote = True
            index_state = _acquire_index_lock(index_path, preview, operation)
            _revalidate(
                root,
                source,
                app_id,
                store,
                preview,
                route,
                budget,
                protection_provider=protection_provider,
                alias=alias,
                actor=actor,
                index_state=index_state,
                git_index_file=index_state["privatePath"],
            )
            stage_name = f".brain-app-install-{operation}"
            apps_fd = _open_pinned_apps(root, preview)
            stage_fd, app_fd, stage_identity, app_identity = _install_files(
                apps_fd, stage_name, app_id, source["files"], source["entries"]
            )
            # Static checks run only after the bounded, no-follow stage exists.
            staged_dir = Path(app_id)
            check_app(
                staged_dir,
                None,
                datetime.now(timezone.utc).isoformat(),
                allow_draft=True,
                verified_files=source["files"],
            )
            staged = _read_committed_files(
                staged_dir,
                source["files"],
                source["entries"],
                parent_fd=stage_fd,
                directory_name=app_id,
                expected_identity=app_identity,
            )
            if _bundle_digest(staged, source["entries"]) != source["bundleSha256"]:
                raise StoreError("Installed App bundle differs from the reviewed source")
            _revalidate(
                root,
                source,
                app_id,
                store,
                preview,
                route,
                budget,
                protection_provider=protection_provider,
                alias=alias,
                actor=actor,
                stage_name=stage_name,
                staged_state="source-stage",
                apps_fd=apps_fd,
                stage_fd=stage_fd,
                app_fd=app_fd,
                stage_identity=stage_identity,
                app_identity=app_identity,
                index_state=index_state,
                git_index_file=index_state["privatePath"],
            )
            _publish_stage(apps_fd, stage_fd, app_fd, stage_name, app_id, stage_identity, app_identity)
            _revalidate(
                root,
                source,
                app_id,
                store,
                preview,
                route,
                budget,
                protection_provider=protection_provider,
                alias=alias,
                actor=actor,
                stage_name=stage_name,
                staged_state="target-worktree",
                apps_fd=apps_fd,
                stage_fd=stage_fd,
                app_fd=app_fd,
                stage_identity=stage_identity,
                app_identity=app_identity,
                index_state=index_state,
                git_index_file=index_state["privatePath"],
            )
            for relative, entry in sorted(source["entries"].items()):
                object_id = (
                    _git_input(
                        root,
                        source["files"][relative],
                        "hash-object",
                        "-w",
                        "--no-filters",
                        "--stdin",
                        budget=budget,
                        index_file=index_state["privatePath"],
                    )
                    .decode("ascii")
                    .strip()
                )
                if len(object_id) != (40 if preview.get("targetObjectFormat") == "sha1" else 64) or not re.fullmatch(
                    r"[a-f0-9]+", object_id
                ):
                    raise StoreError("App install target object id is malformed")
                # Source and target repositories may use different hash formats;
                # the source object id is not a target object id.
                if object_id != _git_blob_oid(source["files"][relative], preview["targetObjectFormat"]):
                    raise StoreError("App install target object differs from the reviewed source bytes")
                mode = "100755" if entry["executable"] else "100644"
                _git(
                    root,
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    f"{mode},{object_id},apps/{app_id}/{relative}",
                    budget=budget,
                    index_file=index_state["privatePath"],
                )
            expected_names = {f"apps/{app_id}/{name}" for name in source["files"]}
            staged_names = {
                value.decode("utf-8")
                for value in _git(
                    root,
                    "diff",
                    "--cached",
                    "--name-only",
                    "-z",
                    preview["targetHead"],
                    budget=budget,
                    index_file=index_state["privatePath"],
                ).split(b"\0")
                if value
            }
            if staged_names != expected_names:
                raise StoreError("App install staged unexpected target changes")
            tree = _git_text(root, "write-tree", budget=budget, index_file=index_state["privatePath"])
            new_head = _git_text(
                root,
                "-c",
                f"user.name={commit_identity[0]}",
                "-c",
                f"user.email={commit_identity[1]}",
                "-c",
                f"author.name={commit_identity[0]}",
                "-c",
                f"author.email={commit_identity[1]}",
                "-c",
                f"committer.name={commit_identity[2]}",
                "-c",
                f"committer.email={commit_identity[3]}",
                "commit-tree",
                tree,
                "-p",
                preview["targetHead"],
                "-m",
                f"Install reviewed disabled App {app_id}",
                "-m",
                f"Source-Commit: {source_commit}",
                "-m",
                f"Bundle-SHA256: {source['bundleSha256']}",
                budget=budget,
                index_file=index_state["privatePath"],
            )
            if not _SHA.fullmatch(new_head):
                raise StoreError("App install commit was not created")
            if (
                _git_text(root, "write-tree", budget=budget, index_file=index_state["privatePath"]) != tree
                or _git_text(root, "rev-parse", "HEAD", budget=budget, index_file=index_state["privatePath"])
                != preview["targetHead"]
            ):
                raise StoreError("App install target changed before publication")
            _revalidate(
                root,
                source,
                app_id,
                store,
                preview,
                route,
                budget,
                protection_provider=protection_provider,
                alias=alias,
                actor=actor,
                stage_name=stage_name,
                staged_state="indexed",
                apps_fd=apps_fd,
                stage_fd=stage_fd,
                app_fd=app_fd,
                stage_identity=stage_identity,
                app_identity=app_identity,
                index_state=index_state,
                git_index_file=index_state["privatePath"],
            )

            _publish_candidate_index(index_state, preview, preview["targetIndexBoundBytes"])
            _revalidate(
                root,
                source,
                app_id,
                store,
                preview,
                route,
                budget,
                protection_provider=protection_provider,
                alias=alias,
                actor=actor,
                stage_name=stage_name,
                staged_state="indexed",
                apps_fd=apps_fd,
                stage_fd=stage_fd,
                app_fd=app_fd,
                stage_identity=stage_identity,
                app_identity=app_identity,
                index_state=index_state,
                git_index_file=index_path,
            )
            _git(
                root,
                "update-ref",
                preview["targetBranch"],
                new_head,
                preview["targetHead"],
                budget=budget,
                index_file=index_path,
            )
            final_head = _git_text(root, "rev-parse", "HEAD", budget=budget, index_file=index_path)
            final_branch = _git_text(root, "symbolic-ref", "-q", "HEAD", budget=budget, index_file=index_path)
            final_status = _git(
                root,
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                budget=budget,
                index_file=index_path,
            )
            final_index, final_index_bytes = _read_index_at(index_state["parentFd"], index_path.name)
            _validate_index(final_index_bytes, preview["targetObjectFormat"])
            if hashlib.sha256(final_index_bytes).hexdigest() != index_state["publishedSha256"]:
                raise StoreError("App install published index differs from its reviewed candidate")
            if final_head != new_head or final_branch != preview["targetBranch"]:
                raise StoreError("App install publication could not be confirmed")
            if final_status:
                raise StoreError("App install Git worktree is not clean after publication")
            _release_index_lock(index_state)
            return {
                "format": "brain-app-install-receipt/v1",
                "appId": app_id,
                "sourceCommit": source_commit,
                "bundleSha256": source["bundleSha256"],
                "previewSha256": preview["previewSha256"],
                "parentHead": preview["targetHead"],
                "installedHead": new_head,
                "state": "disabled-draft",
                "grantsWritten": False,
                "activation": False,
            }
        except BaseException:
            if wrote:
                try:
                    ledger.mark_unknown(reservation["id"])
                except StoreError:
                    pass
            raise
        finally:
            for descriptor in (app_fd, stage_fd, apps_fd):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            if index_state is not None:
                _close_index_state(index_state)


def _revalidate(
    root,
    source,
    app_id,
    store,
    preview,
    route,
    budget,
    *,
    protection_provider,
    alias,
    actor,
    stage_name=None,
    staged_state=None,
    apps_fd=None,
    stage_fd=None,
    app_fd=None,
    stage_identity=None,
    app_identity=None,
    index_state=None,
    git_index_file=None,
):
    _require_clean_source(source["root"], source["sourceCommit"], budget)
    head = _git_text(root, "rev-parse", "--verify", "HEAD^{commit}", budget=budget, index_file=git_index_file)
    branch = _git_text(root, "symbolic-ref", "-q", "HEAD", budget=budget, index_file=git_index_file)
    if head != preview["targetHead"] or branch != preview["targetBranch"]:
        raise StoreError("App install target HEAD changed after review")
    if fingerprint(_git_commit_identity(root, budget)) != preview["commitIdentitySha256"]:
        raise StoreError("App install repository-local Git identity changed after review")
    if staged_state is not None:
        expected_names = {f"apps/{app_id}/{name}" for name in source["files"]}
        cached = {
            value.decode("utf-8")
            for value in _git(
                root,
                "diff",
                "--cached",
                "--name-only",
                "-z",
                preview["targetHead"],
                budget=budget,
                index_file=git_index_file,
            ).split(b"\0")
            if value
        }
        unstaged = {
            value.decode("utf-8")
            for value in _git(root, "diff", "--name-only", "-z", budget=budget, index_file=git_index_file).split(b"\0")
            if value
        }
        untracked = _git(
            root,
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            budget=budget,
            index_file=git_index_file,
        )
        if staged_state == "indexed":
            if cached != expected_names or unstaged or untracked:
                raise StoreError("App install staged target changed after review")
            _assert_index_preview(
                root,
                preview,
                budget,
                index_state=index_state,
                index_file=git_index_file,
                candidate_staged=not index_state["published"],
            )
            _validate_index_entries(root, source, app_id, preview, budget, index_file=git_index_file, staged=True)
            index_info, _index_bytes = (
                _read_index_at(index_state["parentFd"], index_state["path"].name)
                if index_state["published"]
                else _read_candidate_index(index_state, preview["targetObjectFormat"])
            )
            if index_info.st_size > preview["targetIndexBoundBytes"]:
                raise StoreError("App install target index exceeded its preflight bound")
        else:
            stage_prefix = f"apps/{stage_name}/{app_id}/" if staged_state == "source-stage" else f"apps/{app_id}/"
            expected_untracked = {stage_prefix + name for name in source["files"]}
            actual_untracked = {value.decode("utf-8") for value in untracked.split(b"\0") if value}
            if cached or unstaged or not actual_untracked.issubset(expected_untracked):
                raise StoreError("App install stage changed after review")
            _assert_index_preview(root, preview, budget, index_state=index_state, index_file=git_index_file)
            _validate_index_entries(root, source, app_id, preview, budget, index_file=git_index_file, staged=False)
    else:
        _assert_index_preview(root, preview, budget, index_state=index_state, index_file=git_index_file)
        if _git(
            root,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            budget=budget,
            index_file=git_index_file,
        ):
            raise StoreError("App install target worktree changed after review")
        _validate_index_entries(root, source, app_id, preview, budget, index_file=git_index_file, staged=False)
    registration = load_registration(root, required=True)
    selected_path, config = _selected_authority_path(root, store, registration)
    if (
        fingerprint(registration) != route["registrationSha256"]
        or fingerprint(config) != route["configSha256"]
        or store.contract.binding != registration["authority"]["binding"]
        or hashlib.sha256(os.fsencode(selected_path)).hexdigest() != route["authorityPathSha256"]
    ):
        raise StoreError("App install authority or policy changed after review")
    authority = config.get("brain", {}).get("authority", {}) if isinstance(config.get("brain"), dict) else {}
    principals = authority.get("principalsByUid") if isinstance(authority, dict) else None
    operators = authority.get("operatorUids") if isinstance(authority, dict) else None
    uid = str(os.geteuid())
    if (
        not isinstance(principals, dict)
        or principals.get(uid) != actor
        or not isinstance(operators, list)
        or uid not in operators
    ):
        raise StoreError("App install owner identity changed after review")
    fresh_protection = _protection_context(
        protection_provider, root=root, alias=alias, actor=actor, store=store, registration=registration
    )
    if fresh_protection["sha256"] != route["protectionSha256"]:
        raise StoreError("App install protection policy changed after review")
    blob = blob_store_for(root, config, store.contract)
    current_blob_identity = (None, None)
    if registration["blob"]["driver"] == "fs":
        if blob is None or not hasattr(blob, "root"):
            raise StoreError("App install blob route changed after review")
        current_blob_path = Path(blob.root).absolute()
        current_blob_fd = _open_directory_chain(current_blob_path)
        try:
            current_blob = os.fstat(current_blob_fd)
            current_blob_named = current_blob_path.lstat()
            current_blob_identity = (current_blob.st_dev, current_blob.st_ino)
            current_blob_path_sha256 = hashlib.sha256(os.fsencode(current_blob_path.resolve(strict=True))).hexdigest()
            if (
                (current_blob_named.st_dev, current_blob_named.st_ino) != current_blob_identity
                or current_blob_identity != (route["blobDevice"], route["blobInode"])
                or current_blob_path_sha256 != route["blobPathSha256"]
            ):
                raise StoreError("App install blob route changed after review")
        finally:
            os.close(current_blob_fd)
    else:
        current_blob_path_sha256 = hashlib.sha256(os.fsencode(str(Path(store.path).resolve(strict=True)))).hexdigest()
        if blob is not None or current_blob_path_sha256 != route["blobPathSha256"]:
            raise StoreError("App install database blob route changed after review")
    authority_info = selected_path.lstat()
    if (authority_info.st_dev, authority_info.st_ino) != (route["authorityDevice"], route["authorityInode"]) or (
        authority_info.st_dev,
        authority_info.st_ino,
    ) != store.authority_file_identity:
        raise StoreError("App install authority file changed after review")
    current_route = {
        "hostAlias": alias,
        "hostActorSha256": hashlib.sha256(actor.encode("utf-8")).hexdigest(),
        "configSha256": fingerprint(config),
        "registrationSha256": fingerprint(registration),
        "authorityPathSha256": hashlib.sha256(os.fsencode(selected_path)).hexdigest(),
        "authorityDevice": authority_info.st_dev,
        "authorityInode": authority_info.st_ino,
        "blobStore": registration["blob"]["store"],
        "blobDriver": registration["blob"]["driver"],
        "blobLocationSha256": registration["blob"]["locationSha256"],
        "protectionSha256": fresh_protection["sha256"],
        "blobPathSha256": current_blob_path_sha256,
        "blobDevice": current_blob_identity[0],
        "blobInode": current_blob_identity[1],
    }
    if fingerprint(current_route) != fingerprint(route):
        raise StoreError("App install route changed after review")
    root_info = root.stat()
    if hashlib.sha256(os.fsencode(root)).hexdigest() != preview["targetRootSha256"] or (
        root_info.st_dev,
        root_info.st_ino,
    ) != (preview["targetRootDevice"], preview["targetRootInode"]):
        raise StoreError("App install target brain changed after review")
    apps = root / "apps"
    apps_info = apps.lstat()
    if (
        not stat.S_ISDIR(apps_info.st_mode)
        or stat.S_ISLNK(apps_info.st_mode)
        or apps_info.st_uid != os.geteuid()
        or apps_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
        or (apps_info.st_dev, apps_info.st_ino) != (preview["appsDevice"], preview["appsInode"])
    ):
        raise StoreError("App install repository route changed after review")
    target = root / "apps" / app_id
    if apps_fd is not None:
        apps_open = os.fstat(apps_fd)
        apps_named = apps.lstat()
        if (apps_open.st_dev, apps_open.st_ino) != (preview["appsDevice"], preview["appsInode"]) or (
            apps_named.st_dev,
            apps_named.st_ino,
        ) != (apps_open.st_dev, apps_open.st_ino):
            raise StoreError("App install repository route changed after review")
    if staged_state == "source-stage":
        try:
            os.stat(app_id, dir_fd=apps_fd, follow_symlinks=False)
        except FileNotFoundError:
            target_absent = True
        else:
            target_absent = False
        stage_open = os.fstat(stage_fd)
        stage_named = os.stat(stage_name, dir_fd=apps_fd, follow_symlinks=False)
        app_open = os.fstat(app_fd)
        app_named = os.stat(app_id, dir_fd=stage_fd, follow_symlinks=False)
        if (
            not target_absent
            or (stage_open.st_dev, stage_open.st_ino) != stage_identity
            or (stage_named.st_dev, stage_named.st_ino) != stage_identity
            or (app_open.st_dev, app_open.st_ino) != app_identity
            or (app_named.st_dev, app_named.st_ino) != app_identity
        ):
            raise StoreError("App install stage changed after review")
    elif staged_state == "target-worktree" or staged_state == "indexed":
        target_info = os.stat(app_id, dir_fd=apps_fd, follow_symlinks=False)
        app_open = os.fstat(app_fd)
        if (
            not stat.S_ISDIR(target_info.st_mode)
            or (target_info.st_dev, target_info.st_ino) != app_identity
            or (app_open.st_dev, app_open.st_ino) != app_identity
        ):
            raise StoreError("App install stage changed after review")
    else:
        try:
            os.stat(app_id, dir_fd=apps_fd, follow_symlinks=False) if apps_fd is not None else target.lstat()
        except FileNotFoundError:
            pass
        else:
            raise StoreError("App install target appeared after review")


def _open_owned_stage_directory(parent_fd, component, prefix, owned_directories):
    """Open a stage child, creating it once and only reusing its pinned inode."""
    known_prefix = prefix in owned_directories
    created = False
    if known_prefix:
        # A directory already created for this operation must still exist at
        # its original name. Do not recreate and silently repin a missing one.
        expected_identity = owned_directories[prefix]
    else:
        try:
            os.mkdir(component, mode=0o755, dir_fd=parent_fd)
        except FileExistsError as exc:
            raise StoreError("App install nested directory appeared during staging") from exc
        created = True
        expected_identity = None

    child = None
    try:
        try:
            named = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError as exc:
            message = (
                "App install owned nested directory is missing"
                if known_prefix
                else "App install new directory disappeared"
            )
            raise StoreError(message) from exc
        if not stat.S_ISDIR(named.st_mode) or named.st_uid != os.geteuid():
            raise StoreError("App install nested directory is unsafe")
        named_identity = (named.st_dev, named.st_ino, named.st_uid, named.st_mode)
        if created:
            if named.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID):
                raise StoreError("App install new directory has unsafe permissions")
        elif expected_identity != named_identity:
            raise StoreError("App install nested directory appeared or changed during staging")

        child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        opened = os.fstat(child)
        named_after_open = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or (opened.st_dev, opened.st_ino, opened.st_uid, opened.st_mode) != named_identity
            or (named_after_open.st_dev, named_after_open.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise StoreError("App install nested directory changed while opening")

        if created:
            # Only this operation's just-created, identity-pinned inode may be
            # chmodded. Reused directories must already have the expected mode.
            os.fchmod(child, 0o755)
        elif opened.st_mode & 0o777 != 0o755:
            raise StoreError("App install owned nested directory mode changed")

        os.fsync(child)
        opened_after = os.fstat(child)
        named_after_chmod = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
        opened_identity = (opened_after.st_dev, opened_after.st_ino, opened_after.st_uid, opened_after.st_mode)
        if (
            (opened_after.st_dev, opened_after.st_ino) != (opened.st_dev, opened.st_ino)
            or (named_after_chmod.st_dev, named_after_chmod.st_ino, named_after_chmod.st_uid, named_after_chmod.st_mode)
            != opened_identity
            or opened_after.st_uid != os.geteuid()
            or opened_after.st_mode & 0o777 != 0o755
            or opened_after.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
        ):
            raise StoreError("App install nested directory changed while staging")
        if created:
            owned_directories[prefix] = opened_identity
        os.fsync(parent_fd)
        return child
    except BaseException:
        if child is not None:
            os.close(child)
        raise


def _install_files(apps_fd, stage_name, app_id, files, entries):
    """Create a private stage and return its held descriptors and identities."""
    stage_fd = app_fd = None
    try:
        info = os.fstat(apps_fd)
        if (
            info.st_uid != os.geteuid()
            or not stat.S_ISDIR(info.st_mode)
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
        ):
            raise StoreError("App install directory is unsafe")
        os.mkdir(stage_name, mode=0o700, dir_fd=apps_fd)
        stage_fd = os.open(stage_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=apps_fd)
        stage_info = os.fstat(stage_fd)
        named_stage = os.stat(stage_name, dir_fd=apps_fd, follow_symlinks=False)
        stage_identity = (stage_info.st_dev, stage_info.st_ino)
        if stage_identity != (named_stage.st_dev, named_stage.st_ino):
            raise StoreError("App install stage changed while opening")
        os.mkdir(app_id, mode=0o700, dir_fd=stage_fd)
        app_fd = os.open(app_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=stage_fd)
        os.fchmod(app_fd, 0o755)
        owned_directories = {}
        for relative, raw in sorted(files.items()):
            parts = Path(relative).parts
            current = os.dup(app_fd)
            try:
                prefix = ()
                for component in parts[:-1]:
                    prefix += (component,)
                    child = _open_owned_stage_directory(current, component, prefix, owned_directories)
                    os.close(current)
                    current = child
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
                fd = os.open(parts[-1], flags, 0o755 if entries[relative]["executable"] else 0o644, dir_fd=current)
                try:
                    os.fchmod(fd, 0o755 if entries[relative]["executable"] else 0o644)
                    view = memoryview(raw)
                    while view:
                        written = os.write(fd, view)
                        if written <= 0:
                            raise StoreError("App install could not write a complete bundle file")
                        view = view[written:]
                    os.fsync(fd)
                    os.fsync(current)
                finally:
                    os.close(fd)
            finally:
                os.close(current)
        os.fsync(app_fd)
        os.fsync(stage_fd)
        os.fsync(apps_fd)
        app_info = os.fstat(app_fd)
        return stage_fd, app_fd, stage_identity, (app_info.st_dev, app_info.st_ino)
    except BaseException as exc:
        if app_fd is not None:
            try:
                os.close(app_fd)
            except OSError:
                pass
        if stage_fd is not None:
            try:
                os.close(stage_fd)
            except OSError:
                pass
        if isinstance(exc, OSError):
            raise StoreError("App install stage is unavailable or incomplete") from exc
        raise


def _publish_stage(apps_fd, stage_fd, app_fd, stage_name, app_id, stage_identity, app_identity):
    """Move the exact held directory with atomic kernel no-replace semantics."""
    root_before = os.fstat(apps_fd)
    stage_open = os.fstat(stage_fd)
    app_open = os.fstat(app_fd)
    try:
        stage_named = os.stat(stage_name, dir_fd=apps_fd, follow_symlinks=False)
        app_named = os.stat(app_id, dir_fd=stage_fd, follow_symlinks=False)
        if (
            (stage_open.st_dev, stage_open.st_ino) != stage_identity
            or (stage_named.st_dev, stage_named.st_ino) != stage_identity
            or (app_open.st_dev, app_open.st_ino) != app_identity
            or (app_named.st_dev, app_named.st_ino) != app_identity
            or not stat.S_ISDIR(stage_open.st_mode)
            or not stat.S_ISDIR(app_open.st_mode)
            or stage_open.st_uid != os.geteuid()
            or app_open.st_uid != os.geteuid()
            or root_before.st_uid != os.geteuid()
            or root_before.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
        ):
            raise StoreError("App install stage changed before publication")
        _rename_noreplace(stage_fd, app_id, apps_fd, app_id)
        os.fsync(stage_fd)
        published = os.stat(app_id, dir_fd=apps_fd, follow_symlinks=False)
        if (published.st_dev, published.st_ino) != app_identity or not stat.S_ISDIR(published.st_mode):
            raise StoreError("App install publication could not be confirmed")
        # The wrapper is now empty. Remove it only if its original name still
        # identifies the held stage directory; otherwise retain the residue.
        stage_named = os.stat(stage_name, dir_fd=apps_fd, follow_symlinks=False)
        if (stage_named.st_dev, stage_named.st_ino) != stage_identity:
            raise StoreError("App install stage residue changed after publication")
        os.rmdir(stage_name, dir_fd=apps_fd)
        root_after = os.fstat(apps_fd)
        if (root_before.st_dev, root_before.st_ino) != (root_after.st_dev, root_after.st_ino):
            raise StoreError("App install repository changed during publication")
        os.fsync(apps_fd)
    except OSError as exc:
        raise StoreError("App install publication failed or is uncertain") from exc
