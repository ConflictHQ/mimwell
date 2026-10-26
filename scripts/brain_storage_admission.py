"""Opt-in admission accounting for host-managed retained brain content (#536).

This module is deliberately inert unless the owner has explicitly adopted a
versioned host registration. It measures logical retained content bytes, not OS
or database page allocation. Writers use durable reservations before any effect
outside their native database transaction.

Filesystem tree walks run in an isolated standard-library worker. Supplied
InventoryBudget deadlines and counters remain shared across all roots; direct
unbudgeted tree calls have a 30-second per-worker watchdog and may fail closed.
"""
from __future__ import annotations

import errno
try:
    import fcntl
except ImportError:
    fcntl = None
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import sqlite3
import stat
import signal
import subprocess
import sys
import time

from knowledge_policy import fingerprint
from knowledge_store import SNAPSHOT_COLUMNS, StoreError

FORMAT = "brain-retained-content/v1"
ACCOUNTING = "logical-retained-content-bytes/v1"
REGISTRATION = "_internal/brain-storage-admission.json"
LEDGER = "_internal/brain-storage-admission.sqlite3"
LEDGER_LOCK = "_internal/brain-storage-admission.lock"
WRITER_LOCK = "_internal/brain-storage-admission-writer.lock"
PERSISTENT_LOCK_PROTOCOL = "persistent-locks/v2"
LEGACY_PERSISTENT_LOCK_PROTOCOL = "persistent-locks/v1"
MAX_LEDGER_FILE_BYTES = 64 * 1024 * 1024
MAX_LEDGER_META_ROWS = 64
MAX_LEDGER_ROWS = 100_000
MAX_LEDGER_OUTPUT_BYTES = 16 * 1024
UNBUDGETED_TREE_WATCHDOG_SECONDS = 30.0
MAX_PROCESS_GROUP_SCAN_BYTES = 2 * 1024 * 1024
PROCESS_GROUP_SCAN_SECONDS = 1.0
_LEDGER_STATES = frozenset(("reserved", "outcome-unknown", "settled"))


def _check_ledger_deadline(deadline, db=None, budget=None):
    if budget is not None:
        budget.check_time()
    elif time.monotonic() >= deadline:
        raise StoreError("Storage inspection snapshot exceeded its deadline")


def _require_no_ledger_sidecars(ledger_path):
    parent_fd = _open_directory_chain(Path(ledger_path).parent)
    try:
        for suffix in ("-wal", "-shm", "-journal"):
            try:
                info = os.stat(ledger_path.name + suffix, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise StoreError("Storage inspection ledger sidecar is unsafe") from exc
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
                raise StoreError("Storage inspection ledger sidecar is unsafe")
            raise StoreError("Storage inspection ledger has unresolved sidecar state")
    finally:
        os.close(parent_fd)
MAX_REGISTRATION_BYTES = 64 * 1024
MAX_CLIENT_CONFIG_BYTES = 1024 * 1024
MAX_ROOTS = 64
_SHA = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_ACTIVE_ROOTS = ContextVar("brain_storage_admission_roots", default=frozenset())
_ACTIVE_EFFECTS = ContextVar("brain_storage_admission_effects", default={})


def admission_active(root):
    return str(Path(root).resolve()) in _ACTIVE_ROOTS.get()


def active_effect(root):
    """Return the current trusted effect for a root, including across fresh Store objects."""
    return _ACTIVE_EFFECTS.get().get(str(Path(root).resolve()))


class HostWriterRoute:
    """A factory-bound route, not a caller-supplied quota or protection assertion.

    Generic BlobStore/SessionStore constructors remain legacy APIs. Only the
    factories which receive the actual host-selected root install this binding.
    An adopted binding requires the ledger context created by the host writer;
    it never creates adoption or starts an implicit reservation of its own.
    """

    def __init__(self, root, writer, *, contract=None, authority=None):
        self.root = Path(root).resolve(strict=True)
        self.writer, self.contract, self.authority = writer, contract, authority
        info = self.root.stat()
        self.root_identity = (info.st_dev, info.st_ino)
        self.registration = load_registration(self.root)
        self.registration_sha256 = fingerprint(self.registration)
        self._route()

    def _route(self):
        registration = self.registration
        if self.contract is None:
            if self.writer.directory != self.root / "_internal/studio-app-sessions":
                raise StoreError("Host session writer is not the registered session route")
            return
        if registration is None:
            return
        contract = self.contract
        if (registration["authority"] != {"store": contract.authority, "binding": contract.binding}
                or registration["blob"]["store"] != self.writer.store_id
                or contract.blob_store != self.writer.store_id
                or registration["blob"]["driver"] != self.writer.driver
                or contract.cell["blobs"] != self.writer.driver):
            raise StoreError("Host blob writer differs from the adopted contract route")
        if self.writer.driver == "fs":
            location = self.writer.root.resolve(strict=True)
            directory_fd = _open_directory_chain(self.writer.root.absolute())
            try:
                info = os.fstat(directory_fd)
                identity = (info.st_dev, info.st_ino)
                if hasattr(self, "blob_identity") and identity != self.blob_identity:
                    raise StoreError("Host blob writer directory changed")
                self.blob_identity = identity
            finally:
                os.close(directory_fd)
        elif self.writer.driver == "db-blob":
            if self.authority is None or self.writer.dialect is not self.authority.dialect:
                raise StoreError("Host database blob writer has no selected authority connection")
            location, _config = _selected_authority_path(self.root, self.authority, registration)
        else:
            raise StoreError("Adopted host blob writer requires a qualified local route")
        if hashlib.sha256(os.fsencode(str(location))).hexdigest() != registration["blob"]["locationSha256"]:
            raise StoreError("Host blob writer location differs from its adopted route")

    def validate(self):
        root_fd = _open_directory_chain(self.root)
        try:
            info = os.fstat(root_fd)
            if (info.st_dev, info.st_ino) != self.root_identity:
                raise StoreError("Host writer brain root changed")
        finally:
            os.close(root_fd)
        current = load_registration(self.root)
        if fingerprint(current) != self.registration_sha256:
            raise StoreError("Host writer storage registration changed; rebind the host route")
        self._route()
        if current is None:
            return None
        effect = active_effect(self.root)
        if (not isinstance(effect, dict) or not isinstance(effect.get("ledger"), AdmissionLedger)
                or effect.get("authorityBinding") != current["authority"]["binding"]
                or effect["ledger"].root.resolve() != self.root
                or fingerprint(effect["ledger"].registration) != self.registration_sha256):
            raise StoreError("Enrolled host writes require the active adopted brain ledger")
        effect["ledger"].verify_ready()
        effect["ledger"].check_before_commit(effect["identity"], inventory_now=effect["inventory"])
        return effect

    def charge_blob(self, key, data):
        effect = self.validate()
        if effect is None:
            return None
        # Use the same retained-content representation as inventory, including
        # UTF-8 database keys. Filesystem names are basis metadata, not charged
        # content bytes; database keys are persisted native blob cells.
        amount = (_db_blob_retained_bytes(key, data) if self.writer.driver == "db-blob"
                  else len(data))
        token = effect["ledger"].check_external_write(effect["identity"], amount,
            inventory_now=effect["inventory"], consume=True)
        return effect, token

    def complete_blob(self, charge):
        effect = self.validate()
        if charge is None:
            if effect is not None:
                raise StoreError("Host blob adoption changed during its write")
            return
        original, token = charge
        if (effect is None or effect["ledger"] is not original["ledger"]
                or effect["identity"] != original["identity"]):
            raise StoreError("Host blob write lost its active reservation")
        effect["ledger"].complete_external_write(token, actual_bytes=token["boundBytes"],
                                                inventory_now=effect["inventory"])

    def session_write(self, amount, session_id):
        effect = self.validate()
        if effect is None:
            return
        lease = effect.get("sessionWrite")
        if lease is not None:
            # upload_session_write has already debited this exact atomic temp.
            # Charging it again would count the same overlap twice.
            if lease != {"sessionId": session_id, "temporaryBytes": amount}:
                raise StoreError("Host session write differs from its active session lease")
        else:
            effect["ledger"].preflight_external_write(effect["identity"], amount,
                                                      inventory_now=effect["inventory"])


def bind_host_blob_writer(root, contract, writer, *, authority=None):
    """Enroll a declared host-created blob store; generic constructors stay unbound."""
    writer._host_writer_route = HostWriterRoute(root, writer, contract=contract, authority=authority)
    return writer


def _encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _read_private_at(directory_fd, name, *, maximum):
    """Read one owner-private regular file relative to a validated directory FD."""
    try:
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise StoreError("Storage admission registration is unavailable") from exc
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
            or info.st_mode & 0o077 or info.st_size > maximum):
        raise StoreError("Storage admission registration is unsafe or exceeds its limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise StoreError("Storage admission registration changed or is unsafe") from exc
    try:
        opened = os.fstat(fd)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if ((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
                or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
                != (named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns, named.st_ctime_ns)
                or not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.geteuid()
                or opened.st_nlink != 1 or opened.st_mode & 0o077 or opened.st_size > maximum):
            raise StoreError("Storage admission registration changed while opening")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        final = os.fstat(fd)
        named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (len(raw) > maximum or
                (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
                != (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns, final.st_ctime_ns)
                or (final.st_dev, final.st_ino) != (named_after.st_dev, named_after.st_ino)):
            raise StoreError("Storage admission registration changed while reading")
        return raw
    finally:
        os.close(fd)


def _open_directory_chain(path):
    """Open an absolute directory without following any path component links."""
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise StoreError("Safe storage-admission registration lookup is unavailable on this platform")
    path = Path(path).absolute()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        current = os.open(path.anchor or "/", flags)
    except OSError as exc:
        raise StoreError("Storage admission brain root is unavailable or unsafe") from exc
    try:
        for component in path.parts[1:]:
            try:
                named = os.stat(component, dir_fd=current, follow_symlinks=False)
                if not stat.S_ISDIR(named.st_mode):
                    raise StoreError("Storage admission brain root contains an unsafe path component")
                child = os.open(component, flags, dir_fd=current)
            except StoreError:
                raise
            except OSError as exc:
                raise StoreError("Storage admission brain root changed or is unsafe") from exc
            opened = os.fstat(child)
            if ((opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                    or not stat.S_ISDIR(opened.st_mode)):
                os.close(child)
                raise StoreError("Storage admission brain root changed while opening")
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _relative_authority_route(path, selected_root, root, root_info, *, allow_root=False):
    """Map a configured authority path to a root-relative route without trusting child links."""
    path = Path(path)
    if ".." in path.parts:
        raise StoreError("Selected SQLite authority path is unsafe")
    selected_root = Path(selected_root).absolute()
    root = Path(root).absolute()
    if not path.is_absolute():
        path = selected_root / path
    path = Path(os.path.abspath(path))
    if path.is_relative_to(selected_root):
        relative = path.relative_to(selected_root)
    elif path.is_relative_to(root):
        relative = path.relative_to(root)
    else:
        try:
            canonical = path.resolve(strict=True)
        except OSError as exc:
            raise StoreError("Selected SQLite authority path is unavailable") from exc
        if not canonical.is_relative_to(root):
            raise StoreError("Storage admission requires the configured SQLite authority inside this brain")
        relative = canonical.relative_to(root)
        # Accept an absolute route alias only when an existing directory in that
        # spelling is the selected root itself. Child traversal remains O_NOFOLLOW.
        root_alias = None
        for parent in path.parents:
            try:
                resolved_parent = parent.resolve(strict=True)
                parent_info = parent.lstat()
            except OSError:
                continue
            if (resolved_parent == root and stat.S_ISDIR(parent_info.st_mode)
                    and (parent_info.st_dev, parent_info.st_ino)
                    == (root_info.st_dev, root_info.st_ino)):
                root_alias = parent
                break
        if root_alias is None:
            raise StoreError("Storage admission authority route does not identify this brain root")
        relative = path.relative_to(root_alias)
        if Path(os.path.abspath(root / relative)) != canonical:
            raise StoreError("Storage admission authority route alias is unsafe")
    if ((not relative.parts and not allow_root)
            or any(part in (".", "..") for part in relative.parts)):
        raise StoreError("Selected SQLite authority path is unsafe")
    return relative


def _read_storage_config(root, *, forbidden_identities=()):
    """Read the canonical bounded configuration without aliasing an owned native FD."""
    selected_root = Path(root).absolute()
    root = selected_root.resolve(strict=True)
    root_fd = _open_directory_chain(root)
    try:
        root_info = os.fstat(root_fd)
        unsafe_write = stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID
        if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.geteuid()
                or root_info.st_mode & unsafe_write):
            raise StoreError("Storage admission brain root is unavailable or unsafe")

        try:
            info = os.stat("client.config.json", dir_fd=root_fd, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                    or info.st_mode & unsafe_write or info.st_size > MAX_CLIENT_CONFIG_BYTES
                    or (info.st_dev, info.st_ino) in forbidden_identities):
                raise StoreError("Selected authority configuration is unsafe or exceeds its limit")
            fd = os.open("client.config.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd)
        except StoreError:
            raise
        except OSError as exc:
            raise StoreError("Selected authority configuration is unavailable or unsafe") from exc
        try:
            opened = os.fstat(fd)
            def identity(item):
                return item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns

            if (identity(opened) != identity(info) or not stat.S_ISREG(opened.st_mode)
                    or opened.st_uid != os.geteuid() or opened.st_nlink != 1
                    or opened.st_mode & unsafe_write or opened.st_size > MAX_CLIENT_CONFIG_BYTES):
                raise StoreError("Selected authority configuration changed while opening")
            chunks = []
            remaining = MAX_CLIENT_CONFIG_BYTES + 1
            while remaining:
                chunk = os.read(fd, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            final = os.fstat(fd)
            named = os.stat("client.config.json", dir_fd=root_fd, follow_symlinks=False)
            if (len(raw) != opened.st_size or len(raw) > MAX_CLIENT_CONFIG_BYTES
                    or identity(opened) != identity(final)
                    or identity(final) != identity(named)):
                raise StoreError("Selected authority configuration changed while reading")
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)
    try:
        settings = json.loads(raw)
        if not isinstance(settings, dict):
            raise StoreError("Selected authority configuration is invalid")
    except (ValueError, UnicodeDecodeError) as exc:
        raise StoreError("Selected authority configuration is invalid") from exc
    return root, root_info, settings


def _selected_authority_path(root, store, selection):
    """Require the adopted SQLite authority to be the configured file under this brain."""
    selected_root = Path(root).absolute()
    root, root_info, settings = _read_storage_config(root,
        forbidden_identities=(getattr(store, "authority_file_identity", None),))
    unsafe_write = stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID
    try:
        from knowledge_store import SQLiteAuthority, adopted_authority, authority_class, resolve_store_dsn
        selected = adopted_authority(settings)
        if (not isinstance(selected, dict) or selected.get("store") != selection["authority"]["store"]
                or selected.get("binding") != selection["authority"]["binding"]):
            raise StoreError("Selected authority differs from the storage admission preview")
        dsn = resolve_store_dsn(settings, selected["store"])
        if "://" in dsn or authority_class(dsn) is not SQLiteAuthority:
            raise StoreError("Storage admission requires a local SQLite authority")
        selected_relative = _relative_authority_route(Path(dsn), selected_root, root, root_info)
        supplied_relative = _relative_authority_route(Path(store.path), selected_root, root, root_info)
        if selected_relative != supplied_relative:
            raise StoreError("Storage admission requires the configured SQLite authority inside this brain")
        if (not isinstance(store, SQLiteAuthority) or store.contract.authority != selected["store"]
                or store.contract.binding != selected["binding"]):
            raise StoreError("Storage admission selected authority changed")
        relative = selected_relative
        selected_path = root / relative
        parent_fd = _open_directory_chain(root)
        try:
            for component in relative.parts[:-1]:
                named_directory = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
                if (not stat.S_ISDIR(named_directory.st_mode) or named_directory.st_uid != os.geteuid()
                        or named_directory.st_mode & unsafe_write):
                    raise StoreError("Selected SQLite authority path is unsafe")
                child_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                   dir_fd=parent_fd)
                opened_directory = os.fstat(child_fd)
                current_named = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
                if ((opened_directory.st_dev, opened_directory.st_ino)
                        != (named_directory.st_dev, named_directory.st_ino)
                        or (current_named.st_dev, current_named.st_ino)
                        != (opened_directory.st_dev, opened_directory.st_ino)):
                    os.close(child_fd)
                    raise StoreError("Selected SQLite authority path changed while opening")
                os.close(parent_fd)
                parent_fd = child_fd
            before = os.stat(relative.parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1
                    or before.st_mode & unsafe_write):
                raise StoreError("Selected SQLite authority file is unsafe")
            # Do not open and close the authority again here. On POSIX, closing
            # any descriptor for a database can release process-associated
            # SQLite locks held by the already-open authority connection.
            # The connection pins its dev/inode when it opens; compare that
            # pin with no-follow metadata from this held parent directory.
            named_file = os.stat(relative.parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            pinned_identity = getattr(store, "authority_file_identity", None)
            if ((named_file.st_dev, named_file.st_ino) != (before.st_dev, before.st_ino)
                    or pinned_identity != (named_file.st_dev, named_file.st_ino)
                    or not stat.S_ISREG(named_file.st_mode) or named_file.st_uid != os.geteuid()
                    or named_file.st_nlink != 1 or named_file.st_mode & unsafe_write):
                raise StoreError("Selected SQLite authority connection identity changed")
        finally:
            os.close(parent_fd)
        return selected_path, settings
    except StoreError:
        raise
    except (OSError, TypeError, ValueError, KeyError) as exc:
        raise StoreError("Selected SQLite authority route is unavailable or unsafe") from exc


def validate_registration(value):
    required = {"format", "accounting", "brainId", "limitBytes", "authority",
                "blob", "appRepository", "retainedRoots", "protection", "adoption"}
    if not isinstance(value, dict) or set(value) != required:
        raise StoreError("Storage admission registration has unsupported fields")
    if (value["format"] != FORMAT or value["accounting"] != ACCOUNTING
            or not isinstance(value["brainId"], str) or not _ID.fullmatch(value["brainId"])
            or type(value["limitBytes"]) is not int or value["limitBytes"] <= 0):
        raise StoreError("Storage admission registration is invalid")
    authority = value["authority"]
    if (not isinstance(authority, dict) or set(authority) != {"store", "binding"}
            or not isinstance(authority["store"], str) or not authority["store"]
            or not isinstance(authority["binding"], str) or not _SHA.fullmatch(authority["binding"])):
        raise StoreError("Storage admission authority pin is invalid")
    blob = value["blob"]
    if (not isinstance(blob, dict) or set(blob) != {"store", "driver", "locationSha256"}
            or not isinstance(blob["store"], str) or not blob["store"]
            or blob["driver"] not in ("fs", "db-blob")
            or not isinstance(blob["locationSha256"], str) or not _SHA.fullmatch(blob["locationSha256"])):
        raise StoreError("Storage admission blob route pin is invalid or unsupported")
    if value["appRepository"] != {"path": ".", "directory": "apps"}:
        raise StoreError("Storage admission App repository must be the selected brain root/apps")
    roots = value["retainedRoots"]
    if not isinstance(roots, list) or len(roots) > MAX_ROOTS:
        raise StoreError("Storage admission retained roots exceed their bound")
    seen = set()
    for item in roots:
        if (not isinstance(item, dict) or set(item) != {"id", "path", "kind"}
                or not isinstance(item["id"], str) or not _ID.fullmatch(item["id"])
                or item["kind"] not in ("backup", "snapshot")
                or not isinstance(item["path"], str) or not os.path.isabs(item["path"])
                or item["id"] in seen):
            raise StoreError("Storage admission retained root is invalid")
        seen.add(item["id"])
    protection = value["protection"]
    if (not isinstance(protection, dict) or set(protection) != {"profile", "requirementsSha256"}
            or protection["profile"] not in ("per-record", "hybrid-pointer", "whole-root")
            or not isinstance(protection["requirementsSha256"], str)
            or not _SHA.fullmatch(protection["requirementsSha256"])):
        raise StoreError("Storage admission protection selection is invalid")
    adoption = value["adoption"]
    if (not isinstance(adoption, dict) or set(adoption) != {
            "previewSha256", "inventoryBasisSha256", "authorityRevision"}
            or not isinstance(adoption["previewSha256"], str) or not _SHA.fullmatch(adoption["previewSha256"])
            or not isinstance(adoption["inventoryBasisSha256"], str)
            or not _SHA.fullmatch(adoption["inventoryBasisSha256"])
            or not isinstance(adoption["authorityRevision"], str) or not adoption["authorityRevision"]):
        raise StoreError("Storage admission adoption receipt is invalid")
    return value


def validate_selection(value):
    """Validate the operator's proposed selection before preview, without adoption."""
    if not isinstance(value, dict) or "adoption" in value:
        raise StoreError("Storage admission selection is invalid")
    candidate = {**value, "adoption": {
        "previewSha256": "0" * 64,
        "inventoryBasisSha256": "0" * 64,
        "authorityRevision": "preview-only"}}
    validate_registration(candidate)
    return dict(value)


def _admission_platform_available():
    # These are the existing host-owned directory/lock/process primitives, not
    # a Windows lock emulation or an admission capability advertisement.
    return (fcntl is not None and callable(getattr(fcntl, "flock", None))
            and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
            and callable(getattr(os, "geteuid", None)))


def _require_admission_platform():
    if not _admission_platform_available():
        raise StoreError("Host-managed storage admission is unsupported on this platform")


def _unregistered_on_unsupported_platform(root, *, required):
    """Establish only absence, never Windows ownership/admission authority.

    No files are opened, created, parsed or followed. A marker, reparse point,
    inspection error or changed directory refuses. Supported POSIX hosts retain
    the original directory-FD lookup below without entering this branch.
    """
    _require = "Host-managed storage admission is unsupported on this platform"
    if required:
        raise StoreError(_require)
    root = Path(root).absolute()
    seen = []

    def identity(info, contents):
        value = (info.st_dev, info.st_ino, info.st_mode,
                 getattr(info, "st_file_attributes", 0))
        # Ancestor sibling activity does not change this route's identity.
        # Only selected-root/_internal content changes affect marker absence.
        return value + (info.st_size, info.st_mtime_ns, info.st_ctime_ns) if contents else value

    def directory(path, *, contents=False):
        try:
            info = path.lstat()
        except OSError as exc:
            raise StoreError(_require + "; unregistered path cannot be inspected safely") from exc
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or type(info.st_dev) is not int or type(info.st_ino) is not int or info.st_ino <= 0
                or getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
            raise StoreError(_require + "; unregistered path is unsafe")
        seen.append((path, identity(info, contents), contents))
        return info

    current = Path(root.anchor)
    directory(current, contents=current == root)
    for part in root.parts[1:]:
        current = current / part
        directory(current, contents=current == root)
    internal = root / "_internal"
    try:
        internal.lstat()
    except FileNotFoundError:
        internal_present = False
    except OSError as exc:
        raise StoreError(_require + "; internal state cannot be inspected safely") from exc
    else:
        directory(internal, contents=True)
        internal_present = True
    if internal_present:
        markers = ("brain-storage-admission.json", "brain-storage-admission.sqlite3",
            "brain-storage-admission.sqlite3-wal", "brain-storage-admission.sqlite3-shm",
            "brain-storage-admission.sqlite3-journal", "brain-storage-admission.lock",
            "brain-storage-admission-writer.lock")
        for marker in markers:
            try:
                (internal / marker).lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise StoreError(_require + "; admission state is unavailable or unsafe") from exc
            raise StoreError(_require + "; registration or orphaned ledger state is present")
    for path, before, contents in seen:
        try:
            after = path.lstat()
        except OSError as exc:
            raise StoreError(_require + "; unregistered path changed during inspection") from exc
        if identity(after, contents) != before:
            raise StoreError(_require + "; unregistered path changed during inspection")
    # This is not a cross-host lock or an atomic adoption/write boundary. The
    # unsupported host cannot adopt via these APIs; supported hosts use FDs.
    return None


def load_registration(root, *, required=False):
    if not _admission_platform_available():
        return _unregistered_on_unsupported_platform(root, required=required)
    try:
        # Resolve the already-selected brain path once; do not resolve children,
        # so `_internal` symlinks remain visible to the no-follow checks below.
        root = Path(root).resolve(strict=True)
    except OSError as exc:
        raise StoreError("Storage admission brain root is unavailable or unsafe") from exc
    root_fd = _open_directory_chain(root)
    try:
        root_info = os.fstat(root_fd)
        if not stat.S_ISDIR(root_info.st_mode):
            raise StoreError("Storage admission brain root is unavailable or unsafe")
        try:
            internal_info = os.stat("_internal", dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            internal_info = None
        except OSError as exc:
            raise StoreError("Storage admission state directory is unavailable or unsafe") from exc
        if internal_info is None:
            if required:
                raise StoreError("Storage admission is unavailable; owner adoption is required")
            return None
        if not stat.S_ISDIR(internal_info.st_mode):
            raise StoreError("Storage admission state directory is unavailable or unsafe")
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            internal_fd = os.open("_internal", directory_flags, dir_fd=root_fd)
        except OSError as exc:
            raise StoreError("Storage admission state directory changed or is unsafe") from exc
        try:
            opened_internal = os.fstat(internal_fd)
            named_internal = os.stat("_internal", dir_fd=root_fd, follow_symlinks=False)
            if ((opened_internal.st_dev, opened_internal.st_ino)
                    != (internal_info.st_dev, internal_info.st_ino)
                    or (named_internal.st_dev, named_internal.st_ino)
                    != (opened_internal.st_dev, opened_internal.st_ino)
                    or not stat.S_ISDIR(opened_internal.st_mode)):
                raise StoreError("Storage admission state directory changed or is unsafe")
            try:
                os.stat("brain-storage-admission.json", dir_fd=internal_fd, follow_symlinks=False)
            except FileNotFoundError:
                _refuse_orphan_adoption_ledger(internal_fd)
                if required:
                    raise StoreError("Storage admission is unavailable; owner adoption is required")
                final_internal = os.stat("_internal", dir_fd=root_fd, follow_symlinks=False)
                if (final_internal.st_dev, final_internal.st_ino) != (opened_internal.st_dev,
                                                                      opened_internal.st_ino):
                    raise StoreError("Storage admission state directory changed while reading")
                return None
            except OSError as exc:
                raise StoreError("Storage admission registration is unavailable or unsafe") from exc
            if (root_info.st_uid != os.geteuid()
                    or root_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)):
                raise StoreError("Storage admission brain root is unavailable or unsafe")
            if (opened_internal.st_uid != os.geteuid() or opened_internal.st_mode & 0o077):
                raise StoreError("Storage admission state directory is unavailable or unsafe")
            try:
                raw = _read_private_at(internal_fd, "brain-storage-admission.json",
                                       maximum=MAX_REGISTRATION_BYTES)
            except FileNotFoundError as exc:
                raise StoreError("Storage admission registration changed while reading") from exc
            final_internal = os.stat("_internal", dir_fd=root_fd, follow_symlinks=False)
            if (final_internal.st_dev, final_internal.st_ino) != (opened_internal.st_dev, opened_internal.st_ino):
                raise StoreError("Storage admission state directory changed while reading")
        finally:
            os.close(internal_fd)
    finally:
        os.close(root_fd)
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise StoreError("Storage admission registration is invalid") from exc
    return validate_registration(value)


def _refuse_orphan_adoption_ledger(internal_fd):
    """Refuse orphaned #536 ledger state; never infer adoption from brain.authority."""
    markers = ("brain-storage-admission.sqlite3", "brain-storage-admission.sqlite3-wal",
               "brain-storage-admission.sqlite3-shm", "brain-storage-admission.sqlite3-journal",
               "brain-storage-admission.lock", "brain-storage-admission-writer.lock")
    for marker in markers:
        try:
            info = os.stat(marker, dir_fd=internal_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise StoreError("Storage admission ledger state is unavailable or unsafe") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise StoreError("Orphaned storage admission ledger state is unsafe")
        raise StoreError("Orphaned storage admission ledger requires operator reconciliation")


class InventoryBudget:
    """Optional aggregate limits for protected host inspection; default CLI stays unbounded as before."""
    def __init__(self, *, deadline_seconds=10.0, files=50_000, path_bytes=16 * 1024 * 1024,
                 content_bytes=2 * 1024 * 1024 * 1024, rows=250_000, cells=2_000_000,
                 git_output=32 * 1024 * 1024, git_objects=250_000):
        self.deadline = time.monotonic() + deadline_seconds
        self.limits = {"files": files, "pathBytes": path_bytes, "contentBytes": content_bytes,
                       "rows": rows, "cells": cells, "gitOutput": git_output,
                       "gitObjects": git_objects}
        self.used = {key: 0 for key in self.limits}

    def check_time(self):
        if time.monotonic() >= self.deadline:
            raise StoreError("Storage inspection exceeded its time budget")

    def sqlite_progress(self):
        return int(time.monotonic() >= self.deadline)

    def add(self, key, amount):
        self.check_time()
        if type(amount) is not int or amount < 0 or key not in self.limits:
            raise StoreError("Storage inspection budget input is invalid")
        total = self.used[key] + amount
        if total > self.limits[key]:
            raise StoreError("Storage inspection exceeded its bounded inventory")
        self.used[key] = total


def _stable_tree(path, *, max_files=200_000, max_total=2**63 - 1, budget=None):
    """Count a stable tree in a fresh process, isolated from live SQLite locks."""
    result = _stable_tree_worker(path, max_files=max_files, max_total=max_total, budget=budget)
    return result["total"], result["basis"], result["files"]


def _native_content(store, *, budget=None):
    """Measure persisted content cells across all retained authority tables."""
    if store.dialect.driver != "sqlite":
        raise StoreError("Brain retained-content accounting currently requires SQLite authority")
    total = 0
    basis = []
    for table, columns in SNAPSHOT_COLUMNS.items():
        actual = {row[1] for row in store.dialect.execute(f"PRAGMA table_info({table})").fetchall()}
        if set(columns) - actual:
            raise StoreError("Native authority schema is unavailable for storage accounting")
        # Count every stored content cell (including metadata and keys), but not
        # SQLite indexes/pages/WAL. Stream rows in stable key order. The basis
        # hashes their content too, so same-sized substitutions invalidate it.
        order = ",".join(columns)
        cursor = store.dialect.execute(f"SELECT {','.join(columns)} FROM {table} ORDER BY {order}")
        table_bytes = 0
        digest = hashlib.sha256()
        rows = 0
        for row in cursor:
            if budget is not None:
                budget.add("rows", 1)
                budget.add("cells", len(row))
            rows += 1
            for value in row:
                if value is None:
                    raw = b""
                elif isinstance(value, bytes):
                    raw = value
                else:
                    raw = str(value).encode("utf-8")
                table_bytes += len(raw)
                if budget is not None:
                    budget.add("contentBytes", len(raw))
                digest.update(len(raw).to_bytes(8, "big"))
                digest.update(raw)
        total += table_bytes
        basis.append((table, rows, table_bytes, digest.hexdigest()))
    return total, fingerprint(basis)


def _db_blob_retained_bytes(key, content):
    """The exact persisted db-blob content cells, shared by inventory and writers."""
    return len(key.encode("utf-8")) + len(content)


def _db_blobs(store, *, budget=None):
    try:
        rows = store.dialect.execute("SELECT blob_key,content FROM blob_objects ORDER BY blob_key")
    except Exception as exc:
        raise StoreError("Declared db-blob inventory is unavailable") from exc
    total = 0
    basis = []
    count = 0
    for key, content in rows:
        if budget is not None:
            budget.add("rows", 1)
            budget.add("cells", 2)
        raw = bytes(content)
        count += 1
        retained_bytes = _db_blob_retained_bytes(key, raw)
        total += retained_bytes
        if budget is not None:
            budget.add("contentBytes", retained_bytes)
        basis.append((key, len(raw), hashlib.sha256(raw).hexdigest()))
    return total, fingerprint(basis), count


_INVENTORY_GIT_SUPERVISOR = """\
import math, os, select, signal, subprocess, sys, time
status_fd, lifetime_fd = int(sys.argv[1]), int(sys.argv[2])
deadline = float(sys.argv[3])
executable, arguments = sys.argv[4], sys.argv[5:]
group = os.getpid()
if (os.getpgrp() != group or os.getsid(0) != group or not math.isfinite(deadline)):
    raise SystemExit(125)
os.set_blocking(lifetime_fd, False)
os.set_inheritable(lifetime_fd, False)
os.set_inheritable(status_fd, False)

def stop_own_group():
    # This live session leader pins its own group ID. Never target a saved
    # parent PID or infer another process group's ownership from a listing.
    os.killpg(group, signal.SIGKILL)
    os._exit(125)

def watch_owner(timeout):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        stop_own_group()
    try:
        readable, _, _ = select.select([lifetime_fd], [], [], min(timeout, remaining))
    except InterruptedError:
        return
    if readable:
        # The parent holds the sole write end and never writes. EOF, unexpected
        # bytes or a failed read cannot authorize continued work.
        try:
            os.read(lifetime_fd, 1)
        finally:
            stop_own_group()

watch_owner(0)
try:
    process = subprocess.Popen([executable, *arguments], stdin=None,
                               stdout=1, stderr=subprocess.DEVNULL,
                               env=os.environ.copy(), close_fds=True)
except BaseException:
    status = b"E\\n"
else:
    while True:
        watch_owner(0)
        result = process.poll()
        if result is not None:
            break
        watch_owner(.01)
    watch_owner(0)
    status = ("R" + str(result) + "\\n").encode("ascii")
try:
    view = memoryview(status)
    while view:
        written = os.write(status_fd, view)
        view = view[written:]
except OSError:
    pass
try:
    os.close(status_fd)
except OSError:
    pass
for descriptor in (1, 2):
    try:
        os.close(descriptor)
    except OSError:
        pass
while True:
    # Preserve the live leader until ordinary owner cleanup, but never forever
    # after owner death or the already-selected absolute budget deadline.
    watch_owner(.05)
"""


def _close_inventory_resources(child, selector, status_read, status_write, *, group_cleanup_attempted,
                               lifetime_read=None, lifetime_write=None):
    """Always attempt group cleanup and close every post-spawn descriptor."""
    first_error = None

    def attempt(action):
        nonlocal first_error
        try:
            action()
        except BaseException as exc:
            if first_error is None:
                first_error = exc

    if child is not None and not group_cleanup_attempted:
        attempt(lambda: _terminate_owned_inventory_group(child))
    if selector is not None:
        attempt(selector.close)
    if child is not None and child.stdin is not None:
        attempt(child.stdin.close)
    if child is not None and child.stdout is not None:
        attempt(child.stdout.close)
    for descriptor in (status_read, status_write, lifetime_read, lifetime_write):
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if first_error is not None:
        raise first_error


def _bounded_git_output(command, budget, *, stdin_bytes=None, git_index_file=None):
    """Run one bounded Git command with an owned supervisor and optional bounded input."""
    budget.check_time()
    remaining = min(budget.limits["gitOutput"] - budget.used["gitOutput"], 8 * 1024 * 1024)
    if remaining < 0:
        raise StoreError("Storage inspection Git output exceeded its bound")
    if (not sys.platform.startswith(("darwin", "linux")) or not callable(getattr(os, "waitid", None))
            or any(not hasattr(os, name) for name in ("P_PID", "WEXITED", "WNOHANG", "WNOWAIT"))):
        raise StoreError("Safe storage inventory process cleanup is unavailable")
    if not command or not all(isinstance(item, str) for item in command):
        raise StoreError("Managed App bundle history cannot be inventoried")
    if stdin_bytes is not None and (
        not isinstance(stdin_bytes, bytes) or len(stdin_bytes) > 64 * 1024 * 1024
    ):
        raise StoreError("Managed Git input is malformed")
    if git_index_file is not None and (
        not isinstance(git_index_file, str) or not os.path.isabs(git_index_file)
        or "\x00" in git_index_file
    ):
        raise StoreError("Managed Git index path is malformed")
    status_read = status_write = None
    lifetime_read = lifetime_write = None
    child = selector = None
    group_cleanup_attempted = False
    output = bytearray()
    try:
        environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                            "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1",
                            "GIT_TERMINAL_PROMPT": "0"})
        if git_index_file is not None:
            environment["GIT_INDEX_FILE"] = git_index_file
        status_read, status_write = os.pipe()
        lifetime_read, lifetime_write = os.pipe()
        child = subprocess.Popen(
            [sys.executable, "-I", "-S", "-c", _INVENTORY_GIT_SUPERVISOR,
             str(status_write), str(lifetime_read), repr(budget.deadline), command[0], *command[1:]],
            stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True, pass_fds=(status_write, lifetime_read), env=environment)
        os.close(status_write)
        status_write = None
        os.close(lifetime_read)
        lifetime_read = None
        if child.stdout is None:
            raise StoreError("Storage inventory supervisor pipes were not created")
        os.set_blocking(child.stdout.fileno(), False)
        os.set_blocking(status_read, False)
        input_fd = None
        if stdin_bytes is not None:
            if child.stdin is None:
                raise StoreError("Storage inventory supervisor input was not created")
            input_fd = child.stdin.fileno()
            os.set_blocking(input_fd, False)
        selector = selectors.DefaultSelector()
        selector.register(child.stdout, selectors.EVENT_READ)
        selector.register(status_read, selectors.EVENT_READ)
        input_offset = 0
        if input_fd is not None:
            if stdin_bytes:
                selector.register(child.stdin, selectors.EVENT_WRITE)
            else:
                child.stdin.close()
                child.stdin = None
        status = bytearray()
        while selector.get_map():
            budget.check_time()
            if time.monotonic() >= budget.deadline:
                raise StoreError("Storage inspection exceeded its time budget")
            events = selector.select(min(.05, max(0.0, budget.deadline - time.monotonic())))
            if not events:
                _observe_inventory_leader(child)
            for key, _ in events:
                if child.stdin is not None and key.fileobj is child.stdin:
                    remaining_input = memoryview(stdin_bytes)[input_offset:]
                    try:
                        written = os.write(key.fd, remaining_input[:64 * 1024])
                    except BlockingIOError:
                        continue
                    except OSError as exc:
                        raise StoreError("Managed Git command stopped reading its bounded input") from exc
                    if written <= 0:
                        raise StoreError("Managed Git command stopped reading its bounded input")
                    input_offset += written
                    if input_offset == len(stdin_bytes):
                        selector.unregister(child.stdin)
                        child.stdin.close()
                        child.stdin = None
                    continue
                target = output if key.fileobj is child.stdout else status
                cap = remaining if key.fileobj is child.stdout else 32
                try:
                    chunk = os.read(key.fd, min(64 * 1024, cap - len(target) + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(target) + len(chunk) > cap:
                    raise StoreError("Storage inspection Git output exceeded its bound")
                target.extend(chunk)
        if len(status) > 32 or not status.endswith(b"\n"):
            raise StoreError("Storage inventory supervisor returned no bounded exit status")
        try:
            status_text = status.decode("ascii").strip()
            if not status_text.startswith("R"):
                raise ValueError("missing status")
            return_code = int(status_text[1:])
        except (UnicodeDecodeError, ValueError):
            raise StoreError("Storage inventory Git command failed") from None
        group_cleanup_attempted = True
        _terminate_owned_inventory_group(child)
        if return_code != 0:
            raise StoreError("Managed App bundle history cannot be inventoried")
    finally:
        _close_inventory_resources(child, selector, status_read, status_write,
                                   group_cleanup_attempted=group_cleanup_attempted,
                                   lifetime_read=lifetime_read, lifetime_write=lifetime_write)
    budget.add("gitOutput", len(output))
    return bytes(output)


def _observe_inventory_leader(child):
    while True:
        try:
            observed = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            break
        except InterruptedError:
            continue
        except OSError as exc:
            raise StoreError("Cannot safely confirm storage inventory process ownership") from exc
    if observed is not None and observed.si_pid not in (0, child.pid):
        raise StoreError("Storage inventory process identity changed")
    return observed is not None and observed.si_pid == child.pid


_PROCESS_LISTING_FAILURE_REASONS = frozenset((
    "collector-spawn-error", "collector-no-stdout", "collector-setup-error",
    "collector-deadline", "collector-select-error", "collector-read-error",
    "collector-output-limit", "collector-wait-timeout", "collector-wait-error",
    "collector-nonzero-exit", "collector-cleanup-kill-error",
    "collector-cleanup-wait-timeout", "collector-cleanup-wait-error",
    "collector-os-error", "collector-subprocess-error", "collector-refused",
    "collector-error",
))


class _InventoryProcessListingError(StoreError):
    """Finite internal reason for a bounded process-list collector refusal."""
    def __init__(self, reason):
        self.reason = reason if reason in _PROCESS_LISTING_FAILURE_REASONS else "collector-error"
        super().__init__("Storage inventory process listing failed")


def _process_listing_failure_reason(exc):
    if isinstance(exc, _InventoryProcessListingError):
        return exc.reason
    if isinstance(exc, subprocess.TimeoutExpired):
        return "collector-wait-timeout"
    if isinstance(exc, OSError):
        return "collector-os-error"
    if isinstance(exc, subprocess.SubprocessError):
        return "collector-subprocess-error"
    if isinstance(exc, StoreError):
        return "collector-refused"
    return "collector-error"


def _inventory_process_listing_refusal(reason, child, leader_exited_before):
    """Record owned worker IDs and sampled state; this is not a final reap claim."""
    if reason not in _PROCESS_LISTING_FAILURE_REASONS:
        reason = "collector-error"
    before = "exited" if leader_exited_before else "running"
    return StoreError(
        "Storage inventory process-group inspection failed "
        f"[collector={reason}; worker_pid={child.pid}; worker_pgid={child.pid}; "
        f"waitid_before={before}; waitid_after=not-observed; "
        f"popen_returncode_field_set_at_diagnostic={'yes' if child.returncode is not None else 'no'}]"
    )


def _bounded_process_listing(owned_pgid):
    """Capture bounded metadata for the one owned group on qualified Darwin."""
    if type(owned_pgid) is not int or owned_pgid < 1:
        raise _InventoryProcessListingError("collector-refused")
    command = ["/bin/ps", "-axo", "pid=,pgid=,state="]
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    if sys.platform == "darwin":
        # One positive process-group selector asks Darwin for KERN_PROC_PGRP;
        # -x includes no-tty descendants without adding another selector.
        # COMMAND_MODE makes -g argument semantics independent of ambient mode.
        command = ["/bin/ps", "-x", "-g", str(owned_pgid), "-o", "pid=,pgid=,state="]
        environment["COMMAND_MODE"] = "unix2003"
    process = selector = None
    output = bytearray()
    deadline = time.monotonic() + PROCESS_GROUP_SCAN_SECONDS
    try:
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env=environment, close_fds=True)
        except (OSError, subprocess.SubprocessError, ValueError):
            raise _InventoryProcessListingError("collector-spawn-error") from None
        if process.stdout is None:
            raise _InventoryProcessListingError("collector-no-stdout")
        try:
            os.set_blocking(process.stdout.fileno(), False)
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
        except (OSError, ValueError):
            raise _InventoryProcessListingError("collector-setup-error") from None
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _InventoryProcessListingError("collector-deadline")
            try:
                ready = selector.select(remaining)
            except (OSError, ValueError):
                raise _InventoryProcessListingError("collector-select-error") from None
            for key, _ in ready:
                try:
                    chunk = os.read(key.fd, min(64 * 1024,
                                                MAX_PROCESS_GROUP_SCAN_BYTES + 1 - len(output)))
                except (OSError, ValueError):
                    raise _InventoryProcessListingError("collector-read-error") from None
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output.extend(chunk)
                if len(output) > MAX_PROCESS_GROUP_SCAN_BYTES:
                    raise _InventoryProcessListingError("collector-output-limit")
        try:
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise _InventoryProcessListingError("collector-wait-timeout") from None
        except (OSError, subprocess.SubprocessError):
            raise _InventoryProcessListingError("collector-wait-error") from None
        if process.returncode != 0:
            raise _InventoryProcessListingError("collector-nonzero-exit")
        return bytes(output)
    except BaseException:
        if process is not None:
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                except OSError:
                    raise _InventoryProcessListingError("collector-cleanup-kill-error") from None
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                raise _InventoryProcessListingError("collector-cleanup-wait-timeout") from None
            except (OSError, subprocess.SubprocessError):
                raise _InventoryProcessListingError("collector-cleanup-wait-error") from None
        raise
    finally:
        if selector is not None:
            selector.close()
        if process is not None and process.stdout is not None:
            process.stdout.close()


def _inventory_group_live_members(child):
    """Return live members of the owned group without reaping its leader."""
    if type(getattr(child, "pid", None)) is not int or child.pid < 1:
        raise StoreError("Storage inventory process identity changed")
    before = _observe_inventory_leader(child)
    try:
        listing = _bounded_process_listing(child.pid)
    except (OSError, subprocess.SubprocessError, StoreError) as exc:
        # Capture only a finite collector category and the already-observed
        # worker custody facts. Do not emit process rows or OS error strings.
        raise _inventory_process_listing_refusal(
            _process_listing_failure_reason(exc), child, before) from None
    try:
        rows = []
        for line in listing.decode("ascii", "strict").splitlines():
            fields = line.split()
            if (len(fields) != 3 or not fields[0].isdigit() or not fields[1].isdigit()
                    or not fields[2] or not fields[2].isascii()):
                raise ValueError("malformed process listing")
            pid, pgid = int(fields[0]), int(fields[1])
            # Some kernels expose unrelated idle/system processes with PGID 0.
            # A real owned supervisor group has a strictly positive PID, so
            # retain zero-valued unrelated rows without matching them.
            if pid < 1 or pgid < 0:
                raise ValueError("invalid process identity")
            if pgid == child.pid:
                rows.append((pid, fields[2]))
    except (UnicodeDecodeError, ValueError):
        raise StoreError("Storage inventory process-group inspection failed") from None
    after = _observe_inventory_leader(child)
    if before and not after:
        raise StoreError("Storage inventory process identity changed")
    if not after and not any(pid == child.pid for pid, _state in rows):
        raise StoreError("Storage inventory process-group inspection failed")
    live_members = tuple((pid, state) for pid, state in rows if not state.startswith("Z"))
    return after, live_members


def _terminate_owned_inventory_group(child):
    """Kill/reap the live supervisor group while WNOWAIT keeps its ID owned."""
    required = ("P_PID", "WEXITED", "WNOHANG", "WNOWAIT")
    if (not sys.platform.startswith(("darwin", "linux")) or not callable(getattr(os, "waitid", None))
            or any(not hasattr(os, name) for name in required)):
        raise StoreError("Safe storage inventory process cleanup is unavailable")
    # WNOWAIT preserves the child PID as an owned group ID. Never signal after a
    # poll/wait or when another reaper has made ownership uncertain. On normal
    # completion, inspect the group first: Darwin returns EPERM when a group
    # contains no live signalable members, even though its WNOWAIT zombie leader
    # still pins the process-group ID.
    leader_exited = _observe_inventory_leader(child)
    inspection_error = None
    live_members = None
    if leader_exited:
        try:
            inspected_leader_exited, live_members = _inventory_group_live_members(child)
            if not inspected_leader_exited:
                raise StoreError("Storage inventory process identity changed")
        except StoreError as exc:
            inspection_error = exc
    if leader_exited and live_members == ():
        try:
            child.wait(timeout=2.0)
        except subprocess.TimeoutExpired as exc:
            raise StoreError("Storage inventory process cleanup exceeded its deadline") from exc
        if inspection_error is not None:
            raise StoreError("Storage inventory process-group cleanup failed") from inspection_error
        return child.returncode
    kill_error = None
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as exc:
        kill_error = exc
    if kill_error is not None and not leader_exited:
        try:
            # Keep the Popen PID waitable while targeting it; Popen.kill() may
            # poll/reap an already-exited leader before issuing its signal.
            os.kill(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            pass
    group_absent = False
    group_deadline = time.monotonic() + 2.0
    while time.monotonic() < group_deadline:
        try:
            leader_still_owned, live_members = _inventory_group_live_members(child)
        except StoreError as exc:
            if inspection_error is None:
                inspection_error = exc
            break
        if leader_still_owned and not live_members:
            group_absent = True
            break
        time.sleep(min(.025, max(0.0, group_deadline - time.monotonic())))
    try:
        child.wait(timeout=2.0)
    except subprocess.TimeoutExpired as exc:
        try:
            # Popen.kill() polls first and can reap the leader before signaling
            # its numeric PID. Keep WNOWAIT ownership explicit here too.
            # A False waitid(WNOHANG|WNOWAIT) result means the owned child is
            # still running; a successful waitid call keeps its PID waitable.
            _observe_inventory_leader(child)
            os.kill(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            pass
        try:
            child.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            raise StoreError("Storage inventory process cleanup exceeded its deadline") from exc
        raise StoreError("Storage inventory process cleanup exceeded its deadline") from exc
    # EPERM alone is ambiguous on Darwin: it can mean a zombie-only group.
    # Suppress it only when the bounded post-signal scan proves the owned group
    # has no live members while WNOWAIT still pins the leader. Other errors, or
    # any incomplete/failed scan, remain a cleanup refusal.
    verified_zombie_only_eperm = (
        isinstance(kill_error, PermissionError) and kill_error.errno == errno.EPERM and group_absent
    )
    if kill_error is not None and not verified_zombie_only_eperm:
        raise StoreError("Storage inventory process-group cleanup failed") from kill_error
    if inspection_error is not None:
        raise StoreError("Storage inventory process-group cleanup failed") from inspection_error
    if not group_absent:
        raise StoreError("Storage inventory process-group cleanup failed")
    return child.returncode


def _stable_tree_worker(path, *, max_files, max_total, budget=None, _worker_path=None, only_files=None,
                        header_only=False, private_exclusions=None):
    """Run the descriptor-relative tree walk outside every live SQLite PID."""
    if (type(max_files) is not int or max_files < 1 or type(max_total) is not int or max_total < 0
            or (budget is not None and not isinstance(budget, InventoryBudget))
            or type(header_only) is not bool
            or header_only and only_files is None
            or only_files is not None and (not isinstance(only_files, list) or not 1 <= len(only_files) <= 64
                or any(not isinstance(name, str) or not name or name in (".", "..")
                       or len(os.fsencode(name)) > 255 or "/" in name or "\\" in name or "\x00" in name
                       for name in only_files)
                or len(set(only_files)) != len(only_files))
            or private_exclusions is not None and (only_files is not None or header_only
                or not isinstance(private_exclusions, list) or len(private_exclusions) > 128
                or any(not isinstance(name, str) or not name or name.startswith("/") or "\\" in name
                       or "\x00" in name or len(os.fsencode(name)) > 4096
                       or any(part in ("", ".", "..") for part in name.split("/"))
                       for name in private_exclusions))):
        raise StoreError("Registered storage inventory bounds are invalid")
    required = ("P_PID", "WEXITED", "WNOHANG", "WNOWAIT")
    if (not sys.platform.startswith(("darwin", "linux")) or not callable(getattr(os, "waitid", None))
            or any(not hasattr(os, name) for name in required)):
        raise StoreError("Safe storage inventory process cleanup is unavailable")
    worker_path = Path(_worker_path) if _worker_path is not None else Path(__file__).with_name(
        "brain_storage_tree_worker.py")
    try:
        worker_info = worker_path.lstat()
        if (not stat.S_ISREG(worker_info.st_mode)
                or worker_info.st_size > 1024 * 1024
                or worker_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)):
            raise StoreError("Safe registered storage inventory worker is unavailable")
        tree_path = os.fspath(Path(path))
        request_budget = {
            "files": max_files if budget is None else budget.limits["files"] - budget.used["files"],
            "pathBytes": 2**63 - 1 if budget is None else budget.limits["pathBytes"] - budget.used["pathBytes"],
            "contentBytes": max_total if budget is None else min(
                max_total, budget.limits["contentBytes"] - budget.used["contentBytes"]),
        }
        deadline = (time.monotonic() + UNBUDGETED_TREE_WATCHDOG_SECONDS
                    if budget is None else budget.deadline)
        remaining = deadline - time.monotonic()
        if remaining <= 0 or any(value < 0 for value in request_budget.values()):
            raise StoreError("Storage inspection exceeded its bounded inventory")
        request_value = {"path": tree_path, "maxFiles": max_files, "maxTotal": max_total,
                         "limits": request_budget, "deadline": deadline}
        if only_files is not None:
            request_value["onlyFiles"] = only_files
        if header_only:
            request_value["headerOnly"] = True
        if private_exclusions is not None:
            request_value["privateExclusions"] = private_exclusions
        request = json.dumps(request_value,
            ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
        if len(request) > 16 * 1024:
            raise StoreError("Storage inventory request exceeded its bound")
    except (OSError, TypeError, ValueError) as exc:
        if isinstance(exc, StoreError):
            raise
        raise StoreError("Registered storage inventory bounds are invalid") from None

    command = [sys.executable, "-I", "-S", str(worker_path), "--worker-v1"]
    environment = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"}
    child = selector = None
    lifetime_read = lifetime_write = None
    group_cleanup_attempted = False
    output = bytearray()
    request_offset = 0
    try:
        if budget is not None:
            budget.check_time()
        # The canonical worker owns an internal monitor before request parsing.
        # Private fault-injection overrides retain their historical argv and
        # living-parent watchdog; they do not establish owner-death closure.
        worker_pass_fds = ()
        if _worker_path is None:
            lifetime_read, lifetime_write = os.pipe()
            command[-1:-1] = ["--owner-fd", str(lifetime_read), "--deadline", repr(deadline)]
            worker_pass_fds = (lifetime_read,)
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, start_new_session=True,
                                 close_fds=True, env=environment, pass_fds=worker_pass_fds)
        if lifetime_read is not None:
            os.close(lifetime_read)
            lifetime_read = None
        if child.stdin is None or child.stdout is None:
            raise StoreError("Storage inventory worker pipes were not created")
        os.set_blocking(child.stdin.fileno(), False)
        os.set_blocking(child.stdout.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(child.stdin, selectors.EVENT_WRITE, "input")
        selector.register(child.stdout, selectors.EVENT_READ, "output")
        parent_deadline = deadline
        output_eof = False
        child_exited = False
        while not (output_eof and child_exited):
            if time.monotonic() >= parent_deadline:
                raise StoreError("Storage inspection exceeded its time budget")
            if budget is not None:
                budget.check_time()
            for key, _ in selector.select(min(.05, max(0.0, parent_deadline - time.monotonic()))):
                if key.data == "input":
                    try:
                        written = os.write(key.fd, request[request_offset:request_offset + 8192])
                    except BlockingIOError:
                        continue
                    if written <= 0:
                        raise StoreError("Storage inventory worker request could not be sent")
                    request_offset += written
                    if request_offset >= len(request):
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                else:
                    try:
                        chunk = os.read(key.fd, min(4096, 4097 - len(output)))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        output_eof = True
                        continue
                    if len(output) + len(chunk) > 4096:
                        raise StoreError("Storage inventory worker output exceeded its bound")
                    output.extend(chunk)
            child_exited = _observe_inventory_leader(child)
        # The worker is expected to have no descendants. Still kill any process
        # left in its owned group while WNOWAIT keeps the group ID pinned.
        group_cleanup_attempted = True
        return_code = _terminate_owned_inventory_group(child)
        if return_code not in (0, 2):
            raise StoreError("Registered storage inventory failed safely")
    except OSError:
        if budget is not None and child is not None:
            # The worker may have traversed part of the tree before an I/O
            # failure; its counters are no longer trustworthy.
            budget.deadline = min(budget.deadline, time.monotonic())
        raise StoreError("Registered storage inventory worker is unavailable") from None
    except BaseException:
        if budget is not None and child is not None:
            # A killed or malformed worker may have consumed filesystem budget
            # that it could not report. Refuse any reuse of this inventory budget.
            budget.deadline = min(budget.deadline, time.monotonic())
        raise
    finally:
        _close_inventory_resources(child, selector, None, None,
                                   group_cleanup_attempted=group_cleanup_attempted,
                                   lifetime_read=lifetime_read, lifetime_write=lifetime_write)

    try:
        if not output.endswith(b"\n") or output.count(b"\n") != 1:
            raise ValueError("bad framing")
        result = json.loads(output[:-1].decode("ascii"))
        if (not isinstance(result, dict) or type(result.get("workerPid")) is not int
                or result["workerPid"] != child.pid):
            raise ValueError("invalid worker identity")
        used = result.get("used")
        if (not isinstance(used, dict) or set(used) != {"files", "pathBytes", "contentBytes"}
                or any(type(value) is not int or value < 0 for value in used.values())
                or any(used[key] > request_budget[key] for key in used)):
            raise ValueError("invalid worker usage")
        if result.get("ok") is not True:
            if return_code != 2:
                raise ValueError("worker error status mismatch")
            if set(result) != {"ok", "error", "used", "workerPid"}:
                raise ValueError("invalid worker error result")
            if budget is not None:
                for key, value in used.items():
                    budget.add(key, value)
            error = result.get("error")
            known_errors = {
                "A registered storage root is unavailable or unsafe",
                "A registered storage root changed while measuring",
                "A registered storage root changed while opening",
                "A registered storage directory is unsafe",
                "A registered storage directory changed while measuring",
                "A registered storage directory changed while opening",
                "A registered storage entry changed while measuring",
                "A registered storage file is unsafe",
                "A registered storage file changed while opening",
                "A registered storage file changed while measuring",
                "A registered storage file is unavailable",
                "A registered storage path is unsafe",
                "A registered storage path exceeds its bound",
                "Registered storage inventory exceeds its bound",
                "Registered storage inventory bounds are invalid",
                "Native sidecar contains standalone authority content",
                "Unregistered private retained content requires an explicit retained root",
                "Studio App host registration is invalid",
                "Safe registered storage inventory is unavailable on this platform",
                "Storage inspection exceeded its time budget",
                "Storage inspection exceeded its bounded inventory",
            }
            if error not in known_errors:
                raise StoreError("Registered storage inventory failed safely")
            raise StoreError(error)
        if (set(result) != {"ok", "total", "basis", "files", "used", "workerPid"}
                or return_code != 0
                or type(result["total"]) is not int or result["total"] < 0
                or result["total"] > max_total
                or type(result["files"]) is not int or result["files"] < 0
                or result["files"] > max_files
                or result["files"] > used["files"]
                or not isinstance(result["basis"], str) or not _SHA.fullmatch(result["basis"])
                or not isinstance(result["used"], dict)
                or set(result["used"]) != {"files", "pathBytes", "contentBytes"}
                or any(type(value) is not int or value < 0 for value in result["used"].values())
                or result["used"]["contentBytes"] != result["total"]):
            raise ValueError("invalid worker response")
        if budget is not None:
            for key, value in used.items():
                budget.add(key, value)
    except StoreError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        if budget is not None:
            budget.deadline = min(budget.deadline, time.monotonic())
        raise StoreError("Registered storage inventory worker returned an invalid result") from None
    return result


def _git_app_history(root, *, budget=None):
    root = Path(root)
    if budget is None:
        try:
            commits = subprocess.run(["git", "-C", str(root), "rev-list", "--all"],
                                     check=True, capture_output=True, timeout=30).stdout.splitlines()
            objects = set()
            for commit in commits:
                listing = subprocess.run(["git", "-C", str(root), "ls-tree", "-r", "-z", commit.decode(), "--", "apps"],
                                         check=True, capture_output=True, timeout=30).stdout
                for item in listing.split(b"\0"):
                    if not item:
                        continue
                    metadata, _path = item.split(b"\t", 1)
                    mode, kind, object_id = metadata.split(b" ", 2)
                    if kind == b"blob" and mode != b"120000":
                        objects.add(object_id.decode("ascii"))
            sizes = []
            for object_id in sorted(objects):
                size = subprocess.run(["git", "-C", str(root), "cat-file", "-s", object_id],
                                      check=True, capture_output=True, timeout=30).stdout.strip()
                sizes.append((object_id, int(size)))
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            raise StoreError("Managed App bundle history cannot be inventoried") from exc
        return sum(size for _, size in sizes), fingerprint(sizes), len(sizes)
    try:
        object_format, objects_path = _git_primary_object_store(root, budget)
        command = ["git", "-C", str(root), "cat-file", "--batch-all-objects",
                   "--batch-check=%(objectname) %(objecttype) %(objectsize)"]
        listing = _bounded_git_output(command, budget)
        # Bound row materialization before splitlines: loose/packed duplicates
        # are deduplicated below, but cannot make parsing unbounded.
        row_count = listing.count(b"\n") + int(bool(listing) and not listing.endswith(b"\n"))
        remaining_objects = budget.limits["gitObjects"] - budget.used["gitObjects"]
        if row_count > min(500_000, max(1, remaining_objects) * 2):
            raise StoreError("Storage inspection Git object inventory exceeded its bound")
        objects = {}
        for row in listing.splitlines():
            fields = row.split(b" ")
            if len(fields) != 3:
                raise StoreError("Primary Git object inventory is incomplete")
            raw_oid, raw_type, raw_size = fields
            if (len(raw_oid) != (40 if object_format == "sha1" else 64)
                    or not re.fullmatch(rb"[0-9a-f]+", raw_oid)
                    or raw_type not in (b"blob", b"commit", b"tag", b"tree")
                    or not re.fullmatch(rb"(?:0|[1-9][0-9]{0,19})", raw_size)):
                raise StoreError("Primary Git object inventory is malformed")
            object_id = raw_oid.decode("ascii")
            object_type = raw_type.decode("ascii")
            object_size = int(raw_size)
            if object_size > 2**63 - 1:
                raise StoreError("Primary Git object size exceeds its bound")
            previous = objects.get(object_id)
            if previous is not None and previous != (object_type, object_size):
                raise StoreError("Primary Git object inventory contains conflicting duplicates")
            objects[object_id] = (object_type, object_size)
            if len(objects) > remaining_objects:
                raise StoreError("Storage inspection Git object inventory exceeded its bound")
        blob_sizes = [(object_id, object_size) for object_id, (kind, object_size) in objects.items()
                      if kind == "blob"]
        blob_bytes = sum(size for _, size in blob_sizes)
        if blob_bytes > budget.limits["contentBytes"] - budget.used["contentBytes"]:
            raise StoreError("Storage inspection exceeded its bounded inventory")
        # A second bounded enumeration detects additions, removals and type/size
        # changes while the host inventory is being assembled.
        if _bounded_git_output(command, budget) != listing:
            raise StoreError("Primary Git object database changed during inventory")
        after_format, after_objects_path = _git_primary_object_store(root, budget)
        if (after_format, after_objects_path) != (object_format, objects_path):
            raise StoreError("Primary Git object store changed during inventory")
        budget.add("gitObjects", len(objects))
        budget.add("contentBytes", blob_bytes)
        sizes = sorted(blob_sizes)
    except (OSError, subprocess.SubprocessError, ValueError, StoreError) as exc:
        if isinstance(exc, StoreError):
            raise
        raise StoreError("Managed App bundle history cannot be inventoried") from exc
    return sum(size for _, size in sizes), fingerprint({"objectFormat": object_format,
                                                         "blobs": sizes}), len(sizes)


def _git_primary_object_store(root, budget):
    """Reject Git stores whose object inventory could be incomplete or external."""
    prefix = ["git", "-C", str(root), "rev-parse", "--path-format=absolute", "--git-path"]
    try:
        objects_path = Path(_bounded_git_output([*prefix, "objects"], budget).decode("utf-8").strip())
        common_dir = Path(_bounded_git_output(["git", "-C", str(root), "rev-parse",
                                              "--path-format=absolute", "--git-common-dir"], budget)
                         .decode("utf-8").strip())
        object_format = _bounded_git_output(["git", "-C", str(root), "rev-parse",
                                             "--show-object-format=storage"], budget).decode("ascii").strip()
    except (UnicodeDecodeError, OSError, subprocess.SubprocessError) as exc:
        raise StoreError("Primary Git object store cannot be identified") from exc
    if (not objects_path.is_absolute() or not common_dir.is_absolute()
            or object_format not in ("sha1", "sha256")):
        raise StoreError("Primary Git object store identity is invalid")
    # Git worktrees can have a separate git-dir and a shared common-dir. The
    # object path is still accepted only when it resolves beneath that common
    # directory; alternates are rejected below.
    try:
        named_objects_fd = _open_directory_chain(objects_path)
        named_common_fd = _open_directory_chain(common_dir)
        objects_resolved = objects_path.resolve(strict=True)
        common_resolved = common_dir.resolve(strict=True)
        objects_resolved.relative_to(common_resolved)
        if (objects_path.absolute() != objects_resolved or common_dir.absolute() != common_resolved):
            raise StoreError("Primary Git object store path contains a symlink")
        objects_fd = named_objects_fd
        named_objects_fd = None
        opened_objects = os.fstat(objects_fd)
        named_objects = os.stat(objects_resolved, follow_symlinks=False)
        if ((opened_objects.st_dev, opened_objects.st_ino) !=
                (named_objects.st_dev, named_objects.st_ino)):
            raise StoreError("Primary Git object store changed while opening")
        object_store_identity = (str(objects_resolved), opened_objects.st_dev, opened_objects.st_ino)
    except (OSError, ValueError, StoreError) as exc:
        raise StoreError("Primary Git object store path is unsafe or unavailable") from exc
    finally:
        for descriptor in (locals().get("named_objects_fd"), locals().get("named_common_fd")):
            if descriptor is not None:
                os.close(descriptor)
    try:
        info_fd = None
        try:
            info_fd = os.open("info", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=objects_fd)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise StoreError("Primary Git object store metadata is unsafe") from exc
        if info_fd is not None:
            try:
                alternate = _read_git_object_marker(info_fd, "alternates", maximum=64 * 1024)
                if alternate and alternate.strip():
                    raise StoreError("Git object alternates are unavailable for storage inspection")
            finally:
                os.close(info_fd)
        pack_fd = None
        try:
            pack_fd = os.open("pack", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=objects_fd)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise StoreError("Primary Git pack directory is unsafe") from exc
        if pack_fd is not None:
            try:
                with os.scandir(pack_fd) as entries:
                    for index, entry in enumerate(entries, 1):
                        budget.check_time()
                        if index > budget.limits["gitObjects"]:
                            raise StoreError("Primary Git pack inventory exceeded its bound")
                        if entry.name.endswith(".promisor"):
                            raise StoreError("Promisor Git object stores are unavailable for storage inspection")
            finally:
                os.close(pack_fd)
    finally:
        os.close(objects_fd)
    config = _bounded_git_output(["git", "-C", str(root), "config", "--local", "--no-includes",
                                 "--null", "--list"], budget)
    entry_count = config.count(b"\0")
    if entry_count > 10_000:
        raise StoreError("Primary Git configuration inventory exceeded its bound")
    for entry in config.split(b"\0"):
        if not entry:
            continue
        key, separator, value = entry.partition(b"\n")
        if not separator:
            raise StoreError("Primary Git configuration inventory is malformed")
        normalized = key.lower()
        if normalized == b"extensions.partialclone" and value.strip():
            raise StoreError("Partial-clone Git object stores are unavailable for storage inspection")
        if (normalized.startswith(b"remote.") and normalized.endswith(b".promisor")
                and value.strip().lower() in (b"true", b"yes", b"on", b"1")):
            raise StoreError("Promisor Git object stores are unavailable for storage inspection")
    shallow = _bounded_git_output(["git", "-C", str(root), "rev-parse",
                                   "--is-shallow-repository"], budget).strip()
    if shallow != b"false":
        raise StoreError("Shallow Git object stores are unavailable for storage inspection")
    return object_format, object_store_identity


def _read_git_object_marker(directory_fd, name, *, maximum):
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return b""
    except OSError as exc:
        raise StoreError("Primary Git object metadata is unavailable") from exc
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
            or before.st_nlink != 1 or before.st_size > maximum):
        raise StoreError("Primary Git object metadata is unsafe or exceeds its bound")
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    except OSError as exc:
        raise StoreError("Primary Git object metadata changed or is unsafe") from exc
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise StoreError("Primary Git object metadata changed while opening")
        chunks = bytearray()
        while len(chunks) <= maximum:
            chunk = os.read(fd, min(8192, maximum + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (len(chunks) > maximum or (opened.st_dev, opened.st_ino, opened.st_size,
                opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns) or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)):
            raise StoreError("Primary Git object metadata changed while reading")
        return bytes(chunks)
    finally:
        os.close(fd)


def _private_residue_basis(root, store, registration, *, blob_root=None, budget=None):
    """Refuse unknown private content and validate host metadata in the owned worker.

    Standby residue must be explicitly retained before adoption. No native file
    body is opened in this SQLite-owning process, and no residue is deleted.
    """
    root = Path(root).resolve(strict=True)
    internal = root / "_internal"
    native = Path(store.path).resolve(strict=True)
    sessions = internal / "studio-app-sessions"
    managed = [native, sessions, root / "apps", root / ".git"]
    blob = Path(blob_root).resolve(strict=True) if blob_root is not None else None
    if blob is not None:
        if any(path == blob or path.is_relative_to(blob) or blob.is_relative_to(path) for path in managed):
            raise StoreError("Managed blob storage cannot overlap another active managed route")
        managed.append(blob)
    retained = [Path(item["path"]).resolve(strict=True) for item in registration["retainedRoots"]]
    for index, route in enumerate(retained):
        if any(path == route or path.is_relative_to(route) or route.is_relative_to(path) for path in managed):
            raise StoreError("Retained storage roots cannot overlap an active managed route")
        if any(route == other or route.is_relative_to(other) or other.is_relative_to(route)
               for other in retained[:index]):
            raise StoreError("Retained storage roots must not overlap")
    excluded = {root / name for name in (REGISTRATION, LEDGER, LEDGER_LOCK, WRITER_LOCK)}
    excluded.update(Path(str(root / LEDGER) + suffix) for suffix in ("-wal", "-shm", "-journal"))
    excluded.update(Path(str(native) + suffix) for suffix in ("", "-wal", "-shm", "-journal"))
    excluded.update([sessions, *retained])
    if blob is not None:
        excluded.add(blob)
    relative = sorted(path.relative_to(internal).as_posix() for path in excluded if path.is_relative_to(internal))
    if "." in relative:
        raise StoreError("The private state root cannot be an excluded managed tree")
    return _stable_tree_worker(internal, max_files=200_000, max_total=64 * 1024, budget=budget,
                               private_exclusions=relative)


def inventory(root, store, registration, *, session_root=None, blob_root=None, blob_location=None, budget=None):
    """Return one stable accounting basis; any unavailable managed class refuses."""
    _require_admission_platform()
    registration = (validate_registration(registration) if "adoption" in registration
                    else validate_selection(registration))
    if (store.contract.binding != registration["authority"]["binding"]
            or store.contract.authority != registration["authority"]["store"]):
        raise StoreError("Storage admission authority pin changed")
    _private_residue_basis(root, store, registration, blob_root=blob_root, budget=budget)
    native_bytes, native_basis = _native_content(store, budget=budget)
    classes = {"native": native_bytes}
    bases = {"native": native_basis}
    blob = registration["blob"]
    if store.contract.blob_store != blob["store"] or store.contract.cell["blobs"] != blob["driver"]:
        raise StoreError("Storage admission blob route changed")
    if blob["driver"] == "db-blob":
        location = str(Path(blob_location or store.path).resolve())
        if hashlib.sha256(os.fsencode(location)).hexdigest() != blob["locationSha256"]:
            raise StoreError("Storage admission db-blob route location changed")
        amount, basis, count = _db_blobs(store, budget=budget)
        classes["managedBlobs"] = amount
        bases["blobs"] = basis
    else:
        if blob_root is None:
            raise StoreError("Registered filesystem blob route is unavailable")
        location = str(Path(blob_root).resolve(strict=True))
        if hashlib.sha256(os.fsencode(location)).hexdigest() != blob["locationSha256"]:
            raise StoreError("Storage admission filesystem blob route changed")
        amount, basis, count = _stable_tree(blob_root, budget=budget)
        classes["managedBlobs"] = amount
        bases["blobs"] = basis
    app_history_bytes, app_history_basis, app_history_count = _git_app_history(root, budget=budget)
    app_work_bytes, app_work_basis, app_work_count = _stable_tree(Path(root) / "apps", budget=budget)
    classes["retainedAppBundleVersions"] = app_history_bytes
    classes["currentAppBundleWorktree"] = app_work_bytes
    bases["appBundles"] = fingerprint({"history": app_history_basis, "worktree": app_work_basis})
    classes["appBundleObjectCount"] = app_history_count
    classes["appBundleFileCount"] = app_work_count
    # Session files contain accepted uploads and durable effect intents. They
    # are part of the managed content basis even when the caller omits a path.
    session_root = Path(session_root) if session_root is not None else Path(root) / "_internal/studio-app-sessions"
    if session_root.resolve(strict=True) != (Path(root) / "_internal/studio-app-sessions").resolve(strict=True):
        raise StoreError("Storage admission session route is not the registered host route")
    session_bytes, session_basis, session_count = _stable_tree(session_root, budget=budget)
    classes["pendingUploadsAndSessions"] = session_bytes
    bases["sessions"] = session_basis
    classes["sessionFileCount"] = session_count
    for item in registration["retainedRoots"]:
        amount, basis, count = _stable_tree(item["path"], budget=budget)
        classes[item["kind"] + ":" + item["id"]] = amount
        bases[item["kind"] + ":" + item["id"]] = basis
        classes[item["kind"] + "FileCount:" + item["id"]] = count
    total = sum(value for key, value in classes.items()
                if not key.endswith("Count") and "FileCount:" not in key and "ObjectCount" not in key)
    return {"format": "brain-retained-content-inventory/v1", "accounting": ACCOUNTING,
            "limitBytes": registration["limitBytes"], "usedBytes": total, "classes": classes,
            "basisSha256": fingerprint({"registration": registration, "classes": classes, "bases": bases}),
            "classBasis": bases}


class AdmissionLedger:
    """Private durable reservation ledger; ambiguous writes remain charged."""
    def __init__(self, root, registration):
        _require_admission_platform()
        self.root = Path(root)
        self.registration = validate_registration(registration)
        self.path = self.root / LEDGER
        self.lock_path = self.root / LEDGER_LOCK
        self.writer_lock_path = self.root / WRITER_LOCK

    def _persistent_locks_required(self):
        """New adoptions never recreate a missing lock; legacy ledgers retain v1 behavior."""
        persistent, _pins, _protocol = self._lock_state()
        return persistent

    @staticmethod
    def _parse_lock_identity(value):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9]+:[0-9]+", value):
            raise StoreError("Storage admission lock identity is missing or malformed")
        device_text, inode_text = value.split(":", 1)
        device, inode = int(device_text), int(inode_text)
        if (device < 0 or inode <= 0 or device > 2**64 - 1 or inode > 2**64 - 1
                or str(device) != device_text or str(inode) != inode_text):
            raise StoreError("Storage admission lock identity is missing or malformed")
        return device, inode

    def _lock_state(self, *, deadline=None):
        """Read protocol and optional inode pins without migrating older ledgers."""
        try:
            info = self.path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid() or info.st_mode & 0o077
                    or (deadline is not None and info.st_size > MAX_LEDGER_FILE_BYTES)):
                raise StoreError("Storage admission ledger is unavailable or exceeds its inspection bound")
            db = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, timeout=1)
            try:
                db.execute("PRAGMA query_only=ON")
                db.execute("BEGIN")
                db.set_progress_handler(
                    (lambda: int(time.monotonic() >= deadline)) if deadline is not None else (lambda: 0),
                    1000)
                pin_shapes = db.execute("SELECT key,length(CAST(value AS BLOB)) FROM meta WHERE key IN "
                                        "('lockProtocol','writerLockIdentity','ledgerLockIdentity') LIMIT 4").fetchall()
                if len(pin_shapes) > 3 or any(type(size) is not int or size > 64 for _key, size in pin_shapes):
                    raise StoreError("Storage admission lock metadata is malformed")
                rows = dict(db.execute("SELECT key,value FROM meta WHERE key IN "
                                       "('lockProtocol','writerLockIdentity','ledgerLockIdentity')"))
                protocol = rows.get("lockProtocol")
                if protocol not in (None, LEGACY_PERSISTENT_LOCK_PROTOCOL, PERSISTENT_LOCK_PROTOCOL):
                    raise StoreError("Storage admission lock protocol is unsupported")
                persistent = protocol in (LEGACY_PERSISTENT_LOCK_PROTOCOL, PERSISTENT_LOCK_PROTOCOL)
                if protocol == PERSISTENT_LOCK_PROTOCOL:
                    pins = {"writer": self._parse_lock_identity(rows.get("writerLockIdentity")),
                            "ledger": self._parse_lock_identity(rows.get("ledgerLockIdentity"))}
                else:
                    pins = None
                return persistent, pins, protocol
            finally:
                if db.in_transaction:
                    db.rollback()
                db.close()
        except StoreError:
            raise
        except OSError as exc:
            raise StoreError("Storage inspection ledger is unavailable or unsafe") from exc
        except sqlite3.Error as exc:
            raise StoreError("Storage inspection ledger cannot verify its lock protocol") from exc

    @staticmethod
    def _create_lock_file(directory_fd, name):
        flags = (os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_CLOEXEC", 0))
        fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
        try:
            os.fchmod(fd, 0o600)
            info = os.fstat(fd)
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid() or info.st_mode & 0o077
                    or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
                raise StoreError("Storage admission lock file is unsafe")
            os.fsync(fd)
            return info.st_dev, info.st_ino
        finally:
            os.close(fd)

    @staticmethod
    def _remove_created_lock(directory_fd, name, identity):
        try:
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if ((current.st_dev, current.st_ino) == identity and stat.S_ISREG(current.st_mode)
                    and current.st_nlink == 1 and current.st_uid == os.geteuid()):
                os.unlink(name, dir_fd=directory_fd)
        except OSError:
            pass

    def initialize_after_explicit_adoption(self, *, expected_preview_sha256, preview_sha256,
                                           inventory_basis_sha256):
        if (not _SHA.fullmatch(expected_preview_sha256) or expected_preview_sha256 != preview_sha256
                or not _SHA.fullmatch(inventory_basis_sha256)):
            raise StoreError("Storage admission adoption preview changed")
        internal = self.root / "_internal"
        internal_fd = _open_directory_chain(internal)
        internal_info = os.fstat(internal_fd)
        try:
            named_internal = internal.lstat()
        except OSError as exc:
            os.close(internal_fd)
            raise StoreError("Storage admission state directory changed") from exc
        if ((internal_info.st_dev, internal_info.st_ino) != (named_internal.st_dev, named_internal.st_ino)
                or not stat.S_ISDIR(internal_info.st_mode) or internal_info.st_uid != os.geteuid()
                or internal_info.st_mode & 0o077):
            os.close(internal_fd)
            raise StoreError("Storage admission state directory is not owner-private")
        if self.path.exists() or self.path.is_symlink():
            os.close(internal_fd)
            raise StoreError("Storage admission ledger already exists")
        created_locks = []
        for name in (Path(WRITER_LOCK).name, Path(LEDGER_LOCK).name):
            try:
                created_locks.append((name, self._create_lock_file(internal_fd, name)))
            except BaseException:
                for created_name, created_identity in reversed(created_locks):
                    self._remove_created_lock(internal_fd, created_name, created_identity)
                os.close(internal_fd)
                raise
        ledger_identity = None
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
            ledger_info = os.fstat(fd)
            ledger_identity = (ledger_info.st_dev, ledger_info.st_ino)
            os.close(fd)
            db = sqlite3.connect(self.path)
            try:
                db.executescript("""
                    PRAGMA journal_mode=DELETE;
                    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    CREATE TABLE reservations (
                        id TEXT PRIMARY KEY, operation_key TEXT NOT NULL UNIQUE,
                        state TEXT NOT NULL CHECK(state IN ('reserved','outcome-unknown','settled')),
                        reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes >= 0),
                        base_used_bytes INTEGER NOT NULL CHECK(base_used_bytes >= 0),
                        measured_bytes INTEGER, basis_sha256 TEXT NOT NULL,
                        details TEXT NOT NULL, created_at TEXT NOT NULL
                    );
                """)
                db.executemany("INSERT INTO meta(key,value) VALUES(?,?)", [
                    ("format", "brain-storage-admission-ledger/v1"),
                    ("brainId", self.registration["brainId"]),
                    ("authorityBinding", self.registration["authority"]["binding"]),
                    ("adoptionPreviewSha256", preview_sha256),
                    ("adoptionInventoryBasisSha256", inventory_basis_sha256),
                    ("lockProtocol", PERSISTENT_LOCK_PROTOCOL),
                    ("writerLockIdentity", f"{created_locks[0][1][0]}:{created_locks[0][1][1]}"),
                    ("ledgerLockIdentity", f"{created_locks[1][1][0]}:{created_locks[1][1][1]}")])
                db.commit()
            finally:
                db.close()
            os.chmod(self.path, 0o600)
        except BaseException:
            try:
                current = self.path.lstat()
                if (ledger_identity is not None
                        and (current.st_dev, current.st_ino) == ledger_identity
                        and stat.S_ISREG(current.st_mode) and current.st_nlink == 1
                        and current.st_uid == os.geteuid()):
                    self.path.unlink()
            except FileNotFoundError:
                pass
            for created_name, created_identity in reversed(created_locks):
                self._remove_created_lock(internal_fd, created_name, created_identity)
            os.close(internal_fd)
            raise
        else:
            os.close(internal_fd)

    @staticmethod
    def _open_lock(path, *, create=False, expected_identity=None):
        parent_fd = _open_directory_chain(path.parent)
        fd = None
        try:
            parent = os.fstat(parent_fd)
            named_parent = path.parent.lstat()
            if ((parent.st_dev, parent.st_ino) != (named_parent.st_dev, named_parent.st_ino)
                    or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
                    or parent.st_mode & 0o077):
                raise StoreError("Storage admission lock directory is unsafe")
            name = path.name
            try:
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                if not create:
                    raise
                named = None
            if named is not None and (not stat.S_ISREG(named.st_mode) or named.st_nlink != 1
                    or named.st_uid != os.geteuid() or named.st_mode & 0o077):
                raise StoreError("Storage admission lock is unsafe")
            flags = (os.O_RDWR if create else os.O_RDONLY) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            if create:
                flags |= os.O_CREAT
            fd = os.open(name, flags, 0o600, dir_fd=parent_fd)
            opened = os.fstat(fd)
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if ((named is not None and (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino))
                    or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
                    or (expected_identity is not None
                        and (opened.st_dev, opened.st_ino) != expected_identity)
                    or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                    or opened.st_uid != os.geteuid() or opened.st_mode & 0o077):
                raise StoreError("Storage admission lock changed while opening")
            return fd, parent_fd, (opened.st_dev, opened.st_ino), (parent.st_dev, parent.st_ino)
        except FileNotFoundError as exc:
            if fd is not None:
                os.close(fd)
            os.close(parent_fd)
            raise StoreError("Storage inspection is unavailable for an adoption without persistent locks") from exc
        except OSError as exc:
            if fd is not None:
                os.close(fd)
            os.close(parent_fd)
            raise StoreError("Storage admission lock is unavailable or unsafe") from exc
        except BaseException:
            if fd is not None:
                os.close(fd)
            os.close(parent_fd)
            raise

    @contextmanager
    def readonly_snapshot(self, *, registration_sha256, timeout=10.0, budget=None):
        """Read a consistent ledger snapshot without creating files or opening a write transaction."""
        if (not _SHA.fullmatch(registration_sha256) or type(timeout) not in (int, float)
                or not 0 < timeout <= 10.0 or (budget is not None and not isinstance(budget, InventoryBudget))):
            raise StoreError("Storage inspection snapshot request is invalid")
        deadline = min(time.monotonic() + timeout, budget.deadline) if budget is not None else time.monotonic() + timeout
        _check_ledger_deadline(deadline, budget=budget)
        registration = load_registration(self.root)
        if registration is None or fingerprint(registration) != registration_sha256:
            raise StoreError("Storage inspection registration changed")
        if not self.path.exists() or self.path.is_symlink():
            raise StoreError("Storage inspection ledger is unavailable")
        ledger_before = self.path.lstat()
        if (not stat.S_ISREG(ledger_before.st_mode) or ledger_before.st_nlink != 1
                or ledger_before.st_uid != os.geteuid() or ledger_before.st_mode & 0o077
                or ledger_before.st_size > MAX_LEDGER_FILE_BYTES):
            raise StoreError("Storage inspection ledger is unsafe")
        _require_no_ledger_sidecars(self.path)
        persistent, lock_pins, lock_protocol = self._lock_state(deadline=deadline)
        if not persistent or lock_protocol != PERSISTENT_LOCK_PROTOCOL or lock_pins is None:
            raise StoreError("Storage inspection is unavailable without persistent locks and identities")
        writer_fd = ledger_fd = writer_parent_fd = ledger_parent_fd = None
        db = None
        locked = []
        try:
            # Every writer acquires these in the same order: writer fence, then ledger.
            writer_fd, writer_parent_fd, writer_identity, writer_parent_identity = self._open_lock(
                self.writer_lock_path, expected_identity=lock_pins["writer"])
            ledger_fd, ledger_parent_fd, lock_identity, ledger_parent_identity = self._open_lock(
                self.lock_path, expected_identity=lock_pins["ledger"])
            for fd in (writer_fd, ledger_fd):
                while True:
                    _check_ledger_deadline(deadline, budget=budget)
                    try:
                        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                        locked.append(fd)
                        break
                    except BlockingIOError as exc:
                        if time.monotonic() >= deadline:
                            raise StoreError("Storage inspection is busy") from exc
                        time.sleep(.01)
            uri = self.path.as_uri() + "?mode=ro"
            db = sqlite3.connect(uri, uri=True, timeout=max(.01, deadline - time.monotonic()),
                                 isolation_level=None)
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            db.set_progress_handler(
                budget.sqlite_progress if budget is not None else lambda: int(time.monotonic() >= deadline),
                1000)
            _check_ledger_deadline(deadline, db, budget)
            meta_shape = db.execute("SELECT COUNT(*),COALESCE(SUM(length(CAST(key AS BLOB)) "
                                     "+ length(CAST(value AS BLOB))),0) FROM meta").fetchone()
            if (type(meta_shape[0]) is not int or type(meta_shape[1]) is not int
                    or not 0 <= meta_shape[0] <= MAX_LEDGER_META_ROWS
                    or not 0 <= meta_shape[1] <= MAX_LEDGER_OUTPUT_BYTES):
                raise StoreError("Storage inspection ledger metadata exceeds its bound")
            page_count = db.execute("PRAGMA page_count").fetchone()[0]
            page_size = db.execute("PRAGMA page_size").fetchone()[0]
            if (type(page_count) is not int or type(page_size) is not int or page_count < 0
                    or page_size <= 0 or page_count * page_size > MAX_LEDGER_FILE_BYTES):
                raise StoreError("Storage inspection ledger page inventory exceeds its bound")
            meta_columns = tuple(row[1] for row in db.execute("PRAGMA table_info(meta)"))
            reservation_columns = tuple(row[1] for row in db.execute("PRAGMA table_info(reservations)"))
            if (meta_columns != ("key", "value")
                    or reservation_columns != ("id", "operation_key", "state", "reserved_bytes",
                                                "base_used_bytes", "measured_bytes", "basis_sha256",
                                                "details", "created_at")):
                raise StoreError("Storage inspection ledger schema is unsupported")
            _check_ledger_deadline(deadline, db, budget)
            meta_rows = db.execute("SELECT key,value FROM meta LIMIT ?", (MAX_LEDGER_META_ROWS + 1,)).fetchall()
            if len(meta_rows) > MAX_LEDGER_META_ROWS:
                raise StoreError("Storage inspection ledger metadata exceeds its bound")
            meta_bytes = 0
            for key, value in meta_rows:
                if budget is not None:
                    budget.add("rows", 1)
                    budget.add("cells", 2)
                if not isinstance(key, str) or not isinstance(value, str):
                    raise StoreError("Storage inspection ledger metadata is malformed")
                meta_bytes += len(key.encode("utf-8")) + len(value.encode("utf-8"))
                if meta_bytes > MAX_LEDGER_OUTPUT_BYTES:
                    raise StoreError("Storage inspection ledger metadata exceeds its bound")
            if budget is not None:
                budget.add("contentBytes", meta_bytes)
            meta = dict(meta_rows)
            if (meta.get("format") != "brain-storage-admission-ledger/v1"
                    or meta.get("brainId") != registration["brainId"]
                    or meta.get("authorityBinding") != registration["authority"]["binding"]
                    or meta.get("adoptionPreviewSha256") != registration["adoption"]["previewSha256"]
                    or meta.get("adoptionInventoryBasisSha256") != registration["adoption"]["inventoryBasisSha256"]
                    or meta.get("lockProtocol") != PERSISTENT_LOCK_PROTOCOL
                    or self._parse_lock_identity(meta.get("writerLockIdentity")) != lock_pins["writer"]
                    or self._parse_lock_identity(meta.get("ledgerLockIdentity")) != lock_pins["ledger"]):
                raise StoreError("Storage inspection ledger binding changed")
            _check_ledger_deadline(deadline, db, budget)
            state_counts = {state: 0 for state in _LEDGER_STATES}
            active_reserved = active_count = row_count = detail_bytes = 0
            cursor = db.execute(
                "SELECT CASE WHEN state IN ('reserved','outcome-unknown','settled') THEN state END,"
                "reserved_bytes,base_used_bytes,measured_bytes,"
                "length(CAST(id AS BLOB)),length(CAST(operation_key AS BLOB)),"
                "length(CAST(basis_sha256 AS BLOB)),length(CAST(details AS BLOB)),"
                "length(CAST(created_at AS BLOB)),typeof(id),typeof(operation_key),"
                "typeof(basis_sha256),typeof(details),typeof(created_at) "
                "FROM reservations LIMIT ?", (MAX_LEDGER_ROWS + 1,))
            for row in cursor:
                _check_ledger_deadline(deadline, db, budget)
                row_count += 1
                if row_count > MAX_LEDGER_ROWS:
                    raise StoreError("Storage inspection ledger row count exceeds its bound")
                if budget is not None:
                    budget.add("rows", 1)
                    budget.add("cells", len(row))
                (state, reserved, base_used, measured, identity_len, operation_len, basis_len, detail_len,
                 created_len, identity_type, operation_type, basis_type, detail_type, created_type) = row
                if (not isinstance(state, str) or state not in _LEDGER_STATES
                        or type(reserved) is not int or not 0 <= reserved <= self.registration["limitBytes"]
                        or type(base_used) is not int or not 0 <= base_used <= self.registration["limitBytes"]
                        or (measured is not None and (type(measured) is not int
                                                      or not 0 <= measured <= self.registration["limitBytes"]))
                        or identity_type != "text" or identity_len != 64
                        or operation_type != "text" or not 1 <= operation_len <= 256
                        or basis_type != "text" or basis_len != 64
                        or detail_type != "text" or not 2 <= detail_len <= 16 * 1024
                        or created_type != "text" or not 1 <= created_len <= 64):
                    raise StoreError("Storage inspection ledger row is malformed")
                detail_bytes += detail_len
                if detail_bytes > MAX_LEDGER_FILE_BYTES:
                    raise StoreError("Storage inspection ledger detail inventory exceeds its bound")
                if budget is not None:
                    budget.add("contentBytes", detail_len)
                state_counts[state] += 1
                if state in ("reserved", "outcome-unknown"):
                    active_reserved += reserved
                    active_count += 1
                    if active_reserved > self.registration["limitBytes"]:
                        raise StoreError("Storage inspection ledger reserved total exceeds its bound")
            _check_ledger_deadline(deadline, db, budget)
            fresh_registration = load_registration(self.root)
            if (time.monotonic() > deadline or fresh_registration != registration
                    or fingerprint(fresh_registration) != registration_sha256):
                raise StoreError("Storage inspection registration changed during snapshot")
            writer_after = os.stat(self.writer_lock_path.name, dir_fd=writer_parent_fd, follow_symlinks=False)
            lock_after = os.stat(self.lock_path.name, dir_fd=ledger_parent_fd, follow_symlinks=False)
            writer_parent_after = self.writer_lock_path.parent.lstat()
            ledger_parent_after = self.lock_path.parent.lstat()
            ledger_after = self.path.lstat()
            _require_no_ledger_sidecars(self.path)
            writer_pin_after = os.fstat(writer_fd)
            ledger_pin_after = os.fstat(ledger_fd)
            if ((writer_after.st_dev, writer_after.st_ino) != writer_identity
                    or (lock_after.st_dev, lock_after.st_ino) != lock_identity
                    or writer_identity != lock_pins["writer"]
                    or lock_identity != lock_pins["ledger"]
                    or (writer_pin_after.st_dev, writer_pin_after.st_ino) != lock_pins["writer"]
                    or (ledger_pin_after.st_dev, ledger_pin_after.st_ino) != lock_pins["ledger"]
                    or (writer_parent_after.st_dev, writer_parent_after.st_ino) != writer_parent_identity
                    or (ledger_parent_after.st_dev, ledger_parent_after.st_ino) != ledger_parent_identity
                    or (ledger_after.st_dev, ledger_after.st_ino, ledger_after.st_size,
                        ledger_after.st_mtime_ns, ledger_after.st_ctime_ns)
                    != (ledger_before.st_dev, ledger_before.st_ino, ledger_before.st_size,
                        ledger_before.st_mtime_ns, ledger_before.st_ctime_ns)):
                raise StoreError("Storage inspection ledger changed during snapshot")
            result = {"reservedBytes": active_reserved, "reservationCount": active_count,
                   "states": {state: count for state, count in state_counts.items() if count},
                   "registrationSha256": registration_sha256}
            if len(_encode(result)) > MAX_LEDGER_OUTPUT_BYTES:
                raise StoreError("Storage inspection ledger output exceeds its bound")
            _check_ledger_deadline(deadline, db, budget)
            yield result
            if time.monotonic() > deadline:
                raise StoreError("Storage inspection snapshot exceeded its deadline")
        except sqlite3.Error as exc:
            raise StoreError("Storage inspection ledger is unavailable or malformed") from exc
        except OSError as exc:
            raise StoreError("Storage inspection ledger changed or became unavailable") from exc
        finally:
            if db is not None:
                try:
                    if db.in_transaction:
                        db.rollback()
                finally:
                    db.close()
            for fd in reversed(locked):
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
            for fd in (ledger_fd, writer_fd, ledger_parent_fd, writer_parent_fd):
                if fd is not None:
                    os.close(fd)

    @contextmanager
    def _locked(self):
        if self.path.is_symlink() or not self.path.is_file():
            raise StoreError("Storage admission is not adopted or ledger is unavailable")
        persistent, pins, protocol = self._lock_state()
        expected = pins["ledger"] if protocol == PERSISTENT_LOCK_PROTOCOL and pins else None
        fd, parent_fd, identity, parent_identity = self._open_lock(
            self.lock_path, create=not persistent, expected_identity=expected)
        try:
            deadline = time.monotonic() + 2.0
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise StoreError("Storage admission is busy")
                    time.sleep(.01)
            named_after = os.stat(self.lock_path.name, dir_fd=parent_fd, follow_symlinks=False)
            named_parent_after = self.lock_path.parent.lstat()
            opened_after = os.fstat(fd)
            if ((opened_after.st_dev, opened_after.st_ino) != identity
                    or (named_after.st_dev, named_after.st_ino) != identity
                    or (named_parent_after.st_dev, named_parent_after.st_ino) != parent_identity):
                raise StoreError("Storage admission lock changed while locking")
            db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=2, isolation_level=None)
            try:
                ledger_info = self.path.lstat()
                if (not stat.S_ISREG(ledger_info.st_mode) or ledger_info.st_nlink != 1
                        or ledger_info.st_uid != os.geteuid() or ledger_info.st_mode & 0o077):
                    raise StoreError("Storage admission ledger is unsafe")
                db.execute("BEGIN IMMEDIATE")
                meta = dict(db.execute("SELECT key,value FROM meta"))
                if (meta.get("format") != "brain-storage-admission-ledger/v1"
                        or meta.get("brainId") != self.registration["brainId"]
                        or meta.get("authorityBinding") != self.registration["authority"]["binding"]):
                    raise StoreError("Storage admission ledger binding changed")
                if (protocol == PERSISTENT_LOCK_PROTOCOL
                        and (meta.get("lockProtocol") != protocol
                             or self._parse_lock_identity(meta.get("ledgerLockIdentity")) != identity)):
                    raise StoreError("Storage admission ledger lock identity changed")
                yield db
                db.commit()
            except BaseException:
                if db.in_transaction:
                    db.rollback()
                raise
            finally:
                db.close()
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
                os.close(parent_fd)

    @contextmanager
    def _writer_fenced(self):
        """Hold the cross-process writer fence across effects and recovery."""
        persistent, pins, protocol = self._lock_state()
        expected = pins["writer"] if protocol == PERSISTENT_LOCK_PROTOCOL and pins else None
        fd, parent_fd, _identity, parent_identity = self._open_lock(
            self.writer_lock_path, create=not persistent, expected_identity=expected)
        try:
            opened = os.fstat(fd)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise StoreError("Storage admission has a live writer; recovery is unavailable") from exc
            rechecked = os.fstat(fd)
            named_after = os.stat(self.writer_lock_path.name, dir_fd=parent_fd, follow_symlinks=False)
            named_parent_after = self.writer_lock_path.parent.lstat()
            if ((rechecked.st_dev, rechecked.st_ino, rechecked.st_uid, rechecked.st_nlink, rechecked.st_mode)
                    != (opened.st_dev, opened.st_ino, opened.st_uid, opened.st_nlink, opened.st_mode)
                    or (named_after.st_dev, named_after.st_ino) != (opened.st_dev, opened.st_ino)
                    or (named_parent_after.st_dev, named_parent_after.st_ino) != parent_identity):
                raise StoreError("Storage admission writer fence changed while locking")
            current_persistent, current_pins, current_protocol = self._lock_state()
            if (current_protocol == PERSISTENT_LOCK_PROTOCOL
                    and (not current_persistent or current_pins is None
                         or current_pins["writer"] != (opened.st_dev, opened.st_ino))):
                raise StoreError("Storage admission writer fence identity changed")
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
                os.close(parent_fd)

    def reserve(self, *, operation_key, reserved_bytes, basis_sha256, details, inventory_now,
                _writer_fenced=False, _identity=None, _reject_existing=False):
        if (not isinstance(operation_key, str) or not operation_key or len(operation_key) > 256
                or type(reserved_bytes) is not int or reserved_bytes < 0 or not _SHA.fullmatch(basis_sha256)
                or not isinstance(details, dict) or len(_encode(details)) > 16 * 1024):
            raise StoreError("Storage admission reservation is invalid")
        fence = nullcontext() if _writer_fenced else self._writer_fenced()
        with fence, self._locked() as db:
            prior = db.execute("SELECT id,state,reserved_bytes,basis_sha256,details FROM reservations WHERE operation_key=?",
                               (operation_key,)).fetchone()
            if prior:
                if _reject_existing:
                    raise StoreError("Storage admission operation key already has a restore reservation")
                if (prior[1] not in ("reserved", "outcome-unknown") or prior[2] != reserved_bytes
                        or prior[3] != basis_sha256 or prior[4] != _encode(details).decode()):
                    raise StoreError("Storage admission operation key was reused")
                return {"id": prior[0], "state": prior[1], "reservedBytes": prior[2],
                        "basisSha256": prior[3]}
            used = inventory_now()
            existing = db.execute("SELECT COALESCE(SUM(reserved_bytes),0) FROM reservations WHERE state IN ('reserved','outcome-unknown')").fetchone()[0]
            if used["usedBytes"] + int(existing) + reserved_bytes > self.registration["limitBytes"]:
                raise StoreError("Brain retained-content limit would be exceeded")
            identity = _identity or hashlib.sha256(os.urandom(32) + operation_key.encode()).hexdigest()
            if not isinstance(identity, str) or not _SHA.fullmatch(identity):
                raise StoreError("Storage admission reservation identity is invalid")
            if used.get("basisSha256") != basis_sha256:
                raise StoreError("Storage admission inventory basis changed before reservation")
            db.execute("INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?,?)",
                       (identity, operation_key, "reserved", reserved_bytes, used["usedBytes"], None, basis_sha256,
                        _encode(details).decode(), time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
            return {"id": identity, "state": "reserved", "reservedBytes": reserved_bytes,
                    "baseUsedBytes": used["usedBytes"], "basisSha256": used["basisSha256"]}

    def reservation_state(self, identity):
        with self._locked() as db:
            row = db.execute("SELECT state,reserved_bytes FROM reservations WHERE id=?", (identity,)).fetchone()
        if row is None:
            raise StoreError("Storage admission reservation is unavailable")
        return {"state": row[0], "reservedBytes": row[1]}

    @contextmanager
    def upload_session_write(self, identity, *, temporary_bytes, inventory_now, session_id):
        """Debit a session lease while its complete replacement file is staged."""
        if type(temporary_bytes) is not int or temporary_bytes < 0:
            raise StoreError("Storage admission session write bound is invalid")
        with self._writer_fenced():
            before = inventory_now()
            with self._locked() as db:
                row = db.execute("SELECT state,reserved_bytes,details FROM reservations WHERE id=?",
                                 (identity,)).fetchone()
                if row is None or row[0] != "reserved":
                    raise StoreError("Studio App session reservation is unresolved")
                details = json.loads(row[2])
                if (details.get("kind") != "studio-app-session"
                        or details.get("authorityBinding") != self.registration["authority"]["binding"]
                        or details.get("session") != session_id
                        or temporary_bytes > row[1]):
                    raise StoreError("Studio App session lease cannot cover its atomic temporary")
                others = db.execute("SELECT COALESCE(SUM(reserved_bytes),0) FROM reservations "
                                    "WHERE id<>? AND state IN ('reserved','outcome-unknown')",
                                    (identity,)).fetchone()[0]
                prior_reserved = row[1]
                remaining = prior_reserved - temporary_bytes
                if before["usedBytes"] + int(others) + prior_reserved > self.registration["limitBytes"]:
                    raise StoreError("Studio App upload temporary exceeds aggregate retained-content capacity")
                db.execute("UPDATE reservations SET reserved_bytes=? WHERE id=? AND state='reserved'",
                           (remaining, identity))
            effect_token = _ACTIVE_EFFECTS.set({**_ACTIVE_EFFECTS.get(), str(self.root.resolve()): {
                "ledger": self, "identity": identity, "inventory": inventory_now,
                "authorityBinding": self.registration["authority"]["binding"],
                "sessionWrite": {"sessionId": session_id, "temporaryBytes": temporary_bytes}}})
            try:
                yield {"reservedBytes": temporary_bytes}
            except BaseException:
                try:
                    after = inventory_now()
                    growth = max(0, after["usedBytes"] - before["usedBytes"])
                    if growth > temporary_bytes:
                        raise StoreError("Studio App session temporary exceeded its reservation")
                    self._finish_upload_session_write(identity, prior_reserved, growth, after,
                        unknown=after.get("basisSha256") != before.get("basisSha256"))
                except Exception:
                    try:
                        self.mark_unknown(identity)
                    except Exception:
                        pass
                raise
            else:
                after = inventory_now()
                growth = max(0, after["usedBytes"] - before["usedBytes"])
                if growth > temporary_bytes:
                    self.mark_unknown(identity)
                    raise StoreError("Studio App session temporary exceeded its reservation")
                self._finish_upload_session_write(identity, prior_reserved, growth, after)
            finally:
                _ACTIVE_EFFECTS.reset(effect_token)

    def _finish_upload_session_write(self, identity, prior_reserved, growth, after, *, unknown=False):
        with self._locked() as db:
            row = db.execute("SELECT state,reserved_bytes,details FROM reservations WHERE id=?",
                             (identity,)).fetchone()
            if row is None or row[0] != "reserved":
                raise StoreError("Studio App upload reservation is unresolved")
            details = json.loads(row[2])
            if (type(prior_reserved) is not int or prior_reserved < 0
                    or type(growth) is not int or growth < 0):
                raise StoreError("Studio App session reservation is malformed")
            # The persisted file growth is now in inventory. Keep the reserved
            # peak in lockstep with that growth: R-G. T was debited only while
            # the atomic-replace temporary existed and is not charged twice.
            restored = prior_reserved - growth
            if restored < 0:
                db.execute("UPDATE reservations SET state='outcome-unknown' WHERE id=? AND state='reserved'",
                           (identity,))
                raise StoreError("Studio App session write exceeded its retained-growth reservation")
            other = db.execute("SELECT COALESCE(SUM(reserved_bytes),0) FROM reservations "
                                "WHERE id<>? AND state IN ('reserved','outcome-unknown')",
                                (identity,)).fetchone()[0]
            if after["usedBytes"] + int(other) + restored > self.registration["limitBytes"]:
                db.execute("UPDATE reservations SET state='outcome-unknown' WHERE id=? AND state='reserved'",
                           (identity,))
                raise StoreError("Studio App session exceeds its retained-growth reservation")
            db.execute("UPDATE reservations SET state=?,reserved_bytes=?,details=? WHERE id=? AND state='reserved'",
                       ("outcome-unknown" if unknown else "reserved", restored,
                        _encode(details).decode(), identity))

    def extend_reservation(self, identity, *, additional_bytes, inventory_now):
        """Atomically add a known pre-effect bound to an existing upload lease."""
        if type(additional_bytes) is not int or additional_bytes < 0:
            raise StoreError("Storage admission extension is invalid")
        with self._writer_fenced(), self._locked() as db:
            row = db.execute("SELECT state,reserved_bytes,details FROM reservations WHERE id=?",
                             (identity,)).fetchone()
            if row is None or row[0] != "reserved":
                raise StoreError("Storage admission reservation cannot be extended")
            details = json.loads(row[2])
            current = inventory_now()
            others = db.execute("SELECT COALESCE(SUM(reserved_bytes),0) FROM reservations "
                                "WHERE id<>? AND state IN ('reserved','outcome-unknown')",
                                (identity,)).fetchone()[0]
            if (current["usedBytes"] + int(others) + row[1] + additional_bytes
                    > self.registration["limitBytes"]):
                raise StoreError("Brain retained-content limit cannot cover the pending write")
            details["initialReservedBytes"] = details.get("initialReservedBytes", row[1]) + additional_bytes
            db.execute("UPDATE reservations SET reserved_bytes=?,details=? WHERE id=? AND state='reserved'",
                       (row[1] + additional_bytes, _encode(details).decode(), identity))
            return {"id": identity, "state": "reserved", "reservedBytes": row[1] + additional_bytes}

    @contextmanager
    def effect(self, *, operation_key, details, inventory_now, _restore_intent=False):
        """Reserve the entire remaining cap around one host-mediated effect.

        Until every writer has a useful conservative per-operation size bound,
        the safe admission bound is the whole remaining capacity. This serializes
        adopted writes and avoids under-reserving native history/event copies.

        The restore variant inserts a unique reservation and its pre-stage intent
        atomically. Callers may create the empty stage only after this context yields.
        """
        if _restore_intent:
            intent = details.get("restoreIntent") if isinstance(details, dict) else None
            if (not isinstance(details, dict)
                    or set(details) != {"authorityBinding", "operation", "restoreIntent"}
                    or details.get("operation") != "backup.snapshot.restore"
                    or details.get("authorityBinding") != self.registration["authority"]["binding"]
                    or not isinstance(intent, dict)
                    or intent.get("protocol") != "admitted-restore-intent/v2"
                    or intent.get("phase") != "pre-stage"
                    or intent.get("operationId") != operation_key):
                raise StoreError("Storage admission restore intent cannot be reserved")
        with self._writer_fenced():
            before = inventory_now()
            with self._locked() as db:
                existing = db.execute("SELECT COALESCE(SUM(reserved_bytes),0) FROM reservations "
                                      "WHERE state IN ('reserved','outcome-unknown')").fetchone()[0]
            remaining = self.registration["limitBytes"] - before["usedBytes"] - int(existing)
            if remaining < 0:
                raise StoreError("Brain retained-content limit is already exceeded")
            reservation_identity = None
            if _restore_intent:
                intent = details.get("restoreIntent") if isinstance(details, dict) else None
                if (not isinstance(intent, dict)
                        or intent.get("protocol") != "admitted-restore-intent/v2"
                        or intent.get("phase") != "pre-stage"
                        or intent.get("operationId") != operation_key):
                    raise StoreError("Storage admission restore intent cannot be reserved")
                reservation_identity = hashlib.sha256(os.urandom(32) + operation_key.encode()).hexdigest()
                persisted_intent = {**intent, "phase": "reserved", "reservationId": reservation_identity}
                details = {**details, "restoreIntent": persisted_intent}
                if len(_encode(details)) > 16 * 1024:
                    raise StoreError("Storage admission restore intent exceeds its byte bound")
            reservation = self.reserve(operation_key=operation_key, reserved_bytes=remaining,
                basis_sha256=before["basisSha256"], details=details, inventory_now=inventory_now,
                _writer_fenced=True, _identity=reservation_identity,
                _reject_existing=_restore_intent)
            if reservation["state"] != "reserved":
                raise StoreError("A prior storage effect is unresolved; reconcile before retry")
            root_key = str(self.root.resolve())
            root_token = _ACTIVE_ROOTS.set(_ACTIVE_ROOTS.get() | {root_key})
            effect_token = _ACTIVE_EFFECTS.set({**_ACTIVE_EFFECTS.get(), root_key: {
                "ledger": self, "identity": reservation["id"], "inventory": inventory_now,
                "authorityBinding": self.registration["authority"]["binding"]}})
            try:
                if _restore_intent:
                    reservation = {**reservation, "restoreIntent": details["restoreIntent"]}
                yield reservation
            except BaseException:
                try:
                    if _restore_intent:
                        self.mark_unknown(reservation["id"])
                    else:
                        self.release_unwritten(reservation["id"], inventory_now=inventory_now,
                                               _writer_fenced=True)
                except Exception:
                    try:
                        self.mark_unknown(reservation["id"])
                    except Exception:
                        pass
                raise
            else:
                try:
                    if _restore_intent:
                        with self._locked() as db:
                            row = db.execute("SELECT state,details FROM reservations WHERE id=?",
                                             (reservation["id"],)).fetchone()
                        try:
                            persisted = json.loads(row[1])["restoreIntent"] if row else None
                        except (ValueError, TypeError, KeyError):
                            persisted = None
                        if (row is None or row[0] != "reserved" or not isinstance(persisted, dict)
                                or persisted.get("phase") != "stage-bound"
                                or persisted.get("reservationId") != reservation["id"]):
                            self.mark_unknown(reservation["id"])
                            raise StoreError("Restore reservation did not bind its stage before completion")
                    self.settle(reservation["id"], inventory_now=inventory_now,
                                _writer_fenced=True)
                except BaseException:
                    try:
                        self.mark_unknown(reservation["id"])
                    except Exception:
                        pass
                    raise
            finally:
                _ACTIVE_EFFECTS.reset(effect_token)
                _ACTIVE_ROOTS.reset(root_token)

    def bind_restore_stage(self, identity, *, operation_id, stage_identity):
        """Bind the empty stage inode to its reservation before retained bytes are written."""
        active = _ACTIVE_EFFECTS.get().get(str(self.root.resolve()))
        if not active or active.get("ledger") is not self or active.get("identity") != identity:
            raise StoreError("Restore stage binding requires its active durable reservation")
        if (not isinstance(stage_identity, dict) or set(stage_identity) != {"path", "device", "inode"}
                or not isinstance(stage_identity.get("path"), str)
                or len(stage_identity["path"]) > 4096
                or not Path(stage_identity["path"]).is_absolute()
                or ".." in Path(stage_identity["path"]).parts
                or str(Path(stage_identity["path"])) != stage_identity["path"]
                or type(stage_identity.get("device")) is not int
                or not 0 <= stage_identity["device"] < 2**64
                or type(stage_identity.get("inode")) is not int
                or not 0 < stage_identity["inode"] < 2**64):
            raise StoreError("Restore stage identity is invalid")
        with self._locked() as db:
            row = db.execute("SELECT operation_key,state,details FROM reservations WHERE id=?", (identity,)).fetchone()
            if row is None or row[1] != "reserved":
                raise StoreError("Restore reservation is unavailable for stage binding")
            try:
                details = json.loads(row[2])
                intent = details["restoreIntent"]
            except (ValueError, TypeError, KeyError) as exc:
                raise StoreError("Restore reservation intent is unavailable") from exc
            if (set(details) != {"authorityBinding", "operation", "restoreIntent"}
                    or details["operation"] != "backup.snapshot.restore"
                    or details["authorityBinding"] != self.registration["authority"]["binding"]
                    or row[0] != operation_id or intent.get("protocol") != "admitted-restore-intent/v2"
                    or intent.get("phase") != "reserved" or intent.get("reservationId") != identity
                    or intent.get("operationId") != operation_id
                    or intent.get("stagePath") != stage_identity["path"]):
                raise StoreError("Restore reservation intent no longer matches its stage")
            transitioned = {**intent, "phase": "stage-bound", "stageIdentity": stage_identity}
            details["restoreIntent"] = transitioned
            encoded = _encode(details)
            if len(encoded) > 16 * 1024:
                raise StoreError("Restore reservation intent exceeds its byte bound")
            db.execute("UPDATE reservations SET details=? WHERE id=? AND state='reserved'",
                       (encoded.decode("utf-8"), identity))
        return transitioned

    def require_restore_intent(self, identity, *, operation_id, expected, phase, stage_identity=None):
        """Compare the durable intent with trusted in-process pins before a later restore phase."""
        if phase not in ("reserved", "stage-bound") or not isinstance(expected, dict):
            raise StoreError("Restore intent phase is invalid")
        active = _ACTIVE_EFFECTS.get().get(str(self.root.resolve()))
        if not active or active.get("ledger") is not self or active.get("identity") != identity:
            raise StoreError("Restore intent checks require its active durable reservation")
        with self._locked() as db:
            row = db.execute("SELECT operation_key,state,details FROM reservations WHERE id=?", (identity,)).fetchone()
        if row is None or row[1] != "reserved" or row[0] != operation_id:
            raise StoreError("Restore reservation identity is unavailable or changed")
        try:
            details = json.loads(row[2])
            intent = details["restoreIntent"]
        except (ValueError, TypeError, KeyError) as exc:
            raise StoreError("Restore reservation intent is unavailable") from exc
        if (set(details) != {"authorityBinding", "operation", "restoreIntent"}
                or details["operation"] != "backup.snapshot.restore"
                or details["authorityBinding"] != self.registration["authority"]["binding"]
                or intent.get("protocol") != "admitted-restore-intent/v2"
                or intent.get("phase") != phase or intent.get("operationId") != operation_id
                or intent.get("reservationId") != identity):
            raise StoreError("Restore reservation intent is in an unknown phase")
        expected_persisted = {**expected, "phase": phase, "reservationId": identity}
        if phase == "stage-bound":
            if (not isinstance(stage_identity, dict)
                    or set(stage_identity) != {"path", "device", "inode"}
                    or not isinstance(stage_identity.get("path"), str)
                    or type(stage_identity.get("device")) is not int
                    or not 0 <= stage_identity["device"] < 2**64
                    or type(stage_identity.get("inode")) is not int
                    or not 0 < stage_identity["inode"] < 2**64):
                raise StoreError("Bound restore stage identity is required")
            expected_persisted["stageIdentity"] = stage_identity
        if intent != expected_persisted:
            raise StoreError("Restore reservation intent pins changed")
        return intent

    @contextmanager
    def use_reserved_effect(self, identity, *, operation, inventory_now):
        """Run a related writer under an upload's lease, without double-reserving capacity."""
        with self._writer_fenced():
            before = inventory_now()
            with self._locked() as db:
                row = db.execute("SELECT state,reserved_bytes,details FROM reservations WHERE id=?",
                                 (identity,)).fetchone()
                if row is None or row[0] != "reserved":
                    raise StoreError("Studio App upload reservation is unresolved")
                details = json.loads(row[2])
                if (details.get("kind") != "studio-app-upload"
                        or details.get("authorityBinding") != self.registration["authority"]["binding"]):
                    raise StoreError("Studio App upload reservation binding is unavailable")
                others = db.execute("SELECT COALESCE(SUM(reserved_bytes),0) FROM reservations "
                                    "WHERE id<>? AND state IN ('reserved','outcome-unknown')",
                                    (identity,)).fetchone()[0]
                available = self.registration["limitBytes"] - before["usedBytes"] - int(others) - row[1]
                if available < 0:
                    raise StoreError("Brain retained-content limit is already exceeded")
                prior_reserved = row[1]
                expanded = row[1] + available
                details["activeEffect"] = operation
                db.execute("UPDATE reservations SET reserved_bytes=?,details=? WHERE id=? AND state='reserved'",
                           (expanded, _encode(details).decode(), identity))
            root_key = str(self.root.resolve())
            token = _ACTIVE_ROOTS.set(_ACTIVE_ROOTS.get() | {root_key})
            effect_token = _ACTIVE_EFFECTS.set({**_ACTIVE_EFFECTS.get(), root_key: {
                "ledger": self, "identity": identity, "inventory": inventory_now,
                "authorityBinding": self.registration["authority"]["binding"]}})
            try:
                yield {"id": identity, "state": "reserved", "reservedBytes": expanded}
            except BaseException:
                try:
                    after = inventory_now()
                    growth = max(0, after["usedBytes"] - before["usedBytes"])
                    unchanged = after.get("basisSha256") == before.get("basisSha256")
                    self._finish_reserved_effect(identity, expanded, growth, after,
                        state="reserved" if unchanged else "outcome-unknown",
                        restore_reserved=prior_reserved if unchanged else None)
                except Exception:
                    try:
                        self.mark_unknown(identity)
                    except Exception:
                        pass
                raise
            else:
                after = inventory_now()
                growth = max(0, after["usedBytes"] - before["usedBytes"])
                remaining = max(0, prior_reserved - growth)
                self._finish_reserved_effect(identity, expanded, growth, after, state="reserved",
                                             restore_reserved=remaining)
            finally:
                _ACTIVE_EFFECTS.reset(effect_token)
                _ACTIVE_ROOTS.reset(token)

    def _finish_reserved_effect(self, identity, expanded, growth, current, *, state,
                               restore_reserved=None):
        if type(growth) is not int or growth > expanded:
            raise StoreError("Studio App effect exceeded its durable upload reservation")
        with self._locked() as db:
            row = db.execute("SELECT state,details FROM reservations WHERE id=?", (identity,)).fetchone()
            if row is None or row[0] != "reserved":
                raise StoreError("Studio App upload reservation is unresolved")
            remaining = expanded - growth if restore_reserved is None else restore_reserved
            details = json.loads(row[1])
            pending = details.get("externalPendingBytes", details.get("externalWriteBytes", 0))
            if type(pending) is not int or pending < 0:
                raise StoreError("Studio App external write reservation is malformed")
            if pending and state == "reserved" and restore_reserved is None:
                raise StoreError("Studio App effect has an unfinished external write")
            if state == "reserved" and restore_reserved is not None:
                # The complete inventory basis proves this effect wrote nothing.
                details.pop("externalPendingBytes", None)
                details.pop("externalWriteBytes", None)
            details.pop("activeEffect", None)
            others = db.execute("SELECT COALESCE(SUM(reserved_bytes),0) FROM reservations "
                                "WHERE id<>? AND state IN ('reserved','outcome-unknown')",
                                (identity,)).fetchone()[0]
            if current["usedBytes"] + int(others) + remaining > self.registration["limitBytes"]:
                raise StoreError("Studio App effect exceeds aggregate retained-content capacity")
            db.execute("UPDATE reservations SET state=?,reserved_bytes=?,details=? WHERE id=? AND state='reserved'",
                       (state, remaining, _encode(details).decode(), identity))

    def mark_unknown(self, identity):
        with self._locked() as db:
            cursor = db.execute("UPDATE reservations SET state='outcome-unknown' WHERE id=? AND state='reserved'", (identity,))
            if cursor.rowcount != 1:
                raise StoreError("Storage admission reservation is unavailable")

    def recover_stale_reserved(self, identity, *, expected_basis_sha256, inventory_now):
        """Fence all writers, then conservatively convert a stranded reservation to unknown."""
        if not isinstance(expected_basis_sha256, str) or not _SHA.fullmatch(expected_basis_sha256):
            raise StoreError("Storage admission recovery basis is invalid")
        with self._writer_fenced(), self._locked() as db:
            row = db.execute("SELECT state FROM reservations WHERE id=?", (identity,)).fetchone()
            if row is None or row[0] != "reserved":
                raise StoreError("Only a stranded reserved effect can be recovered")
            current = inventory_now()
            if current.get("basisSha256") != expected_basis_sha256:
                raise StoreError("Storage admission recovery inventory changed")
            db.execute("UPDATE reservations SET state='outcome-unknown' WHERE id=? AND state='reserved'",
                       (identity,))
        return {"id": identity, "state": "outcome-unknown", "basisSha256": expected_basis_sha256}

    def settle(self, identity, *, inventory_now, expected_basis_sha256=None, _writer_fenced=False):
        """Settle from a fresh trusted inventory; callers cannot assert byte counts."""
        fence = nullcontext() if _writer_fenced else self._writer_fenced()
        with fence, self._locked() as db:
            row = db.execute("SELECT reserved_bytes,state,base_used_bytes,details FROM reservations WHERE id=?", (identity,)).fetchone()
            if row is None or row[1] not in ("reserved", "outcome-unknown"):
                raise StoreError("Storage admission reservation is unavailable")
            details = json.loads(row[3])
            if details.get("externalPendingBytes", details.get("externalWriteBytes", 0)):
                raise StoreError("Managed external write outcome must be completed or reconciled before settlement")
            current = inventory_now()
            if expected_basis_sha256 is not None and current.get("basisSha256") != expected_basis_sha256:
                raise StoreError("Storage admission inventory changed during reconciliation")
            used = current["usedBytes"]
            measured_bytes = max(0, used - row[2])
            others = db.execute("SELECT COALESCE(SUM(reserved_bytes),0) FROM reservations "
                                "WHERE id<>? AND state IN ('reserved','outcome-unknown')", (identity,)).fetchone()[0]
            if used + int(others) > self.registration["limitBytes"]:
                raise StoreError("Measured brain retained content exceeds its limit")
            db.execute("UPDATE reservations SET state='settled',measured_bytes=? WHERE id=?",
                       (measured_bytes, identity))

    def reconcile_unknown(self, identity, *, expected_basis_sha256, inventory_now):
        """Operator-confirm an unknown effect against one exact current inventory."""
        if not isinstance(expected_basis_sha256, str) or not _SHA.fullmatch(expected_basis_sha256):
            raise StoreError("Storage admission reconciliation basis is invalid")
        with self._writer_fenced(), self._locked() as db:
            row = db.execute("SELECT reserved_bytes,state,base_used_bytes FROM reservations WHERE id=?",
                             (identity,)).fetchone()
            if row is None or row[1] != "outcome-unknown":
                raise StoreError("Only an unknown storage effect can be reconciled")
            current = inventory_now()
            if current.get("basisSha256") != expected_basis_sha256:
                raise StoreError("Storage admission inventory changed during reconciliation")
            used = current["usedBytes"]
            others = db.execute("SELECT COALESCE(SUM(reserved_bytes),0) FROM reservations "
                                "WHERE id<>? AND state IN ('reserved','outcome-unknown')", (identity,)).fetchone()[0]
            if used + int(others) > self.registration["limitBytes"]:
                raise StoreError("Measured brain retained content exceeds its limit")
            db.execute("UPDATE reservations SET state='settled',measured_bytes=? WHERE id=?",
                       (max(0, used - row[2]), identity))

    def check_before_commit(self, identity, *, inventory_now):
        """Enforce the cap against the in-flight writer's same-connection view."""
        with self._locked() as db:
            row = db.execute("SELECT state FROM reservations WHERE id=?", (identity,)).fetchone()
            if row is None or row[0] != "reserved":
                raise StoreError("Storage admission reservation is unavailable before commit")
            current = inventory_now()
            others = db.execute("SELECT COALESCE(SUM(reserved_bytes),0) FROM reservations "
                                "WHERE id<>? AND state IN ('reserved','outcome-unknown')", (identity,)).fetchone()[0]
            if current["usedBytes"] + int(others) > self.registration["limitBytes"]:
                raise StoreError("Brain retained-content limit would be exceeded; native transaction rolled back")

    def check_external_write(self, identity, additional_bytes, *, inventory_now, consume=True):
        """Check a write bound, optionally recording it before its external effect."""
        if type(additional_bytes) is not int or additional_bytes < 0:
            raise StoreError("Storage admission byte bound is invalid")
        with self._locked() as db:
            row = db.execute("SELECT state,reserved_bytes,base_used_bytes,details FROM reservations WHERE id=?",
                             (identity,)).fetchone()
            if row is None or row[0] != "reserved":
                raise StoreError("Storage admission reservation is unavailable before external write")
            current = inventory_now()
            growth = max(0, current["usedBytes"] - row[2])
            details = json.loads(row[3])
            prior_external = details.get("externalPendingBytes", details.get("externalWriteBytes", 0))
            if type(prior_external) is not int or prior_external < 0:
                raise StoreError("Managed external write reservation is malformed")
            others = db.execute("SELECT COALESCE(SUM(reserved_bytes),0) FROM reservations "
                                "WHERE id<>? AND state IN ('reserved','outcome-unknown')", (identity,)).fetchone()[0]
            # Upload leases reserve only their specific attachment object; session
            # writes can legitimately grow the shared inventory during that lease.
            upload_lease = details.get("kind") == "studio-app-upload"
            committed_external = details.get("externalCommittedBytes", 0)
            if type(committed_external) is not int or committed_external < 0:
                raise StoreError("Managed external write reservation is malformed")
            projected_consumption = (committed_external + prior_external + additional_bytes if upload_lease
                                     else growth + prior_external + additional_bytes)
            remaining = row[1] - projected_consumption
            reserved_overrun = remaining < 0
            projected = current["usedBytes"] + int(others) + max(0, remaining)
            if reserved_overrun or projected > self.registration["limitBytes"]:
                raise StoreError("Managed write exceeds cumulative reserved brain retained-content capacity")
            if consume:
                details.pop("externalWriteBytes", None)
                details["externalPendingBytes"] = prior_external + additional_bytes
                db.execute("UPDATE reservations SET details=? WHERE id=? AND state='reserved'",
                           (_encode(details).decode(), identity))
            return {"identity": identity, "boundBytes": additional_bytes,
                    "inventoryBeforeUsedBytes": current["usedBytes"]} if consume else None

    def preflight_external_write(self, identity, additional_bytes, *, inventory_now):
        """Prove an aggregate bound fits without charging it before individual writes."""
        self.check_external_write(identity, additional_bytes, inventory_now=inventory_now, consume=False)

    def complete_external_write(self, token, *, actual_bytes, inventory_now):
        """Move one precharged write bound out of pending state after inventory observes it."""
        if (not isinstance(token, dict) or set(token) != {
                "identity", "boundBytes", "inventoryBeforeUsedBytes"}
                or not isinstance(token["identity"], str)
                or type(token["boundBytes"]) is not int or token["boundBytes"] < 0
                or type(token["inventoryBeforeUsedBytes"]) is not int
                or type(actual_bytes) is not int or actual_bytes < 0
                or actual_bytes > token["boundBytes"]):
            raise StoreError("Managed external write receipt is invalid")
        identity, bound = token["identity"], token["boundBytes"]
        with self._locked() as db:
            row = db.execute("SELECT state,reserved_bytes,base_used_bytes,details FROM reservations WHERE id=?",
                             (identity,)).fetchone()
            if row is None or row[0] != "reserved":
                raise StoreError("Managed external write reservation is unavailable")
            details = json.loads(row[3])
            pending = details.get("externalPendingBytes", details.get("externalWriteBytes", 0))
            if type(pending) is not int or pending < bound:
                raise StoreError("Managed external write reservation changed before completion")
            current = inventory_now()
            if current["usedBytes"] < token["inventoryBeforeUsedBytes"]:
                raise StoreError("Managed external write inventory moved backwards")
            if current["usedBytes"] - token["inventoryBeforeUsedBytes"] > bound:
                raise StoreError("Managed external write exceeded its precharged byte bound")
            if current["usedBytes"] - token["inventoryBeforeUsedBytes"] < actual_bytes:
                raise StoreError("Managed external write is not fully represented in retained-content inventory")
            pending -= bound
            growth = max(0, current["usedBytes"] - row[2])
            upload_lease = details.get("kind") == "studio-app-upload"
            committed_external = details.get("externalCommittedBytes", 0)
            if type(committed_external) is not int or committed_external < 0:
                raise StoreError("Managed external write reservation is malformed")
            if (committed_external + pending > row[1] if upload_lease else growth + pending > row[1]):
                raise StoreError("Managed external write exceeded its reserved inventory bound")
            others = db.execute("SELECT COALESCE(SUM(reserved_bytes),0) FROM reservations "
                                "WHERE id<>? AND state IN ('reserved','outcome-unknown')", (identity,)).fetchone()[0]
            if upload_lease:
                details["externalCommittedBytes"] = committed_external + actual_bytes
                remaining_consumption = committed_external + actual_bytes + pending
            else:
                remaining_consumption = growth + pending
            remaining = row[1] - remaining_consumption
            if current["usedBytes"] + int(others) + max(0, remaining) > self.registration["limitBytes"]:
                raise StoreError("Managed external write exceeds aggregate retained-content capacity")
            if pending:
                details["externalPendingBytes"] = pending
            else:
                details.pop("externalPendingBytes", None)
                details.pop("externalWriteBytes", None)
            db.execute("UPDATE reservations SET details=? WHERE id=? AND state='reserved'",
                       (_encode(details).decode(), identity))

    def release_unwritten(self, identity, *, inventory_now, _writer_fenced=False):
        """Release only a still-reserved effect when the complete basis is unchanged."""
        fence = nullcontext() if _writer_fenced else self._writer_fenced()
        with fence, self._locked() as db:
            row = db.execute("SELECT state,basis_sha256 FROM reservations WHERE id=?", (identity,)).fetchone()
            if row is None or row[0] != "reserved":
                raise StoreError("Unknown storage effects cannot be released by timeout or caller assertion")
            current = inventory_now()
            if current.get("basisSha256") != row[1]:
                raise StoreError("Storage admission effect may have written bytes; operator reconciliation is required")
            cursor = db.execute("DELETE FROM reservations WHERE id=? AND state='reserved'", (identity,))
            if cursor.rowcount != 1:
                raise StoreError("Storage admission reservation is unavailable")

    def reservations(self):
        with self._locked() as db:
            rows = db.execute("SELECT id,operation_key,state,reserved_bytes,measured_bytes,basis_sha256,created_at "
                              "FROM reservations WHERE state IN ('reserved','outcome-unknown') ORDER BY created_at,id").fetchall()
            return [{"id": row[0], "operationKey": row[1], "state": row[2],
                     "reservedBytes": row[3], "measuredBytes": row[4],
                     "basisSha256": row[5], "createdAt": row[6]} for row in rows]

    def verify_ready(self):
        """Fail closed if the explicit adoption ledger is missing or mismatched."""
        with self._locked() as db:
            meta = dict(db.execute("SELECT key,value FROM meta"))
            expected = self.registration["adoption"]
            if (meta.get("adoptionPreviewSha256") != expected["previewSha256"]
                    or meta.get("adoptionInventoryBasisSha256") != expected["inventoryBasisSha256"]):
                raise StoreError("Storage admission ledger does not match the adopted registration")


def apply_adoption(root, store, selection, *, expected_preview_sha256,
                   expected_authority_revision, blob_root=None, session_root=None):
    """Apply only a caller-confirmed preview. This function never changes brain config/policy."""
    _require_admission_platform()
    selection = {key: value for key, value in validate_selection(selection).items() if key != "adoption"}
    # Reuse the selected authority's real SQLite writer transaction. Do not
    # manufacture a second native connection or a pre-adoption lock protocol.
    # This coordinates canonical native writers, not arbitrary filesystem actors
    # or a distributed transaction with ledger/registration publication.
    if store.dialect.driver != "sqlite" or store.dialect.in_transaction:
        raise StoreError("Storage adoption requires an idle selected SQLite authority")
    store.dialect.begin(write=True)
    try:
        store._writer_ready()
        selected_path, selected_config = _selected_authority_path(root, store, selection)
        selected_config_sha256 = fingerprint(selected_config)
        preview = preview_adoption(root, store, selection, blob_root=blob_root, session_root=session_root)
        if preview.get("previewSha256") != expected_preview_sha256:
            raise StoreError("Storage admission adoption preview changed; review a new preview")
        authority_revision = fingerprint({"binding": store.contract.binding,
                                          "nativeBasis": preview["classBasis"]["native"]})
        if authority_revision != expected_authority_revision:
            raise StoreError("Storage admission authority revision changed; review a new preview")
        current_path, current_config = _selected_authority_path(root, store, selection)
        if current_path != selected_path or fingerprint(current_config) != selected_config_sha256:
            raise StoreError("Storage adoption selected route changed during preview")
        registration_raw = adoption_file_bytes(selection, preview_sha256=preview["previewSha256"],
            inventory_basis_sha256=preview["basisSha256"], authority_revision=authority_revision)
        internal = Path(root) / "_internal"
        info = internal.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink < 1):
            raise StoreError("Storage admission state directory is not owner-private")
        registration_path = Path(root) / REGISTRATION
        ledger = AdmissionLedger(root, json.loads(registration_raw))
        ledger.initialize_after_explicit_adoption(expected_preview_sha256=expected_preview_sha256,
            preview_sha256=preview["previewSha256"], inventory_basis_sha256=preview["basisSha256"])
        try:
            current_path, current_config = _selected_authority_path(root, store, selection)
            if current_path != selected_path or fingerprint(current_config) != selected_config_sha256:
                raise StoreError("Storage adoption selected route changed before publication")
            fd = os.open(registration_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(registration_raw)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            # Publication is not atomic with native/ledger state. Preserve the
            # created ledger and locks as fail-closed orphan evidence, including
            # a replaced path whose ownership is no longer ours. An ambiguous
            # failure never grants deletion or an automatic adoption retry.
            raise
        return {"format": "brain-storage-adoption-receipt/v1",
                "registrationSha256": hashlib.sha256(registration_raw).hexdigest(),
                "previewSha256": preview["previewSha256"],
                "inventoryBasisSha256": preview["basisSha256"],
                "authorityRevision": authority_revision}

    finally:
        # Adoption changes no native content. Roll back this read-only use of
        # BEGIN IMMEDIATE on every exit, including a refused/interrupted publish;
        # never commit or roll back a caller-owned outer transaction.
        if store.dialect.in_transaction:
            primary = sys.exc_info()[1]
            try:
                store.dialect.rollback()
            except BaseException:
                if primary is None:
                    raise
                primary.add_note("Native adoption fence rollback failed; transaction custody is unresolved.")


def configured_admission(root, store):
    """Return the adopted ledger and a fresh full inventory callback, or None."""
    registration = load_registration(root)
    if registration is None:
        return None
    _selected_path, _selected_config = _selected_authority_path(root, store, registration)
    ledger = AdmissionLedger(root, registration)
    ledger.verify_ready()
    from knowledge_store import blob_store_for

    def inventory_now():
        before_path, config = _selected_authority_path(root, store, registration)
        blob_store = blob_store_for(root, config, store.contract)
        blob_root = getattr(blob_store, "root", None)
        blob_location = store.path if registration["blob"]["driver"] == "db-blob" else None
        current = inventory(root, store, registration, blob_root=blob_root,
                            blob_location=blob_location)
        after_path, after_config = _selected_authority_path(root, store, registration)
        if before_path != after_path or fingerprint(config) != fingerprint(after_config):
            raise StoreError("Storage admission selected authority configuration changed during inventory")
        return current
    inventory_now()
    return ledger, inventory_now


def preview_adoption(root, store, registration, *, blob_root=None, session_root=None):
    _require_admission_platform()
    registration = validate_selection(registration)
    _selected_authority_path(root, store, registration)
    # Legacy administrative callers could have used a reserved sidecar name
    # before this writer version refused those targets. Do not silently omit a
    # standalone native/FilesAuthority backup under a WAL/SHM basename. Inspect
    # at most 16 bytes per existing sidecar ONLY in the already-owned worker.
    native = Path(store.path)
    try:
        Path(str(native) + "-journal").lstat()
    except FileNotFoundError:
        pass
    else:
        raise StoreError("Selected WAL authority has unresolved rollback-journal residue")
    _stable_tree_worker(native.parent, max_files=200_000, max_total=32,
        only_files=[native.name + "-wal", native.name + "-shm"], header_only=True)
    value = inventory(root, store, registration, blob_root=blob_root, session_root=session_root)
    value["previewSha256"] = fingerprint({k: v for k, v in value.items() if k != "previewSha256"})
    return value


def adoption_file_bytes(registration, *, preview_sha256, inventory_basis_sha256, authority_revision):
    """Prepare the explicit owner-reviewed registration payload; never writes it."""
    registration = validate_selection(registration)
    if (not _SHA.fullmatch(preview_sha256) or not _SHA.fullmatch(inventory_basis_sha256)
            or not isinstance(authority_revision, str) or not authority_revision):
        raise StoreError("Storage admission adoption receipt is invalid")
    return _encode({**registration, "adoption": {"previewSha256": preview_sha256,
        "inventoryBasisSha256": inventory_basis_sha256, "authorityRevision": authority_revision}})
