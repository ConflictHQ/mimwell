"""Preview and bounded local snapshot operations for host-registered destinations."""

import hashlib
import json
import os
from pathlib import Path
import stat

from knowledge_policy import fingerprint, local_path, timestamp
from knowledge_store import StoreError

MAX_CLIENT_CONFIG_BYTES = 1024 * 1024


def _open_private_directory(root, relative):
    """Open a registered private directory by no-follow descriptors."""
    path = local_path(relative)
    if path.parts[0] != "_internal":
        raise StoreError("Backup destination must be under the private internal root")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise StoreError("Safe backup destination access is unavailable on this platform")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root = Path(root).absolute()
    if ".." in root.parts:
        raise StoreError("Backup destination root is unsafe")
    current = None
    try:
        current = os.open("/", flags)
        for part in root.parts[1:]:
            child = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = child
    except OSError:
        if current is not None:
            os.close(current)
        raise StoreError("Backup destination is unavailable or unsafe") from None
    root_info = os.fstat(current)
    if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.geteuid()
            or stat.S_IMODE(root_info.st_mode) & 0o700 != 0o700 or root_info.st_mode & 0o077):
        os.close(current)
        raise StoreError("Backup destination requires private operator-owned directories")
    try:
        for part in path.parts:
            child = os.open(part, flags, dir_fd=current)
            info = os.fstat(child)
            named = os.stat(part, dir_fd=current, follow_symlinks=False)
            if ((info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
                    or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) & 0o700 != 0o700 or info.st_mode & 0o077):
                os.close(child)
                raise StoreError("Backup destination requires private operator-owned directories")
            os.close(current)
            current = child
        return current
    except StoreError:
        os.close(current)
        raise
    except OSError:
        os.close(current)
        raise StoreError("Backup destination is unavailable or unsafe") from None


def _private_directory(root, relative):
    path = local_path(relative)
    if path.parts[0] != "_internal":
        raise StoreError("Backup destination must be under the private internal root")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise StoreError("Safe backup destination inspection is unavailable on this platform")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptors = []
    try:
        current_fd = os.open(root, flags)
        descriptors.append(current_fd)
        for part in path.parts:
            opened_fd = os.open(part, flags, dir_fd=current_fd)
            descriptors.append(opened_fd)
            opened = os.fstat(opened_fd)
            named = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
            if ((opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                    or not stat.S_ISDIR(opened.st_mode) or opened.st_uid != os.geteuid()
                    or opened.st_mode & 0o077):
                raise StoreError("Backup destination requires private operator-owned directories")
            current_fd = opened_fd
        info = os.fstat(current_fd)
        return root.joinpath(*path.parts), {
            "device": info.st_dev,
            "inode": info.st_ino,
            "mode": stat.S_IMODE(info.st_mode),
            "owner": info.st_uid,
        }
    except StoreError:
        raise
    except OSError:
        raise StoreError("Registered backup destination is unavailable or unsafe") from None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _read_client_config(root):
    path = root / "client.config.json"
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        raise StoreError("Backup preview cannot safely verify the current authority mode")
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        raise StoreError("Backup preview cannot verify the current authority mode") from None
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise StoreError("Backup preview cannot verify the current authority mode")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError:
        raise StoreError("Backup preview cannot verify the current authority mode") from None
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise StoreError("Backup preview cannot verify the current authority mode")
        if opened.st_size > MAX_CLIENT_CONFIG_BYTES:
            raise StoreError("Backup preview cannot verify the current authority mode")
        chunks = []
        remaining = MAX_CLIENT_CONFIG_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after_fd = os.fstat(fd)
        after_name = path.lstat()

        def identity(item):
            return item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns

        if identity(opened) != identity(after_fd) or identity(opened) != identity(after_name):
            raise StoreError("Backup preview cannot verify the current authority mode")
        raw = b"".join(chunks)
        if len(raw) > MAX_CLIENT_CONFIG_BYTES:
            raise StoreError("Backup preview cannot verify the current authority mode")
        try:
            return json.loads(raw)
        except (UnicodeDecodeError, ValueError):
            raise StoreError("Backup preview cannot verify the current authority mode") from None
    except OSError:
        raise StoreError("Backup preview cannot verify the current authority mode") from None
    finally:
        os.close(fd)


def _reject_adopted_or_protected(root):
    internal = root / "_internal"
    try:
        internal_info = internal.lstat()
    except FileNotFoundError:
        internal_info = None
    if internal_info is not None and (not stat.S_ISDIR(internal_info.st_mode) or stat.S_ISLNK(internal_info.st_mode)):
        raise StoreError("Backup preview cannot verify the current storage protection mode")
    if internal_info is not None:
        for name in (
            "brain-storage-admission.json",
            "brain-storage-admission.sqlite3",
            "brain-storage-admission.sqlite3-wal",
            "brain-storage-admission.sqlite3-shm",
            "brain-storage-admission.sqlite3-journal",
            "brain-storage-admission.lock",
            "brain-storage-admission-writer.lock",
        ):
            try:
                (internal / name).lstat()
            except FileNotFoundError:
                continue
            except OSError:
                raise StoreError("Backup preview cannot verify the current storage protection mode") from None
            raise StoreError("Routed backup preview is unavailable for adopted or protected storage")
    settings = _read_client_config(root)
    if settings is None:
        return
    if not isinstance(settings, dict):
        raise StoreError("Backup preview cannot verify the current authority mode")
    brain = settings.get("brain", {})
    if brain is None:
        brain = {}
    if not isinstance(brain, dict):
        raise StoreError("Backup preview cannot verify the current authority mode")
    if any(key in brain for key in ("protection", "storageAdmission", "storageAdmissionMode")):
        raise StoreError("Routed backup preview is unavailable for protected storage")


def _checkpoint(store, target, max_physical_source_footprint_bytes):
    status = store._meta("status")
    if status != "active":
        raise StoreError("Backup preview requires an active authority")
    row = store.dialect.execute("SELECT sequence,digest FROM events ORDER BY sequence DESC LIMIT 1").fetchone()
    if row is None:
        raise StoreError("Backup preview requires a journal checkpoint")
    page_count = int(store.dialect.execute("PRAGMA page_count").fetchone()[0])
    page_size = int(store.dialect.execute("PRAGMA page_size").fetchone()[0])
    source = Path(target)
    source_info = source.lstat()
    if (not stat.S_ISREG(source_info.st_mode) or source_info.st_uid != os.geteuid()
            or source_info.st_mode & 0o077):
        raise StoreError("Native authority file is not a private operator-owned regular file")
    page_footprint = page_count * page_size
    wal_bytes = 0
    wal = Path(str(source) + "-wal")
    try:
        wal_info = wal.lstat()
    except FileNotFoundError:
        wal_info = None
    if wal_info is not None:
        if (not stat.S_ISREG(wal_info.st_mode) or wal_info.st_uid != os.geteuid()
                or wal_info.st_mode & 0o077):
            raise StoreError("Native authority journal is not a regular operator-owned file")
        wal_bytes = wal_info.st_size
    physical_footprint = max(source_info.st_size, page_footprint) + wal_bytes
    if physical_footprint > max_physical_source_footprint_bytes:
        raise StoreError("Native authority exceeds the registered preview size bound")
    checkpoint = {
        "authorityInstanceSha256": hashlib.sha256(store._meta("instance").encode("utf-8")).hexdigest(),
        "schemaVersion": store._meta("schema_version"),
        "eventSequence": row[0],
        "journalHeadSha256": row[1],
        "physicalSourceFootprintBytes": physical_footprint,
        "databaseFileBytes": source_info.st_size,
        "databasePageFootprintBytes": page_footprint,
        "walBytes": wal_bytes,
        "databaseFileDevice": source_info.st_dev,
        "databaseFileInode": source_info.st_ino,
        "databaseFileMtimeNs": source_info.st_mtime_ns,
        "databaseFileCtimeNs": source_info.st_ctime_ns,
        "walFileDevice": wal_info.st_dev if wal_info is not None else None,
        "walFileInode": wal_info.st_ino if wal_info is not None else None,
        "walFileMtimeNs": wal_info.st_mtime_ns if wal_info is not None else None,
        "walFileCtimeNs": wal_info.st_ctime_ns if wal_info is not None else None,
    }
    return checkpoint


def _native_blob_representation(contract):
    if contract.blob_store is None:
        return "none"
    if contract.cell.get("blobs") == "db-blob":
        return "inline-db-blob"
    return "external-references"


def run_preview(root, host_config, host, selected, destination, request, *, actor, clock, authorize,
                max_response_bytes):
    """Return a bounded basis without reading snapshot rows or touching the destination."""
    if "connection" in selected or "path" not in selected:
        raise StoreError("Backup preview supports only a registered local SQLite authority")
    from knowledge_operations import load_host, response_bytes
    from operation_backend import select_backend

    _reject_adopted_or_protected(root)
    adapter, target, driver, _, backend_current = select_backend(root, selected)
    if driver != "sqlite":
        raise StoreError("Backup preview supports only a local SQLite authority")
    _, root_identity_fields = _private_directory(root, destination["root"])
    route_binding = fingerprint({
        "destination": request["arguments"]["destination"],
        "authority": destination["authority"],
        "store": destination["store"],
        "root": destination["root"],
        "maxPhysicalSourceFootprintBytes": destination["maxPhysicalSourceFootprintBytes"],
    })
    host_selection = fingerprint({
        "format": host["format"],
        "authorityAlias": request["authority"],
        "authorityRegistration": selected,
        "backupDestination": destination,
    })
    root_identity = fingerprint({
        "routeBinding": route_binding,
        **root_identity_fields,
    })
    initial_value = clock()
    initial = timestamp(initial_value)

    def guard(not_before=initial, route_check=backend_current):
        if authorize is not None and authorize() != actor:
            raise StoreError("Operation identity changed")
        if load_host(root, host_config) != host or timestamp(clock()) < not_before:
            raise StoreError("Operation host selection changed")
        _reject_adopted_or_protected(root)
        route_check()
        _, current_identity_fields = _private_directory(root, destination["root"])
        current_identity = fingerprint({
            "routeBinding": route_binding,
            **current_identity_fields,
        })
        if current_identity != root_identity:
            raise StoreError("Backup destination changed during preview")

    guard()
    store = adapter(target, expected_binding=selected["binding"], readonly=True, intake_clock=clock)
    try:
        with store.request_transaction(write=False):
            guard()
            backup_stores = [item for item in store.contract.stores.values() if "backup" in item["roles"]]
            selected_store = store.contract.stores.get(destination["store"])
            if (len(backup_stores) != 1 or backup_stores[0]["id"] != destination["store"] or
                    selected_store is None or selected_store["driver"] != "files" or
                    selected_store["roles"] != ["backup"]):
                raise StoreError("Contract must declare exactly one matching local-files backup store")
            authorities = [item for item in store.contract.stores.values()
                           if {"records", "journal"}.issubset(item["roles"])]
            if len(authorities) != 1 or store.contract.authority != authorities[0]["id"]:
                raise StoreError("Selected native authority differs from the contract authority")
            checkpoint = _checkpoint(store, target, destination["maxPhysicalSourceFootprintBytes"])
            blob_representation = _native_blob_representation(store.contract)
            authority_store = store.contract.authority
            authority_binding = store.contract.binding
        store.close()
        store = None

        # A second transaction on the same connection would see the first
        # transaction's snapshot. Reopen the authority to observe commits made
        # after the initial checkpoint before releasing the preview.
        guard()
        fresh_adapter, fresh_target, fresh_driver, _, fresh_backend_current = select_backend(root, selected)
        if fresh_driver != "sqlite" or fresh_target != target:
            raise StoreError("Selected native authority route changed during preview")
        fresh_backend_current()
        fresh_store = fresh_adapter(target, expected_binding=selected["binding"], readonly=True, intake_clock=clock)
        store = fresh_store
        with fresh_store.request_transaction(write=False):
            guard(route_check=fresh_backend_current)
            fresh_checkpoint = _checkpoint(
                fresh_store, target, destination["maxPhysicalSourceFootprintBytes"]
            )
            if fresh_checkpoint != checkpoint:
                raise StoreError("Native authority checkpoint changed during preview")
            if (fresh_store.contract.authority != authority_store or
                    fresh_store.contract.binding != authority_binding or
                    _native_blob_representation(fresh_store.contract) != blob_representation):
                raise StoreError("Native authority route changed during preview")
            preview = {
                "format": "backup-preview/v1",
                "authorityAlias": request["authority"],
                "authorityStore": authority_store,
                "authorityBinding": authority_binding,
                "hostSelectionSha256": host_selection,
                "checkpoint": checkpoint,
                "destinationId": request["arguments"]["destination"],
                "destinationStore": destination["store"],
                "destinationBindingSha256": root_identity,
                "nativeBlobRepresentation": blob_representation,
                "snapshotProduced": False,
                "writePerformed": False,
                "durableWriterAvailable": False,
                "protectedModesSupported": False,
                "adoptedModesSupported": False,
                "limits": {
                    "maxPhysicalSourceFootprintBytes": destination["maxPhysicalSourceFootprintBytes"],
                    "bulkExportRead": False,
                    "snapshotBytesBounded": False,
                },
            }
            preview["previewSha256"] = fingerprint(preview)
            final_at = clock()
            if timestamp(final_at) < initial:
                raise StoreError("Operation clock moved backwards")
            raw = response_bytes(request, fresh_store, preview, actor, initial_value, final_at, max_response_bytes)
            fresh_store.revalidate_request(final_at)
            guard(not_before=timestamp(final_at), route_check=fresh_backend_current)
            return raw
    finally:
        if store is not None:
            store.close()
