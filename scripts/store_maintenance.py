"""Protected operator reports and native store/cache maintenance (#422).

Whole-authority snapshots are selected by a private operator host and reuse
brain_snapshot's native adapters. Ordinary record-read grants do not authorize
these actions. The only mutating pilot operates on a registered derived cache.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sqlite3
import stat

from brain_federation import fields
from brain_snapshot import (AdmittedRestoreContext, _assert_restore_context_basis,
                            _snapshot_admission, _sticky_restore_guard, _validate_plan, capture, restore)
from context_bundle import encode
from context_host import decode
from knowledge_operations import private_path
from knowledge_policy import fingerprint
from knowledge_store import SQLiteAuthority, StoreError, utcnow
from maintenance_audit import audit, operation as audit_operation

HOST_FORMAT = "store-maintenance-host/v1"
HOST_FORMAT_V2 = "store-maintenance-host/v2"
LIMIT = 256 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
OPERATIONS = ("store.inspect", "cache.maintain", "snapshot.capture", "snapshot.restore", "migration.report")
INSPECTION_OPERATION = "storage.inspect"
PIN_KEYS = ("operatingHost", "snapshotPlan")
OPTIONAL_PIN_KEYS = ("cacheHost",)


class MaintenanceError(ValueError):
    """A selected operator maintenance action is unavailable or stale."""


def _registered_retained_destination(registration, destination):
    """Pin the unique registered retained root containing a new destination."""
    from brain_storage_admission import _open_directory_chain

    destination = Path(destination)
    if not destination.is_absolute() or ".." in destination.parts:
        raise MaintenanceError("Restore destination path is not canonical")
    try:
        destination_text = str(destination)
        destination_bytes = destination_text.encode("utf-8")
        name_bytes = destination.name.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise MaintenanceError("Restore destination path is not valid UTF-8") from exc
    if (len(destination_bytes) > 4096 or len(name_bytes) > 255
            or destination_text != str(Path(os.path.abspath(destination)))):
        raise MaintenanceError("Restore destination path exceeds its bounds or is not canonical")
    if destination.exists() or destination.is_symlink():
        raise MaintenanceError("Restore destination must be new")
    parent = destination.parent
    try:
        canonical_parent = parent.resolve(strict=True)
        if canonical_parent != parent:
            raise MaintenanceError("Restore destination parent must use its canonical path")
        parent_fd = _open_directory_chain(canonical_parent)
    except (OSError, StoreError) as exc:
        raise MaintenanceError("Restore destination parent is unavailable or unsafe") from exc
    matches = []
    try:
        parent_info = os.fstat(parent_fd)
        if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.geteuid()
                or parent_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)):
            raise MaintenanceError("Restore destination parent is unavailable or unsafe")
        try:
            os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise MaintenanceError("Restore destination must be new")

        for item in registration["retainedRoots"]:
            if item["kind"] not in ("snapshot", "backup"):
                continue
            registered_spelling = Path(item["path"])
            if (not registered_spelling.is_absolute() or ".." in registered_spelling.parts):
                raise MaintenanceError("Registered retained root path is unsafe")
            try:
                root_text = str(registered_spelling)
                root_bytes = root_text.encode("utf-8")
                root_components = registered_spelling.parts[1:]
                if (len(root_bytes) > 4096 or len(root_components) > 256
                        or any(len(component.encode("utf-8")) > 255 for component in root_components)
                        or str(registered_spelling.resolve(strict=True)) != root_text):
                    raise MaintenanceError("Registered retained root path must be canonical and bounded")
                # Open the configured spelling itself. Do not resolve away an
                # ancestor link before applying O_NOFOLLOW to every component.
                root_fd = _open_directory_chain(registered_spelling)
            except (OSError, StoreError, UnicodeEncodeError) as exc:
                raise MaintenanceError("Registered retained root is unavailable or unsafe") from exc
            try:
                root_info = os.fstat(root_fd)
                named_root = registered_spelling.lstat()
                if ((named_root.st_dev, named_root.st_ino) != (root_info.st_dev, root_info.st_ino)
                        or not stat.S_ISDIR(root_info.st_mode)
                        or root_info.st_uid != os.geteuid()
                        or root_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH
                                                | stat.S_ISUID | stat.S_ISGID)):
                    raise MaintenanceError("Registered retained root changed or is unsafe")
                if parent == registered_spelling or parent.is_relative_to(registered_spelling):
                    relative = parent.relative_to(registered_spelling)
                    try:
                        components = tuple(relative.parts)
                        relative_bytes = str(relative).encode("utf-8")
                        if (len(components) > 256 or len(relative_bytes) > 4096
                                or any(component in ("", ".", "..")
                                       or len(component.encode("utf-8")) > 255
                                       for component in components)):
                            raise MaintenanceError("Restore destination route exceeds its bounds")
                    except UnicodeEncodeError as exc:
                        raise MaintenanceError("Restore destination route is not valid UTF-8") from exc
                    walk_fd = _open_relative_retained_parent(root_fd, components)
                    try:
                        walked = os.fstat(walk_fd)
                        if (walked.st_dev, walked.st_ino) != (parent_info.st_dev, parent_info.st_ino):
                            raise MaintenanceError("Restore destination parent changed during root walk")
                    finally:
                        os.close(walk_fd)
                    parent_check_fd = _open_directory_chain(parent)
                    try:
                        parent_checked = os.fstat(parent_check_fd)
                        if ((parent_checked.st_dev, parent_checked.st_ino)
                                != (parent_info.st_dev, parent_info.st_ino)):
                            raise MaintenanceError("Restore destination parent path changed during root walk")
                    finally:
                        os.close(parent_check_fd)
                    # Ensure the registered pathname still names the opened root
                    # after the independent parent and root-relative walks.
                    check_fd = _open_directory_chain(registered_spelling)
                    try:
                        checked = os.fstat(check_fd)
                        named_after = registered_spelling.lstat()
                        if ((checked.st_dev, checked.st_ino) != (root_info.st_dev, root_info.st_ino)
                                or (named_after.st_dev, named_after.st_ino)
                                != (root_info.st_dev, root_info.st_ino)):
                            raise MaintenanceError("Registered retained root changed during destination walk")
                    finally:
                        os.close(check_fd)
                    matches.append({"id": item["id"], "kind": item["kind"],
                                    "path": registered_spelling,
                                    "identity": (root_info.st_dev, root_info.st_ino),
                                    "parentIdentity": (parent_info.st_dev, parent_info.st_ino)})
            finally:
                os.close(root_fd)
    finally:
        os.close(parent_fd)
    if len(matches) != 1:
        raise MaintenanceError("Restore destination must belong to exactly one registered retained root")
    return matches[0]


def _open_relative_retained_parent(root_fd, components):
    """Open a bounded descendant directory using only no-follow dirfd walks."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    current = os.dup(root_fd)
    try:
        for component in components:
            try:
                named = os.stat(component, dir_fd=current, follow_symlinks=False)
                unsafe_write = stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID
                if (not stat.S_ISDIR(named.st_mode) or named.st_uid != os.geteuid()
                        or named.st_mode & unsafe_write):
                    raise MaintenanceError("Restore destination parent contains a non-directory")
                child = os.open(component, flags, dir_fd=current)
            except MaintenanceError:
                raise
            except OSError as exc:
                raise MaintenanceError("Restore destination parent changed or is unsafe") from exc
            try:
                opened = os.fstat(child)
                if ((opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                        or not stat.S_ISDIR(opened.st_mode) or opened.st_uid != os.geteuid()
                        or opened.st_mode & unsafe_write):
                    raise MaintenanceError("Restore destination parent changed while opening")
            except BaseException:
                os.close(child)
                raise
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _read_private(root, relative):
    path = private_path(Path(root), relative)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_mode & 0o077 or before.st_nlink != 1):
            raise MaintenanceError("Maintenance registrations require private regular files")
        raw = stream.read(LIMIT + 1)
        after = os.fstat(stream.fileno())
        if len(raw) > LIMIT or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                                before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                                       after.st_mtime_ns, after.st_ctime_ns):
            raise MaintenanceError("Maintenance registration exceeds its bound or changed during read")
    return decode(raw), hashlib.sha256(raw).hexdigest()


def _pinned(root, declaration):
    fields(declaration, ("path", "sha256"))
    if not isinstance(declaration["path"], str) or not re_full_sha(declaration["sha256"]):
        raise MaintenanceError("Invalid pinned maintenance registration")
    value, digest = _read_private(root, declaration["path"])
    if digest != declaration["sha256"]:
        raise MaintenanceError("Pinned maintenance registration changed")
    return value, digest


def re_full_sha(value):
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def load_host(root, relative):
    root = Path(root).absolute()
    if root.is_symlink() or not root.is_dir():
        raise MaintenanceError("Maintenance root must be a real directory")
    host, digest = _read_private(root, relative)
    optional = tuple(key for key in OPTIONAL_PIN_KEYS if key in host)
    fields(host, ("format", "principalsByUid", "grants", *PIN_KEYS, *optional))
    host_format = host.get("format")
    allowed_operations = set(OPERATIONS) | ({INSPECTION_OPERATION} if host_format == HOST_FORMAT_V2 else set())
    if (host_format not in (HOST_FORMAT, HOST_FORMAT_V2) or not isinstance(host["principalsByUid"], dict)
            or not isinstance(host["grants"], dict)):
        raise MaintenanceError("Invalid store maintenance host")
    for uid, principal in host["principalsByUid"].items():
        if (not isinstance(uid, str) or not uid.isdecimal() or not isinstance(principal, str)
                or not principal.strip()):
            raise MaintenanceError("Invalid protected operator identity mapping")
    for principal, grants in host["grants"].items():
        if (not isinstance(principal, str) or not principal.strip() or not isinstance(grants, list)
                or len(grants) != len(set(grants)) or any(item not in allowed_operations for item in grants)):
            raise MaintenanceError("Invalid store maintenance action grant")
    plan, plan_sha = _pinned(root, host["snapshotPlan"])
    repository, authorities, _ = _validate_plan(plan)
    if repository != root.resolve(strict=True):
        raise MaintenanceError("Snapshot plan is not bound to this maintenance root")
    operating_host, operating_sha = _pinned(root, host["operatingHost"])
    if operating_host.get("format") != "operating-views-host/v1":
        raise MaintenanceError("Selected operating host has an unsupported format")
    cache_host = None
    cache_sha = None
    if "cacheHost" in host:
        cache_host, cache_sha = _pinned(root, host["cacheHost"])
    return {"raw": host, "sha256": digest, "plan": plan, "planSha256": plan_sha,
            "repository": repository, "authorities": authorities, "operatingHost": operating_host,
            "operatingHostSha256": operating_sha, "cacheHost": cache_host, "cacheHostSha256": cache_sha,
            "hostFormat": host_format}


def _actor(selection):
    return selection["raw"]["principalsByUid"].get(str(os.geteuid()))


def _guard(root, host_path, selection, actor, authorize):
    if authorize is not None and authorize() != actor:
        raise MaintenanceError("Operator identity changed")
    fresh = load_host(root, host_path)
    if fresh != selection or _actor(fresh) != actor:
        raise MaintenanceError("Maintenance host selection changed")


def _operating(root, host_config, selection, view, actor, authorize):
    from operating_views import run as run_view

    host_path = selection["raw"]["operatingHost"]["path"]
    request = {"format": "operating-view-request/v1", "view": view}
    return decode(run_view(root, host_path, request, actor=actor,
                           authorize=authorize or (lambda: _actor(load_host(root, host_config))), clock=utcnow))


def _space(root):
    usage = os.statvfs(root)
    block = usage.f_frsize or usage.f_bsize
    return {"capacityBytes": usage.f_blocks * block, "usedBytes": (usage.f_blocks - usage.f_bfree) * block,
            "availableBytes": usage.f_bavail * block, "measurement": "filesystem-statvfs"}


def _current_canonical_authority(root, selection):
    """Bind maintenance reads to the currently adopted authority, not only the old snapshot plan."""
    from knowledge_store import adopted_authority, authority_class, private_path, resolve_store_dsn

    config_path = root / "client.config.json"
    descriptor = os.open(config_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > LIMIT:
            raise MaintenanceError("Current store selection is not a bounded regular file")
        raw = stream.read(LIMIT + 1)
        after = os.fstat(stream.fileno())
        if (len(raw) > LIMIT or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                                 before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                                        after.st_mtime_ns, after.st_ctime_ns)):
            raise MaintenanceError("Current store selection changed during read")
    settings = decode(raw)
    try:
        declared = adopted_authority(settings)
        if not isinstance(declared, dict) or not isinstance(declared.get("store"), str):
            raise MaintenanceError("No current adopted authority is declared")
        entry = next((row for row in selection["authorities"] if row["id"] == declared["store"]), None)
        if entry is None or entry["kind"] != "sqlite-authority" or declared.get("binding") != entry["binding"]:
            raise MaintenanceError("Current adopted authority does not match the pinned snapshot plan")
        dsn = resolve_store_dsn(settings, declared["store"])
        adapter = authority_class(dsn)
        if adapter is not SQLiteAuthority:
            raise MaintenanceError("Current adopted authority adapter differs from the pinned snapshot plan")
        selected_path = private_path(root, dsn, "sqlite").resolve(strict=True)
        if selected_path != entry["source"]:
            raise MaintenanceError("Current adopted authority path differs from the pinned snapshot plan")
        return entry
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise MaintenanceError("Current adopted authority selection is unavailable") from exc


def _authority_capacity(selection):
    rows = []
    for entry in selection["authorities"]:
        source = Path(entry["source"])
        if entry["kind"] != "sqlite-authority":
            rows.append({"id": entry["id"], "kind": entry["kind"], "state": "registered",
                         "bytes": None, "detail": "Capacity is not measured for this adapter."})
            continue
        store = SQLiteAuthority(source, expected_binding=entry["binding"], readonly=True)
        try:
            # This is a read-only, pinned capacity observation. The authority's
            # transaction helper defaults to BEGIN IMMEDIATE, so use a plain
            # SQLite read transaction and close it explicitly.
            store.db.execute("BEGIN")
            try:
                page_count = store.db.execute("PRAGMA page_count").fetchone()[0]
                page_size = store.db.execute("PRAGMA page_size").fetchone()[0]
                free_pages = store.db.execute("PRAGMA freelist_count").fetchone()[0]
            finally:
                store.db.rollback()
            info = source.stat()
            rows.append({"id": entry["id"], "kind": entry["kind"], "binding": store.contract.binding,
                         "fileBytes": info.st_size, "pageCount": page_count, "pageSizeBytes": page_size,
                         "freePages": free_pages, "integrity": "not-probed"})
        finally:
            store.close()
    return rows


def _snapshot_basis(selection):
    """Recheck each selected SQLite contract without exporting record contents."""
    basis = []
    for entry in selection["authorities"]:
        row = {"id": entry["id"], "kind": entry["kind"], "target": entry["target"]}
        if entry["kind"] == "sqlite-authority":
            store = SQLiteAuthority(entry["source"], expected_binding=entry["binding"], readonly=True)
            try:
                row["binding"] = store.contract.binding
            finally:
                store.close()
        basis.append(row)
    return basis


def _authority_checkpoint(store):
    """Read the current SQLite authority identity and journal tip at one read point."""
    store.dialect.execute("BEGIN")
    try:
        row = store.dialect.execute(
            "SELECT sequence,digest FROM events ORDER BY sequence DESC LIMIT 1").fetchone()
        if row is None:
            raise MaintenanceError("Current authority checkpoint is unavailable")
        return {"instance": store._meta("instance"), "status": store._meta("status"),
                "sequence": row["sequence"], "digest": row["digest"]}
    finally:
        store.dialect.rollback()


def _admitted_restore_context(root, host_config, selection, actor, authorize, store, destination):
    """Bind the private restore API to this authenticated operator selection."""
    from brain_storage_admission import _open_directory_chain, _selected_authority_path, load_registration
    if actor not in selection["raw"].get("grants", {}) or "snapshot.restore" not in selection["raw"]["grants"][actor]:
        raise MaintenanceError("Operator snapshot restore grant is unavailable")
    _guard(root, host_config, selection, actor, authorize)
    root = Path(root).resolve(strict=True)
    root_fd = _open_directory_chain(root)
    try:
        root_info = os.fstat(root_fd)
        root_identity = (root_info.st_dev, root_info.st_ino)
    finally:
        os.close(root_fd)
    registration = load_registration(root)
    if registration is None:
        raise MaintenanceError("Admitted restore registration is unavailable")
    retained_destination = _registered_retained_destination(registration, destination)
    destination = Path(destination)
    destination_parent_identity = retained_destination["parentIdentity"]
    registration_sha256 = fingerprint(registration)
    host_config_sha256 = selection["sha256"]
    mapping = dict(selection["raw"]["principalsByUid"])
    mapping_sha256 = fingerprint(mapping)
    selected_path, client_settings = _selected_authority_path(root, store, registration)
    authority_path = Path(selected_path).resolve(strict=True)
    if authority_path != Path(store.path).resolve(strict=True):
        raise MaintenanceError("Selected restore authority route differs from the opened authority")
    if (store.contract.authority != registration["authority"]["store"]
            or store.contract.binding != registration["authority"]["binding"]):
        raise MaintenanceError("Opened restore authority differs from its registration")
    authority_file_identity = getattr(store, "authority_file_identity", None)
    if (not isinstance(authority_file_identity, tuple) or len(authority_file_identity) != 2):
        raise MaintenanceError("Opened restore authority has no stable file identity")
    client_config_sha256 = fingerprint(client_settings)
    authority_binding = store.contract.binding
    checkpoint = _authority_checkpoint(store)
    if checkpoint["status"] != "active":
        raise MaintenanceError("Current authority is not active")

    def guard():
        _guard(root, host_config, selection, actor, authorize)
        current_root_fd = _open_directory_chain(root)
        try:
            current_root = os.fstat(current_root_fd)
            if (current_root.st_dev, current_root.st_ino) != root_identity:
                raise MaintenanceError("Selected restore brain root changed")
        finally:
            os.close(current_root_fd)
        current_registration = load_registration(root)
        if current_registration is None or fingerprint(current_registration) != registration_sha256:
            raise MaintenanceError("Storage registration changed during restore")
        current_destination = _registered_retained_destination(current_registration, destination)
        if current_destination != retained_destination:
            raise MaintenanceError("Registered restore destination root changed")
        current_path, current_settings = _selected_authority_path(root, store, current_registration)
        if (Path(current_path).resolve(strict=True) != authority_path
                or fingerprint(current_settings) != client_config_sha256):
            raise MaintenanceError("Current authority route changed during restore")
        current_parent_fd = _open_directory_chain(authority_path.parent)
        try:
            current_file = os.stat(authority_path.name, dir_fd=current_parent_fd, follow_symlinks=False)
            current_file_identity = (current_file.st_dev, current_file.st_ino)
        finally:
            os.close(current_parent_fd)
        if current_file_identity != authority_file_identity:
            raise MaintenanceError("Current authority file identity changed during restore")
        route_guard = getattr(store, "_snapshot_route_guard", None)
        if not callable(route_guard):
            raise MaintenanceError("Selected restore route has no trusted freshness guard")
        route_guard()
        reopened = SQLiteAuthority(authority_path, expected_binding=authority_binding, readonly=True)
        try:
            current_checkpoint = _authority_checkpoint(reopened)
            if (getattr(reopened, "authority_file_identity", None) != authority_file_identity
                    or reopened.contract.binding != authority_binding
                    or current_checkpoint != checkpoint):
                raise MaintenanceError("Current authority checkpoint changed during restore")
            # Recheck host and filesystem routing after the database reads. A valid
            # grant at entry is not a release-time authorization for a long query.
            _guard(root, host_config, selection, actor, authorize)
            final_registration = load_registration(root)
            if final_registration is None:
                raise MaintenanceError("Storage registration disappeared during restore")
            final_destination = _registered_retained_destination(final_registration, destination)
            final_path, final_settings = _selected_authority_path(root, store, final_registration)
            final_root_fd = _open_directory_chain(root)
            try:
                final_root = os.fstat(final_root_fd)
                if (final_root.st_dev, final_root.st_ino) != root_identity:
                    raise MaintenanceError("Selected restore brain root changed")
            finally:
                os.close(final_root_fd)
            final_parent_fd = _open_directory_chain(authority_path.parent)
            try:
                final_file = os.stat(authority_path.name, dir_fd=final_parent_fd,
                                     follow_symlinks=False)
                final_file_identity = (final_file.st_dev, final_file.st_ino)
            finally:
                os.close(final_parent_fd)
            route_guard()
            final_checkpoint = _authority_checkpoint(reopened)
            if (final_registration is None
                    or fingerprint(final_registration) != registration_sha256
                    or Path(final_path).resolve(strict=True) != authority_path
                    or fingerprint(final_settings) != client_config_sha256
                    or final_destination != retained_destination
                    or final_file_identity != authority_file_identity
                    or final_checkpoint != checkpoint):
                raise MaintenanceError("Restore host or authority basis changed before release")
            current_checkpoint = final_checkpoint
            current_file_identity = final_file_identity
            current_registration = final_registration
            current_settings = final_settings
        finally:
            reopened.close()
        _assert_restore_context_basis(context, {
            "actor": actor,
            "restoreGrant": "snapshot.restore",
            "actorMapping": dict(selection["raw"]["principalsByUid"]),
            "actorMappingSha256": fingerprint(selection["raw"]["principalsByUid"]),
            "authorityBinding": authority_binding,
            "authorityCheckpoint": current_checkpoint,
            "authorityFileIdentity": current_file_identity,
            "authorityInstance": current_checkpoint["instance"],
            "authorityPath": authority_path,
            "authorityStoreId": registration["authority"]["store"],
            "brainRoot": root,
            "brainRootIdentity": root_identity,
            "clientConfigSha256": fingerprint(current_settings),
            "hostConfigSha256": selection["sha256"],
            "registrationSha256": fingerprint(current_registration),
            "destinationPath": destination,
            "destinationParentIdentity": destination_parent_identity,
            "retainedRootId": retained_destination["id"],
            "retainedRootKind": retained_destination["kind"],
            "retainedRootPath": retained_destination["path"],
            "retainedRootIdentity": retained_destination["identity"],
        })

    guard = _sticky_restore_guard(guard)
    context = AdmittedRestoreContext(brain_root=Path(root).resolve(strict=True), actor=actor,
        restore_grant="snapshot.restore",
        brain_root_identity=root_identity,
        destination_path=destination,
        destination_parent_identity=destination_parent_identity,
        retained_root_id=retained_destination["id"],
        retained_root_kind=retained_destination["kind"],
        retained_root_path=retained_destination["path"],
        retained_root_identity=retained_destination["identity"],
        host_config_sha256=host_config_sha256,
        client_config_sha256=client_config_sha256,
        registration_sha256=registration_sha256, authority_instance=checkpoint["instance"],
        authority_path=authority_path, authority_file_identity=authority_file_identity,
        authority_store_id=registration["authority"]["store"],
        authority_binding=authority_binding, authority_checkpoint=checkpoint,
        actor_mapping=mapping, actor_mapping_sha256=mapping_sha256, guard=guard)
    return context


def _protected_destination(path):
    target = Path(path)
    if not target.is_absolute() or target.exists() or target.is_symlink():
        raise MaintenanceError("Output must be a new absolute path")
    parent = target.parent
    resolved_parent = parent.resolve(strict=True)
    info = resolved_parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077
            or resolved_parent.is_symlink()):
        raise MaintenanceError("Output parent must be a private operator-owned directory")
    return resolved_parent / target.name


def _private_snapshot(path):
    snapshot = Path(path)
    if not snapshot.is_absolute():
        raise MaintenanceError("Snapshot path must be absolute")
    snapshot = snapshot.resolve(strict=True)
    info = snapshot.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077
            or snapshot.is_symlink()):
        raise MaintenanceError("Snapshot must be a private operator-owned directory")
    return snapshot


def _read_snapshot_manifest(snapshot):
    path = snapshot / "manifest.json"
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_mode & 0o077 or before.st_nlink != 1):
            raise MaintenanceError("Snapshot manifest is not private operator-owned state")
        raw = stream.read(LIMIT + 1)
        after = os.fstat(stream.fileno())
        if len(raw) > LIMIT or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                                before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                                       after.st_mtime_ns, after.st_ctime_ns):
            raise MaintenanceError("Snapshot manifest exceeds its bound or changed during read")
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    return decode(raw), identity


def _snapshot_directory_identity(snapshot):
    info = snapshot.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise MaintenanceError("Snapshot directory changed or is no longer private")
    return info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns


def _same_operating_view(root, host_config, selection, view, actor, authorize, previous):
    _guard(root, host_config, selection, actor, authorize)
    current = _operating(root, host_config, selection, view, actor, authorize)
    if (current.get("view") != previous.get("view")
            or current.get("snapshot") != previous.get("snapshot")
            or current.get("native") != previous.get("native")
            or current.get("nativeSha256") != previous.get("nativeSha256")):
        raise MaintenanceError("Operating source or policy basis changed during maintenance")
    return current


def _result(selection, operation, actor, now, body):
    value = {"format": "store-maintenance-result/v1", "operation": operation,
             "principal": actor, "evaluatedAt": now, "hostSha256": selection["sha256"],
             "snapshotPlanSha256": selection["planSha256"], **body}
    raw = encode(value)
    if len(raw) > MAX_OUTPUT:
        raise MaintenanceError("Maintenance result exceeds its output budget")
    return raw


def _standby_restore_available(root):
    """Only unadopted brains use the legacy standby restore implementation."""
    from brain_storage_admission import load_registration

    try:
        return load_registration(root) is None
    except StoreError:
        # Invalid or orphaned admission state cannot authorize the unbounded
        # legacy restore path either.
        return False


def _storage_inspection(root, host_config, selection, actor, authorize, now):
    """Return a bounded observation; current writer coverage is not a complete capacity guarantee."""
    from brain_storage_admission import (AdmissionLedger, InventoryBudget, _selected_authority_path,
                                         inventory, load_registration)
    from knowledge_store import blob_store_for

    if authorize is None or authorize() != actor:
        raise MaintenanceError("A fresh authenticated operator identity is required")
    _guard(root, host_config, selection, actor, authorize)
    if len(selection["authorities"]) != 1 or selection["authorities"][0]["kind"] != "sqlite-authority":
        raise MaintenanceError("Storage inspection requires exactly one selected SQLite authority")
    entry = selection["authorities"][0]
    registration = load_registration(root)

    def verify_release_basis(store=None, selected_path=None, config=None):
        """Recheck authority and host pins after response serialization, just before release."""
        _guard(root, host_config, selection, actor, authorize)
        try:
            current_entry = _current_canonical_authority(root, selection)
            current_registration = load_registration(root)
        except MaintenanceError:
            raise
        except (OSError, StoreError, ValueError) as exc:
            raise MaintenanceError("Storage inspection basis changed before release") from exc
        if current_entry != entry:
            raise MaintenanceError("Current adopted authority changed before inspection release")
        if current_registration != registration:
            raise MaintenanceError("Storage inspection adoption changed before release")
        if registration is None:
            return
        if store is None or selected_path is None or config is None:
            raise MaintenanceError("Storage inspection authority could not be revalidated")
        current_path, current_config = _selected_authority_path(root, store, registration)
        if (current_path != selected_path or fingerprint(current_config) != fingerprint(config)):
            raise MaintenanceError("Storage inspection authority route changed before release")

    if registration is None:
        value = {"format": "brain.storage.inspect/v1", "state": "unavailable",
                 "evaluatedAt": now, "available": False, "measurementComplete": False,
                 "limitBytes": None, "measuredBytes": None, "reservedBytes": None,
                 "classes": {}, "basisSha256": None,
                 "protection": {"coverage": "unqualified", "complete": False},
                 "unavailableReasons": ["No explicit retained-content adoption is registered."],
                 "aggregateCapacity": {"available": False,
                                       "reason": "Writer coverage and protection qualification are incomplete."}}
        raw = encode(value)
        if len(raw) > 64 * 1024:
            raise MaintenanceError("Storage inspection response exceeds its output budget")
        verify_release_basis()
        return raw

    try:
        probe = SQLiteAuthority(entry["source"], expected_binding=entry["binding"], readonly=True)
        try:
            selected_path, config = _selected_authority_path(root, probe, registration)
            probe_identity = getattr(probe, "authority_file_identity", None)
        finally:
            probe.close()
        if Path(selected_path).resolve(strict=True) != Path(entry["source"]).resolve(strict=True):
            raise MaintenanceError("Current adopted authority route differs from the host plan")
        store = SQLiteAuthority(selected_path, expected_binding=registration["authority"]["binding"], readonly=True)
        if getattr(store, "authority_file_identity", None) != probe_identity:
            store.close()
            raise MaintenanceError("Selected SQLite authority changed while opening inspection snapshot")
    except (OSError, StoreError, ValueError) as exc:
        raise MaintenanceError("Current adopted authority is unavailable") from exc
    try:
        if (store.contract.binding != entry["binding"]
                or store.contract.authority != registration["authority"]["store"]):
            raise MaintenanceError("Current adopted authority binding changed")
        ledger = AdmissionLedger(root, registration)
        budget = InventoryBudget()
        with ledger.readonly_snapshot(registration_sha256=fingerprint(registration), timeout=10.0,
                                      budget=budget) as ledger_state:
            blob_store = blob_store_for(root, config, store.contract)
            if not hasattr(store.db, "setlimit") or not hasattr(sqlite3, "SQLITE_LIMIT_LENGTH"):
                raise MaintenanceError("This SQLite runtime cannot enforce the inspection cell bound")
            store.db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 16 * 1024 * 1024)
            store.db.set_progress_handler(budget.sqlite_progress, 1000)
            store.dialect.execute("BEGIN")
            try:
                try:
                    measured = inventory(root, store, registration,
                                         blob_root=getattr(blob_store, "root", None),
                                         blob_location=store.path if registration["blob"]["driver"] == "db-blob" else None,
                                         budget=budget)
                except (StoreError, sqlite3.Error):
                    measured = None
                current_path, current_config = _selected_authority_path(root, store, registration)
                if (current_path != selected_path or fingerprint(current_config) != fingerprint(config)):
                    raise MaintenanceError("Storage inspection authority route changed during measurement")
                if load_registration(root) != registration:
                    raise MaintenanceError("Storage inspection adoption changed during measurement")
            finally:
                store.dialect.rollback()
                store.db.set_progress_handler(None, 0)
            final_path, final_config = _selected_authority_path(root, store, registration)
            if final_path != selected_path or fingerprint(final_config) != fingerprint(config):
                raise MaintenanceError("Storage inspection authority route changed before release")
            _guard(root, host_config, selection, actor, authorize)
            fresh_registration = load_registration(root)
            if fresh_registration != registration:
                raise MaintenanceError("Storage inspection adoption changed during measurement")
            coverage_reason = "Current writer coverage and protection are not qualified."
            if measured is None:
                value = {"format": "brain.storage.inspect/v1", "state": "unavailable",
                         "evaluatedAt": now, "available": False, "measurementComplete": False,
                         "limitBytes": registration["limitBytes"], "measuredBytes": None,
                         "reservedBytes": ledger_state["reservedBytes"], "classes": {}, "basisSha256": None,
                         "accounting": "logical-retained-content-bytes/v1",
                         "protection": {"selectedProfile": registration["protection"]["profile"],
                                        "requirementsSha256": registration["protection"]["requirementsSha256"],
                                        "coverage": "unqualified", "complete": False},
                         "reservationStates": ledger_state["states"],
                         "unavailableReasons": ["The bounded inventory could not complete."],
                         "aggregateCapacity": {"available": False, "reason": coverage_reason}}
            else:
                value = {"format": "brain.storage.inspect/v1", "state": "completed",
                         "evaluatedAt": now, "available": True, "measurementComplete": True,
                         "limitBytes": measured["limitBytes"], "measuredBytes": measured["usedBytes"],
                         "reservedBytes": ledger_state["reservedBytes"],
                         "classes": measured["classes"], "basisSha256": measured["basisSha256"],
                         "accounting": "logical-retained-content-bytes/v1",
                         "protection": {"selectedProfile": registration["protection"]["profile"],
                                        "requirementsSha256": registration["protection"]["requirementsSha256"],
                                        "coverage": "unqualified", "complete": False},
                         "reservationStates": ledger_state["states"],
                         "unavailableReasons": [coverage_reason],
                         "aggregateCapacity": {"available": False, "reason": coverage_reason}}
        raw = encode(value)
        if len(raw) > 64 * 1024:
            raise MaintenanceError("Storage inspection response exceeds its output budget")
        verify_release_basis(store, selected_path, config)
        return raw
    except (StoreError, sqlite3.Error) as exc:
        # A missing legacy lock pair is unavailable, never lazily created here.
        if any(marker in str(exc) for marker in (
                "without persistent locks", "lock is unavailable", "Storage inspection ledger",
                "Storage inspection snapshot", "Storage admission lock", "Storage admission ledger")):
            raw = encode({"format": "brain.storage.inspect/v1", "state": "unavailable",
                          "evaluatedAt": now, "available": False, "measurementComplete": False,
                          "limitBytes": registration["limitBytes"], "measuredBytes": None,
                          "reservedBytes": None, "classes": {}, "basisSha256": None,
                          "protection": {"selectedProfile": registration["protection"]["profile"],
                                         "requirementsSha256": registration["protection"]["requirementsSha256"],
                                         "coverage": "unqualified", "complete": False},
                          "unavailableReasons": ["The bounded admission-ledger snapshot is unavailable; no partial totals were returned."],
                          "aggregateCapacity": {"available": False,
                                                "reason": "Current writer coverage and protection are not qualified."}})
            if len(raw) > 64 * 1024:
                raise MaintenanceError("Storage inspection response exceeds its output budget")
            verify_release_basis(store, selected_path, config)
            return raw
        raise MaintenanceError("Storage inspection basis changed or is unavailable") from exc
    finally:
        store.close()


def execute(root, host_config, request, *, clock=utcnow, authorize=None,
            snapshot_protection_adapter=None):
    root = Path(root).absolute()
    if (isinstance(request, dict) and request.get("format") == "store-maintenance-request/v2"):
        fields(request, ("format", "operation"))
        if request["operation"] != INSPECTION_OPERATION:
            raise MaintenanceError("Unsupported store maintenance request")
        selection = load_host(root, host_config)
        if selection["hostFormat"] != HOST_FORMAT_V2:
            raise MaintenanceError("Version 2 inspection requires a version 2 operator host")
        actor = _actor(selection)
        if not actor or INSPECTION_OPERATION not in selection["raw"]["grants"].get(actor, []):
            raise MaintenanceError("Operator action unavailable")
        now = clock()
        return _storage_inspection(root, host_config, selection, actor, authorize, now)
    fields(request, ("format", "operation", "arguments"))
    if request["format"] != "store-maintenance-request/v1" or request["operation"] not in OPERATIONS:
        raise MaintenanceError("Unsupported store maintenance request")
    operation_name, arguments = request["operation"], request["arguments"]
    expected_args = {"store.inspect": (), "cache.maintain": (), "snapshot.capture": ("output",),
                     "snapshot.restore": ("snapshot", "output"), "migration.report": ()}[operation_name]
    fields(arguments, expected_args)
    selection = load_host(root, host_config)
    actor = _actor(selection)
    if not actor or operation_name not in selection["raw"]["grants"].get(actor, []):
        raise MaintenanceError("Operator action unavailable")
    now = clock()
    _guard(root, host_config, selection, actor, authorize)
    with audit(root) as journal:
        audit_operation(journal, "store-maintenance.requested", actor, operation_name,
                        {"requestSha256": fingerprint(request)})
        _guard(root, host_config, selection, actor, authorize)
        if operation_name == "store.inspect":
            restore_available = _standby_restore_available(root)
            from brain_storage_admission import load_registration
            snapshot_available = load_registration(root) is None
            operating = _operating(root, host_config, selection, "store.health", actor, authorize)
            canonical = _current_canonical_authority(root, selection)
            observed = operating.get("native", {}).get("authority", {})
            if (observed.get("store") != canonical["id"]
                    or observed.get("binding") != canonical["binding"]
                    or observed.get("state") != "declared"):
                raise MaintenanceError("Operating view and current adopted authority do not match")
            capacity = {"filesystem": _space(root), "authorities": _authority_capacity(selection)}
            _same_operating_view(root, host_config, selection, "store.health", actor, authorize, operating)
            if _current_canonical_authority(root, selection)["source"] != canonical["source"]:
                raise MaintenanceError("Current adopted authority changed during store inspection")
            body = {"state": "completed", "operatingView": operating, "capacity": capacity,
                    "capabilities": {"authorityRepair": False, "authorityReindex": False,
                                     "registeredDerivedCacheMaintenance": bool(selection["cacheHost"]),
                                     "snapshot": snapshot_available, "restoreToNewStandby": restore_available,
                                     "migrationReport": "upgrade" in selection["operatingHost"]},
                    "limits": ["SQLite integrity is not scanned by the doctor; cache maintenance verifies its own integrity.",
                               "Non-SQLite authority byte capacity is not measured."]}
        elif operation_name == "cache.maintain":
            if selection["cacheHost"] is None:
                raise MaintenanceError("No derived cache is registered by this operator host")
            from memory_maintenance import load_processing_cache, maintain_processing_cache

            cache_path = selection["raw"]["cacheHost"]["path"]
            cache, revalidate_cache = load_processing_cache(root, cache_path, actor=actor, now=clock)
            authority_paths = [entry["source"] for entry in selection["authorities"]
                               if entry["kind"] == "sqlite-authority"]
            canonical = _current_canonical_authority(root, selection)
            if len(authority_paths) != 1 or authority_paths[0] != canonical["source"]:
                raise MaintenanceError("Cache maintenance requires exactly one selected SQLite authority")

            def revalidate():
                _guard(root, host_config, selection, actor, authorize)
                current = _current_canonical_authority(root, selection)
                if current["source"] != canonical["source"]:
                    raise MaintenanceError("Current adopted authority changed during cache maintenance")
                revalidate_cache()

            result = maintain_processing_cache(cache, authority_path=authority_paths[0],
                                               revalidate=revalidate)
            body = {"state": "completed", "native": result,
                    "capabilities": {"derivedCacheReindex": True, "corruptCacheRepair": False,
                                     "canonicalAuthorityModified": False},
                    "limits": ["Only the explicitly registered derived SQLite processing cache is selected.",
                               "Corrupt or unverifiable cache contents refuse; they are not repaired."]}
        elif operation_name == "snapshot.capture":
            if (snapshot_protection_adapter is not None
                    and getattr(snapshot_protection_adapter, "actor", None) != actor):
                raise MaintenanceError("Snapshot protection adapter does not match the selected operator")
            destination = _protected_destination(arguments["output"])
            before = _snapshot_basis(selection)
            _guard(root, host_config, selection, actor, authorize)
            manifest = capture(selection["plan"], destination,
                               protection_adapter=snapshot_protection_adapter,
                               fault=lambda phase: _guard(root, host_config, selection, actor, authorize)
                               if phase == "before-recheck" else None)
            try:
                _guard(root, host_config, selection, actor, authorize)
                after = _snapshot_basis(load_host(root, host_config))
            except (MaintenanceError, OSError, ValueError) as exc:
                audit_operation(journal, "store-maintenance.partial", actor, operation_name,
                                {"target": str(destination), "reason": "host-changed-after-capture"})
                raise MaintenanceError("Snapshot was captured but current authorization changed; inspect the private snapshot") from exc
            if before != after:
                audit_operation(journal, "store-maintenance.partial", actor, operation_name,
                                {"target": str(destination), "reason": "authority-binding-changed-after-capture"})
                raise MaintenanceError("Authority binding changed during snapshot capture")
            protected_snapshot = manifest.get("format") == "protected-snapshot/v1"
            body = {"state": "completed", "snapshotSha256": manifest["sha256"],
                    "snapshotPath": str(destination),
                    "authorityIds": ([entry["id"] for entry in selection["plan"]["authorities"]]
                                     if protected_snapshot else
                                     [row["id"] for row in manifest["authorities"]]),
                    "consistency": ({"mode": "protected-snapshot/chunked-stability/v1",
                                     "globalTransaction": False}
                                    if protected_snapshot else manifest["consistency"]),
                    "activated": False,
                    "capabilities": {"capture": True, "globalTransaction": False}}
        elif operation_name == "snapshot.restore":
            snapshot = _private_snapshot(arguments["snapshot"])
            destination = _protected_destination(arguments["output"])
            # brain_snapshot performs the full path, object and manifest validation. This
            # admission check binds the user-selected archive to this host's exact plan.
            manifest, manifest_identity = _read_snapshot_manifest(snapshot)
            directory_identity = _snapshot_directory_identity(snapshot)
            if (manifest.get("planSha256") != fingerprint(selection["plan"])
                    or manifest.get("id") != selection["plan"]["id"]):
                raise MaintenanceError("Snapshot is not registered to this operator host")
            before = _snapshot_basis(selection)
            _guard(root, host_config, selection, actor, authorize)
            admission_store = _snapshot_admission(root, selection["plan"]["authorities"], destination)
            if admission_store is None:
                receipt = restore(snapshot, destination)
            else:
                try:
                    restore_context = _admitted_restore_context(
                        root, host_config, selection, actor, authorize, admission_store, destination)
                    receipt = restore(snapshot, destination, admission=(admission_store, None),
                                      context=restore_context)
                finally:
                    admission_store.close()
            try:
                current_manifest, current_manifest_identity = _read_snapshot_manifest(snapshot)
                current_directory_identity = _snapshot_directory_identity(snapshot)
            except (OSError, MaintenanceError) as exc:
                audit_operation(journal, "store-maintenance.partial", actor, operation_name,
                                {"target": str(destination), "reason": "snapshot-changed-during-restore"})
                raise MaintenanceError("Restore created a standby target but the snapshot changed; inspect the target") from exc
            if (receipt.get("snapshotSha256") != manifest.get("sha256")
                    or current_manifest != manifest or current_manifest_identity != manifest_identity
                    or current_directory_identity != directory_identity):
                audit_operation(journal, "store-maintenance.partial", actor, operation_name,
                                {"target": str(destination), "reason": "snapshot-changed-during-restore"})
                raise MaintenanceError("Restore created a standby target but the snapshot changed; inspect the target")
            try:
                _guard(root, host_config, selection, actor, authorize)
                after = _snapshot_basis(load_host(root, host_config))
            except (MaintenanceError, OSError, ValueError) as exc:
                audit_operation(journal, "store-maintenance.partial", actor, operation_name,
                                {"target": str(destination), "reason": "host-changed-after-restore"})
                raise MaintenanceError("Restore created a standby target but current authorization changed; inspect the target") from exc
            if before != after:
                audit_operation(journal, "store-maintenance.partial", actor, operation_name,
                                {"target": str(destination), "reason": "authority-binding-changed-after-restore"})
                raise MaintenanceError("Current authority binding changed during restore; target remains standby")
            body = {"state": "completed", "restore": receipt, "target": str(destination),
                    "activated": False, "cutoverVerified": False,
                    "capabilities": {"restoreToNewTarget": True, "overwrite": False}}
        else:
            operating = _operating(root, host_config, selection, "upgrade.diff", actor, authorize)
            _same_operating_view(root, host_config, selection, "upgrade.diff", actor, authorize, operating)
            body = {"state": "completed", "migration": operating,
                    "capabilities": {"migrationReport": True, "migrationApplied": False}}
        _guard(root, host_config, selection, actor, authorize)
        result = _result(selection, operation_name, actor, now, body)
        audit_operation(journal, "store-maintenance.completed", actor, operation_name,
                        {"resultSha256": hashlib.sha256(result).hexdigest()})
        # Audit I/O may take long enough for host identity or grants to change.
        # Do not release a result unless the original authority still holds.
        _guard(root, host_config, selection, actor, authorize)
        if operation_name == "store.inspect" and _standby_restore_available(root) != restore_available:
            raise MaintenanceError("Storage admission state changed during store inspection")
        return result
