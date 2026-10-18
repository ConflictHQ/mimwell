"""Protected operator reports and native store/cache maintenance (#422).

Whole-authority snapshots are selected by a private operator host and reuse
brain_snapshot's native adapters. Ordinary record-read grants do not authorize
these actions. The only mutating pilot operates on a registered derived cache.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat

from brain_federation import fields
from brain_snapshot import _validate_plan, capture, restore
from context_bundle import encode
from context_host import decode
from knowledge_operations import private_path
from knowledge_policy import fingerprint
from knowledge_store import SQLiteAuthority, utcnow
from maintenance_audit import audit, operation as audit_operation

HOST_FORMAT = "store-maintenance-host/v1"
LIMIT = 256 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
OPERATIONS = ("store.inspect", "cache.maintain", "snapshot.capture", "snapshot.restore", "migration.report")
PIN_KEYS = ("operatingHost", "snapshotPlan")
OPTIONAL_PIN_KEYS = ("cacheHost",)


class MaintenanceError(ValueError):
    """A selected operator maintenance action is unavailable or stale."""


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
    if (host["format"] != HOST_FORMAT or not isinstance(host["principalsByUid"], dict)
            or not isinstance(host["grants"], dict)):
        raise MaintenanceError("Invalid store maintenance host")
    for uid, principal in host["principalsByUid"].items():
        if (not isinstance(uid, str) or not uid.isdecimal() or not isinstance(principal, str)
                or not principal.strip()):
            raise MaintenanceError("Invalid protected operator identity mapping")
    for principal, grants in host["grants"].items():
        if (not isinstance(principal, str) or not principal.strip() or not isinstance(grants, list)
                or len(grants) != len(set(grants)) or any(item not in OPERATIONS for item in grants)):
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
            "operatingHostSha256": operating_sha, "cacheHost": cache_host, "cacheHostSha256": cache_sha}


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


def execute(root, host_config, request, *, clock=utcnow, authorize=None):
    root = Path(root).absolute()
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
                                     "snapshot": True, "restoreToNewStandby": True,
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
            destination = _protected_destination(arguments["output"])
            before = _snapshot_basis(selection)
            _guard(root, host_config, selection, actor, authorize)
            manifest = capture(selection["plan"], destination,
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
            body = {"state": "completed", "snapshotSha256": manifest["sha256"],
                    "snapshotPath": str(destination), "authorityIds": [row["id"] for row in manifest["authorities"]],
                    "consistency": manifest["consistency"], "activated": False,
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
            receipt = restore(snapshot, destination)
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
        return result
