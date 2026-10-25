"""Exclusive local-file backup publication for a host-registered SQLite authority.

Artifacts use the authority's existing canonical ``knowledge-authority/v1``
snapshot representation. Every write is bounded and non-replacing. A durable
intent is created before staging; a separate receipt confirms publication. An
unknown partial state is never retried or removed implicitly.
"""

import hashlib
import json
import os
import stat
from types import SimpleNamespace

from knowledge_policy import fingerprint, timestamp
from knowledge_store import StoreError, encoded

MAX_OPERATION_METADATA_BYTES = 32 * 1024
MAX_INTENT_BYTES = 16 * 1024
MAX_RECEIPT_BYTES = 16 * 1024
CHUNK_BYTES = 64 * 1024


def _same_destination(root, destination, descriptor, expected_binding, destination_id):
    from knowledge_operation_backup import _open_private_directory

    current = _open_private_directory(root, destination["root"])
    try:
        left, right = os.fstat(descriptor), os.fstat(current)
        if (left.st_dev, left.st_ino) != (right.st_dev, right.st_ino):
            raise StoreError("Backup destination changed during operation")
        route_binding = fingerprint({
            "destination": destination_id,
            "authority": destination["authority"],
            "store": destination["store"],
            "root": destination["root"],
            "maxPhysicalSourceFootprintBytes": destination["maxPhysicalSourceFootprintBytes"],
        })
        binding = fingerprint({
            "routeBinding": route_binding,
            "device": left.st_dev,
            "inode": left.st_ino,
            "mode": stat.S_IMODE(left.st_mode),
            "owner": left.st_uid,
        })
        if binding != expected_binding:
            raise StoreError("Backup destination differs from the exact preview binding")
    finally:
        os.close(current)


def _exists(directory, name):
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False
    except OSError:
        raise StoreError("Backup operation state is unavailable") from None


def _read_private(directory, name, limit):
    if type(limit) is not int or not 0 <= limit <= 64 * 1024 * 1024:
        raise StoreError("Backup operation state has an invalid byte bound")
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except OSError:
        raise StoreError("Backup operation state is unavailable or unsafe") from None
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_mode & 0o077 or before.st_nlink not in (1, 2)
                or before.st_size > limit):
            raise StoreError("Backup operation state is unavailable or unsafe")
        chunks = []
        size = 0
        while True:
            part = os.read(fd, min(CHUNK_BYTES, limit + 1 - size))
            if not part:
                break
            chunks.append(part)
            size += len(part)
            if size > limit:
                raise StoreError("Backup operation state exceeds its byte bound")
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_size,
                    value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after) or identity(after) != identity(named):
            raise StoreError("Backup operation state changed during inspection")
        return b"".join(chunks), after
    finally:
        os.close(fd)


def _write_exclusive(directory, name, raw, limit):
    if len(raw) > limit:
        raise StoreError("Backup operation metadata exceeds its byte bound")
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
    except FileExistsError:
        raise StoreError("Backup operation ID or private staging entry already exists") from None
    except OSError:
        raise StoreError("Backup operation state cannot be created safely") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise StoreError("Backup operation state cannot be created safely")
        with os.fdopen(fd, "wb", closefd=False) as stream:
            view = memoryview(raw)
            offset = 0
            while offset < len(view):
                written = stream.write(view[offset:offset + CHUNK_BYTES])
                if not written:
                    raise StoreError("Backup stage write made no progress")
                offset += written
            stream.flush()
            os.fsync(fd)
    except BaseException:
        os.close(fd)
        raise
    else:
        os.close(fd)


def _publish_stage(directory, stage, final, *, expected_bytes, expected_sha256):
    """Link a verified private stage without ever unlinking a pathname.

    Keeping the stage hard link is intentional: unlinkat has no inode-conditional
    form, so a concurrent name replacement between stat and unlink could remove an
    unrelated entry. The durable stage is also useful evidence for inspection.
    """
    try:
        fd = os.open(stage, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except OSError:
        raise StoreError("Backup stage is unavailable or unsafe") from None
    try:
        before = os.fstat(fd)
        named = os.stat(stage, dir_fd=directory, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_mode & 0o077 or before.st_nlink != 1
                or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
                or before.st_size != expected_bytes):
            raise StoreError("Backup stage identity or size is unsafe")
        digest = hashlib.sha256()
        size = 0
        while True:
            part = os.read(fd, CHUNK_BYTES)
            if not part:
                break
            size += len(part)
            if size > expected_bytes:
                raise StoreError("Backup stage exceeds its expected byte bound")
            digest.update(part)
        after_read = os.fstat(fd)
        current_name = os.stat(stage, dir_fd=directory, follow_symlinks=False)
        def identity(item):
            return (item.st_dev, item.st_ino, item.st_size,
                    item.st_mtime_ns, item.st_ctime_ns)
        if (size != expected_bytes or digest.hexdigest() != expected_sha256
                or identity(before) != identity(after_read)
                or identity(after_read) != identity(current_name)):
            raise StoreError("Backup stage changed or differs from its durable basis")
        try:
            os.link(stage, final, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        except FileExistsError:
            raise StoreError("Backup artifact already exists; replacement is refused") from None
        except OSError:
            raise StoreError("Backup artifact could not be published safely") from None
        os.fsync(directory)
        linked = os.stat(final, dir_fd=directory, follow_symlinks=False)
        stage_named = os.stat(stage, dir_fd=directory, follow_symlinks=False)
        after_link = os.fstat(fd)
        stable_after_link = (after_link.st_dev, after_link.st_ino, after_link.st_size,
                             after_link.st_mtime_ns)
        stable_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        if ((linked.st_dev, linked.st_ino) != (before.st_dev, before.st_ino)
                or (stage_named.st_dev, stage_named.st_ino) != (before.st_dev, before.st_ino)
                or (after_link.st_dev, after_link.st_ino) != (before.st_dev, before.st_ino)
                or after_link.st_nlink != 2 or stable_after_link != stable_before):
            raise StoreError("Backup publication identity changed; residue requires inspection")
        os.lseek(fd, 0, os.SEEK_SET)
        verify = hashlib.sha256()
        verified_size = 0
        while True:
            part = os.read(fd, CHUNK_BYTES)
            if not part:
                break
            verified_size += len(part)
            if verified_size > expected_bytes:
                raise StoreError("Published backup stage exceeds its expected byte bound")
            verify.update(part)
        final_after = os.stat(final, dir_fd=directory, follow_symlinks=False)
        stage_after = os.stat(stage, dir_fd=directory, follow_symlinks=False)
        after_verify = os.fstat(fd)
        if (verified_size != expected_bytes or verify.hexdigest() != expected_sha256
                or (final_after.st_dev, final_after.st_ino) != (before.st_dev, before.st_ino)
                or (stage_after.st_dev, stage_after.st_ino) != (before.st_dev, before.st_ino)
                or (after_verify.st_dev, after_verify.st_ino, after_verify.st_size,
                    after_verify.st_mtime_ns) != stable_before):
            raise StoreError("Published backup identity changed; residue requires inspection")
    finally:
        os.close(fd)


def _decode_object(raw, limit, label):
    if len(raw) > limit:
        raise StoreError(f"{label} exceeds its byte bound")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise StoreError(f"{label} is malformed") from None
    if not isinstance(value, dict):
        raise StoreError(f"{label} is malformed")
    return value


def _read_intent(directory, request_id):
    name = f"intent-{request_id}.json"
    raw, info = _read_private(directory, name, MAX_INTENT_BYTES)
    intent = _decode_object(raw, MAX_INTENT_BYTES, "Backup intent")
    basis = {key: value for key, value in intent.items() if key != "intentSha256"}
    expected_fields = {"format", "requestId", "destinationId", "destinationStore",
                       "destinationBindingSha256", "hostSelectionSha256", "authorityBinding",
                       "sourceCheckpoint", "sourceCheckpointSha256", "previewSha256", "snapshotSha256",
                       "artifactName", "artifactBytes", "artifactSha256", "blobMode", "blobCompleteness",
                       "snapshotRepresentationUpperBoundBytes", "limits", "intentSha256"}
    if (set(intent) != expected_fields
            or intent.get("format") != "routed-backup-intent/v1"
            or intent.get("requestId") != request_id
            or intent.get("intentSha256") != fingerprint(basis)
            or not isinstance(intent.get("sourceCheckpoint"), dict)
            or intent.get("sourceCheckpointSha256") != fingerprint(intent["sourceCheckpoint"])
            or intent.get("artifactName") != f"snapshot-{request_id}.json"
            or type(intent.get("artifactBytes")) is not int
            or not 1 <= intent["artifactBytes"] <= 64 * 1024 * 1024
            or not isinstance(intent.get("artifactSha256"), str)
            or len(intent["artifactSha256"]) != 64
            or set(intent["artifactSha256"]) - set("0123456789abcdef")
            or encoded(intent) != raw.decode("utf-8")):
        raise StoreError("Backup intent is corrupt or does not match this request")
    staged_name = f"stage-{request_id}.intent"
    if info.st_nlink == 2:
        staged, staged_info = _read_private(directory, staged_name, MAX_INTENT_BYTES)
        if staged != raw or (staged_info.st_dev, staged_info.st_ino) != (info.st_dev, info.st_ino):
            raise StoreError("Backup intent has inconsistent staging residue")
    elif info.st_nlink != 1 or _exists(directory, staged_name):
        raise StoreError("Backup intent has unknown staging residue")
    return intent


def _read_staged_intent(directory, request_id):
    """Validate an intent left before its exclusive final-name link."""
    name = f"stage-{request_id}.intent"
    raw, info = _read_private(directory, name, MAX_INTENT_BYTES)
    if info.st_nlink != 1 or _exists(directory, f"intent-{request_id}.json"):
        raise StoreError("Backup intent staging residue has an unknown link state")
    intent = _decode_object(raw, MAX_INTENT_BYTES, "Backup staged intent")
    basis = {key: value for key, value in intent.items() if key != "intentSha256"}
    expected_fields = {"format", "requestId", "destinationId", "destinationStore",
                       "destinationBindingSha256", "hostSelectionSha256", "authorityBinding",
                       "sourceCheckpoint", "sourceCheckpointSha256", "previewSha256", "snapshotSha256",
                       "artifactName", "artifactBytes", "artifactSha256", "blobMode", "blobCompleteness",
                       "snapshotRepresentationUpperBoundBytes", "limits", "intentSha256"}
    if (set(intent) != expected_fields
            or intent.get("format") != "routed-backup-intent/v1"
            or intent.get("requestId") != request_id
            or intent.get("intentSha256") != fingerprint(basis)
            or not isinstance(intent.get("sourceCheckpoint"), dict)
            or intent.get("sourceCheckpointSha256") != fingerprint(intent["sourceCheckpoint"])
            or intent.get("artifactName") != f"snapshot-{request_id}.json"
            or type(intent.get("artifactBytes")) is not int
            or not 1 <= intent["artifactBytes"] <= 64 * 1024 * 1024
            or not isinstance(intent.get("artifactSha256"), str)
            or len(intent["artifactSha256"]) != 64
            or set(intent["artifactSha256"]) - set("0123456789abcdef")
            or encoded(intent) != raw.decode("utf-8")):
        raise StoreError("Backup staged intent is corrupt or does not match this request")
    return intent


def _read_receipt(directory, request_id, intent):
    name = f"receipt-{request_id}.json"
    if not _exists(directory, name):
        return None
    raw, info = _read_private(directory, name, MAX_RECEIPT_BYTES)
    receipt = _decode_object(raw, MAX_RECEIPT_BYTES, "Backup receipt")
    basis = {key: value for key, value in receipt.items() if key != "receiptSha256"}
    expected_fields = {"format", "requestId", "intentSha256", "previewSha256", "artifactName",
                       "artifactBytes", "artifactSha256", "snapshotSha256", "sourceCheckpointSha256",
                       "reconciled", "receiptSha256"}
    if (set(receipt) != expected_fields
            or receipt.get("format") != "routed-backup-receipt/v1"
            or receipt.get("requestId") != request_id
            or receipt.get("intentSha256") != intent["intentSha256"]
            or receipt.get("previewSha256") != intent["previewSha256"]
            or receipt.get("artifactName") != intent["artifactName"]
            or type(receipt.get("artifactBytes")) is not int
            or receipt.get("artifactBytes") != intent["artifactBytes"]
            or receipt.get("artifactSha256") != intent["artifactSha256"]
            or receipt.get("snapshotSha256") != intent["snapshotSha256"]
            or receipt.get("sourceCheckpointSha256") != intent["sourceCheckpointSha256"]
            or type(receipt.get("reconciled")) is not bool
            or receipt.get("receiptSha256") != fingerprint(basis)
            or encoded(receipt) != raw.decode("utf-8")):
        raise StoreError("Backup receipt is corrupt or inconsistent")
    receipt_stage = f"stage-{request_id}.receipt"
    if info.st_nlink == 2:
        staged, staged_info = _read_private(directory, receipt_stage, MAX_RECEIPT_BYTES)
        if staged != raw or (staged_info.st_dev, staged_info.st_ino) != (info.st_dev, info.st_ino):
            raise StoreError("Backup receipt has inconsistent staging residue")
    elif info.st_nlink != 1 or _exists(directory, receipt_stage):
        raise StoreError("Backup receipt has unknown staging residue")
    artifact, info = _read_private(directory, intent["artifactName"], intent["artifactBytes"])
    if (len(artifact) != intent["artifactBytes"]
            or hashlib.sha256(artifact).hexdigest() != intent["artifactSha256"]):
        raise StoreError("Published backup differs from its durable receipt")
    if info.st_nlink == 2:
        stage, stage_info = _read_private(directory, f"stage-{request_id}.snapshot", intent["artifactBytes"])
        if stage != artifact or (stage_info.st_dev, stage_info.st_ino) != (info.st_dev, info.st_ino):
            raise StoreError("Published backup has inconsistent staging residue")
    elif info.st_nlink != 1:
        raise StoreError("Published backup has unexpected link state")
    return receipt


def _preview_basis(root, host_config, host, selected, destination, request, actor, clock, authorize,
                   max_response_bytes):
    from knowledge_operation_backup import run_preview

    preview_request = {
        "format": "knowledge-operation-request/v7",
        "authority": request["authority"],
        "operation": "backup.preview",
        "arguments": {"destination": request["arguments"]["destination"]},
    }
    raw = run_preview(root, host_config, host, selected, destination, preview_request,
                      actor=actor, clock=clock, authorize=authorize,
                      max_response_bytes=max_response_bytes)
    preview = json.loads(raw)["native"]
    return preview


def _checkpoint_now(root, host_config, host, selected, destination, preview, *, actor, clock, authorize,
                    expected_checkpoint=None):
    from knowledge_operation_backup import _checkpoint, _reject_adopted_or_protected
    from knowledge_operations import load_host
    from operation_backend import select_backend

    if authorize is not None and authorize() != actor:
        raise StoreError("Operation identity changed")
    if load_host(root, host_config) != host:
        raise StoreError("Operation host selection changed")
    _reject_adopted_or_protected(root)
    adapter, target, driver, _, backend_current = select_backend(root, selected)
    if driver != "sqlite":
        raise StoreError("Routed backup supports only a local SQLite authority")
    backend_current()
    store = adapter(target, expected_binding=selected["binding"], readonly=True, intake_clock=clock)
    try:
        with store.request_transaction(write=False):
            if authorize is not None and authorize() != actor:
                raise StoreError("Operation identity changed")
            if load_host(root, host_config) != host:
                raise StoreError("Operation host selection changed")
            _reject_adopted_or_protected(root)
            backend_current()
            checkpoint = _checkpoint(store, target, destination["maxPhysicalSourceFootprintBytes"])
            if checkpoint != (expected_checkpoint or preview["checkpoint"]):
                raise StoreError("Native authority checkpoint changed during backup")
            if (store.contract.binding != preview["authorityBinding"]
                    or store.contract.authority != preview["authorityStore"]):
                raise StoreError("Native authority contract changed during backup")
        return target
    finally:
        store.close()


def _validate_backup_contract(store, destination, expected_binding):
    backup_stores = [item for item in store.contract.stores.values() if "backup" in item["roles"]]
    selected = store.contract.stores.get(destination["store"])
    authorities = [item for item in store.contract.stores.values()
                   if {"records", "journal"}.issubset(item["roles"])]
    if (store.contract.binding != expected_binding or len(backup_stores) != 1
            or backup_stores[0]["id"] != destination["store"] or selected is None
            or selected["driver"] != "files" or selected["roles"] != ["backup"]
            or len(authorities) != 1 or store.contract.authority != authorities[0]["id"]):
        raise StoreError("Contract must declare the exact native authority and one matching local-files backup store")
    if store.contract.blob_store is not None and store.contract.cell.get("blobs") != "db-blob":
        raise StoreError("Routed backup refuses externally stored blobs before snapshot export")
    return store.contract.cell.get("blobs")


def _enforce_registered_operation_bound(intent, destination):
    if (type(intent.get("artifactBytes")) is not int
            or intent["artifactBytes"] > destination["maxSnapshotBytes"]
            or intent.get("limits") != {"maxSnapshotBytes": destination["maxSnapshotBytes"],
                                         "maxOperationMetadataBytes": MAX_OPERATION_METADATA_BYTES}):
        raise StoreError("Backup intent exceeds the current registered operation bounds")
    intent_bytes = len(encoded(intent).encode("utf-8"))
    if (intent["artifactBytes"] + intent_bytes + MAX_RECEIPT_BYTES
            > destination["maxSnapshotBytes"] + MAX_OPERATION_METADATA_BYTES):
        raise StoreError("Backup intent and retained artifact exceed the total operation bound")


def _inspect_files(directory, request_id, intent):
    receipt = _read_receipt(directory, request_id, intent)
    if receipt is not None:
        return {"format": "backup-inspection/v1", "requestId": request_id,
                "state": "complete", "receipt": receipt}
    if _exists(directory, f"stage-{request_id}.receipt"):
        raise StoreError("Backup receipt has incomplete staging residue; explicit operator review is required")
    artifact_exists = _exists(directory, intent["artifactName"])
    stage_name = f"stage-{request_id}.snapshot"
    stage_exists = _exists(directory, stage_name)
    if artifact_exists:
        artifact, info = _read_private(directory, intent["artifactName"], intent["artifactBytes"])
        if (len(artifact) != intent["artifactBytes"]
                or hashlib.sha256(artifact).hexdigest() != intent["artifactSha256"]):
            raise StoreError("Backup artifact is inconsistent with its durable intent")
        if stage_exists:
            staged, stage_info = _read_private(directory, stage_name, intent["artifactBytes"])
            if (staged != artifact or (info.st_dev, info.st_ino) != (stage_info.st_dev, stage_info.st_ino)):
                raise StoreError("Backup stage is not the published artifact; operator reconciliation is required")
            if info.st_nlink != 2:
                raise StoreError("Backup artifact link count is inconsistent with its stage")
        elif info.st_nlink != 1:
            raise StoreError("Backup artifact has an unknown link state; reconciliation is unavailable")
        return {"format": "backup-inspection/v1", "requestId": request_id,
                "state": "published-receipt-pending", "artifactSha256": intent["artifactSha256"],
                "artifactBytes": intent["artifactBytes"], "reconcileAvailable": True}
    if stage_exists:
        raise StoreError("Backup has an incomplete stage; automatic retry or cleanup is refused")
    raise StoreError("Backup intent has no artifact; automatic retry is refused")


def _make_receipt(directory, intent, *, reconciled=False, guard=None, destination_guard=None):
    artifact, info = _read_private(directory, intent["artifactName"], intent["artifactBytes"])
    if (len(artifact) != intent["artifactBytes"]
            or hashlib.sha256(artifact).hexdigest() != intent["artifactSha256"]
            or info.st_nlink not in (1, 2)):
        raise StoreError("Backup artifact does not match the durable intent")
    snapshot = _decode_object(artifact, intent["artifactBytes"], "Backup snapshot")
    from knowledge_store import Authority

    Authority.validate_snapshot(snapshot)
    if (snapshot["sha256"] != intent["snapshotSha256"]
            or encoded(snapshot).encode("utf-8") != artifact):
        raise StoreError("Backup snapshot differs from the durable intent")
    if info.st_nlink == 2:
        stage_name = f"stage-{intent['requestId']}.snapshot"
        staged, stage_info = _read_private(directory, stage_name, intent["artifactBytes"])
        if (staged != artifact or (info.st_dev, info.st_ino) != (stage_info.st_dev, stage_info.st_ino)):
            raise StoreError("Backup staging residue differs from the published artifact")
    receipt = {
        "format": "routed-backup-receipt/v1",
        "requestId": intent["requestId"],
        "intentSha256": intent["intentSha256"],
        "previewSha256": intent["previewSha256"],
        "artifactName": intent["artifactName"],
        "artifactBytes": len(artifact),
        "artifactSha256": intent["artifactSha256"],
        "snapshotSha256": intent["snapshotSha256"],
        "sourceCheckpointSha256": intent["sourceCheckpointSha256"],
        "reconciled": reconciled,
    }
    receipt["receiptSha256"] = fingerprint(receipt)
    raw = encoded(receipt).encode("utf-8")
    if len(raw) > MAX_RECEIPT_BYTES:
        raise StoreError("Backup receipt exceeds its byte bound")
    stage = f"stage-{intent['requestId']}.receipt"
    final = f"receipt-{intent['requestId']}.json"
    if _exists(directory, final) or _exists(directory, stage):
        raise StoreError("Backup receipt already exists or has unknown staging residue")
    if guard is not None:
        guard()
    if destination_guard is not None:
        destination_guard()
    _write_exclusive(directory, stage, raw, MAX_RECEIPT_BYTES)
    if guard is not None:
        guard()
    if destination_guard is not None:
        destination_guard()
    _publish_stage(directory, stage, final, expected_bytes=len(raw),
                   expected_sha256=hashlib.sha256(raw).hexdigest())
    return receipt


def _respond(request, actor, at_value, native, binding, final_at, max_response_bytes):
    from knowledge_operations import response_bytes

    store = SimpleNamespace(contract=SimpleNamespace(binding=binding))
    raw = response_bytes(request, store, native, actor, at_value, final_at, max_response_bytes)
    return raw


def _respond_checked(request, actor, initial, at_value, native, binding, final_at, max_response_bytes,
                     *, guard, destination_guard):
    final_time = timestamp(final_at)
    if final_time < initial:
        raise StoreError("Operation clock moved backwards")
    raw = _respond(request, actor, at_value, native, binding, final_at, max_response_bytes)
    # Revalidate after serialization, since constructing the response can take
    # time and the current authorization or destination may have changed.
    guard(not_before=final_time)
    destination_guard()
    return raw


def run_writer_operation(root, host_config, host, selected, destination, request, *, actor, clock,
                         authorize, max_response_bytes):
    """Run bounded backup write/inspect/reconcile under the current host grants."""
    from knowledge_operation_backup import _checkpoint, _open_private_directory, _reject_adopted_or_protected
    from knowledge_operations import load_host
    from operation_backend import select_backend

    operation = request["operation"]
    args = request["arguments"]
    request_id = args["requestId"]
    if selected.get("connection") is not None or "path" not in selected:
        raise StoreError("Routed backup supports only a registered local SQLite authority")
    preview = _preview_basis(root, host_config, host, selected, destination, request, actor, clock,
                             authorize, max_response_bytes)
    if operation == "backup.write" and preview["previewSha256"] != args["expectedPreviewSha256"]:
        raise StoreError("Backup preview changed; an exact current preview is required")
    initial_value = clock()
    initial = timestamp(initial_value)

    def guard(not_before=initial):
        if authorize is not None and authorize() != actor:
            raise StoreError("Operation identity changed")
        if load_host(root, host_config) != host or timestamp(clock()) < not_before:
            raise StoreError("Operation host selection changed")
        _reject_adopted_or_protected(root)
        _, _, driver, _, backend_current = select_backend(root, selected)
        if driver != "sqlite":
            raise StoreError("Routed backup supports only a registered local SQLite authority")
        backend_current()

    directory = _open_private_directory(root, destination["root"])
    try:
        _same_destination(root, destination, directory, preview["destinationBindingSha256"], args["destination"])

        def destination_guard():
            _same_destination(root, destination, directory,
                              preview["destinationBindingSha256"], args["destination"])

        if operation == "backup.write":
            if any(_exists(directory, name) for name in (
                    f"intent-{request_id}.json", f"receipt-{request_id}.json",
                    f"stage-{request_id}.intent", f"stage-{request_id}.snapshot",
                    f"stage-{request_id}.receipt", f"snapshot-{request_id}.json")):
                raise StoreError("Backup request ID or residual state already exists; no retry is attempted")
            adapter, target, driver, _, backend_current = select_backend(root, selected)
            if driver != "sqlite":
                raise StoreError("Routed backup supports only a registered local SQLite authority")
            backend_current()
            store = adapter(target, expected_binding=selected["binding"], readonly=True, intake_clock=clock)
            try:
                with store.request_transaction(write=False):
                    guard()
                    blob_mode = _validate_backup_contract(store, destination, preview["authorityBinding"])
                    checkpoint = _checkpoint(store, target, destination["maxPhysicalSourceFootprintBytes"])
                    if checkpoint != preview["checkpoint"]:
                        raise StoreError("Native authority checkpoint changed after backup preview")
                    representation_bound = store.snapshot_serialized_upper_bound()
                    if representation_bound > destination["maxSnapshotBytes"]:
                        raise StoreError("Snapshot conservative representation bound exceeds its registered byte limit")
                    snapshot = store.snapshot_in_read_transaction()
                    artifact_raw = encoded(snapshot).encode("utf-8")
                    if len(artifact_raw) > destination["maxSnapshotBytes"]:
                        raise StoreError("Canonical snapshot exceeds its registered byte limit")
                    Authority = type(store)
                    Authority.validate_snapshot(snapshot)
            finally:
                store.close()
            _checkpoint_now(root, host_config, host, selected, destination, preview,
                            actor=actor, clock=clock, authorize=authorize)
            artifact_sha = hashlib.sha256(artifact_raw).hexdigest()
            intent = {
                "format": "routed-backup-intent/v1",
                "requestId": request_id,
                "destinationId": args["destination"],
                "destinationStore": destination["store"],
                "destinationBindingSha256": preview["destinationBindingSha256"],
                "hostSelectionSha256": preview["hostSelectionSha256"],
                "authorityBinding": preview["authorityBinding"],
                "sourceCheckpoint": checkpoint,
                "sourceCheckpointSha256": fingerprint(checkpoint),
                "previewSha256": preview["previewSha256"],
                "snapshotSha256": snapshot["sha256"],
                "artifactName": f"snapshot-{request_id}.json",
                "artifactBytes": len(artifact_raw),
                "artifactSha256": artifact_sha,
                "blobMode": blob_mode or "none",
                "blobCompleteness": "included" if blob_mode == "db-blob" else "not-applicable",
                "snapshotRepresentationUpperBoundBytes": representation_bound,
                "limits": {"maxSnapshotBytes": destination["maxSnapshotBytes"],
                           "maxOperationMetadataBytes": MAX_OPERATION_METADATA_BYTES},
            }
            intent["intentSha256"] = fingerprint(intent)
            intent_raw = encoded(intent).encode("utf-8")
            if len(intent_raw) > MAX_INTENT_BYTES:
                raise StoreError("Backup intent exceeds its byte bound")
            receipt_bound = len(encoded({"format": "routed-backup-receipt/v1", "requestId": request_id,
                                        "intentSha256": intent["intentSha256"],
                                        "previewSha256": intent["previewSha256"],
                                        "artifactName": intent["artifactName"],
                                        "artifactBytes": len(artifact_raw), "artifactSha256": artifact_sha,
                                        "snapshotSha256": snapshot["sha256"],
                                        "sourceCheckpointSha256": intent["sourceCheckpointSha256"],
                                        "reconciled": False, "receiptSha256": "0" * 64}).encode("utf-8"))
            if len(artifact_raw) + len(intent_raw) + receipt_bound > destination["maxSnapshotBytes"] + MAX_OPERATION_METADATA_BYTES:
                raise StoreError("Backup operation representation and residue exceed its total byte bound")
            guard()
            _same_destination(root, destination, directory, preview["destinationBindingSha256"], args["destination"])
            _write_exclusive(directory, f"stage-{request_id}.intent", intent_raw, MAX_INTENT_BYTES)
            _publish_stage(directory, f"stage-{request_id}.intent", f"intent-{request_id}.json",
                           expected_bytes=len(intent_raw), expected_sha256=hashlib.sha256(intent_raw).hexdigest())
            guard()
            _same_destination(root, destination, directory, preview["destinationBindingSha256"], args["destination"])
            _write_exclusive(directory, f"stage-{request_id}.snapshot", artifact_raw,
                             destination["maxSnapshotBytes"])
            _checkpoint_now(root, host_config, host, selected, destination, preview,
                            actor=actor, clock=clock, authorize=authorize)
            guard()
            _same_destination(root, destination, directory, preview["destinationBindingSha256"], args["destination"])
            _publish_stage(directory, f"stage-{request_id}.snapshot", intent["artifactName"],
                           expected_bytes=len(artifact_raw), expected_sha256=artifact_sha)
            guard()
            _same_destination(root, destination, directory, preview["destinationBindingSha256"], args["destination"])
            receipt = _make_receipt(directory, intent, guard=guard,
                                    destination_guard=lambda: _same_destination(
                                        root, destination, directory,
                                        preview["destinationBindingSha256"], args["destination"]))
            guard()
            _same_destination(root, destination, directory, preview["destinationBindingSha256"], args["destination"])
            final_at = clock()
            return _respond_checked(request, actor, initial, initial_value, receipt,
                                    preview["authorityBinding"], final_at, max_response_bytes,
                                    guard=guard, destination_guard=destination_guard)

        intent_name = f"intent-{request_id}.json"
        if operation == "backup.inspect" and not _exists(directory, intent_name):
            if _exists(directory, f"stage-{request_id}.intent"):
                staged_intent = _read_staged_intent(directory, request_id)
                if (staged_intent["destinationId"] != args["destination"]
                        or staged_intent["hostSelectionSha256"] != preview["hostSelectionSha256"]
                        or staged_intent["destinationBindingSha256"] != preview["destinationBindingSha256"]
                        or staged_intent["authorityBinding"] != preview["authorityBinding"]
                        or staged_intent["previewSha256"] != preview["previewSha256"]):
                    raise StoreError("Staged backup intent differs from the current host selection or preview")
                _enforce_registered_operation_bound(staged_intent, destination)
                later_residue = any(_exists(directory, name) for name in (
                    f"stage-{request_id}.snapshot", f"stage-{request_id}.receipt",
                    staged_intent["artifactName"], f"receipt-{request_id}.json"))
                native = {"format": "backup-inspection/v1", "requestId": request_id,
                          "state": "unknown-residue" if later_residue else "intent-staged-incomplete",
                          "reconcileAvailable": False}
                guard()
                _same_destination(root, destination, directory,
                                  preview["destinationBindingSha256"], args["destination"])
                final_at = clock()
                return _respond_checked(request, actor, initial, initial_value, native,
                                        preview["authorityBinding"], final_at, max_response_bytes,
                                        guard=guard, destination_guard=destination_guard)
            raise StoreError("Backup intent is unavailable; no retry or reconciliation is attempted")
        intent = _read_intent(directory, request_id)
        if intent["destinationId"] != args["destination"]:
            raise StoreError("Backup intent belongs to another registered destination")
        if (intent["hostSelectionSha256"] != preview["hostSelectionSha256"]
                or intent["destinationBindingSha256"] != preview["destinationBindingSha256"]
                or intent["authorityBinding"] != preview["authorityBinding"]):
            raise StoreError("Backup intent route differs from the current host selection")
        _enforce_registered_operation_bound(intent, destination)
        if operation == "backup.inspect":
            native = _inspect_files(directory, request_id, intent)
        else:
            if args["expectedIntentSha256"] != intent["intentSha256"]:
                raise StoreError("Exact durable backup intent basis is required")
            if preview["previewSha256"] != intent["previewSha256"]:
                raise StoreError("Backup source checkpoint or destination differs from its durable intent")
            receipt = _read_receipt(directory, request_id, intent)
            if receipt is None:
                _checkpoint_now(root, host_config, host, selected, destination, preview,
                                actor=actor, clock=clock, authorize=authorize,
                                expected_checkpoint=intent["sourceCheckpoint"])
                guard()
                _same_destination(root, destination, directory, preview["destinationBindingSha256"], args["destination"])
                receipt = _make_receipt(directory, intent, reconciled=True, guard=guard,
                                        destination_guard=lambda: _same_destination(
                                            root, destination, directory,
                                            preview["destinationBindingSha256"], args["destination"]))
            native = {"format": "backup-inspection/v1", "requestId": request_id,
                      "state": "complete", "receipt": receipt}
        guard()
        _same_destination(root, destination, directory, preview["destinationBindingSha256"], args["destination"])
        final_at = clock()
        return _respond_checked(request, actor, initial, initial_value, native,
                                preview["authorityBinding"], final_at, max_response_bytes,
                                guard=guard, destination_guard=destination_guard)
    finally:
        os.close(directory)
