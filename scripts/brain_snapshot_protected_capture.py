"""Small, ciphertext-only capture path for an explicitly injected host adapter."""
import hashlib
import io
import itertools
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import uuid

from brain_snapshot_protection import (MAX_ENTRIES,
    MAX_PLAINTEXT_BYTES, SnapshotProtectionAdapter,
    protected_peak_bound, seal_payload)
from brain_protection import MAX_PROTECTED_ENVELOPE
from knowledge_policy import fingerprint


def prepare_effect_details(plan, destination, *, store, adapter):
    """Bind the exact bounded source and retained route before reserving bytes."""
    import brain_snapshot as snapshot
    from brain_snapshot_v2 import plan_git_artifacts, parse_index
    from brain_storage_admission import load_registration

    root, authorities, exclusions = snapshot._validate_plan(plan, bounded=True)
    registration = load_registration(root)
    if registration is None:
        raise snapshot.SnapshotError("Adopted snapshot registration is unavailable")
    adapter.verify(root=root, registration=registration)
    store._snapshot_route_guard(require_active=False)
    destination = Path(destination).absolute()
    if destination.exists() or destination.is_symlink():
        raise snapshot.SnapshotError("Snapshot destination must not already exist")
    retained_id = getattr(store, "_snapshot_retained_root_id", None)
    retained_kind = getattr(store, "_snapshot_retained_root_kind", None)
    retained_relative_parent = getattr(store, "_snapshot_retained_relative_parent", None)
    retained_parent_identity = getattr(store, "_snapshot_parent_identity", None)
    if (not isinstance(retained_id, str) or retained_kind not in ("snapshot", "backup")
            or not isinstance(retained_relative_parent, str)
            or not isinstance(retained_parent_identity, tuple) or len(retained_parent_identity) != 2):
        raise snapshot.SnapshotError("Registered snapshot route identity is unavailable")
    relative_destination = PurePosixPath(retained_relative_parent, destination.name)
    relative_text = str(relative_destination)
    if (len(relative_text.encode("utf-8")) > 4096 or ".." in relative_destination.parts
            or relative_text.startswith("/")):
        raise snapshot.SnapshotError("Snapshot destination path exceeds its private route bound")

    git_dir_pin = getattr(store, "_snapshot_git_dir_pin", None)
    if git_dir_pin is None:
        git_dir_pin = snapshot._v2_pin_git_directory(root)
        store._snapshot_git_dir_pin = git_dir_pin
    snapshot._v2_verify_git_directory(root, git_dir_pin)
    object_format = snapshot._v2_git(root, "rev-parse", "--show-object-format=storage",
                                     output_limit=128).decode("ascii").strip()
    before_git = snapshot._v2_git_state(root, object_format)
    indexed_entries = parse_index(before_git["index"], object_format=object_format)
    reachable_ids = snapshot._v2_object_ids(root, before_git["refs"], before_git["head"],
                                            object_format=object_format)
    if not {entry["oid"] for entry in indexed_entries}.issubset(set(reachable_ids)):
        raise snapshot.SnapshotError(
            "Protected snapshot capture requires every indexed Git object to be reachable from a selected ref")
    if len(reachable_ids) > MAX_ENTRIES:
        raise snapshot.SnapshotError("Protected snapshot exceeds its bounded Git-object count")
    sizes = snapshot._v2_object_sizes(root, reachable_ids)
    refs_bytes = "".join(f"{row['oid']} {row['name']}\n" for row in before_git["refs"]).encode("ascii")
    git_plan = plan_git_artifacts(sizes.values(), refs_bytes,
        pack_representation="non-delta-no-reuse/v1", object_format=object_format)
    if len(reachable_ids) != git_plan["objects"]:
        raise snapshot.SnapshotError("Git object inventory does not match its planned count")
    files = snapshot._inventory(root, authorities, exclusions, bounded=True)
    if len(files) > MAX_ENTRIES:
        raise snapshot.SnapshotError("Protected snapshot exceeds its bounded repository file count")
    snapshots = [snapshot._authority_snapshot(entry, bounded=True) for entry in authorities]
    captured = [{"id": entry["id"], "target": entry["target"], **value}
                for entry, value in zip(authorities, snapshots)]
    object_inventory = ("\n".join(reachable_ids) + "\n").encode("ascii")
    plan_sha256 = fingerprint(plan)
    source_basis_sha256 = fingerprint({
        "git": {"head": before_git["head"], "headRef": before_git["headRef"],
                "refs": before_git["refs"],
                "indexSha256": hashlib.sha256(before_git["index"]).hexdigest(),
                "objectInventorySha256": hashlib.sha256(object_inventory).hexdigest(),
                "objectCount": len(reachable_ids), "objectBytes": git_plan["objectBytes"]},
        "files": files, "authorities": captured,
        "registration": fingerprint(registration)})
    return {
        "format": "protected-snapshot-capture-effect/v1",
        "planSha256": plan_sha256,
        "sourceBasisSha256": source_basis_sha256,
        "registrationSha256": fingerprint(registration),
        "providerActorSha256": adapter.provider_actor_sha256,
        "profileSha256": adapter.profile_sha256,
        "requirementsSha256": adapter.requirements_sha256,
        "retainedRoute": {"id": retained_id, "kind": retained_kind,
                          "destination": relative_text,
                          "parentDevice": retained_parent_identity[0],
                          "parentInode": retained_parent_identity[1]},
    }


def _read_source(snapshot, path, descriptor):
    source = Path(path).absolute()
    output, result = snapshot._v2_source_worker().read_bytes(
        source, expected_bytes=descriptor["bytes"])
    if (len(output) != descriptor["bytes"] or result["sha256"] != descriptor["sha256"]
            or result["sqlite"]):
        raise snapshot.SnapshotError("Protected snapshot source changed while reading")
    return output


def _ustar_payload_upper_bound(sizes):
    """Return tarfile's exact conservative USTAR stream bound for entry sizes."""
    from brain_snapshot import SnapshotError

    total = 1024  # USTAR end-of-archive blocks.
    for size in sizes:
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise SnapshotError("Protected snapshot entry has an invalid size")
        total += 512 + ((size + 511) // 512) * 512
    record_size = tarfile.RECORDSIZE
    return ((total + record_size - 1) // record_size) * record_size


def _tar_payload(entries, *, upper_bound):
    import brain_snapshot as snapshot

    stream = io.BytesIO()
    try:
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, raw in entries:
                info = tarfile.TarInfo(name)
                info.size = len(raw)
                info.mode = 0o600
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 0
                archive.addfile(info, io.BytesIO(raw))
                if stream.tell() > upper_bound or stream.tell() > MAX_PLAINTEXT_BYTES:
                    raise snapshot.SnapshotError("Protected snapshot archive exceeded its preflight bound")
    except (OSError, tarfile.TarError) as exc:
        raise snapshot.SnapshotError("Protected snapshot archive could not be encoded") from exc
    result = stream.getvalue()
    if len(result) > upper_bound or len(result) > MAX_PLAINTEXT_BYTES:
        raise snapshot.SnapshotError("Protected snapshot archive exceeded its fixed byte bound")
    return result


def _pack_header(pack, *, object_format, object_count):
    from brain_snapshot import SnapshotError

    hash_bytes = 20 if object_format == "sha1" else 32
    if (len(pack) < 12 + hash_bytes or pack[:4] != b"PACK"
            or int.from_bytes(pack[4:8], "big") not in (2, 3)
            or int.from_bytes(pack[8:12], "big") != object_count
            or hashlib.new(object_format, pack[:-hash_bytes]).digest() != pack[-hash_bytes:]):
        raise SnapshotError("Protected snapshot Git pack failed its bounded integrity check")


def capture_v1(plan, destination, *, store, reservation, adapter,
               expected_effect_details, fault=None):
    """Capture a small bounded snapshot without writing plaintext to disk."""
    import brain_snapshot as snapshot
    from brain_snapshot_v2 import plan_git_artifacts, parse_index

    if not isinstance(adapter, SnapshotProtectionAdapter):
        raise snapshot.SnapshotError("Trusted snapshot protection adapter is unavailable")
    root, authorities, exclusions = snapshot._validate_plan(plan, bounded=True)
    from brain_storage_admission import load_registration
    registration = load_registration(root)
    if registration is None:
        raise snapshot.SnapshotError("Adopted snapshot registration is unavailable")
    adapter.verify(root=root, registration=registration)
    destination = Path(destination).absolute()
    resolved = destination.resolve()
    if destination.exists() or destination.is_symlink() or snapshot._within(resolved, root) or any(
            snapshot._within(resolved, entry["source"]) or snapshot._within(entry["source"], resolved)
            for entry in authorities):
        raise snapshot.SnapshotError("Snapshot destination must be new and outside all sources")
    if not destination.parent.is_dir():
        raise snapshot.SnapshotError("Snapshot parent must already exist")
    active = getattr(store, "_storage_admission_reservation", None)
    if (not isinstance(reservation, dict) or not isinstance(active, tuple) or len(active) < 4
            or active[2] != reservation.get("id") or reservation.get("state") != "reserved"):
        raise snapshot.SnapshotError("Protected snapshot reservation is unavailable")
    parent_identity = getattr(store, "_snapshot_parent_identity", None)
    actual_route = expected_effect_details.get("retainedRoute")
    actual_relative = str(PurePosixPath(
        str(getattr(store, "_snapshot_retained_relative_parent", "")), destination.name))
    if (not isinstance(actual_route, dict)
            or actual_route.get("id") != getattr(store, "_snapshot_retained_root_id", None)
            or actual_route.get("kind") != getattr(store, "_snapshot_retained_root_kind", None)
            or actual_route.get("destination") != actual_relative
            or not isinstance(parent_identity, tuple) or len(parent_identity) != 2
            or actual_route.get("parentDevice") != parent_identity[0]
            or actual_route.get("parentInode") != parent_identity[1]):
        raise snapshot.SnapshotError("Protected snapshot retained route changed after reservation")

    git_dir_pin = getattr(store, "_snapshot_git_dir_pin", None)
    if git_dir_pin is None:
        git_dir_pin = snapshot._v2_pin_git_directory(root)
        store._snapshot_git_dir_pin = git_dir_pin
    object_format = snapshot._v2_git(root, "rev-parse", "--show-object-format=storage",
                                     output_limit=128).decode("ascii").strip()
    before_git = snapshot._v2_git_state(root, object_format)
    indexed_entries = parse_index(before_git["index"], object_format=object_format)
    reachable_ids = snapshot._v2_object_ids(root, before_git["refs"], before_git["head"],
                                            object_format=object_format)
    indexed_oids = {entry["oid"] for entry in indexed_entries}
    if not indexed_oids.issubset(set(reachable_ids)):
        raise snapshot.SnapshotError(
            "Protected snapshot capture requires every indexed Git object to be reachable from a selected ref")
    object_ids = reachable_ids
    if len(object_ids) > MAX_ENTRIES:
        raise snapshot.SnapshotError("Protected snapshot exceeds its bounded Git-object count")
    sizes = snapshot._v2_object_sizes(root, object_ids)
    refs_bytes = "".join(f"{row['oid']} {row['name']}\n" for row in before_git["refs"]).encode("ascii")
    git_plan = plan_git_artifacts(sizes.values(), refs_bytes,
        pack_representation="non-delta-no-reuse/v1", object_format=object_format)
    if len(object_ids) != git_plan["objects"]:
        raise snapshot.SnapshotError("Git object inventory does not match its planned count")
    files = snapshot._inventory(root, authorities, exclusions, bounded=True)
    if len(files) > MAX_ENTRIES:
        raise snapshot.SnapshotError("Protected snapshot exceeds its bounded repository file count")
    snapshots = [snapshot._authority_snapshot(entry, bounded=True) for entry in authorities]
    captured = [{"id": entry["id"], "target": entry["target"], **value}
                for entry, value in zip(authorities, snapshots)]
    sources = {}
    unique_objects = {}
    for relative, descriptor in files.items():
        if descriptor["type"] == "file":
            unique_objects[descriptor["sha256"]] = descriptor["bytes"]
            if len(unique_objects) > MAX_ENTRIES:
                raise snapshot.SnapshotError("Protected snapshot exceeds its bounded file-object count")
            sources.setdefault(descriptor["sha256"], (root / relative, descriptor))
    for entry, value in zip(authorities, snapshots):
        if entry["kind"] == "sqlite-authority":
            continue
        for relative, descriptor in value["files"].items():
            if descriptor["type"] == "file":
                unique_objects[descriptor["sha256"]] = descriptor["bytes"]
                if len(unique_objects) > MAX_ENTRIES:
                    raise snapshot.SnapshotError("Protected snapshot exceeds its bounded file-object count")
                source = entry["source"] if relative == "." else entry["source"] / relative
                sources.setdefault(descriptor["sha256"], (source, descriptor))
    if len(unique_objects) > MAX_ENTRIES:
        raise snapshot.SnapshotError("Protected snapshot exceeds its bounded file-object count")
    object_inventory = ("\n".join(object_ids) + "\n").encode("ascii")
    plan_sha256 = fingerprint(plan)
    source_basis_sha256 = fingerprint({"git": {"head": before_git["head"],
        "headRef": before_git["headRef"], "refs": before_git["refs"],
        "indexSha256": hashlib.sha256(before_git["index"]).hexdigest(),
        "objectInventorySha256": hashlib.sha256(object_inventory).hexdigest(),
        "objectCount": len(object_ids), "objectBytes": git_plan["objectBytes"]},
        "files": files, "authorities": captured, "registration": fingerprint(registration)})
    if (expected_effect_details.get("planSha256") != plan_sha256
            or expected_effect_details.get("sourceBasisSha256") != source_basis_sha256
            or expected_effect_details.get("registrationSha256") != fingerprint(registration)
            or expected_effect_details.get("profileSha256") != adapter.profile_sha256
            or expected_effect_details.get("requirementsSha256") != adapter.requirements_sha256):
        raise snapshot.SnapshotError("Protected snapshot source changed after reservation")
    preflight_manifest = {"protocolVersion": "3.0", "format": "protected-snapshot-payload/v1",
        "id": plan["id"], "planSha256": plan_sha256, "sourceBasisSha256": source_basis_sha256,
        "git": {"objectFormat": object_format, "head": before_git["head"],
            "headRef": before_git["headRef"], "refs": before_git["refs"],
            "objectInventorySha256": hashlib.sha256(object_inventory).hexdigest(),
            "objectInventoryBytes": len(object_inventory), "objectCount": len(object_ids),
            "objectBytes": git_plan["objectBytes"], "packSha256": "0" * 64,
            "packBytes": git_plan["packBytesUpperBound"],
            "packRepresentation": git_plan["packRepresentation"],
            "index": {"format": "git-index-bytes/v1",
                      "sha256": hashlib.sha256(before_git["index"]).hexdigest(),
                      "bytes": len(before_git["index"])}},
        "files": files, "authorities": captured, "exclusions": exclusions,
        "consistency": {"mode": "before-after-stability-check", "globalTransaction": False,
                        "quiescence": plan["quiescence"]},
        "restoreMode": "separate-target-with-standby-authorities",
        # Reserve the fixed-width checksum field that the final manifest adds.
        "sha256": "0" * 64}
    manifest_upper = snapshot._json(preflight_manifest)
    if len(manifest_upper) > MAX_PLAINTEXT_BYTES:
        raise snapshot.SnapshotError("Protected snapshot metadata exceeds its archive byte bound")
    raw_upper = _ustar_payload_upper_bound(itertools.chain(
        (git_plan["packBytesUpperBound"], len(before_git["index"]),
         len(object_inventory), len(manifest_upper)), unique_objects.values()))
    if raw_upper > MAX_PLAINTEXT_BYTES:
        raise snapshot.SnapshotError("Protected snapshot exceeds its fixed plaintext archive bound")
    protected_bound = protected_peak_bound(raw_upper)
    store._snapshot_route_guard()
    store._storage_admission_require(protected_bound)
    if fault:
        fault("after-preflight")

    pack = snapshot._v2_git(root, "pack-objects", "--stdout", "--all", "--no-reuse-delta",
        "--no-reuse-object", "--window=0", "--depth=0", "--threads=1", "--window-memory=16m",
        output_limit=git_plan["packBytesUpperBound"], timeout=120)
    if len(pack) > git_plan["packBytesUpperBound"]:
        raise snapshot.SnapshotError("Protected Git pack exceeded its planned bound")
    _pack_header(pack, object_format=object_format, object_count=len(object_ids))
    object_bytes = {}
    for digest, (source, descriptor) in sources.items():
        object_bytes[digest] = _read_source(snapshot, source, descriptor)
    manifest = dict(preflight_manifest)
    manifest["git"] = {**manifest["git"], "packSha256": hashlib.sha256(pack).hexdigest(),
                        "packBytes": len(pack)}
    manifest.pop("sha256")
    manifest["sha256"] = fingerprint(manifest)
    manifest_bytes = snapshot._json(manifest)
    if len(manifest_bytes) > len(manifest_upper) or len(manifest_bytes) > MAX_PLAINTEXT_BYTES:
        raise snapshot.SnapshotError("Protected snapshot manifest exceeded its preflight bound")
    entries = [("manifest.json", manifest_bytes), ("git/index.bin", before_git["index"]),
               ("git/repository.pack", pack), ("git/object-inventory", object_inventory)]
    entries.extend((f"objects/{digest}", data) for digest, data in sorted(object_bytes.items()))
    raw_upper = _ustar_payload_upper_bound(len(data) for _name, data in entries)
    if len(entries) > MAX_ENTRIES or raw_upper > MAX_PLAINTEXT_BYTES:
        raise snapshot.SnapshotError("Protected snapshot archive exceeds its fixed output bound")
    payload = _tar_payload(entries, upper_bound=raw_upper)
    del entries
    object_bytes.clear()

    def source_guard():
        store._snapshot_route_guard()
        current_registration = load_registration(root)
        if current_registration is None:
            raise snapshot.SnapshotError("Snapshot registration was removed during capture")
        adapter.verify(root=root, registration=current_registration)
        snapshot._v2_verify_git_directory(root, git_dir_pin)
        current_git = snapshot._v2_git_state(root, object_format)
        if (before_git != current_git or files != snapshot._inventory(root, authorities, exclusions, bounded=True)
                or snapshots != [snapshot._authority_snapshot(entry, bounded=True) for entry in authorities]):
            raise snapshot.SnapshotError("Source changed during protected capture")

    source_guard()
    sealed = seal_payload(payload, adapter=adapter, plan_sha256=plan_sha256,
                          source_basis_sha256=source_basis_sha256)
    if sealed["peakBoundBytes"] > protected_bound:
        raise snapshot.SnapshotError("Protected ciphertext exceeded its reservation bound")
    del payload

    parent_fd = store._snapshot_parent_fd
    parent_info = os.fstat(parent_fd)
    if (parent_info.st_dev, parent_info.st_ino) != store._snapshot_parent_identity:
        raise snapshot.SnapshotError("Registered snapshot destination parent changed")
    stage_name = ".brain-snapshot-protected-v1-" + uuid.uuid4().hex
    stage_created, stage_fd, stage_identity, published = False, None, None, False
    try:
        store._snapshot_route_guard()
        os.mkdir(stage_name, mode=0o700, dir_fd=parent_fd)
        stage_created = True
        created = os.stat(stage_name, dir_fd=parent_fd, follow_symlinks=False)
        stage_identity = (created.st_dev, created.st_ino)
        stage_fd = os.open(stage_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        snapshot._verify_snapshot_stage(parent_fd, stage_name, stage_fd, stage_identity)
        outputs = [(row["name"], row["bytes"]) for row in sealed["chunks"]]
        outputs.append(("manifest.json", sealed["manifestBytes"]))
        for output_index, (name, raw) in enumerate(outputs):
            source_guard()
            adapter.reauthorize(sealed["chunks"][output_index]["envelope"]
                                 if output_index < len(sealed["chunks"])
                                 else sealed["chunks"][0]["envelope"])
            charge = store._storage_admission_consume(len(raw))
            snapshot._v2_stage_write(stage_fd, name, raw)
            store._storage_admission_complete_external(charge, actual_bytes=len(raw))
        if fault:
            fault("before-recheck")
        source_guard()
        total = 0
        for name, _raw in outputs:
            info = snapshot._v2_stage_stat(stage_fd, name, max_bytes=MAX_PROTECTED_ENVELOPE + 2 * 1024 * 1024)
            total += info.st_size
        if total > protected_bound:
            raise snapshot.SnapshotError("Protected snapshot exceeded its preflight peak bound")
        for row in sealed["chunks"]:
            adapter.reauthorize(row["envelope"])
        source_guard()
        try:
            os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise snapshot.SnapshotError("Snapshot destination appeared during capture")
        snapshot._verify_snapshot_stage(parent_fd, stage_name, stage_fd, stage_identity)
        for row in sealed["chunks"]:
            adapter.reauthorize(row["envelope"])
        os.fsync(stage_fd)
        os.rename(stage_name, destination.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        published = True
        published_info = os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        if (published_info.st_dev, published_info.st_ino) != stage_identity:
            raise snapshot.SnapshotError("Published protected snapshot does not match its pinned stage")
        if fault:
            fault("after-publish")
        source_guard()
        for row in sealed["chunks"]:
            adapter.reauthorize(row["envelope"])
        store._storage_admission_precommit()
        os.fsync(parent_fd)
        return sealed["manifest"]
    finally:
        if not published and stage_created and stage_fd is not None and stage_identity is not None:
            try:
                snapshot._verify_snapshot_stage(parent_fd, stage_name, stage_fd, stage_identity)
                for name in os.listdir(stage_fd):
                    info = os.stat(name, dir_fd=stage_fd, follow_symlinks=False)
                    if not stat.S_ISREG(info.st_mode):
                        raise snapshot.SnapshotError("Protected staging contains an unexpected entry")
                    os.unlink(name, dir_fd=stage_fd)
                snapshot._verify_snapshot_stage(parent_fd, stage_name, stage_fd, stage_identity)
                os.rmdir(stage_name, dir_fd=parent_fd)
            except (OSError, snapshot.SnapshotError):
                # Residue stays inside registered inventory; effect cleanup marks it unknown.
                pass
        if stage_fd is not None:
            try:
                os.close(stage_fd)
            except OSError:
                pass
