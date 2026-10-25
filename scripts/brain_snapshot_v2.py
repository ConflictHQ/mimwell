"""Pure bounded codec/planning primitives for a future admitted snapshot v2.

This module intentionally performs no I/O and invokes no subprocesses. It is not
an alternate restore writer and does not make adopted restore available.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Iterable

from brain_snapshot import SnapshotError
from knowledge_policy import fingerprint


PROTOCOL = "2.0"
MAX_INDEX_ENTRIES = 100_000
MAX_INDEX_RAW_BYTES = 64 * 1024 * 1024
MAX_INDEX_PATH_BYTES = 4096
MAX_INDEX_PATH_TOTAL = 24 * 1024 * 1024
MAX_STAGED_BLOB_BYTES = 128 * 1024 * 1024
MAX_STAGED_BLOBS_BYTES = 512 * 1024 * 1024
MAX_GIT_OBJECTS = 2_000_000
MAX_GIT_OBJECT_BYTES = 8 * 1024 * 1024 * 1024
MAX_GIT_OBJECT_BYTES_SINGLE = 512 * 1024 * 1024
MAX_BUNDLE_BYTES = 12 * 1024 * 1024 * 1024
MAX_INDEX_FILE_BYTES = 256 * 1024 * 1024
MAX_RESTORE_SQLITE_TOTAL_BYTES = 8 * 1024 * 1024 * 1024
MAX_RESTORE_RETAINED_TOTAL_BYTES = 64 * 1024 * 1024 * 1024
_OBJECT_FORMATS = {"sha1": ("sha1", 40), "sha256": ("sha256", 64)}
_HEX = re.compile(r"^[0-9a-f]+$")
_MODES = {b"100644", b"100755", b"120000"}
_PACK_REPRESENTATION = "non-delta-no-reuse/v1"
_WORKING_INDEX_FORMAT = "git-index-v2-no-extensions/v1"


def _object_format(value: str) -> tuple[str, int]:
    if not isinstance(value, str) or len(value) > 6 or value not in _OBJECT_FORMATS:
        raise SnapshotError("Unsupported Git object format")
    return _OBJECT_FORMATS[value]


def _path_parts(path: bytes) -> tuple[bytes, ...]:
    if (not isinstance(path, bytes) or not path or len(path) > MAX_INDEX_PATH_BYTES
            or path.startswith(b"/") or b"\x00" in path):
        raise SnapshotError("Git index path is outside the supported byte-path bounds")
    parts = tuple(path.split(b"/"))
    if (len(parts) > 128 or any(part in (b"", b".", b"..") or part.lower() == b".git"
                                 for part in parts)):
        raise SnapshotError("Git index path is unsafe or too deep")
    return parts


def _split_index_records(index_bytes: bytes) -> list[bytes]:
    """The caller must establish the record-count bound before this allocation."""
    return index_bytes[:-1].split(b"\0")


def parse_index(index_bytes: bytes, *, object_format: str = "sha1") -> list[dict]:
    """Parse exact `git ls-files --stage -z` bytes without decoding paths."""
    _, oid_length = _object_format(object_format)
    if not isinstance(index_bytes, bytes) or len(index_bytes) > MAX_INDEX_RAW_BYTES:
        raise SnapshotError("Git index listing exceeds its byte bound")
    if not index_bytes:
        return []
    if not index_bytes.endswith(b"\0"):
        raise SnapshotError("Git index listing is not NUL terminated")

    record_count = index_bytes.count(b"\0")
    if record_count > MAX_INDEX_ENTRIES:
        raise SnapshotError("Git index exceeds its entry-count bound")
    rows = _split_index_records(index_bytes)
    entries = []
    paths = set()
    total_path_bytes = 0
    previous = None
    for row in rows:
        header, separator, path = row.partition(b"\t")
        fields = header.split(b" ")
        if not separator or len(fields) != 3 or fields[0] not in _MODES:
            raise SnapshotError("Git index entry has an unsupported mode or shape")
        mode, oid_raw, stage_raw = fields
        try:
            oid_text = oid_raw.decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise SnapshotError("Git index entry has a non-ASCII object ID") from exc
        if len(oid_raw) != oid_length or not _HEX.fullmatch(oid_text):
            raise SnapshotError("Git index entry has an invalid object ID")
        if stage_raw != b"0":
            raise SnapshotError("Unmerged Git index stages are unsupported")
        parts = _path_parts(path)
        total_path_bytes += len(path)
        if total_path_bytes > MAX_INDEX_PATH_TOTAL:
            raise SnapshotError("Git index paths exceed their aggregate byte bound")
        if path in paths or (previous is not None and path <= previous):
            raise SnapshotError("Git index paths are duplicate or not canonically ordered")
        paths.add(path)
        previous = path
        entries.append({"mode": mode.decode("ascii"), "oid": oid_raw.decode("ascii"),
                        "path": path, "parts": parts})

    # A file/symlink cannot also be a parent directory of another index path.
    for entry in entries:
        for length in range(1, len(entry["parts"])):
            if b"/".join(entry["parts"][:length]) in paths:
                raise SnapshotError("Git index contains a file/directory path collision")
    return entries


def _git_oid(data: bytes, algorithm: str) -> str:
    header = b"blob " + str(len(data)).encode("ascii") + b"\0"
    digest = hashlib.new(algorithm)
    digest.update(header)
    digest.update(data)
    return digest.hexdigest()


def encode_index(index_bytes: bytes, staged_blobs: dict[str, bytes], *,
                 object_format: str = "sha1") -> dict:
    """Build a canonical manifest and content-addressed staged-blob mapping.

    `staged_blobs` is an in-memory result supplied by a future bounded reader;
    this function neither runs Git nor reads/writes files.
    """
    algorithm, _ = _object_format(object_format)
    if type(staged_blobs) is not dict:
        raise SnapshotError("Staged Git blobs have invalid shape")
    entries = parse_index(index_bytes, object_format=object_format)
    needed = {entry["oid"] for entry in entries}
    if len(staged_blobs) > MAX_INDEX_ENTRIES:
        raise SnapshotError("Staged Git blob map exceeds its entry-count bound")
    if set(staged_blobs) != needed:
        raise SnapshotError("Staged blob set does not exactly match index objects")

    symlink_oids = {entry["oid"] for entry in entries if entry["mode"] == "120000"}
    blob_table: dict[str, dict] = {}
    data_by_sha: dict[str, bytes] = {}
    total = 0
    for oid in sorted(needed):
        data = staged_blobs[oid]
        if not isinstance(data, bytes) or len(data) > MAX_STAGED_BLOB_BYTES:
            raise SnapshotError("Staged Git blob exceeds its individual byte bound")
        if _git_oid(data, algorithm) != oid:
            raise SnapshotError("Staged Git blob does not match its object ID")
        total += len(data)
        if total > MAX_STAGED_BLOBS_BYTES:
            raise SnapshotError("Staged Git blobs exceed their aggregate byte bound")
        if oid in symlink_oids and (not data or b"\0" in data):
            raise SnapshotError("Git symlink blob has an unsupported target")
        sha = hashlib.sha256(data).hexdigest()
        blob_table[oid] = {"sha256": sha, "bytes": len(data)}
        data_by_sha[sha] = data

    manifest = {
        "protocolVersion": PROTOCOL,
        "objectFormat": object_format,
        "indexSha256": hashlib.sha256(index_bytes).hexdigest(),
        "entries": [{"mode": entry["mode"], "oid": entry["oid"],
                     "pathB64": base64.b64encode(entry["path"]).decode("ascii")}
                    for entry in entries],
        "blobs": blob_table,
    }
    manifest["sha256"] = fingerprint(manifest)
    raw_manifest = json.dumps(manifest, ensure_ascii=True, sort_keys=True,
                              separators=(",", ":"), allow_nan=False).encode("ascii")
    if len(raw_manifest) > MAX_INDEX_RAW_BYTES:
        raise SnapshotError("Git index manifest exceeds its byte bound")
    return {"manifest": manifest, "blobs": data_by_sha}


def validate_index_package(package: dict) -> dict[str, bytes]:
    """Validate a decoded manifest/blob package and return bytes by Git OID.

    Callers must cap the encoded manifest before JSON decoding. This function
    validates shallow shape and aggregate sizes before base64 decoding or
    canonical JSON serialization/fingerprinting.
    """
    if not isinstance(package, dict) or len(package) != 2 or set(package) != {"manifest", "blobs"}:
        raise SnapshotError("Git index package has unsupported fields")
    manifest, blobs = package["manifest"], package["blobs"]
    required = {"protocolVersion", "objectFormat", "indexSha256", "entries", "blobs", "sha256"}
    if not isinstance(manifest, dict) or len(manifest) != len(required) or set(manifest) != required:
        raise SnapshotError("Git index manifest has unsupported fields")
    if (not isinstance(manifest["protocolVersion"], str)
            or len(manifest["protocolVersion"]) != len(PROTOCOL)
            or manifest["protocolVersion"] != PROTOCOL):
        raise SnapshotError("Unsupported Git index manifest protocol")
    algorithm, oid_length = _object_format(manifest["objectFormat"])
    if (not isinstance(manifest["indexSha256"], str) or len(manifest["indexSha256"]) != 64
            or not re.fullmatch(r"[0-9a-f]{64}", manifest["indexSha256"])
            or not isinstance(manifest["sha256"], str) or len(manifest["sha256"]) != 64
            or not re.fullmatch(r"[0-9a-f]{64}", manifest["sha256"])):
        raise SnapshotError("Git index digest is invalid")
    entries, descriptors = manifest["entries"], manifest["blobs"]
    if not isinstance(entries, list) or len(entries) > MAX_INDEX_ENTRIES or not isinstance(descriptors, dict):
        raise SnapshotError("Git index manifest exceeds its structural bounds")
    if not isinstance(blobs, dict) or len(descriptors) > len(entries) or len(blobs) > len(entries):
        raise SnapshotError("Git index blob package has invalid shape")

    # Validate all shallow scalar shapes/counts before decoding base64, hashing
    # blobs, or asking json.dumps/fingerprint to traverse the manifest.
    encoded_path_total = 0
    for entry in entries:
        if (not isinstance(entry, dict) or len(entry) != 3 or set(entry) != {"mode", "oid", "pathB64"}
                or not isinstance(entry["mode"], str) or len(entry["mode"]) != 6
                or entry["mode"] not in {"100644", "100755", "120000"}
                or not isinstance(entry["oid"], str) or len(entry["oid"]) != oid_length
                or not _HEX.fullmatch(entry["oid"]) or not isinstance(entry["pathB64"], str)):
            raise SnapshotError("Git index entry has invalid bounded scalar fields")
        if len(entry["pathB64"]) > 4 * ((MAX_INDEX_PATH_BYTES + 2) // 3):
            raise SnapshotError("Git index path encoding exceeds its individual byte bound")
        encoded_path_total += len(entry["pathB64"])
        if encoded_path_total > (MAX_INDEX_PATH_TOTAL * 4 + 2) // 3 + MAX_INDEX_ENTRIES * 4:
            raise SnapshotError("Git index path encodings exceed their aggregate bound")
    descriptor_total = 0
    for oid, descriptor in descriptors.items():
        if (not isinstance(oid, str) or len(oid) != oid_length or not _HEX.fullmatch(oid)
                or not isinstance(descriptor, dict) or len(descriptor) != 2
                or set(descriptor) != {"sha256", "bytes"}
                or not isinstance(descriptor["sha256"], str) or len(descriptor["sha256"]) != 64
                or not re.fullmatch(r"[0-9a-f]{64}", descriptor["sha256"])
                or type(descriptor["bytes"]) is not int or not 0 <= descriptor["bytes"] <= MAX_STAGED_BLOB_BYTES):
            raise SnapshotError("Git blob descriptor has invalid bounded scalar fields")
        descriptor_total += descriptor["bytes"]
        if descriptor_total > MAX_STAGED_BLOBS_BYTES:
            raise SnapshotError("Staged Git blobs exceed their aggregate byte bound")
    blob_total = 0
    for sha, data in blobs.items():
        if (not isinstance(sha, str) or len(sha) != 64 or not _HEX.fullmatch(sha)
                or not isinstance(data, bytes) or len(data) > MAX_STAGED_BLOB_BYTES):
            raise SnapshotError("Git index blob bytes exceed their individual bound")
        blob_total += len(data)
        if blob_total > MAX_STAGED_BLOBS_BYTES:
            raise SnapshotError("Git index blob bytes exceed their aggregate bound")

    # Now the complete object graph is shallow and bounded; canonical encoding
    # and recursive fingerprinting cannot encounter attacker-sized nesting.
    try:
        manifest_bytes = json.dumps(manifest, ensure_ascii=True, sort_keys=True,
                                    separators=(",", ":"), allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise SnapshotError("Git index manifest is not bounded JSON") from exc
    if len(manifest_bytes) > MAX_INDEX_RAW_BYTES:
        raise SnapshotError("Git index manifest exceeds its byte bound")
    if manifest["sha256"] != fingerprint({key: value for key, value in manifest.items() if key != "sha256"}):
        raise SnapshotError("Git index manifest digest is invalid")

    index_bytes = bytearray()
    reconstructed_blobs: dict[str, bytes] = {}
    paths = set()
    total_paths = 0
    previous = None
    for entry in entries:
        try:
            mode = entry["mode"].encode("ascii")
            oid_raw = entry["oid"].encode("ascii")
            path = base64.b64decode(entry["pathB64"], validate=True)
        except (AttributeError, TypeError, UnicodeEncodeError, ValueError) as exc:
            raise SnapshotError("Git index entry encoding is invalid") from exc
        if mode not in _MODES or len(oid_raw) != oid_length or not _HEX.fullmatch(oid_raw.decode("ascii")):
            raise SnapshotError("Git index entry mode or object ID is invalid")
        _path_parts(path)
        if base64.b64encode(path).decode("ascii") != entry["pathB64"]:
            raise SnapshotError("Git index path encoding is not canonical")
        if path in paths or (previous is not None and path <= previous):
            raise SnapshotError("Git index paths are duplicate or not canonically ordered")
        paths.add(path)
        previous = path
        total_paths += len(path)
        if total_paths > MAX_INDEX_PATH_TOTAL:
            raise SnapshotError("Git index paths exceed their aggregate byte bound")
        encoded_entry = mode + b" " + oid_raw + b" 0\t" + path + b"\0"
        if len(index_bytes) + len(encoded_entry) > MAX_INDEX_RAW_BYTES:
            raise SnapshotError("Reconstructed Git index exceeds its byte bound")
        index_bytes.extend(encoded_entry)
        oid = entry["oid"]
        if oid not in descriptors:
            raise SnapshotError("Git index references a missing blob descriptor")
        if oid not in reconstructed_blobs:
            descriptor = descriptors[oid]
            if not isinstance(descriptor, dict) or set(descriptor) != {"sha256", "bytes"}:
                raise SnapshotError("Git blob descriptor has unsupported fields")
            sha = descriptor["sha256"]
            size = descriptor["bytes"]
            if (not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha)
                    or type(size) is not int or size < 0 or size > MAX_STAGED_BLOB_BYTES):
                raise SnapshotError("Git blob descriptor is invalid")
            data = blobs.get(sha)
            if not isinstance(data, bytes) or len(data) != size or hashlib.sha256(data).hexdigest() != sha:
                raise SnapshotError("Git staged blob is missing or corrupt")
            if _git_oid(data, algorithm) != oid:
                raise SnapshotError("Git staged blob does not match its object ID")
            reconstructed_blobs[oid] = data
        if mode == b"120000":
            link_data = reconstructed_blobs[oid]
            if not link_data or b"\0" in link_data:
                raise SnapshotError("Git symlink blob has an unsupported target")
    for path in paths:
        components = path.split(b"/")
        for length in range(1, len(components)):
            if b"/".join(components[:length]) in paths:
                raise SnapshotError("Git index contains a file/directory path collision")
    if set(descriptors) != set(reconstructed_blobs):
        raise SnapshotError("Git index contains an unreferenced blob descriptor")
    if set(blobs) != {item["sha256"] for item in descriptors.values()}:
        raise SnapshotError("Git index package contains unreferenced blob bytes")
    if len(index_bytes) > MAX_INDEX_RAW_BYTES or hashlib.sha256(index_bytes).hexdigest() != manifest["indexSha256"]:
        raise SnapshotError("Reconstructed Git index does not match its captured digest")
    if sum(len(value) for value in reconstructed_blobs.values()) > MAX_STAGED_BLOBS_BYTES:
        raise SnapshotError("Staged Git blobs exceed their aggregate byte bound")
    return reconstructed_blobs


def plan_git_artifacts(object_sizes: Iterable[int], refs: bytes, *, pack_representation: str,
                       object_format: str = "sha1") -> dict:
    """Calculate deterministic conservative bundle/pack/index size bounds.

    `object_sizes` is the already bounded inventory's uncompressed object sizes;
    this planner consumes numbers only and performs no Git process or I/O. Its
    formula is valid only for a writer that uses and verifies the fixed
    non-delta/no-reuse representation. An arbitrary Git bundle can contain
    delta/reused encodings whose size is not bounded by this planner's inputs.
    """
    _, oid_hex_length = _object_format(object_format)
    oid_bytes = oid_hex_length // 2
    if (not isinstance(pack_representation, str) or len(pack_representation) != len(_PACK_REPRESENTATION)
            or pack_representation != _PACK_REPRESENTATION):
        raise SnapshotError("Git artifact bound requires the fixed non-delta/no-reuse representation")
    if not isinstance(refs, bytes) or len(refs) > MAX_INDEX_RAW_BYTES:
        raise SnapshotError("Git ref listing exceeds its byte bound")
    count = total = 0
    for size in object_sizes:
        if type(size) is not int or size < 0 or size > MAX_GIT_OBJECT_BYTES_SINGLE:
            raise SnapshotError("Git object inventory contains an invalid size")
        count += 1
        total += size
        if count > MAX_GIT_OBJECTS or total > MAX_GIT_OBJECT_BYTES:
            raise SnapshotError("Git object inventory exceeds its count or byte bound")

    # Conservative pack entry headers and zlib expansion. Checked against fixed
    # limits below; these values are bounds, not predictions of compression.
    # Pack checksums and index object IDs are binary hashes, not hex text.
    pack = (12 + oid_bytes + count * 10 + total + (total >> 12) + (total >> 14)
            + (total >> 25) + count * 13)
    bundle = pack + len(refs) + 4096
    # Git index v2: signature/version, fanout, binary OIDs, CRCs, 32-bit offsets,
    # worst-case 64-bit large-offset slots, and two binary checksums.
    index = 8 + 256 * 4 + count * (oid_bytes + 4 + 4 + 8) + 2 * oid_bytes
    if bundle > MAX_BUNDLE_BYTES or index > MAX_INDEX_FILE_BYTES:
        raise SnapshotError("Git artifact plan exceeds its fixed byte bound")
    return {"objectFormat": object_format, "objects": count, "objectBytes": total,
            "packBytesUpperBound": pack, "bundleBytesUpperBound": bundle,
            "indexBytesUpperBound": index, "packRepresentation": pack_representation}


def plan_standby_restore_budget(manifest: dict, *, source_pack_bytes: int,
                                source_object_bytes: int, source_manifest_bytes: int,
                                object_inventory_bytes: int, sqlite_image_bytes: Iterable[int],
                                standby_metadata_bytes: int, writer_transient_bytes: int) -> dict:
    """Bound logical retained bytes while the source snapshot and standby coexist.

    The source archive remains retained while a separate standby tree is assembled.
    Git objects and materialized worktree files are distinct retained copies; SQLite
    images are counted at their exact serialized length. The caller supplies the
    bounded exact/preflight total for metadata plus fixed Git config/HEAD/refs outputs,
    and the maximum simultaneously retained writer scratch files. In-memory data,
    SQLite pages/WAL, and process memory are outside this logical-content calculation.
    Call once with no SQLite image sizes before preparation, pass the returned SQLite
    allowance to `prepare_standby_sqlite_images`, then call again with the exact image
    sizes before reserving or writing the standby.
    """
    if not isinstance(manifest, dict):
        raise SnapshotError("Standby restore manifest has invalid shape")
    git = manifest.get("git")
    if not isinstance(git, dict):
        raise SnapshotError("Standby restore manifest has no Git inventory")
    _, oid_hex_length = _object_format(git.get("objectFormat"))
    oid_bytes = oid_hex_length // 2
    integer_inputs = (source_pack_bytes, source_object_bytes, source_manifest_bytes,
                      object_inventory_bytes, git.get("objectCount"), git.get("objectBytes"),
                      standby_metadata_bytes, writer_transient_bytes)
    if any(type(value) is not int or value < 0 for value in integer_inputs):
        raise SnapshotError("Standby restore inventory has invalid byte counts")
    if (source_pack_bytes > MAX_BUNDLE_BYTES or source_object_bytes > MAX_GIT_OBJECT_BYTES
            or source_manifest_bytes > 64 * 1024 * 1024
            or object_inventory_bytes > MAX_GIT_OBJECTS * 65
            or standby_metadata_bytes == 0
            or standby_metadata_bytes > MAX_INDEX_RAW_BYTES
            or writer_transient_bytes > MAX_BUNDLE_BYTES + MAX_INDEX_FILE_BYTES
            or not 1 <= git["objectCount"] <= MAX_GIT_OBJECTS
            or git["objectBytes"] > MAX_GIT_OBJECT_BYTES):
        raise SnapshotError("Standby restore source exceeds its fixed byte bounds")

    sqlite_total = 0
    sqlite_count = 0
    for size in sqlite_image_bytes:
        if type(size) is not int or not 4096 <= size <= 512 * 1024 * 1024:
            raise SnapshotError("Standby SQLite image is outside its exact byte bound")
        sqlite_total += size
        sqlite_count += 1
        if sqlite_count > 1024 or sqlite_total > MAX_RESTORE_SQLITE_TOTAL_BYTES:
            raise SnapshotError("Standby SQLite images exceed their aggregate byte bound")

    authorities = manifest.get("authorities", [])
    if not isinstance(authorities, list) or len(authorities) > 1024:
        raise SnapshotError("Standby authority list exceeds its count bound")
    if any(not isinstance(authority, dict) for authority in authorities):
        raise SnapshotError("Standby authority descriptor has invalid shape")
    worktree_descriptors = [manifest.get("files", {})] + [
        authority.get("files", {}) for authority in authorities
        if authority.get("kind") in {"file", "tree"}]
    if any(not isinstance(descriptors, dict) for descriptors in worktree_descriptors):
        raise SnapshotError("Standby worktree inventory has invalid shape")
    if sum(len(descriptors) for descriptors in worktree_descriptors) > 1_000_000:
        raise SnapshotError("Standby worktree inventory exceeds its aggregate path bound")
    worktree_bytes = 0
    for descriptors in worktree_descriptors:
        if not isinstance(descriptors, dict) or len(descriptors) > MAX_INDEX_ENTRIES * 3:
            raise SnapshotError("Standby worktree inventory has invalid shape")
        for descriptor in descriptors.values():
            if not isinstance(descriptor, dict):
                raise SnapshotError("Standby worktree descriptor has invalid shape")
            if descriptor.get("type") == "file":
                size = descriptor.get("bytes")
                if type(size) is not int or not 0 <= size <= MAX_STAGED_BLOB_BYTES:
                    raise SnapshotError("Standby worktree file exceeds its byte bound")
                worktree_bytes += size
                if worktree_bytes > 8 * 1024 * 1024 * 1024:
                    raise SnapshotError("Standby worktree exceeds its aggregate byte bound")
            elif descriptor.get("type") == "symlink":
                target = descriptor.get("target")
                if not isinstance(target, str) or len(target) > MAX_INDEX_PATH_BYTES or "\x00" in target:
                    raise SnapshotError("Standby symlink target is outside its byte bound")
                try:
                    target_bytes = target.encode("utf-8")
                except UnicodeEncodeError as exc:
                    raise SnapshotError("Standby symlink target is not valid UTF-8") from exc
                if len(target_bytes) > MAX_INDEX_PATH_BYTES:
                    raise SnapshotError("Standby symlink target exceeds its byte bound")
                worktree_bytes += len(target_bytes)
                if worktree_bytes > 8 * 1024 * 1024 * 1024:
                    raise SnapshotError("Standby worktree exceeds its aggregate byte bound")
            else:
                raise SnapshotError("Standby worktree descriptor has unsupported type")

    index_manifest = git.get("index")
    if (not isinstance(index_manifest, dict) or not isinstance(index_manifest.get("blobs"), dict)
            or len(index_manifest["blobs"]) > MAX_INDEX_ENTRIES):
        raise SnapshotError("Standby restore has no validated staged-index inventory")
    staged_bytes = 0
    for descriptor in index_manifest["blobs"].values():
        size = descriptor.get("bytes") if isinstance(descriptor, dict) else None
        if type(size) is not int or not 0 <= size <= MAX_STAGED_BLOB_BYTES:
            raise SnapshotError("Standby staged blob exceeds its byte bound")
        staged_bytes += size
        if staged_bytes > MAX_STAGED_BLOBS_BYTES:
            raise SnapshotError("Standby staged blobs exceed their aggregate byte bound")
    worktree_bytes += staged_bytes
    if worktree_bytes > 8 * 1024 * 1024 * 1024:
        raise SnapshotError("Standby worktree and staged files exceed their aggregate byte bound")

    # Conservative output pack formula for the fixed non-delta/no-reuse writer.
    count, object_bytes = git["objectCount"], git["objectBytes"]
    # Hashes in the pack and index files use binary OID bytes. This bound therefore
    # follows the serialized size, unlike the hexadecimal object IDs in the manifest.
    pack_bytes = (12 + oid_bytes + count * 10 + object_bytes + (object_bytes >> 12)
                  + (object_bytes >> 14) + (object_bytes >> 25) + count * 13)
    index_bytes = 8 + 256 * 4 + count * (oid_bytes + 4 + 4 + 8) + 2 * oid_bytes
    if pack_bytes > MAX_BUNDLE_BYTES or index_bytes > MAX_INDEX_FILE_BYTES:
        raise SnapshotError("Standby Git artifacts exceed their fixed output bounds")

    # Pin the writer to Git index v2 with no optional extensions. Each entry has
    # 40 stat bytes, a binary OID, two flag bytes, a NUL-terminated path, and up to
    # seven padding bytes. The file also has a 12-byte header and binary checksum.
    entries = index_manifest.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_INDEX_ENTRIES:
        raise SnapshotError("Standby working index exceeds its entry-count bound")
    working_index_bytes = 0
    path_bytes_total = 0
    for entry in entries:
        if (not isinstance(entry, dict) or entry.get("mode") not in {"100644", "100755", "120000"}
                or not isinstance(entry.get("oid"), str) or len(entry["oid"]) != oid_hex_length
                or any(char not in "0123456789abcdef" for char in entry["oid"])
                or not isinstance(entry.get("pathB64"), str)
                or len(entry["pathB64"]) > 4 * ((MAX_INDEX_PATH_BYTES + 2) // 3)):
            raise SnapshotError("Standby working index entry is malformed")
        try:
            path = base64.b64decode(entry["pathB64"], validate=True)
        except (ValueError, TypeError) as exc:
            raise SnapshotError("Standby working index path encoding is invalid") from exc
        if not path or len(path) > MAX_INDEX_PATH_BYTES:
            raise SnapshotError("Standby working index path exceeds its byte bound")
        path_bytes_total += len(path)
        entry_bytes = 40 + oid_bytes + 2 + len(path) + 1
        working_index_bytes += (entry_bytes + 7) & ~7
        if path_bytes_total > MAX_INDEX_PATH_TOTAL or working_index_bytes > MAX_INDEX_RAW_BYTES:
            raise SnapshotError("Standby working index exceeds its aggregate byte bound")
    working_index_bytes += 12 + oid_bytes

    # Source archive and output standby coexist. The source object directory contains
    # worktree content-addressed files plus any staged blobs; output worktree files
    # and the packed repository are separate copies. Include metadata/inventory too.
    source_retained = source_pack_bytes + source_object_bytes + source_manifest_bytes + object_inventory_bytes
    non_sqlite_output = (pack_bytes + index_bytes + working_index_bytes + worktree_bytes
                         + standby_metadata_bytes)
    non_sqlite_new = non_sqlite_output + writer_transient_bytes
    non_sqlite_peak = source_retained + non_sqlite_new
    if non_sqlite_peak > MAX_RESTORE_RETAINED_TOTAL_BYTES:
        raise SnapshotError("Source and non-SQLite standby content exceed their aggregate byte budget")
    sqlite_allowance = min(MAX_RESTORE_SQLITE_TOTAL_BYTES,
                           MAX_RESTORE_RETAINED_TOTAL_BYTES - non_sqlite_peak)
    if sqlite_total > sqlite_allowance:
        raise SnapshotError("Standby SQLite images exceed the remaining retained-byte reservation")
    output_retained = non_sqlite_output + sqlite_total
    new_reservation = output_retained + writer_transient_bytes
    peak_retained = source_retained + new_reservation
    if peak_retained > MAX_RESTORE_RETAINED_TOTAL_BYTES:
        raise SnapshotError("Source and standby retained content exceed their aggregate byte budget")
    return {"sourceRetainedBytes": source_retained, "standbyPackBytesUpperBound": pack_bytes,
            "standbyIndexBytesUpperBound": index_bytes, "standbyWorktreeBytes": worktree_bytes,
            "standbyWorkingIndexBytes": working_index_bytes,
            "workingIndexFormat": _WORKING_INDEX_FORMAT,
            "standbySqliteImageBytes": sqlite_total, "standbySqliteImageCount": sqlite_count,
            "standbyMetadataBytes": standby_metadata_bytes,
            "standbySqliteAllowanceBytes": sqlite_allowance,
            "writerTransientBytesUpperBound": writer_transient_bytes,
            "standbyRetainedBytesUpperBound": output_retained,
            "newBytesReservationUpperBound": new_reservation,
            "peakRetainedBytesUpperBound": peak_retained,
            "accounting": "logical-retained-content-bytes/v1"}


def prepare_standby_sqlite_images(authorities, *, max_total_bytes=MAX_RESTORE_SQLITE_TOTAL_BYTES,
                                  blob_store=None):
    """Prepare bounded exact SQLite standby images under one aggregate reservation.

    Each image uses the existing SQLite standby builder, whose page and exact
    serialization limits are capped by the remaining aggregate allowance. The
    returned images remain in memory together until the caller finishes staging;
    callers must charge their sum before creating any target file.
    """
    if type(max_total_bytes) is not int or not 4096 <= max_total_bytes <= MAX_RESTORE_SQLITE_TOTAL_BYTES:
        raise SnapshotError("Aggregate standby SQLite image budget is invalid")
    if not isinstance(authorities, (list, tuple)) or len(authorities) > 1024:
        raise SnapshotError("Standby SQLite authority list exceeds its count bound")
    from knowledge_store import (MAX_RESTORE_SQLITE_IMAGE_BYTES, StoreError,
                                 prepare_sqlite_standby_image)

    images = []
    total = 0
    for entry in authorities:
        if (not isinstance(entry, dict) or entry.get("kind") != "sqlite-authority"
                or not isinstance(entry.get("snapshot"), dict)):
            raise SnapshotError("Standby SQLite authority descriptor is invalid")
        remaining = max_total_bytes - total
        if remaining < 4096:
            raise SnapshotError("Standby SQLite images exceed their aggregate byte reservation")
        try:
            raw, instance = prepare_sqlite_standby_image(
                entry["snapshot"], max_bytes=min(remaining, MAX_RESTORE_SQLITE_IMAGE_BYTES),
                blob_store=blob_store)
        except StoreError as exc:
            raise SnapshotError("Standby SQLite image exceeded its reserved bounds") from exc
        if not isinstance(raw, bytes) or len(raw) > remaining:
            raise SnapshotError("Prepared standby SQLite image exceeded its aggregate reservation")
        total += len(raw)
        images.append({"id": entry.get("id"), "bytes": raw, "instance": instance,
                       "sha256": hashlib.sha256(raw).hexdigest()})
    return {"images": images, "totalBytes": total, "count": len(images),
            "accounting": "logical-retained-content-bytes/v1"}
