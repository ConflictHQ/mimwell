"""Reviewed, read-only transfer of a selected authorized live-record view.

The shared interchange engine computes losses. Acknowledgement binds selection
and exact bytes; it is not destination permission, training consent or a backup.
"""

from hashlib import sha256

from knowledge_interchange import FORMAT, canonical, pack, project
from knowledge_operations import response_bytes
from knowledge_policy import fingerprint, timestamp
from knowledge_store import StoreError

MAX_EXPORT_BYTES = 512 * 1024
MAX_EXPORT_RECORDS = 2000


def prepare(store, args, *, actor, at):
    description = store.describe(actor, at=at)
    if not description["collections"]:
        raise StoreError("Transfer source unavailable")
    snapshot = store.read_snapshot(actor, at=at, max_records=MAX_EXPORT_RECORDS, max_body_bytes=MAX_EXPORT_BYTES)
    if len(canonical(snapshot).encode("utf-8")) > MAX_EXPORT_BYTES:
        raise StoreError("Selected view exceeds transfer limit")
    source_revision = fingerprint(snapshot["checkpoint"])
    scope = {
        "selection": "authorized-live-records",
        "principal": actor,
        "collections": sorted(c["id"] for c in description["collections"]),
        "excluded": ["native-history", "pending-proposals", "credentials", "unreadable-records", "external-source-bytes"],
    }
    package = pack(snapshot["graph"], {"id": store.contract.document["id"], "revision": source_revision}, {
        "scope": scope, "revisions": snapshot["revisions"], "purpose": args["purpose"],
        "contract": store.contract.binding,
    })
    if args["targetFormat"] == FORMAT:
        value = package
        report = {"projection": False, "history": "not-transferred", "authority": "none",
                  "losses": [], "sourceDigest": package["sha256"], "mapping": "exact-selected-graph-json/v1"}
    else:
        projection = project(package, args["targetFormat"])
        value, report = projection["graph"], projection["report"]
    wire = canonical(value) + "\n"
    raw = wire.encode("utf-8")
    if len(raw) > MAX_EXPORT_BYTES:
        raise StoreError("Export exceeds transfer limit")
    preview = {
        "format": "knowledge-transfer-preview/v1",
        "purpose": args["purpose"], "targetFormat": args["targetFormat"],
        "sourceRevision": source_revision, "sourceSha256": fingerprint(snapshot),
        "scope": scope, "report": report, "lossesSha256": fingerprint(report),
        "records": len(snapshot["graph"]["nodes"]), "relationships": len(snapshot["graph"]["edges"]),
        "artifact": {"filename": "brain-" + ("exchange" if args["targetFormat"] == FORMAT else "graph") + ".json",
                     "mediaType": "application/json", "encoding": "utf-8", "bytes": len(raw),
                     "sha256": sha256(raw).hexdigest()},
    }
    preview["previewSha256"] = fingerprint(preview)
    return preview, wire


def run_transfer(store, request, *, actor, clock, guard, max_response_bytes):
    args, operation = request["arguments"], request["operation"]
    at = clock()
    preview, wire = prepare(store, args, actor=actor, at=at)
    if operation == "transfer.download":
        if args["expectedPreviewSha256"] != preview["previewSha256"] or args["acknowledgedLossesSha256"] != preview["lossesSha256"]:
            raise StoreError("Transfer selection changed or losses not acknowledged; preview again")
        native = {"format": "knowledge-transfer-download/v1", "preview": preview,
                  "acknowledgedLossesSha256": args["acknowledgedLossesSha256"], "artifactWire": wire}
    else:
        native = preview
    # No file is written or download content released until encoding, identity,
    # source revision, policy and clock checks succeed at the final observation.
    response_bytes(request, store, native, actor, at, at, max_response_bytes)
    guard(not_before=timestamp(at))
    final_at = clock()
    if timestamp(final_at) < timestamp(at):
        raise StoreError("Transfer clock moved backwards")
    current, current_wire = prepare(store, args, actor=actor, at=final_at)
    if current != preview or current_wire != wire:
        raise StoreError("Transfer source changed during release; preview again")
    raw = response_bytes(request, store, native, actor, at, final_at, max_response_bytes)
    guard(not_before=timestamp(final_at))
    return raw
