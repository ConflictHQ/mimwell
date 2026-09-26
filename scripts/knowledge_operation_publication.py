"""Preview and publish to an explicitly registered private projection consumer."""

import os

from brain_federation import fields
from context_bundle import encode
from context_host import decode
from intake_capture import read_stable
from knowledge_policy import timestamp
from knowledge_store import StoreError, atomic_projection, projection_basis


def run_publication(root, selected, store, request, *, actor, clock, guard, max_response_bytes):
    from knowledge_operations import private_path, response_bytes, MAX_RESPONSE_BYTES

    args, operation = request["arguments"], request["operation"]
    consumer = selected.get("consumers", {}).get(args["consumer"])
    if consumer is None:
        raise StoreError("Publication consumer unavailable")
    fields(consumer, ("path", "principal"))
    if consumer["principal"] != actor:
        raise StoreError("Publication consumer unavailable")
    path = private_path(root, consumer["path"], allow_missing=True)
    # A projection must never replace the authority, its WAL or host operation files.
    if not str(consumer["path"]).startswith("_internal/projections/") or path.suffix != ".json":
        raise StoreError("Publication requires a private projections JSON target")
    at = clock()
    preview = store.delivery_preview(actor, at=at)
    basis = projection_basis(preview)
    guard(not_before=timestamp(at))
    if operation == "publication.preview":
        final_at = clock()
        current = store.delivery_preview(actor, at=final_at)
        if timestamp(final_at) < timestamp(at) or projection_basis(current) != basis:
            raise StoreError("Publication preview changed")
        native = {
            "format": "publication-preview/v1",
            "consumer": args["consumer"],
            "target": "private-local-projection",
            "projectionSha256": basis,
            "payload": preview,
        }
        raw = response_bytes(request, store, native, actor, at, final_at, max_response_bytes)
        guard(not_before=timestamp(final_at))
        return raw
    if operation != "publication.deliver" or args["expectedProjectionSha256"] != basis:
        raise StoreError("Publication selection changed; preview again")
    # Check the bounded acknowledgement shape before the external side effect.
    response_bytes(
        request, store, {"delivered": True, "sequence": preview["sequence"]}, actor, at, at, max_response_bytes
    )
    last = [timestamp(at)]

    def current_basis():
        guard(not_before=last[0])
        now = clock()
        if timestamp(now) < last[0]:
            raise StoreError("Publication clock moved backwards")
        current = store.delivery_preview(actor, at=now)
        if projection_basis(current) != basis:
            raise StoreError("Publication scope or source changed")
        last[0] = timestamp(now)
        return now

    def verify_sink():
        private_path(root, consumer["path"])
        raw, _ = read_stable(root, consumer["path"], MAX_RESPONSE_BYTES)
        if projection_basis(decode(raw)) != basis:
            raise StoreError("Projection sink did not retain the selected basis")

    def publish(payload):
        current_basis()
        if projection_basis(payload) != basis:
            raise StoreError("Native publication differs from selected preview")
        if len(encode(payload)) > MAX_RESPONSE_BYTES:
            raise StoreError("Projection exceeds publication byte limit")
        private_path(root, consumer["path"], allow_missing=True)
        lock_relative = consumer["path"] + ".lock"
        lock = private_path(root, lock_relative, allow_missing=True)
        descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        os.close(descriptor)
        private_path(root, lock_relative)
        atomic_projection(path, payload)
        verify_sink()

    def checkpoint(stage):
        if stage == "after-delivery":
            current_basis()  # Refuse acknowledgement when release authority changed.

    def acknowledge():
        current_basis()
        verify_sink()

    receipt = store.deliver(
        args["consumer"],
        actor,
        publish,
        at=current_basis(),
        fault=checkpoint,
        expected_projection_sha256=basis,
        acknowledge_guard=acknowledge,
    )
    final_at = current_basis()
    raw = response_bytes(request, store, receipt, actor, at, final_at, max_response_bytes)
    guard(not_before=timestamp(final_at))
    return raw
