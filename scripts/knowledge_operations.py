"""Shared, bounded operations over a host-selected native knowledge authority.

Trusted host files select writers and allowed operations. Requests never choose
paths, identity, credentials, policies or clocks. A successful response preserves
the native result exactly; a failed local response rolls back the native mutation.
"""

from pathlib import Path
from contextlib import nullcontext
import os
import re
import stat

from brain_federation import fields
from context_bundle import encode
from context_host import decode
from knowledge_policy import fingerprint, local_path, timestamp
from knowledge_store import SQLiteAuthority, StoreError, utcnow, encoded

ARGUMENTS = {
    "authority.inspect": (),
    "source.inspect": ("source",),
    "source.capture": ("source", "expectedSourceSha256"),
    "source.extraction-preview": ("source", "captureSha256"),
    "source.extract": ("source", "captureSha256", "expectedProfileSha256"),
    "publication.preview": ("consumer",),
    "publication.deliver": ("consumer", "expectedProjectionSha256"),
    "record.get": ("record",),
    "record.patch-propose": ("record", "expectedRevision", "requestId", "title", "text", "reason", "evidence"),
    "proposal.propose": ("request", "record"),
    "proposal.inspect": ("proposal",),
    "proposal.review": ("proposal", "expectedProposalSha256", "reason"),
    "proposal.dispose": ("proposal", "expectedProposalSha256", "action", "reason"),
    "proposal.commit": ("proposal", "expectedProposalSha256"),
}
TRANSFER_ARGUMENTS = {
    "transfer.preview": ("purpose", "targetFormat"),
    "transfer.download": ("purpose", "targetFormat", "expectedPreviewSha256", "acknowledgedLossesSha256"),
}
REVIEW_ARGUMENTS = {
    "source.list": ("limit", "cursor"),
    "proposal.list": ("collections", "limit", "cursor"),
    "collection.semantic-inspect": ("collection",),
}
INTAKE_ARGUMENTS = {
    "intake.history-propose": ("record", "expectedRevision", "item", "intent", "requestId", "reason"),
    "intake.delivery-propose": ("history", "historyRevision", "destination", "record", "expectedRevision", "requestId", "reason"),
    "intake.processed-delivery-propose": ("history", "historyRevision", "destination", "record", "expectedRevision", "requestId", "reason", "processing"),
    "intake.source-review": ("proposal", "expectedProposalSha256", "reason"),
    "intake.source-revoke": ("proposal", "expectedProposalSha256", "reason"),
    "intake.completion-plan": ("request",),
    "intake.completion-refresh": ("maxEvents", "maxBytes"),
}
WRITES = frozenset(
    ("record.patch-propose", "proposal.propose", "proposal.review", "proposal.dispose", "proposal.commit")
) | (INTAKE_ARGUMENTS.keys() - {"intake.completion-plan", "intake.completion-refresh"})
MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


def private_path(root, relative, *, allow_missing=False):
    path = local_path(relative)
    if path.parts[0] != "_internal":
        raise StoreError("Operations host state must be private")
    for index in range(1, len(path.parts) + 1):
        current = root / Path(*path.parts[:index])
        try:
            info = current.lstat()
        except FileNotFoundError:
            if allow_missing and index == len(path.parts):
                continue
            raise
        required = stat.S_ISREG if index == len(path.parts) else stat.S_ISDIR
        if not required(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise StoreError("Operations state requires private operator-owned paths")
    return root / path


def load_host(root, relative):
    if root.is_symlink() or not root.is_dir():
        raise StoreError("Operations root must be a real directory")
    path = private_path(root, relative)
    with path.open("rb") as stream:
        raw = stream.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise StoreError("Operations host exceeds its limit")
    host = decode(raw)
    fields(host, ("format", "principalsByUid", "authorities"))
    if (
        host["format"] not in tuple("knowledge-operations-host/v" + str(version) for version in range(1, 5))
        or not isinstance(host["principalsByUid"], dict)
        or not isinstance(host["authorities"], dict)
        or not 1 <= len(host["authorities"]) <= 64
    ):
        raise StoreError("Invalid operations host")
    for uid, actor in host["principalsByUid"].items():
        if not re.fullmatch(r"[0-9]+", uid) or not isinstance(actor, str) or not actor.strip():
            raise StoreError("Invalid local principal mapping")
    for identity, entry in host["authorities"].items():
        options = ("sources", "consumers", "intake") if host["format"] == "knowledge-operations-host/v4" else ("sources", "consumers")
        optional = tuple(key for key in options if key in entry)
        fields(entry, ("path", "binding", "grants", *optional))
        for key in optional:
            if not isinstance(entry[key], dict) or len(entry[key]) > 1000:
                raise StoreError("Invalid bounded operation registrations")
        if "intake" in optional:
            from knowledge_operation_intake import validate_registration

            validate_registration(entry["intake"])
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", identity)
            or not isinstance(entry["binding"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", entry["binding"])
            or not isinstance(entry["grants"], dict)
        ):
            raise StoreError("Invalid authority registration")
        for actor, verbs in entry["grants"].items():
            if (
                not isinstance(actor, str)
                or not actor.strip()
                or not isinstance(verbs, list)
                or any(not isinstance(verb, str) or verb not in (
                    ARGUMENTS if host["format"] == "knowledge-operations-host/v1" else
                    ARGUMENTS | TRANSFER_ARGUMENTS if host["format"] == "knowledge-operations-host/v2" else
                    ARGUMENTS | TRANSFER_ARGUMENTS | REVIEW_ARGUMENTS if host["format"] == "knowledge-operations-host/v3" else
                    ARGUMENTS | TRANSFER_ARGUMENTS | REVIEW_ARGUMENTS | INTAKE_ARGUMENTS
                ) for verb in verbs)
                or len(verbs) != len(set(verbs))
            ):
                raise StoreError("Invalid operations grant")
    return host


def validate_request(request):
    fields(request, ("format", "authority", "operation", "arguments"))
    if (
        request["format"] not in tuple("knowledge-operation-request/v" + str(version) for version in range(1, 5))
        or not isinstance(request["authority"], str)
        or not isinstance(request["operation"], str)
        or request["operation"] not in (ARGUMENTS | TRANSFER_ARGUMENTS | REVIEW_ARGUMENTS | INTAKE_ARGUMENTS)
    ):
        raise StoreError("Unsupported knowledge operation")
    operation, args = request["operation"], request["arguments"]
    version = "v4" if operation in INTAKE_ARGUMENTS else "v3" if operation in REVIEW_ARGUMENTS else "v2" if operation in TRANSFER_ARGUMENTS else "v1"
    if request["format"] != "knowledge-operation-request/" + version:
        raise StoreError("Operation request version does not match the selected operation")
    fields(args, (ARGUMENTS | TRANSFER_ARGUMENTS | REVIEW_ARGUMENTS | INTAKE_ARGUMENTS)[operation])
    if operation in INTAKE_ARGUMENTS:
        from knowledge_operation_intake import validate_arguments

        validate_arguments(operation, args)
    if operation == "collection.semantic-inspect" and (
        not isinstance(args["collection"], str) or not 1 <= len(args["collection"]) <= 2000
    ):
        raise StoreError("Invalid semantic collection selection")
    if operation in ("source.list", "proposal.list"):
        if type(args["limit"]) is not int or not 1 <= args["limit"] <= 100:
            raise StoreError("Invalid review discovery limit")
        cursor = args["cursor"]
        if cursor is not None and (
            not isinstance(cursor, dict) or set(cursor) != {"basisSha256", "after"}
            or not isinstance(cursor["basisSha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", cursor["basisSha256"])
            or not isinstance(cursor["after"], str) or not 1 <= len(cursor["after"]) <= 2000
        ):
            raise StoreError("Invalid review discovery cursor")
        if operation == "proposal.list" and (
            not isinstance(args["collections"], list) or not 1 <= len(args["collections"]) <= 16
            or any(not isinstance(key, str) or not 1 <= len(key) <= 2000 for key in args["collections"])
            or len(set(args["collections"])) != len(args["collections"])
        ):
            raise StoreError("Invalid proposal collection selection")
    if operation in TRANSFER_ARGUMENTS:
        if args["purpose"] not in ("analysis", "interchange") or args["targetFormat"] not in (
            "brain-exchange/v1", "conflict-kg/v1", "calliope-kg/v1"
        ):
            raise StoreError("Unsupported transfer purpose or format")
    for key in ("proposal", "reason", "source", "consumer"):
        if key in args and (not isinstance(args[key], str) or not args[key].strip() or len(args[key]) > 2000):
            raise StoreError("Invalid operation text")
    if operation == "record.get" and (not isinstance(args["record"], str) or not 1 <= len(args["record"]) <= 2000):
        raise StoreError("Invalid record identity")
    for key in (
        "expectedProposalSha256",
        "captureSha256",
        "expectedProfileSha256",
        "expectedProjectionSha256",
        "expectedSourceSha256",
        "expectedPreviewSha256",
        "acknowledgedLossesSha256",
    ):
        if key not in args or key == "expectedSourceSha256" and args[key] is None:
            continue
        if not isinstance(args[key], str) or not re.fullmatch(r"[0-9a-f]{64}", args[key]):
            raise StoreError("Exact operation basis required")
    if operation == "record.patch-propose":
        for key, limit in (
            ("record", 2000),
            ("requestId", 2000),
            ("expectedRevision", 256),
            ("title", 2000),
            ("text", 65536),
        ):
            if (
                not isinstance(args[key], str)
                or len(args[key]) > limit
                or key not in ("title", "text")
                and not args[key].strip()
            ):
                raise StoreError("Invalid record patch")
        if (
            not isinstance(args["evidence"], list)
            or not 1 <= len(args["evidence"]) <= 128
            or any(not isinstance(value, str) or not value.strip() or len(value) > 2000 for value in args["evidence"])
        ):
            raise StoreError("Record patch requires bounded evidence references")
    if operation == "proposal.dispose" and args["action"] not in ("reject", "defer", "withdraw"):
        raise StoreError("Unsupported disposition")


def execute(store, operation, args, *, actor, at):
    """Dispatch to native APIs; these returns are never rebuilt as new receipts."""
    if operation == "collection.semantic-inspect":
        from knowledge_operation_semantics import inspect_collection

        return inspect_collection(store, args["collection"], actor=actor, at=at)
    if operation == "authority.inspect":
        result = store.describe(actor, at=at)
        if not result["collections"]:
            raise StoreError("Authority unavailable")
        return result
    if operation == "record.get":
        return store.get(args["record"], actor, at=at)
    if operation == "record.patch-propose":
        current = store.get(args["record"], actor, at=at)
        if (
            not current
            or not current["record"]
            or current["withheldRelations"]
            or current["revision"] != args["expectedRevision"]
        ):
            raise StoreError("Record unavailable or changed; inspect before editing")
        value = current["record"]
        value["content"].update(title=args["title"], text=args["text"])
        resource = store.contract.collections[value["collection"]]["resource"]
        mutation = {
            "id": args["requestId"],
            "record": value["id"],
            "resource": resource,
            "mutation": "correct",
            "expectedRevision": args["expectedRevision"],
            "reason": args["reason"],
            "evidence": args["evidence"],
            "sourceResource": None,
        }
        return store.propose(mutation, value, actor, at=at)
    if operation == "proposal.propose":
        return store.propose(args["request"], args["record"], actor, at=at)
    if operation == "proposal.inspect":
        return store.inspect(args["proposal"], actor, at=at)
    if operation == "proposal.list":
        from proposal_queue import inspect_queue

        return inspect_queue(store, args["collections"], actor, at=at, limit=args["limit"], cursor=args["cursor"])
    basis = args["expectedProposalSha256"]
    if operation == "proposal.review":
        return store.review(args["proposal"], actor, args["reason"], at=at, expected_proposal_sha256=basis)
    if operation == "proposal.dispose":
        return store.dispose(
            args["proposal"], actor, args["action"], args["reason"], at=at, expected_proposal_sha256=basis
        )
    if operation == "proposal.commit":
        return store.commit(args["proposal"], actor, at=at, expected_proposal_sha256=basis)
    raise StoreError("Unsupported knowledge operation")


def response_bytes(request, store, native, actor, at, final_at, limit):
    response = {
        "format": request["format"].replace("knowledge-operation-request/", "knowledge-operation/"),
        "authority": request["authority"],
        "operation": request["operation"],
        "contract": store.contract.binding,
        "requestWire": encoded(request),
        "requestSha256": fingerprint(request),
        "authorization": {"principal": actor, "evaluatedAt": at, "revalidatedAt": final_at},
        "state": "completed",
        "native": native,
        "nativeWire": encoded(native),
        "nativeSha256": fingerprint(native),
    }
    raw = encode(response)
    if len(raw) > limit:
        raise StoreError("Operation response exceeds its limit")
    return raw


def run(root, host_config, request, *, actor, clock=utcnow, authorize=None, max_response_bytes=MAX_RESPONSE_BYTES):
    """Trusted identity/clock; authorize() refreshes transport identity at each gate."""
    if type(max_response_bytes) is not int or not 1 <= max_response_bytes <= MAX_RESPONSE_BYTES:
        raise StoreError("Invalid operations response bound")
    if len(encode(request)) > MAX_REQUEST_BYTES:
        raise StoreError("Operation request exceeds its limit")
    validate_request(request)
    root = Path(root).absolute()
    host = load_host(root, host_config)
    selected = host["authorities"].get(request["authority"])
    operation, args = request["operation"], request["arguments"]
    if selected is None or operation not in selected["grants"].get(actor, []):
        raise StoreError("Operation unavailable")
    path = private_path(root, selected["path"])
    path_identity = (path.stat().st_dev, path.stat().st_ino)
    initial = timestamp(clock())

    def guard(not_before=initial):
        if authorize is not None and authorize() != actor:
            raise StoreError("Operation identity changed")
        if load_host(root, host_config) != host or timestamp(clock()) < not_before:
            raise StoreError("Operation host selection changed")
        current = private_path(root, selected["path"]).stat()
        if (current.st_dev, current.st_ino) != path_identity:
            raise StoreError("Authority file changed during operation")

    guard()
    write = operation in WRITES
    store = SQLiteAuthority(
        path,
        expected_binding=selected["binding"],
        readonly=not (write or operation == "publication.deliver"),
        intake_clock=clock,
    )
    try:
        intake = None
        if "intake" in selected:
            from knowledge_operation_intake import IntakeOperations

            intake = IntakeOperations(root, selected["intake"], store, guard=guard)
        if operation in ("intake.completion-plan", "intake.completion-refresh"):
            from knowledge_operation_completion import run_completion

            if intake is None:
                raise StoreError("Intake host registration required")
            return run_completion(intake, request, actor=actor, clock=clock,
                                  max_response_bytes=max_response_bytes)
        if operation in TRANSFER_ARGUMENTS:
            from knowledge_operation_transfer import run_transfer

            return run_transfer(store, request, actor=actor, clock=clock, guard=guard,
                                max_response_bytes=max_response_bytes)
        if operation.startswith("source.") and operation != "source.list":
            from knowledge_operation_sources import run_source

            at = clock()
            native, final_at = run_source(root, selected, store, operation, args, actor=actor, clock=clock, guard=guard)
            if timestamp(final_at) < timestamp(at):
                raise StoreError("Operation clock moved backwards")
            raw = response_bytes(request, store, native, actor, at, final_at, max_response_bytes)
            guard(not_before=timestamp(final_at))
            return raw
        if operation.startswith("publication."):
            from knowledge_operation_publication import run_publication

            return run_publication(
                root,
                selected,
                store,
                request,
                actor=actor,
                clock=clock,
                guard=guard,
                max_response_bytes=max_response_bytes,
            )
        from native_inspection import inspection_budget

        def invoke(at):
            if operation in INTAKE_ARGUMENTS:
                if intake is None:
                    raise StoreError("Intake host registration required")
                return intake.execute(operation, args, actor=actor, at=at)
            if intake is not None and operation in ("proposal.review", "proposal.commit"):
                intake.validate_proposal(args["proposal"], actor=actor, at=at,
                                         acknowledgement=operation == "proposal.commit")
            if operation == "source.list":
                from knowledge_operation_sources import list_sources

                return list_sources(root, selected, store, args, actor=actor, at=at, guard=guard)
            return execute(store, operation, args, actor=actor, at=at)

        with store.request_transaction(write=write), (
            inspection_budget(store) if operation == "proposal.list" else nullcontext()
        ):
            guard()  # Waiting for the writer lock must not preserve a revoked token.
            at = clock()
            native = invoke(at)
            response = {
                "format": request["format"].replace("knowledge-operation-request/", "knowledge-operation/"),
                "authority": request["authority"],
                "operation": operation,
                "contract": store.contract.binding,
                "requestWire": encoded(request),
                "requestSha256": fingerprint(request),
                "authorization": {"principal": actor, "evaluatedAt": at},
                "state": "completed",
                "native": native,
                "nativeWire": encoded(native),
                "nativeSha256": fingerprint(native),
            }
            raw = encode(response)
            if len(raw) > max_response_bytes:
                raise StoreError("Operation response exceeds its limit")
            guard()  # Native writes roll back if encoding or current-host validation fails.
            final_at = clock()
            if timestamp(final_at) < timestamp(at):
                raise StoreError("Operation clock moved backwards")
            store.revalidate_request(final_at)
            if intake is not None:
                intake.revalidate(final_at)
            # Reads and prior commit acknowledgements have no new mutation basis.
            # Repeating a prior acknowledgement is a read check, never approval of
            # a new write. New writes are checked against their captured native basis.
            if not write or operation == "proposal.commit" and not store._request_checks:
                if invoke(final_at) != native:
                    raise StoreError("Operation result is no longer releasable")
            response["authorization"]["revalidatedAt"] = final_at
            raw = encode(response)
            if len(raw) > max_response_bytes:
                raise StoreError("Operation response exceeds its limit")
            guard(not_before=timestamp(final_at))
            return raw
    finally:
        store.close()
