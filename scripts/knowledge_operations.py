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
from knowledge_store import StoreError, utcnow, encoded

ARGUMENTS = {
    "authority.inspect": (),
    "source.inspect": ("source",),
    "source.capture": ("source", "expectedSourceSha256"),
    "source.extraction-preview": ("source", "captureSha256"),
    "source.extract": ("source", "captureSha256", "expectedProfileSha256"),
    "publication.preview": ("consumer",),
    "publication.deliver": ("consumer", "expectedProjectionSha256"),
    "record.get": ("record",),
    "record.history": ("record", "limit"),
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
FILE_ARGUMENTS = {
    "file.inspect": (),
    "file.history": ("limit",),
    "file.propose": ("expectedRevision", "requestId", "reason", "documentWire"),
    "file.proposal-inspect": ("proposal",),
    "file.review": ("proposal", "expectedProposalSha256", "reason"),
    "file.publish": ("proposal", "expectedProposalSha256"),
    "file.propose-binary": ("expectedRevision", "requestId", "reason", "contentBase64"),
}
FILE_GROUP_ARGUMENTS = {
    "file.group.inspect": (),
    "file.group.propose": ("expectedGroupRevision", "expectedAuthorizationSha256", "requestId", "reason", "documentWire"),
    "file.group.propose-binary": ("expectedGroupRevision", "expectedAuthorizationSha256", "requestId", "reason", "contentBase64"),
    "file.group.proposal-inspect": ("proposal",),
    "file.group.review": ("proposal", "expectedProposalSha256", "reason"),
    "file.group.destination-publish": ("proposal", "expectedProposalSha256", "destination"),
    "file.group.status": ("proposal",),
}
FILE_OPERATIONS = frozenset(FILE_ARGUMENTS)
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
    if not isinstance(host, dict):
        raise StoreError("Invalid operations host")
    file_host = host.get("format") in ("knowledge-operations-host/v6", "knowledge-operations-host/v7", "knowledge-operations-host/v8")
    host_fields = (("format", "principalsByUid", "authorities", "fileAuthorities", "publicationGroups")
                   if host.get("format") == "knowledge-operations-host/v8" else
                   ("format", "principalsByUid", "authorities", "fileAuthorities") if file_host else
                   ("format", "principalsByUid", "authorities"))
    fields(host, host_fields)
    if (
        host["format"] not in tuple("knowledge-operations-host/v" + str(version) for version in range(1, 9))
        or not isinstance(host["principalsByUid"], dict)
        or not isinstance(host["authorities"], dict)
        or len(host["authorities"]) > 64
        or file_host and
           (not isinstance(host["fileAuthorities"], dict) or not 1 <= len(host["fileAuthorities"]) <= 64)
        or not host["authorities"] and not host.get("fileAuthorities")
        or host["format"] == "knowledge-operations-host/v8" and not isinstance(host.get("publicationGroups"), dict)
    ):
        raise StoreError("Invalid operations host")
    if set(host["authorities"]) & set(host.get("fileAuthorities", {})):
        raise StoreError("Native and file authority identities must be distinct")
    if host["format"] == "knowledge-operations-host/v8" and (
            len(host["publicationGroups"]) > 16 or
            set(host["publicationGroups"]) & (set(host["authorities"]) | set(host["fileAuthorities"]))):
        raise StoreError("File publication group identities are invalid")
    for uid, actor in host["principalsByUid"].items():
        if not re.fullmatch(r"[0-9]+", uid) or not isinstance(actor, str) or not actor.strip():
            raise StoreError("Invalid local principal mapping")
    for identity, entry in host["authorities"].items():
        options = ("sources", "consumers", "intake") if host["format"] in ("knowledge-operations-host/v4", "knowledge-operations-host/v5", "knowledge-operations-host/v6", "knowledge-operations-host/v7", "knowledge-operations-host/v8") else ("sources", "consumers")
        optional = tuple(key for key in options if key in entry)
        remote = host['format'] in ('knowledge-operations-host/v5', 'knowledge-operations-host/v6', 'knowledge-operations-host/v7', 'knowledge-operations-host/v8') and 'connection' in entry
        fields(entry, ("connection" if remote else "path", "binding", "grants", *optional))
        if remote:
            from operation_backend import validate_connection
            validate_connection(entry['connection'])
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
    if file_host:
        from git_file_authoring import ARGUMENTS as FILE_ARGUMENTS
        file_verbs = set(FILE_ARGUMENTS) | {"authority.inspect"}
        for identity, entry in host["fileAuthorities"].items():
            if entry.get("writer") == "json-commit":
                file_fields = ("writer", "repository", "sourceRef", "reviewPrefix", "path", "schema",
                               "schemaSha256", "configSha256", "maxBytes", "grants")
            elif host["format"] == "knowledge-operations-host/v7" and entry.get("writer") == "markdown-commit":
                file_fields = ("writer", "repository", "sourceRef", "reviewPrefix", "path", "contentProfile",
                               "contentProfileSha256", "configSha256", "maxBytes", "grants")
            elif host["format"] == "knowledge-operations-host/v8" and entry.get("writer") == "markdown-commit":
                file_fields = ("writer", "repository", "sourceRef", "reviewPrefix", "path", "contentProfile",
                               "contentProfileSha256", "configSha256", "maxBytes", "grants")
            elif host["format"] == "knowledge-operations-host/v8" and entry.get("writer") == "binary-commit":
                file_fields = ("writer", "repository", "sourceRef", "reviewPrefix", "path", "contentProfile",
                               "contentProfileSha256", "mediaType", "configSha256", "maxBytes", "grants")
            else:
                raise StoreError("Invalid registered file writer")
            fields(entry, file_fields)
            if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", identity)
                    or not isinstance(entry["grants"], dict)):
                raise StoreError("Invalid registered file authority")
            for actor, verbs in entry["grants"].items():
                if (not isinstance(actor, str) or not actor.strip() or not isinstance(verbs, list)
                        or len(verbs) != len(set(verbs))
                        or any(not isinstance(verb, str) or verb not in file_verbs for verb in verbs)):
                    raise StoreError("Invalid file authority grant")
        if host["format"] == "knowledge-operations-host/v8":
            groups = host["publicationGroups"]
            if len(groups) > 16 or set(groups) & (set(host["authorities"]) | set(host["fileAuthorities"])):
                raise StoreError("Invalid file publication group identity")
            for group_id, group in groups.items():
                if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", group_id) or
                        not isinstance(group, dict) or set(group) != {"controlRepository", "controlRef", "targets"} or
                        not isinstance(group["targets"], list) or not 2 <= len(group["targets"]) <= 4 or
                        len(set(group["targets"])) != len(group["targets"]) or
                        any(target not in host["fileAuthorities"] for target in group["targets"]) or
                        not isinstance(group["controlRepository"], str) or
                        not re.fullmatch(r"_internal/[A-Za-z0-9._/-]{1,180}\.git", group["controlRepository"]) or
                        not isinstance(group["controlRef"], str) or
                        not re.fullmatch(r"refs/heads/[A-Za-z0-9._/-]{1,120}", group["controlRef"])):
                    raise StoreError("Invalid registered file publication group")
                targets = [host["fileAuthorities"][target] for target in group["targets"]]
                profile_keys = ("writer", "contentProfile", "contentProfileSha256")
                if any(target.get("writer") not in ("markdown-commit", "binary-commit") for target in targets):
                    raise StoreError("Publication groups require a compatible declared file writer")
                first_profile = tuple(targets[0].get(key) for key in profile_keys)
                if any(tuple(target.get(key) for key in profile_keys) != first_profile for target in targets):
                    raise StoreError("Publication group writers must share one content profile")
                if first_profile[0] == "binary-commit" and any(target.get("mediaType") != targets[0].get("mediaType") for target in targets):
                    raise StoreError("Binary publication group media type must be fixed across destinations")
                if len({(target["repository"], target["sourceRef"], target["path"]) for target in targets}) != len(targets):
                    raise StoreError("Publication group targets must be distinct")
                if (group["controlRepository"] != targets[0]["repository"] or
                        group["controlRef"] != targets[0]["sourceRef"]):
                    raise StoreError("Publication group control basis must be its first registered target")
    return host


def validate_request(request):
    fields(request, ("format", "authority", "operation", "arguments"))
    if (
        request["format"] not in tuple("knowledge-operation-request/v" + str(version) for version in range(1, 7))
        or not isinstance(request["authority"], str)
        or not isinstance(request["operation"], str)
        or request["operation"] not in (ARGUMENTS | TRANSFER_ARGUMENTS | REVIEW_ARGUMENTS | INTAKE_ARGUMENTS | FILE_ARGUMENTS | FILE_GROUP_ARGUMENTS)
    ):
        raise StoreError("Unsupported knowledge operation")
    operation, args = request["operation"], request["arguments"]
    file_v6 = set(FILE_GROUP_ARGUMENTS) | {"file.propose-binary"}
    version = ("v6" if operation in file_v6 or operation in FILE_ARGUMENTS and request["format"] == "knowledge-operation-request/v6"
               else "v5" if operation in FILE_ARGUMENTS else "v4" if operation in INTAKE_ARGUMENTS
               else "v3" if operation in REVIEW_ARGUMENTS else "v2" if operation in TRANSFER_ARGUMENTS else "v1")
    if request["format"] != "knowledge-operation-request/" + version:
        raise StoreError("Operation request version does not match the selected operation")
    fields(args, (ARGUMENTS | TRANSFER_ARGUMENTS | REVIEW_ARGUMENTS | INTAKE_ARGUMENTS | FILE_ARGUMENTS | FILE_GROUP_ARGUMENTS)[operation])
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
            "brain-exchange/v1", "mimwell-kg/v1"
        ):
            raise StoreError("Unsupported transfer purpose or format")
    if operation in FILE_ARGUMENTS:
        if operation == "file.history" and (type(args["limit"]) is not int or not 1 <= args["limit"] <= 50):
            raise StoreError("Invalid bounded file history limit")
        if operation in ("file.proposal-inspect", "file.review", "file.publish") and (
                not isinstance(args["proposal"], str) or not re.fullmatch(r"[0-9a-f-]{36}", args["proposal"])):
            raise StoreError("Invalid file proposal identity")
        if operation in ("file.review", "file.publish") and (
                not isinstance(args["expectedProposalSha256"], str) or
                not re.fullmatch(r"[0-9a-f]{64}", args["expectedProposalSha256"])):
            raise StoreError("Exact file proposal basis required")
        if operation == "file.review" and (
                not isinstance(args["reason"], str) or not args["reason"].strip() or len(args["reason"]) > 2000):
            raise StoreError("A bounded review reason is required")
        if operation == "file.propose" and (
                not isinstance(args["expectedRevision"], str) or not re.fullmatch(r"[0-9a-f]{64}", args["expectedRevision"])
                or not isinstance(args["requestId"], str) or not re.fullmatch(r"[0-9a-f-]{36}", args["requestId"])
                or not isinstance(args["reason"], str) or not args["reason"].strip() or len(args["reason"]) > 2000
                or not isinstance(args["documentWire"], str) or len(args["documentWire"]) > 262144):
            raise StoreError("Invalid file proposal")
        if operation == "file.propose-binary" and (
                not isinstance(args["expectedRevision"], str) or not re.fullmatch(r"[0-9a-f]{64}", args["expectedRevision"])
                or not isinstance(args["requestId"], str) or not re.fullmatch(r"[0-9a-f-]{36}", args["requestId"])
                or not isinstance(args["reason"], str) or not args["reason"].strip() or len(args["reason"]) > 2000
                or not isinstance(args["contentBase64"], str) or len(args["contentBase64"]) > 699052):
            raise StoreError("Invalid bounded binary file proposal")
    if operation in FILE_GROUP_ARGUMENTS:
        if operation in ("file.group.propose", "file.group.propose-binary") and (
                not isinstance(args["requestId"], str) or not re.fullmatch(r"[0-9a-f-]{36}", args["requestId"])
                or not isinstance(args["reason"], str) or not args["reason"].strip() or len(args["reason"]) > 2000):
            raise StoreError("Invalid file group proposal")
        if operation in ("file.group.propose", "file.group.propose-binary") and (
                not isinstance(args["expectedGroupRevision"], str) or
                not re.fullmatch(r"[0-9a-f]{64}", args["expectedGroupRevision"]) or
                not isinstance(args["expectedAuthorizationSha256"], str) or
                not re.fullmatch(r"[0-9a-f]{64}", args["expectedAuthorizationSha256"])):
            raise StoreError("Exact registered file group revision required")
        if operation == "file.group.propose" and (not isinstance(args["documentWire"], str) or len(args["documentWire"]) > 65536):
            raise StoreError("Invalid bounded file group text")
        if operation == "file.group.propose-binary" and (not isinstance(args["contentBase64"], str) or len(args["contentBase64"]) > 699052):
            raise StoreError("Invalid bounded file group asset")
        if operation in ("file.group.proposal-inspect", "file.group.review", "file.group.destination-publish", "file.group.status") and (
                not isinstance(args["proposal"], str) or not re.fullmatch(r"[0-9a-f-]{36}", args["proposal"])):
            raise StoreError("Invalid file group proposal identity")
        if operation in ("file.group.review", "file.group.destination-publish") and (
                not isinstance(args["expectedProposalSha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", args["expectedProposalSha256"])):
            raise StoreError("Exact file group proposal basis required")
        if operation == "file.group.destination-publish" and (
                not isinstance(args["destination"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", args["destination"])):
            raise StoreError("Invalid registered destination identity")
    for key in ("proposal", "reason", "source", "consumer"):
        if key in args and (not isinstance(args[key], str) or not args[key].strip() or len(args[key]) > 2000):
            raise StoreError("Invalid operation text")
    if operation == "record.history" and (type(args['limit']) is not int or not 1 <= args['limit'] <= 50):
        raise StoreError('Invalid bounded record history limit')
    if operation in ("record.get", "record.history") and (not isinstance(args["record"], str) or not 1 <= len(args["record"]) <= 2000):
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
    if operation == "record.history":
        return store.history(args['record'], actor, at=at, limit=args['limit'])
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


def _file_authority_response(request, native, actor, at, final_at, binding, limit):
    response = {
        "format": request["format"].replace("knowledge-operation-request/", "knowledge-operation/"),
        "authority": request["authority"],
        "operation": request["operation"],
        "contract": binding,
        "requestWire": encoded(request),
        "requestSha256": fingerprint(request),
        "authorization": {"principal": actor, "evaluatedAt": at, "revalidatedAt": final_at},
        "state": "completed",
        "native": native,
        "nativeWire": encoded(native),
        "nativeSha256": fingerprint(native),
    }
    if request["operation"] == "authority.inspect":
        response["hostCapabilities"] = native.pop("hostCapabilities")
        response["nativeWire"] = encoded(native)
        response["nativeSha256"] = fingerprint(native)
    raw = encode(response)
    if len(raw) > limit:
        raise StoreError("Operation response exceeds its limit")
    return raw


def _run_file_authority(root, host_config, host, selected, request, *, actor, clock, authorize, max_response_bytes):
    operation = request["operation"]
    if operation != "authority.inspect" and operation not in FILE_ARGUMENTS:
        raise StoreError("Operation unavailable for this file authority")
    if operation == "authority.inspect":
        if "authority.inspect" not in selected["grants"].get(actor, []):
            raise StoreError("Operation unavailable")
    elif ("file.propose" if operation == "file.propose-binary" else operation) not in selected["grants"].get(actor, []):
        raise StoreError("Operation unavailable")
    initial = timestamp(clock())

    def guard(not_before=initial):
        if authorize is not None and authorize() != actor:
            raise StoreError("Operation identity changed")
        if load_host(root, host_config) != host or timestamp(clock()) < not_before:
            raise StoreError("Operation host selection changed")

    guard()
    from git_file_authoring import _load_pins, capabilities, run_operation
    pin = _load_pins(root, selected)
    binding = fingerprint(selected)
    if operation == "authority.inspect":
        native = {"authority": request["authority"], "driver": "files", "collections": []}
        file_writer = {"path": pin["path"], "writer": selected["writer"]}
        if selected["writer"] == "json-commit":
            file_writer["schema"] = selected["schema"]
        else:
            file_writer["contentProfile"] = selected["contentProfile"]
        native["hostCapabilities"] = {
            "format": "authoring-capabilities/v1",
            "authority": request["authority"],
            "principal": actor,
            "binding": binding,
            "operations": capabilities(selected, actor),
            "authorization": "host-registration-only",
            "nativePolicy": "required-per-operation",
            "executionAuthorized": False,
            "fileWriter": file_writer,
        }
    else:
        native = run_operation(root, selected, operation, request["arguments"], actor=actor,
                               actors=tuple(selected["grants"]), clock=clock, guard=guard)
    final_at = clock()
    if timestamp(final_at) < initial:
        raise StoreError("Operation clock moved backwards")
    guard(not_before=timestamp(final_at))
    pin_now = _load_pins(root, selected)
    if pin_now["schemaBytes"] != pin["schemaBytes"]:
        raise StoreError("File writer schema changed during operation")
    return _file_authority_response(request, native, actor, initial.isoformat(), final_at,
                                   binding, max_response_bytes)


def _run_file_group_authority(root, host_config, host, group, request, *, actor, clock, authorize, max_response_bytes):
    operation = request["operation"]
    if operation != "authority.inspect" and operation not in FILE_GROUP_ARGUMENTS:
        raise StoreError("Operation unavailable for this publication group")
    verb = {"authority.inspect": "file.inspect", "file.group.inspect": "file.inspect",
            "file.group.propose": "file.propose", "file.group.propose-binary": "file.propose",
            "file.group.proposal-inspect": "file.proposal-inspect", "file.group.review": "file.review",
            "file.group.destination-publish": "file.publish", "file.group.status": "file.proposal-inspect"}.get(operation)
    targets = [host["fileAuthorities"][target_id] for target_id in group["targets"]]
    if verb is None or any(verb not in target["grants"].get(actor, []) for target in targets):
        raise StoreError("Operation unavailable")
    initial = timestamp(clock())
    group_id = request["authority"]
    binding = fingerprint({"group": group, "targets": [{"id": target_id, "entry": host["fileAuthorities"][target_id]}
                                                       for target_id in group["targets"]]})

    def guard(not_before=initial):
        if authorize is not None and authorize() != actor:
            raise StoreError("Operation identity changed")
        if load_host(root, host_config) != host or timestamp(clock()) < not_before:
            raise StoreError("Operation host selection changed")

    guard()
    if operation == "authority.inspect":
        from git_file_publication import inspect
        native = {"authority": group_id, "driver": "files", "collections": [],
                  "group": inspect(root, host, group, group_id)}
        native["hostCapabilities"] = {
            "format": "authoring-capabilities/v1", "authority": group_id, "principal": actor,
            "binding": binding,
            "operations": sorted(name for name, mapped in {
                "file.group.inspect": "file.inspect", "file.group.propose": "file.propose",
                "file.group.propose-binary": "file.propose", "file.group.proposal-inspect": "file.proposal-inspect",
                "file.group.review": "file.review", "file.group.destination-publish": "file.publish",
                "file.group.status": "file.proposal-inspect"}.items()
                if all(mapped in target["grants"].get(actor, []) for target in targets)),
            "authorization": "host-registration-only", "nativePolicy": "required-per-operation",
            "executionAuthorized": False,
        }
    else:
        from git_file_publication import run_group
        native = run_group(root, host, group, group_id, operation, request["arguments"], actor=actor, guard=guard)
    final_at = clock()
    if timestamp(final_at) < initial:
        raise StoreError("Operation clock moved backwards")
    guard(not_before=timestamp(final_at))
    return _file_authority_response(request, native, actor, initial.isoformat(), final_at,
                                   binding, max_response_bytes)


def run(root, host_config, request, *, actor, clock=utcnow, authorize=None, max_response_bytes=MAX_RESPONSE_BYTES):
    """Trusted identity/clock; authorize() refreshes transport identity at each gate."""
    if type(max_response_bytes) is not int or not 1 <= max_response_bytes <= MAX_RESPONSE_BYTES:
        raise StoreError("Invalid operations response bound")
    if len(encode(request)) > MAX_REQUEST_BYTES:
        raise StoreError("Operation request exceeds its limit")
    validate_request(request)
    root = Path(root).absolute()
    host = load_host(root, host_config)
    file_group = host.get("publicationGroups", {}).get(request["authority"])
    if file_group is not None:
        return _run_file_group_authority(root, host_config, host, file_group, request, actor=actor,
                                         clock=clock, authorize=authorize, max_response_bytes=max_response_bytes)
    file_selected = host.get("fileAuthorities", {}).get(request["authority"])
    if file_selected is not None:
        return _run_file_authority(root, host_config, host, file_selected, request, actor=actor,
                                   clock=clock, authorize=authorize, max_response_bytes=max_response_bytes)
    selected = host["authorities"].get(request["authority"])
    operation, args = request["operation"], request["arguments"]
    if selected is None or operation not in selected["grants"].get(actor, []):
        raise StoreError("Operation unavailable")
    from operation_backend import select_backend, supports
    adapter, target, driver, store_id, backend_current = select_backend(root, selected)
    if not supports(driver, operation):
        raise StoreError('Operation is not packaged for this native adapter')
    initial = timestamp(clock())

    def guard(not_before=initial):
        if authorize is not None and authorize() != actor:
            raise StoreError("Operation identity changed")
        if load_host(root, host_config) != host or timestamp(clock()) < not_before:
            raise StoreError("Operation host selection changed")
        backend_current()

    guard()
    write = operation in WRITES
    store = adapter(
        target,
        expected_binding=selected["binding"],
        readonly=not (write or operation == "publication.deliver"),
        intake_clock=clock,
    )
    try:
        if store_id is not None and store.contract.authority != store_id:
            raise StoreError('Native authority store differs from the registered writer')
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
            if operation == "authority.inspect":
                # Host availability is separate from the untouched native
                # description. It never promises per-record permission.
                response["hostCapabilities"] = {
                    "format": "authoring-capabilities/v1",
                    "authority": request["authority"],
                    "principal": actor,
                    "binding": store.contract.binding,
                    "operations": sorted(verb for verb in selected["grants"][actor] if supports(driver, verb)),
                    "authorization": "host-registration-only",
                    "nativePolicy": "required-per-operation",
                    "executionAuthorized": False,
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
