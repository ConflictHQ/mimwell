"""Shared registered source capture and extraction using existing native engines."""

from copy import deepcopy
from functools import partial
from pathlib import Path

from brain_federation import fields
from context_access import ContextAccessError, ReadBoundary
from context_host import decode
from intake_capture import authorize, bind_capture, capture, check, read_stable, save_capture
from intake_extraction import extract_capture, profile_check
from knowledge_policy import fingerprint, timestamp
from knowledge_store import StoreError
from maintenance_audit import audit, operation as log_operation

MAX_SOURCE_BYTES = 16 * 1024 * 1024


def list_sources(root, selected, store, args, *, actor, at, guard):
    """Discover authorized registrations, without touching source bytes or paths."""
    guard()
    store._read_state()
    rows, configurations = [], []
    for identity in sorted(selected.get("sources", {})):
        source = registration(selected, identity)
        try:
            boundary = ReadBoundary(
                store.contract.policy, actor=actor, now=at, scopes=source["scopes"],
                bindings={key: {} for key in ("nodes", "edges", "paths", "assertions", "references")},
            )
        except ContextAccessError:
            # A registration's explicitly selected read scope may be unavailable
            # to this actor. Do not expose it or suppress other readable sources.
            continue
        if not boundary.permits_resource(source["registration"]["resource"], identity):
            continue
        authorize(boundary, source["registration"])
        rows.append(registration_view(source))
        configurations.append(fingerprint(source))
    guard()
    basis = fingerprint({"instance": store._meta("instance"), "contract": store.contract.binding,
                         "actor": actor, "sources": rows, "configurations": configurations})
    cursor, start = args["cursor"], 0
    if cursor is not None:
        ids = [row["source"] for row in rows]
        if cursor["basisSha256"] != basis or cursor["after"] not in ids:
            raise StoreError("Source list changed; refresh the selection")
        start = ids.index(cursor["after"]) + 1
    page = rows[start:start + args["limit"]]
    return {"format": "source-registration-list/v1", "basisSha256": basis,
            "sources": page, "visibleTotal": len(rows),
            "nextCursor": {"basisSha256": basis, "after": page[-1]["source"]}
                          if start + len(page) < len(rows) else None,
            "availability": "not-observed", "freshness": "unknown"}


def registration(selected, identity):
    source = selected.get("sources", {}).get(identity)
    if source is None:
        raise StoreError("Source unavailable")
    fields(source, ("registration", "root", "scopes", "maxBytes", "extraction"))
    check(source["registration"], "registration")
    if (
        source["registration"]["id"] != identity
        or not isinstance(source["root"], str)
        or not Path(source["root"]).is_absolute()
        or not isinstance(source["scopes"], list)
        or not source["scopes"]
        or any(not isinstance(scope, str) for scope in source["scopes"])
        or type(source["maxBytes"]) is not int
        or not 1 <= source["maxBytes"] <= MAX_SOURCE_BYTES
    ):
        raise StoreError("Invalid registered source")
    profile_check(source["extraction"])
    if source["extraction"]["maxSourceBytes"] > source["maxBytes"]:
        raise StoreError("Extraction exceeds the registered source bound")
    source = deepcopy(source)
    source["root"] = str(Path(source["root"]))
    return source


def registration_view(source):
    """Shared sanitized registration observation; no source availability claim."""
    registered = source["registration"]
    profile = source["extraction"]
    return {
        "format": "source-registration-view/v1",
        "source": registered["id"],
        "registrationSha256": fingerprint(registered),
        "sourceId": registered["sourceId"],
        "itemId": registered["itemId"],
        "mediaType": registered["mediaType"],
        "resource": registered["resource"],
        "scopes": source["scopes"],
        "expectedSourceSha256": registered["sha256"],
        "maxBytes": source["maxBytes"],
        "extraction": {
            "adapter": profile["adapter"],
            "profileSha256": fingerprint(profile),
            "maxSourceBytes": profile["maxSourceBytes"],
            "maxTextBytes": profile["maxTextBytes"],
            "maxPages": profile["maxPages"],
            "timeoutSeconds": profile["timeoutSeconds"],
        },
        "availability": "not-observed",
        "freshness": "unknown",
    }


def run_source(root, selected, store, operation, args, *, actor, clock, guard):
    from knowledge_operations import private_path

    source = registration(selected, args["source"])
    registered = source["registration"]
    initial = timestamp(clock())
    last = [initial]

    def boundary():
        guard(not_before=last[0])
        now = clock()
        if timestamp(now) < last[0]:
            raise StoreError("Source operation clock moved backwards")
        last[0] = timestamp(now)
        store._read_state()
        view = ReadBoundary(
            store.contract.policy,
            actor=actor,
            now=now,
            scopes=source["scopes"],
            bindings={key: {} for key in ("nodes", "edges", "paths", "assertions", "references")},
        )
        authorize(view, registered)
        return view

    current = boundary()  # Read permission precedes source/cache access and audit.
    if operation == "source.inspect":
        return registration_view(source), boundary().now
    with audit(root) as journal:
        log = partial(log_operation, journal)
        if operation == "source.capture":
            capsule = capture(
                current,
                registered,
                root=source["root"],
                max_bytes=source["maxBytes"],
                expected_sha256=args["expectedSourceSha256"],
                log=log,
            )
            digest = fingerprint(capsule)
            # A final source gate precedes private cache publication; a later
            # failed response may leave a valid private orphan, never a record.
            final = boundary()
            bind_capture(final, registered, capsule, expected_sha256=digest, log=log)
            save_capture(root, capsule)
            log("capture.saved", actor, digest, {"itemSha256": fingerprint(capsule["receipt"]["item"])})
            return {
                "format": "source-capture-result/v1",
                "source": registered["id"],
                "captureSha256": digest,
                "receipt": capsule["receipt"],
            }, boundary().now
        digest = args["captureSha256"]
        # The caller selects a receipt ID, never supplies a capsule or cache path.
        # Only private host-owned capture files are admitted; source authorization
        # and the registration binding still precede content release.
        relative = "_internal/intake/captures/" + digest + ".json"
        private_path(root, relative)
        raw, _ = read_stable(root, relative, ((source["maxBytes"] + 2) // 3) * 4 + 2097152)
        capsule = decode(raw)
        if capsule.get("receipt", {}).get("rootSha256") != fingerprint(
            {"id": registered["root"], "path": source["root"]}
        ):
            raise StoreError("Capture belongs to an earlier source-root registration")
        current, item, _ = bind_capture(boundary(), registered, capsule, expected_sha256=digest, log=log)
        if item["source"]["byteLength"] > source["maxBytes"]:
            raise StoreError("Captured source exceeds its registration bound")
        profile = source["extraction"]
        if operation == "source.extraction-preview":
            return {
                "format": "source-extraction-preview/v1",
                "source": registered["id"],
                "captureSha256": digest,
                "item": item,
                "profileSha256": fingerprint(profile),
                "adapter": profile["adapter"],
                "sourceBytes": item["source"]["byteLength"],
                "maxTextBytes": profile["maxTextBytes"],
                "maxPages": profile["maxPages"],
                "timeoutSeconds": profile["timeoutSeconds"],
                "modelCalls": 0,
                "processCalls": int(profile["adapter"] == "poppler-text/v1"),
                "state": "planned",
                "sourceBasis": "historical-capture; current read authorization",
            }, boundary().now
        if operation != "source.extract" or args["expectedProfileSha256"] != fingerprint(profile):
            raise StoreError("Extraction selection changed; preview again")
        result = extract_capture(boundary, registered, capsule, expected_sha256=digest, profile=profile, log=log)
        return result, boundary().now
