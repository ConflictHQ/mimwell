"""Bounded, staged native transfer for opt-in Studio App records.

Every stage produces only a native proposal. The caller must use the destination
authority's ordinary independent review and commit operations, then resume with
the returned operator receipt. Blob storage is immutable and outside the native
record transaction; a failed proposal can leave orphaned destination blobs.
"""

from copy import deepcopy
import hashlib
import json

from blob_store import decode as decode_blob, encode as encode_blob, locator as make_locator, verify as verify_blob
from knowledge_policy import fingerprint
from knowledge_store import StoreError
from studio_app_attachments import verify_app_attachment_bytes

FORMAT = "studio-app-transfer/v1"
RECEIPT_FORMAT = "studio-app-import-receipt/v1"
PROTECTED_SOURCE_CONTEXT = "studio-app-transfer-protected-context/v2"
MAX_PACKAGE_BYTES = 32 * 1024 * 1024
STAGES = ("metric", "studio.app-query", "studio.component", "studio.app")


def _stage(record):
    kind = record.get("kind")
    return "metric" if kind == "metric" else kind


def _destination_id(source_authority, source_binding, identity):
    prefix, separator, _ = identity.partition(":")
    if not separator:
        raise StoreError("Studio App transfer record identity is invalid")
    suffix = fingerprint({"source": source_authority, "binding": source_binding, "id": identity})[:24]
    return prefix + ":import-" + suffix


def _context(package, locator, source_attachment=None):
    app = next(value for value in package["records"] if value["record"]["kind"] == "studio.app")
    if source_attachment is not None and source_attachment.get("protection") is not None:
        protection = source_attachment["protection"]
        if (not isinstance(protection, dict)
                or set(protection) != {"format", "contentBytes", "contentSha256"}
                or protection.get("format") != "protected-bytes/v1"
                or type(protection.get("contentBytes")) is not int
                or not 1 <= protection["contentBytes"] <= 16 * 1024 * 1024
                or not isinstance(protection.get("contentSha256"), str)
                or len(protection["contentSha256"]) != 64
                or any(char not in "0123456789abcdef" for char in protection["contentSha256"])
                or source_attachment.get("blob") != locator):
            raise StoreError("Protected source App attachment pins are invalid")
        source_attachment_fields = {key: deepcopy(value) for key, value in source_attachment.items()
                                    if key not in {"blob", "protection"}}
        return {"format": PROTECTED_SOURCE_CONTEXT,
                "sourceAuthority": package["source"]["authority"],
                "sourceBinding": package["source"]["binding"],
                "destinationAuthority": package["destination"]["authority"],
                "destinationBinding": package["destination"]["binding"],
                "record": app["record"]["id"], "recordRevision": app["revision"],
                "sourceAttachment": source_attachment_fields,
                "sourceLocator": deepcopy(locator),
                "content": {"sha256": protection["contentSha256"],
                            "bytes": protection["contentBytes"]}}
    return {"sourceAuthority": package["source"]["authority"],
            "sourceBinding": package["source"]["binding"],
            "destinationAuthority": package["destination"]["authority"],
            "destinationBinding": package["destination"]["binding"],
            "record": app["record"]["id"], "recordRevision": app["revision"],
            "sourceStore": locator["store"], "key": locator["key"],
            "sha256": locator["sha256"], "bytes": locator["bytes"]}


def _now(clock):
    value = clock()
    if not isinstance(value, str) or not value:
        raise StoreError("Studio App transfer clock is unavailable")
    return value


def _guard(source, destination, app_id, actor, source_authority, destination_authority,
           source_binding, destination_binding, clock, identity_guard, expected_records=None):
    at = _now(clock)
    if not callable(identity_guard) or identity_guard(
            actor, source_authority, destination_authority, source_binding, destination_binding) is not True:
        raise StoreError("Studio App transfer host identity changed or was revoked")
    if (source.contract.binding != source_binding or destination.contract.binding != destination_binding
            or not source.contract.studio_apps_enabled or not destination.contract.studio_apps_enabled):
        raise StoreError("Studio App transfer source or destination binding changed")
    records = _collect(source, app_id, actor, at)
    if expected_records is not None and records != expected_records:
        raise StoreError("Studio App source changed or read access was revoked; restart the transfer")
    return at, records


def _seal_bytes(raw, context, protection):
    if context.get("format") == PROTECTED_SOURCE_CONTEXT and protection is None:
        raise StoreError("Protected source App attachments cannot be declassified by transfer")
    if protection is None:
        return {"encoding": "base64/v1", "content": encode_blob(raw)}
    host, required, selected = protection[:3]
    if selected.get("mode") != "per-record":
        raise StoreError("Selected protection profile has no portable App blob envelope")
    digest = fingerprint(context)
    from brain_protection import ProtectionError
    try:
        sealed = host.seal_bytes(raw, context=context, object_id=digest[:32],
            revision=hashlib.sha256(context["recordRevision"].encode()).hexdigest()[:32],
            required=required, selected=selected)
    except ProtectionError as exc:
        raise StoreError("Protected App attachment cannot be sealed under the selected profile") from exc
    encoding = "protected-bytes/v2" if context.get("format") == PROTECTED_SOURCE_CONTEXT else "protected-bytes/v1"
    return {"encoding": encoding, "envelope": sealed}


def _open_bytes(value, context, protection):
    if value.get("encoding") == "base64/v1":
        if protection is not None:
            required, selected = protection[1], protection[2]
            if (selected.get("mode") != "plaintext" or required.get("encryption") or required.get("mediation")
                    or not required.get("plaintextCopies")):
                raise StoreError("Plaintext App attachment is forbidden by destination protection requirements")
        try:
            raw = decode_blob(value["content"])
        except Exception as exc:
            raise StoreError("Studio App attachment transfer bytes are invalid") from exc
    elif value.get("encoding") == "protected-record/v1":
        if protection is None:
            raise StoreError("Protected App attachment requires a configured ProtectionHost")
        host, required, selected = protection
        from brain_protection import ProtectionError
        digest = fingerprint(context)
        if value.get("contextSha256") != digest:
            raise StoreError("Protected App attachment context differs from the selected transfer")
        try:
            body = host.open(value["envelope"], expected_object=digest[:32],
                             expected_revision=hashlib.sha256(context["recordRevision"].encode()).hexdigest()[:32],
                             expected_profile=selected, required=required, offline=True)
        except ProtectionError as exc:
            raise StoreError("Protected App attachment cannot be opened under the selected profile") from exc
        if not isinstance(body, dict) or body.get("context") != context:
            raise StoreError("Protected App attachment is bound to another transfer")
        try:
            raw = decode_blob(body["content"])
        except Exception as exc:
            raise StoreError("Protected App attachment bytes are invalid") from exc
    elif value.get("encoding") in ("protected-bytes/v1", "protected-bytes/v2"):
        if protection is None:
            raise StoreError("Protected App attachment requires a configured ProtectionHost")
        if ((value.get("encoding") == "protected-bytes/v2")
                != (context.get("format") == PROTECTED_SOURCE_CONTEXT)):
            raise StoreError("Protected App attachment context version is unsupported")
        host, required, selected = protection[:3]
        from brain_protection import ProtectionError
        try:
            envelope = value.get("envelope")
            digest = fingerprint(context)
            raw = host.open_bytes(envelope, context=context, expected_object=digest[:32],
                expected_revision=hashlib.sha256(context["recordRevision"].encode()).hexdigest()[:32],
                expected_profile=selected, required=required)
        except (ProtectionError, TypeError, ValueError) as exc:
            raise StoreError("Protected App attachment cannot be opened under the selected profile") from exc
    else:
        raise StoreError("Unsupported Studio App attachment envelope")
    if context.get("format") == PROTECTED_SOURCE_CONTEXT:
        content_pin = context.get("content")
        if (not isinstance(content_pin, dict) or set(content_pin) != {"sha256", "bytes"}
                or type(content_pin.get("bytes")) is not int
                or not 1 <= content_pin["bytes"] <= 16 * 1024 * 1024
                or not isinstance(content_pin.get("sha256"), str)
                or len(content_pin["sha256"]) != 64
                or any(char not in "0123456789abcdef" for char in content_pin["sha256"])):
            raise StoreError("Protected App attachment content pin is invalid")
        expected_bytes = content_pin["bytes"]
        expected_sha256 = content_pin["sha256"]
    else:
        expected_bytes = context["bytes"]
        expected_sha256 = context["sha256"]
    if len(raw) != expected_bytes or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise StoreError("Studio App attachment bytes differ from the pinned source")
    return raw


def _collect(source, app_id, actor, at):
    if not source.contract.studio_apps_enabled:
        raise StoreError("Studio App transfer requires the explicitly selected apps profile")
    opened = not source.dialect.in_transaction
    if opened:
        source.dialect.begin()
    try:
        result = source.get(app_id, actor, at=at)
        if not result or not isinstance(result.get("record"), dict) or result["record"].get("kind") != "studio.app":
            raise StoreError("Studio App transfer source is unavailable")
        if result.get("withheldRelations"):
            raise StoreError("Studio App transfer contains relationships outside the source read scope")
        app = result["record"]
        targets = source._readable_studio_binding_targets(app, actor, at)
        from studio_app_bindings import app_binding_status
        if not app_binding_status(app, targets)["available"]:
            raise StoreError("Studio App bindings are unavailable at the source")
        records = [{"revision": result["revision"], "record": app}]
        records.extend({"revision": value["revision"], "record": {k: v for k, v in value.items() if k != "revision"}}
                       for value in targets.values()
                       if value.get("kind") in ("metric", "studio.app-query", "studio.component"))
        records.sort(key=lambda value: (STAGES.index(_stage(value["record"])), value["record"]["id"]))
        ids = {value["record"]["id"] for value in records}
        for value in records:
            if value["record"].get("blobs") and value["record"]["kind"] != "studio.app":
                raise StoreError("Studio App transfer cannot omit blobs from a bound dependency")
            visible = []
            for edge in value["record"]["relations"]:
                if not source._target_readable(edge["target"], actor, at):
                    raise StoreError("Studio App transfer contains relationships outside the source read scope")
                if edge["target"] not in ids:
                    raise StoreError("Studio App transfer has an unselected native relationship dependency")
                visible.append(edge)
            value["record"]["relations"] = visible
        return records
    finally:
        if opened and source.dialect.in_transaction:
            source.dialect.rollback()


def _collections(destination):
    result = {}
    for identity, value in destination.contract.collections.items():
        result.setdefault(value["kind"], []).append((identity, value))
    return result


def _request(destination, record, package_sha, actor, at):
    collections = _collections(destination).get(record["kind"], [])
    if len(collections) != 1:
        raise StoreError("Destination must declare exactly one collection for each imported kind")
    collection_id, collection = collections[0]
    request = {"id": "studio-transfer-" + package_sha[:24] + "-" + fingerprint(record["id"])[:12],
               "resource": collection["resource"], "record": record["id"], "mutation": "create",
               "expectedRevision": None, "reason": "Import reviewed Studio App package " + package_sha,
               "evidence": ["studio-app-transfer:" + package_sha], "sourceResource": None}
    destination.contract.decision(request, actor, "propose", None, at=at)
    return request, collection_id


def prepare_package(source, destination, app_id, actor, *, source_authority, destination_authority,
                    blob_reader, protection, source_protection=None,
                    destination_blob_protected, clock, identity_guard):
    """Prepare a pinned graph and exact attachment bytes for one destination.

    `blob_reader` is a trusted host callback. Native source policy is checked before
    it is called. Protected attachment envelopes bind both authorities, contract
    bindings, App revision and source blob locator.
    """
    if (not isinstance(source_authority, str) or not source_authority
            or not isinstance(destination_authority, str) or not destination_authority
            or not destination.contract.studio_apps_enabled):
        raise StoreError("Studio App transfer authority selection is unavailable")
    if type(destination_blob_protected) is not bool:
        raise StoreError("Destination blob protection must be selected by the trusted host")
    at, records = _guard(source, destination, app_id, actor, source_authority, destination_authority,
                         source.contract.binding, destination.contract.binding, clock, identity_guard)
    root = next(value for value in records if value["record"]["kind"] == "studio.app")
    # Check all destination kind and write-policy boundaries before reading bytes.
    if not destination.contract.studio_apps_enabled:
        raise StoreError("Destination does not select the Studio apps profile")
    for value in records:
        identity = _destination_id(source_authority, source.contract.binding, value["record"]["id"])
        current = destination._record_metadata(identity)
        if current is not None:
            raise StoreError("Destination record identity is already used or tombstoned")
        record = {**deepcopy(value["record"]), "id": identity}
        _request(destination, record, "0" * 64, actor, at)

    app = root["record"]
    attachments = app.get("content", {}).get("data", {}).get("attachments", [])
    if (not destination_blob_protected
            and any(isinstance(item, dict) and item.get("protection") is not None
                    for item in attachments)):
        raise StoreError("Protected source App attachments cannot be declassified by transfer")
    if attachments and destination_blob_protected and protection is None:
        raise StoreError("Protected destination App attachments require an authorized durable byte provider")
    locators = {item["key"]: item for item in app.get("blobs", [])}
    attachment_by_key = {item["blob"]["key"]: item
                         for item in app.get("content", {}).get("data", {}).get("attachments", [])}
    raw_contents = {}
    stored_contents = {}
    for key, locator in locators.items():
        if not callable(blob_reader):
            raise StoreError("A trusted source blob reader is required")
        try:
            stored = verify_blob(locator, blob_reader(locator))
            stored_contents[key] = stored
            attachment = attachment_by_key.get(key)
            if not isinstance(attachment, dict):
                raise StoreError("Studio App source attachment metadata is unavailable")
            if attachment.get("protection") is not None:
                if source_protection is None:
                    raise StoreError("Protected source App attachment requires its current byte provider")
                from studio_app_mcp import _open_attachment
                raw = _open_attachment(stored, binding=source.contract.binding,
                    record_id=app["id"], attachment=attachment, protection=source_protection)
            else:
                raw = stored
            if attachment.get("role") == "pglite-snapshot" and attachment.get("protection") is not None:
                from studio_app_attachments import verify_pglite_snapshot_bytes
                verify_pglite_snapshot_bytes(attachment, raw)
        except Exception as exc:
            raise StoreError("Selected Studio App attachment is unavailable") from exc
        raw_contents[key] = raw
    if attachments:
        verify_app_attachment_bytes(app, stored_contents)
    package = {"format": FORMAT,
               "source": {"authority": source_authority, "binding": source.contract.binding,
                          "recordRevisions": {value["record"]["id"]: value["revision"] for value in records}},
               "destination": {"authority": destination_authority, "binding": destination.contract.binding,
                               "blobProtected": destination_blob_protected},
               "app": app_id, "records": deepcopy(records), "attachments": []}
    for key, locator in locators.items():
        attachment = attachment_by_key[key]
        context = _context(package, locator, attachment)
        item = {"locator": deepcopy(locator),
                "payload": _seal_bytes(raw_contents[key], context, protection)}
        if destination_blob_protected:
            attachment = attachment_by_key[key]
            destination_id = _destination_id(source_authority, source.contract.binding, app_id)
            from studio_app_mcp import _seal_attachment
            stored, protection_metadata = _seal_attachment(raw_contents[key],
                binding=destination.contract.binding, record={"id": destination_id},
                role=attachment["role"], fmt=attachment["format"], protection=protection,
                source_revision=attachment["source"]["revision"])
            destination_locator = make_locator(destination.contract.blob_store,
                "sha256/" + hashlib.sha256(stored).hexdigest(), stored, locator["mediaType"])
            item["destinationStorage"] = {"locator": destination_locator,
                "data": encode_blob(stored), "protection": protection_metadata}
        package["attachments"].append(item)
    package["sha256"] = fingerprint(package)
    from context_bundle import encode
    if len(encode(package)) > MAX_PACKAGE_BYTES:
        raise StoreError("Studio App transfer package exceeds its limit")
    _guard(source, destination, app_id, actor, source_authority, destination_authority,
           package["source"]["binding"], package["destination"]["binding"], clock, identity_guard, records)
    for value in records:
        rewritten = {**deepcopy(value["record"]), "id": _destination_id(
            source_authority, package["source"]["binding"], value["record"]["id"])}
        _request(destination, rewritten, package["sha256"], actor, _now(clock))
    return package


def verify_current_source(source, destination, package, actor, *, source_authority,
                          destination_authority, blob_reader, source_protection, protection,
                          destination_blob_protected, clock, identity_guard):
    """Recheck a retained transfer package without resealing randomized envelopes."""
    _validate_package(package)
    if (source_authority != package["source"]["authority"]
            or destination_authority != package["destination"]["authority"]
            or destination_blob_protected != package["destination"]["blobProtected"]):
        raise StoreError("Studio App transfer source or destination binding changed")
    _guard(source, destination, package["app"], actor, source_authority, destination_authority,
        package["source"]["binding"], package["destination"]["binding"], clock, identity_guard,
        package["records"])
    app = next(value["record"] for value in package["records"] if value["record"]["kind"] == "studio.app")
    attachments = {item["blob"]["key"]: item for item in
        app.get("content", {}).get("data", {}).get("attachments", [])}
    for item in package["attachments"]:
        locator = item["locator"]
        try:
            stored = verify_blob(locator, blob_reader(locator))
            attachment = attachments[locator["key"]]
            if attachment.get("protection") is not None:
                if source_protection is None:
                    raise StoreError("Protected source App attachment requires its current byte provider")
                from studio_app_mcp import _open_attachment
                current = _open_attachment(stored, binding=source.contract.binding,
                    record_id=package["app"], attachment=attachment, protection=source_protection)
            else:
                current = stored
            source_attachment = attachments.get(locator["key"])
            if not isinstance(source_attachment, dict):
                raise StoreError("Studio App source attachment metadata is unavailable")
            packaged = _open_bytes(item["payload"], _context(package, locator, source_attachment), protection)
        except StoreError:
            raise
        except Exception as exc:
            raise StoreError("Studio App transfer source attachment is unavailable") from exc
        if current != packaged:
            raise StoreError("Studio App transfer source changed")
    _guard(source, destination, package["app"], actor, source_authority, destination_authority,
        package["source"]["binding"], package["destination"]["binding"], clock, identity_guard,
        package["records"])
    return True


def new_receipt(package):
    _validate_package(package)
    return {"format": RECEIPT_FORMAT, "packageSha256": package["sha256"],
            "source": deepcopy(package["source"]), "destination": deepcopy(package["destination"]),
            "records": {value["record"]["id"]: {"destinationId": _destination_id(
                package["source"]["authority"], package["source"]["binding"], value["record"]["id"])}
                        for value in package["records"]}}


def _validate_package(package):
    if (not isinstance(package, dict) or set(package) != {
            "format", "source", "destination", "app", "records", "attachments", "sha256"}
            or package.get("format") != FORMAT
            or not isinstance(package.get("source"), dict)
            or set(package["source"]) != {"authority", "binding", "recordRevisions"}
            or not isinstance(package["destination"], dict)
            or set(package["destination"]) != {"authority", "binding", "blobProtected"}
            or type(package["destination"].get("blobProtected")) is not bool
            or any(not isinstance(package[side].get("authority"), str) or not package[side]["authority"]
                   or not isinstance(package[side].get("binding"), str)
                   or len(package[side]["binding"]) != 64
                   or any(char not in "0123456789abcdef" for char in package[side]["binding"])
                   for side in ("source", "destination"))
            or not isinstance(package["source"].get("recordRevisions"), dict)
            or not isinstance(package.get("app"), str) or not package["app"]
            or not isinstance(package.get("records"), list) or not 1 <= len(package["records"]) <= 256
            or not isinstance(package.get("attachments"), list) or len(package["attachments"]) > 8):
        raise StoreError("Studio App transfer package is invalid")
    identities = []
    allowed = {"metric", "studio.app-query", "studio.component", "studio.app"}
    for item in package["records"]:
        if (not isinstance(item, dict) or set(item) != {"revision", "record"}
                or not isinstance(item["revision"], str) or not item["revision"]
                or not isinstance(item["record"], dict) or item["record"].get("kind") not in allowed
                or not isinstance(item["record"].get("id"), str)):
            raise StoreError("Studio App transfer package record is invalid")
        identities.append(item["record"]["id"])
    if (len(identities) != len(set(identities)) or package["app"] not in identities
            or sum(item["record"]["kind"] == "studio.app" for item in package["records"]) != 1
            or package["source"]["recordRevisions"] != {
                item["record"]["id"]: item["revision"] for item in package["records"]}):
        raise StoreError("Studio App transfer package source revision map is invalid")
    app = next(item["record"] for item in package["records"] if item["record"]["kind"] == "studio.app")
    from studio_app_attachments import validate_app_attachments
    validate_app_attachments(app)
    # Protected destinations carry an independently sealed final blob in
    # addition to the transfer-session envelope. The source record remains
    # immutable in the package; the final locator is applied only when the
    # destination proposal is prepared.
    for item in package["records"]:
        if item["record"]["kind"] != "studio.app" and item["record"].get("blobs"):
            raise StoreError("Studio App transfer cannot omit blobs from a bound dependency")
    locators = {locator["key"]: locator for locator in app.get("blobs", [])}
    attachments = package["attachments"]
    if any(not isinstance(item, dict) or set(item) not in (
                {"locator", "payload"}, {"locator", "payload", "destinationStorage"})
           or not isinstance(item.get("locator"), dict) or not isinstance(item.get("payload"), dict)
           for item in attachments):
        raise StoreError("Studio App transfer package attachment set is invalid")
    attachment_keys = [item["locator"].get("key") for item in attachments]
    app_attachments = app.get("content", {}).get("data", {}).get("attachments", [])
    if (any(isinstance(item, dict) and item.get("protection") is not None
            for item in app_attachments) and not package["destination"]["blobProtected"]):
        raise StoreError("Protected source App attachments cannot be declassified by transfer")
    if (len(attachment_keys) != len(set(attachment_keys)) or set(attachment_keys) != set(locators)
            or any(item["locator"] != locators.get(item["locator"].get("key"))
                   or item["payload"].get("encoding") not in (
                       "base64/v1", "protected-record/v1", "protected-bytes/v1", "protected-bytes/v2")
                   for item in attachments)):
        raise StoreError("Studio App transfer package attachment set is invalid")
    source_attachment_by_key = {item["blob"]["key"]: item for item in app_attachments
                                if isinstance(item, dict) and isinstance(item.get("blob"), dict)}
    for item in attachments:
        source_attachment = source_attachment_by_key.get(item["locator"].get("key"))
        source_protected = isinstance(source_attachment, dict) and source_attachment.get("protection") is not None
        if source_protected and item["payload"].get("encoding") != "protected-bytes/v2":
            raise StoreError("Legacy protected-source transfer package context is unsupported")
        if not source_protected and item["payload"].get("encoding") == "protected-bytes/v2":
            raise StoreError("Protected-source transfer context has no protected source attachment")
    if package["destination"]["blobProtected"] and len(attachments) != len(locators):
        raise StoreError("Protected destination App attachment set is incomplete")
    for item in attachments:
        destination_storage = item.get("destinationStorage")
        if package["destination"]["blobProtected"] != (destination_storage is not None):
            raise StoreError("Studio App destination protection storage is incomplete")
        if destination_storage is not None:
            if (not isinstance(destination_storage, dict)
                    or set(destination_storage) != {"locator", "data", "protection"}
                    or not isinstance(destination_storage.get("locator"), dict)
                    or not isinstance(destination_storage.get("data"), str)
                    or not isinstance(destination_storage.get("protection"), dict)):
                raise StoreError("Studio App destination protection storage is invalid")
            try:
                stored = decode_blob(destination_storage["data"])
                verify_blob(destination_storage["locator"], stored)
            except Exception as exc:
                raise StoreError("Studio App destination protection storage is invalid") from exc
    if package.get("sha256") != fingerprint({k: v for k, v in package.items() if k != "sha256"}):
        raise StoreError("Studio App transfer package digest is invalid")
    from context_bundle import encode
    raw = encode({k: v for k, v in package.items() if k != "sha256"})
    if len(raw) > MAX_PACKAGE_BYTES:
        raise StoreError("Studio App transfer package exceeds its limit")


def _validate_receipt(package, receipt, destination):
    _validate_package(package)
    if (not isinstance(receipt, dict) or set(receipt) != {"format", "packageSha256", "source", "destination", "records"}
            or receipt.get("format") != RECEIPT_FORMAT
            or receipt.get("packageSha256") != package["sha256"]
            or receipt.get("source") != package["source"] or receipt.get("destination") != package["destination"]
            or receipt["destination"].get("binding") != destination.contract.binding
            or not isinstance(receipt.get("records"), dict)):
        raise StoreError("Studio App import receipt does not match selected package and destination")
    expected = new_receipt(package)["records"]
    if set(receipt["records"]) != set(expected) or any(
        not isinstance(receipt["records"].get(identity), dict)
        or receipt["records"][identity].get("destinationId") != value["destinationId"]
        for identity, value in expected.items()
    ):
        raise StoreError("Studio App import receipt record mapping is invalid")
    for state in receipt["records"].values():
        if set(state) - {"destinationId", "proposal", "recordSha256", "phase", "destinationRevision"}:
            raise StoreError("Studio App import receipt state is invalid")
        if "proposal" in state and (not isinstance(state["proposal"], str) or not state["proposal"]):
            raise StoreError("Studio App import receipt proposal is invalid")
        if "recordSha256" in state and (not isinstance(state["recordSha256"], str)
                or len(state["recordSha256"]) != 64):
            raise StoreError("Studio App import receipt content pin is invalid")
        if "phase" in state and state["phase"] not in STAGES:
            raise StoreError("Studio App import receipt phase is invalid")
        if "destinationRevision" in state and (not isinstance(state["destinationRevision"], str)
                or not state["destinationRevision"]):
            raise StoreError("Studio App import receipt destination revision is invalid")
    return receipt


def _rewrite(record, receipt, destination, package_sha, destination_revisions,
             destination_storage_by_source_key=None):
    value = deepcopy(record)
    origin_id = value["id"]
    entry = receipt["records"][origin_id]
    value["id"] = entry["destinationId"]
    collections = _collections(destination).get(value["kind"], [])
    if len(collections) != 1:
        raise StoreError("Destination kind collection selection is ambiguous")
    value["collection"] = collections[0][0]
    id_map = {identity: item["destinationId"] for identity, item in receipt["records"].items()}
    revision_map = destination_revisions
    if any(target not in id_map for edge in value["relations"] for target in [edge["target"]]):
        raise StoreError("Studio App relationship target is outside the transfer package")
    for edge in value["relations"]:
        edge["target"] = id_map[edge["target"]]
    data = value.get("content", {}).get("data", {})
    if value["kind"] == "studio.app-query":
        source_target = data["metric"]
        if source_target not in id_map or not revision_map[source_target]:
            raise StoreError("Destination Metric must be committed before its App Query")
        data["metric"] = id_map[source_target]
        data["metricRevision"] = revision_map[source_target]
    elif value["kind"] == "studio.component":
        for binding in data["queryBindings"]:
            origin = binding["query"]
            binding["query"] = id_map[origin]
            binding["revision"] = revision_map[origin]
    elif value["kind"] == "studio.app":
        for section in data["layout"]["sections"]:
            origin = section["component"]
            section["component"] = id_map[origin]
            section["componentRevision"] = revision_map[origin]
    if value.get("blobs"):
        if destination.contract.blob_store is None:
            raise StoreError("Destination has no native blob store for App attachments")
        destination_storage_by_source_key = destination_storage_by_source_key or {}
        for locator in value["blobs"]:
            selected_storage = destination_storage_by_source_key.get(locator["key"])
            if selected_storage is not None:
                locator.update(deepcopy(selected_storage["locator"]))
            else:
                locator["store"] = destination.contract.blob_store
        for attachment in data.get("attachments", []):
            old_key = attachment["blob"]["key"]
            selected_storage = destination_storage_by_source_key.get(old_key)
            if selected_storage is not None:
                attachment["blob"] = deepcopy(selected_storage["locator"])
                attachment["protection"] = deepcopy(selected_storage["protection"])
            else:
                attachment["blob"]["store"] = destination.contract.blob_store
    return value


def _commit_receipt(destination, proposal):
    from proposal_disposition import committed, intent

    if committed(destination, proposal) != "committed":
        raise StoreError("Studio App import requires an attributed native commit receipt")
    rows = destination.dialect.receipts_for(intent(proposal))
    for body in rows:
        value = json.loads(body)
        if value.get("proposal") == proposal["id"]:
            return value
    raise StoreError("Studio App import commit receipt is unavailable")


def _verify_existing(destination, source_item, receipt, actor, at, package_sha, revisions,
                     destination_storage_by_source_key=None):
    origin_id = source_item["record"]["id"]
    state = receipt["records"][origin_id]
    proposal_id = state.get("proposal")
    if not proposal_id:
        if any(key in state for key in ("recordSha256", "phase", "destinationRevision")):
            raise StoreError("Studio App import receipt has unauthenticated proposal state")
        if destination._record_metadata(state["destinationId"]) is not None:
            raise StoreError("Studio App destination record exists without its transfer proposal")
        return None
    expected = _rewrite(source_item["record"], receipt, destination, package_sha, revisions,
                        destination_storage_by_source_key)
    request, _ = _request(destination, expected, package_sha, actor, at)
    inspected = destination.inspect(proposal_id, actor, at=at)
    proposal = inspected["proposal"]
    if (proposal.get("id") != proposal_id or proposal.get("actor") != actor
            or proposal.get("contract") != destination.contract.binding or proposal.get("request") != request
            or proposal.get("record") != expected or state.get("recordSha256") != fingerprint(expected)
            or state.get("phase") != _stage(source_item["record"])):
        raise StoreError("Studio App import receipt does not identify the exact expected native proposal")
    lifecycle = inspected["lifecycle"]["state"]
    if lifecycle == "committed-unattributed":
        raise StoreError("Studio App import refuses an unattributed native commit")
    if lifecycle == "committed":
        committed_receipt = _commit_receipt(destination, proposal)
        current = inspected.get("current")
        if (not current or current["revision"] != committed_receipt.get("revision")
                or committed_receipt.get("after") != expected or current.get("record") != expected):
            raise StoreError("Studio App committed record changed after its native commit receipt")
        if (state.get("destinationRevision") is not None
                and state["destinationRevision"] != committed_receipt["revision"]):
            raise StoreError("Studio App receipt revision differs from the native commit receipt")
        state["destinationRevision"] = committed_receipt["revision"]
        return state["destinationRevision"]
    if lifecycle in ("rejected", "withdrawn", "deferred"):
        raise StoreError("Studio App import proposal was rejected, withdrawn or deferred")
    if lifecycle != "pending" or inspected.get("expired"):
        raise StoreError("Studio App import proposal lifecycle is unavailable")
    return {"pending": proposal_id}


def advance(source, destination, package, receipt, actor, *, source_authority, destination_authority,
            blob_reader, protection, source_protection=None, blob_writer,
            destination_blob_protected, clock, identity_guard,
            before_effect=None):
    """Create/resume exactly one native proposal phase; never review or commit it."""
    receipt = _validate_receipt(package, receipt, destination)
    if (source_authority != package["source"]["authority"] or destination_authority != package["destination"]["authority"]
            or destination_blob_protected != package["destination"]["blobProtected"]):
        raise StoreError("Studio App transfer source or destination binding changed")
    at, current_records = _guard(source, destination, package["app"], actor, source_authority,
        destination_authority, package["source"]["binding"], package["destination"]["binding"],
        clock, identity_guard, package["records"])
    raw_by_key = {}
    source_stored_by_key = {}
    destination_storage_by_source_key = {}
    destination_stored_by_key = {}
    app = next(value["record"] for value in package["records"] if value["record"]["kind"] == "studio.app")
    if (not destination_blob_protected
            and any(isinstance(item, dict) and item.get("protection") is not None
                    for item in app.get("content", {}).get("data", {}).get("attachments", []))):
        raise StoreError("Protected source App attachments cannot be declassified by transfer")
    source_attachments = {item["blob"]["key"]: item for item in
        app.get("content", {}).get("data", {}).get("attachments", [])}
    destination_app_id = _destination_id(source_authority, source.contract.binding, package["app"])
    for item in package["attachments"]:
        source_locator = item["locator"]
        try:
            source_stored = verify_blob(source_locator, blob_reader(source_locator))
            source_stored_by_key[source_locator["key"]] = source_stored
        except Exception as exc:
            raise StoreError("Studio App source attachment is unavailable") from exc
        source_attachment = source_attachments.get(source_locator["key"])
        if not isinstance(source_attachment, dict):
            raise StoreError("Studio App source attachment metadata is unavailable")
        if source_attachment.get("protection") is not None:
            if source_protection is None:
                raise StoreError("Protected source App attachment requires its current byte provider")
            from studio_app_mcp import _open_attachment
            live = _open_attachment(source_stored, binding=source.contract.binding,
                record_id=package["app"], attachment=source_attachment, protection=source_protection)
            if source_attachment.get("role") == "pglite-snapshot":
                from studio_app_attachments import verify_pglite_snapshot_bytes
                verify_pglite_snapshot_bytes(source_attachment, live)
        else:
            live = source_stored
        context = _context(package, source_locator, source_attachment)
        packaged = _open_bytes(item["payload"], context, protection)
        if packaged != live:
            raise StoreError("Studio App package attachment differs from the current source")
        raw_by_key[source_locator["key"]] = live
        destination_storage = item.get("destinationStorage")
        if destination_storage is not None:
            stored = decode_blob(destination_storage["data"])
            locator_value = destination_storage["locator"]
            verify_blob(locator_value, stored)
            from studio_app_mcp import _open_attachment
            target_attachment = {key: source_attachment[key] for key in
                                 ("role", "format", "source") if key in source_attachment}
            target_attachment["protection"] = destination_storage["protection"]
            target_plain = _open_attachment(stored, binding=destination.contract.binding,
                record_id=destination_app_id, attachment=target_attachment, protection=protection)
            if target_plain != live:
                raise StoreError("Studio App destination ciphertext differs from the source attachment")
            selected_storage = {"locator": locator_value, "protection": destination_storage["protection"]}
            destination_storage_by_source_key[source_locator["key"]] = selected_storage
            destination_stored_by_key[locator_value["key"]] = stored
    if app.get("blobs"):
        verify_app_attachment_bytes(app, source_stored_by_key)
    _guard(source, destination, package["app"], actor, source_authority, destination_authority,
           package["source"]["binding"], package["destination"]["binding"], clock, identity_guard,
           package["records"])
    destination_revisions = {}
    for phase in STAGES:
        for source_item in (value for value in package["records"] if _stage(value["record"]) == phase):
            origin_id = source_item["record"]["id"]
            prerequisites = [value for value in package["records"]
                             if STAGES.index(_stage(value["record"])) < STAGES.index(phase)]
            if any(value["record"]["id"] not in destination_revisions for value in prerequisites):
                raise StoreError("Studio App import phases must commit dependencies before dependents")
            existing = _verify_existing(destination, source_item, receipt, actor, _now(clock),
                                        package["sha256"], destination_revisions,
                                        destination_storage_by_source_key)
            _guard(source, destination, package["app"], actor, source_authority, destination_authority,
                   package["source"]["binding"], package["destination"]["binding"], clock, identity_guard,
                   package["records"])
            if isinstance(existing, dict) and "pending" in existing:
                return {"status": "awaiting-native-review", "phase": phase,
                        "proposal": existing["pending"], "receipt": receipt,
                        "destinationBlobWritesAreNontransactional": bool(package["attachments"])}
            if isinstance(existing, str):
                destination_revisions[origin_id] = existing
                continue
            record = _rewrite(source_item["record"], receipt, destination, package["sha256"],
                              destination_revisions, destination_storage_by_source_key)
            if before_effect is not None:
                if not callable(before_effect):
                    raise StoreError("Studio App effect-intent callback is invalid")
                before_effect(phase, origin_id, fingerprint(record))
            written = []
            try:
                with destination.request_transaction(write=True):
                    now, _ = _guard(source, destination, package["app"], actor, source_authority,
                        destination_authority, package["source"]["binding"], package["destination"]["binding"],
                        clock, identity_guard, package["records"])
                    request, _ = _request(destination, record, package["sha256"], actor, now)
                    destination._prepare(request, record, actor, "propose", at=now)
                    if record.get("blobs"):
                        if not callable(blob_writer):
                            raise StoreError("A trusted destination blob writer is required")
                        for locator in record["blobs"]:
                            if locator["key"] in destination_stored_by_key:
                                blob_value = destination_stored_by_key[locator["key"]]
                            else:
                                source_locator = next(item["locator"] for item in package["attachments"]
                                                      if item["locator"]["key"] == locator["key"])
                                blob_value = raw_by_key[source_locator["key"]]
                            blob_writer(locator, blob_value)
                            written.append(locator["key"])
                    now, _ = _guard(source, destination, package["app"], actor, source_authority,
                        destination_authority, package["source"]["binding"], package["destination"]["binding"],
                        clock, identity_guard, package["records"])
                    request, _ = _request(destination, record, package["sha256"], actor, now)
                    result = destination.propose(request, record, actor, at=now)
                    _guard(source, destination, package["app"], actor, source_authority, destination_authority,
                        package["source"]["binding"], package["destination"]["binding"],
                        clock, identity_guard, package["records"])
            except Exception as exc:
                if written:
                    raise StoreError("Import proposal failed after immutable blob writes; destination blobs may be orphaned") from exc
                raise
            receipt["records"][origin_id].update({"proposal": result["proposal"],
                "recordSha256": fingerprint(record), "phase": phase})
            return {"status": "awaiting-native-review", "phase": phase, "proposal": result["proposal"],
                    "receipt": receipt, "destinationBlobWritesAreNontransactional": bool(written)}
    _guard(source, destination, package["app"], actor, source_authority, destination_authority,
           package["source"]["binding"], package["destination"]["binding"], clock, identity_guard,
           package["records"])
    return {"status": "complete", "receipt": receipt, "destinationBlobWritesAreNontransactional": bool(package["attachments"])}
