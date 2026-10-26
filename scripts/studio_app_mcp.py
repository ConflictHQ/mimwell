"""Bounded stdio MCP surface for host-authorized Studio App transfers.

The host injects identity and alias resolution; neither is a tool argument.
This module deliberately has no HTTP route. Native review and commit remain
the authority's existing independent operations.
"""
from __future__ import annotations

import hashlib
import hmac
import base64
import json
import os
import re
import secrets
import stat
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from context_bundle import encode
from sql_dialect import StoreError
from studio_app_sessions import (MAX_CHUNK_BYTES, MAX_FRAME_BYTES, MAX_SESSION_BYTES,
                                 SessionStore, compact_response)

SERVER_NAME = "mimwell-studio-apps"
PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26")
_ATTACHMENT_BASE_FIELDS = {"id", "size", "sha256", "role", "format", "mediaType"}
_PGLITE_METADATA_FIELDS = {"postgresMajor", "pgliteVersion", "compression", "expandedBytes", "expandedSha256"}


def _attachment_declaration_schema():
    return {"type": "object", "additionalProperties": False,
        "required": ["id", "size", "sha256", "role", "format", "mediaType"],
        "properties": {
            "id": {"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,31}$"},
            "size": {"type": "integer", "minimum": 1, "maximum": 16777216},
            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "role": {"type": "string", "enum": ["sql-fallback", "csv-fallback", "pglite-snapshot"]},
            "format": {"type": "string", "enum": ["sql", "csv", "pglite-snapshot"]},
            "mediaType": {"type": "string", "enum": ["application/sql", "text/plain", "text/csv", "application/octet-stream"]},
            "postgresMajor": {"type": "integer", "minimum": 1, "maximum": 1000},
            "pgliteVersion": {"type": "string", "minLength": 1, "maxLength": 128},
            "compression": {"type": "string", "enum": ["gzip"]},
            "expandedBytes": {"type": "integer", "minimum": 1, "maximum": 67108864},
            "expandedSha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}},
        "allOf": [
            {"if": {"properties": {"role": {"const": "pglite-snapshot"}}, "required": ["role"]},
             "then": {"required": sorted(_PGLITE_METADATA_FIELDS),
                      "properties": {"format": {"const": "pglite-snapshot"},
                                     "mediaType": {"const": "application/octet-stream"}}}},
            {"if": {"properties": {"role": {"enum": ["sql-fallback", "csv-fallback"]}},
                     "required": ["role"]},
             "then": {"not": {"anyOf": [{"required": [key]} for key in sorted(_PGLITE_METADATA_FIELDS)]}}},
            {"if": {"properties": {"role": {"const": "sql-fallback"}}, "required": ["role"]},
             "then": {"properties": {"format": {"const": "sql"},
                                     "mediaType": {"enum": ["application/sql", "text/plain"]}}}},
            {"if": {"properties": {"role": {"const": "csv-fallback"}}, "required": ["role"]},
             "then": {"properties": {"format": {"const": "csv"}, "mediaType": {"const": "text/csv"}}}}]}


def _attachment_declaration_fields(declaration):
    role = declaration.get("role") if isinstance(declaration, dict) else None
    if role == "pglite-snapshot":
        return _ATTACHMENT_BASE_FIELDS | _PGLITE_METADATA_FIELDS
    if role in ("sql-fallback", "csv-fallback"):
        return _ATTACHMENT_BASE_FIELDS
    raise StoreError("Studio App attachment role is unsupported")


def _validate_attachment_declaration(declaration):
    expected_fields = _attachment_declaration_fields(declaration)
    if (set(declaration) != expected_fields
            or not isinstance(declaration.get("id"), str)
            or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", declaration["id"])
            or type(declaration.get("size")) is not int
            or not 1 <= declaration["size"] <= 16 * 1024 * 1024
            or not isinstance(declaration.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", declaration["sha256"])):
        raise StoreError("Studio App attachment declarations are invalid")
    formats = {"sql-fallback": ("sql", {"application/sql", "text/plain"}),
               "csv-fallback": ("csv", {"text/csv"}),
               "pglite-snapshot": ("pglite-snapshot", {"application/octet-stream"})}
    expected_format, expected_media = formats[declaration["role"]]
    if declaration["format"] != expected_format or declaration["mediaType"] not in expected_media:
        raise StoreError("Studio App attachment role or media type is unsupported")
    if declaration["role"] == "pglite-snapshot":
        from studio_app_attachments import validate_pglite_snapshot_metadata
        validate_pglite_snapshot_metadata(declaration)


def _has_embedded_component(record):
    if not isinstance(record, dict) or record.get("kind") != "studio.component":
        return False
    content = record.get("content", {})
    data = content.get("data", {}) if isinstance(content, dict) else {}
    definition = data.get("definition", {}) if isinstance(data, dict) else {}
    options = definition.get("options", {}) if isinstance(definition, dict) else {}
    return isinstance(options, dict) and "embedded" in options


TOOLS = {
    "apps.aliases": {"description": "List host-registered aliases and grants for this principal. Optional embeddedFormats reports selected native profile support; embeddedViews lists closed view kinds accepted by native handlers, not browser rendering. Neither field grants quota, protection or write permission.",
        "inputSchema": {"type": "object", "additionalProperties": False}},
    "apps.storage.admission": {"description": "Read bounded logical retained-content admission for one registered App alias. Attachment staging is available when plaintext is permitted or the selected host provides the qualified protected-byte route; native records, history and metadata remain outside that protection scope.",
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["alias"],
            "properties": {"alias": {"type": "string", "minLength": 1, "maxLength": 64}}}},
    "apps.open.begin": {"description": "Pin a committed, currently readable App graph for bounded read-only Studio rendering. When a byte provider is selected, attachment-bearing open-session data is sealed in the host session file and reauthorized on each read.",
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["alias", "appId"],
            "properties": {"alias": {"type": "string", "minLength": 1, "maxLength": 64},
                           "appId": {"type": "string", "minLength": 1, "maxLength": 256}}}},
    "apps.open.read": {"description": "Read one bounded chunk of a pinned record or attachment; current authority, route, access and checkpoint are rechecked.",
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["session", "item", "id", "offset"],
            "properties": {"session": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                           "item": {"type": "string", "enum": ["record", "attachment"]},
                           "id": {"type": "string", "maxLength": 256},
                           "offset": {"type": "integer", "minimum": 0}}}},
    "apps.open.status": {"description": "Revalidate the exact current App graph and source checkpoint for a read session.",
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["session"],
            "properties": {"session": {"type": "string", "pattern": "^[0-9a-f]{64}$"}}}},
    "apps.open.abort": {"description": "Stop further reads from a pinned App session. Chunks already delivered cannot be recalled.",
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["session"],
            "properties": {"session": {"type": "string", "pattern": "^[0-9a-f]{64}$"}}}},
    "apps.save.begin": {"description": "Create a bounded, host-scoped Studio App draft session. Attachment chunks and final blobs are sealed when the selected byte provider is required or selected. No native record is written until advance creates a pending proposal.",
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["alias", "reason"],
            "properties": {"alias": {"type": "string", "minLength": 1, "maxLength": 64},
                          "record": {"type": "object"},
                          "records": {"type": "array", "minItems": 1, "maxItems": 32, "items": {"type": "object"}},
                          "attachments": {"type": "array", "maxItems": 8,
                              "items": _attachment_declaration_schema()},
                          "reason": {"type": "string", "minLength": 1, "maxLength": 512},
                          "evidence": {"type": "array", "maxItems": 8, "items": {"type": "string", "minLength": 1, "maxLength": 512}}}}},
    "apps.save.attachment.begin": {"description": "Declare one bounded attachment upload for an active App save session.",
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["session", "id", "size", "sha256", "role", "format", "mediaType"],
            "properties": {"session": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                **_attachment_declaration_schema()["properties"]},
            "allOf": _attachment_declaration_schema()["allOf"]}},
    "apps.save.attachment.chunk": {"description": "Upload one ordered base64 chunk, at most 32 KiB, to an active App save session.",
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["session", "id", "index", "data"],
            "properties": {"session": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "id": {"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,31}$"},
                "index": {"type": "integer", "minimum": 0}, "data": {"type": "string", "maxLength": 43692}}}},
    "apps.save.attachment.finish": {"description": "Verify, content-address and attach one completed upload to its App save session.",
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["session", "id"],
            "properties": {"session": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "id": {"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,31}$"}}}},
    "apps.save.advance": {"description": "Save a Studio App draft as a native create-only proposal. It remains pending for independent native review and commit.",
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["session"],
            "properties": {"session": {"type": "string", "pattern": "^[0-9a-f]{64}$"}}}},
    "apps.save.status": {"description": "Inspect a Studio App save session. Returns the retained destination alias for the caller's continuation guard. embeddedFormats and embeddedViews are derived from the retained plan and same-App snapshot attachment; embeddedViews reports native validation/binding only, not browser rendering. Neither field grants authority or a source-freshness claim.",
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["session"],
            "properties": {"session": {"type": "string", "pattern": "^[0-9a-f]{64}$"}}}},
    "apps.save.abort": {"description": "Stop further draft-session writes. Any native proposal already created remains pending for the existing native review workflow.",
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["session"],
            "properties": {"session": {"type": "string", "pattern": "^[0-9a-f]{64}$"}}}},
    "apps.transfer.begin": {"description": "Pin an App graph from registered source and destination aliases. Protected attachments require current source and destination byte providers; protected sources cannot be transferred to plaintext destinations. Staging creates no approval or commit.",
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["source", "destination", "appId"],
            "properties": {"source": {"type": "string", "minLength": 1, "maxLength": 64},
                          "destination": {"type": "string", "minLength": 1, "maxLength": 64},
                          "appId": {"type": "string", "minLength": 1, "maxLength": 256}}}},
    "apps.transfer.advance": {"description": "Advance one native proposal phase after prior dependencies have been independently committed. Never reviews or commits.",
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["session"],
            "properties": {"session": {"type": "string", "pattern": "^[0-9a-f]{64}$"}}}},
    "apps.transfer.status": {"description": "Read the bounded phase state of an authenticated transfer session.",
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["session"],
            "properties": {"session": {"type": "string", "pattern": "^[0-9a-f]{64}$"}}}},
    "apps.transfer.abort": {"description": "Stop further transfer-session I/O. Native proposals and immutable blob writes already made are not deleted.",
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["session"],
            "properties": {"session": {"type": "string", "pattern": "^[0-9a-f]{64}$"}}}},
}


def _tool_result(value, is_error=False, *, max_text_bytes=MAX_FRAME_BYTES):
    raw = compact_response(value)
    if len(raw) > max_text_bytes:
        raise StoreError("Studio App tool summary exceeds its wire budget")
    return {"content": [{"type": "text", "text": raw.decode("utf-8")}], "isError": is_error}


def _utcnow():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _attachment_scope_is_protected(policy, scope_id, native_actor, at):
    """Allow plaintext only for an effectively company-wide readable scope.

    Scope identifiers are operator-selected addresses; their spelling carries
    no protection meaning. The effective policy and declared scope space do.
    """
    from knowledge_policy import timestamp
    scope = policy.scopes.get(scope_id)
    if not scope:
        return True
    try:
        rules, _, _ = policy.effective(scope_id, timestamp(at))
    except Exception:
        return True
    all_principals = set(policy.principals)
    return not (scope["space"] in ("company", "product", "workspace")
                and set(rules.get("readers", [])) == all_principals
                and native_actor in rules.get("readers", []))


def _plaintext_staging_allowed(destination, record, native_actor, at):
    """Only stage attachment plaintext when both host and native scope allow it."""
    return (not destination.get("blob_protected", False)
            and not destination["attachment_protected"](record, native_actor, at))


def _attachment_storage_allowed(destination, record, native_actor, at):
    """Allow plaintext staging only by policy, otherwise require the selected byte provider."""
    if _plaintext_staging_allowed(destination, record, native_actor, at):
        return True
    return destination.get("protection") is not None


def _protected_attachment_bound(size, protection):
    """Return the exact canonical JSON size for this fixed-shape binary envelope."""
    from brain_protection import (MAX_PROTECTED_ENVELOPE, MAX_PROTECTED_BYTES,
                                  profile, requirements)
    from context_bundle import encode
    if type(size) is not int or not 1 <= size <= MAX_PROTECTED_BYTES:
        raise StoreError("Protected Studio App attachment exceeds its binary limit")
    # All content dependent fields have fixed-width encodings; ciphertext base64
    # length depends only on plaintext length plus the GCM tag. Measure the
    # canonical object itself so admission and the eventual blob use one charge.
    if not isinstance(protection, (tuple, list)) or len(protection) not in (3, 4):
        raise StoreError("Protected Studio App attachment provider is unavailable")
    _host, raw_required, raw_selected = protection[:3]
    required, selected = requirements(raw_required), profile(raw_selected)
    if selected["mode"] != "per-record":
        raise StoreError("Protected Studio App attachment provider is unavailable")
    envelope = {"format": "protected-bytes/v1", "object": "0" * 32,
        "revision": "0" * 32, "requirements": required, "profile": selected,
        "contextSha256": "0" * 64, "contentBytes": size,
        "contentSha256": "0" * 64,
        "storage": {"encoding": "aes256gcm/v1", "nonce": "A" * 16,
                    "ciphertext": "A" * (((size + 16 + 2) // 3) * 4)},
        "signature": (None if selected["signer"] is None else
                      {"algorithm": "ed25519/v1", "value": "A" * 88})}
    bound = len(encode(envelope))
    if bound > MAX_PROTECTED_ENVELOPE:
        raise StoreError("Protected Studio App attachment envelope exceeds its limit")
    return bound


def _attachment_context(binding, record_id, attachment, content_sha256, content_bytes):
    source = attachment.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("revision"), str):
        raise StoreError("Studio App protected attachment source revision is unavailable")
    return {"authorityBinding": binding, "recordId": record_id,
            "sourceRevision": source["revision"], "role": attachment["role"],
            "format": attachment["format"], "contentSha256": content_sha256,
            "contentBytes": content_bytes}


def _validate_native_protection_scope(value):
    """Reject a byte-wrapper provider when the selected brain needs native encryption.

    The current SQLite authority stores App records, proposals, history and
    receipts as ordinary native rows. The injected provider protects attachment
    bytes only; it cannot claim protection for those native surfaces.
    """
    expected = {"format", "nativeRecordBodies", "nativeHistory", "nativeMetadata"}
    if not isinstance(value, dict) or set(value) != expected or value.get("format") != "studio-app-protection-scope/v1":
        raise StoreError("Studio App protection scope is unavailable")
    if any(type(value[key]) is not bool for key in expected - {"format"}):
        raise StoreError("Studio App protection scope is unavailable")
    if any(value[key] for key in expected - {"format"}):
        raise StoreError("Selected brain requires native protection that this App writer does not provide")
    return dict(value)


def _validate_registered_app_protection(registration, protection):
    """Bind App protection to its owner pin and refuse unsupported storage needs."""
    if protection is None:
        if registration is not None:
            raise StoreError("Studio App protection registration differs")
        return
    from brain_protection import assess, profile, requirements
    from knowledge_policy import fingerprint

    try:
        host, raw_required, raw_selected, native_scope = protection
        required = requirements(raw_required)
        selected = profile(raw_selected)
        expected_scope = {"format": "studio-app-protection-scope/v1",
                          "nativeRecordBodies": False, "nativeHistory": False,
                          "nativeMetadata": False}
        if ((registration is not None
                and (selected["mode"] != registration["protection"]["profile"]
                     or fingerprint(required) != registration["protection"]["requirementsSha256"]))
                or native_scope != expected_scope or required["opaqueMetadata"]
                or not required["plaintextCopies"]
                or not assess(required, selected, offline=True, operation="retain")["supported"]):
            raise StoreError("Studio App protection registration differs")
        host.available(selected)
    except StoreError:
        raise
    except Exception as exc:
        raise StoreError("Studio App protection registration is unavailable") from exc


def _seal_attachment(raw, *, binding, record, role, fmt, protection, source_revision=None):
    if protection is None:
        raise StoreError("Protected Studio App attachment storage is unavailable")
    if protection[1].get("opaqueMetadata"):
        raise StoreError("Opaque attachment metadata is unavailable for the current App format")
    digest = hashlib.sha256(raw).hexdigest()
    source_revision = source_revision if source_revision is not None else "sha256:" + digest
    if not isinstance(source_revision, str) or not source_revision:
        raise StoreError("Studio App protected attachment source revision is unavailable")
    attachment = {"role": role, "format": fmt,
                  "source": {"id": "studio-save:" + record["id"], "revision": source_revision}}
    context = _attachment_context(binding, record["id"], attachment, digest, len(raw))
    object_id = hashlib.sha256((binding + "\0" + record["id"] + "\0" + role).encode()).hexdigest()[:32]
    revision = hashlib.sha256(source_revision.encode()).hexdigest()[:32]
    host, required, selected = protection[:3]
    from brain_protection import ProtectionError
    try:
        envelope = host.seal_bytes(raw, context=context, object_id=object_id, revision=revision,
                                   required=required, selected=selected)
        return encode(envelope), {"format": "protected-bytes/v1", "contentBytes": len(raw),
                                  "contentSha256": digest}
    except ProtectionError as exc:
        raise StoreError("Protected Studio App attachment could not be retained") from exc


def _open_attachment(raw, *, binding, record_id, attachment, protection):
    if protection is None or attachment.get("protection", {}).get("format") != "protected-bytes/v1":
        raise StoreError("Protected Studio App attachment is unavailable")
    from brain_protection import ProtectionError
    try:
        envelope = json.loads(raw)
        metadata = attachment["protection"]
        context = _attachment_context(binding, record_id, attachment,
                                      metadata["contentSha256"], metadata["contentBytes"])
        object_id = hashlib.sha256((binding + "\0" + record_id + "\0" + attachment["role"]).encode()).hexdigest()[:32]
        revision = hashlib.sha256(attachment["source"]["revision"].encode()).hexdigest()[:32]
        host, required, selected = protection[:3]
        plain = host.open_bytes(envelope, context=context, expected_object=object_id,
            expected_revision=revision, expected_profile=selected, required=required)
    except (ValueError, KeyError, TypeError, ProtectionError) as exc:
        raise StoreError("Protected Studio App attachment could not be opened") from exc
    if len(plain) != metadata["contentBytes"] or hashlib.sha256(plain).hexdigest() != metadata["contentSha256"]:
        raise StoreError("Protected Studio App attachment differs from its native pin")
    return plain


def _upload_reservation_bytes(size, *, stored_bytes=None):
    """Reserve only this attachment's exact or maximum retained blob bytes."""
    if type(size) is not int or not 1 <= size <= 16 * 1024 * 1024:
        raise StoreError("Studio App attachment declaration is invalid")
    stored_bytes = size if stored_bytes is None else stored_bytes
    if type(stored_bytes) is not int or stored_bytes < size or stored_bytes > 15 * 1024 * 1024:
        raise StoreError("Studio App stored attachment bound is invalid")
    return stored_bytes


def _session_reservation_bytes(current_session_bytes):
    """Cover one max-sized atomic temporary plus growth to the session limit.

    The current file is already counted in inventory. The additional retained
    growth is MAX_SESSION_BYTES-current_session_bytes; a replacement temporary
    may independently reach MAX_SESSION_BYTES before rename.
    """
    if type(current_session_bytes) is not int or not 0 <= current_session_bytes <= MAX_SESSION_BYTES:
        raise StoreError("Studio App session cannot be covered by the retained-content limit")
    return MAX_SESSION_BYTES + (MAX_SESSION_BYTES - current_session_bytes)


class StudioAppsMCP:
    """Identity/alias callbacks are host-owned and re-evaluated on every call.

    `identity()` returns the transport-authenticated principal. `resolve(actor,
    alias, capability)` returns a trusted mapping with an open authority,
    authority identity, blob callbacks, protection selection and current
    registration revalidation callback. Request arguments contain no actor,
    path, DSN, resource, collection, protection or blob locator.
    """

    def __init__(self, *, identity, aliases, resolve, sessions: SessionStore,
                 clock, storage_admission=None, max_line_bytes=MAX_FRAME_BYTES):
        if not all(callable(value) for value in (identity, aliases, resolve, clock)):
            raise ValueError("Studio App MCP requires trusted host callbacks")
        if storage_admission is not None and not callable(storage_admission):
            raise ValueError("Studio App admission callback is invalid")
        if type(max_line_bytes) is not int or not 1 <= max_line_bytes <= MAX_FRAME_BYTES:
            raise ValueError("Studio App MCP frame limit is invalid")
        self.identity, self.aliases, self.resolve = identity, aliases, resolve
        self.storage_admission = storage_admission
        self.sessions, self.clock = sessions, clock
        self.max_line_bytes = max_line_bytes
        self.sessions.admission_effect = self._session_admission_effect
        self.sessions.protection_codec = self._session_protection_codec

    def _session_protection_codec(self, direction, session, session_id, *, _selected=None):
        """Seal attachment-bearing session fields with the freshly selected host provider."""
        if direction not in ("seal", "open", "validate") or not isinstance(session, dict):
            raise StoreError("Studio App protected session is unavailable")
        payload = session.get("payload")
        if not isinstance(payload, dict):
            return session
        mode = payload.get("mode")
        uploads = payload.get("uploads", {})
        needs_chunks = (mode == "save" and isinstance(uploads, dict) and any(
            isinstance(upload, dict) and upload.get("protectedChunks") is True
            for upload in uploads.values()))
        needs_package = mode == "open" and payload.get("protectedContent") is True
        if not needs_chunks and not needs_package:
            return session
        actor = session.get("actor")
        alias = payload.get("alias")
        capability = "read" if mode == "open" else "propose"
        if (not isinstance(actor, str) or not isinstance(alias, str) or self.identity() != actor):
            raise StoreError("Studio App protected session identity changed")
        if _selected is not None and direction != "validate":
            raise StoreError("Studio App borrowed session selection is invalid")
        own_selected = _selected is None
        selected = self.resolve(actor, alias, capability) if own_selected else _selected
        try:
            if (selected["authority"] != payload.get("authority")
                    or selected["binding"] != payload.get("binding")
                    or selected["native_actor"] != payload.get("nativeActor")
                    or selected["registration"] != payload.get("registration")):
                raise StoreError("Studio App protected session route changed")
            protection = selected.get("protection")
            if protection is None:
                raise StoreError("Studio App protected session provider is unavailable")
            host, required, selected_profile, _scope = protection
            from brain_protection import MAX_PROTECTED_BYTES, ProtectionError
            from knowledge_policy import fingerprint

            def seal(raw, context, label):
                opaque = fingerprint({"session": session_id, "context": context})
                revision = hashlib.sha256((session_id + "\0" + label).encode()).hexdigest()[:32]
                try:
                    return host.seal_bytes(raw, context=context, object_id=opaque[:32], revision=revision,
                                           required=required, selected=selected_profile)
                except ProtectionError as exc:
                    raise StoreError("Studio App protected session could not be retained") from exc

            def open_envelope(envelope, context, label):
                opaque = fingerprint({"session": session_id, "context": context})
                revision = hashlib.sha256((session_id + "\0" + label).encode()).hexdigest()[:32]
                try:
                    raw = host.open_bytes(envelope, context=context, expected_object=opaque[:32],
                        expected_revision=revision, expected_profile=selected_profile, required=required)
                    if direction == "validate":
                        # Opening authenticates these staged bytes using the current
                        # profile/key and existing read permission. Retaining them
                        # also requires the current retain permission; read alone
                        # never grants publication after retention was revoked.
                        from brain_protection import combine
                        header = {key: value for key, value in envelope.items()
                                  if key not in ("storage", "signature")}
                        header["requirements"] = combine(required, envelope["requirements"])
                        host.permit(header, "retain")
                        host.available(selected_profile)
                    return raw
                except ProtectionError as exc:
                    raise StoreError("Studio App protected session could not be opened") from exc

            if needs_chunks:
                declarations = {item.get("id"): item for item in payload.get("attachmentDeclarations", [])
                                if isinstance(item, dict)}
                plan = payload.get("plan", [])
                target_index = payload.get("attachmentRecordIndex")
                if (type(target_index) is not int or not 0 <= target_index < len(plan)
                        or not isinstance(plan[target_index], dict)):
                    raise StoreError("Studio App protected upload target changed")
                target = plan[target_index]
                for attachment_id, upload in uploads.items():
                    if not isinstance(upload, dict) or upload.get("protectedChunks") is not True:
                        continue
                    declaration = declarations.get(attachment_id)
                    if not isinstance(declaration, dict):
                        raise StoreError("Studio App protected upload declaration changed")
                    chunks = upload.get("chunks")
                    if (not isinstance(chunks, list)
                            or len(chunks) > (16 * 1024 * 1024 + 32 * 1024 - 1) // (32 * 1024)):
                        raise StoreError("Studio App protected upload chunk set is invalid")
                    converted = []
                    for index, chunk in enumerate(chunks):
                        context = {"format": "studio-app-session-chunk/v1", "actor": actor,
                            "alias": alias, "authority": payload["authority"], "binding": payload["binding"],
                            "nativeActor": payload["nativeActor"],
                            "registrationSha256": fingerprint(payload["registration"]),
                            "session": session_id, "attachment": attachment_id, "index": index,
                            "declaration": declaration, "targetRecord": target["record"]["id"],
                            "targetRecordSha256": target["recordSha256"]}
                        if direction == "seal":
                            if not isinstance(chunk, str):
                                raise StoreError("Studio App protected upload chunk is malformed")
                            try:
                                raw = base64.b64decode(chunk, validate=True)
                            except (ValueError, TypeError) as exc:
                                raise StoreError("Studio App protected upload chunk is malformed") from exc
                            if not 1 <= len(raw) <= MAX_CHUNK_BYTES:
                                raise StoreError("Studio App protected upload chunk exceeds its limit")
                            context.update({"contentBytes": len(raw),
                                            "contentSha256": hashlib.sha256(raw).hexdigest()})
                            envelope = seal(raw, context, f"chunk:{attachment_id}:{index}")
                            converted.append({"format": "protected-bytes/v1", "envelope": envelope})
                        else:
                            if (not isinstance(chunk, dict) or set(chunk) != {"format", "envelope"}
                                    or chunk.get("format") != "protected-bytes/v1"
                                    or not isinstance(chunk.get("envelope"), dict)):
                                raise StoreError("Studio App protected upload chunk is malformed")
                            envelope = chunk["envelope"]
                            context.update({"contentBytes": envelope.get("contentBytes"),
                                            "contentSha256": envelope.get("contentSha256")})
                            raw = open_envelope(envelope, context, f"chunk:{attachment_id}:{index}")
                            if (len(raw) > MAX_CHUNK_BYTES or len(raw) > MAX_PROTECTED_BYTES
                                    or envelope.get("contentBytes") != len(raw)
                                    or envelope.get("contentSha256") != hashlib.sha256(raw).hexdigest()):
                                raise StoreError("Studio App protected upload chunk exceeds its limit")
                            converted.append(base64.b64encode(raw).decode("ascii"))
                    upload["chunks"] = converted

            if needs_package:
                fields = ("records", "attachments")
                if direction == "seal":
                    if any(not isinstance(payload.get(key), list) for key in fields):
                        raise StoreError("Studio App protected open package is unavailable")
                    raw = encode({key: payload[key] for key in fields})
                    context = {"format": "studio-app-open-session/v1", "actor": actor,
                        "alias": alias, "authority": payload["authority"], "binding": payload["binding"],
                        "nativeActor": payload["nativeActor"],
                        "registrationSha256": fingerprint(payload["registration"]),
                        "session": session_id, "appId": payload["appId"],
                        "checkpointSha256": payload["checkpointSha256"],
                        "packageSha256": payload["packageSha256"]}
                    if len(raw) > 10 * 1024 * 1024:
                        raise StoreError("Protected Studio App open package exceeds the binary protection limit")
                    context.update({"contentBytes": len(raw),
                                    "contentSha256": hashlib.sha256(raw).hexdigest()})
                    payload["protectedPackage"] = seal(raw, context, "open-package")
                    for key in fields:
                        payload.pop(key, None)
                else:
                    envelope = payload.get("protectedPackage")
                    if not isinstance(envelope, dict):
                        raise StoreError("Studio App protected open package is malformed")
                    context = {"format": "studio-app-open-session/v1", "actor": actor,
                        "alias": alias, "authority": payload["authority"], "binding": payload["binding"],
                        "nativeActor": payload["nativeActor"],
                        "registrationSha256": fingerprint(payload["registration"]),
                        "session": session_id, "appId": payload["appId"],
                        "checkpointSha256": payload["checkpointSha256"],
                        "packageSha256": payload["packageSha256"],
                        "contentBytes": envelope.get("contentBytes"),
                        "contentSha256": envelope.get("contentSha256")}
                    raw = open_envelope(envelope, context, "open-package")
                    try:
                        decoded = json.loads(raw)
                    except (ValueError, TypeError) as exc:
                        raise StoreError("Studio App protected open package is malformed") from exc
                    if (not isinstance(decoded, dict) or set(decoded) != set(fields)
                            or any(not isinstance(decoded[key], list) for key in fields)
                            or encode(decoded) != raw):
                        raise StoreError("Studio App protected open package is malformed")
                    payload.update(decoded)
                    payload.pop("protectedPackage", None)
            if self.identity() != actor:
                raise StoreError("Studio App protected session identity changed")
            return session
        finally:
            if own_selected:
                selected["store"].close()

    def _session_protection_precommit(self, persisted, session_id, *, selected):
        """Reauthorize exact staged bytes using the admission-owned native store."""
        refresh = selected.get("session_publication_protection")
        if not callable(refresh):
            raise StoreError("Studio App selected session publication route is unavailable")
        current = {**selected, "protection": refresh()}
        self._session_protection_codec("validate", persisted, session_id, _selected=current)

    @staticmethod
    def _require_adopted_native_scope(destination):
        if destination.get("admission") is not None and destination.get("native_protection_scope") is None:
            raise StoreError("Adopted App writes require an explicit native-protection scope")

    @staticmethod
    def _upload_lease_state(destination, upload, *, allow_settled=False):
        reservation_id = upload.get("admissionReservation") if isinstance(upload, dict) else None
        if reservation_id is None:
            if destination.get("admission") is not None:
                raise StoreError("Adopted Studio App upload has no durable content reservation")
            return None
        admission = destination.get("admission")
        if admission is None:
            raise StoreError("Studio App upload reservation is unavailable")
        ledger, _inventory_now = admission
        state = ledger.reservation_state(reservation_id)["state"]
        if state != "reserved" and not (allow_settled and state == "settled"):
            raise StoreError("Studio App upload reservation is unresolved")
        return reservation_id

    @staticmethod
    def _settle_upload_lease(destination, upload, *, allow_settled=False):
        reservation_id = StudioAppsMCP._upload_lease_state(
            destination, upload, allow_settled=allow_settled)
        if reservation_id is not None:
            ledger, inventory_now = destination["admission"]
            if ledger.reservation_state(reservation_id)["state"] == "settled":
                return
            try:
                ledger.settle(reservation_id, inventory_now=inventory_now)
            except BaseException:
                try:
                    ledger.mark_unknown(reservation_id)
                except Exception:
                    pass
                raise

    @staticmethod
    def _settle_session_lease(destination, session):
        admission = destination.get("admission")
        identity = session.get("storageAdmission", {}).get("sessionReservation")
        if identity is None:
            return
        if admission is None:
            raise StoreError("Studio App session reservation is unavailable")
        ledger, inventory_now = admission
        if ledger.reservation_state(identity)["state"] == "settled":
            return
        try:
            ledger.settle(identity, inventory_now=inventory_now)
        except BaseException:
            try:
                ledger.mark_unknown(identity)
            except Exception:
                pass
            raise

    @contextmanager
    def _session_admission_effect(self, session, *, current, previous, delta, temporary_bytes, session_id):
        """Admit every session-file replacement against its host-selected brain."""
        from brain_storage_admission import admission_active, load_registration
        root = self.sessions.directory.parent.parent
        registration = load_registration(root)
        if registration is None:
            yield None
            return
        if not isinstance(session, dict) or not isinstance(session.get("actor"), str):
            raise StoreError("Studio App session admission identity is unavailable")
        payload = session.get("payload", {})
        mode = payload.get("mode") if isinstance(payload, dict) else None
        alias = payload.get("destination") if mode == "transfer" else payload.get("alias")
        capability = "read" if mode == "open" else "propose"
        if not isinstance(alias, str) or self.identity() != session["actor"]:
            raise StoreError("Studio App session admission route or identity is unavailable")
        selected = self.resolve(session["actor"], alias, capability)
        try:
            def guarded(reservation):
                if not isinstance(reservation, dict):
                    raise StoreError("Studio App session admission result is invalid")
                return {**reservation, "_sessionPublicationGuard":
                    lambda persisted, identity: self._session_protection_precommit(
                        persisted, identity, selected=selected)}

            if admission_active(root):
                selected["store"]._storage_admission_require(temporary_bytes)
                yield guarded({"reservedBytes": temporary_bytes})
                return
            admission = selected.get("admission")
            if admission is None:
                raise StoreError("Studio App session admission is unavailable for the adopted brain")
            session_reservation = current.get("storageAdmission", {}).get("sessionReservation")
            if session_reservation:
                ledger, inventory_now = admission
                if ledger.reservation_state(session_reservation)["state"] == "settled":
                    with selected["store"]._storage_admission_effect("studio-app.session-after-settlement") as reservation:
                        yield guarded(reservation)
                    return
                with ledger.upload_session_write(session_reservation,
                        temporary_bytes=temporary_bytes, inventory_now=inventory_now,
                        session_id=session_id) as reservation:
                    yield guarded(reservation)
                return
            with selected["store"]._storage_admission_effect("studio-app.session") as reservation:
                yield guarded(reservation)
        finally:
            selected["store"].close()

    def dispatch(self, message):
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return None
        if "method" not in message:
            return None
        if "id" not in message:
            return None
        rid, method, params = message.get("id"), message.get("method"), message.get("params") or {}
        if (not isinstance(rid, (str, int, float)) or isinstance(rid, bool) or not isinstance(params, dict)
                or len(encode(rid)) > 256):
            safe_id = rid if isinstance(rid, (str, int, float)) and not isinstance(rid, bool) and len(encode(rid)) <= 256 else None
            return {"jsonrpc": "2.0", "id": safe_id, "error": {"code": -32600, "message": "Invalid Request"}}
        if method == "initialize":
            version = params.get("protocolVersion")
            return {"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": version if version in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": "1.0.0"},
                "instructions": "Host-authorized Studio App save and transfer proposals. Review and commit remain independent native operations."}}
        if method == "ping":
            return {"jsonrpc": "2.0", "id": rid, "result": {}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": rid, "result": {"tools": [
                {"name": name, **spec, "annotations": {"readOnlyHint": name in ("apps.aliases", "apps.storage.admission", "apps.open.begin", "apps.open.read", "apps.open.status", "apps.save.status", "apps.transfer.status"),
                    "destructiveHint": False, "idempotentHint": name in ("apps.aliases", "apps.storage.admission", "apps.open.status", "apps.open.abort", "apps.save.status", "apps.transfer.status", "apps.transfer.abort"),
                    "openWorldHint": False}} for name, spec in TOOLS.items()]}}
        if method != "tools/call":
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "Method not found"}}
        params = params if isinstance(params, dict) else {}
        name, arguments = params.get("name"), params.get("arguments", {})
        try:
            if name not in TOOLS or not isinstance(arguments, dict):
                raise StoreError("Studio App tool is unavailable")
            # Reserve the exact JSON-RPC envelope overhead before any tool can
            # mutate host state. The compact tool result must fit the residual.
            envelope_overhead = len(encode({"jsonrpc": "2.0", "id": rid,
                                             "result": {"content": [{"type": "text", "text": ""}],
                                                        "isError": False}}))
            if envelope_overhead >= self.max_line_bytes:
                raise StoreError("Studio App response exceeds the MCP frame limit")
            if name in {"apps.open.begin", "apps.open.abort", "apps.save.begin", "apps.save.advance", "apps.save.abort", "apps.save.attachment.begin",
                        "apps.save.attachment.chunk", "apps.save.attachment.finish",
                        "apps.transfer.begin", "apps.transfer.advance", "apps.transfer.abort"}:
                # All mutation acknowledgements are compact summaries. Reserve
                # their full documented text budget before running effects.
                mutation_bound = encode({"jsonrpc": "2.0", "id": rid,
                    "result": {"content": [{"type": "text", "text": "\\" * 4096}], "isError": False}})
                if len(mutation_bound) > self.max_line_bytes:
                    raise StoreError("Studio App response exceeds the MCP frame limit")
            value = self._call(name, arguments)
            result = _tool_result(value, max_text_bytes=4096 if name in {
                "apps.open.begin", "apps.open.status", "apps.open.abort", "apps.save.begin", "apps.save.advance", "apps.save.status", "apps.save.abort",
                "apps.save.attachment.begin", "apps.save.attachment.chunk", "apps.save.attachment.finish", "apps.transfer.begin",
                "apps.transfer.advance", "apps.transfer.abort"} else MAX_FRAME_BYTES)
            response = {"jsonrpc": "2.0", "id": rid, "result": result}
            raw = encode(response)
            if len(raw) > self.max_line_bytes:
                # Tool implementations preflight their bounded summaries. This
                # branch is a defense for read-only and future handlers.
                raise StoreError("Studio App response exceeds the MCP frame limit")
            return response
        except (StoreError, ValueError, TypeError, KeyError):
            result = _tool_result({"error": "Studio App operation is unavailable"}, is_error=True)
            return {"jsonrpc": "2.0", "id": rid, "result": result}

    def _call(self, name, arguments):
        actor = self.identity()
        if not isinstance(actor, str) or not actor:
            raise StoreError("Studio App host identity is unavailable")
        if name == "apps.aliases":
            if arguments:
                raise StoreError("Unexpected argument")
            result = self.aliases(actor)
            if not isinstance(result, list) or len(result) > 64:
                raise StoreError("Studio App alias registration is invalid")
            return {"aliases": result}
        if name == "apps.storage.admission":
            if set(arguments) != {"alias"} or self.storage_admission is None:
                raise StoreError("Studio App admission is unavailable")
            try:
                result = self.storage_admission(actor, arguments["alias"])
            except StoreError:
                raise
            except Exception as exc:
                raise StoreError("Studio App admission is unavailable") from exc
            compact_response(result)
            return result
        if name == "apps.open.begin":
            if set(arguments) != {"alias", "appId"}:
                raise StoreError("Studio App open arguments are invalid")
            source = self.resolve(actor, arguments["alias"], "read")
            try:
                protected_content = source.get("protection") is not None
                if (not source["attachment_staging_available"](source["native_actor"], self.clock())
                        and not protected_content):
                    raise StoreError("Protected App attachments require an authorized byte provider")
                package = self._open_package(source, actor, arguments["appId"])
                preview = {"session": "0" * 64, "state": "ready", "packageSha256": package["sha256"],
                    "checkpointSha256": package["checkpointSha256"], "records": len(package["records"]),
                    "attachments": len(package["attachments"]), "attachmentBytes": package["attachmentBytes"],
                    "recordBytes": package["recordBytes"], "complete": False}
                compact_response(preview)
                handle = self.sessions.create(actor, {"mode": "open", "alias": source["alias"],
                    "authority": source["authority"], "binding": source["binding"],
                    "nativeActor": source["native_actor"], "registration": source["registration"],
                    "protectedContent": protected_content,
                    "appId": arguments["appId"], "checkpoint": package["checkpoint"],
                    "checkpointSha256": package["checkpointSha256"], "recordPins": package["recordPins"],
                    "attachmentPins": package["attachmentPins"], "records": package["records"],
                    "attachments": package["attachments"],
                    "recordBytes": package["recordBytes"], "attachmentBytes": package["attachmentBytes"],
                    "packageSha256": package["sha256"]})
                response = {**preview, "session": handle}
                compact_response(response)
                if not self._open_current(actor, self.sessions.get(handle, actor)["payload"]):
                    self.sessions.abort(handle, actor)
                    raise StoreError("Studio App source changed before open response release")
                return response
            finally:
                source["store"].close()
        if name == "apps.open.read":
            if set(arguments) != {"session", "item", "id", "offset"}:
                raise StoreError("Studio App open read arguments are invalid")
            session = self.sessions.get(arguments["session"], actor)
            payload = session["payload"]
            if payload.get("mode") != "open" or not self._open_current(actor, payload):
                raise StoreError("Studio App open session is unavailable")
            item_type = arguments["item"]
            items = payload.get("records", []) if item_type == "record" else payload.get("attachments", [])
            try:
                index = int(arguments["id"])
            except (TypeError, ValueError) as exc:
                raise StoreError("Studio App open item is unavailable") from exc
            if (item_type not in ("record", "attachment") or str(index) != arguments["id"]
                    or not 0 <= index < len(items) or type(arguments["offset"]) is not int):
                raise StoreError("Studio App open item is unavailable")
            item = items[index]
            if item_type == "record":
                from blob_store import decode as decode_blob
                raw = decode_blob(item["data"])
                content_type = "application/json"
                if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
                    raise StoreError("Studio App open record differs from its pin")
            else:
                from blob_store import decode as decode_blob, verify as verify_blob
                locator = item["locator"]
                raw = decode_blob(item["data"])
                if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
                    raise StoreError("Studio App attachment differs from its pinned content address")
                if not item.get("protectedBytes"):
                    verify_blob(locator, raw)
                content_type = locator["mediaType"]
            offset = arguments["offset"]
            if offset < 0 or offset > len(raw):
                raise StoreError("Studio App open offset is unavailable")
            chunk = raw[offset:offset + 32 * 1024]
            from blob_store import encode as encode_blob
            response = {"session": arguments["session"], "item": item_type, "id": item["id"],
                "kind": item.get("kind"), "role": item.get("role"), "format": item.get("format"),
                "revision": item.get("revision"), "contentType": content_type,
                "bytes": len(raw), "sha256": item["sha256"], "offset": offset,
                "nextOffset": offset + len(chunk), "done": offset + len(chunk) == len(raw),
                "data": encode_blob(chunk)}
            response.update({key: item[key] for key in _PGLITE_METADATA_FIELDS if key in item})
            compact_response(response)
            latest = self.sessions.get(arguments["session"], actor)
            if (latest.get("payload") != payload or self.identity() != actor
                    or not self._open_current(actor, latest["payload"])):
                raise StoreError("Studio App open authorization changed before chunk release")
            return response
        if name == "apps.open.status":
            if set(arguments) != {"session"}:
                raise StoreError("Studio App open status arguments are invalid")
            session = self.sessions.get(arguments["session"], actor)
            payload = session["payload"]
            if payload.get("mode") != "open" or not self._open_current(actor, payload):
                raise StoreError("Studio App open session is unavailable")
            return {"session": arguments["session"], "state": "ready", "appId": payload["appId"],
                    "packageSha256": payload["packageSha256"], "checkpointSha256": payload["checkpointSha256"],
                    "records": len(payload["records"]), "attachments": len(payload["attachments"]), "complete": False}
        if name == "apps.open.abort":
            if set(arguments) != {"session"}:
                raise StoreError("Studio App open abort arguments are invalid")
            session = self.sessions.get(arguments["session"], actor)
            if session["payload"].get("mode") != "open":
                raise StoreError("Studio App open session is unavailable")
            return self.sessions.abort(arguments["session"], actor)
        if name == "apps.save.begin":
            if (set(arguments) - {"alias", "record", "records", "reason", "evidence", "attachments"}
                    or not {"alias", "reason"}.issubset(arguments)
                    or ("record" in arguments) == ("records" in arguments)):
                raise StoreError("Studio App save arguments are invalid")
            reason, evidence = arguments["reason"], arguments.get("evidence", [])
            if (not isinstance(reason, str) or not reason.strip() or len(reason) > 512
                    or not isinstance(evidence, list) or len(evidence) > 8
                    or any(not isinstance(item, str) or not item.strip() or len(item) > 512 for item in evidence)):
                raise StoreError("Studio App save rationale is invalid")
            alias = arguments["alias"]
            destination = self.resolve(actor, alias, "propose")
            try:
                self._require_adopted_native_scope(destination)
                drafts = [arguments["record"]] if "record" in arguments else arguments["records"]
                if (not isinstance(drafts, list) or not 1 <= len(drafts) <= 32
                        or "attachments" in arguments and not isinstance(arguments["attachments"], list)):
                    raise StoreError("Studio App save plan is invalid")
                rank = {"studio.app-query": 0, "studio.component": 1, "studio.app": 2}
                plan, seen = [], set()
                previous_rank = -1
                for draft in drafts:
                    if (not isinstance(draft, dict) or set(draft) - {"id", "kind", "content", "relations"}
                            or not {"id", "kind", "content", "relations"}.issubset(draft)
                            or draft["kind"] not in rank):
                        raise StoreError("Studio App save record shape is invalid")
                    current_rank = rank[draft["kind"]]
                    if current_rank < previous_rank or draft["id"] in seen:
                        raise StoreError("Studio App save records must be unique and dependency ordered")
                    previous_rank = current_rank
                    seen.add(draft["id"])
                    matches = [(identity, value) for identity, value in destination["store"].contract.collections.items()
                               if value.get("kind") == draft["kind"]]
                    if len(matches) != 1:
                        raise StoreError("Studio App save collection is unavailable")
                    collection, _ = matches[0]
                    record = {"id": draft["id"], "kind": draft["kind"], "collection": collection,
                              "content": draft["content"], "relations": draft["relations"]}
                    destination["store"].contract.validate_record(record)
                    if destination["store"]._record_metadata(record["id"]) is not None:
                        raise StoreError("Studio App create identity already exists or is tombstoned")
                    from studio_app_transfer import fingerprint
                    request = {"id": secrets.token_hex(16), "resource": destination["store"].contract.collections[collection]["resource"],
                        "record": record["id"], "mutation": "create", "expectedRevision": None,
                        "reason": reason.strip(), "evidence": evidence, "sourceResource": None}
                    plan.append({"record": record, "recordSha256": fingerprint(record), "request": request,
                                 "last": {"state": "ready", "record": record["id"],
                                          "recordSha256": fingerprint(record)}})
                indices = {item["record"]["id"]: index for index, item in enumerate(plan)}
                for index, item in enumerate(plan):
                    record = item["record"]
                    data = record.get("content", {}).get("data", {})
                    bindings = []
                    if record["kind"] == "studio.component":
                        bindings = [(binding.get("query"), binding.get("revision"))
                                    for binding in data.get("queryBindings", [])]
                    elif record["kind"] == "studio.app":
                        bindings = [(section.get("component"), section.get("componentRevision"))
                                    for section in data.get("layout", {}).get("sections", [])]
                    for target, revision in bindings:
                        if target in indices and (indices[target] >= index or revision != "pending"):
                            raise StoreError("Studio App save dependency must use a prior pending revision pin")
                record = plan[0]["record"]
                request = plan[0]["request"]
                declarations = arguments.get("attachments", [])
                app_indices = [i for i, item in enumerate(plan) if item["record"]["kind"] == "studio.app"]
                attachment_index = app_indices[0] if len(app_indices) == 1 else None
                attachment_record = plan[attachment_index]["record"] if attachment_index is not None else None
                has_embedded_component = any(_has_embedded_component(item["record"]) for item in plan)
                if has_embedded_component and attachment_record is None:
                    raise StoreError("Studio embedded components require a parent App attachment")
                if (not isinstance(declarations, list) or len(declarations) > 8
                        or declarations and attachment_record is None
                        or declarations and attachment_index != len(plan) - 1
                        or sum(item.get("size", 0) for item in declarations if isinstance(item, dict))
                            > 16 * 1024 * 1024):
                    raise StoreError("Studio App attachment declarations are invalid")
                if (declarations and not _attachment_storage_allowed(
                        destination, attachment_record, destination["native_actor"], self.clock())):
                    raise StoreError("Protected destination App attachments require an authorized byte provider")
                seen_uploads = set()
                seen_roles = set()
                for declaration in declarations:
                    _validate_attachment_declaration(declaration)
                    if declaration["id"] in seen_uploads or declaration["role"] in seen_roles:
                        raise StoreError("Studio App attachment declarations are invalid")
                    seen_uploads.add(declaration["id"])
                    seen_roles.add(declaration["role"])
                if ("pglite-snapshot" in seen_roles
                        and not seen_roles.intersection({"sql-fallback", "csv-fallback"})):
                    raise StoreError("A PGlite snapshot requires a declared SQL or CSV fallback")
                requires_embedded = False
                if attachment_record is not None or declarations:
                    from studio_app_bindings import validate_embedded_attachment_refs
                    try:
                        requires_embedded = validate_embedded_attachment_refs(
                            attachment_record, [item["record"] for item in plan], declarations)
                    except (ValueError, KeyError, TypeError, AttributeError) as exc:
                        raise StoreError("Studio App snapshot does not match its declared attachment") from exc
                if requires_embedded and not destination["store"].contract.studio_embedded_enabled:
                    raise StoreError("Studio App embedded snapshots are unavailable for this alias")
                if (requires_embedded and not any(item.get("role") == "pglite-snapshot" for item in declarations)):
                    raise StoreError("Studio App embedded snapshot attachment is unavailable")
                if declarations and record.get("content", {}).get("data", {}).get("attachments"):
                    raise StoreError("Studio App attachments are supplied through bounded uploads")
                from studio_app_transfer import fingerprint
                preview = {"session": "0" * 64, "state": "ready", "record": record["id"],
                           "recordSha256": fingerprint(record), "stages": len(plan), "next": "apps.save.advance"}
                compact_response(preview)
                handle = self.sessions.create(actor, {"mode": "save", "alias": alias,
                    "authority": destination["authority"], "binding": destination["binding"],
                    "nativeActor": destination["native_actor"], "registration": destination["registration"],
                    "request": request,
                    "record": record, "recordSha256": fingerprint(record),
                    "plan": plan, "stageIndex": 0, "committedRevisions": {},
                    "attachmentRecordIndex": attachment_index,
                    "attachmentDeclarations": declarations,
                    "requiresEmbedded": requires_embedded,
                    "last": {"state": "ready", "record": record["id"],
                             "recordSha256": fingerprint(record)}})
                if not self._save_guard(actor, alias, destination["authority"], destination["binding"],
                                        destination["native_actor"], destination["registration"],
                                        requires_embedded=requires_embedded):
                    self.sessions.abort(handle, actor)
                    raise StoreError("Studio App registration changed before draft response release")
                return {**preview, "session": handle}
            finally:
                destination["store"].close()
        if name in ("apps.save.attachment.begin", "apps.save.attachment.chunk", "apps.save.attachment.finish"):
            required = {"session", "id"}
            if name.endswith(".begin"):
                required |= {"size", "sha256", "role", "format", "mediaType"}
            elif name.endswith(".chunk"):
                required |= {"index", "data"}
            if (not required.issubset(arguments) if name.endswith(".begin")
                    else set(arguments) != required):
                raise StoreError("Studio App attachment arguments are invalid")
            session_id, attachment_id = arguments["session"], arguments["id"]
            session = self.sessions.get(session_id, actor)
            payload = session["payload"]
            if (payload.get("mode") != "save" or payload.get("last", {}).get("proposal")
                    or payload.get("effectIntent")):
                raise StoreError("Studio App save session no longer accepts attachments")
            declaration = next((item for item in payload.get("attachmentDeclarations", [])
                                if item.get("id") == attachment_id), None)
            if declaration is None:
                raise StoreError("Studio App attachment declaration is unavailable")
            expected_arguments = {"session", "id"} | _attachment_declaration_fields(declaration)
            if name.endswith(".begin") and set(arguments) != expected_arguments:
                raise StoreError("Studio App attachment arguments are invalid")
            lease_holder = {"id": payload.get("uploads", {}).get(attachment_id, {}).get("admissionReservation")}
            def upload_guard(current_session, *, allow_settled=False):
                live_payload = current_session.get("payload", {})
                if (current_session.get("state") != "active" or current_session.get("expires", 0) <= self.sessions.clock()
                        or live_payload.get("mode") != "save" or live_payload.get("effectIntent")
                        or live_payload.get("last", {}).get("proposal")):
                    return False
                try:
                    current_destination = self.resolve(actor, live_payload["alias"], "propose")
                    try:
                        target_index = live_payload.get("attachmentRecordIndex")
                        target_plan = live_payload.get("plan", [])
                        target_record = (target_plan[target_index]["record"]
                                         if type(target_index) is int and 0 <= target_index < len(target_plan)
                                         else None)
                        attachment_storage_allowed = (target_record is not None and
                            _attachment_storage_allowed(current_destination, target_record,
                                live_payload["nativeActor"], self.clock()))
                        upload = live_payload.get("uploads", {}).get(attachment_id, {})
                        reservation_id = upload.get("admissionReservation") or lease_holder.get("id")
                        if current_destination.get("admission") is not None:
                            if not reservation_id:
                                return False
                            reservation_state = current_destination["admission"][0].reservation_state(
                                reservation_id)["state"]
                            if reservation_state != "reserved" and not (
                                    allow_settled and reservation_state == "settled"
                                    and upload.get("complete")):
                                return False
                        def current_save_guard():
                            selected_guard = current_destination.get("selected_save_guard")
                            if callable(selected_guard):
                                # Revalidate this already-owned selection; never cache
                                # authority, grants, inventory or provider state.
                                if self.identity() != actor:
                                    return False
                                return (selected_guard(live_payload["authority"], live_payload["binding"],
                                    live_payload["nativeActor"], live_payload["registration"],
                                    requires_embedded=live_payload.get("requiresEmbedded", False))
                                    and self.identity() == actor)
                            # Other trusted embeddings retain their original full
                            # resolve/recheck/close behavior without this callback.
                            return self._save_guard(actor, live_payload["alias"], live_payload["authority"],
                                live_payload["binding"], live_payload["nativeActor"], live_payload["registration"],
                                requires_embedded=live_payload.get("requiresEmbedded", False))

                        return (self._save_destination_matches(current_destination, live_payload)
                                and target_record is not None and target_record.get("kind") == "studio.app"
                                and attachment_storage_allowed and current_save_guard())
                    finally:
                        current_destination["store"].close()
                except Exception:
                    return False
            if name.endswith(".begin"):
                for key in expected_arguments - {"session", "id"}:
                    if arguments[key] != declaration[key]:
                        raise StoreError("Studio App attachment upload differs from its declaration")
                if declaration["role"] == "pglite-snapshot":
                    fallback_ready = any(
                        item.get("role") in ("sql-fallback", "csv-fallback")
                        and payload.get("uploads", {}).get(item.get("id"), {}).get("complete")
                        for item in payload.get("attachmentDeclarations", []))
                    if not fallback_ready:
                        raise StoreError("Complete the declared SQL or CSV fallback before the PGlite snapshot")
                destination = self.resolve(actor, payload["alias"], "propose")
                try:
                    self._require_adopted_native_scope(destination)
                    reservation = None
                    session_reservation = None
                    created_session_reservation = False
                    attachment_index = payload.get("attachmentRecordIndex")
                    plan = payload.get("plan", [])
                    target_record = (plan[attachment_index]["record"]
                        if type(attachment_index) is int and 0 <= attachment_index < len(plan) else None)
                    if (target_record is None or not _attachment_storage_allowed(
                            destination, target_record, payload.get("nativeActor"), self.clock())):
                        raise StoreError("Protected destination App attachments require an authorized byte provider")
                    protected_chunks = destination.get("protection") is not None
                    stored_bound = (_protected_attachment_bound(declaration["size"], destination["protection"])
                                    if protected_chunks else declaration["size"])
                    if destination.get("admission") is not None:
                        ledger, inventory_now = destination["admission"]
                        session_reservation = (session.get("storageAdmission", {})
                                               .get("sessionReservation"))
                        reserved_bytes = _upload_reservation_bytes(declaration["size"],
                                                                   stored_bytes=stored_bound)
                        before = inventory_now()
                        details = {"kind": "studio-app-upload", "session": session_id,
                            "attachment": attachment_id, "declaredSha256": declaration["sha256"],
                            "declaredBytes": declaration["size"], "initialReservedBytes": reserved_bytes,
                            "authorityBinding": destination["binding"]}
                        reservation = ledger.reserve(operation_key=f"studio-app-upload:{session_id}:{attachment_id}",
                            reserved_bytes=reserved_bytes, basis_sha256=before["basisSha256"],
                            details=details, inventory_now=inventory_now)
                        if reservation["state"] != "reserved":
                            raise StoreError("Studio App upload reservation is unresolved")
                        lease_holder["id"] = reservation["id"]
                        if session_reservation is None:
                            try:
                                current_session_bytes = len(encode(session))
                                before_session = inventory_now()
                                session_bound = _session_reservation_bytes(current_session_bytes)
                                session_reservation = ledger.reserve(
                                    operation_key=f"studio-app-session:{session_id}",
                                    reserved_bytes=session_bound,
                                    basis_sha256=before_session["basisSha256"],
                                    details={"kind": "studio-app-session", "session": session_id,
                                             "initialReservedBytes": session_bound,
                                             "authorityBinding": destination["binding"]},
                                    inventory_now=inventory_now)
                                if session_reservation["state"] != "reserved":
                                    raise StoreError("Studio App session reservation is unresolved")
                                session_reservation = session_reservation["id"]
                                created_session_reservation = True
                            except BaseException:
                                try:
                                    ledger.release_unwritten(reservation["id"], inventory_now=inventory_now)
                                except Exception:
                                    try:
                                        ledger.mark_unknown(reservation["id"])
                                    except Exception:
                                        pass
                                raise
                    try:
                        self.sessions.begin_upload(session_id, actor, attachment_id,
                            size=declaration["size"], sha256=declaration["sha256"],
                            admission_reservation=reservation["id"] if reservation else None,
                            admission_session_reservation=session_reservation,
                            protected_chunks=protected_chunks,
                            guard=upload_guard, identity_check=self.identity)
                    except BaseException:
                        if reservation is not None:
                            try:
                                ledger.release_unwritten(reservation["id"], inventory_now=inventory_now)
                            except Exception:
                                try:
                                    ledger.mark_unknown(reservation["id"])
                                except Exception:
                                    pass
                        if created_session_reservation:
                            try:
                                ledger.release_unwritten(session_reservation, inventory_now=inventory_now)
                            except Exception:
                                try:
                                    ledger.mark_unknown(session_reservation)
                                except Exception:
                                    pass
                        raise
                finally:
                    destination["store"].close()
                latest = self.sessions.get(session_id, actor)
                if self.identity() != actor or not upload_guard(latest):
                    self.sessions.abort(session_id, actor)
                    raise StoreError("Studio App attachment authorization changed before response release")
                return {"session": session_id, "attachment": attachment_id, "nextChunk": 0,
                        "maxChunkBytes": 32 * 1024}
            if name.endswith(".chunk"):
                upload = payload.get("uploads", {}).get(attachment_id, {})
                lease_holder["id"] = upload.get("admissionReservation")
                accepted = self.sessions.write_chunk(session_id, actor, attachment_id,
                    index=arguments["index"], data=arguments["data"],
                    guard=upload_guard, identity_check=self.identity)
                latest = self.sessions.get(session_id, actor)
                current_destination = self.resolve(actor, latest["payload"]["alias"], "propose")
                try:
                    latest_upload = latest["payload"].get("uploads", {}).get(attachment_id, {})
                    self._upload_lease_state(current_destination, latest_upload)
                finally:
                    current_destination["store"].close()
                if self.identity() != actor or not upload_guard(latest):
                    self.sessions.abort(session_id, actor)
                    raise StoreError("Studio App attachment authorization changed before response release")
                return {"session": session_id, **accepted}

            # Completion first verifies the full upload pin. The blob effect is
            # then protected by a durable unknown-outcome intent, current host
            # registration checks and the selected native writer transaction.
            _, raw = self.sessions.finish_upload(session_id, actor, attachment_id,
                guard=lambda current: upload_guard(current, allow_settled=True),
                identity_check=self.identity)
            if declaration["role"] == "pglite-snapshot":
                from studio_app_attachments import verify_pglite_snapshot_bytes
                verify_pglite_snapshot_bytes(declaration, raw)
            destination = self.resolve(actor, payload["alias"], "propose")
            try:
                upload_state = self.sessions.get(session_id, actor)["payload"].get("uploads", {}).get(attachment_id, {})
                self._upload_lease_state(destination, upload_state, allow_settled=True)
                self._require_adopted_native_scope(destination)
                attachment_index = payload.get("attachmentRecordIndex")
                plan = payload.get("plan", [])
                if (type(attachment_index) is not int or not 0 <= attachment_index < len(plan)):
                    raise StoreError("Studio App attachment target is unavailable")
                record = plan[attachment_index]["record"]
                if (record.get("kind") != "studio.app" or not self._save_destination_matches(destination, payload)
                        or not self._save_guard(actor, payload["alias"], payload["authority"],
                            payload["binding"], payload["nativeActor"], payload["registration"], requires_embedded=payload.get("requiresEmbedded", False))):
                    raise StoreError("Studio App attachment destination is unavailable")
                store = destination["store"]
                if not _attachment_storage_allowed(
                        destination, record, destination["native_actor"], self.clock()):
                    raise StoreError("Protected destination App attachments require an authorized byte provider")
                if not store.contract.blob_store:
                    raise StoreError("Studio App destination has no content-addressed blob store")
                # On replay, identify the already-pinned attachment from the
                # upload's immutable source tuple and verify its bytes instead
                # of writing a second object under the settled upload lease.
                source_id = "studio-save:" + record["id"]
                source_revision = "sha256:" + declaration["sha256"]
                existing_attachments = [item for item in record.get("content", {}).get("data", {}).get("attachments", [])
                    if isinstance(item, dict) and item.get("role") == declaration["role"]
                    and item.get("format") == declaration["format"]
                    and item.get("source") == {"id": source_id, "revision": source_revision}]
                if existing_attachments:
                    if len(existing_attachments) != 1:
                        raise StoreError("Studio App attachment replay is ambiguous")
                    attachment = existing_attachments[0]
                    locator_value = attachment.get("blob")
                    from blob_store import check_locator, verify as verify_blob
                    check_locator(locator_value)
                    from studio_app_transfer import fingerprint
                    if (locator_value["store"] != store.contract.blob_store
                            or locator_value["mediaType"] != declaration["mediaType"]
                            or plan[attachment_index].get("recordSha256") != fingerprint(record)):
                        raise StoreError("Studio App attachment replay pin is inconsistent")
                    existing_stored = destination["blob_reader"](locator_value)
                    verify_blob(locator_value, existing_stored)
                    existing_plain = existing_stored
                    if attachment.get("protection") is not None:
                        existing_plain = _open_attachment(existing_stored, binding=store.contract.binding,
                            record_id=record["id"], attachment=attachment,
                            protection=destination.get("protection"))
                    elif destination.get("protection") is not None:
                        raise StoreError("Existing plaintext App attachment cannot satisfy the selected protection")
                    latest = self.sessions.get(session_id, actor)
                    if (existing_plain != raw or self.identity() != actor
                            or not upload_guard(latest, allow_settled=True)):
                        raise StoreError("Studio App attachment replay could not be verified")
                    self._settle_upload_lease(destination,
                        latest["payload"].get("uploads", {}).get(attachment_id, {}), allow_settled=True)
                    return {"session": session_id, "attachment": attachment_id, "complete": True,
                            "sha256": declaration["sha256"], "bytes": len(raw), "alreadyPresent": True,
                            "blobWriteMayBeOrphaned": True}
                from blob_store import locator
                protection_metadata = None
                if destination.get("protection") is not None:
                    stored, protection_metadata = _seal_attachment(raw, binding=store.contract.binding,
                        record=record, role=declaration["role"], fmt=declaration["format"],
                        protection=destination["protection"])
                    if len(stored) != _protected_attachment_bound(
                            declaration["size"], destination["protection"]):
                        raise StoreError("Protected Studio App attachment size differs from its admitted envelope")
                else:
                    stored = raw
                if protection_metadata is not None and not callable(destination.get("guarded_blob_writer")):
                    raise StoreError("Protected Studio App blob host has no publication boundary")
                stored_digest = hashlib.sha256(stored).hexdigest()
                expected_locator = locator(store.contract.blob_store,
                    "sha256/" + stored_digest, stored, declaration["mediaType"])
                if expected_locator["sha256"] != stored_digest:
                    raise StoreError("Studio App attachment digest changed")
                upload_reservation = upload_state.get("admissionReservation")
                if destination.get("admission") is not None and upload_reservation:
                    ledger, inventory_now = destination["admission"]
                    available = ledger.reservation_state(upload_reservation)["reservedBytes"]
                    if len(stored) != available:
                        raise StoreError("Studio App stored attachment differs from its exact pre-effect reservation")
                if expected_locator in record.get("blobs", []):
                    existing = destination["blob_reader"](expected_locator)
                    latest = self.sessions.get(session_id, actor)
                    if (existing != stored or self.identity() != actor
                            or not upload_guard(latest, allow_settled=True)):
                        raise StoreError("Studio App attachment replay could not be verified")
                    self._settle_upload_lease(destination,
                        latest["payload"].get("uploads", {}).get(attachment_id, {}), allow_settled=True)
                    return {"session": session_id, "attachment": attachment_id, "complete": True,
                            "sha256": declaration["sha256"], "bytes": len(raw), "alreadyPresent": True,
                            "blobWriteMayBeOrphaned": True}
                result = {}
                def write_attachment(current, mark_intent):
                    live = current["payload"]
                    live_plan = live.get("plan", [])
                    live_index = live.get("attachmentRecordIndex")
                    if (live_index != attachment_index or type(live_index) is not int
                            or not 0 <= live_index < len(live_plan)
                            or live_plan[live_index].get("recordSha256") != plan[attachment_index].get("recordSha256")):
                        raise StoreError("Studio App save draft changed")
                    mark_intent(hashlib.sha256(encode({"session": session_id, "attachment": attachment_id,
                        "sha256": declaration["sha256"]})).hexdigest(),
                        {"phase": "attachment", "attachment": attachment_id,
                         "residual": "An immutable content-addressed blob may exist; inspect its exact digest before recovery."})
                    current_destination = self.resolve(actor, live["alias"], "propose")
                    try:
                        current_attachment_storage_allowed = _attachment_storage_allowed(
                            current_destination, live_plan[live_index]["record"],
                            live["nativeActor"], self.clock())
                        if (not self._save_guard(actor, live["alias"], live["authority"], live["binding"],
                                live["nativeActor"], live["registration"], requires_embedded=live.get("requiresEmbedded", False))
                                or not self._save_destination_matches(current_destination, live)
                                or not current_attachment_storage_allowed):
                            raise StoreError("Studio App attachment authorization changed")
                        updated = json.loads(json.dumps(live_plan[live_index]["record"]))
                        updated.setdefault("blobs", []).append(expected_locator)
                        data = updated["content"].setdefault("data", {})
                        attachment_metadata = {key: declaration[key] for key in _PGLITE_METADATA_FIELDS
                                               if key in declaration}
                        data.setdefault("attachments", []).append({"role": declaration["role"],
                            "format": declaration["format"], "blob": expected_locator,
                            "capturedAt": self.clock(), **attachment_metadata,
                            "source": {"id": "studio-save:" + updated["id"],
                                       "revision": "sha256:" + declaration["sha256"]},
                            **({"protection": protection_metadata} if protection_metadata is not None else {})})
                        current_destination["store"].contract.validate_record(updated)
                        from studio_app_transfer import fingerprint
                        digest = fingerprint(updated)
                        live_upload = live.get("uploads", {}).get(attachment_id, {})
                        def check_publication(staged, current_protection):
                            if staged != stored or self.identity() != actor:
                                raise StoreError("Studio App staged attachment pin or identity changed")
                            current = {**current_destination, "protection": current_protection}
                            if not _attachment_storage_allowed(current, updated, live["nativeActor"], self.clock()):
                                raise StoreError("Studio App attachment policy no longer permits storage")
                            if protection_metadata is None:
                                if current_protection is not None:
                                    raise StoreError("Plaintext attachment cannot satisfy current protection")
                                return
                            attachment = updated["content"]["data"]["attachments"][-1]
                            plain = _open_attachment(staged, binding=store.contract.binding,
                                record_id=updated["id"], attachment=attachment, protection=current_protection)
                            if plain != raw:
                                raise StoreError("Protected Studio App attachment source changed")
                            from brain_protection import ProtectionError, combine
                            host_object, required, selected_profile = current_protection[:3]
                            envelope = json.loads(staged)
                            header = {key: value for key, value in envelope.items()
                                      if key not in ("storage", "signature")}
                            header["requirements"] = combine(required, envelope["requirements"])
                            try:
                                host_object.permit(header, "retain")
                                host_object.available(selected_profile)
                            except ProtectionError as exc:
                                raise StoreError("Protected Studio App attachment retention changed") from exc
                        guarded_writer = (current_destination.get("guarded_blob_writer")
                                          if protection_metadata is not None else None)
                        selected_guard = current_destination.get("selected_save_guard")
                        if ((callable(guarded_writer) or protection_metadata is not None)
                                and not callable(selected_guard)):
                            raise StoreError("Studio App host has no selected-connection save guard")
                        def recheck_selected_save():
                            if callable(selected_guard):
                                return selected_guard(live["authority"], live["binding"],
                                    live["nativeActor"], live["registration"],
                                    requires_embedded=live.get("requiresEmbedded", False))
                            # Ordinary unprotected legacy custom hosts keep their
                            # existing adapter semantics; protected hosts refuse.
                            return self._save_guard(actor, live["alias"], live["authority"], live["binding"],
                                live["nativeActor"], live["registration"],
                                requires_embedded=live.get("requiresEmbedded", False))
                        with current_destination["store"]._storage_admission_effect(
                                "studio-app.attachment",
                                reservation_id=live_upload.get("admissionReservation")):
                            with current_destination["store"].request_transaction(write=True):
                                if not recheck_selected_save():
                                    raise StoreError("Studio App attachment authorization changed before write")
                                if callable(guarded_writer):
                                    before_commit = guarded_writer(expected_locator, stored, check_publication)
                                    if not callable(before_commit):
                                        raise StoreError("Studio App guarded publication receipt is unavailable")
                                else:
                                    if protection_metadata is not None:
                                        raise StoreError("Protected Studio App host has no publication boundary")
                                    current_destination["blob_writer"](expected_locator, stored)
                                    before_commit = None
                                if not recheck_selected_save():
                                    raise StoreError("Studio App attachment authorization changed during write")
                                if before_commit is not None:
                                    before_commit()
                        result.update({"record": updated, "digest": digest})
                        updated_plan = list(live_plan)
                        updated_plan[live_index] = {**updated_plan[live_index], "record": updated,
                            "recordSha256": digest,
                            "last": {"state": "ready", "record": updated["id"], "recordSha256": digest}}
                        replacement = {**live, "plan": updated_plan}
                        if live.get("stageIndex") == live_index:
                            replacement.update({"record": updated, "recordSha256": digest,
                                "last": {"state": "ready", "record": updated["id"], "recordSha256": digest}})
                        return {**current, "payload": replacement}
                    finally:
                        current_destination["store"].close()
                self.sessions.run_operation(session_id, actor, write_attachment, identity_check=self.identity)
                latest = self.sessions.get(session_id, actor)
                latest_plan = latest["payload"].get("plan", [])
                latest_index = latest["payload"].get("attachmentRecordIndex")
                if (latest["payload"].get("effectIntent")
                        or type(latest_index) is not int or not 0 <= latest_index < len(latest_plan)
                        or latest_plan[latest_index].get("recordSha256") != result.get("digest")
                        or self.identity() != actor or not upload_guard(latest)):
                    raise StoreError("Studio App attachment authorization changed before response release")
                self._settle_upload_lease(destination, latest["payload"].get("uploads", {}).get(attachment_id, {}))
                return {"session": session_id, "attachment": attachment_id, "complete": True,
                        "sha256": declaration["sha256"], "bytes": len(raw),
                        "blobWriteMayBeOrphaned": store.contract.cell["blobs"] != "db-blob"}
            finally:
                destination["store"].close()
        if name == "apps.save.advance":
            if set(arguments) != {"session"}:
                raise StoreError("Studio App save arguments are invalid")
            session = self.sessions.get(arguments["session"], actor)
            if session["payload"].get("mode") != "save":
                raise StoreError("Studio App save session is unavailable")
            payload = session["payload"]
            if payload.get("uploads"):
                destination = self.resolve(actor, payload["alias"], "propose")
                try:
                    for upload in payload["uploads"].values():
                        if not isinstance(upload, dict) or not upload.get("complete"):
                            raise StoreError("Studio App save has an unfinished attachment upload")
                        reservation_id = upload.get("admissionReservation")
                        if reservation_id and (destination.get("admission") is None
                                or destination["admission"][0].reservation_state(reservation_id)["state"] != "settled"):
                            raise StoreError("Studio App attachment content reservation is unresolved")
                finally:
                    destination["store"].close()
            if payload.get("effectIntent"):
                return self._call("apps.save.status", arguments)
            if payload.get("last", {}).get("proposal"):
                observed = self._call("apps.save.status", arguments)
                if not observed.get("stageCommitted") or observed.get("complete"):
                    if observed.get("complete"):
                        latest_session = self.sessions.get(arguments["session"], actor)
                        if latest_session.get("storageAdmission"):
                            destination = self.resolve(actor, payload["alias"], "propose")
                            try:
                                self._settle_session_lease(destination, latest_session)
                            finally:
                                destination["store"].close()
                    return observed
                old_index = payload.get("stageIndex", 0)
                def select_next(value):
                    live = value["payload"]
                    if (live.get("stageIndex") != old_index
                            or live.get("last", {}).get("proposal") != observed.get("proposal")):
                        raise StoreError("Studio App save stage changed during advancement")
                    next_index = old_index + 1
                    if next_index >= len(live.get("plan", [])):
                        raise StoreError("Studio App save plan is malformed")
                    revisions = dict(live.get("committedRevisions", {}))
                    revisions[live["record"]["id"]] = observed["revision"]
                    stage = json.loads(json.dumps(live["plan"][next_index]))
                    record = stage["record"]
                    planned = {item["record"]["id"] for item in live["plan"]}
                    data = record.get("content", {}).get("data", {})
                    def pin(target, field, owner):
                        if target in planned:
                            if target not in revisions or owner.get(field) != "pending":
                                raise StoreError("Studio App save dependency requires its exact pending revision pin")
                            owner[field] = revisions[target]
                    if record["kind"] == "studio.component":
                        for binding in data.get("queryBindings", []):
                            pin(binding.get("query"), "revision", binding)
                    elif record["kind"] == "studio.app":
                        for section in data.get("layout", {}).get("sections", []):
                            pin(section.get("component"), "componentRevision", section)
                    destination = self.resolve(actor, live["alias"], "propose")
                    try:
                        destination["store"].contract.validate_record(record)
                    finally:
                        destination["store"].close()
                    from studio_app_transfer import fingerprint
                    stage["record"] = record
                    stage["recordSha256"] = fingerprint(record)
                    stage["last"] = {"state": "ready", "record": record["id"],
                                      "recordSha256": stage["recordSha256"]}
                    live["plan"][next_index] = stage
                    live["stageIndex"] = next_index
                    live["committedRevisions"] = revisions
                    live["record"] = stage["record"]
                    live["recordSha256"] = stage["recordSha256"]
                    live["request"] = stage["request"]
                    live["last"] = stage["last"]
                    return value
                self.sessions.update(arguments["session"], actor, select_next)
                session = self.sessions.get(arguments["session"], actor)
                payload = session["payload"]
            result = {}
            def propose(current, mark_intent):
                live = current["payload"]
                destination = self.resolve(actor, live["alias"], "propose")
                try:
                    self._require_adopted_native_scope(destination)
                    if (not self._save_destination_matches(destination, live)
                            or not self._save_guard(actor, live["alias"], live["authority"], live["binding"],
                                            live["nativeActor"], live["registration"], requires_embedded=live.get("requiresEmbedded", False))):
                        raise StoreError("Studio App save authority changed")
                    embedded_formats = self._classify_save_embedded(actor, live)
                    embedded_views = self._classify_save_embedded_views(live, embedded_formats)
                    destination["store"].contract.validate_record(live["record"])
                    from studio_app_transfer import fingerprint
                    if fingerprint(live["record"]) != live["recordSha256"]:
                        raise StoreError("Studio App save draft changed")
                    mark_intent(hashlib.sha256(encode({"session": arguments["session"],
                        "request": live["request"], "recordSha256": live["recordSha256"]})).hexdigest(),
                        {"phase": live["record"]["kind"], "recordSha256": live["recordSha256"],
                         "residual": "A native create proposal may exist; inspect this exact request before retry."})
                    with destination["store"].request_transaction(write=True):
                        if (not self._save_destination_matches(destination, live)
                                or not self._save_guard(actor, live["alias"], live["authority"], live["binding"],
                                                live["nativeActor"], live["registration"], requires_embedded=live.get("requiresEmbedded", False))):
                            raise StoreError("Studio App save authority changed before native write")
                        if destination["store"]._record_metadata(live["record"]["id"]) is not None:
                            raise StoreError("Studio App create identity already exists or is tombstoned")
                        proposed = destination["store"].propose(live["request"], live["record"],
                            destination["native_actor"], at=self.clock())
                        if (not self._save_destination_matches(destination, live)
                                or not self._save_guard(actor, live["alias"], live["authority"], live["binding"],
                                                live["nativeActor"], live["registration"], requires_embedded=live.get("requiresEmbedded", False))):
                            raise StoreError("Studio App save authorization changed during native write")
                    summary = {"state": "awaiting-native-review", "record": live["record"]["id"],
                               "recordSha256": live["recordSha256"], "proposal": proposed["proposal"],
                               "stageIndex": live.get("stageIndex", 0), "stages": len(live.get("plan", [None])),
                               "stageCommitted": False, "revision": None, "complete": False}
                    response = {**self._save_status_fields(
                        arguments["session"], live, embedded_formats, embedded_views), **summary}
                    compact_response(response)
                    result["response"] = response
                    return {**current, "payload": {**live, "last": summary}}
                finally:
                    destination["store"].close()
            self.sessions.run_operation(arguments["session"], actor, propose,
                                        identity_check=self.identity)
            latest = self.sessions.get(arguments["session"], actor)
            if latest["payload"].get("effectIntent") or latest["payload"].get("recordSha256") != payload["recordSha256"]:
                raise StoreError("Studio App save state changed before response release")
            if not self._save_guard(actor, payload["alias"], payload["authority"], payload["binding"],
                                    payload["nativeActor"], payload["registration"], requires_embedded=payload.get("requiresEmbedded", False)):
                raise StoreError("Studio App save authorization changed before response release")
            return result["response"]
        if name in ("apps.save.status", "apps.save.abort"):
            if set(arguments) != {"session"}:
                raise StoreError("Studio App save arguments are invalid")
            session = self.sessions.get(arguments["session"], actor)
            payload = session["payload"]
            if payload.get("mode") != "save":
                raise StoreError("Studio App save session is unavailable")
            if name == "apps.save.abort":
                uploads = payload.get("uploads", {})
                response = self.sessions.abort(arguments["session"], actor)
                destination = self.resolve(actor, payload["alias"], "propose")
                try:
                    for upload in uploads.values():
                        if isinstance(upload, dict) and upload.get("admissionReservation"):
                            self._settle_upload_lease(destination, upload, allow_settled=True)
                    self._settle_session_lease(destination, session)
                finally:
                    destination["store"].close()
                return response
            embedded_formats = self._classify_save_embedded(actor, payload)
            embedded_views = self._classify_save_embedded_views(payload, embedded_formats)
            if payload.get("effectIntent"):
                if not self._save_guard(actor, payload["alias"], payload["authority"], payload["binding"],
                                        payload["nativeActor"], payload["registration"], requires_embedded=payload.get("requiresEmbedded", False)):
                    raise StoreError("Studio App save registration changed during status inspection")
                latest = self.sessions.get(arguments["session"], actor)
                if latest.get("payload") != payload or self.identity() != actor:
                    raise StoreError("Studio App save session changed during status inspection")
                return {**self._save_status_fields(arguments["session"], payload, embedded_formats, embedded_views),
                        "state": "outcome-unknown",
                        "record": payload.get("record", {}).get("id"),
                        "recordSha256": payload.get("recordSha256"), "complete": False,
                        "residual": "A native create proposal may exist; inspect the exact create request before retry."}
            destination = self.resolve(actor, payload["alias"], "propose")
            try:
                if (destination["authority"] != payload["authority"] or destination["binding"] != payload["binding"]
                        or destination["native_actor"] != payload["nativeActor"]
                        or destination["registration"] != payload["registration"]):
                    raise StoreError("Studio App save authority changed")
                summary = payload["last"]
                proposal_id = summary.get("proposal")
                state = summary.get("state", "ready")
                if proposal_id:
                    inspected = destination["store"].inspect(proposal_id, destination["native_actor"], at=self.clock())
                    proposal = inspected["proposal"]
                    from studio_app_transfer import fingerprint, _commit_receipt
                    if (proposal.get("id") != proposal_id or proposal.get("request") != payload["request"]
                            or proposal.get("record") != payload["record"] or proposal.get("actor") != payload["nativeActor"]
                            or proposal.get("contract") != payload["binding"]
                            or fingerprint(payload["record"]) != payload["recordSha256"]):
                        raise StoreError("Studio App save proposal no longer matches its exact draft")
                    lifecycle = inspected.get("lifecycle", {}).get("state")
                    if lifecycle in ("rejected", "withdrawn", "deferred", "committed-unattributed"):
                        raise StoreError("Studio App save proposal has no acceptable native review outcome")
                    if lifecycle == "committed":
                        receipt = _commit_receipt(destination["store"], proposal)
                        current = inspected.get("current")
                        if (receipt.get("proposal") != proposal_id or receipt.get("request") != payload["request"]
                                or receipt.get("after") != payload["record"] or receipt.get("proposedBy") != payload["nativeActor"]
                                or receipt.get("contract") != payload["binding"] or receipt.get("previousRevision") is not None
                                or not current or current.get("record") != payload["record"]
                                or current.get("revision") != receipt.get("revision")):
                            raise StoreError("Studio App saved record differs from its attributed native commit")
                        state = "committed"
                    elif lifecycle == "pending" and not inspected.get("expired"):
                        state = "awaiting-native-review"
                    else:
                        raise StoreError("Studio App save proposal is expired or unavailable")
                response = {**self._save_status_fields(arguments["session"], payload, embedded_formats, embedded_views),
                            "state": state,
                            "record": payload["record"]["id"], "recordSha256": payload["recordSha256"],
                            "proposal": proposal_id, "stageIndex": payload.get("stageIndex", 0),
                            "stages": len(payload.get("plan", [None])),
                            "stageCommitted": state == "committed",
                            "revision": receipt.get("revision") if proposal_id and state == "committed" else None,
                            "complete": state == "committed"
                                and payload.get("stageIndex", 0) == len(payload.get("plan", [None])) - 1}
            finally:
                destination["store"].close()
            if not self._save_guard(actor, payload["alias"], payload["authority"], payload["binding"],
                                    payload["nativeActor"], payload["registration"], requires_embedded=payload.get("requiresEmbedded", False)):
                raise StoreError("Studio App save identity or registration changed during status inspection")
            latest = self.sessions.get(arguments["session"], actor)
            if latest.get("payload") != payload or self.identity() != actor:
                raise StoreError("Studio App save session changed during status inspection")
            return response
        if name == "apps.transfer.begin":
            if set(arguments) != {"source", "destination", "appId"}:
                raise StoreError("Studio App transfer arguments are invalid")
            source, destination = self._resolve_pair(actor, arguments["source"], arguments["destination"])
            try:
                if source["alias"] == destination["alias"]:
                    raise StoreError("Studio App transfer requires distinct registered aliases")
                from studio_app_transfer import prepare_package, new_receipt
                source_app = source["store"].get(arguments["appId"], source["native_actor"], at=self.clock())
                if not source_app or not isinstance(source_app.get("record"), dict):
                    raise StoreError("Studio App source is unavailable")
                destination_blob_protected = self._attachment_boundary(
                    source, destination, source_app["record"], self.clock())
                native_actor = source["native_actor"]
                package = prepare_package(source["store"], destination["store"], arguments["appId"], native_actor,
                    source_authority=source["authority"], destination_authority=destination["authority"],
                    blob_reader=source["blob_reader"], protection=destination["protection"],
                    source_protection=source.get("protection"),
                    destination_blob_protected=destination_blob_protected, clock=self.clock,
                    identity_guard=lambda who, src, dst, sb, db: self._guard(actor, source, destination, src, dst, sb, db, native_actor=who))
                app_record = next(item["record"] for item in package["records"]
                                  if item["record"]["kind"] == "studio.app")
                from studio_app_bindings import validate_embedded_attachment_refs
                try:
                    embedded = validate_embedded_attachment_refs(
                        app_record, [item["record"] for item in package["records"]],
                        app_record.get("content", {}).get("data", {}).get("attachments", []))
                except ValueError as exc:
                    raise StoreError("Studio App embedded snapshot is unavailable") from exc
                if embedded and (not source["store"].contract.studio_embedded_enabled
                                 or not destination["store"].contract.studio_embedded_enabled):
                    raise StoreError("Studio App embedded snapshots are unavailable for this transfer")
                receipt = new_receipt(package)
                destination_app_id = receipt["records"][arguments["appId"]]["destinationId"]
                preview = {"session": "0" * 64, "packageSha256": package["sha256"],
                           "records": len(package["records"]), "attachments": len(package["attachments"]),
                           "destinationAppId": destination_app_id, "next": "apps.transfer.advance"}
                compact_response(preview)
                if not self._guard(actor, source, destination, source["authority"], destination["authority"],
                                   source["binding"], destination["binding"], native_actor=native_actor,
                                   requires_embedded=embedded):
                    raise StoreError("Studio App transfer capability changed before session creation")
                handle = self.sessions.create(actor, {"mode": "transfer", "source": source["alias"],
                    "destination": destination["alias"], "appId": arguments["appId"], "package": package,
                    "receipt": receipt, "requiresEmbedded": embedded, "last": {"state": "ready"}})
                return {**preview, "session": handle}
            finally:
                source["store"].close()
                destination["store"].close()
        if name in ("apps.transfer.status", "apps.transfer.abort", "apps.transfer.advance"):
            if set(arguments) != {"session"}:
                raise StoreError("Studio App session arguments are invalid")
            session = self.sessions.get(arguments["session"], actor)
            if session["payload"].get("mode") != "transfer":
                raise StoreError("Studio App transfer session is unavailable")
            if name == "apps.transfer.status":
                payload = session["payload"]
                source, destination = self._resolve_pair(actor, payload["source"], payload["destination"])
                try:
                    self._validate_embedded_transfer(source, destination, payload)
                    intent = payload.get("effectIntent")
                    if isinstance(intent, dict) and intent.get("state") == "outcome-unknown":
                        from studio_app_transfer import verify_current_source
                        app_record = next(item["record"] for item in payload["package"]["records"]
                                          if item["record"]["kind"] == "studio.app")
                        destination_blob_protected = self._attachment_boundary(
                            source, destination, app_record, self.clock())
                        verify_current_source(source["store"], destination["store"], payload["package"],
                            source["native_actor"], source_authority=source["authority"],
                            destination_authority=destination["authority"], blob_reader=source["blob_reader"],
                            source_protection=source.get("protection"), protection=destination["protection"],
                            destination_blob_protected=destination_blob_protected, clock=self.clock,
                            identity_guard=lambda who, src, dst, sb, db: self._guard(
                                actor, source, destination, src, dst, sb, db, native_actor=who,
                                requires_embedded=payload.get("requiresEmbedded", False)))
                        response = {"session": arguments["session"], "state": "outcome-unknown",
                                "phase": intent.get("phase"), "recordSha256": intent.get("recordSha256"),
                                "residual": intent.get("residual",
                                    "A native proposal may exist. Inspect the exact request in the destination before retrying."),
                                "complete": False}
                    else:
                        class WouldPropose(Exception):
                            pass
                        from studio_app_transfer import advance
                        app_record = next(item["record"] for item in payload["package"]["records"]
                                          if item["record"]["kind"] == "studio.app")
                        destination_blob_protected = self._attachment_boundary(
                            source, destination, app_record, self.clock())
                        try:
                            value = advance(source["store"], destination["store"], payload["package"],
                                payload["receipt"], source["native_actor"], source_authority=source["authority"],
                                destination_authority=destination["authority"], blob_reader=source["blob_reader"],
                                protection=destination["protection"], source_protection=source.get("protection"),
                                blob_writer=destination["blob_writer"],
                                destination_blob_protected=destination_blob_protected, clock=self.clock,
                                identity_guard=lambda who, src, dst, sb, db: self._guard(
                                    actor, source, destination, src, dst, sb, db, native_actor=who,
                                    requires_embedded=payload.get("requiresEmbedded", False)),
                                before_effect=lambda *_: (_ for _ in ()).throw(WouldPropose()))
                            response = {"session": arguments["session"], "state": value["status"],
                                "phase": value.get("phase"), "proposal": value.get("proposal"),
                                "complete": value["status"] == "complete"}
                        except WouldPropose:
                            response = {"session": arguments["session"], "state": "ready-for-native-proposal",
                                        "complete": False}
                    if not self._guard(actor, source, destination, source["authority"],
                                       destination["authority"], source["binding"], destination["binding"],
                                       native_actor=source["native_actor"],
                                       requires_embedded=payload.get("requiresEmbedded", False)):
                        raise StoreError("Studio App transfer is unavailable")
                finally:
                    source["store"].close()
                    destination["store"].close()
                current = self.sessions.get(arguments["session"], actor)
                if (current["payload"].get("receipt") != session["payload"].get("receipt")
                        or current["payload"].get("package", {}).get("sha256")
                            != session["payload"].get("package", {}).get("sha256")):
                    raise StoreError("Studio App transfer session changed during status inspection")
                if not self._guard(actor, source, destination, source["authority"],
                                   destination["authority"], source["binding"], destination["binding"],
                                   native_actor=source["native_actor"],
                                   requires_embedded=payload.get("requiresEmbedded", False)):
                    raise StoreError("Studio App transfer identity or registration changed during status inspection")
                return response
            if name == "apps.transfer.abort":
                return self.sessions.abort(arguments["session"], actor)
            payload = session["payload"]
            compact_response({"session": arguments["session"], "state": "awaiting-native-review",
                              "phase": "studio.component", "proposal": "x" * 512, "complete": False,
                              "destinationBlobWritesAreNontransactional": True})
            result = {}
            def perform(current, mark_intent):
                live = current["payload"]
                source, destination = self._resolve_pair(actor, live["source"], live["destination"])
                try:
                    self._validate_embedded_transfer(source, destination, live)
                    from studio_app_transfer import advance
                    app_record = next(item["record"] for item in live["package"]["records"]
                                      if item["record"]["kind"] == "studio.app")
                    destination_blob_protected = self._attachment_boundary(
                        source, destination, app_record, self.clock())
                    with destination["store"]._storage_admission_effect("studio-app.transfer"):
                        value = advance(source["store"], destination["store"], live["package"], live["receipt"], source["native_actor"],
                            source_authority=source["authority"], destination_authority=destination["authority"],
                            blob_reader=source["blob_reader"], protection=destination["protection"],
                            source_protection=source.get("protection"),
                            blob_writer=destination["blob_writer"], destination_blob_protected=destination_blob_protected,
                            clock=self.clock, identity_guard=lambda who, src, dst, sb, db: self._guard(
                                actor, source, destination, src, dst, sb, db, native_actor=who,
                                requires_embedded=live.get("requiresEmbedded", False)),
                            before_effect=lambda phase, origin_id, record_sha: mark_intent(
                                hashlib.sha256(encode({"session": arguments["session"],
                                    "packageSha256": live["package"]["sha256"], "phase": phase,
                                    "origin": origin_id, "recordSha256": record_sha})).hexdigest(),
                                {"phase": phase, "origin": origin_id, "recordSha256": record_sha,
                                 "residual": "A native proposal may exist; inspect this exact record request before retry."}))
                    phase = value.get("phase")
                    proposal = value.get("proposal")
                    if (phase is not None and (not isinstance(phase, str) or len(phase) > 64)
                            or proposal is not None and (not isinstance(proposal, str) or len(proposal) > 256)):
                        raise StoreError("Studio App native phase summary is invalid")
                    summary = {"state": value["status"], "phase": phase,
                               "proposal": proposal, "complete": value["status"] == "complete",
                               "destinationBlobWritesAreNontransactional": value.get("destinationBlobWritesAreNontransactional", False)}
                    response = {"session": arguments["session"], **summary}
                    compact_response(response)
                    result["response"] = response
                    result["receipt"] = value.get("receipt", live["receipt"])
                    return {**current, "payload": {**live, "receipt": value.get("receipt", live["receipt"]),
                                                       "last": summary}}
                finally:
                    source["store"].close()
                    destination["store"].close()
            self.sessions.run_operation(arguments["session"], actor, perform,
                                        identity_check=self.identity)
            latest = self.sessions.get(arguments["session"], actor)
            if (latest["payload"].get("effectIntent")
                    or latest["payload"].get("receipt") != result.get("receipt", payload["receipt"])
                    or latest["payload"].get("package", {}).get("sha256") != payload["package"]["sha256"]):
                raise StoreError("Studio App transfer state changed before response release")
            source_check, destination_check = self._resolve_pair(actor, payload["source"], payload["destination"])
            try:
                if not self._guard(actor, source_check, destination_check,
                    source_check["authority"], destination_check["authority"],
                    source_check["binding"], destination_check["binding"],
                    native_actor=source_check["native_actor"],
                    requires_embedded=payload.get("requiresEmbedded", False)):
                    raise StoreError("Studio App transfer authorization changed before response release")
            finally:
                source_check["store"].close()
                destination_check["store"].close()
            return result["response"]
        raise StoreError("Studio App tool is unavailable")

    def _guard(self, actor, source, destination, source_authority, destination_authority,
               source_binding, destination_binding, native_actor=None, requires_embedded=False):
        if self.identity() != actor:
            return False
        try:
            current_source, current_destination = self._resolve_pair(actor, source["alias"], destination["alias"])
        except Exception:
            return False
        try:
            return (current_source["authority"] == source_authority
                    and current_destination["authority"] == destination_authority
                    and current_source["binding"] == source_binding
                    and current_destination["binding"] == destination_binding
                    and current_source["native_actor"] == current_destination["native_actor"]
                    and (native_actor is None or current_source["native_actor"] == native_actor)
                    and current_source["registration"] == source["registration"]
                    and current_destination["registration"] == destination["registration"]
                    and (not requires_embedded
                         or current_source["store"].contract.studio_embedded_enabled
                         and current_destination["store"].contract.studio_embedded_enabled))
        finally:
            current_source["store"].close()
            current_destination["store"].close()

    @staticmethod
    def _validate_embedded_transfer(source, destination, payload):
        records = payload.get("package", {}).get("records", [])
        app = next((item.get("record") for item in records
                    if isinstance(item, dict) and isinstance(item.get("record"), dict)
                    and item["record"].get("kind") == "studio.app"), None)
        if app is None:
            raise StoreError("Studio App embedded transfer package is unavailable")
        from studio_app_bindings import validate_component_options, validate_embedded_attachment_refs
        components = [item["record"] for item in records
                      if isinstance(item, dict) and isinstance(item.get("record"), dict)
                      and item["record"].get("kind") == "studio.component"]
        try:
            embedded = validate_embedded_attachment_refs(
                app, [item["record"] for item in records],
                app.get("content", {}).get("data", {}).get("attachments", []))
            persisted = payload.get("requiresEmbedded")
            if ((persisted is None and embedded)
                    or persisted is not None and (type(persisted) is not bool or persisted != embedded)):
                raise ValueError("Studio App transfer classification is unavailable")
            if not embedded:
                return
            if (not source["store"].contract.studio_embedded_enabled
                    or not destination["store"].contract.studio_embedded_enabled):
                raise ValueError("Studio App embedded profile is unavailable")
            for component in components:
                options = component.get("content", {}).get("data", {}).get("definition", {}).get("options", {})
                if isinstance(options, dict) and "embedded" in options:
                    for selected in (source, destination):
                        validate_component_options(component,
                            embedded_schema=selected["store"].contract.studio_embedded_schema,
                            embedded_enabled=True)
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise StoreError("Studio App embedded transfer package is unavailable") from exc

    def _save_guard(self, actor, alias, authority, binding, native_actor, registration, *, requires_embedded=False):
        if self.identity() != actor:
            return False
        try:
            current = self.resolve(actor, alias, "propose")
        except Exception:
            return False
        try:
            return (current["authority"] == authority and current["binding"] == binding
                    and current["native_actor"] == native_actor
                    and current["registration"] == registration
                    and (not requires_embedded or current["store"].contract.studio_embedded_enabled)
                    and self.identity() == actor)
        finally:
            current["store"].close()

    def _classify_save_embedded(self, actor, payload):
        """Derive the retained plan's embedded format for the authenticated session owner."""
        destination = self.resolve(actor, payload.get("alias"), "propose")
        try:
            if not self._save_destination_matches(destination, payload):
                raise StoreError("Studio App save route changed during embedded classification")
            plan = payload.get("plan")
            if not isinstance(plan, list) or not plan or len(plan) > 32:
                raise StoreError("Studio App save plan is unavailable")
            records = [item.get("record") for item in plan
                       if isinstance(item, dict) and isinstance(item.get("record"), dict)]
            if len(records) != len(plan):
                raise StoreError("Studio App save plan is unavailable")
            apps = [record for record in records if record.get("kind") == "studio.app"]
            if len(apps) > 1:
                raise StoreError("Studio App save plan is ambiguous")
            if not apps:
                embedded = False
            else:
                app = apps[0]
                app_attachments = app.get("content", {}).get("data", {}).get("attachments", [])
                declarations = payload.get("attachmentDeclarations", [])
                actual_pglite_items = [item for item in app_attachments
                                       if isinstance(item, dict) and item.get("role") == "pglite-snapshot"]
                declared_pglite = [item for item in declarations
                                   if isinstance(item, dict) and item.get("role") == "pglite-snapshot"]
                actual_pglite = bool(actual_pglite_items)
                if actual_pglite:
                    if len(actual_pglite_items) != 1 or len(declared_pglite) != 1:
                        raise StoreError("Studio App embedded attachment declaration is unavailable")
                    actual = actual_pglite_items[0]
                    protection = actual.get("protection")
                    locator = actual.get("blob")
                    actual_sha = (protection.get("contentSha256") if isinstance(protection, dict) else None)
                    if actual_sha is None and isinstance(locator, dict):
                        actual_sha = locator.get("sha256")
                    declared = declared_pglite[0]
                    if (actual_sha != declared.get("sha256")
                            or any(actual.get(key) != declared.get(key) for key in _PGLITE_METADATA_FIELDS)):
                        raise StoreError("Studio App embedded attachment changed from its declaration")
                attachment_basis = app_attachments if actual_pglite else declarations
                from studio_app_bindings import validate_component_options, validate_embedded_attachment_refs
                embedded = validate_embedded_attachment_refs(app, records, attachment_basis)
                if embedded:
                    if not destination["store"].contract.studio_embedded_enabled:
                        raise StoreError("Studio App embedded snapshots are unavailable for this alias")
                    for record in records:
                        if record.get("kind") != "studio.component":
                            continue
                        options = record.get("content", {}).get("data", {}).get("definition", {}).get("options", {})
                        if isinstance(options, dict) and "embedded" in options:
                            validate_component_options(record,
                                embedded_schema=destination["store"].contract.studio_embedded_schema,
                                embedded_enabled=True)
                            view_kind = options["embedded"]["view"]["kind"]
                            if view_kind not in destination["store"].contract.studio_embedded_views:
                                raise StoreError("Studio App embedded view is unavailable for this alias")
            persisted = payload.get("requiresEmbedded")
            if ((persisted is None and embedded)
                    or persisted is not None and (type(persisted) is not bool or persisted != bool(embedded))):
                raise StoreError("Studio App embedded session classification is unavailable")
            return ["studio-embedded/v1"] if embedded else []
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise StoreError("Studio App embedded session is unavailable") from exc
        finally:
            destination["store"].close()

    @staticmethod
    def _classify_save_embedded_views(payload, embedded_formats):
        """Return retained, already-validated embedded view kinds for this session."""
        if not embedded_formats:
            return []
        plan = payload.get("plan")
        if not isinstance(plan, list):
            raise StoreError("Studio App embedded save plan is unavailable")
        kinds = set()
        for item in plan:
            record = item.get("record") if isinstance(item, dict) else None
            options = (record.get("content", {}).get("data", {}).get("definition", {}).get("options", {})
                       if isinstance(record, dict) else {})
            embedded = options.get("embedded") if isinstance(options, dict) else None
            if embedded is not None:
                view = embedded.get("view") if isinstance(embedded, dict) else None
                kind = view.get("kind") if isinstance(view, dict) else None
                if kind not in ("table", "kpi", "chart", "diagram"):
                    raise StoreError("Studio App embedded save plan has an unsupported view kind")
                kinds.add(kind)
        return [kind for kind in ("table", "kpi", "chart", "diagram") if kind in kinds]

    @staticmethod
    def _save_destination_matches(destination, payload):
        return (destination.get("authority") == payload.get("authority")
                and destination.get("binding") == payload.get("binding")
                and destination.get("native_actor") == payload.get("nativeActor")
                and destination.get("registration") == payload.get("registration"))

    @staticmethod
    def _save_status_fields(session_id, payload, embedded_formats, embedded_views):
        """Return continuation identity from the authenticated retained session only."""
        alias = payload.get("alias")
        if not isinstance(alias, str) or not alias:
            raise StoreError("Studio App save alias is unavailable")
        return {"session": session_id, "alias": alias, "embeddedFormats": embedded_formats,
                "embeddedViews": embedded_views}

    def _open_state(self, source, actor, app_id, *, include_data):
        """Return the exact readable native App graph pinned to one authority checkpoint."""
        from blob_store import encode as encode_blob
        from knowledge_policy import fingerprint
        from studio_app_attachments import validate_app_attachments, verify_app_attachment_bytes
        from studio_app_transfer import _collect

        at = self.clock()
        records = _collect(source["store"], app_id, source["native_actor"], at)
        snapshot = source["store"].read_snapshot(source["native_actor"], at=at, max_records=10_000,
                                                  max_body_bytes=16 * 1024 * 1024)
        revisions = snapshot.get("revisions", {})
        if any(revisions.get(item["record"]["id"]) != item["revision"] for item in records):
            raise StoreError("Studio App source changed while opening its committed graph")
        from studio_app_bindings import MAX_APP_BINDING_BYTES
        record_bytes = 0
        record_items = []
        for item in records:
            raw = encode(item["record"])
            record_bytes += len(raw)
            if record_bytes > MAX_APP_BINDING_BYTES:
                raise StoreError("Studio App open record bytes exceed their limit")
            record_items.append({"id": item["record"]["id"], "kind": item["record"]["kind"],
                "revision": item["revision"], "sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw), **({"data": encode_blob(raw)} if include_data else {})})
        app_item = next((item for item in records if item["record"]["kind"] == "studio.app"), None)
        if app_item is None:
            raise StoreError("Studio App source is unavailable")
        app = app_item["record"]
        from studio_app_bindings import validate_embedded_attachment_refs
        try:
            embedded = validate_embedded_attachment_refs(
                app, [item["record"] for item in records],
                app.get("content", {}).get("data", {}).get("attachments", []))
            if embedded:
                from studio_app_bindings import validate_component_options
                for item in records:
                    component = item["record"]
                    if component.get("kind") != "studio.component":
                        continue
                    options = component.get("content", {}).get("data", {}).get("definition", {}).get("options", {})
                    if isinstance(options, dict) and "embedded" in options:
                        validate_component_options(component,
                            embedded_schema=source["store"].contract.studio_embedded_schema,
                            embedded_enabled=source["store"].contract.studio_embedded_enabled)
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise StoreError("Studio App embedded snapshot reference is unavailable") from exc
        if embedded and not source["store"].contract.studio_embedded_enabled:
            raise StoreError("Studio App embedded snapshots are unavailable for this alias")
        attachment_bytes = validate_app_attachments(app)
        protected_app = (source.get("blob_protected")
                or source["attachment_protected"](app, source["native_actor"], at))
        if attachment_bytes and protected_app and source.get("protection") is None:
            raise StoreError("Protected Studio App attachments are unavailable for this host")
        attachment_items = []
        if attachment_bytes:
            contents = {}
            plaintexts = {}
            if include_data:
                attachments_by_key = {item["blob"]["key"]: item
                    for item in app["content"]["data"].get("attachments", [])}
                for locator in app.get("blobs", []):
                    raw = source["blob_reader"](locator)
                    if not isinstance(raw, bytes):
                        raise StoreError("Studio App attachment is unavailable")
                    contents[locator["key"]] = raw
                    attachment = attachments_by_key[locator["key"]]
                    if protected_app and attachment.get("protection") is None:
                        raise StoreError("Protected Studio App attachment lacks its authenticated byte envelope")
                    if attachment.get("protection") is not None:
                        plain = _open_attachment(raw, binding=source["binding"], record_id=app["id"],
                            attachment=attachment, protection=source.get("protection"))
                        if attachment.get("role") == "pglite-snapshot":
                            from studio_app_attachments import verify_pglite_snapshot_bytes
                            verify_pglite_snapshot_bytes(attachment, plain)
                        plaintexts[locator["key"]] = plain
                verify_app_attachment_bytes(app, contents)
                if plaintexts:
                    plain_record = json.loads(json.dumps(app))
                    plain_contents = {}
                    for attachment in plain_record["content"]["data"].get("attachments", []):
                        locator = attachment["blob"]
                        old_key = locator["key"]
                        plain = plaintexts.get(old_key, contents[old_key])
                        if old_key in plaintexts:
                            plain_locator = {**locator, "key": "sha256/" + hashlib.sha256(plain).hexdigest(),
                                "sha256": hashlib.sha256(plain).hexdigest(), "bytes": len(plain)}
                            attachment["blob"] = plain_locator
                            plain_record["blobs"] = [plain_locator if item["key"] == old_key else item
                                for item in plain_record["blobs"]]
                            locator = plain_locator
                        plain_contents[locator["key"]] = plain
                    verify_app_attachment_bytes(plain_record, plain_contents)
            locator_by_key = {locator["key"]: locator for locator in app["blobs"]}
            for index, attachment in enumerate(app["content"]["data"].get("attachments", [])):
                locator = attachment["blob"]
                raw = plaintexts.get(locator["key"], contents.get(locator["key"]))
                attachment_items.append({"id": str(index), "role": attachment["role"],
                    "format": attachment["format"], "locator": locator,
                    "sha256": attachment.get("protection", {}).get("contentSha256", locator["sha256"]),
                    "bytes": attachment.get("protection", {}).get("contentBytes", locator["bytes"]),
                    **{key: attachment[key] for key in _PGLITE_METADATA_FIELDS if key in attachment},
                    **({"protectedBytes": True} if attachment.get("protection") else {}),
                    **({"data": encode_blob(raw)} if include_data else {})})
            if include_data and set(contents) != set(locator_by_key):
                raise StoreError("Studio App attachment inventory changed")
        checkpoint = snapshot["checkpoint"]
        checkpoint_sha = hashlib.sha256(encode(checkpoint)).hexdigest()
        record_pins = [{key: item[key] for key in ("id", "kind", "revision", "sha256", "bytes")}
                       for item in record_items]
        attachment_pins = []
        for item in attachment_items:
            pin = {key: item[key] for key in ("id", "role", "format", "locator", "sha256", "bytes")}
            pin.update({key: item[key] for key in _PGLITE_METADATA_FIELDS if key in item})
            if item.get("protectedBytes"):
                pin["protectedBytes"] = True
            attachment_pins.append(pin)
        attachment_bytes = sum(item["bytes"] for item in attachment_items)
        package_sha = fingerprint({"format": "studio-app-open/v1", "app": app_id,
            "checkpoint": checkpoint, "records": record_pins, "attachments": attachment_pins})
        return {"checkpoint": checkpoint, "checkpointSha256": checkpoint_sha,
            "recordPins": record_pins, "records": record_items,
            "attachmentPins": attachment_pins, "attachments": attachment_items,
            "recordBytes": record_bytes, "attachmentBytes": attachment_bytes,
            "sha256": package_sha}

    def _open_package(self, source, actor, app_id):
        package = self._open_state(source, actor, app_id, include_data=True)
        if len(encode(package)) > 32 * 1024 * 1024:
            raise StoreError("Studio App open package exceeds its limit")
        return package

    def _open_current(self, actor, payload):
        """Recheck selected route, checkpoint, graph revisions, and read policy."""
        source = None
        try:
            if self.identity() != actor:
                return False
            source = self.resolve(actor, payload["alias"], "read")
            if (source["authority"] != payload["authority"] or source["binding"] != payload["binding"]
                    or source["native_actor"] != payload["nativeActor"]
                    or source["registration"] != payload["registration"]):
                return False
            if (payload.get("protectedContent") and source.get("protection") is None
                    or not payload.get("protectedContent")
                    and not source["attachment_staging_available"](source["native_actor"], self.clock())):
                return False
            current = self._open_state(source, actor, payload["appId"], include_data=False)
            return (current["checkpoint"] == payload["checkpoint"]
                    and current["recordPins"] == payload["recordPins"]
                    and current["attachmentPins"] == payload.get("attachmentPins")
                    and current["sha256"] == payload["packageSha256"]
                    and self.identity() == actor)
        except Exception:
            return False
        finally:
            if source is not None:
                source["store"].close()

    def _resolve_pair(self, actor, source_alias, destination_alias):
        source = self.resolve(actor, source_alias, "read")
        try:
            destination = self.resolve(actor, destination_alias, "propose")
        except Exception:
            source["store"].close()
            raise
        if source.get("native_actor") != destination.get("native_actor"):
            source["store"].close()
            destination["store"].close()
            raise StoreError("Studio App source and destination native actor mappings differ")
        try:
            self._require_adopted_native_scope(destination)
        except Exception:
            source["store"].close()
            destination["store"].close()
            raise
        return source, destination

    @staticmethod
    def _attachment_boundary(source, destination, app_record, at):
        if not app_record.get("blobs"):
            return False
        source_protected = (source["attachment_protected"](
            app_record, source["native_actor"], at) or source.get("blob_protected", False)
            or any(isinstance(item, dict) and item.get("protection") is not None
                   for item in app_record.get("content", {}).get("data", {}).get("attachments", [])))
        destination_record = {"collection": destination.get("attachment_collection")}
        destination_protected = (destination["attachment_protected"](
            destination_record, destination["native_actor"], at) or destination.get("blob_protected", False))
        if source_protected and source.get("protection") is None:
            raise StoreError("Protected source App attachments require the current byte provider")
        if source_protected and destination.get("protection") is None:
            raise StoreError("Protected source App attachments cannot be declassified by transfer")
        if destination_protected and destination.get("protection") is None:
            raise StoreError("Protected destination App attachments require the current byte provider")
        # A selected provider is used for final blob storage even when current
        # policy also permits plaintext, so package and persisted forms agree.
        return bool(destination_protected or destination.get("protection") is not None)

    def serve_stdio(self, stdin=None, stdout=None):
        stdin, stdout = stdin or sys.stdin.buffer, stdout or sys.stdout.buffer
        while True:
            line = stdin.readline(self.max_line_bytes + 1)
            if not line:
                return 0
            if len(line) > self.max_line_bytes:
                # Stop at the frame boundary; do not drain an unbounded hostile line.
                return 2
            try:
                message = json.loads(line)
                response = self.dispatch(message)
                if response is not None:
                    raw = encode(response)
                    if len(raw) > self.max_line_bytes:
                        return 2
                    stdout.write(raw.rstrip(b"\n") + b"\n")
                    stdout.flush()
            except Exception:
                # Never write diagnostics or exception data to the MCP stream.
                return 1
        return 0


class RegisteredHost:
    """Reload the private host registry and open only its declared local stores."""

    def __init__(self, root, relative, *, protection_provider=None, clock=_utcnow):
        self.root = Path(root).resolve()
        self.relative = relative
        # A trusted embedding application may supply the already-owned
        # ProtectionHost/profile/key callbacks. No MCP argument or environment
        # value can select or construct this provider.
        if protection_provider is not None and not callable(protection_provider):
            raise StoreError("Studio App protection provider is invalid")
        if not callable(clock):
            raise StoreError("Studio App host clock is invalid")
        self.protection_provider = protection_provider
        self.clock = clock

    def _host(self):
        from knowledge_operations import private_path
        path = private_path(self.root, self.relative)
        value = self._read_bounded_json(path, max_bytes=64 * 1024, private=True)
        from brain_storage_tree_worker import HostRegistrationError, validate_host_registration
        try:
            return validate_host_registration(value)
        except HostRegistrationError as exc:
            raise StoreError(str(exc)) from exc

    @staticmethod
    def _read_bounded_json(path, *, max_bytes, private):
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise StoreError("Studio App host file is unavailable") from exc
        try:
            before = os.fstat(fd)
            named = os.stat(path, follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                    or before.st_nlink != 1 or before.st_size > max_bytes
                    or (private and before.st_mode & 0o077)
                    or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)):
                raise StoreError("Studio App host file is unsafe or exceeds its limit")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(max_bytes + 1)
            after = os.fstat(fd)
            named_after = os.stat(path, follow_symlinks=False)
            if (len(raw) > max_bytes
                    or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    != (named_after.st_dev, named_after.st_ino, named_after.st_size,
                        named_after.st_mtime_ns, named_after.st_ctime_ns)):
                raise StoreError("Studio App host file changed during read")
        finally:
            os.close(fd)
        try:
            return json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise StoreError("Studio App host file is malformed") from exc

    @staticmethod
    def _reject_symlink_path(path):
        path = Path(path)
        if any(part.is_symlink() for part in (path, *path.parents)):
            raise StoreError("Studio App host stores cannot follow symlinks")
        return path

    def identity(self):
        token = os.environ.get("BRAIN_STUDIO_APPS_TOKEN", "")
        if not isinstance(token, str) or not 32 <= len(token) <= 512:
            raise StoreError("Studio App host identity is unavailable")
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        host = self._host()
        actor = next((value for key, value in host["principals"].items()
                      if hmac.compare_digest(key, digest)), None)
        if actor is None:
            raise StoreError("Studio App host identity is unavailable")
        return actor

    def _owner_app_install_target(self):
        """Open the currently adopted brain for a local OS-owner install operation.

        This is deliberately not part of StudioAppsMCP's JSON-RPC surface. App
        read/propose grants and bearer tokens cannot authorize installation.
        """
        from brain_storage_admission import _open_directory_chain, _selected_authority_path, load_registration
        from knowledge_store import SQLiteAuthority, adopted_authority, authority_class, resolve_store_dsn
        from knowledge_policy import fingerprint

        root = self.root.resolve(strict=True)
        root_fd = _open_directory_chain(root)
        try:
            root_info = os.fstat(root_fd)
            if (root_info.st_uid != os.geteuid()
                    or root_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)):
                raise StoreError("Studio App install requires the current OS owner of a safe brain root")
        finally:
            os.close(root_fd)
        config_path = self._reject_symlink_path(root / "client.config.json")
        config = self._read_bounded_json(config_path, max_bytes=1024 * 1024, private=False)
        selected = adopted_authority(config)
        uid = str(os.geteuid())
        authority = (config.get("brain") or {}).get("authority")
        principals = authority.get("principalsByUid") if isinstance(authority, dict) else None
        operators = authority.get("operatorUids") if isinstance(authority, dict) else None
        if (not isinstance(selected, dict) or not isinstance(principals, dict)
                or not isinstance(principals.get(uid), str) or not principals[uid]
                or not isinstance(operators, list) or uid not in operators):
            raise StoreError("Studio App install requires the registered native local operator")
        actor = principals[uid]
        dsn = resolve_store_dsn(config, selected["store"])
        path = Path(dsn)
        if not path.is_absolute():
            path = root / path
        path = self._reject_symlink_path(path)
        if authority_class(dsn) is not SQLiteAuthority:
            raise StoreError("Studio App install supports only the adopted local SQLite authority")
        store = SQLiteAuthority(path, expected_binding=selected["binding"], readonly=True)
        try:
            registration = load_registration(root, required=True)
            selected_path, selected_config = _selected_authority_path(root, store, registration)
            if (selected_path != path or fingerprint(selected_config) != fingerprint(config)
                    or registration["authority"]["store"] != selected["store"]
                    or registration["authority"]["binding"] != selected["binding"]):
                raise StoreError("Studio App install authority differs from the adopted brain")
            host = self._host()
            matching = []
            for alias, entry in host["aliases"].items():
                alias_root = Path(entry["root"])
                self._reject_symlink_path(alias_root)
                alias_authority = Path(entry["authority"])
                if not alias_authority.is_absolute():
                    alias_authority = root / alias_authority
                self._reject_symlink_path(alias_authority)
                if (alias_root.resolve(strict=True) == root
                        and alias_authority.resolve(strict=True) == selected_path
                        and entry["binding"] == store.contract.binding):
                    matching.append(alias)
            if len(matching) != 1:
                raise StoreError("Studio App install requires one unambiguous host alias for this brain")
            if self.protection_provider is None:
                raise StoreError("Studio App install is unavailable without the trusted host protection provider")
            return root, store, matching[0], actor, registration
        except BaseException:
            store.close()
            raise

    def owner_app_install_preview(self, source_root, app_id, source_commit):
        """Return a local-only exact-bundle preview for the current OS owner."""
        from brain_app_install import preview_app_install

        root, store, alias, actor, _registration = self._owner_app_install_target()
        try:
            return preview_app_install(root, source_root, app_id, source_commit, store,
                protection_provider=self.protection_provider, alias=alias, actor=actor)
        finally:
            store.close()

    def owner_app_install_apply(self, source_root, app_id, source_commit, preview_sha256):
        """Install only the exact previewed disabled draft; never enroll or activate it."""
        from brain_app_install import apply_app_install

        root, store, alias, actor, _registration = self._owner_app_install_target()
        try:
            return apply_app_install(root, source_root, app_id, source_commit, store,
                expected_preview_sha256=preview_sha256,
                protection_provider=self.protection_provider, alias=alias, actor=actor)
        finally:
            store.close()

    def storage_admission(self, actor, alias):
        """Read the current brain-wide logical admission state without creating state."""
        if not isinstance(actor, str) or not actor or not isinstance(alias, str):
            raise StoreError("Studio App admission is unavailable")
        if self.identity() != actor:
            raise StoreError("Studio App host identity changed")
        destination = self.resolve(actor, alias, "propose", capability_discovery=True)
        store = destination["store"]
        try:
            from brain_storage_admission import (AdmissionLedger, InventoryBudget,
                _selected_authority_path, fingerprint, inventory, load_registration)
            from brain_protection import assess, profile as validate_profile, requirements
            from knowledge_store import blob_store_for, adopted_authority, resolve_store_dsn

            host = self._host()
            entry = host["aliases"].get(alias)
            if entry is None or "propose" not in entry["grants"].get(actor, []):
                raise StoreError("Studio App admission is unavailable")
            root = Path(entry["root"]).resolve(strict=True)
            registration = load_registration(root)
            if registration is None:
                raise StoreError("Studio App admission registration is unavailable")
            _selected_authority_path(root, store, registration)
            if (registration["authority"]["store"] != store.contract.authority
                    or registration["authority"]["binding"] != store.contract.binding
                    or registration["blob"]["store"] != store.contract.blob_store
                    or registration["blob"]["driver"] != store.contract.cell["blobs"]):
                raise StoreError("Studio App admission route is unavailable")

            protection = destination.get("protection")
            if protection is None:
                raise StoreError("Studio App admission protection is unavailable")
            protection_host, raw_required, raw_selected, native_scope = protection
            required = requirements(raw_required)
            selected_profile = validate_profile(raw_selected)
            expected_scope = {"format": "studio-app-protection-scope/v1",
                              "nativeRecordBodies": False, "nativeHistory": False,
                              "nativeMetadata": False}
            if (selected_profile["mode"] != registration["protection"]["profile"]
                    or fingerprint(required) != registration["protection"]["requirementsSha256"]
                    or native_scope != expected_scope
                    or required["opaqueMetadata"] or not required["plaintextCopies"]
                    or not assess(required, selected_profile, offline=True, operation="retain")["supported"]):
                raise StoreError("Studio App admission protection registration differs")
            protection_host.available(selected_profile)
            if (not destination["attachment_staging_available"](
                    destination["native_actor"], self.clock())
                    and destination.get("protection") is None):
                raise StoreError("Studio App attachment staging is unavailable for protected scope")

            config_path = root / "client.config.json"
            config = self._read_bounded_json(config_path, max_bytes=1024 * 1024, private=False)
            selected = adopted_authority(config)
            if (not isinstance(selected, dict) or selected.get("binding") != store.contract.binding
                    or selected.get("store") != store.contract.authority):
                raise StoreError("Studio App admission authority is unavailable")
            blob_store = blob_store_for(root, config, store.contract)
            blob_root = None
            blob_location = None
            if registration["blob"]["driver"] == "fs":
                if blob_store is None or not hasattr(blob_store, "root"):
                    raise StoreError("Studio App admission blob route is unavailable")
                blob_root = self._reject_symlink_path(Path(blob_store.root)).resolve(strict=True)
            else:
                blob_location = store.path

            budget = InventoryBudget(deadline_seconds=8.0)
            ledger = AdmissionLedger(root, registration)
            registration_sha256 = fingerprint(registration)
            with ledger.readonly_snapshot(registration_sha256=registration_sha256,
                    timeout=8.0, budget=budget) as ledger_state:
                measured = inventory(root, store, registration, blob_root=blob_root,
                    blob_location=blob_location, budget=budget)
                limit_bytes = measured["limitBytes"]
                used_bytes = measured["usedBytes"]
                reserved_bytes = ledger_state["reservedBytes"]
                safe_integer = 2**53 - 1
                values = (limit_bytes, used_bytes, reserved_bytes)
                if any(type(value) is not int or not 0 <= value <= safe_integer for value in values):
                    raise StoreError("Studio App admission arithmetic is unavailable")
                if used_bytes + reserved_bytes > safe_integer:
                    raise StoreError("Studio App admission arithmetic is unavailable")
                remaining_bytes = max(0, limit_bytes - used_bytes - reserved_bytes)
                route = destination["registration"]["_route"]
                plaintext_staging = (not destination["blob_protected"]
                    and destination["attachment_staging_available"](destination["native_actor"], self.clock()))
                route_basis = fingerprint({"registrationSha256": registration_sha256,
                    "configSha256": route["configSha256"], "authorityDevice": route["authorityDevice"],
                    "authorityInode": route["authorityInode"], "blobDevice": route.get("blobDevice"),
                    "blobInode": route.get("blobInode"), "blobPathSha256": route.get("blobPathSha256")})
                result = {"format": "studio-app-storage-admission/v1",
                    "state": "ready" if remaining_bytes > 0 else "limit-reached",
                    "alias": alias,
                    "budget": {"scope": "registered-brain-logical-retained-content/v1",
                        "accounting": "logical-retained-content-bytes/v1", "limitBytes": limit_bytes,
                        "measuredBytes": used_bytes, "reservedBytes": reserved_bytes,
                        "remainingBytes": remaining_bytes, "inventoryBasisSha256": measured["basisSha256"]},
                    "writerCoverage": {"scope": "host-mediated-studio-app-sqlite-session-upload-save/v1",
                        "operations": ["apps.save.begin", "apps.save.attachment.begin",
                            "apps.save.attachment.chunk", "apps.save.attachment.finish",
                            "apps.save.advance", "apps.save.abort"]},
                    "attachmentStaging": ({"scope": "effectively-company-wide-readable/v1",
                        "plaintextPermitted": True} if plaintext_staging else {
                        "scope": "selected-provider-encrypted/v1", "plaintextPermitted": False}),
                    "protection": {"profileMode": selected_profile["mode"],
                        "requirementsSha256": registration["protection"]["requirementsSha256"],
                        "nativeScope": {key: native_scope[key] for key in (
                            "nativeRecordBodies", "nativeHistory", "nativeMetadata")}},
                    "aggregateCapacityAvailable": False,
                    "claimsNotMade": ["physical-disk-capacity", "whole-root-protection",
                                      "all-brain-writers-covered"],
                    "routeBasisSha256": route_basis,
                    "checkedAt": _utcnow()}
                compact_response(result)
                budget.check_time()

                # Re-derive identity, grants, route, registration and provider
                # immediately before releasing this point-in-time summary.
                if self.identity() != actor or self._host() != host:
                    raise StoreError("Studio App admission identity or grant changed")
                fresh_config = self._read_bounded_json(config_path, max_bytes=1024 * 1024, private=False)
                if fingerprint(fresh_config) != fingerprint(config):
                    raise StoreError("Studio App admission configuration changed")
                fresh_registration = load_registration(root)
                if (fresh_registration is None
                        or fingerprint(fresh_registration) != registration_sha256):
                    raise StoreError("Studio App admission registration changed")
                _selected_authority_path(root, store, fresh_registration)
                fresh_selected = adopted_authority(fresh_config)
                fresh_dsn = resolve_store_dsn(fresh_config, fresh_selected["store"])
                fresh_path = Path(fresh_dsn)
                if not fresh_path.is_absolute():
                    fresh_path = root / fresh_path
                fresh_path = self._reject_symlink_path(fresh_path)
                fresh_info = fresh_path.stat()
                if ((fresh_info.st_dev, fresh_info.st_ino)
                        != (route["authorityDevice"], route["authorityInode"])):
                    raise StoreError("Studio App admission authority changed")
                fresh_blob = blob_store_for(root, fresh_config, store.contract)
                if blob_root is not None:
                    if fresh_blob is None or not hasattr(fresh_blob, "root"):
                        raise StoreError("Studio App admission blob route changed")
                    fresh_blob_root = self._reject_symlink_path(Path(fresh_blob.root)).resolve(strict=True)
                    fresh_blob_info = fresh_blob_root.stat()
                    if ((fresh_blob_info.st_dev, fresh_blob_info.st_ino)
                            != (route.get("blobDevice"), route.get("blobInode"))
                            or hashlib.sha256(os.fsencode(fresh_blob_root)).hexdigest()
                            != route.get("blobPathSha256")):
                        raise StoreError("Studio App admission blob route changed")
                fresh_protection = self.protection_provider(root=root, alias=alias, actor=actor,
                    store=store, registration=destination["registration"])
                if (not isinstance(fresh_protection, tuple) or len(fresh_protection) != 4
                        or fresh_protection[0] is not protection_host
                        or fresh_protection[2] != raw_selected or fresh_protection[3] != native_scope
                        or fingerprint(requirements(fresh_protection[1]))
                        != registration["protection"]["requirementsSha256"]
                        or requirements(fresh_protection[1])["opaqueMetadata"]):
                    raise StoreError("Studio App admission protection changed")
                if not assess(requirements(fresh_protection[1]),
                        validate_profile(fresh_protection[2]), offline=True,
                        operation="retain")["supported"]:
                    raise StoreError("Studio App admission protection changed")
                fresh_protection[0].available(validate_profile(fresh_protection[2]))
                budget.check_time()
                return result
        finally:
            store.close()

    def aliases(self, actor):
        host = self._host()
        result = []
        for alias, entry in sorted(host["aliases"].items()):
            capabilities = sorted(entry["grants"].get(actor, []))
            if not capabilities:
                continue
            item = {"alias": alias, "capabilities": capabilities,
                    "attachments": "native-policy-checked"}
            selected = None
            try:
                selected = self.resolve(actor, alias, capabilities[0], capability_discovery=True)
                if selected["store"].contract.studio_embedded_enabled:
                    item["embeddedFormats"] = ["studio-embedded/v1"]
                    item["embeddedViews"] = list(selected["store"].contract.studio_embedded_views)
            except Exception:
                # Capability discovery does not turn a stale or unavailable alias
                # into an advertised host feature.
                pass
            finally:
                if selected is not None:
                    selected["store"].close()
            result.append(item)
        return result

    def _protection_for_selected(self, root, alias, actor, store, registration, selected_registration):
        """Refresh only the host provider against the already-owned native connection."""
        protection = None
        if self.protection_provider is not None:
            supplied = self.protection_provider(root=root, alias=alias, actor=actor,
                store=store, registration=registration)
            if supplied is not None:
                if not isinstance(supplied, tuple) or len(supplied) != 4:
                    raise StoreError("Studio App protection provider is unavailable")
                host_object, required, selected_profile, native_scope = supplied
                from brain_protection import ProtectionHost, profile, requirements
                if (not isinstance(host_object, ProtectionHost)
                        or requirements(required) != required
                        or profile(selected_profile) != selected_profile
                        or selected_profile["mode"] != "per-record"):
                    raise StoreError("Studio App protection provider is unavailable")
                protection = (host_object, required, selected_profile,
                              _validate_native_protection_scope(native_scope))
        _validate_registered_app_protection(selected_registration, protection)
        return protection

    def resolve(self, actor, alias, capability, *, capability_discovery=False):
        if type(capability_discovery) is not bool:
            raise StoreError("Studio App alias is unavailable")
        if not isinstance(alias, str):
            raise StoreError("Studio App alias is unavailable")
        host = self._host()
        entry = host["aliases"].get(alias)
        if entry is None or capability not in entry["grants"].get(actor, []):
            raise StoreError("Studio App alias is unavailable")
        root = Path(entry["root"]).resolve()
        self._reject_symlink_path(root)
        if not root.is_dir():
            raise StoreError("Studio App alias is unavailable")
        authority_path = Path(entry["authority"])
        if not authority_path.is_absolute():
            authority_path = root / authority_path
        self._reject_symlink_path(authority_path)
        if not authority_path.is_file():
            raise StoreError("Studio App alias is unavailable")
        from knowledge_store import SQLiteAuthority, blob_store_for
        config_path = self._reject_symlink_path(root / "client.config.json")
        config = self._read_bounded_json(config_path, max_bytes=1024 * 1024, private=False)
        from knowledge_store import adopted_authority, resolve_store_dsn
        selected = adopted_authority(config)
        if (not isinstance(selected, dict) or selected.get("binding") != entry["binding"]
                or not isinstance(selected.get("store"), str)):
            raise StoreError("Studio App alias differs from the currently selected native authority")
        selected_dsn = resolve_store_dsn(config, selected["store"])
        selected_path = Path(selected_dsn)
        if not selected_path.is_absolute():
            selected_path = root / selected_path
        self._reject_symlink_path(selected_path)
        if selected_path.resolve() != authority_path.resolve():
            raise StoreError("Studio App alias is not the selected native authority")
        try:
            authority_before = authority_path.stat()
        except OSError as exc:
            raise StoreError("Studio App alias is unavailable") from exc
        store = SQLiteAuthority(authority_path, expected_binding=entry["binding"],
                                readonly=capability_discovery)
        try:
            if not store.contract.studio_apps_enabled:
                raise StoreError("Studio App profile is not selected")
            blob_store = blob_store_for(root, config, store.contract)
            selected_registration = None
            authority_after = authority_path.stat()
            before_identity = (authority_before.st_dev, authority_before.st_ino, authority_before.st_size,
                               authority_before.st_mtime_ns, authority_before.st_ctime_ns)
            after_identity = (authority_after.st_dev, authority_after.st_ino, authority_after.st_size,
                              authority_after.st_mtime_ns, authority_after.st_ctime_ns)
            if before_identity != after_identity:
                raise StoreError("Studio App selected authority changed while opening")
            route = {"configSha256": hashlib.sha256(encode(config)).hexdigest(),
                     "authorityDevice": authority_after.st_dev, "authorityInode": authority_after.st_ino}
            if blob_store is not None:
                if not hasattr(blob_store, "root"):
                    raise StoreError("Studio App pilot requires a locally pinned filesystem or database blob route")
                configured_blob_root = Path(blob_store.root)
                self._reject_symlink_path(configured_blob_root)
                blob_root = configured_blob_root.resolve(strict=True)
                blob_stat = blob_root.stat()
                if not blob_root.is_dir():
                    raise StoreError("Studio App blob route is unavailable")
                route.update({"blobDevice": blob_stat.st_dev, "blobInode": blob_stat.st_ino,
                              "blobPathSha256": hashlib.sha256(os.fsencode(blob_root)).hexdigest()})
            registration = {**entry, "_route": route}
            if capability_discovery:
                # Capability listing must not enter the normal admission path:
                # configured_admission takes a writer transaction and can create
                # legacy lock files. Validate any existing adoption read-only.
                from brain_storage_admission import AdmissionLedger, _selected_authority_path, load_registration
                from knowledge_policy import fingerprint
                selected_registration = load_registration(root)
                if selected_registration is None:
                    admission = None
                else:
                    _selected_authority_path(root, store, selected_registration)
                    ledger = AdmissionLedger(root, selected_registration)
                    with ledger.readonly_snapshot(
                            registration_sha256=fingerprint(selected_registration)):
                        pass
                    admission = None
            else:
                from brain_storage_admission import configured_admission
                admission = configured_admission(root, store)
                if admission is not None:
                    selected_registration = admission[0].registration
            # Pin the current native policy/contract on this selected connection.
            # The bounded CASE prevents a constructor-to-capture replacement from
            # returning an oversized raw value after an earlier size observation.
            from knowledge_store import MAX_RESTORE_CELL_BYTES, encoded as encode_native
            bundle_shape = store.dialect.db.execute(
                "SELECT typeof(value),length(CAST(value AS BLOB)) FROM metadata WHERE key='bundle'"
            ).fetchone()
            if (bundle_shape is None or bundle_shape[0] != "text"
                    or type(bundle_shape[1]) is not int
                    or not 1 <= bundle_shape[1] <= MAX_RESTORE_CELL_BYTES):
                raise StoreError("Studio App selected native bundle is unavailable")
            bundle_row = store.dialect.db.execute(
                "SELECT CASE WHEN typeof(value)='text' AND length(CAST(value AS BLOB)) "
                "BETWEEN 1 AND ? THEN value ELSE NULL END FROM metadata WHERE key='bundle'",
                (MAX_RESTORE_CELL_BYTES,)).fetchone()
            if bundle_row is None or type(bundle_row[0]) is not str:
                raise StoreError("Studio App selected native bundle changed while opening")
            try:
                # Preserve existing valid native JSON formatting at open. Compare
                # canonical encodings, not Python equality (False != JSON zero).
                same_bundle = (encode_native(json.loads(bundle_row[0]))
                               == encode_native(store.contract.bundle))
            except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
                raise StoreError("Studio App selected native bundle is invalid") from exc
            if not same_bundle:
                raise StoreError("Studio App selected native bundle changed while opening")
            selected_bundle = bundle_row[0]
            selected_bundle_bytes = len(selected_bundle.encode("utf-8"))
            protection = self._protection_for_selected(
                root, alias, actor, store, registration, selected_registration)
        except Exception:
            store.close()
            raise

        def attachment_protected(record, native_actor, at):
            collection = store.contract.collections.get(record.get("collection"))
            if not collection or collection.get("kind") != "studio.app":
                return True
            resource = store.contract.policy.resources.get(collection.get("resource"))
            if not resource:
                return True
            scope_id = resource["scope"]
            return _attachment_scope_is_protected(store.contract.policy, scope_id, native_actor, at)

        app_collections = [(identity, definition) for identity, definition in store.contract.collections.items()
                           if definition.get("kind") == "studio.app"]

        def attachment_staging_available(native_actor, at):
            return (bool(app_collections) and not entry.get("blobProtected", False)
                    and all(not attachment_protected({"collection": identity}, native_actor, at)
                            for identity, _definition in app_collections))

        def blob_reader(locator):
            if store.contract.cell["blobs"] == "db-blob":
                if locator["store"] != store.contract.blob_store:
                    raise StoreError("Studio App blob alias mismatch")
                return store.dialect.blob(locator["key"])
            if blob_store is None:
                return None
            return blob_store.get(locator)

        writer = blob_store
        if store.contract.cell["blobs"] == "db-blob":
            from blob_store import DbBlobStore
            from brain_storage_admission import bind_host_blob_writer
            writer = bind_host_blob_writer(root, store.contract,
                DbBlobStore(store.contract.blob_store, store.dialect), authority=store)

        def blob_writer(locator, raw, *, _before_publish=None):
            if store.contract.cell["blobs"] == "db-blob" and _before_publish is not None:
                raise StoreError("Database blob guards require the owned native transaction boundary")
            if writer is None:
                raise StoreError("Studio App destination has no native blob writer")
            if locator["store"] != store.contract.blob_store:
                raise StoreError("Studio App blob alias mismatch")
            # The bound driver owns one charge/completion. Keep M75's explicit
            # staged-publication callback and selected native transaction seam.
            created = writer.put(locator["key"], raw, locator["mediaType"],
                                 _before_publish=_before_publish)
            if created != locator:
                raise StoreError("Studio App destination blob differs from its pin")

        def current_blob_protection():
            # Never open/close another native DB descriptor while its writer
            # fence/SQLite transaction is held. Reuse this exact selected store.
            if self.identity() != actor or self._host() != host:
                raise StoreError("Studio App blob identity or host grants changed")
            # Compare in SQLite, returning only type/length/boolean. No late raw
            # allocation and no loose Python bool/int JSON equality are involved.
            bundle_now = store.dialect.db.execute(
                "SELECT typeof(value),length(CAST(value AS BLOB)),value=? "
                "FROM metadata WHERE key='bundle'", (selected_bundle,)).fetchone()
            if bundle_now is None or tuple(bundle_now) != ("text", selected_bundle_bytes, 1):
                raise StoreError("Studio App selected native policy or contract changed")
            self._reject_symlink_path(root)
            self._reject_symlink_path(config_path)
            fresh_config = self._read_bounded_json(config_path, max_bytes=1024 * 1024, private=False)
            if hashlib.sha256(encode(fresh_config)).hexdigest() != route["configSha256"]:
                raise StoreError("Studio App blob source configuration changed")
            self._reject_symlink_path(authority_path)
            current_authority = authority_path.stat()
            if (current_authority.st_dev, current_authority.st_ino) != (
                    route["authorityDevice"], route["authorityInode"]):
                raise StoreError("Studio App blob selected authority changed")
            from brain_storage_admission import load_registration, _selected_authority_path
            from knowledge_policy import fingerprint
            current_registration = load_registration(root)
            if fingerprint(current_registration) != fingerprint(selected_registration):
                raise StoreError("Studio App blob adoption changed")
            if current_registration is not None:
                _selected_authority_path(root, store, current_registration)
            if blob_store is not None:
                self._reject_symlink_path(blob_store.root)
                current_root = Path(blob_store.root).resolve(strict=True)
                current_info = current_root.stat()
                if ((current_info.st_dev, current_info.st_ino) != (route["blobDevice"], route["blobInode"])
                        or hashlib.sha256(os.fsencode(current_root)).hexdigest() != route["blobPathSha256"]):
                    raise StoreError("Studio App blob directory changed")
            return self._protection_for_selected(
                root, alias, actor, store, registration, current_registration)

        def selected_save_guard(expected_authority, expected_binding, expected_native_actor,
                                expected_registration, *, requires_embedded=False):
            # This runs with the original SQLite write transaction/fence live.
            # Refresh host/config/registration/provider WITHOUT resolve/open/close.
            from knowledge_policy import fingerprint
            if (type(requires_embedded) is not bool or expected_authority != alias
                    or expected_binding != store.contract.binding
                    or expected_native_actor != entry["nativeActors"].get(actor)
                    or fingerprint(expected_registration) != fingerprint(registration)
                    or requires_embedded and not store.contract.studio_embedded_enabled):
                raise StoreError("Studio App selected save authority changed")
            current_blob_protection()
            return True

        def guarded_blob_writer(locator, raw, check_publication):
            if not callable(check_publication):
                raise StoreError("Studio App blob publication guard is unavailable")
            def check(staged):
                check_publication(staged, current_blob_protection())
            if store.contract.cell["blobs"] == "db-blob":
                # RegisteredHost selects SQLiteAuthority, not a remote transaction.
                if store.dialect.driver != "sqlite" or not store.dialect.db.in_transaction:
                    raise StoreError("Protected database blob requires its owned SQLite write transaction")
                check(raw)
                blob_writer(locator, raw)
                def before_native_commit():
                    shape = store.dialect.db.execute(
                        "SELECT typeof(content),length(content) FROM blob_objects WHERE blob_key=?",
                        (locator["key"],)).fetchone()
                    if shape is None or tuple(shape) != ("blob", locator["bytes"]):
                        raise StoreError("Staged native blob differs from its bounded pin")
                    check(store.dialect.blob(locator["key"]))
                return before_native_commit
            if blob_store is None or blob_store.driver != "fs":
                raise StoreError("Studio App blob route has no qualified publication boundary")
            blob_writer(locator, raw, _before_publish=check)
            # A later refusal cannot erase an already published FS blob. Its
            # retained bytes and unknown outcome remain the existing ledger's.
            return lambda: check(blob_reader(locator))

        if capability_discovery:
            try:
                # Recheck the host-owned identity, route and adoption basis after
                # profile/protection inspection, before returning a capability.
                if self.identity() != actor or self._host() != host:
                    raise StoreError("Studio App alias changed during capability discovery")
                fresh_config = self._read_bounded_json(config_path, max_bytes=1024 * 1024, private=False)
                if hashlib.sha256(encode(fresh_config)).hexdigest() != route["configSha256"]:
                    raise StoreError("Studio App selected authority configuration changed during discovery")
                fresh_selected = adopted_authority(fresh_config)
                if (not isinstance(fresh_selected, dict) or fresh_selected.get("binding") != entry["binding"]
                        or fresh_selected.get("store") != selected["store"]):
                    raise StoreError("Studio App selected authority changed during discovery")
                fresh_dsn = resolve_store_dsn(fresh_config, fresh_selected["store"])
                fresh_path = Path(fresh_dsn)
                if not fresh_path.is_absolute():
                    fresh_path = root / fresh_path
                self._reject_symlink_path(fresh_path)
                fresh_info = fresh_path.stat()
                if ((fresh_info.st_dev, fresh_info.st_ino)
                        != (route["authorityDevice"], route["authorityInode"])):
                    raise StoreError("Studio App selected authority changed during discovery")
                fresh_registration = load_registration(root)
                if fingerprint(fresh_registration) != fingerprint(selected_registration):
                    raise StoreError("Studio App storage registration changed during discovery")
                if fresh_registration is not None:
                    _selected_authority_path(root, store, fresh_registration)
                if blob_store is not None:
                    fresh_blob_root = self._reject_symlink_path(Path(blob_store.root)).resolve(strict=True)
                    fresh_blob_info = fresh_blob_root.stat()
                    if ((fresh_blob_info.st_dev, fresh_blob_info.st_ino)
                            != (route.get("blobDevice"), route.get("blobInode"))
                            or hashlib.sha256(os.fsencode(fresh_blob_root)).hexdigest()
                            != route.get("blobPathSha256")):
                        raise StoreError("Studio App blob route changed during discovery")
            except Exception:
                store.close()
                raise

        return {"alias": alias, "authority": alias, "binding": store.contract.binding,
                "store": store, "blob_reader": blob_reader, "blob_writer": blob_writer,
                "guarded_blob_writer": guarded_blob_writer,
                "selected_save_guard": selected_save_guard,
                "session_publication_protection": current_blob_protection,
                "attachment_protected": attachment_protected,
                "attachment_staging_available": attachment_staging_available,
                "attachment_collection": app_collections[0][0] if len(app_collections) == 1 else None,
                "blob_protected": entry.get("blobProtected", False),
                "protection": protection,
                "native_protection_scope": protection[3] if protection is not None else None,
                "admission": admission,
                "native_actor": entry["nativeActors"][actor],
                "registration": registration}

    def guard(self, actor, source, destination, source_authority, destination_authority,
              source_binding, destination_binding):
        current_source = current_destination = None
        try:
            if self.identity() != actor:
                return False
            current_source, current_destination = self._resolve_pair(actor, source["alias"], destination["alias"])
            return (current_source["authority"] == source_authority == source["authority"]
                    and current_destination["authority"] == destination_authority == destination["authority"]
                    and current_source["binding"] == source_binding
                    and current_destination["binding"] == destination_binding
                    and current_source["native_actor"] == current_destination["native_actor"]
                    and current_source["native_actor"] == source.get("native_actor")
                    and current_destination["native_actor"] == destination.get("native_actor")
                    and current_source["registration"] == source["registration"]
                    and current_destination["registration"] == destination["registration"]
                    and self.identity() == actor)
        except Exception:
            return False
        finally:
            if current_source is not None:
                current_source["store"].close()
            if current_destination is not None:
                current_destination["store"].close()


def create_application(*, protection_provider=None):
    """Factory for an authenticated local stdio MCP child; HTTP is not exposed."""
    root = os.environ.get("BRAIN_ROOT")
    if not root:
        raise ValueError("BRAIN_ROOT must name the host brain root")
    host_path = os.environ.get("BRAIN_STUDIO_APPS_HOST", "_internal/studio-apps-host.json")
    host = RegisteredHost(root, host_path, protection_provider=protection_provider)
    host._host()  # fail at startup on an unsafe or malformed registration
    from studio_app_sessions import SessionStore
    sessions = SessionStore.for_host(root)
    return StudioAppsMCP(identity=host.identity, aliases=host.aliases, resolve=host.resolve,
                         storage_admission=host.storage_admission,
                         sessions=sessions, clock=_utcnow)


if __name__ == "__main__":
    raise SystemExit(create_application().serve_stdio())
