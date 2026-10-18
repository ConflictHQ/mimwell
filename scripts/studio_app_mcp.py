"""Bounded stdio MCP surface for host-authorized Studio App transfers.

The host injects identity and alias resolution; neither is a tool argument.
This module deliberately has no HTTP route. Native review and commit remain
the authority's existing independent operations.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

from context_bundle import encode
from sql_dialect import StoreError
from studio_app_sessions import MAX_FRAME_BYTES, SessionStore, compact_response

SERVER_NAME = "mimwell-studio-apps"
PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26")
TOOLS = {
    "apps.aliases": {"description": "List only host-registered Studio App source and destination aliases available to this authenticated principal.",
        "inputSchema": {"type": "object", "additionalProperties": False}},
    "apps.open.begin": {"description": "Pin a committed, currently readable App graph for bounded read-only Studio rendering.",
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
    "apps.save.begin": {"description": "Create a bounded, host-scoped Studio App draft session. No native record is written until advance creates a pending proposal.",
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["alias", "reason"],
            "properties": {"alias": {"type": "string", "minLength": 1, "maxLength": 64},
                          "record": {"type": "object"},
                          "records": {"type": "array", "minItems": 1, "maxItems": 32, "items": {"type": "object"}},
                          "attachments": {"type": "array", "maxItems": 8, "items": {"type": "object",
                              "additionalProperties": False, "required": ["id", "size", "sha256", "role", "format", "mediaType"],
                              "properties": {"id": {"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,31}$"},
                                  "size": {"type": "integer", "minimum": 1, "maximum": 16777216},
                                  "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                                  "role": {"type": "string", "enum": ["sql-fallback", "csv-fallback"]},
                                  "format": {"type": "string", "enum": ["sql", "csv"]},
                                  "mediaType": {"type": "string", "enum": ["application/sql", "text/plain", "text/csv"]}}}},
                          "reason": {"type": "string", "minLength": 1, "maxLength": 512},
                          "evidence": {"type": "array", "maxItems": 8, "items": {"type": "string", "minLength": 1, "maxLength": 512}}}}},
    "apps.save.attachment.begin": {"description": "Declare one bounded attachment upload for an active App save session.",
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["session", "id", "size", "sha256", "role", "format", "mediaType"],
            "properties": {"session": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "id": {"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,31}$"},
                "size": {"type": "integer", "minimum": 1, "maximum": 16777216},
                "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "role": {"type": "string", "enum": ["sql-fallback", "csv-fallback"]},
                "format": {"type": "string", "enum": ["sql", "csv"]},
                "mediaType": {"type": "string", "enum": ["application/sql", "text/plain", "text/csv"]}}}},
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
    "apps.save.status": {"description": "Inspect the bounded status of a Studio App save session and its native proposal.",
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["session"],
            "properties": {"session": {"type": "string", "pattern": "^[0-9a-f]{64}$"}}}},
    "apps.save.abort": {"description": "Stop further draft-session writes. Any native proposal already created remains pending for the existing native review workflow.",
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["session"],
            "properties": {"session": {"type": "string", "pattern": "^[0-9a-f]{64}$"}}}},
    "apps.transfer.begin": {"description": "Pin a reviewed App graph from a registered source alias to a registered destination alias. Returns an opaque bounded session handle; stages no approval or commit.",
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


class StudioAppsMCP:
    """Identity/alias callbacks are host-owned and re-evaluated on every call.

    `identity()` returns the transport-authenticated principal. `resolve(actor,
    alias, capability)` returns a trusted mapping with an open authority,
    authority identity, blob callbacks, protection selection and current
    registration revalidation callback. Request arguments contain no actor,
    path, DSN, resource, collection, protection or blob locator.
    """

    def __init__(self, *, identity, aliases, resolve, sessions: SessionStore,
                 clock, max_line_bytes=MAX_FRAME_BYTES):
        if not all(callable(value) for value in (identity, aliases, resolve, clock)):
            raise ValueError("Studio App MCP requires trusted host callbacks")
        if type(max_line_bytes) is not int or not 1 <= max_line_bytes <= MAX_FRAME_BYTES:
            raise ValueError("Studio App MCP frame limit is invalid")
        self.identity, self.aliases, self.resolve = identity, aliases, resolve
        self.sessions, self.clock = sessions, clock
        self.max_line_bytes = max_line_bytes

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
                {"name": name, **spec, "annotations": {"readOnlyHint": name in ("apps.aliases", "apps.open.begin", "apps.open.read", "apps.open.status", "apps.save.status", "apps.transfer.status"),
                    "destructiveHint": False, "idempotentHint": name in ("apps.aliases", "apps.open.status", "apps.open.abort", "apps.save.status", "apps.transfer.status", "apps.transfer.abort"),
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
        if name == "apps.open.begin":
            if set(arguments) != {"alias", "appId"}:
                raise StoreError("Studio App open arguments are invalid")
            source = self.resolve(actor, arguments["alias"], "read")
            try:
                package = self._open_package(source, actor, arguments["appId"])
                preview = {"session": "0" * 64, "state": "ready", "packageSha256": package["sha256"],
                    "checkpointSha256": package["checkpointSha256"], "records": len(package["records"]),
                    "attachments": len(package["attachments"]), "attachmentBytes": package["attachmentBytes"],
                    "recordBytes": package["recordBytes"], "complete": False}
                compact_response(preview)
                handle = self.sessions.create(actor, {"mode": "open", "alias": source["alias"],
                    "authority": source["authority"], "binding": source["binding"],
                    "nativeActor": source["native_actor"], "registration": source["registration"],
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
                if (not isinstance(declarations, list) or len(declarations) > 8
                        or declarations and attachment_record is None
                        or declarations and attachment_index != len(plan) - 1
                        or sum(item.get("size", 0) for item in declarations if isinstance(item, dict))
                            > 16 * 1024 * 1024):
                    raise StoreError("Studio App attachment declarations are invalid")
                if declarations and (destination.get("blob_protected")
                        or destination["attachment_protected"](attachment_record, destination["native_actor"], self.clock())):
                    raise StoreError("Protected destination App attachments are unavailable")
                seen_uploads = set()
                for declaration in declarations:
                    if (not isinstance(declaration, dict)
                            or set(declaration) != {"id", "size", "sha256", "role", "format", "mediaType"}
                            or not isinstance(declaration.get("id"), str)
                            or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", declaration["id"])
                            or declaration["id"] in seen_uploads
                            or type(declaration.get("size")) is not int or not 1 <= declaration["size"] <= 16 * 1024 * 1024
                            or not isinstance(declaration.get("sha256"), str)
                            or not re.fullmatch(r"[0-9a-f]{64}", declaration["sha256"])):
                        raise StoreError("Studio App attachment declarations are invalid")
                    formats = {"sql-fallback": {"format": "sql", "media": {"application/sql", "text/plain"}},
                               "csv-fallback": {"format": "csv", "media": {"text/csv"}}}
                    expected = formats.get(declaration["role"])
                    if (not expected or declaration["format"] != expected["format"]
                            or declaration["mediaType"] not in expected["media"]):
                        raise StoreError("Studio App attachment role or media type is unsupported")
                    seen_uploads.add(declaration["id"])
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
                    "last": {"state": "ready", "record": record["id"],
                             "recordSha256": fingerprint(record)}})
                if not self._save_guard(actor, alias, destination["authority"], destination["binding"],
                                        destination["native_actor"], destination["registration"]):
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
            if set(arguments) != required:
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
            def upload_guard(current_session):
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
                        return (self._save_destination_matches(current_destination, live_payload)
                                and target_record is not None and target_record.get("kind") == "studio.app"
                                and not current_destination.get("blob_protected")
                                and not current_destination["attachment_protected"](
                                    target_record, live_payload["nativeActor"], self.clock())
                                and self._save_guard(actor, live_payload["alias"], live_payload["authority"],
                                    live_payload["binding"], live_payload["nativeActor"], live_payload["registration"]))
                    finally:
                        current_destination["store"].close()
                except Exception:
                    return False
            if name.endswith(".begin"):
                for key in ("size", "sha256", "role", "format", "mediaType"):
                    if arguments[key] != declaration[key]:
                        raise StoreError("Studio App attachment upload differs from its declaration")
                self.sessions.begin_upload(session_id, actor, attachment_id,
                    size=declaration["size"], sha256=declaration["sha256"],
                    guard=upload_guard, identity_check=self.identity)
                latest = self.sessions.get(session_id, actor)
                if self.identity() != actor or not upload_guard(latest):
                    self.sessions.abort(session_id, actor)
                    raise StoreError("Studio App attachment authorization changed before response release")
                return {"session": session_id, "attachment": attachment_id, "nextChunk": 0,
                        "maxChunkBytes": 32 * 1024}
            if name.endswith(".chunk"):
                accepted = self.sessions.write_chunk(session_id, actor, attachment_id,
                    index=arguments["index"], data=arguments["data"],
                    guard=upload_guard, identity_check=self.identity)
                latest = self.sessions.get(session_id, actor)
                if self.identity() != actor or not upload_guard(latest):
                    self.sessions.abort(session_id, actor)
                    raise StoreError("Studio App attachment authorization changed before response release")
                return {"session": session_id, **accepted}

            # Completion first verifies the full upload pin. The blob effect is
            # then protected by a durable unknown-outcome intent, current host
            # registration checks and the selected native writer transaction.
            _, raw = self.sessions.finish_upload(session_id, actor, attachment_id,
                guard=upload_guard, identity_check=self.identity)
            destination = self.resolve(actor, payload["alias"], "propose")
            try:
                attachment_index = payload.get("attachmentRecordIndex")
                plan = payload.get("plan", [])
                if (type(attachment_index) is not int or not 0 <= attachment_index < len(plan)):
                    raise StoreError("Studio App attachment target is unavailable")
                record = plan[attachment_index]["record"]
                if (record.get("kind") != "studio.app" or not self._save_destination_matches(destination, payload)
                        or not self._save_guard(actor, payload["alias"], payload["authority"],
                            payload["binding"], payload["nativeActor"], payload["registration"])):
                    raise StoreError("Studio App attachment destination is unavailable")
                store = destination["store"]
                if (destination.get("blob_protected")
                        or destination["attachment_protected"](record, destination["native_actor"], self.clock())):
                    raise StoreError("Protected destination App attachments are unavailable")
                if not store.contract.blob_store:
                    raise StoreError("Studio App destination has no content-addressed blob store")
                from blob_store import locator
                expected_locator = locator(store.contract.blob_store,
                    "sha256/" + declaration["sha256"], raw, declaration["mediaType"])
                if expected_locator["sha256"] != declaration["sha256"]:
                    raise StoreError("Studio App attachment digest changed")
                if expected_locator in record.get("blobs", []):
                    existing = destination["blob_reader"](expected_locator)
                    latest = self.sessions.get(session_id, actor)
                    if existing != raw or self.identity() != actor or not upload_guard(latest):
                        raise StoreError("Studio App attachment replay could not be verified")
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
                        if (not self._save_guard(actor, live["alias"], live["authority"], live["binding"],
                                live["nativeActor"], live["registration"])
                                or not self._save_destination_matches(current_destination, live)
                                or current_destination.get("blob_protected")
                        or current_destination["attachment_protected"](
                                    live_plan[live_index]["record"], live["nativeActor"], self.clock())):
                            raise StoreError("Studio App attachment authorization changed")
                        updated = json.loads(json.dumps(live_plan[live_index]["record"]))
                        updated.setdefault("blobs", []).append(expected_locator)
                        data = updated["content"].setdefault("data", {})
                        data.setdefault("attachments", []).append({"role": declaration["role"],
                            "format": declaration["format"], "blob": expected_locator,
                            "capturedAt": self.clock(),
                            "source": {"id": "studio-save:" + updated["id"],
                                       "revision": "sha256:" + declaration["sha256"]}})
                        current_destination["store"].contract.validate_record(updated)
                        from studio_app_transfer import fingerprint
                        digest = fingerprint(updated)
                        with current_destination["store"].request_transaction(write=True):
                            if not self._save_guard(actor, live["alias"], live["authority"], live["binding"],
                                    live["nativeActor"], live["registration"]):
                                raise StoreError("Studio App attachment authorization changed before write")
                            current_destination["blob_writer"](expected_locator, raw)
                            if not self._save_guard(actor, live["alias"], live["authority"], live["binding"],
                                    live["nativeActor"], live["registration"]):
                                raise StoreError("Studio App attachment authorization changed during write")
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
            if payload.get("effectIntent"):
                return self._call("apps.save.status", arguments)
            if payload.get("last", {}).get("proposal"):
                observed = self._call("apps.save.status", arguments)
                if not observed.get("stageCommitted") or observed.get("complete"):
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
                    if (not self._save_destination_matches(destination, live)
                            or not self._save_guard(actor, live["alias"], live["authority"], live["binding"],
                                            live["nativeActor"], live["registration"])):
                        raise StoreError("Studio App save authority changed")
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
                                                live["nativeActor"], live["registration"])):
                            raise StoreError("Studio App save authority changed before native write")
                        if destination["store"]._record_metadata(live["record"]["id"]) is not None:
                            raise StoreError("Studio App create identity already exists or is tombstoned")
                        proposed = destination["store"].propose(live["request"], live["record"],
                            destination["native_actor"], at=self.clock())
                        if (not self._save_destination_matches(destination, live)
                                or not self._save_guard(actor, live["alias"], live["authority"], live["binding"],
                                                live["nativeActor"], live["registration"])):
                            raise StoreError("Studio App save authorization changed during native write")
                    summary = {"state": "awaiting-native-review", "record": live["record"]["id"],
                               "recordSha256": live["recordSha256"], "proposal": proposed["proposal"],
                               "stageIndex": live.get("stageIndex", 0), "stages": len(live.get("plan", [None])),
                               "stageCommitted": False, "revision": None, "complete": False}
                    response = {"session": arguments["session"], **summary}
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
                                    payload["nativeActor"], payload["registration"]):
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
                return self.sessions.abort(arguments["session"], actor)
            if payload.get("effectIntent"):
                if not self._save_guard(actor, payload["alias"], payload["authority"], payload["binding"],
                                        payload["nativeActor"], payload["registration"]):
                    raise StoreError("Studio App save registration changed during status inspection")
                latest = self.sessions.get(arguments["session"], actor)
                if latest.get("payload") != payload or self.identity() != actor:
                    raise StoreError("Studio App save session changed during status inspection")
                return {"session": arguments["session"], "state": "outcome-unknown",
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
                response = {"session": arguments["session"], "state": state,
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
                                    payload["nativeActor"], payload["registration"]):
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
                    destination_blob_protected=destination_blob_protected, clock=self.clock,
                    identity_guard=lambda who, src, dst, sb, db: self._guard(actor, source, destination, src, dst, sb, db, native_actor=who))
                receipt = new_receipt(package)
                destination_app_id = receipt["records"][arguments["appId"]]["destinationId"]
                preview = {"session": "0" * 64, "packageSha256": package["sha256"],
                           "records": len(package["records"]), "attachments": len(package["attachments"]),
                           "destinationAppId": destination_app_id, "next": "apps.transfer.advance"}
                compact_response(preview)
                handle = self.sessions.create(actor, {"mode": "transfer", "source": source["alias"],
                    "destination": destination["alias"], "appId": arguments["appId"], "package": package,
                    "receipt": receipt, "last": {"state": "ready"}})
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
                    intent = payload.get("effectIntent")
                    if isinstance(intent, dict) and intent.get("state") == "outcome-unknown":
                        from studio_app_transfer import prepare_package
                        app_record = next(item["record"] for item in payload["package"]["records"]
                                          if item["record"]["kind"] == "studio.app")
                        destination_blob_protected = self._attachment_boundary(
                            source, destination, app_record, self.clock())
                        current_package = prepare_package(source["store"], destination["store"],
                            payload["appId"], source["native_actor"], source_authority=source["authority"],
                            destination_authority=destination["authority"], blob_reader=source["blob_reader"],
                            protection=destination["protection"],
                            destination_blob_protected=destination_blob_protected, clock=self.clock,
                            identity_guard=lambda who, src, dst, sb, db: self._guard(
                                actor, source, destination, src, dst, sb, db, native_actor=who))
                        if current_package["sha256"] != payload["package"].get("sha256"):
                            raise StoreError("Studio App transfer is unavailable")
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
                                protection=destination["protection"], blob_writer=destination["blob_writer"],
                                destination_blob_protected=destination_blob_protected, clock=self.clock,
                                identity_guard=lambda who, src, dst, sb, db: self._guard(
                                    actor, source, destination, src, dst, sb, db, native_actor=who),
                                before_effect=lambda *_: (_ for _ in ()).throw(WouldPropose()))
                            response = {"session": arguments["session"], "state": value["status"],
                                "phase": value.get("phase"), "proposal": value.get("proposal"),
                                "complete": value["status"] == "complete"}
                        except WouldPropose:
                            response = {"session": arguments["session"], "state": "ready-for-native-proposal",
                                        "complete": False}
                    if not self._guard(actor, source, destination, source["authority"],
                                       destination["authority"], source["binding"], destination["binding"],
                                       native_actor=source["native_actor"]):
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
                                   native_actor=source["native_actor"]):
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
                    from studio_app_transfer import advance
                    app_record = next(item["record"] for item in live["package"]["records"]
                                      if item["record"]["kind"] == "studio.app")
                    destination_blob_protected = self._attachment_boundary(
                        source, destination, app_record, self.clock())
                    value = advance(source["store"], destination["store"], live["package"], live["receipt"], source["native_actor"],
                        source_authority=source["authority"], destination_authority=destination["authority"],
                        blob_reader=source["blob_reader"], protection=destination["protection"],
                        blob_writer=destination["blob_writer"], destination_blob_protected=destination_blob_protected,
                        clock=self.clock, identity_guard=lambda who, src, dst, sb, db: self._guard(
                            actor, source, destination, src, dst, sb, db, native_actor=who),
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
                    native_actor=source_check["native_actor"]):
                    raise StoreError("Studio App transfer authorization changed before response release")
            finally:
                source_check["store"].close()
                destination_check["store"].close()
            return result["response"]
        raise StoreError("Studio App tool is unavailable")

    def _guard(self, actor, source, destination, source_authority, destination_authority,
               source_binding, destination_binding, native_actor=None):
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
                    and current_destination["registration"] == destination["registration"])
        finally:
            current_source["store"].close()
            current_destination["store"].close()

    def _save_guard(self, actor, alias, authority, binding, native_actor, registration):
        if self.identity() != actor:
            return False
        try:
            current = self.resolve(actor, alias, "propose")
        except Exception:
            return False
        try:
            return (current["authority"] == authority and current["binding"] == binding
                    and current["native_actor"] == native_actor
                    and current["registration"] == registration and self.identity() == actor)
        finally:
            current["store"].close()

    @staticmethod
    def _save_destination_matches(destination, payload):
        return (destination.get("authority") == payload.get("authority")
                and destination.get("binding") == payload.get("binding")
                and destination.get("native_actor") == payload.get("nativeActor")
                and destination.get("registration") == payload.get("registration"))

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
        attachment_bytes = validate_app_attachments(app)
        if attachment_bytes and (source.get("blob_protected")
                or source["attachment_protected"](app, source["native_actor"], at)):
            raise StoreError("Protected Studio App attachments are unavailable for Studio open")
        attachment_items = []
        if attachment_bytes:
            contents = {}
            if include_data:
                for locator in app.get("blobs", []):
                    raw = source["blob_reader"](locator)
                    if not isinstance(raw, bytes):
                        raise StoreError("Studio App attachment is unavailable")
                    contents[locator["key"]] = raw
                verify_app_attachment_bytes(app, contents)
            locator_by_key = {locator["key"]: locator for locator in app["blobs"]}
            for index, attachment in enumerate(app["content"]["data"].get("attachments", [])):
                locator = attachment["blob"]
                raw = contents.get(locator["key"])
                attachment_items.append({"id": str(index), "role": attachment["role"],
                    "format": attachment["format"], "locator": locator,
                    "sha256": locator["sha256"], "bytes": locator["bytes"],
                    **({"data": encode_blob(raw)} if include_data else {})})
            if include_data and set(contents) != set(locator_by_key):
                raise StoreError("Studio App attachment inventory changed")
        checkpoint = snapshot["checkpoint"]
        checkpoint_sha = hashlib.sha256(encode(checkpoint)).hexdigest()
        record_pins = [{key: item[key] for key in ("id", "kind", "revision", "sha256", "bytes")}
                       for item in record_items]
        attachment_pins = [{key: item[key] for key in ("id", "role", "format", "locator", "sha256", "bytes")}
                           for item in attachment_items]
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
        return source, destination

    @staticmethod
    def _attachment_boundary(source, destination, app_record, at):
        if not app_record.get("blobs"):
            return False
        source_protected = (source["attachment_protected"](
            app_record, source["native_actor"], at) or source.get("blob_protected", False))
        destination_record = {"collection": destination.get("attachment_collection")}
        destination_protected = (destination["attachment_protected"](
            destination_record, destination["native_actor"], at) or destination.get("blob_protected", False))
        if source_protected:
            raise StoreError("Protected source App attachments are unavailable for portable transfer")
        return bool(destination_protected)

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

    def __init__(self, root, relative):
        self.root = Path(root).resolve()
        self.relative = relative

    def _host(self):
        from knowledge_operations import private_path
        path = private_path(self.root, self.relative)
        value = self._read_bounded_json(path, max_bytes=64 * 1024, private=True)
        if (not isinstance(value, dict) or set(value) != {"format", "principals", "aliases"}
                or value.get("format") != "studio-app-mcp-host/v1"
                or not isinstance(value["principals"], dict) or not isinstance(value["aliases"], dict)
                or not 1 <= len(value["aliases"]) <= 64 or len(value["principals"]) > 256):
            raise StoreError("Studio App host registration is invalid")
        for digest, actor in value["principals"].items():
            if (not isinstance(digest, str) or len(digest) != 64
                    or any(char not in "0123456789abcdef" for char in digest)
                    or not isinstance(actor, str) or not actor.strip() or len(actor) > 256):
                raise StoreError("Studio App host principal registration is invalid")
        for alias, entry in value["aliases"].items():
            if (not isinstance(alias, str) or not alias.isidentifier() or len(alias) > 64
                    or not isinstance(entry, dict)
                    or set(entry) - {"root", "authority", "binding", "grants", "nativeActors", "blobProtected"}
                    or not {"root", "authority", "binding", "grants", "nativeActors"}.issubset(entry)
                    or not isinstance(entry["root"], str) or not Path(entry["root"]).is_absolute()
                    or not isinstance(entry["authority"], str)
                    or not isinstance(entry["binding"], str) or len(entry["binding"]) != 64
                    or not isinstance(entry["grants"], dict) or not isinstance(entry["nativeActors"], dict)
                    or "blobProtected" in entry and type(entry["blobProtected"]) is not bool):
                raise StoreError("Studio App host alias registration is invalid")
            for actor, grants in entry["grants"].items():
                native_actor = entry["nativeActors"].get(actor)
                if (actor not in value["principals"].values() or not isinstance(native_actor, str)
                        or not native_actor.strip() or len(native_actor) > 256 or not isinstance(grants, list)
                        or len(grants) != len(set(grants))
                        or any(grant not in ("read", "propose") for grant in grants)):
                    raise StoreError("Studio App host alias grant is invalid")
            if set(entry["nativeActors"]) != set(entry["grants"]):
                raise StoreError("Studio App native actor mappings must match explicit alias grants")
        return value

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

    def aliases(self, actor):
        host = self._host()
        return [{"alias": alias, "capabilities": sorted(entry["grants"].get(actor, [])),
                 "attachments": "native-policy-checked"}
                for alias, entry in sorted(host["aliases"].items()) if entry["grants"].get(actor)]

    def resolve(self, actor, alias, capability):
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
        store = SQLiteAuthority(authority_path, expected_binding=entry["binding"])
        try:
            if not store.contract.studio_apps_enabled:
                raise StoreError("Studio App profile is not selected")
            blob_store = blob_store_for(root, config, store.contract)
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

        def blob_reader(locator):
            if store.contract.cell["blobs"] == "db-blob":
                if locator["store"] != store.contract.blob_store:
                    raise StoreError("Studio App blob alias mismatch")
                return store.dialect.blob(locator["key"])
            if blob_store is None:
                return None
            return blob_store.get(locator)

        def blob_writer(locator, raw):
            if store.contract.cell["blobs"] == "db-blob":
                if locator["store"] != store.contract.blob_store:
                    raise StoreError("Studio App blob alias mismatch")
                store.dialect.add_blob(locator["key"], raw)
            elif blob_store is not None:
                created = blob_store.put(locator["key"], raw, locator["mediaType"])
                if created != locator:
                    raise StoreError("Studio App destination blob differs from its pin")
            else:
                raise StoreError("Studio App destination has no native blob writer")

        return {"alias": alias, "authority": alias, "binding": store.contract.binding,
                "store": store, "blob_reader": blob_reader, "blob_writer": blob_writer,
                "attachment_protected": attachment_protected,
                "attachment_collection": app_collections[0][0] if len(app_collections) == 1 else None,
                "blob_protected": entry.get("blobProtected", False),
                "protection": None,
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


def create_application():
    """Factory for an authenticated local stdio MCP child; HTTP is not exposed."""
    root = os.environ.get("BRAIN_ROOT")
    if not root:
        raise ValueError("BRAIN_ROOT must name the host brain root")
    host_path = os.environ.get("BRAIN_STUDIO_APPS_HOST", "_internal/studio-apps-host.json")
    host = RegisteredHost(root, host_path)
    host._host()  # fail at startup on an unsafe or malformed registration
    from studio_app_sessions import SessionStore
    sessions = SessionStore(Path(root) / "_internal" / "studio-app-sessions")
    return StudioAppsMCP(identity=host.identity, aliases=host.aliases, resolve=host.resolve,
                         sessions=sessions, clock=_utcnow)


if __name__ == "__main__":
    raise SystemExit(create_application().serve_stdio())
