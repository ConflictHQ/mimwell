"""Structured citation-envelope helpers for MCP 2025-06-18.

The host keeps this adapter disabled unless an application explicitly opts in.
Legacy tool text remains the canonical content block and is hashed byte-for-byte.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import hmac
import html
import json
from pathlib import Path
import re
from collections.abc import Mapping
from urllib.parse import urlencode, urlsplit

CONTRACT = "mimwell-mcp-citation-result/v1"
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "mcp-citation-result-v1.schema.json"
MAX_SCHEMA_BYTES = 512 * 1024
MAX_CITATION_HTML_BYTES = 2 * 1024 * 1024
MAX_CITATION_SOURCE_BYTES = 16 * 1024 * 1024
MAX_STRUCTURED_RESULT_BYTES = 16 * 1024 * 1024
MAX_CITATIONS = 256
_SHA = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_CURRENT_EVIDENCE = object()


class StructuredResultUnavailable(Exception):
    """The successful tool value cannot fit the advertised structured contract."""


def validate_public_origin(value: str | None) -> str | None:
    """Accept an explicit HTTPS origin, optionally with a fixed path prefix."""
    if not isinstance(value, str) or not value or len(value) > 512:
        return None
    try:
        parts = urlsplit(value)
        if (parts.scheme != "https" or not parts.hostname or parts.username is not None
                or parts.password is not None or parts.query or parts.fragment
                or parts.path not in ("", "/") or parts.port not in (None, 443)):
            return None
    except ValueError:
        return None
    return f"https://{parts.netloc}"


def _entry(view, path: str, *, observed=_CURRENT_EVIDENCE):
    entry = view.brain.source_artifacts.get(path)
    if observed is _CURRENT_EVIDENCE:
        observed = view.artifact_evidence.get(path)
    if (not isinstance(entry, Mapping) or entry.get("status") != "bound"
            or type(entry.get("size")) is not int or not 0 <= entry["size"] <= 256 * 1024 * 1024
            or not isinstance(entry.get("sha256"), str) or not _SHA256.fullmatch(entry["sha256"])
            or not isinstance(observed, Mapping) or observed.get("status") != "bound"
            or observed.get("size") != entry["size"] or observed.get("sha256") != entry["sha256"]):
        return None
    return entry


def _url(origin, resource_type, path, target, commit, *, pointer=None):
    if not origin or not isinstance(commit, str) or not _SHA.fullmatch(commit):
        return None
    values = {"type": resource_type, "path": path, "target": target, "revision": commit}
    if pointer is not None:
        values["pointer"] = pointer
    query = urlencode(values)
    return f"{origin}/.well-known/mimwell/citation?{query}"


def _html(title, kind, text, data):
    if (not isinstance(title, str) or not isinstance(kind, str) or not isinstance(text, str)
            or (len(title) + len(kind) + len(text)) * 6 > MAX_CITATION_HTML_BYTES):
        return None
    try:
        if _bounded_json_estimate(data, MAX_CITATION_HTML_BYTES) is None:
            return None
        encoded = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > MAX_CITATION_HTML_BYTES:
            return None
        body = ("<!doctype html><html><head><meta charset=\"utf-8\"><title>" + html.escape(title)
                + "</title></head><body><main><h1>" + html.escape(title) + "</h1><p>"
                + html.escape(kind) + "</p><p>" + html.escape(text) + "</p><details><summary>Source data</summary><pre>"
                + html.escape(encoded) + "</pre></details></main></body></html>").encode("utf-8")
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return None
    return body if len(body) <= MAX_CITATION_HTML_BYTES else None


def _bounded_json_estimate(value, limit):
    """Conservative iterative bound before serializing result-controlled values."""
    pending = [(value, 0)]
    total = 2
    visited = 0
    while pending:
        current, depth = pending.pop()
        visited += 1
        if visited > 100_000 or depth > 64:
            return None
        if isinstance(current, str):
            try:
                string_bytes = len(current.encode("utf-8", errors="strict"))
            except UnicodeError:
                return None
            total += string_bytes * 6 + 2
        elif isinstance(current, dict):
            total += 2 + max(0, len(current) - 1)
            pending.extend((key, depth + 1) for key in current)
            pending.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            total += 2 + max(0, len(current) - 1)
            pending.extend((child, depth + 1) for child in current)
        elif current is None or isinstance(current, bool):
            total += 5
        elif type(current) in (int, float):
            total += 32
        else:
            return None
        if total > limit:
            return None
    return total


def _compiled(view):
    receipt = view.brain.source_attestation
    if (not isinstance(receipt, dict) or not isinstance(receipt.get("sourceCommit"), str)
            or not _SHA.fullmatch(receipt["sourceCommit"])
            or not isinstance(receipt.get("graphSha256"), str)
            or not _SHA256.fullmatch(receipt["graphSha256"])):
        return None
    graph = _entry(view, "app/brain.json")
    if graph is None or graph["sha256"] != receipt["graphSha256"]:
        return None
    return {"status": "bound", "commit": receipt["sourceCommit"],
            "graphSha256": receipt["graphSha256"]}


def _record_binding(view, node, pointer, origin, commit, *, source_path="app/brain.json"):
    if not isinstance(node, dict) or not isinstance(node.get("id"), str):
        return None
    node = view.node(node["id"])
    if not isinstance(node, dict):
        return None
    path = "app/brain.json" if source_path == "app/brain.json" else source_path
    entry = _entry(view, path)
    if entry is None:
        return None
    title = node.get("title") if isinstance(node.get("title"), str) and node["title"] else node["id"]
    kind = node.get("kind") if isinstance(node.get("kind"), str) and node["kind"] else "Record"
    text = node.get("text") if isinstance(node.get("text"), str) else ""
    if _html(title, kind, text, node) is None:
        return None
    url = _url(origin, "compiled-record", path, node["id"], commit)
    if url is None:
        return None
    return {"resultPointer": pointer,
            "citation": {"record_id": node["id"], "kind": kind, "title": title, "path": path,
                         "revision": commit, "url": url},
            "resourceBinding": {"type": "compiled-record", "path": path,
                                "sha256": entry["sha256"], "bytes": entry["size"]}}


def _document_binding(view, path, title, pointer, origin, commit, *, text, observed):
    if not isinstance(path, str) or not view.read_doc_allowed or not isinstance(text, str):
        return None
    # Use the observation made by the read that produced this result. Never
    # reread here: a later read could replace the evidence while the returned
    # content still comes from the first read.
    entry = _entry(view, path, observed=observed)
    if entry is None:
        return None
    kind = "document"
    if _html(title or path, kind, text, {"path": path}) is None:
        return None
    url = _url(origin, "document", path, path, commit)
    if url is None:
        return None
    return {"resultPointer": pointer,
            "citation": {"record_id": None, "kind": kind, "title": title or path,
                         "path": path, "revision": commit, "url": url},
            "resourceBinding": {"type": "document", "path": path,
                                "sha256": entry["sha256"], "bytes": entry["size"]}}


def _schema_projection(view, kind):
    if not isinstance(kind, dict) or not isinstance(kind.get("id"), str):
        return None
    node_kinds = kind.get("node") if isinstance(kind.get("node"), list) else [kind.get("node")]
    node_kinds = [value for value in node_kinds if isinstance(value, str)]
    counts = {}
    for node in view.nodes:
        if isinstance(node.get("kind"), str):
            counts[node["kind"]] = counts.get(node["kind"], 0) + 1
    return {"id": kind["id"], "title": kind.get("title"), "description": kind.get("description"),
            "recordKinds": node_kinds, "records": sum(counts.get(value, 0) for value in node_kinds)}


def _schema_binding(view, kind, result_item, result_pointer, origin, commit):
    if not isinstance(kind, dict) or not isinstance(kind.get("id"), str) or not view.kind_visible(kind):
        return None
    path = "brain-schema.json"
    if not view.gate.can_read(path, view.email):
        return None
    entry = _entry(view, path)
    from brain_mcp import MAX_STATIC_BYTES

    raw = getattr(view.brain, "_brain_schema_raw", None)
    kinds = getattr(view.brain, "_schema_kinds", None)
    if entry is None or entry["size"] > MAX_STATIC_BYTES or not isinstance(raw, bytes) or not isinstance(kinds, tuple):
        return None
    if (entry["size"] != len(raw) or not _SHA256.fullmatch(entry["sha256"])
            or not hmac.compare_digest(entry["sha256"], hashlib.sha256(raw).hexdigest())):
        return None
    matches = [index for index, candidate in enumerate(kinds) if candidate is kind]
    if len(matches) != 1:
        return None
    source_index = matches[0]
    source_kind = kinds[source_index]
    if (not isinstance(source_kind, dict) or source_kind.get("id") != kind["id"]
            or not any(source_kind is candidate for candidate in view.brain.kinds)):
        return None
    expected_result = _schema_projection(view, source_kind)
    if result_item != expected_result:
        return None
    json_pointer = f"/kinds/{source_index}"
    title = kind.get("title") if isinstance(kind.get("title"), str) and kind["title"] else kind["id"]
    if _html(title, "Schema kind", str(kind.get("description") or ""), kind) is None:
        return None
    url = _url(origin, "schema-kind", path, kind["id"], commit, pointer=json_pointer)
    if url is None:
        return None
    return {"resultPointer": result_pointer,
            "citation": {"record_id": None, "kind": "schema-kind", "title": title,
                         "path": path, "revision": commit, "url": url},
            "resourceBinding": {"type": "schema-kind", "path": path,
                                "sha256": entry["sha256"], "bytes": entry["size"],
                                "jsonPointer": json_pointer}}


def render_html(title, kind, text, data):
    return _html(title, kind, text, data)


def structured_result(view, tool, value, text, *, public_origin=None, link_identity=False,
                      document_path=None, document_evidence=None):
    """Build a bounded envelope or signal that the caller must fail the tool call."""
    if _bounded_json_estimate(value, MAX_STRUCTURED_RESULT_BYTES) is None:
        raise StructuredResultUnavailable
    is_native = view.native_adopted
    authority_view = "native-adopted" if is_native else "compiled"
    compiled = None if is_native else _compiled(view)
    # This candidate has no browser-openable native route whose URL revision
    # semantics match the public compiled citation's commit field.
    native = {"status": "unavailable"} if is_native else {"status": "not-applicable"}

    bindings, reasons = [], set()
    if is_native:
        reasons.add("result-variant-unqualified")
    elif compiled is None:
        reasons.add("no-source-binding")
    origin = validate_public_origin(public_origin) if link_identity else None
    if not is_native and origin is None:
        reasons.add("no-openable-url")
    if not is_native and compiled is not None and origin is not None:
        commit = compiled["commit"]
        candidates = []
        failure_reasons = []
        document_bytes = 0
        omitted = False
        if tool == "search_records" and isinstance(value, dict) and isinstance(value.get("matches"), list):
            for index, item in enumerate(value["matches"]):
                pointer = f"/matches/{index}"
                if isinstance(item, dict) and item.get("type") == "record":
                    node = view.node(item.get("id")) if isinstance(item.get("id"), str) else None
                    binding = _record_binding(view, node, pointer, origin, commit)
                    candidates.append(binding)
                    failure_reasons.append("no-source-binding" if binding is None else None)
                elif isinstance(item, dict) and item.get("type") == "document":
                    path = item.get("path")
                    manifest_entry = view.brain.source_artifacts.get(path) if isinstance(path, str) else None
                    if (isinstance(manifest_entry, Mapping) and manifest_entry.get("status") == "bound"
                            and type(manifest_entry.get("size")) is int
                            and document_bytes + manifest_entry["size"] <= MAX_CITATION_SOURCE_BYTES):
                        document_bytes += manifest_entry["size"]
                        try:
                            from brain_mcp import _read_document

                            document_text = _read_document(view, path)
                            observed = view.artifact_evidence.get(path)
                            observed = dict(observed) if isinstance(observed, Mapping) else None
                        except Exception:
                            document_text, observed = None, None
                        binding = _document_binding(view, path, item.get("title"), pointer, origin, commit,
                                                    text=document_text, observed=observed)
                    else:
                        binding = None
                    candidates.append(binding)
                    failure_reasons.append("document-bytes-unbound" if binding is None else None)
                else:
                    candidates.append(None)
                    failure_reasons.append("result-variant-unqualified")
        elif tool == "read_record" and isinstance(value, dict) and isinstance(value.get("record"), dict):
            binding = _record_binding(view, value["record"], "/record", origin, commit)
            candidates.append(binding)
            failure_reasons.append("no-source-binding" if binding is None else None)
        elif tool == "read_record" and isinstance(value, str):
            entry = (_entry(view, document_path, observed=document_evidence)
                     if isinstance(document_path, str) else None)
            if entry is not None and entry["size"] <= MAX_CITATION_SOURCE_BYTES:
                binding = _document_binding(view, document_path, document_path, "", origin, commit,
                                            text=value, observed=document_evidence)
            else:
                binding = None
            candidates.append(binding)
            failure_reasons.append("document-bytes-unbound" if binding is None else None)
        elif tool == "list_definitions" and isinstance(value, dict):
            for key in ("terms", "metrics"):
                rows = value.get(key)
                if isinstance(rows, list):
                    for index, item in enumerate(rows):
                        if len(candidates) >= MAX_CITATIONS:
                            omitted = True
                            break
                        record_id = item.get("id") if isinstance(item, dict) else None
                        node = view.node(record_id) if isinstance(record_id, str) else None
                        binding = _record_binding(view, node, f"/{key}/{index}", origin, commit)
                        candidates.append(binding)
                        failure_reasons.append("no-source-binding" if binding is None else None)
            rows = value.get("kinds")
            if isinstance(rows, list):
                for index, item in enumerate(rows):
                    if len(candidates) >= MAX_CITATIONS:
                        omitted = omitted or index < len(rows)
                        break
                    kind_id = item.get("id") if isinstance(item, dict) else None
                    matching = [entry for entry in view.brain.kinds
                                if entry.get("id") == kind_id and _schema_projection(view, entry) == item]
                    kind = matching[0] if len(matching) == 1 else None
                    binding = _schema_binding(view, kind, item, f"/kinds/{index}", origin, commit)
                    candidates.append(binding)
                    failure_reasons.append("schema-definition-unbound" if binding is None else None)
        elif tool == "resolve_metric" and isinstance(value, dict) and isinstance(value.get("metric"), dict):
            node = view.node(value["metric"].get("id"))
            binding = _record_binding(view, node, "/metric", origin, commit)
            candidates.append(binding)
            failure_reasons.append("no-source-binding" if binding is None else None)
        elif tool == "resolve_metric" and isinstance(value, dict) and isinstance(value.get("candidates"), list):
            for index, item in enumerate(value["candidates"]):
                if len(candidates) >= MAX_CITATIONS:
                    omitted = index < len(value["candidates"])
                    break
                node = view.node(item.get("id")) if isinstance(item, dict) else None
                binding = _record_binding(view, node, f"/candidates/{index}", origin, commit)
                candidates.append(binding)
                failure_reasons.append("no-source-binding" if binding is None else None)
        else:
            reasons.add("result-variant-unqualified")
        bindings = [item for item in candidates if item is not None]
        reasons.update(reason for reason in failure_reasons if reason)
        if omitted:
            reasons.add("result-variant-unqualified")
        if not candidates:
            reasons.add("no-citable-results")
        if bindings and (len(bindings) < len(candidates) or omitted):
            status = "partial"
        elif bindings:
            status = "complete"
            reasons.clear()
        else:
            status = "unavailable"
        # For tool errors/empty successful results, citations remain unavailable.
    else:
        status = "unavailable"
    if not bindings and not reasons:
        reasons.add("no-citable-results")
    envelope = {
        "contract": CONTRACT,
        "tool": tool,
        "resultTextSha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "result": value,
        "citations": {"status": status, "bindings": bindings, "unavailableReasons": sorted(reasons)},
        "provenance": {"compiled": compiled or {"status": "unbound", "commit": None,
                                                  "graphSha256": None}, "native": native},
        "authorityView": authority_view,
    }
    return envelope


def output_schema(tool: str, authority_view: str) -> dict:
    """Return a tool- and view-specific copy of the closed output schema."""
    if tool not in {"search_records", "read_record", "list_definitions", "resolve_metric"}:
        raise ValueError("tool has no citation output schema")
    if authority_view not in {"compiled", "native-adopted"}:
        raise ValueError("unknown citation authority view")
    raw = SCHEMA_PATH.read_bytes()
    if len(raw) > MAX_SCHEMA_BYTES:
        raise ValueError("citation output schema exceeds its size limit")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("citation output schema has duplicate keys")
            result[key] = value
        return result

    try:
        schema = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(
            ValueError("citation output schema has a nonfinite number")))
    except (ValueError, TypeError, UnicodeDecodeError, RecursionError) as exc:
        raise ValueError("citation output schema is invalid") from exc
    if not isinstance(schema, dict) or schema.get("properties", {}).get("contract", {}).get("const") != CONTRACT:
        raise ValueError("citation output schema has an unsupported contract")
    schema = deepcopy(schema)
    contract = schema.get("x-tool-contracts", {}).get(tool)
    if not isinstance(contract, dict) or not isinstance(contract.get("legacyInputSchema"), dict) \
            or not isinstance(contract.get("nativeInputSchema"), dict):
        raise ValueError("citation output schema has no frozen tool input contract")
    schema["properties"]["tool"] = {"const": tool}
    schema["properties"]["authorityView"] = {"const": authority_view}
    return schema



# Native-only version2 is an explicit host AND per-request proposal. These
# helpers do not change the frozen compiled-source version1 path above.
NATIVE_CONTRACT_V2 = "mimwell-mcp-citation-result/v2"
NATIVE_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "mcp-native-citation-result-v2.schema.json"


def native_output_schema(tool):
    if tool not in ("search_records", "read_record", "list_definitions", "resolve_metric"):
        raise ValueError("tool has no native citation contract")
    with NATIVE_SCHEMA_PATH.open("rb") as stream:
        raw = stream.read(MAX_SCHEMA_BYTES + 1)
    if len(raw) > MAX_SCHEMA_BYTES:
        raise ValueError("native citation schema exceeds its bound")
    def pairs(rows):
        value = {}
        for key, child in rows:
            if key in value:
                raise ValueError("duplicate native citation schema key")
            value[key] = child
        return value
    schema = json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite native citation schema")))
    if (schema.get("properties", {}).get("contract", {}).get("const") != NATIVE_CONTRACT_V2
            or schema.get("properties", {}).get("authorityView") != {"const": "native-adopted"}
            or tool not in schema.get("x-tool-contracts", {})):
        raise ValueError("native citation schema has the wrong contract")
    schema["properties"]["tool"] = {"const": tool}
    return schema


def _native_record_binding(view, identity, pointer, route):
    from brain_mcp import MCPApplication, NATIVE_RECORD_PATH, MAX_NATIVE_RECORD_HTML_BYTES
    node = view.node(identity) if isinstance(identity, str) else None
    revision = view.native_revisions.get(identity)
    if not isinstance(node, dict) or not isinstance(revision, str):
        return None
    try:
        query = urlencode({"id": identity, "revision": revision})
    except (UnicodeError, ValueError, TypeError):
        return None
    if MCPApplication._native_record_query(query) != {"id": identity, "revision": revision}:
        return None
    # The legacy handler result is already request-bounded. Avoid rendering
    # arbitrary objects, and use the SAME native-reader serialization/limit.
    if _bounded_json_estimate(node, MAX_STRUCTURED_RESULT_BYTES) is None:
        return None
    try:
        raw = json.dumps(node, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
        rendered = MCPApplication._native_record_html(node)
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return None
    if rendered is None or len(raw) > MAX_NATIVE_RECORD_HTML_BYTES:
        return None
    title = node.get("title") if isinstance(node.get("title"), str) and node["title"] else identity
    kind = node.get("kind") if isinstance(node.get("kind"), str) else "Record"
    return {"resultPointer": pointer,
        "citation": {"record_id": identity, "kind": kind, "title": title,
            "path": NATIVE_RECORD_PATH, "revision": revision,
            "url": route["readerOrigin"] + NATIVE_RECORD_PATH + "?" + query},
        "nativeRevision": revision,
        "resourceBinding": {"type": "native-record-view", "path": NATIVE_RECORD_PATH,
            "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}}


def _native_result_is_current(view, tool, value):
    """Do not cite a current record for a different/stale returned value."""
    from brain_mcp import _record_entry, _aliases, TERM_KIND
    def same(left, right):
        try:
            return json.dumps(left, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) == json.dumps(
                right, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (ValueError, TypeError, UnicodeError, RecursionError):
            return False
    def node(item):
        return view.node(item.get("id")) if isinstance(item, dict) and isinstance(item.get("id"), str) else None
    if not isinstance(value, dict):
        return False
    if tool == "read_record":
        return node(value.get("record")) is not None and same(value["record"], node(value["record"]))
    if tool == "resolve_metric" and isinstance(value.get("metric"), dict):
        return node(value["metric"]) is not None and same(value["metric"], node(value["metric"]))
    if tool in ("search_records", "resolve_metric"):
        rows = value.get("matches" if tool == "search_records" else "candidates")
        return isinstance(rows, list) and all(node(item) is not None and same(
            item, _record_entry(node(item), item.get("matched"))) for item in rows)
    if tool == "list_definitions":
        for key in ("terms", "metrics"):
            rows = value.get(key)
            if not isinstance(rows, list):
                return False
            for item in rows:
                record = node(item)
                if record is None:
                    return False
                name = "term" if record.get("kind") == TERM_KIND else "name"
                expected = {"id": record["id"], name: record.get("title"),
                            "definition": record.get("text"), "aliases": _aliases(record)}
                if not same(item, expected):
                    return False
        return True
    return False


def native_structured_result(view, tool, value, text, *, route, revalidate):
    """Native2 capture uses current ordinary identity; it grants no permissions.

    route is a trusted transport capture, never request input. Revalidation binds
    origin/route/brain audience/host instance AND the current token/native policy
    before and after record capture. This is not atomic network delivery or DNS
    verification of an operator-declared public origin.
    """
    from brain_mcp import NATIVE_RECORD_PATH
    if (not view.native_adopted or not callable(revalidate)
            or type(route) is not dict or set(route) != {"brainAudience", "readerOrigin", "readerPath"}
            or route["readerPath"] != NATIVE_RECORD_PATH
            or validate_public_origin(route["readerOrigin"]) != route["readerOrigin"]
            or not isinstance(route["brainAudience"], str)
            or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", route["brainAudience"]) is None
            or revalidate() is not True
            or _bounded_json_estimate(value, MAX_STRUCTURED_RESULT_BYTES) is None
            or not _native_result_is_current(view, tool, value)):
        raise StructuredResultUnavailable
    pairs, reasons = [], set()
    if tool == "search_records" and isinstance(value, dict) and isinstance(value.get("matches"), list):
        for index, item in enumerate(value["matches"]):
            if isinstance(item, dict) and item.get("type") == "record":
                pairs.append((f"/matches/{index}", item.get("id")))
            else:
                reasons.add("result-variant-unqualified")
    elif tool == "read_record" and isinstance(value, dict) and isinstance(value.get("record"), dict):
        pairs.append(("/record", value["record"].get("id")))
    elif tool == "list_definitions" and isinstance(value, dict):
        for key in ("terms", "metrics"):
            rows = value.get(key)
            if not isinstance(rows, list):
                reasons.add("result-variant-unqualified")
                continue
            for index, item in enumerate(rows):
                pairs.append((f"/{key}/{index}", item.get("id") if isinstance(item, dict) else None))
        if value.get("kinds"):
            # Schema definitions are not native records and cannot acquire a
            # fabricated identity merely to fit this reader route.
            reasons.add("schema-definition-unbound")
    elif tool == "resolve_metric" and isinstance(value, dict) and isinstance(value.get("metric"), dict):
        pairs.append(("/metric", value["metric"].get("id")))
    elif tool == "resolve_metric" and isinstance(value, dict) and isinstance(value.get("candidates"), list):
        pairs.extend((f"/candidates/{index}", item.get("id") if isinstance(item, dict) else None)
                     for index, item in enumerate(value["candidates"]))
    else:
        reasons.add("result-variant-unqualified")
    bindings = []
    for index, (pointer, identity) in enumerate(pairs):
        if index >= MAX_CITATIONS:
            reasons.add("result-variant-unqualified")
            break
        binding = _native_record_binding(view, identity, pointer, route)
        if binding is None:
            reasons.add("native-reader-disabled")
        else:
            bindings.append(binding)
    if not pairs:
        reasons.add("no-citable-results")
    if revalidate() is not True:
        raise StructuredResultUnavailable
    status = "complete" if bindings and not reasons else "partial" if bindings else "unavailable"
    return {"contract": NATIVE_CONTRACT_V2, "tool": tool, "authorityView": "native-adopted",
        "resultTextSha256": hashlib.sha256(text.encode("utf-8")).hexdigest(), "result": value,
        "citations": {"status": status, "bindings": bindings, "unavailableReasons": sorted(reasons)},
        "provenance": {"compiled": {"status": "unbound", "commit": None, "graphSha256": None},
                       "native": {"status": "bound" if bindings else "unavailable", **route}}}
