"""The brain as an MCP server over streamable HTTP and stdio (#459).

`POST /mcp` speaks the Model Context Protocol (protocol 2025-06-18, and
2025-03-26 for older clients): JSON-RPC 2.0, one message per POST, a JSON reply
to each request and 202 to a notification. It is stateless: no Mcp-Session-Id
and no server-to-client stream (GET and DELETE answer 405), so any replica can
answer any request. runtime/portal-container/ runs it behind nginx at /mcp,
beside the static portal.

Read tools:
  search_records    rank the brain's compiled records and indexed documents
  read_record       one record with its relationships, or one document's text
  list_definitions  glossary terms, metrics and the record kinds, with counts
  resolve_metric    a metric's definition record by name, alias or id; listed
                    only when the caller can read at least one Metric record

An operator may explicitly enable the additional `propose_change` tool. It
places a proposed correction in the existing native review queue and never
reviews or commits it. An adopted authority can additionally expose
`read_correction_basis` when the same mapped principal has both native host
reader and proposal grants on one unambiguous route to the selected brain.

What the tools read is the brain's published asset set (`BRAIN_ROOT`, the
`_site/` the portal serves): app/brain.json, app/knowledge-pack.json,
brain-schema.json and the documents, read and indexed once at start. Ranking is
context_search.score_record's keyword score, from a term index (TermIndex).
The brain's own `access` rules apply per caller through scripts/access_gate.py,
the Python twin of access.js, so a caller never gets more here than the portal
gives the same identity; the reader-independent half of that check is done once
(access_gate.Prepared). A Worker read tool withheld by `access.restricted_tools`
also withholds the MCP tool that serves the same data (TOOL_SOURCES); the MCP
tool names may be restricted too.

Identity. With BRAIN_MCP_JWKS_URL, BRAIN_MCP_ISSUER and BRAIN_MCP_AUDIENCE set,
every request must carry a valid Astrolift brain read token in
BRAIN_MCP_TOKEN_HEADER (default X-Astrolift-Brain-Token; scripts/brain_token.py),
and the verified email is mapped through the protected MCP identity file before
native reads or proposals. Legacy email rules retain the same matching semantics
as access.js. Opt-in typed GUID rules apply only to this verifier-backed host;
the Cloudflare Worker has no typed token context and will not grant those rules.
A legacy brain may use anonymous access only when
the operator explicitly selects public-only mode. Setting only some verifier
settings refuses to start. The token is never logged or echoed.

Typed GUID read principals require both BRAIN_MCP_TYPED_PRINCIPALS=true and a
host-configured BRAIN_MCP_EXPECTED_ORG_GUID. They affect only the read gate by
default. An operator may separately map verified app/agent subjects to existing
native reader actors in the private `_internal/mcp-typed-readers.json` file;
that file grants no native permissions. The legacy email/UID mapping remains
separate and continues to serve people and local stdio callers. Typed reads are
disabled unless the verifier is explicitly configured, and do not grant
proposal, review, commit, correction-basis or metric execution access.

Correction bases are bounded direct native reads, separate from compiled
`read_record` responses. They supply the complete admitted record, native revision
and registered proposal coordinates; review and commit remain separate operations.

When a native authority is adopted, static portal assets are refused. The
current publication contract protects records through MCP; it does not yet
authorize the full graph, knowledge pack, or unbound documents for static reads.

Factory for gunicorn: `brain_mcp:create_application()`.
"""
from __future__ import annotations

from array import array
from collections.abc import Mapping
from copy import deepcopy
from functools import cached_property
from http import HTTPStatus
import hmac
import hashlib
import html
import json
import mimetypes
import os
from contextlib import nullcontext
from pathlib import Path
import re
import sys
import unicodedata
from types import MappingProxyType
from urllib.parse import parse_qsl

import access_gate
import brain_token
import metric_executor
import public_status
from context_host import _read_raw, decode
from context_search import FIELDS, score_record, terms
from knowledge_operations import StoreError, load_host, private_path, private_store_path
from record_sources import record_slug

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26")
LATEST_PROTOCOL = PROTOCOL_VERSIONS[0]
TOKEN_HEADER = "X-Astrolift-Brain-Token"
SERVER_NAME = "mimwell-brain"
MAX_BODY_BYTES = 64 * 1024
MAX_DOC_BYTES = 8 * 1024 * 1024
MAX_STATIC_BYTES = 64 * 1024 * 1024
MAX_NATIVE_RECORD_HTML_BYTES = 64 * 1024
MAX_TYPED_NATIVE_READERS_BYTES = 64 * 1024
MAX_TYPED_NATIVE_READERS = 1000
_TYPED_NATIVE_SUBJECT = re.compile(
    r"(?:app|agent):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
NATIVE_RECORD_PATH = "/.well-known/mimwell/native-record"
CITATION_PATH = "/.well-known/mimwell/citation"
DEFAULT_MAX_DOC_CHARS = 300000
SUMMARY_CHARS = 300
MAX_RELATIONSHIPS = 100
METRIC_KIND = "Metric"
TERM_KIND = "Term"
DOCUMENT_KIND = "document"
_HEADER_NAME = re.compile(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*")
_REQUEST_ID = (str, int, float)  # MCP RequestId: string | number
_DOC_EXT = re.compile(r"\.(md|json|txt|py|js|toml|html|css)\Z", re.IGNORECASE | re.ASCII)
_ESCAPE = re.compile(r"%[0-9a-f]{2}", re.IGNORECASE | re.ASCII)
_SCHEME = re.compile(r"[a-z][a-z0-9+.-]*:", re.IGNORECASE | re.ASCII)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# Read only as filtered views by access.js; a reader gets their content here
# through the record tools instead of the raw file.
_SERVER_ONLY = frozenset({"client.config.json", "app/brain-meta.json", "app/brain-manifest.json"})
SOURCE_RECEIPT_PATH = Path("/opt/brain/private/source-receipt.json")
SOURCE_RECEIPT_OWNER_UID = 0
SOURCE_ARTIFACT_MANIFEST_PATH = Path("/opt/brain/private/source-artifacts.json")

# The Worker read tools each MCP tool serves the data of (worker.js TOOLS).
TOOL_SOURCES = {
    "search_records": ("search_graph", "search_knowledge"),
    "read_record": ("search_graph", "read_doc"),
    "list_definitions": ("search_graph",),
    "resolve_metric": ("search_graph",),
    "run_metric": ("search_graph",),
}
_READ_ONLY = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
TOOLS = {
    "search_records": {
        "title": "Search records",
        "description": ("Search this brain's records (decisions, glossary terms, metrics, people, specs, sessions and "
                        "every other kind it compiles) and its indexed documents. Returns ranked matches: records "
                        "with their id and kind, documents with their path. Read one with read_record."),
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["query"], "properties": {
            "query": {"type": "string", "minLength": 1, "maxLength": 256,
                      "description": "Keywords, e.g. 'pricing decision' or 'churn'."},
            "kind": {"type": "string", "maxLength": 64,
                     "description": "Only records of this kind (e.g. 'Decision', 'Term', 'Metric'), "
                                    "or 'document' for documents only."},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10}}},
    },
    "read_record": {
        "title": "Read a record",
        "description": ("Read one record by its id (as search_records returns it), with its relationships, or one "
                        "document by its path, which returns the document's text. Give exactly one of id or path."),
        "inputSchema": {"type": "object", "additionalProperties": False,
                        "oneOf": [{"required": ["id"]}, {"required": ["path"]}], "properties": {
            "id": {"type": "string", "minLength": 1, "maxLength": 512,
                   "description": "A record id, e.g. 'decision:pick-alpha'."},
            "path": {"type": "string", "minLength": 1, "maxLength": 512,
                     "description": "A document path, e.g. 'knowledge/docs/overview.md'."}}},
    },
    "list_definitions": {
        "title": "List definitions",
        "description": ("List what this brain defines: its glossary terms, its metrics, and the kinds of record it "
                        "holds with how many of each you can read. Filter with an optional query."),
        "inputSchema": {"type": "object", "additionalProperties": False, "properties": {
            "query": {"type": "string", "minLength": 1, "maxLength": 256,
                      "description": "Only definitions whose name, alias or text contains this."},
            "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50,
                      "description": "At most this many terms, and as many metrics."}}},
    },
    "resolve_metric": {
        "title": "Resolve a metric",
        "description": ("Resolve a metric by name, alias or id to its definition record (its meaning, formula or "
                        "query template, unit and owner, as the brain records them) and its relationships."),
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["name"], "properties": {
            "name": {"type": "string", "minLength": 1, "maxLength": 256,
                     "description": "A metric's name, alias or id, e.g. 'monthly recurring revenue'."}}},
    },
    "run_metric": {
        "title": "Run a governed metric",
        "description": ("Execute a reviewed source-bound metric with its fixed aggregation, allowlisted dimensions, "
                        "typed parameter filters and read-only query limits. Caller input cannot supply SQL or a source."),
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["name"], "properties": {
            "name": {"type": "string", "minLength": 1, "maxLength": 256},
            "dimensions": {"type": "array", "uniqueItems": True, "maxItems": 16,
                           "items": {"type": "string", "pattern": "^[a-z][a-z0-9_-]*$"}},
            "filters": {"type": "object", "maxProperties": 32},
            "grain": {"type": "string", "enum": ["day", "week", "month", "quarter", "year"]},
            "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100}}},
    },
    "propose_change": {
        "title": "Propose a reviewed change",
        "description": ("Submit a desired native record plus bounded source attribution, reason and native evidence "
                        "to the configured review queue. This does not change the brain; an independent reviewer "
                        "must approve it. Copy the complete record and exact expectedRevision from "
                        "read_correction_basis; preserve unrelated fields and relationships. Use evidence as a "
                        "list of native reference strings. Source attribution is unverified metadata, not identity "
                        "or proof. This tool cannot review, approve, commit or publish."),
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["change"], "properties": {
            "change": {"type": "object", "additionalProperties": False,
                "required": ["format", "requestId", "authority", "resource", "expectedRevision",
                             "record", "source", "reason", "evidence"],
                "properties": {
                    "format": {"type": "string", "const": "learned-change/v1"},
                    "requestId": {"type": "string", "minLength": 1, "maxLength": 256},
                    "authority": {"type": "string", "minLength": 1, "maxLength": 256},
                    "resource": {"type": "string", "minLength": 1, "maxLength": 256},
                    "expectedRevision": {"type": ["string", "null"], "minLength": 1, "maxLength": 256},
                    "record": {"$schema": "https://json-schema.org/draft/2020-12/schema",
                        "$id": "conflict:schema/knowledge-record/v1",
                        "type": "object", "additionalProperties": False,
                        "required": ["id", "collection", "kind", "content", "relations"],
                        "description": "Use the complete native record from read_correction_basis; edit only the intended fields and preserve all unrelated fields and relationships. The authority performs its kind-specific validation.",
                        "properties": {
                            "id": {"type": "string", "minLength": 1},
                            "collection": {"type": "string", "minLength": 1},
                            "kind": {"type": "string", "minLength": 1},
                            "content": {"type": "object", "additionalProperties": False,
                                "properties": {
                                    "title": {"type": "string"}, "text": {"type": "string"},
                                    "data": {"type": "object"},
                                    "source": {"type": ["string", "object"],
                                        "properties": {"path": {"type": "string", "minLength": 1},
                                                       "locator": {"type": "string"}},
                                        "required": ["path"], "additionalProperties": False},
                                    "labels": {"type": "array", "items": {"type": "string"}},
                                    "owner": {"type": "string"}, "status": {"type": "string"},
                                    "durability": {"type": "string", "enum": ["durable-logic", "point-in-time", "ephemeral"]},
                                    "derived": {"type": "boolean"}},
                                "required": []},
                            "relations": {"type": "array", "items": {"type": "object",
                                "properties": {"rel": {"type": "string", "minLength": 1},
                                               "target": {"type": "string", "minLength": 1},
                                               "evidence": {"type": "object"}},
                                "required": ["rel", "target"], "additionalProperties": False}},
                            "evidence": {"type": "object"},
                            "blobs": {"type": "array", "items": {"type": "object",
                                "properties": {"store": {"type": "string", "minLength": 1},
                                               "key": {"type": "string", "minLength": 1},
                                               "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                                               "bytes": {"type": "integer", "minimum": 0},
                                               "mediaType": {"type": "string", "minLength": 3}},
                                "required": ["store", "key", "sha256", "bytes", "mediaType"],
                                "additionalProperties": False}}}},
                    "source": {"type": "object", "additionalProperties": False,
                        "required": ["kind", "id", "revision", "observationSha256"],
                        "properties": {"kind": {"type": "string", "enum": ["conversation", "run", "app"]},
                                       "id": {"type": "string", "minLength": 1, "maxLength": 256},
                                       "revision": {"type": "string", "minLength": 1, "maxLength": 128},
                                       "observationSha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"}}},
                    "reason": {"type": "string", "minLength": 1, "maxLength": 700},
                    "evidence": {"type": "array", "minItems": 1, "maxItems": 128,
                                 "items": {"type": "string", "minLength": 1, "maxLength": 2000}}}}}},
    },
    "read_correction_basis": {
        "title": "Read a correction basis",
        "description": ("Read the complete admitted native record, exact revision, and registered proposal "
                        "coordinates before proposing a correction. This is not approval or a write. "
                        "Preserve unrelated fields; use propose_change for independent review."),
        "inputSchema": {"type": "object", "additionalProperties": False, "required": ["id"],
                        "properties": {"id": {"type": "string", "minLength": 1, "maxLength": 512}}},
    },
}


class ToolError(Exception):
    """A refusal or a miss the caller can act on; returned as an isError result."""


def _log(event, **fields):
    print(json.dumps({"event": event, **fields}, sort_keys=True), file=sys.stderr, flush=True)


def _fold(value):
    return unicodedata.normalize("NFKC", value).casefold() if isinstance(value, str) else ""


def _summary(value):
    return " ".join(value.split())[:SUMMARY_CHARS] if isinstance(value, str) else ""


def _native_edge_key(edge):
    """Canonical full edge value, including relation-specific attributes."""
    return json.dumps(edge, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _native_owned_ids(store, snapshot, candidate_ids):
    """Classify file-fallback IDs against one unchanged native read checkpoint.

    Metadata is private host state; callers receive only the IDs withheld from
    file fallback. Unsupported adapters or any changed checkpoint fail closed.
    """
    if candidate_ids is None:
        return None
    if (len(candidate_ids) > 10000
            or any(len(identity.encode("utf-8")) > 512 for identity in candidate_ids)
            or sum(len(identity.encode("utf-8")) for identity in candidate_ids) > 5 * 1024 * 1024):
        return None
    if not candidate_ids:
        return set()
    dialect = getattr(store, "dialect", None)
    if (dialect is None or not callable(getattr(dialect, "begin", None))
            or not callable(getattr(dialect, "rollback", None))
            or not callable(getattr(dialect, "journal_head", None))
            or not callable(getattr(store, "_record_metadata", None))
            or not callable(getattr(store, "_meta", None))):
        return None
    checkpoint = snapshot.get("checkpoint")
    if not isinstance(checkpoint, dict):
        return None
    try:
        dialect.begin()
        if (store.contract.binding != checkpoint.get("binding")
                or store._meta("instance") != checkpoint.get("instance")
                or store._meta("status") != checkpoint.get("state")):
            return None
        head = dialect.journal_head()
        if (head is None or head["sequence"] != checkpoint.get("sequence")
                or head["digest"] != checkpoint.get("digest")):
            return None
        return {identity for identity in candidate_ids if store._record_metadata(identity) is not None}
    except Exception:
        # Any adapter/query failure makes file fallback unsafe for these IDs.
        return None
    finally:
        if getattr(dialect, "in_transaction", False):
            dialect.rollback()


def _aliases(node):
    data = node.get("data")
    aliases = data.get("aliases") if isinstance(data, dict) else None
    return [a for a in aliases if isinstance(a, str)] if isinstance(aliases, list) else []


def safe_doc_path(raw, roots=()):
    """worker.js safeDocPath: a plain corpus path with a supported extension, or None."""
    if not isinstance(raw, str):
        return None
    path = raw.strip()
    if not path:
        return None
    if _ESCAPE.search(path):
        try:
            path = access_gate.decode_uri_component(path)
        except ValueError:
            return None
    path = path.replace("\\", "/")
    if _CONTROL.search(path) or _SCHEME.match(path) or path.startswith("~") or path.startswith("//"):
        return None
    parts = [part for part in path.split("/") if part]
    if not parts or any(part in (".", "..") or part.startswith(".") for part in parts):
        return None
    clean = "/".join(parts)
    if not _DOC_EXT.search(clean):
        return None
    if roots and not any(clean == root or clean.startswith(root + "/") for root in roots):
        return None
    return clean


class TermIndex:
    """context_search.score_record, precomputed: term -> (row, field weight) postings.

    `search(wanted)` gives each row the matched terms and score score_record
    would give it (tests/test_brain_mcp.py holds the two equal), without
    tokenizing every row again on every request.
    """

    def __init__(self, rows):
        if any(type(weight) is not int or not 0 < weight < 8 for weight in FIELDS.values()):
            raise ValueError("context_search.FIELDS weights must be integers from 1 to 7")
        self._postings = {}
        for i, row in enumerate(rows):
            for field, weight in FIELDS.items():
                value = row.get(field, "")
                if isinstance(value, str):
                    for term in terms(value):
                        self._postings.setdefault(term, array("q")).append(i * 8 + weight)

    def search(self, wanted):
        """row -> (sorted matched terms, score), for rows matching at least one term."""
        matched, score = {}, {}
        for term in wanted:
            for code in self._postings.get(term, ()):
                row = code >> 3
                matched.setdefault(row, set()).add(term)
                score[row] = score.get(row, 0) + (code & 7)
        return {row: (sorted(found), score[row]) for row, found in matched.items()}


class Brain:
    """The published asset set one process serves, read and indexed once at start."""

    def __init__(self, root):
        self.root = Path(root).absolute()
        self.unreadable = []
        config = self._json("client.config.json", required=True)
        if not isinstance(config, dict):
            raise ValueError("client.config.json must be a JSON object")
        self.config = config
        try:
            from knowledge_store import adopted_authority

            self.native_authority = adopted_authority(config)
        except (StoreError, ValueError, TypeError):
            # An invalid adoption declaration must not silently fall back to
            # the legacy path-only access gate.
            self.native_authority = False
        brain = config.get("brain") if isinstance(config.get("brain"), dict) else {}
        client = config.get("client") if isinstance(config.get("client"), dict) else {}
        self.name = str(brain.get("name") or client.get("name") or "Brain")
        assistant = config.get("assistant") if isinstance(config.get("assistant"), dict) else {}
        roots = assistant.get("docRoots")
        self.doc_roots = tuple(r for r in (str(x).strip("/") for x in roots) if r) if isinstance(roots, list) else ()
        limit = assistant.get("maxDocChars")
        self.max_doc_chars = limit if type(limit) is int and limit > 0 else DEFAULT_MAX_DOC_CHARS
        graph_raw = None
        try:
            graph_raw = _read_raw(self.root, "app/brain.json")
            graph = decode(graph_raw)
        except FileNotFoundError:
            graph = None
        except (OSError, ValueError):
            self.unreadable.append("app/brain.json")
            graph = None
        graph_loaded = isinstance(graph, dict)
        graph = graph if graph_loaded else {}
        from source_receipt import load_receipt

        # The receipt is optional for legacy builds. When the private image
        # copy exists, malformed or mismatched provenance is a startup error.
        # Hash the exact bytes already parsed above; never reopen the graph.
        self.source_attestation = load_receipt(
            SOURCE_RECEIPT_PATH,
            graph_raw if graph_loaded else None,
            owner_uid=SOURCE_RECEIPT_OWNER_UID,
        )
        from source_artifact_manifest import load_manifest

        loaded_artifacts = load_manifest(
            SOURCE_ARTIFACT_MANIFEST_PATH,
            self.source_attestation,
            graph_raw if graph_loaded else None,
            owner_uid=SOURCE_RECEIPT_OWNER_UID,
        ) or {}
        self.source_artifacts = MappingProxyType({
            key: MappingProxyType(dict(value)) for key, value in loaded_artifacts.get("entries", {}).items()
        })
        self.artifact_coverage = loaded_artifacts.get("coverage", "unavailable")
        self.artifact_coverage_reasons = loaded_artifacts.get("reasonCodes", ())
        startup_artifact_evidence = {}
        self._artifact_evidence_startup = startup_artifact_evidence
        if graph_raw is not None:
            self._observe_artifact("app/brain.json", graph_raw)
        self.nodes = [n for n in graph.get("nodes") or [] if isinstance(n, dict) and isinstance(n.get("id"), str)]
        self.edges = [e for e in graph.get("edges") or [] if isinstance(e, dict)
                      and isinstance(e.get("source"), str) and isinstance(e.get("target"), str)]
        self._brain_schema_raw = None
        self._schema_kinds = None
        pack = self._json("app/knowledge-pack.json")
        items = pack.get("items") if isinstance(pack, dict) else None
        self.documents = [i for i in items or [] if isinstance(i, dict) and isinstance(i.get("path"), str) and i["path"]]
        schema = self._json("brain-schema.json")
        kinds = schema.get("kinds") if isinstance(schema, dict) else None
        self._schema_kinds = tuple(kinds) if isinstance(kinds, list) else None
        self.kinds = [k for k in kinds or [] if isinstance(k, dict) and isinstance(k.get("id"), str)]
        release = self._json("engine-release.json")
        self.version = str(release.get("version") or "0") if isinstance(release, dict) else "0"
        gate = access_gate.make_access(config.get("access"))
        if gate.needs_register:
            register = self._json("app/people.json")
            if register is not None:
                gate = gate.bind_register(register)
        self.gate = gate
        self.index = {}
        self.adjacent = {}
        for i, node in enumerate(self.nodes):
            self.index.setdefault(node["id"], i)
        for j, edge in enumerate(self.edges):
            self.adjacent.setdefault(edge["source"], []).append(j)
            if edge["target"] != edge["source"]:
                self.adjacent.setdefault(edge["target"], []).append(j)
        self.metric_rows = [i for i, n in enumerate(self.nodes) if n.get("kind") == METRIC_KIND]
        self.definition_rows = [i for i, n in enumerate(self.nodes) if n.get("kind") in (TERM_KIND, METRIC_KIND)]
        self.record_terms = TermIndex(self.nodes)
        self.document_terms = TermIndex({"id": d["path"], "title": str(d.get("title") or ""),
                                         "text": str(d.get("summary") or "")} for d in self.documents)
        # The reader-independent half of the access filter, for the gate's path rules.
        self.node_access = self.edge_access = self.document_access = None
        if gate.paths_enabled:
            self.node_access = access_gate.Prepared(gate, ((access_gate.node_paths(n), n) for n in self.nodes))
            self.edge_access = access_gate.Prepared(
                gate, ((access_gate.node_paths({"evidence": e.get("evidence")}), e) for e in self.edges))
            self.document_access = access_gate.Prepared(
                gate, (([d["path"]], {"title": d.get("title"), "summary": d.get("summary")}) for d in self.documents))
        self.artifact_evidence = MappingProxyType(
            {key: MappingProxyType(dict(value)) for key, value in startup_artifact_evidence.items()})
        del self._artifact_evidence_startup

    def _observe_artifact(self, relative, raw):
        expected = self.source_artifacts.get(relative)
        if (isinstance(expected, Mapping) and expected.get("status") == "bound"
                and type(expected.get("size")) is int and expected["size"] == len(raw)
                and isinstance(expected.get("sha256"), str)
                and hmac.compare_digest(expected["sha256"], hashlib.sha256(raw).hexdigest())):
            state = {"status": "bound", "size": len(raw), "sha256": expected["sha256"]}
        else:
            state = {"status": "unavailable"}
        startup = getattr(self, "_artifact_evidence_startup", None)
        if startup is not None:
            startup[relative] = state
        return state

    def _json(self, relative, required=False):
        try:
            raw = _read_raw(self.root, relative)
            if relative == "brain-schema.json":
                self._brain_schema_raw = raw
            if relative in ("app/knowledge-pack.json", "brain-schema.json"):
                self._observe_artifact(relative, raw)
            return decode(raw)
        except FileNotFoundError:
            if relative == "brain-schema.json":
                self._brain_schema_raw = None
            if required:
                raise
        except (OSError, ValueError):
            if relative == "brain-schema.json":
                self._brain_schema_raw = None
            if required:
                raise
            self.unreadable.append(relative)
        if relative in ("app/knowledge-pack.json", "brain-schema.json"):
            startup = getattr(self, "_artifact_evidence_startup", None)
            if startup is not None:
                startup[relative] = {"status": "unavailable"}
        return None


class View:
    """What one caller may read of the brain. Visibility is worked out only for
    what a request touches, from the brain's prepared access (Brain.node_access)."""

    def __init__(self, brain, email, *, propose_change=None, native_actor=None, native_ids=None,
                 native_relations=None, native_nodes=None, native_root=None, identity_authorized=True,
                 native_authorize=None, correction_basis=None, native_revisions=None,
                 suppress_metric_execution=False):
        self.brain, self.email, self.gate = brain, email, brain.gate
        # Per-request copy: later document reads never mutate shared Brain state.
        self.artifact_evidence = dict(brain.artifact_evidence)
        self.artifact_coverage = brain.artifact_coverage
        self.artifact_coverage_reasons = brain.artifact_coverage_reasons
        native_adopted = brain.native_authority is not None
        self.propose_change = propose_change
        self.correction_basis = correction_basis
        self.native_actor = native_actor
        self.native_ids = frozenset() if native_adopted and native_ids is None else native_ids
        self.native_relations = native_relations or {}
        self.native_nodes = native_nodes or {}
        self.native_revisions = native_revisions or {}
        self.native_root = native_root or brain.root
        self.identity_authorized = identity_authorized
        self.native_authorize = native_authorize
        self.suppress_metric_execution = suppress_metric_execution is True
        self.native_adopted = native_adopted
        self.owner = self.gate.is_owner(email)
        self.scoped = self.gate.paths_enabled and not self.owner
        self.records_allowed = self.identity_authorized and self.gate.tool_allowed("search_graph", email) and not (
            self.native_adopted and (native_actor is None or not native_ids))
        # Native record policies cannot authorize unbound prose documents.
        self.documents_allowed = (self.identity_authorized and self.gate.tool_allowed("search_knowledge", email)
                                  and not self.native_adopted)
        self.read_doc_allowed = (self.identity_authorized and self.gate.tool_allowed("read_doc", email)
                                 and not self.native_adopted)

    def observe_document_artifact(self, path, raw):
        expected = self.brain.source_artifacts.get(path)
        if (isinstance(expected, Mapping) and expected.get("status") == "bound"
                and type(expected.get("size")) is int and expected["size"] == len(raw)
                and isinstance(expected.get("sha256"), str)
                and hmac.compare_digest(expected["sha256"], hashlib.sha256(raw).hexdigest())):
            self.artifact_evidence[path] = {"status": "bound", "size": len(raw),
                                            "sha256": expected["sha256"]}
        else:
            self.artifact_evidence[path] = {"status": "unavailable"}

    @cached_property
    def _node_mask(self):
        return self.brain.node_access.mask(self.email) if self.scoped else None

    @cached_property
    def _edge_mask(self):
        return self.brain.edge_access.mask(self.email) if self.scoped else None

    @cached_property
    def _document_mask(self):
        return self.brain.document_access.mask(self.email) if self.scoped else None

    def visible(self, row):
        node = self.brain.nodes[row]
        return ((self._node_mask is None or self._node_mask[row])
                and (self.native_ids is None or node["id"] in self.native_ids))

    def visible_id(self, record_id):
        row = self.brain.index.get(record_id)
        return row is not None and self.visible(row)

    def node(self, record_id):
        row = self.brain.index.get(record_id)
        if row is None or not self.visible(row):
            return None
        return self.native_nodes.get(record_id, self.brain.nodes[row]) if self.native_adopted \
            else self.brain.nodes[row]

    @cached_property
    def nodes(self):
        return [self.node(node["id"]) for row, node in enumerate(self.brain.nodes) if self.visible(row)]

    def documents(self, rows):
        mask = self._document_mask
        return [row for row in rows if mask is None or mask[row]]

    def kind_visible(self, kind):
        if self.native_adopted:
            node_kinds = kind.get("node") if isinstance(kind.get("node"), list) else [kind.get("node")]
            return bool(set(node_kinds) & {node.get("kind") for node in self.nodes})
        if not self.scoped:
            return True
        allow = self.gate.allow_for(self.email)
        storage = kind.get("storage")
        paths = storage if isinstance(storage, list) else [storage]
        artifact = kind.get("artifact")
        return (all(allow(p) for p in paths if isinstance(p, str))
                and (not isinstance(artifact, str) or allow(artifact)) and not self.gate.mentions_restricted(kind, allow))

    def metrics(self):
        return [self.brain.nodes[row] for row in self.brain.metric_rows if self.visible(row)]

    def tools(self):
        allowed = {"search_graph": self.records_allowed, "search_knowledge": self.documents_allowed,
                   "read_doc": self.read_doc_allowed}
        names = []
        for name, sources in TOOL_SOURCES.items():
            if name == "run_metric" and self.suppress_metric_execution:
                continue
            if not self.gate.tool_allowed(name, self.email) or not any(allowed[s] for s in sources):
                continue
            if name in ("resolve_metric", "run_metric") and not any(
                    self.visible(row) for row in self.brain.metric_rows):
                continue
            names.append(name)
        if self.propose_change is not None:
            names.append("propose_change")
            if self.correction_basis is not None:
                names.append("read_correction_basis")
        return names

    def relationships(self, node_id):
        """The edges filter_graph keeps for this reader, as rows about the other end."""
        brain, rows = self.brain, []
        for j in brain.adjacent.get(node_id, ()):
            edge = brain.edges[j]
            other, direction = (edge["target"], "out") if edge["source"] == node_id else (edge["source"], "in")
            if ((self.scoped and not self._edge_mask[j])
                    or ((self.scoped or self.native_adopted) and not self.visible_id(other))):
                continue
            if self.native_adopted and _native_edge_key(edge) not in self.native_relations.get(edge["source"], set()):
                continue
            neighbor = brain.nodes[brain.index[other]] if other in brain.index else {}
            rows.append({"rel": str(edge.get("rel") or "related_to"), "direction": direction, "id": other,
                         "kind": neighbor.get("kind"), "title": neighbor.get("title")})
        rows.sort(key=lambda row: (row["direction"], row["rel"], row["id"]))
        return rows


def _arguments(arguments, allowed):
    unknown = sorted(set(arguments) - set(allowed))
    if unknown:
        raise ToolError(f"unknown argument(s): {', '.join(unknown)}")


def _string(arguments, name, *, required=False, limit=256):
    value = arguments.get(name)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ToolError(f"{name} must be a non-empty string of at most {limit} characters")
    return value


def _integer(arguments, name, default, maximum):
    value = arguments.get(name, default)
    if type(value) is not int or not 1 <= value <= maximum:
        raise ToolError(f"{name} must be an integer from 1 to {maximum}")
    return value


def _record_entry(node, matched=None):
    paths = access_gate.node_paths(node)
    entry = {"type": "record", "id": node["id"], "kind": node.get("kind"), "title": node.get("title"),
             "summary": _summary(node.get("text")), "source": paths[0] if paths else None}
    if matched is not None:
        entry["matched"] = matched
    return entry


def search_records(view, arguments):
    _arguments(arguments, ("query", "kind", "limit"))
    query = _string(arguments, "query", required=True)
    kind = _string(arguments, "kind", limit=64)
    limit = _integer(arguments, "limit", 10, 50)
    wanted = set(terms(query))
    if not 1 <= len(wanted) <= 32:
        raise ToolError("query needs between 1 and 32 words")
    kind_key = _fold(kind) if kind else None
    brain, ranked = view.brain, []
    if view.records_allowed and kind_key != DOCUMENT_KIND:
        for row, (matched, score) in brain.record_terms.search(wanted).items():
            node = brain.nodes[row]
            if (kind_key and _fold(node.get("kind")) != kind_key) or not view.visible(row):
                continue
            public_node = view.node(node["id"])
            ranked.append((-len(matched), -score, node["id"], ("record", row),
                           _record_entry(public_node, matched)))
    if view.documents_allowed and kind_key in (None, DOCUMENT_KIND):
        hits = brain.document_terms.search(wanted)
        for row in view.documents(hits):
            item, (matched, score) = brain.documents[row], hits[row]
            ranked.append((-len(matched), -score, item["path"], ("document", row), {
                "type": "document", "path": item["path"], "title": str(item.get("title") or ""),
                "summary": _summary(str(item.get("summary") or "")), "matched": matched}))
    ranked.sort(key=lambda row: row[:4])
    return {"query": query, "total": len(ranked), "matches": [row[4] for row in ranked[:limit]]}


def _read_document(view, path):
    brain, gate = view.brain, view.gate
    clean = safe_doc_path(path, brain.doc_roots)
    if clean is None:
        raise ToolError("path must be a plain path inside the brain (no absolute paths, '..' or dot-directories) "
                        "with a supported extension (.md .json .txt .py .js .toml .html .css)")
    missing = f"No readable document at {clean}."
    if not gate.can_read(clean, view.email):
        raise ToolError(missing)
    if view.scoped and (clean in _SERVER_ONLY or clean in access_gate.FILTERED_ARTIFACTS):
        raise ToolError(f"{clean} is served to you only as a filtered view; read its records with "
                        "search_records, read_record (by id) or list_definitions instead.")
    try:
        raw = _read_raw(brain.root, clean, max_bytes=MAX_DOC_BYTES)
    except (OSError, ValueError):
        raise ToolError(missing) from None
    view.observe_document_artifact(clean, raw)
    text = raw.decode("utf-8", errors="replace")
    if clean.endswith(".json"):
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        # Unparseable JSON is still checked, as text, for a reader with path rules.
        if view.scoped and not gate.artifact_safe_for(clean, text if data is None else data, view.email):
            raise ToolError(missing)
        if clean == "client.config.json" and isinstance(data, dict) and "access" in data:
            # Owner lists and restricted paths are server-only, for owners too.
            text = json.dumps({k: v for k, v in data.items() if k != "access"}, indent=2, ensure_ascii=False)
    if len(text) > brain.max_doc_chars:
        text = text[:brain.max_doc_chars] + f"\n\n[truncated: {len(text)} characters in total]"
    return text


def read_record(view, arguments):
    _arguments(arguments, ("id", "path"))
    if ("id" in arguments) == ("path" in arguments):
        raise ToolError("give exactly one of id or path")
    if "path" in arguments:
        if not view.read_doc_allowed:
            raise ToolError("reading documents is not available to this caller")
        return _read_document(view, _string(arguments, "path", required=True, limit=512))
    record_id = _string(arguments, "id", required=True, limit=512)
    if not view.records_allowed:
        raise ToolError("reading records is not available to this caller")
    node = view.node(record_id)
    if node is None:
        raise ToolError(f"No readable record has the id {record_id!r}.")
    rows = view.relationships(record_id)
    return {"record": node, "relationships": rows[:MAX_RELATIONSHIPS], "relationshipCount": len(rows)}


def list_definitions(view, arguments):
    _arguments(arguments, ("query", "limit"))
    query = _string(arguments, "query")
    limit = _integer(arguments, "limit", 50, 200)
    key = _fold(query) if query else None

    def wanted(*texts):
        return key is None or any(key in _fold(text) for text in texts)

    brain, terms_out, metrics_out = view.brain, [], []
    definitions = (brain.nodes[row] for row in brain.definition_rows if view.visible(row))
    for node in sorted(definitions, key=lambda n: (_fold(n.get("title") or n["id"]), n["id"])):
        aliases = _aliases(node)
        if not wanted(node.get("title"), node.get("text"), *aliases):
            continue
        name = "term" if node["kind"] == TERM_KIND else "name"
        entry = {"id": node["id"], name: node.get("title"), "definition": node.get("text"), "aliases": aliases}
        (terms_out if node["kind"] == TERM_KIND else metrics_out).append(entry)
    counts = {}
    for node in view.nodes:
        if isinstance(node.get("kind"), str):
            counts[node["kind"]] = counts.get(node["kind"], 0) + 1
    kinds_out = []
    for kind in brain.kinds:
        if not view.kind_visible(kind) or not wanted(kind["id"], kind.get("title"), kind.get("description")):
            continue
        node_kinds = kind.get("node") if isinstance(kind.get("node"), list) else [kind.get("node")]
        node_kinds = [n for n in node_kinds if isinstance(n, str)]
        kinds_out.append({"id": kind["id"], "title": kind.get("title"), "description": kind.get("description"),
                          "recordKinds": node_kinds, "records": sum(counts.get(n, 0) for n in node_kinds)})
    return {"terms": terms_out[:limit], "metrics": metrics_out[:limit], "kinds": kinds_out,
            "counts": {"terms": len(terms_out), "metrics": len(metrics_out), "kinds": len(kinds_out)}}


def resolve_metric(view, arguments):
    _arguments(arguments, ("name",))
    name = _string(arguments, "name", required=True).strip()
    metrics = view.metrics()
    found = [node for node in metrics if node["id"] == name]
    if not found:
        key = _fold(name)
        found = [node for node in metrics if _fold(node.get("title")) == key
                 or key in [_fold(alias) for alias in _aliases(node)]]
    if len(found) == 1:
        rows = view.relationships(found[0]["id"])
        return {"metric": view.node(found[0]["id"]) or found[0],
                "relationships": rows[:MAX_RELATIONSHIPS], "relationshipCount": len(rows)}
    if found:
        return {"candidates": [_record_entry(view.node(node["id"]) or node)
                                for node in sorted(found, key=lambda n: n["id"])],
                "note": f"{len(found)} metrics answer to {name!r}; resolve one by its id."}
    wanted = set(terms(name))
    near = sorted(((-len(m), -s, node["id"], node) for node in metrics
                   for m, s in [score_record(node, wanted)] if m), key=lambda row: row[:3])[:5]
    hint = "; ".join(row[2] + (f" ({row[3]['title']})" if isinstance(row[3].get("title"), str) else "")
                     for row in near)
    raise ToolError(f"No metric named {name!r}." + (f" Closest: {hint}." if hint else ""))


def run_metric(view, arguments):
    _arguments(arguments, ("name", "dimensions", "filters", "grain", "limit"))
    name = _string(arguments, "name", required=True).strip()
    metrics = view.metrics()
    found = [node for node in metrics if node["id"] == name]
    if not found:
        key = _fold(name)
        found = [node for node in metrics if _fold(node.get("title")) == key
                 or key in [_fold(alias) for alias in _aliases(node)]]
    if len(found) != 1:
        if found:
            raise ToolError("Metric name is ambiguous; run one by its id: " + ", ".join(n["id"] for n in found))
        raise ToolError(f"No metric named {name!r}.")
    metric = found[0]
    if view.native_adopted and (view.native_authorize is None or not view.native_authorize()):
        raise ToolError("native reader mapping is unavailable or no longer current")
    rows = view.relationships(metric["id"])
    outgoing = [row for row in rows if row["direction"] == "out"]
    def linked(relation):
        return [row["id"] for row in outgoing if row["rel"] == relation]
    source_ids, entity_ids = linked("backed_by"), linked("measures")
    data = metric.get("data") if isinstance(metric.get("data"), dict) else {}
    datasource = data.get("datasource") if isinstance(data.get("datasource"), dict) else {}
    expected_source = "source:" + record_slug(datasource.get("id", ""))
    if source_ids != [expected_source] or len(entity_ids) != 1:
        raise ToolError("Metric has no unique, readable source and entity binding.")
    entity = view.node(entity_ids[0])
    if not entity or entity.get("kind") != "Entity" or (entity.get("data") or {}).get("name") != data.get("entity"):
        raise ToolError("Metric's source entity is missing or differs from its reviewed definition.")
    source = view.node(source_ids[0])
    if not source or source.get("kind") != "Source":
        raise ToolError("Metric's bound source is not readable.")
    field_nodes = {}
    for row in view.relationships(entity["id"]):
        if row["direction"] != "out" or row["rel"] != "has_field":
            continue
        field = view.node(row["id"])
        field_data = field.get("data") if isinstance(field, dict) else None
        if field and field.get("kind") == "Field" and isinstance(field_data, dict) \
                and isinstance(field_data.get("name"), str):
            field_nodes[field_data["name"]] = field
    if not field_nodes:
        raise ToolError("Metric's bound source entity has no readable catalog fields.")
    for relation, names in (("uses_measure", [data.get("measure")]),
                            ("has_dimension", [d.get("field") for d in data.get("dimensions", [])
                                               if isinstance(d, dict)]),
                            ("filterable_by", [f.get("field") for f in data.get("filters", [])
                                               if isinstance(f, dict)]),
                            ("groups_by_time", [data.get("grain", {}).get("field")
                                                if isinstance(data.get("grain"), dict) else None])):
        names = [name for name in names if name is not None]
        linked_ids = set(linked(relation))
        if any(name not in field_nodes or field_nodes[name]["id"] not in linked_ids for name in names):
            raise ToolError("Metric's field relationships do not match its reviewed definition.")
    try:
        brain_config = view.brain.config.get("brain") if isinstance(view.brain.config.get("brain"), dict) else {}
        metric_executor.authorize_metric_reader(view.native_root, view.brain.config,
                                                brain_config.get("authority"), view.email, metric,
                                                trusted_actor=view.native_actor)
        databases = metric_executor.source_bindings()
        database = databases.get(datasource.get("id"))
        if not database:
            raise metric_executor.MetricExecutionError("metric datasource is not configured on this host")
        result = metric_executor.execute_metric(
            metric, {k: v for k, v in arguments.items() if k != "name"},
            entity=data["entity"], fields=field_nodes, source_node=source_ids[0], database=database,
            projection_root=view.brain.root, authority=brain_config.get("authority"))
        # The query is bounded but still takes time. Recheck operator mapping,
        # live native access and canonical revision before releasing its rows.
        metric_executor.authorize_metric_reader(view.native_root, view.brain.config,
                                                brain_config.get("authority"), view.email, metric,
                                                trusted_actor=view.native_actor)
        if view.native_adopted and (not callable(view.native_authorize) or not view.native_authorize()):
            raise metric_executor.MetricExecutionError("native reader mapping changed while the metric was executing")
        result["relationships"] = rows[:MAX_RELATIONSHIPS]
        return result
    except (KeyError, TypeError, metric_executor.MetricExecutionError) as exc:
        raise ToolError(str(exc)) from exc


def propose_change(view, arguments):
    _arguments(arguments, ("change",))
    if view.propose_change is None:
        raise ToolError("Proposing changes is not enabled for this caller.")
    change = arguments.get("change")
    if not isinstance(change, dict):
        raise ToolError("change must be a learned-change/v1 object")
    try:
        return view.propose_change(change).decode("utf-8")
    except (StoreError, OSError, ValueError, TypeError, KeyError) as exc:
        raise ToolError(str(exc)) from exc


def read_correction_basis(view, arguments):
    _arguments(arguments, ("id",))
    identity = _string(arguments, "id", required=True, limit=512)
    if view.correction_basis is None or view.propose_change is None:
        raise ToolError("Reading correction bases is not enabled for this caller.")
    try:
        return view.correction_basis(identity)
    except (StoreError, OSError, ValueError, TypeError, KeyError) as exc:
        raise ToolError("The complete correction basis is unavailable; refresh the record or host grants.") from exc


HANDLERS = {"search_records": search_records, "read_record": read_record,
            "list_definitions": list_definitions, "resolve_metric": resolve_metric, "run_metric": run_metric,
            "propose_change": propose_change, "read_correction_basis": read_correction_basis}


def _result(rid, result):
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _error(rid, code, message):
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def _instructions(brain, view):
    metric = " and resolve_metric for definitions or run_metric for a governed result" \
        if "resolve_metric" in view.tools() and "run_metric" in view.tools() else ""
    proposal = " It can also submit a change for independent review; this never changes canon directly." \
        if "propose_change" in view.tools() else ""
    if view.native_adopted:
        return (f"{brain.name} is a Mimwell brain. Search and read records allowed by its current native policy, "
                f"and use list_definitions for the visible vocabulary and record kinds{metric}. "
                f"Cite record ids.{proposal}")
    return (f"{brain.name} is a Mimwell brain: typed records, documents and definitions. Find with search_records, "
            f"read with read_record, use list_definitions for its vocabulary and record kinds{metric}. "
            f"Cite record ids and document paths.{proposal}")


def _tool_description(name, view, *, structured_citations=False, protocol_version=None,
                      native_citations_v2=False):
    if native_citations_v2 and not view.native_adopted:
        raise ValueError("Native citation v2 requires a native view")
    tool = deepcopy({"name": name, **TOOLS[name]})
    if view.native_adopted and name == "search_records":
        tool["description"] = ("Search records the current native authority policy allows you to read. An optional "
                               "kind filter narrows the visible record categories.")
    if view.native_adopted and name == "read_record":
        tool["description"] = "Read one current native-authority record by its id, with allowed relationships."
        tool["inputSchema"]["properties"].pop("path", None)
        tool["inputSchema"].pop("oneOf", None)
        tool["inputSchema"]["required"] = ["id"]
    if name == "propose_change":
        tool["annotations"] = {"readOnlyHint": False, "destructiveHint": False,
                               "idempotentHint": False, "openWorldHint": False}
    else:
        tool["annotations"] = dict(_READ_ONLY)
    if (structured_citations and protocol_version == LATEST_PROTOCOL
            and name in ("search_records", "read_record", "list_definitions", "resolve_metric")):
        from mcp_citations import output_schema

        authority_view = "native-adopted" if view.native_adopted else "compiled"
        tool["outputSchema"] = output_schema(name, authority_view)
    if native_citations_v2 and protocol_version == LATEST_PROTOCOL and name in (
            "search_records", "read_record", "list_definitions", "resolve_metric"):
        from mcp_citations import native_output_schema
        tool["outputSchema"] = native_output_schema(name)
    return tool


def call_tool(view, params, *, structured_citations=False, protocol_version=None,
              public_origin=None, link_identity=False, native_citations_v2=False,
              native_citation_route=None, native_citation_revalidate=None):
    """tools/call: (result, None) or (None, JSON-RPC error)."""
    if native_citations_v2 and (not view.native_adopted or params.get("name") not in {
            "search_records", "read_record", "list_definitions", "resolve_metric"}):
        return None, (-32602, "Requested native read citation contract is unavailable")
    name, arguments = params.get("name"), params.get("arguments")
    arguments = {} if arguments is None else arguments
    if not isinstance(name, str) or name not in view.tools():
        return None, (-32602, f"Unknown tool: {name}")
    if not isinstance(arguments, dict):
        return None, (-32602, "arguments must be an object")
    try:
        value = HANDLERS[name](view, arguments)
    except ToolError as exc:
        return {"content": [{"type": "text", "text": f"Error: {exc}"}], "isError": True}, None
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    result = {"content": [{"type": "text", "text": text}], "isError": False}
    if native_citations_v2 and protocol_version == LATEST_PROTOCOL and name in (
            "search_records", "read_record", "list_definitions", "resolve_metric"):
        from mcp_citations import StructuredResultUnavailable, native_structured_result
        try:
            result["structuredContent"] = native_structured_result(
                view, name, value, text, route=native_citation_route,
                revalidate=native_citation_revalidate)
        except StructuredResultUnavailable:
            return {"content": [{"type": "text", "text": "Error: native citation result is unavailable."}],
                    "isError": True}, None
        return result, None
    if (structured_citations and protocol_version == LATEST_PROTOCOL
            and name in ("search_records", "read_record", "list_definitions", "resolve_metric")):
        from mcp_citations import StructuredResultUnavailable, structured_result

        document_path = arguments.get("path") if name == "read_record" else None
        document_evidence = view.artifact_evidence.get(document_path) if isinstance(document_path, str) else None
        document_evidence = dict(document_evidence) if isinstance(document_evidence, Mapping) else None
        try:
            structured = structured_result(
                view, name, value, text, public_origin=public_origin,
                link_identity=link_identity,
                document_path=document_path, document_evidence=document_evidence,
            )
        except StructuredResultUnavailable:
            # An opted-in success must satisfy the outputSchema advertised by
            # tools/list. Report the bounded-output refusal as a tool error rather
            # than returning a successful content-only response.
            return {"content": [{"type": "text",
                                  "text": "Error: tool result cannot fit the structured output limits."}],
                    "isError": True}, None
        result["structuredContent"] = structured
    return result, None


def dispatch(brain, view, message, *, protocol_version=None, structured_citations=False,
             public_origin=None, link_identity=False, native_citations_v2=False,
             native_citation_route=None, native_citation_revalidate=None):
    """One JSON-RPC request object (already validated) -> its JSON-RPC reply."""
    rid, method, params = message["id"], message["method"], message.get("params", {})
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return _error(rid, -32602, "params must be an object")
    selected_native_v2 = False
    metadata = params.get("_meta")
    if isinstance(metadata, dict) and "mimwell/citationContract" in metadata:
        selected = metadata["mimwell/citationContract"]
        if selected not in ("1", "2"):
            return _error(rid, -32602, "Requested citation contract is unavailable")
        if selected == "2":
            chosen = protocol_version
            if method == "initialize":
                requested = params.get("protocolVersion")
                chosen = requested if requested in PROTOCOL_VERSIONS else LATEST_PROTOCOL
            if (not native_citations_v2 or not view.native_adopted or chosen != LATEST_PROTOCOL
                    or not isinstance(native_citation_route, dict)
                    or not callable(native_citation_revalidate)):
                return _error(rid, -32602, "Requested citation contract is unavailable")
            selected_native_v2 = True
    if method == "initialize":
        requested = params.get("protocolVersion")
        version = requested if requested in PROTOCOL_VERSIONS else LATEST_PROTOCOL
        initialized = {"contract": public_status.CONTRACT_VERSION,
                       "protocolVersion": version, "capabilities": {"tools": {"listChanged": False}},
                       "serverInfo": {"name": SERVER_NAME, "title": brain.name, "version": brain.version},
                       "instructions": _instructions(brain, view)}
        if structured_citations and version == LATEST_PROTOCOL:
            initialized["toolsContract"] = public_status.TOOLS_CONTRACT_VERSION
            initialized["citationContract"] = public_status.CITATION_CONTRACT_VERSION
            initialized["citationAuthorityViews"] = ["compiled"]
        if selected_native_v2:
            initialized["toolsContract"] = "2"
            initialized["citationContract"] = "mimwell-mcp-citation-result/v2"
            initialized["citationAuthorityViews"] = ["native-adopted"]
            initialized["instructions"] = (
                "Explicit native citation contract v2 selects four existing read tools. "
                "It does not expose proposal or write tools; each request must select v2.")
        return _result(rid, initialized)
    if method == "ping":
        return _result(rid, {})
    if method == "tools/list":
        return _result(rid, {"tools": [_tool_description(
            name, view, structured_citations=structured_citations,
            protocol_version=protocol_version, native_citations_v2=selected_native_v2)
            for name in view.tools()
            if not selected_native_v2 or name in {
                "search_records", "read_record", "list_definitions", "resolve_metric"}]})
    if method == "tools/call":
        if selected_native_v2 and params.get("name") not in {
                "search_records", "read_record", "list_definitions", "resolve_metric"}:
            return _error(rid, -32602, "Native citation contract v2 contains only read tools")
        result, error = call_tool(view, params, structured_citations=structured_citations,
                                  protocol_version=protocol_version, public_origin=public_origin,
                                  link_identity=link_identity, native_citations_v2=selected_native_v2,
                                  native_citation_route=native_citation_route,
                                  native_citation_revalidate=native_citation_revalidate)
        return _result(rid, result) if error is None else _error(rid, *error)
    return _error(rid, -32601, f"Method not found: {method}")


def _media_type(value):
    return value.split(";", 1)[0].strip().lower()


class MCPApplication:
    """WSGI transport for MCP plus per-request scoped static files."""

    def __init__(self, brain, *, verifier=None, token_header=TOKEN_HEADER, allowed_origins=(),
                 static_identity_source="anonymous", edge_identity_secret=None, proposals_enabled=False,
                 native_record_identity_source="off", native_record_edge_secret=None,
                 operations_root=None, operations_host="_internal/knowledge-operations.json",
                 public_only=False, status_declaration=None, structured_citations=False,
                 citation_public_origin=None, native_citations_v2=False):
        if not _HEADER_NAME.fullmatch(token_header or ""):
            raise ValueError("BRAIN_MCP_TOKEN_HEADER must be an HTTP header name of letters, digits and dashes")
        self.brain = brain
        self.verifier = verifier
        self.token_header = token_header
        self._token_key = "HTTP_" + token_header.upper().replace("-", "_")
        self.allowed_origins = frozenset(allowed_origins)
        if static_identity_source not in ("anonymous", "token", "edge"):
            raise ValueError("BRAIN_STATIC_IDENTITY_SOURCE must be anonymous, token or edge")
        if static_identity_source == "token" and verifier is None:
            raise ValueError("BRAIN_STATIC_IDENTITY_SOURCE=token requires brain token verification")
        if static_identity_source == "edge" and (verifier is not None or not edge_identity_secret):
            raise ValueError("edge identity requires no token verifier and BRAIN_STATIC_EDGE_SECRET")
        self.static_identity_source = static_identity_source
        self.edge_identity_secret = edge_identity_secret or ""
        if native_record_identity_source not in ("off", "token", "edge"):
            raise ValueError("BRAIN_NATIVE_RECORD_IDENTITY_SOURCE must be off, token or edge")
        if native_record_identity_source == "token" and verifier is None:
            raise ValueError("BRAIN_NATIVE_RECORD_IDENTITY_SOURCE=token requires brain token verification")
        if native_record_identity_source == "edge" and (not isinstance(native_record_edge_secret, str)
                                                           or not native_record_edge_secret
                                                           or len(native_record_edge_secret) > 4096):
            raise ValueError("edge native record identity requires BRAIN_NATIVE_RECORD_EDGE_SECRET")
        self.native_record_identity_source = native_record_identity_source
        self.native_record_edge_secret = native_record_edge_secret or ""
        self.proposals_enabled = proposals_enabled is True
        self.operations_root = Path(operations_root).absolute() if operations_root else brain.root
        self.operations_host = operations_host
        self.native_reader_file = "_internal/mcp-identities.json"
        self.typed_native_reader_file = "_internal/mcp-typed-readers.json"
        if public_only is not True and public_only is not False:
            raise ValueError("public_only must be a boolean")
        if public_only and brain.native_authority is not None:
            raise ValueError("adopted authorities require an authenticated native principal")
        self.public_only = public_only
        if structured_citations is not True and structured_citations is not False:
            raise ValueError("structured_citations must be a boolean")
        self.structured_citations = structured_citations
        self.citation_public_origin = None
        if structured_citations or native_citations_v2:
            from mcp_citations import validate_public_origin

            self.citation_public_origin = validate_public_origin(citation_public_origin)
        if type(native_citations_v2) is not bool:
            raise ValueError("native_citations_v2 must be a boolean")
        self.native_citations_v2 = native_citations_v2
        self._native_citation_binding = None
        if native_citations_v2:
            audience, issuer = getattr(verifier, "audience", None), getattr(verifier, "issuer", None)
            if (brain.native_authority in (None, False) or native_record_identity_source != "token"
                    or not brain_token._canonical_guid(audience) or not isinstance(issuer, str)
                    or not issuer or self.citation_public_origin is None):
                raise ValueError("Native citation v2 requires selected authority, token reader and bound brain origin")
            self._native_citation_binding = (brain, brain.root, verifier, issuer, audience,
                                            self.citation_public_origin)
        self.status_declaration = public_status.validate(status_declaration) if status_declaration is not None else None
        if self.proposals_enabled:
            # Validate the protected operator registration at startup. It is
            # outside the published asset tree in container deployments.
            load_host(self.operations_root, self.operations_host)

    def _native_citation_route(self, view):
        """One configured host binding; no caller-controlled origin or private root disclosure."""
        bound = self._native_citation_binding
        if (not self.native_citations_v2 or bound is None or self.brain is not bound[0]
                or view.brain is not bound[0] or self.brain.root != bound[1]
                or self.verifier is not bound[2] or self.verifier.issuer != bound[3]
                or self.verifier.audience != bound[4] or self.citation_public_origin != bound[5]
                or self.native_record_identity_source != "token"):
            return None
        return {"brainAudience": bound[4], "readerOrigin": bound[5], "readerPath": NATIVE_RECORD_PATH}

    def _proposal_for(self, email, environ):
        if not self.proposals_enabled or not email:
            return None
        try:
            host = load_host(self.operations_root, self.operations_host)
        except (StoreError, OSError, ValueError):
            return None
        actor = self._native_identity(email)
        if actor is None:
            return None
        if not any("proposal.propose" in entry["grants"].get(actor, [])
                   for entry in host["authorities"].values()):
            return None

        def authorize():
            current, refusal, _caller = self._identity(environ)
            mapped = None if refusal is not None else self._native_identity(current)
            return mapped if mapped == actor else None

        def submit(change):
            from learned_proposals import propose

            return propose(self.operations_root, self.operations_host, change,
                           actor=actor, authorize=authorize)

        submit.correction_basis = self._correction_basis_for(actor, authorize)
        return submit

    def _proposal_for_uid(self, uid):
        if not self.proposals_enabled or uid is None:
            return None
        try:
            host = load_host(self.operations_root, self.operations_host)
            actor = host["principalsByUid"].get(str(uid))
            mapped_actor = self._native_identity("", uid)
        except (StoreError, OSError, ValueError, TypeError):
            return None
        if not isinstance(actor, str) or not actor.strip() or actor != mapped_actor or not any(
                "proposal.propose" in entry["grants"].get(actor, [])
                for entry in host["authorities"].values()):
            return None

        def authorize():
            try:
                current = load_host(self.operations_root, self.operations_host)
                if (current["principalsByUid"].get(str(uid)) != actor
                        or self._native_identity("", uid) != actor or not any(
                        "proposal.propose" in entry["grants"].get(actor, [])
                        for entry in current["authorities"].values())):
                    return None
                return actor
            except (StoreError, OSError, ValueError, TypeError):
                return None

        def submit(change):
            from learned_proposals import propose

            return propose(self.operations_root, self.operations_host, change, actor=actor, authorize=authorize)

        submit.correction_basis = self._correction_basis_for(actor, authorize)
        return submit

    def _correction_basis_for(self, actor, authorize):
        """One unambiguous registered route to this brain, never a caller route."""
        authority = self.brain.native_authority
        if not isinstance(authority, dict):
            return None

        def selection():
            from knowledge_store import resolve_store_dsn
            from operation_backend import select_backend

            host = load_host(self.operations_root, self.operations_host)
            choices = [(name, entry) for name, entry in host['authorities'].items()
                       if entry['binding'] == authority['binding']
                       and {'record.get', 'proposal.propose'} <= set(entry['grants'].get(actor, []))]
            if len(choices) != 1 or authorize() != actor:
                raise StoreError('Correction basis route unavailable')
            name, entry = choices[0]
            _, target, driver, store_id, current = select_backend(self.operations_root, entry)
            dsn = resolve_store_dsn(self.brain.config, authority['store'])
            if driver == 'sqlite':
                if private_store_path(self.operations_root, dsn) != target:
                    raise StoreError('Correction basis route differs from the selected brain')
            elif store_id != authority['store'] or target != dsn:
                raise StoreError('Correction basis route differs from the selected brain')
            current()
            return name, host

        try:
            selected_name, selected_host = selection()
        except (StoreError, OSError, ValueError, TypeError, KeyError):
            return None

        def read(identity):
            from learned_proposals import correction_basis

            if selection() != (selected_name, selected_host):
                raise StoreError('Correction basis registration changed')
            result = correction_basis(self.operations_root, self.operations_host,
                                      selected_name, identity, binding=authority['binding'],
                                      actor=actor, authorize=authorize)
            if selection() != (selected_name, selected_host):
                raise StoreError('Correction basis registration changed')
            return result

        return read

    def _native_identity(self, email, uid=None):
        """Resolve only identities held by the operator-owned private host file."""
        authority = self.brain.native_authority
        if authority is False:
            return None
        try:
            path = private_path(self.operations_root, self.native_reader_file)
            with path.open("rb") as stream:
                raw = stream.read(64 * 1024 + 1)
            if len(raw) > 64 * 1024:
                raise ValueError("native reader registration exceeds its limit")
            mapping = decode(raw)
            if (not isinstance(mapping, dict) or set(mapping) != {
                    "format", "authorityBinding", "principalsByIdentity", "principalsByUid",
                    "fileSourcesByIdentity"}
                    or mapping["format"] != "mcp-identities/v1"
                    or mapping["authorityBinding"] != (authority.get("binding") if isinstance(authority, dict) else None)
                    or not isinstance(mapping["principalsByIdentity"], dict)
                    or not isinstance(mapping["principalsByUid"], dict)
                    or not isinstance(mapping["fileSourcesByIdentity"], dict)
                    or len(mapping["principalsByIdentity"]) > 1000
                    or len(mapping["principalsByUid"]) > 1000
                    or len(mapping["fileSourcesByIdentity"]) > 1000):
                raise ValueError("MCP identity registration does not match the selected authority")
            actor = None
            if isinstance(email, str) and email:
                actor = mapping["principalsByIdentity"].get(email.lower())
            if actor is None and uid is not None:
                actor = mapping["principalsByUid"].get(str(uid))
            if not isinstance(actor, str) or not actor.strip() or actor != actor.strip():
                return None
            return actor
        except (StoreError, OSError, ValueError, TypeError, KeyError):
            return None

    @staticmethod
    def _typed_native_subject(caller):
        """Return an app/agent namespace candidate, including malformed subjects."""
        subject = getattr(caller, "subject", None)
        if isinstance(subject, str) and (subject.startswith("app:") or subject.startswith("agent:")):
            return subject
        return None

    def _typed_native_identity(self, caller):
        """Map a verified non-person token to one existing native reader actor."""
        authority = self.brain.native_authority
        verifier = self.verifier
        subject = self._typed_native_subject(caller)
        expected_org = getattr(verifier, "expected_org_guid", None)
        binding = authority.get("binding") if isinstance(authority, dict) else None
        if (subject is None or not isinstance(authority, dict)
                or not isinstance(caller, brain_token.Caller)
                or not isinstance(verifier, brain_token.TokenVerifier)
                or verifier.typed_principals_enabled is not True
                or caller.contract != "1"
                or not isinstance(binding, str) or not binding
                or not brain_token._canonical_guid(expected_org)
                or not isinstance(caller.access_principals, tuple)
                or subject not in caller.access_principals
                or not _TYPED_NATIVE_SUBJECT.fullmatch(subject)):
            return None
        try:
            path = private_path(self.operations_root, self.typed_native_reader_file)
            with path.open("rb") as stream:
                raw = stream.read(MAX_TYPED_NATIVE_READERS_BYTES + 1)
            if len(raw) > MAX_TYPED_NATIVE_READERS_BYTES:
                raise ValueError("typed native reader registration exceeds its limit")
            mapping = decode(raw)
            if (not isinstance(mapping, dict) or set(mapping) != {
                    "format", "expectedOrgGuid", "authorityBinding", "principalsBySubject"}
                    or mapping["format"] != "mcp-typed-readers/v1"
                    or mapping["expectedOrgGuid"] != expected_org
                    or mapping["authorityBinding"] != binding
                    or not isinstance(mapping["principalsBySubject"], dict)
                    or len(mapping["principalsBySubject"]) > MAX_TYPED_NATIVE_READERS):
                raise ValueError("typed native reader registration does not match the selected authority")
            for configured_subject, actor in mapping["principalsBySubject"].items():
                if (not isinstance(configured_subject, str)
                        or not _TYPED_NATIVE_SUBJECT.fullmatch(configured_subject)
                        or not isinstance(actor, str) or not actor or actor != actor.strip()
                        or len(actor) > 200
                        or any(ord(char) < 0x20 or ord(char) == 0x7f for char in actor)):
                    raise ValueError("typed native reader registration has an invalid entry")
            return mapping["principalsBySubject"].get(subject)
        except (StoreError, OSError, ValueError, TypeError, KeyError, RecursionError):
            return None

    def _native_read_identity(self, email, uid=None, caller=None):
        """Resolve typed non-person reads separately from legacy email/UID readers."""
        typed_subject = self._typed_native_subject(caller)
        if typed_subject is not None:
            return self._typed_native_identity(caller)
        if (caller is not None and getattr(caller, "contract", None) == "1"
                and not isinstance(caller, brain_token.Caller)):
            return None
        return self._native_identity(email, uid)

    def _native_read(self, email, uid=None, *, caller=None):
        """Resolve a trusted host principal and restrict compiled rows to its live native view."""
        authority = self.brain.native_authority
        if authority is None:
            return None, None, None, None, {}, {}
        if authority is False:
            return None, frozenset(), {}, None, {}, {}
        actor = self._native_read_identity(email, uid, caller)
        if actor is None:
            return None, frozenset(), {}, None, {}, {}
        try:

            from knowledge_store import FileReference, authority_class, resolve_store_dsn, utcnow

            dsn = resolve_store_dsn(self.brain.config, authority["store"])
            adapter = authority_class(dsn)
            driver = adapter.dialect_class.driver if adapter is not FileReference else "files"
            if driver in ("files", "sqlite"):
                database = private_store_path(self.operations_root, dsn)
            else:
                database = dsn
            store = (adapter(database, expected_binding=authority["binding"]) if adapter is FileReference
                     else adapter(database, expected_binding=authority["binding"], readonly=True))
            try:
                if store.contract.authority != authority["store"]:
                    raise ValueError("configured native authority differs from the selected store")
                now = utcnow()
                if not callable(getattr(store, "read_snapshot", None)):
                    raise ValueError("native adapter has no bounded reader snapshot")
                snapshot = store.read_snapshot(actor, at=now, max_records=10000,
                                               max_body_bytes=16 * 1024 * 1024)
                live_nodes = {node["id"]: node for node in snapshot["graph"]["nodes"]}
                live_edge_keys = {_native_edge_key(edge) for edge in snapshot["graph"]["edges"]}
                native_edges = {}
                for edge in snapshot["graph"]["edges"]:
                    native_edges.setdefault(edge["source"], set()).add(_native_edge_key(edge))
                ids = set()
                relations = {}
                native_nodes = {}
                if self._typed_native_subject(caller) is not None:
                    allowed_files, file_edge_keys, file_basis = {}, set(), None
                else:
                    allowed_files, file_edge_keys, file_basis = self._file_source_graph(actor)
                candidate_ids, candidate_bytes = set(), 0
                for node in self.brain.nodes:
                    identity = node.get("id")
                    if identity in allowed_files and identity not in candidate_ids:
                        candidate_ids.add(identity)
                        candidate_bytes += len(identity.encode("utf-8"))
                        if len(candidate_ids) > 10000 or candidate_bytes > 5 * 1024 * 1024:
                            candidate_ids = None
                            break
                file_candidates = sorted(candidate_ids) if candidate_ids is not None else None
                owned_ids = _native_owned_ids(store, snapshot, file_candidates)
                for node in self.brain.nodes:
                    native_node = live_nodes.get(node["id"])
                    compiled = dict(node)
                    if native_node is not None:
                        if (isinstance(node.get("source"), str) and node["source"].startswith("app/projections/")
                                and "source" not in native_node):
                            compiled.pop("source", None)
                        data = compiled.get("data")
                        native_data = native_node.get("data") if isinstance(native_node.get("data"), dict) else {}
                        if (isinstance(data, dict) and "governance" in data
                                and "governance" not in native_data
                                and isinstance(node.get("source"), str)
                                and node["source"].startswith("app/projections/")):
                            data = dict(data)
                            data.pop("governance", None)
                            compiled["data"] = data
                        if compiled == native_node:
                            ids.add(node["id"])
                            native_nodes[node["id"]] = native_node
                            relations[node["id"]] = native_edges.get(node["id"], set())
                    elif owned_ids is not None and node["id"] not in owned_ids and node["id"] in allowed_files:
                        relative, file_node = allowed_files[node["id"]]
                        file_compiled = dict(node)
                        if file_compiled.get("source") == relative:
                            file_compiled.pop("source", None)
                        if file_compiled == file_node:
                            ids.add(node["id"])
                            native_nodes[node["id"]] = file_node
                for edge in self.brain.edges:
                    if edge["source"] in ids and edge["target"] in ids \
                            and (_native_edge_key(edge) in live_edge_keys
                                 or _native_edge_key(edge) in file_edge_keys):
                        relations.setdefault(edge["source"], set()).add(_native_edge_key(edge))
                revisions = snapshot["revisions"]
                policy_sha256 = snapshot["graph"].get("meta", {}).get("lifecycle", {}).get("policySha256")
                if (not isinstance(policy_sha256, str)
                        or not re.fullmatch(r"[a-f0-9]{64}", policy_sha256)):
                    raise ValueError("native snapshot has no valid policy fingerprint")
                basis_value = {"checkpoint": snapshot["checkpoint"], "revisions": revisions,
                               "policySha256": policy_sha256,
                               "ids": sorted(ids),
                               "relations": {key: sorted(value) for key, value in sorted(relations.items())},
                               "fileSources": file_basis}
                basis = hashlib.sha256(json.dumps(basis_value, sort_keys=True, separators=(",", ":"))
                                       .encode("utf-8")).hexdigest()
                return actor, frozenset(ids), relations, basis, native_nodes, revisions
            finally:
                store.close()
        except (OSError, ValueError, TypeError, KeyError, StoreError):
            # An adopted authority with missing or invalid host state is closed.
            return None, frozenset(), {}, None, {}, {}

    def _file_source_graph(self, actor):
        """Load exact nodes and edges from actor-specific, digest-pinned catalog files."""
        try:
            path = private_path(self.operations_root, self.native_reader_file)
            with path.open("rb") as stream:
                raw = stream.read(64 * 1024 + 1)
            if len(raw) > 64 * 1024:
                return {}, set(), None
            pins = decode(raw).get("fileSourcesByIdentity", {}).get(actor, {})
            if not isinstance(pins, dict) or len(pins) > 32:
                return {}, set(), None
            result, edges = {}, set()
            effective_pins = {}
            root = self.brain.root.resolve()
            for relative, digest in pins.items():
                if (not isinstance(relative, str) or relative.startswith("/") or ".." in relative.split("/")
                        or not relative.startswith("app/") or not isinstance(digest, str)
                        or not re.fullmatch(r"[a-f0-9]{64}", digest)):
                    continue
                try:
                    payload = _read_raw(root, relative, max_bytes=1024 * 1024)
                except (OSError, ValueError):
                    continue
                if not hmac.compare_digest(hashlib.sha256(payload).hexdigest(), digest):
                    continue
                effective_pins[relative] = digest
                document = decode(payload)
                rows = document.get("nodes") if isinstance(document, dict) else None
                file_edges = document.get("edges", []) if isinstance(document, dict) else None
                if (not isinstance(rows, list) or len(rows) > 10000 or not isinstance(file_edges, list)
                        or len(file_edges) > 50000):
                    continue
                for row in rows:
                    if isinstance(row, dict) and isinstance(row.get("id"), str):
                        if row["id"] in result and result[row["id"]] != (relative, row):
                            return {}, set(), None
                        result[row["id"]] = (relative, row)
                for edge in file_edges:
                    if (isinstance(edge, dict) and isinstance(edge.get("source"), str)
                            and isinstance(edge.get("target"), str) and isinstance(edge.get("rel"), str)):
                        edges.add(_native_edge_key(edge))
            pin_bytes = json.dumps(effective_pins, sort_keys=True, separators=(",", ":")).encode("utf-8")
            return result, edges, hashlib.sha256(pin_bytes).hexdigest()
        except (OSError, ValueError, TypeError, StoreError, KeyError):
            return {}, set(), None

    def _view(self, email, environ, *, uid=None, caller=None):
        typed_subject = self._typed_native_subject(caller)
        if typed_subject is not None:
            native_view = self._native_read(email, uid, caller=caller)
        else:
            native_view = self._native_read(email, uid)
        actor, native_ids, native_relations, basis, native_nodes, native_revisions = native_view
        def current():
            if self.brain.native_authority is False:
                return False
            if typed_subject is not None:
                _current_email, refusal, current_caller = self._identity(environ)
                if refusal is not None or current_caller != caller:
                    return False
                observed = self._native_read(email, uid, caller=caller)
                identity_still_matches = self._native_read_identity(email, uid, caller) == actor
            else:
                observed = self._native_read(email, uid)
                identity_still_matches = self._native_identity(email, uid) == actor
            return observed[0] == actor and observed[1] == native_ids and observed[2] == native_relations \
                and observed[3] == basis and observed[4] == native_nodes and observed[5] == native_revisions \
                and identity_still_matches
        # A typed app/agent principal never borrows proposal grants through an
        # optional email claim or a matching legacy email mapping.
        proposal = None if typed_subject is not None else self._proposal_for(email, environ)
        return View(self.brain, email, propose_change=proposal,
                    correction_basis=getattr(proposal, 'correction_basis', None),
                    native_actor=actor, native_ids=native_ids, native_relations=native_relations,
                    native_nodes=native_nodes,
                    native_revisions=native_revisions,
                    native_root=self.operations_root,
                    suppress_metric_execution=typed_subject is not None,
                    native_authorize=current
                    if self.brain.native_authority not in (None, False) and actor else None)

    def _stdio_view(self, uid):
        actor, native_ids, native_relations, basis, native_nodes, native_revisions = self._native_read("", uid)
        if self.brain.native_authority is None and actor is None:
            actor = self._native_identity("", uid)
        # A local UID is the trusted caller. Reuse its operator-mapped principal
        # for legacy path rules when that principal is also an email identity.
        identity = actor or ("" if self.public_only else "__mcp_unmapped__")
        def current():
            if self.brain.native_authority is False:
                return False
            observed = self._native_read("", uid)
            return observed[0] == actor and observed[1] == native_ids and observed[2] == native_relations \
                and observed[3] == basis and observed[4] == native_nodes and observed[5] == native_revisions \
                and self._native_identity("", uid) == actor
        proposal = self._proposal_for_uid(uid)
        return View(self.brain, identity, propose_change=proposal,
                    correction_basis=getattr(proposal, 'correction_basis', None),
                    native_actor=actor, native_ids=native_ids, native_relations=native_relations,
                    native_nodes=native_nodes,
                    native_revisions=native_revisions,
                    native_root=self.operations_root, identity_authorized=actor is not None or self.public_only,
                    native_authorize=current
                    if self.brain.native_authority not in (None, False) and actor else None)

    def _static_identity(self, environ):
        if self.static_identity_source == "token":
            return self._identity(environ)
        if self.static_identity_source != "edge":
            return "", None, None
        assertion = environ.get("HTTP_X_PORTAL_AUTH_ASSERTION", "")
        if not isinstance(assertion, str) or not hmac.compare_digest(assertion, self.edge_identity_secret):
            return "", None, None
        email = environ.get("HTTP_X_AUTH_REQUEST_EMAIL", "")
        return email.strip().lower() if isinstance(email, str) else "", None, None

    def _native_record_identity(self, environ):
        """Resolve identity for the opt-in native HTML reader, independently of static files."""
        if self.native_record_identity_source == "token":
            email, refusal, caller = self._identity(environ)
            return (email, caller) if refusal is None else (None, None)
        if self.native_record_identity_source != "edge":
            return None, None
        assertion = environ.get("HTTP_X_PORTAL_AUTH_ASSERTION", "")
        email = environ.get("HTTP_X_AUTH_REQUEST_EMAIL", "")
        if (not isinstance(assertion, str)
                or not hmac.compare_digest(assertion, self.native_record_edge_secret)
                or not isinstance(email, str) or not email.strip()):
            return None, None
        return email.strip().lower(), None

    @staticmethod
    def _native_record_query(query):
        if not isinstance(query, str) or len(query) > 2048:
            return None
        try:
            values = parse_qsl(query, keep_blank_values=True, strict_parsing=True,
                               max_num_fields=2, encoding="utf-8", errors="strict")
        except (ValueError, UnicodeError):
            return None
        if len(values) != 2 or {key for key, _ in values} != {"id", "revision"}:
            return None
        result = dict(values)
        try:
            identity_bytes = result["id"].encode("utf-8", errors="strict")
            revision_bytes = result["revision"].encode("utf-8", errors="strict")
        except UnicodeError:
            return None
        if (not identity_bytes or len(identity_bytes) > 512
                or not revision_bytes or len(revision_bytes) > 256
                or any(ord(char) < 0x20 or ord(char) == 0x7f
                       for char in result["id"] + result["revision"])):
            return None
        return result

    @staticmethod
    def _citation_query(query):
        if not isinstance(query, str) or len(query) > 4096:
            return None
        try:
            values = parse_qsl(query, keep_blank_values=True, strict_parsing=True,
                               max_num_fields=5, encoding="utf-8", errors="strict")
        except (ValueError, UnicodeError):
            return None
        keys = [key for key, _ in values]
        if (len(set(keys)) != len(keys)
                or set(keys) not in ({"type", "path", "target", "revision"},
                                    {"type", "path", "target", "revision", "pointer"})):
            return None
        result = dict(values)
        if (result["type"] not in ("compiled-record", "document", "schema-kind")
                or not result["path"] or len(result["path"].encode("utf-8")) > 512
                or not result["target"] or len(result["target"].encode("utf-8")) > 512
                or not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", result["revision"])
                or (result["type"] == "schema-kind" and "pointer" not in result)
                or (result["type"] != "schema-kind" and "pointer" in result)
                or ("pointer" in result and not re.fullmatch(r"/kinds/(?:0|[1-9][0-9]*)", result["pointer"]))
                or any(ord(char) < 0x20 or ord(char) == 0x7f
                       for value in result.values() for char in value)):
            return None
        return result

    def _citation(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET")
        head = method == "HEAD"
        if method not in ("GET", "HEAD"):
            return self._respond(start_response, 405, b"Method not allowed\n", "text/plain; charset=utf-8",
                                 [("Allow", "GET, HEAD")])
        if (not self.structured_citations or self.brain.native_authority is not None
                or self.citation_public_origin is None):
            return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8", head=head)
        query = self._citation_query(environ.get("QUERY_STRING", ""))
        email, refusal, caller = self._static_identity(environ)
        if query is None or refusal is not None:
            return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8", head=head)
        from mcp_citations import _compiled, _entry, render_html

        scope = self.brain.gate.verified_identity(caller) if caller is not None else nullcontext()
        with scope:
            view = View(self.brain, email)
            receipt = _compiled(view)
            if receipt is None or not hmac.compare_digest(receipt["commit"], query["revision"]):
                return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8", head=head)
            title = kind = text = None
            data = None
            resource_type, path, target = query["type"], query["path"], query["target"]
            if resource_type == "compiled-record":
                if (path != "app/brain.json" or not view.records_allowed
                        or _entry(view, path) is None or not view.visible_id(target)):
                    return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8", head=head)
                data = view.node(target)
                if not isinstance(data, dict):
                    return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8", head=head)
                title = data.get("title") if isinstance(data.get("title"), str) and data["title"] else target
                kind = data.get("kind") if isinstance(data.get("kind"), str) else "Record"
                text = data.get("text") if isinstance(data.get("text"), str) else ""
            elif resource_type == "document":
                if path != target or not view.read_doc_allowed:
                    return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8", head=head)
                try:
                    text = _read_document(view, path)
                except ToolError:
                    return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8", head=head)
                if _entry(view, path) is None:
                    return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8", head=head)
                item = next((entry for entry in self.brain.documents if entry.get("path") == path), {})
                title, kind, data = str(item.get("title") or path), "document", {"path": path}
            else:
                if path != "brain-schema.json" or not self.brain.gate.can_read(path, email):
                    return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8", head=head)
                first_raw = getattr(self.brain, "_brain_schema_raw", None)
                kinds = getattr(self.brain, "_schema_kinds", None)
                pointer = query.get("pointer", "")
                match = re.fullmatch(r"/kinds/(0|[1-9][0-9]*)", pointer)
                if not isinstance(first_raw, bytes) or not isinstance(kinds, tuple) or match is None:
                    return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8", head=head)
                entry = _entry(view, path)
                if (entry is None or entry.get("size") != len(first_raw)
                        or not hmac.compare_digest(entry.get("sha256", ""), hashlib.sha256(first_raw).hexdigest())):
                    return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8", head=head)
                index = int(match.group(1))
                if index >= len(kinds):
                    return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8", head=head)
                selected = kinds[index]
                if (not isinstance(selected, dict) or selected.get("id") != target
                        or not any(selected is candidate for candidate in self.brain.kinds)
                        or not view.kind_visible(selected)):
                    return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8", head=head)
                title = selected.get("title") if isinstance(selected.get("title"), str) else target
                kind, text, data = "Schema kind", str(selected.get("description") or ""), selected
            payload = render_html(title, kind, text, data)
            if payload is None:
                return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8", head=head)
        return self._respond(start_response, 200, payload, "text/html; charset=utf-8",
                             [("Content-Security-Policy", "default-src 'none'; base-uri 'none'; "
                               "form-action 'none'; frame-ancestors 'none'; object-src 'none'; style-src 'none'"),
                              ("Referrer-Policy", "no-referrer")], head=head)

    @staticmethod
    def _native_record_html(record):
        # Show only the selected authorized record. Escaping the serialized value
        # makes every record-controlled string inert, including markup and URLs.
        encoded = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        title = record.get("title") if isinstance(record.get("title"), str) and record["title"] else record["id"]
        kind = record.get("kind") if isinstance(record.get("kind"), str) else "Record"
        text = record.get("text")
        content = record.get("content")
        if not isinstance(text, str) and isinstance(content, dict):
            text = content.get("text")
        if not isinstance(text, str):
            text = ""
        document = ("<!doctype html><html><head><meta charset=\"utf-8\"><title>" + html.escape(title)
                    + "</title></head><body><main><h1>" + html.escape(title) + "</h1><p>"
                    + html.escape(kind) + "</p><p>" + html.escape(text) + "</p><details><summary>Record data</summary><pre>"
                    + html.escape(encoded) + "</pre></details></main></body></html>").encode("utf-8")
        if len(document) > MAX_NATIVE_RECORD_HTML_BYTES:
            return None
        return document

    def _native_record(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET")
        head = method == "HEAD"
        if method not in ("GET", "HEAD"):
            return self._respond(start_response, 405, b"Method not allowed\n", "text/plain; charset=utf-8",
                                 [("Allow", "GET, HEAD")])
        if (self.native_record_identity_source == "off" or self.brain.native_authority in (None, False)):
            return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8", head=head)
        query = self._native_record_query(environ.get("QUERY_STRING", ""))
        email, caller = self._native_record_identity(environ)
        if query is None or email is None:
            return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8", head=head)
        scope = self.brain.gate.verified_identity(caller) if caller is not None else nullcontext()
        with scope:
            view = self._view(email, environ, caller=caller)
            identity = query["id"]
            revision = view.native_revisions.get(identity)
            record = view.node(identity) if view.records_allowed else None
            try:
                revision_matches = isinstance(revision, str) and hmac.compare_digest(
                    revision.encode("utf-8", errors="strict"), query["revision"].encode("utf-8", errors="strict"))
            except UnicodeError:
                revision_matches = False
            if (not revision_matches
                    or not isinstance(record, dict) or not callable(view.native_authorize)
                    or not view.native_authorize()):
                return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8", head=head)
            payload = self._native_record_html(record)
            if payload is None or not view.native_authorize():
                return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8", head=head)
        return self._respond(start_response, 200, payload, "text/html; charset=utf-8",
                             [("Content-Security-Policy", "default-src 'none'; base-uri 'none'; "
                               "form-action 'none'; frame-ancestors 'none'; object-src 'none'; style-src 'none'"),
                              ("Referrer-Policy", "no-referrer")], head=method == "HEAD")

    def _static_asset(self, path):
        """Read a published file without following symlinks or escaping BRAIN_ROOT."""
        if not path or any(part.startswith(".") for part in path.split("/")):
            raise FileNotFoundError(path)
        return _read_raw(self.brain.root, path, max_bytes=MAX_STATIC_BYTES)

    def _static_json(self, path, raw, email):
        gate = self.brain.gate
        try:
            data = decode(raw)
        except (ValueError, UnicodeError, RecursionError):
            # A filtered or generic JSON artifact that cannot be parsed cannot
            # be checked for path references. Fail closed for scoped readers.
            if path == "client.config.json" or gate.paths_enabled:
                raise FileNotFoundError(path) from None
            return raw

        if path == "client.config.json":
            return json.dumps(gate.filter_config(data, email), ensure_ascii=False).encode("utf-8")
        if not gate.paths_enabled or gate.is_owner(email):
            return raw
        if path in access_gate.FILTERED_ARTIFACTS:
            filtered = gate.filter_artifact(path, data, email)
        elif path == "app/brain-meta.json":
            graph = self.brain._json("app/brain.json")
            if not isinstance(graph, dict):
                raise FileNotFoundError(path)
            filtered = gate.filter_brain_meta(graph, email)
        elif path == "app/brain-manifest.json":
            graph = self.brain._json("app/brain.json")
            schema = self.brain._json("brain-schema.json")
            filtered = gate.filter_brain_manifest(data, graph, schema, email)
            if filtered is None:
                raise FileNotFoundError(path)
        elif path in ("activity.json", "app/activity.json"):
            filtered = self._filter_activity(data, email)
        else:
            if not gate.artifact_safe_for(path, data, email):
                raise FileNotFoundError(path)
            return raw
        return json.dumps(filtered, ensure_ascii=False).encode("utf-8")

    def _filter_activity(self, data, email):
        """Reader-safe recent activity, including prose from mixed-source commits."""
        gate, activity = self.brain.gate, []
        if not isinstance(data, list):
            return activity
        path_token = re.compile(r"[A-Za-z0-9_@%.~\-]+(?:[/\\][A-Za-z0-9_@%.~\-]+)+")
        file_token = re.compile(r"(^|[\s(\"'=:\[>])([A-Za-z0-9_.\-]+\.(?:md|markdown|txt|json|jsonl|ndjson|csv|sql|ya?ml|pdf|docx?|pptx?|xlsx?))(?=$|[\s)\"',;:\]<>?#])", re.IGNORECASE | re.ASCII)
        allow = gate.allow_for(email)

        def mask(text):
            if not isinstance(text, str):
                return text
            text = path_token.sub(lambda match: match.group(0) if allow(match.group(0)) and allow(re.sub(r"\.+$", "", match.group(0))) else "[restricted]", text)
            return file_token.sub(lambda match: match.group(0) if allow(match.group(2)) else match.group(1) + "[restricted]", text)

        for row in data:
            if not isinstance(row, dict):
                continue
            item = dict(row)
            files = item.get("files")
            restricted_source = isinstance(files, list) and any(
                isinstance(path, str) and path and not allow(path)
                for path in ((f if isinstance(f, str) else f.get("path") if isinstance(f, dict) else None) for f in files))
            if isinstance(files, list):
                item["files"] = [f for f in files if
                                  isinstance(f, str) and allow(f)
                                  or isinstance(f, dict) and (not isinstance(f.get("path"), str) or allow(f["path"]))
                                  or not isinstance(f, (str, dict))]
            if restricted_source:
                if not item["files"]:
                    continue
                item["title"] = "[restricted activity]"
                item.pop("body", None)
            for key in ("title", "body"):
                if key in item:
                    item[key] = mask(item[key])
            if gate.mentions_restricted(item, allow):
                item.pop("body", None)
            if gate.mentions_restricted(item, allow):
                continue
            activity.append(item)
        return activity

    def _static(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET")
        if method not in ("GET", "HEAD"):
            return self._respond(start_response, 405, b"Method not allowed\n", "text/plain; charset=utf-8",
                                 [("Allow", "GET, HEAD")])
        if self.brain.native_authority is not None:
            return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8",
                                 head=method == "HEAD")
        email, refusal, caller = self._static_identity(environ)
        if refusal is not None:
            status, body, extra = refusal
            payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
            return self._respond(start_response, status, payload, "application/json", extra)
        scope = self.brain.gate.verified_identity(caller) if caller is not None else nullcontext()
        with scope:
            return self._static_authorized(environ, start_response, email, method)

    def _static_authorized(self, environ, start_response, email, method):
        raw_path = environ.get("PATH_INFO", "")
        path = access_gate.normalize_path(raw_path)
        gate = self.brain.gate
        if path != "client.config.json" and not gate.can_read(path, email):
            return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8")
        trailing_slash = raw_path.endswith("/")
        if not path:
            candidates = ["index.html"]
        elif trailing_slash:
            candidates = [path.rstrip("/") + "/index.html"]
        else:
            candidates = [path, path + ".html", path + "/index.html"]
        clean, content = None, None
        for candidate in candidates:
            if candidate != "client.config.json" and not gate.can_read(candidate, email):
                continue
            try:
                content = self._static_asset(candidate)
                clean = candidate
                break
            except (OSError, ValueError):
                continue
        if clean is None:
            return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8")
        # Check the URL spelling and the actual alias selected by try_files: a
        # rule on `page.html` must also cover the `/page` alias.
        if clean != "client.config.json" and not gate.can_read(clean, email):
            return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8")
        if clean.lower().endswith(".json"):
            try:
                content = self._static_json(clean, content, email)
            except (OSError, ValueError):
                return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8")
        content_type = mimetypes.guess_type(clean)[0] or "application/octet-stream"
        extra = [("Vary", "X-Auth-Request-Email, X-Portal-Auth-Assertion, " + self.token_header)]
        return self._respond(start_response, 200, content, content_type, extra,
                             head=method == "HEAD")

    @staticmethod
    def _respond(start_response, status, body, content_type, extra=(), *, head=False):
        headers = [("Content-Type", content_type), ("Content-Length", str(len(body))),
                   ("Cache-Control", "private, no-store"), ("X-Content-Type-Options", "nosniff"), *extra]
        start_response(f"{status} {HTTPStatus(status).phrase}", headers)
        return [b"" if head else body]

    def _identity(self, environ):
        """(email, refusal, verified caller); the caller is host-internal only."""
        if self.verifier is None:
            if self.public_only:
                return "", None, None
            return None, self._unauthorized("this endpoint requires a verified identity or explicit public-only mode"), None
        token = environ.get(self._token_key)
        if not token:
            return None, self._unauthorized(f"send a brain read token in {self.token_header}"), None
        try:
            caller = self.verifier.verify(token)
        except brain_token.TokenError:
            return None, self._unauthorized("the brain read token is not valid for this brain"), None
        except brain_token.KeysUnavailable:
            return None, (503, _error(None, -32000, "Service unavailable: brain token keys cannot be fetched"),
                          [("Retry-After", "30")]), None
        return caller.email.lower(), None, caller

    def _unauthorized(self, detail):
        return (401, _error(None, -32000, f"Unauthorized: {detail}"),
                [("WWW-Authenticate", f'BrainToken realm="brain-mcp", header="{self.token_header}"')])

    def _handle(self, environ):
        if environ.get("PATH_INFO") != "/mcp":
            return 404, _error(None, -32000, "Not found"), []
        origin = environ.get("HTTP_ORIGIN")
        if origin is not None and origin not in self.allowed_origins:
            return 403, _error(None, -32000, "Forbidden: origin not allowed"), []
        # Bind the credential actually presented at initial verification. This
        # extra capture is used only by the explicitly selected native-v2 path.
        native_request_token = environ.get(self._token_key) if self.native_citations_v2 else None
        email, refusal, caller = self._identity(environ)
        if refusal is not None:
            return refusal
        if environ.get("REQUEST_METHOD") != "POST":
            return 405, _error(None, -32000, "Method not allowed: this endpoint takes POST"), [("Allow", "POST")]
        if _media_type(environ.get("CONTENT_TYPE", "")) != "application/json":
            return 415, _error(None, -32000, "Unsupported Media Type: Content-Type must be application/json"), []
        accept = environ.get("HTTP_ACCEPT")
        if accept and not any(_media_type(part) in ("application/json", "application/*", "*/*")
                              for part in accept.split(",")):
            return 406, _error(None, -32000, "Not Acceptable: this endpoint answers application/json"), []
        size = environ.get("CONTENT_LENGTH") or ""
        if not size:
            return 411, _error(None, -32000, "Length Required"), []
        if not re.fullmatch(r"[0-9]{1,20}", size):
            return 400, _error(None, -32600, "Invalid Content-Length"), []
        if int(size) > MAX_BODY_BYTES:
            return 413, _error(None, -32000, "Payload Too Large"), []
        raw = self._read(environ["wsgi.input"], int(size))
        if raw is None:
            return 400, _error(None, -32600, "Incomplete request body"), []
        try:
            message = decode(raw)
        except ValueError:
            return 400, _error(None, -32700, "Parse error"), []
        if isinstance(message, list):
            return 400, _error(None, -32600, "Invalid Request: JSON-RPC batches are not supported"), []
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return 400, _error(None, -32600, "Invalid Request"), []
        method = message.get("method")
        if method == "initialize":
            pass
        elif (version := environ.get("HTTP_MCP_PROTOCOL_VERSION")) is not None and version not in PROTOCOL_VERSIONS:
            return 400, _error(None, -32000, "Bad Request: unsupported MCP-Protocol-Version "
                                             f"(supported: {', '.join(PROTOCOL_VERSIONS)})"), []
        if "method" not in message:
            # A response to a request this server never sends; acknowledged, ignored.
            ok = "id" in message and ("result" in message or "error" in message)
            return (202, None, []) if ok else (400, _error(None, -32600, "Invalid Request"), [])
        if not isinstance(method, str):
            return 400, _error(None, -32600, "Invalid Request"), []
        if "id" not in message:
            return 202, None, []
        rid = message["id"]
        if not isinstance(rid, _REQUEST_ID) or isinstance(rid, bool):
            return 400, _error(None, -32600, "Invalid Request: id must be a string or a number"), []
        scope = self.brain.gate.verified_identity(caller) if caller is not None else nullcontext()
        with scope:
            view = self._view(email, environ, caller=caller)
            requested_protocol = environ.get("HTTP_MCP_PROTOCOL_VERSION")
            if method == "initialize" and requested_protocol not in PROTOCOL_VERSIONS:
                requested_protocol = message.get("params", {}).get("protocolVersion") \
                    if isinstance(message.get("params"), dict) else None
            native_route = None
            native_current = None
            params = message.get("params")
            metadata = params.get("_meta") if isinstance(params, dict) else None
            if self.native_citations_v2 and isinstance(metadata, dict) and metadata.get("mimwell/citationContract") == "2":
                native_route = self._native_citation_route(view)
                def native_current():
                    # Legacy email/user native views recheck the native mapping,
                    # not the token. Native-v2 must reverify every token family
                    # with the current verifier/clock before and after capture.
                    if (native_route is None or self._native_citation_route(view) != native_route
                            or environ.get(self._token_key) != native_request_token):
                        return False
                    current_email, current_refusal, current_caller = self._identity(environ)
                    return (current_refusal is None and current_email == email
                            and current_caller == caller and callable(view.native_authorize)
                            and view.native_authorize() is True
                            and environ.get(self._token_key) == native_request_token
                            and self._native_citation_route(view) == native_route)
            response = dispatch(
                self.brain, view, message, protocol_version=requested_protocol,
                structured_citations=self.structured_citations,
                public_origin=self.citation_public_origin,
                link_identity=(self.public_only and self.static_identity_source in ("anonymous", "edge")),
                native_citations_v2=self.native_citations_v2, native_citation_route=native_route,
                native_citation_revalidate=native_current,
            )
        if view.native_adopted and (not callable(view.native_authorize) or not view.native_authorize()):
            return 200, _error(rid, -32001, "Native view changed or authorization was revoked; retry"), []
        return 200, response, []

    @staticmethod
    def _read(stream, size):
        chunks, remaining = [], size
        while remaining:
            chunk = stream.read(remaining)
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def __call__(self, environ, start_response):
        if environ.get("PATH_INFO") == CITATION_PATH:
            try:
                return self._citation(environ, start_response)
            except Exception as exc:
                _log("citation-error", type=type(exc).__name__)
                return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8",
                                     head=environ.get("REQUEST_METHOD") == "HEAD")
        if environ.get("PATH_INFO") == NATIVE_RECORD_PATH:
            try:
                return self._native_record(environ, start_response)
            except Exception as exc:
                _log("native-record-error", type=type(exc).__name__)
                return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8",
                                     head=environ.get("REQUEST_METHOD") == "HEAD")
        if environ.get("PATH_INFO") == public_status.STATUS_PATH:
            method = environ.get("REQUEST_METHOD", "GET")
            if method not in ("GET", "HEAD"):
                return self._respond(start_response, 405, b"Method not allowed\n", "text/plain; charset=utf-8",
                                     [("Allow", "GET, HEAD")])
            # The status route discloses no authenticated/native inventory. A
            # public-only legacy deployment may report its anonymous view.
            records = None
            if self.public_only and self.brain.native_authority is None:
                view = View(self.brain, "")
                if view.records_allowed:
                    records = len(view.nodes)
            if self.native_citations_v2:
                body = public_status.document(self.brain.version, self.status_declaration, records=records,
                    structured_citations=self.structured_citations, native_citations_v2=True)
            else:
                body = public_status.document(self.brain.version, self.status_declaration, records=records,
                                              structured_citations=self.structured_citations)
            payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
            return self._respond(start_response, 200, payload, "application/json", head=method == "HEAD")
        if environ.get("PATH_INFO") != "/mcp":
            if (environ.get("PATH_INFO") or "").startswith("/mcp/"):
                return self._respond(start_response, 404, b"Not found\n", "text/plain; charset=utf-8")
            try:
                return self._static(environ, start_response)
            except Exception as exc:
                _log("static-error", type=type(exc).__name__)
                return self._respond(start_response, 500, b"Internal error\n", "text/plain; charset=utf-8")
        try:
            status, body, extra = self._handle(environ)
        except Exception as exc:
            # Never the message text: it could carry request data.
            _log("mcp-error", type=type(exc).__name__)
            status, body, extra = 500, _error(None, -32603, "Internal error"), []
        payload = b"" if body is None else json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
        headers = [("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"),
                   ("Content-Length", str(len(payload))), *extra]
        if body is not None:
            headers.insert(0, ("Content-Type", "application/json"))
        start_response(f"{status} {HTTPStatus(status).phrase}", headers)
        return [payload]


def create_application():
    """One brain per process, configured only by the environment."""
    root = os.environ.get("BRAIN_ROOT")
    if not root:
        raise ValueError("BRAIN_ROOT must name the published brain (the portal's _site/)")
    brain = Brain(root)
    settings = {key: os.environ.get(key, "").strip()
                for key in ("BRAIN_MCP_JWKS_URL", "BRAIN_MCP_ISSUER", "BRAIN_MCP_AUDIENCE")}
    typed_setting = os.environ.get("BRAIN_MCP_TYPED_PRINCIPALS", "").strip().lower()
    if typed_setting not in ("", "0", "false", "1", "true"):
        raise ValueError("BRAIN_MCP_TYPED_PRINCIPALS must be true or false")
    typed_enabled = typed_setting in ("1", "true")
    expected_org_guid = os.environ.get("BRAIN_MCP_EXPECTED_ORG_GUID", "").strip() or None
    if typed_enabled and not all(settings.values()):
        raise ValueError("typed principals require the complete brain token verifier configuration")
    if expected_org_guid and not typed_enabled:
        raise ValueError("BRAIN_MCP_EXPECTED_ORG_GUID requires BRAIN_MCP_TYPED_PRINCIPALS=true")
    verifier = None
    if any(settings.values()):
        if not all(settings.values()):
            raise ValueError("Set BRAIN_MCP_JWKS_URL, BRAIN_MCP_ISSUER and BRAIN_MCP_AUDIENCE together, or none")
        verifier = brain_token.TokenVerifier(jwks_url=settings["BRAIN_MCP_JWKS_URL"],
                                             issuer=settings["BRAIN_MCP_ISSUER"],
                                             audience=settings["BRAIN_MCP_AUDIENCE"],
                                             typed_principals_enabled=typed_enabled,
                                             expected_org_guid=expected_org_guid)
    header = os.environ.get("BRAIN_MCP_TOKEN_HEADER", "").strip() or TOKEN_HEADER
    origins = [o.strip() for o in os.environ.get("BRAIN_MCP_ALLOWED_ORIGINS", "").split(",") if o.strip()]
    static_source = os.environ.get("BRAIN_STATIC_IDENTITY_SOURCE", "anonymous").strip().lower()
    native_record_source = os.environ.get("BRAIN_NATIVE_RECORD_IDENTITY_SOURCE", "off").strip().lower()
    proposal_setting = os.environ.get("BRAIN_MCP_ENABLE_PROPOSALS", "").strip().lower()
    if proposal_setting not in ("", "0", "false", "1", "true"):
        raise ValueError("BRAIN_MCP_ENABLE_PROPOSALS must be true or false")
    proposals_enabled = proposal_setting in ("1", "true")
    public_setting = os.environ.get("BRAIN_MCP_PUBLIC_ONLY", "").strip().lower()
    if public_setting not in ("", "0", "false", "1", "true"):
        raise ValueError("BRAIN_MCP_PUBLIC_ONLY must be true or false")
    public_only = public_setting in ("1", "true")
    citation_setting = os.environ.get("BRAIN_MCP_STRUCTURED_CITATIONS", "").strip().lower()
    if citation_setting not in ("", "0", "false", "1", "true"):
        raise ValueError("BRAIN_MCP_STRUCTURED_CITATIONS must be true or false")
    structured_citations = citation_setting in ("1", "true")
    native_citation_setting = os.environ.get("BRAIN_MCP_NATIVE_CITATIONS_V2", "").strip().lower()
    if native_citation_setting not in ("", "0", "false", "1", "true"):
        raise ValueError("BRAIN_MCP_NATIVE_CITATIONS_V2 must be true or false")
    native_citations_v2 = native_citation_setting in ("1", "true")
    citation_origin = os.environ.get("BRAIN_MCP_CITATION_PUBLIC_ORIGIN", "").strip() or None
    if citation_origin and not (structured_citations or native_citations_v2):
        raise ValueError("BRAIN_MCP_CITATION_PUBLIC_ORIGIN requires structured citations")
    if structured_citations:
        from mcp_citations import validate_public_origin
        if validate_public_origin(citation_origin) is None:
            raise ValueError("Structured citations require an explicit valid HTTPS public origin")
        # The frozen v1 resource/commit contract cannot cite native authority
        # data without borrowing compiled provenance. Native v2 is separate.
        if brain.native_authority is not None:
            raise ValueError("Structured citation v1 requires a compiled-source authority")
    operations_root = Path(os.environ.get("BRAIN_OPERATIONS_ROOT", root)).absolute()
    declaration = public_status.load(operations_root, os.environ.get("BRAIN_PUBLIC_STATUS", "").strip())
    application = MCPApplication(brain, verifier=verifier, token_header=header, allowed_origins=origins,
                                 static_identity_source=static_source,
                                 edge_identity_secret=os.environ.get("BRAIN_STATIC_EDGE_SECRET", ""),
                                 native_record_identity_source=native_record_source,
                                 native_record_edge_secret=os.environ.get("BRAIN_NATIVE_RECORD_EDGE_SECRET", ""),
                                 proposals_enabled=proposals_enabled,
                                 operations_root=operations_root,
                                 operations_host=os.environ.get("BRAIN_OPERATIONS_HOST",
                                                                "_internal/knowledge-operations.json"),
                                 public_only=public_only, status_declaration=declaration,
                                 structured_citations=structured_citations,
                                 citation_public_origin=citation_origin,
                                 native_citations_v2=native_citations_v2)
    if brain.gate.lockdown:
        _log("mcp-access-lockdown", problems=len(brain.gate.problems))
    _log("mcp-ready", brain=brain.name, records=len(brain.nodes), documents=len(brain.documents),
         unreadable=brain.unreadable, tokens="verified" if verifier else "not verified here (edge-gated)",
         access="lockdown" if brain.gate.lockdown else "configured" if brain.gate.present else "open")
    return application


def serve_stdio(application, input_stream=None, output_stream=None, *, uid=None):
    """Serve newline-delimited JSON-RPC; stdout contains protocol messages only."""
    input_stream = input_stream or sys.stdin.buffer
    output_stream = output_stream or sys.stdout.buffer
    uid = os.getuid() if uid is None else uid
    negotiated_protocol = None

    def reply(value):
        output_stream.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n")
        output_stream.flush()

    while True:
        raw = input_stream.readline(MAX_BODY_BYTES + 2)
        if not raw:
            return
        if len(raw) > MAX_BODY_BYTES + 1 or (len(raw) == MAX_BODY_BYTES + 1 and not raw.endswith(b"\n")):
            reply(_error(None, -32700, "Parse error: message exceeds the configured limit"))
            return  # Do not drain an unbounded attacker-controlled line.
        if raw.endswith(b"\n"):
            raw = raw[:-1]
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        try:
            message = decode(raw)
        except (ValueError, UnicodeError):
            reply(_error(None, -32700, "Parse error"))
            continue
        if isinstance(message, list) or not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            reply(_error(None, -32600, "Invalid Request"))
            continue
        method = message.get("method")
        if not isinstance(method, str):
            reply(_error(message.get("id"), -32600, "Invalid Request"))
            continue
        if "id" not in message:
            # Server notifications do not produce responses.
            continue
        rid = message["id"]
        if not isinstance(rid, _REQUEST_ID) or isinstance(rid, bool):
            reply(_error(None, -32600, "Invalid Request: id must be a string or a number"))
            continue
        try:
            view = application._stdio_view(uid)
            response = dispatch(
                application.brain, view, message, protocol_version=negotiated_protocol,
                structured_citations=application.structured_citations,
                public_origin=application.citation_public_origin,
                link_identity=(application.public_only and application.static_identity_source in ("anonymous", "edge")),
            )
            if (message.get("method") == "initialize" and isinstance(response, dict)
                    and isinstance(response.get("result"), dict)):
                negotiated_protocol = response["result"].get("protocolVersion")
            if view.native_adopted and (not callable(view.native_authorize) or not view.native_authorize()):
                response = _error(rid, -32001, "Native view changed or authorization was revoked; retry")
        except Exception as exc:
            _log("mcp-stdio-error", type=type(exc).__name__)
            response = _error(rid, -32603, "Internal error")
        reply(response)


def stdio_main():
    """Executable entry point for local MCP clients using the protected UID map."""
    try:
        application = create_application()
        uid = os.getuid()
        if not application.public_only and not application._stdio_view(uid).identity_authorized:
            raise ValueError("local UID has no MCP identity mapping in the protected host configuration")
        serve_stdio(application, uid=uid)
    except Exception as exc:
        _log("mcp-stdio-startup-error", type=type(exc).__name__)
        return 1
    return 0
