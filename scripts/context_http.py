"""Authenticated read-only context endpoint and WSGI adapter (#93).

The operator owns roots, credentials and limits. No caller-selected host paths,
grants or clocks are accepted. Deploy behind TLS with server-enforced deadlines;
the in-process admission limit cannot cancel blocked I/O or Python execution.
"""
from __future__ import annotations

from copy import deepcopy
import datetime as dt
import hashlib
import hmac
from http import HTTPStatus
from pathlib import Path
import re
from threading import BoundedSemaphore
from time import monotonic

from context_bundle import encode, validate_request
from context_search import validate_search
from context_host import GraphValidationCache, MAX_INPUT_BYTES, decode, load_live, load_snapshot
from knowledge_policy import local_path, timestamp, validate as validate_schema


DEFAULT_BUDGET = {"maxNodes": 1000, "maxEdges": 2000, "maxHops": 8,
                  "maxReferences": 20, "maxQuestions": 100, "maxBytes": 1024 * 1024}


class _Refusal(Exception):
    def __init__(self, status):
        self.status = status


def _usage_basis(result):
    """The recipe binding and scopes, wherever this operation's response carries them."""
    source = result.get("request", result)
    return source.get("recipe"), source.get("scopes")


def _usage_records(operation, result):
    """Returned record identity/kind/scope only, never a node's title/text/data (#348)."""
    if operation in ("context", "cite"):
        component = "citation" if operation == "cite" else "nodes"
        return [{"component": component, "id": node["id"], "kind": node["kind"], "scope": node.get("scope")}
                for node in result.get("nodes", [])]
    if operation in ("search", "documents"):
        return [{"component": "matches", "id": match["record"]["id"], "kind": match["record"]["kind"],
                "scope": match["record"].get("scope")} for match in result.get("matches", [])]
    return []


def usage_log_entry(operation, result, *, audience_class, policy_scope, elapsed, now):
    """A schema-checked, content-free usage-log entry for one successfully answered request.

    ``result`` is the decoded answer (before wire encoding); ``audience_class`` and
    ``policy_scope`` come from the authorized snapshot, never a request field.
    Validating against schemas/context-usage-log.schema.json makes "no content, no
    identity beyond the audience class" a structural property of this function, not
    just a review note: additionalProperties is false throughout that schema.
    """
    recipe, scopes = _usage_basis(result)
    entry = {"protocolVersion": "1.0", "time": now, "operation": operation, "recipe": recipe,
             "scopes": list(scopes or []), "policyScope": policy_scope, "audienceClass": audience_class,
             "records": _usage_records(operation, result), "truncation": list(result.get("truncation", [])),
             "gaps": deepcopy(result.get("gaps", [])), "latencyMs": round(elapsed * 1000, 3)}
    validate_schema(entry, "context-usage-log")
    return entry


class ContextEndpoint:
    """Load a fresh authorized snapshot for each admitted request.

    ``credentials()`` returns operator-owned records with exactly ``sha256``,
    ``actor`` and ``expiresAt`` (UTC timestamp or None). Use high-entropy bearer
    secrets, never human passwords. Reloading this provider enables revocation.
    ``clock()`` is trusted host input. Limits apply per endpoint/process.
    ``authority`` is an operator-selected authority DSN (a SQLite path or a
    postgres/mysql URL): each request then reads it through ``load_live``
    instead of a pinned graph snapshot.

    ``usage_log`` is an optional operator-supplied sink (one JSON-serializable
    entry per call, e.g. the append-only file writer ``context_service.py``
    builds from ``BRAIN_CONTEXT_USAGE_LOG``). It only ever fires when the brain's
    own host config ALSO declares ``usageLog`` (#348): the operator and the brain
    must both opt in, or nothing is logged. A logging failure never turns an
    otherwise successful response into a refusal.
    """

    def __init__(self, *, root, host_config, credentials, clock=None,
                 max_request_bytes=65536, max_response_bytes=1024 * 1024,
                 max_concurrent=4, budget=None, authority=None, usage_log=None):
        if not callable(credentials) or (clock is not None and not callable(clock)):
            raise ValueError("Invalid context credential provider or clock")
        if usage_log is not None and not callable(usage_log):
            raise ValueError("Invalid context usage log sink")
        for limit in (max_request_bytes, max_response_bytes):
            if type(limit) is not int or not 1 <= limit <= MAX_INPUT_BYTES:
                raise ValueError("Invalid context byte limit")
        if type(max_concurrent) is not int or max_concurrent < 1:
            raise ValueError("Invalid context concurrency limit")
        selected = dict(DEFAULT_BUDGET) if budget is None else dict(budget)
        if set(selected) != set(DEFAULT_BUDGET) or any(
                type(value) is not int or value < (1 if key in ("maxNodes", "maxBytes") else 0)
                for key, value in selected.items()):
            raise ValueError("Invalid context budget ceilings")
        selected["maxBytes"] = min(selected["maxBytes"], max_response_bytes)
        self._root, self._config = Path(root).absolute(), str(local_path(host_config))
        self._authority = authority
        self._usage_log = usage_log
        self._credentials = credentials
        self._clock = clock or (lambda: dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"))
        self._budget = selected
        self.max_request_bytes, self._output_limit = max_request_bytes, max_response_bytes
        self._admission = BoundedSemaphore(max_concurrent)
        self._validation_cache = GraphValidationCache()

    def _authenticate(self, authorization):
        if not isinstance(authorization, str) or len(authorization) > 4103 or not re.fullmatch(
                r"Bearer [A-Za-z0-9._~+/\-]+=*", authorization, flags=re.IGNORECASE):
            raise _Refusal(401)
        supplied = hashlib.sha256(authorization[7:].encode("ascii")).hexdigest()
        now = self._clock()
        current = timestamp(now)
        entries = self._credentials()
        if not isinstance(entries, list):
            raise ValueError("Invalid credential records")
        seen, actor = set(), None
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"sha256", "actor", "expiresAt"}:
                raise ValueError("Invalid credential record")
            digest = entry["sha256"]
            if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                    or digest in seen or not isinstance(entry["actor"], str) or not entry["actor"].strip()):
                raise ValueError("Invalid credential identity")
            seen.add(digest)
            expiry = timestamp(entry["expiresAt"]) if entry["expiresAt"] is not None else None
            if hmac.compare_digest(supplied, digest) and (expiry is None or current < expiry):
                actor = entry["actor"]
        if actor is None:
            raise _Refusal(401)
        return actor, now

    operations = ("basis", "context", "search", "documents")

    def _check(self, operation, request):
        """Refuse a malformed request, or one above this endpoint's ceilings, before loading."""
        if operation == "basis":
            if request != {}:
                raise ValueError("Basis discovery requires an empty object")
        elif operation in ("search", "documents"):
            validate_search(request)
            if (request["budget"]["maxMatches"] > self._budget["maxNodes"]
                    or request["budget"]["maxBytes"] > self._budget["maxBytes"]):
                raise _Refusal(413)
        else:
            validate_request(request)
            if any(request["budget"][key] > limit for key, limit in self._budget.items()):
                raise _Refusal(413)

    def _prepare(self, operation, request, actor, now):
        """Load fresh host inputs; the returned call answers the request from them."""
        snapshot = self._load(actor, now)

        def answer():
            return (snapshot.basis() if operation == "basis" else snapshot.search(request)
                    if operation == "search" else snapshot.documents(request)
                    if operation == "documents" else snapshot.compile(request))
        # A fresh closure per call, never shared state on self: safe under concurrency.
        # FederationEndpoint's override returns a plain callable with no such attribute.
        answer.snapshot = snapshot
        return answer

    def _log_usage(self, operation, result, *, snapshot, elapsed, now):
        """Best-effort, opt-in usage signal; never lets logging affect the response (#348)."""
        if self._usage_log is None or snapshot is None or getattr(snapshot, "usage_log_scope", None) is None:
            return
        try:
            entry = usage_log_entry(operation, result, audience_class=snapshot.audience_class,
                                    policy_scope=snapshot.usage_log_scope, elapsed=elapsed, now=now)
            self._usage_log(entry)
        except Exception:
            # A malformed entry or a failed sink write must not turn an already
            # successful, already-computed answer into a refusal.
            pass

    def _serve(self, read_body, authorization, operation):
        if operation not in self.operations:
            return 404, b""
        if not self._admission.acquire(blocking=False):
            return 503, b""
        try:
            actor, _ = self._authenticate(authorization)
            raw = read_body()
            if not isinstance(raw, bytes):
                raise _Refusal(400)
            if len(raw) > self.max_request_bytes:
                raise _Refusal(413)
            try:
                request = decode(raw)
                self._check(operation, request)
            except (ValueError, TypeError, KeyError):
                raise _Refusal(400) from None
            # Recheck after body input: a slow upload must not preserve a revoked
            # or expired credential. Policy also evaluates at this fresh time.
            current_actor, now = self._authenticate(authorization)
            if current_actor != actor:
                raise _Refusal(401)
            answer = self._prepare(operation, request, actor, now)
            started = monotonic()
            try:
                result = answer()
                response = encode(result)
            except (ValueError, TypeError, KeyError):
                raise _Refusal(400) from None
            if len(response) > self._output_limit:
                raise _Refusal(413)
            self._log_usage(operation, result, snapshot=getattr(answer, "snapshot", None),
                            elapsed=monotonic() - started, now=now)
            return 200, response
        except _Refusal as exc:
            return exc.status, b""
        except Exception:
            # The network boundary must not expose source paths, pins, records,
            # provider errors or exception text. Host failures remain unavailable.
            return 503, b""
        finally:
            self._admission.release()

    def _load(self, actor, now):
        if self._authority is None:
            return load_snapshot(self._root, self._config, actor=actor, now=now,
                                 validation_cache=self._validation_cache)
        from knowledge_store import authority_class
        store = authority_class(str(self._authority))(self._authority, readonly=True)
        try:
            return load_live(self._root, self._config, store, actor=actor, now=now,
                             validation_cache=self._validation_cache)
        finally:
            store.close()

    def handle(self, raw, authorization, *, operation="context"):
        """Return (HTTP status, JSON bytes); every failure has an empty body."""
        return self._serve(lambda: raw, authorization, operation)


class ContextApplication:
    """WSGI transport for POST /basis, /search, /documents and /context, with no write routes.

    The ingress must reject ambiguous/duplicate HTTP framing and set trusted WSGI
    metadata. No forwarded user header grants access. No CORS is enabled here.
    """

    routes = {"/basis": "basis", "/context": "context", "/search": "search", "/documents": "documents"}

    def __init__(self, endpoint):
        if not isinstance(endpoint, ContextEndpoint):
            raise ValueError("A context endpoint is required")
        self.endpoint = endpoint

    def _handle(self, environ):
        operation = self.routes.get(environ.get("PATH_INFO"))
        if operation is None:
            return 404, b""
        if environ.get("REQUEST_METHOD") != "POST":
            return 405, b""
        if environ.get("QUERY_STRING") or environ.get("HTTP_TRANSFER_ENCODING"):
            return 400, b""
        if (environ.get("CONTENT_TYPE", "").lower() != "application/json"
                or environ.get("HTTP_CONTENT_ENCODING", "identity").lower() != "identity"):
            return 415, b""
        size = environ.get("CONTENT_LENGTH", "")
        if not size:
            return 411, b""
        if not isinstance(size, str) or len(size) > 20 or not re.fullmatch(r"[0-9]+", size):
            return 400, b""
        length = int(size)
        if length > self.endpoint.max_request_bytes:
            return 413, b""

        def read_body():
            remaining, chunks = length, []
            stream = environ["wsgi.input"]
            while remaining:
                chunk = stream.read(remaining)
                if not isinstance(chunk, bytes) or not chunk or len(chunk) > remaining:
                    raise _Refusal(400)
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks)

        return self.endpoint._serve(read_body, environ.get("HTTP_AUTHORIZATION"), operation)

    def __call__(self, environ, start_response):
        try:
            status, body = self._handle(environ)
        except Exception:
            status, body = 503, b""
        headers = [("Content-Type", "application/json"), ("Content-Length", str(len(body))),
                   ("Cache-Control", "no-store"), ("Vary", "Authorization"),
                   ("X-Content-Type-Options", "nosniff")]
        if status == 401:
            headers.append(("WWW-Authenticate", 'Bearer realm="brain-context"'))
        if status == 405:
            headers.append(("Allow", "POST"))
        start_response(f"{status} {HTTPStatus(status).phrase}", headers)
        return [body]
