"""Pinned local snapshot loader for the core context compiler.

The host configuration is operator-owned, separate from a context request. This
offline loader consumes a compiled snapshot at its declared knowledge basis;
``load_live`` reads an adopted authority at request time instead (#229).
An optional policy-scoped local projection observation checks a refresh receipt;
it does not fetch sources, reconstruct history or establish upstream source age.
"""
from __future__ import annotations

from collections import OrderedDict
import hashlib
import json
import math
from pathlib import Path
import re
from threading import Lock

from brain_recipes import Catalog
from context_access import ReadBoundary
from context_bundle import ContextError, ContextSnapshot, _object
from context_collection import CollectionView
from knowledge_policy import PolicyError, fingerprint, load_policy, local_path, timestamp
from ontology import Registry
from principals import PrincipalError, Principals

MAX_INPUT_BYTES = 64 * 1024 * 1024


class GraphValidationCache:
    """Bounded successful-validation keys, never graphs or authorized views.

    Callers still read and verify every pinned input and construct a fresh policy
    boundary. Content fingerprints prevent changed records reusing validation;
    validator resource bytes participate independently of the ontology binding.
    """

    def __init__(self, *, capacity=16, schemas=None):
        if type(capacity) is not int or capacity < 1:
            raise ValueError("Invalid validation cache capacity")
        self._capacity = capacity
        self._schemas = Path(schemas) if schemas is not None else Path(__file__).resolve().parents[1] / "schemas"
        self._validated = OrderedDict()
        self._lock = Lock()

    def _schema_basis(self):
        names = ("brain-node.schema.json", "brain-edge.schema.json",
                 "brain-envelope.schema.json", "evidence.schema.json")
        return tuple(hashlib.sha256((self._schemas / name).read_bytes()).hexdigest() for name in names)

    def validate(self, graph, ontology):
        # These are actual decoded contents, not caller-supplied digest claims.
        content = (fingerprint(graph), fingerprint(ontology))
        with self._lock:
            basis = self._schema_basis()
            key = (*content, basis)
            if key in self._validated:
                self._validated.move_to_end(key)
                return
            Registry(ontology, schemas=self._schemas).validate_graph(graph, require_binding=True)
            if self._schema_basis() != basis:
                raise ContextError("Validation schemas changed during graph validation")
            self._validated[key] = None
            while len(self._validated) > self._capacity:
                self._validated.popitem(last=False)


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ContextError("Duplicate context JSON key")
            result[key] = value
        return result

    def nonfinite(_):
        raise ContextError("Nonfinite context JSON number")

    def decimal(value):
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ContextError("Nonfinite context JSON number")
        return parsed

    if len(raw) > MAX_INPUT_BYTES:
        raise ContextError("Context input exceeds its size limit")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite, parse_float=decimal)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ContextError("Invalid context JSON") from exc


def read_json(path):
    with Path(path).open("rb") as stream:
        return decode(stream.read(MAX_INPUT_BYTES + 1))


def _read_raw(root, relative, expected=None, *, max_bytes=MAX_INPUT_BYTES):
    if type(max_bytes) is not int or not 0 <= max_bytes <= MAX_INPUT_BYTES:
        raise ContextError("Invalid context input byte limit")
    if not isinstance(relative, str):
        raise ContextError("Context host inputs require relative path strings")
    path = local_path(relative)
    if any((root / Path(*path.parts[:i])).is_symlink() for i in range(1, len(path.parts) + 1)):
        raise ContextError("Context host inputs cannot follow symlinks")
    with (root / path).open("rb") as stream:
        raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ContextError("Context input exceeds its size limit")
    if expected is not None and hashlib.sha256(raw).hexdigest() != expected:
        raise ContextError("Pinned context source changed")
    return raw


def _read(root, relative, expected=None):
    return decode(_read_raw(root, relative, expected))


def read_pinned(root, descriptor, *, raw=False, max_bytes=MAX_INPUT_BYTES):
    _object(descriptor, ("path", "sha256"), "pinned context source")
    digest = descriptor["sha256"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ContextError("Context source needs a SHA-256 pin")
    content = _read_raw(root, descriptor["path"], digest, max_bytes=max_bytes)
    return content if raw else decode(content)


def load_boundary(root, settings, *, actor, now):
    """Verify policy, ontology and practice pins before constructing a boundary."""
    policy_config = settings["policy"]
    optional = ("people",) if isinstance(policy_config, dict) and "people" in policy_config else ()
    _object(policy_config, ("path", "sha256", "ontologySha256") + optional, "context policy pin")
    read_pinned(root, {key: policy_config[key] for key in ("path", "sha256")})
    ontology = read_pinned(root, {"path": "brain-schema.json", "sha256": policy_config["ontologySha256"]})
    policy = load_policy(root, policy_config)
    if optional:
        # A pinned person register lets policy grants name the person, not the credential (#212).
        # It rides on this policy instance, so boundaries derived from it keep it.
        try:
            policy.register = Principals(read_pinned(root, policy_config["people"]))
        except PrincipalError as exc:
            raise ContextError("Invalid context person register") from exc
    boundary = ReadBoundary(policy, actor=actor, now=now, scopes=settings["scopes"],
                            bindings=read_pinned(root, settings["bindings"]))
    return boundary, ontology


def _host_config(root, config_path, source):
    root = Path(root)
    if root.is_symlink():
        raise ContextError("Context root cannot be a symlink")
    config = _read(root, config_path)
    config_fields = ("protocolVersion", source, "policy", "recipe", "bindings", "scopes", "collection")
    if isinstance(config, dict) and "federation" in config:
        config_fields += ("federation",)
    if source == "graph" and isinstance(config, dict) and "projectionFreshness" in config:
        config_fields += ("projectionFreshness",)
    if isinstance(config, dict) and "corpus" in config:
        config_fields += ("corpus",)
    if isinstance(config, dict) and "usageLog" in config:
        config_fields += ("usageLog",)
    _object(config, config_fields, "context host configuration")
    if config["protocolVersion"] != "1.0":
        raise ContextError("Unsupported context host configuration")
    return root, config


def load_snapshot(root, config_path, *, actor, now, references=None, validation_cache=None):
    """Only the authenticated host chooses paths, identity and a reference plan."""
    root, config = _host_config(root, config_path, "graph")
    graph_config = config["graph"]
    _object(graph_config, ("path", "sha256", "asOf"), "context graph snapshot")
    graph = read_pinned(root, {key: graph_config[key] for key in ("path", "sha256")})
    boundary, ontology = load_boundary(root, config, actor=actor, now=now)
    return _context(root, config, graph, boundary, ontology, revision=graph_config["sha256"],
                    as_of=graph_config["asOf"], references=references, validation_cache=validation_cache)


def load_live(root, config_path, authority, *, actor, now, references=None, validation_cache=None):
    """Serve the declared authority cell at request time instead of a pinned file (#229).

    The host configuration names ``authority: {binding, audience}`` in place of
    ``graph``. The graph is the authority's projection for ``audience`` at ``now``,
    the same graph ``deliver()`` would publish, then the per-request boundary
    applies exactly as in snapshot mode. Its revision is the SHA-256 of the graph's
    canonical JSON and its ``asOf`` the journal head's write time, so a snapshot
    of that graph written canonically answers byte-identically.
    """
    root, config = _host_config(root, config_path, "authority")
    settings = config["authority"]
    _object(settings, ("binding", "audience"), "context authority")
    if authority.contract.binding != settings["binding"]:
        raise ContextError("Context authority differs from its adopted binding")
    boundary, ontology = load_boundary(root, config, actor=actor, now=now)
    view = authority.read_snapshot(settings["audience"], at=now)
    if view["checkpoint"]["state"] != "active":
        raise ContextError("Context requires an active authority")
    graph = view["graph"]
    return _context(root, config, graph, boundary, ontology, revision=fingerprint(graph),
                    as_of=view["asOf"], references=references, validation_cache=validation_cache)


def load_corpus(root, config):
    """Verify the optional pinned corpus index (#284) and return its local path, or None.

    The corpus index is a SQLite file (``corpus_index.py``'s ``corpus-index/v1``
    schema), pinned like any other host source: an operator declares ``path`` and
    ``sha256``, and a changed or missing file refuses the request rather than
    serving stale or substituted content. Its content is read later, per request,
    by ``context_corpus.document_records``, not decoded as JSON here.
    """
    settings = config.get("corpus")
    if settings is None:
        return None
    _object(settings, ("path", "sha256"), "context corpus index pin")
    read_pinned(root, settings, raw=True)
    return root / local_path(settings["path"])


def _context(root, config, graph, boundary, ontology, *, revision, as_of, references, validation_cache):
    def pinned(descriptor):
        return read_pinned(root, descriptor)

    if validation_cache is None:
        Registry(ontology).validate_graph(graph, require_binding=True)
    else:
        validation_cache.validate(graph, ontology)
    recipe = pinned(config["recipe"])
    collection = None
    if config["collection"] is not None:
        settings = config["collection"]
        _object(settings, ("catalogs", "recipe", "assessment", "bindings", "targetId"), "context collection config")
        if not isinstance(settings["catalogs"], list) or not settings["catalogs"]:
            raise ContextError("A collection recipe catalog is required")
        catalog = Catalog([pinned(item) for item in settings["catalogs"]], root)
        collection_recipe, _ = catalog.resolve(settings["recipe"])
        collection_ontology = catalog.ontology(collection_recipe)
        if validation_cache is None:
            collection_ontology.validate_graph(graph, require_binding=True)
        else:
            validation_cache.validate(graph, collection_ontology.declaration)
        questions, _ = catalog.questions(collection_recipe, collection_ontology)
        assessment = pinned(settings["assessment"]) if settings["assessment"] is not None else None
        collection = CollectionView(questions, assessment, boundary=boundary, bindings=pinned(settings["bindings"]),
                                    as_of=as_of, target_id=settings["targetId"])
    if config.get("federation") is not None:
        if references is not None:
            raise ContextError("Choose one host reference configuration")
        from federation_host import load_references
        references = load_references(root, pinned(config["federation"]), boundary=boundary)
    freshness = None
    if config.get("projectionFreshness") is not None:
        settings = config["projectionFreshness"]
        _object(settings, ("resource",), "projection freshness configuration")
        if not isinstance(settings["resource"], str) or not settings["resource"]:
            raise ContextError("Projection freshness requires a policy resource")
        # Publish only the coarse scoped signal, with an explicit policy grant.
        # Denied observations are not read, counted or included in request pins.
        if boundary.permits_resource(settings["resource"], "projection-freshness"):
            from projection_freshness import observe
            freshness = observe(root, brain_sha256=revision)
    usage_log_scope = None
    if config.get("usageLog") is not None:
        settings = config["usageLog"]
        _object(settings, ("scope",), "context usage log configuration")
        usage_log_scope = settings["scope"]
        if not isinstance(usage_log_scope, str) or not usage_log_scope:
            raise ContextError("Context usage log requires a policy scope")
        try:
            # Fail closed on a misconfigured scope; retention/access are declared
            # by this scope's rules, never recomputed or duplicated here (#348).
            boundary.policy.effective(usage_log_scope, timestamp(boundary.now))
        except (KeyError, PolicyError) as exc:
            raise ContextError("Context usage log scope is unavailable") from exc
    return ContextSnapshot(graph, boundary=boundary, brain_revision=revision,
                           as_of=as_of, recipe=recipe, collection=collection, references=references,
                           freshness=freshness, corpus=load_corpus(root, config), usage_log_scope=usage_log_scope)
