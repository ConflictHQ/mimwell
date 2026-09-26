"""Deterministic, bounded assembly over an already-authorized graph (#55).

The host supplies the snapshot, current read boundary and recipe. Requests can
select within that authority, but cannot provide grants or revise source pins.
Peer calls use host-registered transports for admitted references only. Neighbors
are never treated as proof that a question is answered.
"""
from __future__ import annotations

from collections import deque
from copy import deepcopy
import json

from evidence import EvidenceError, validate_record
from knowledge_policy import fingerprint, timestamp


class ContextError(ValueError):
    pass


def encode(bundle):
    """The wire encoding against which maxBytes is enforced, including newline."""
    return (json.dumps(bundle, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def _object(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ContextError(f"Invalid {label} fields")


def _text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ContextError(f"Invalid {label}")


def validate_request(request):
    _object(request, ("protocolVersion", "target", "scopes", "recipe", "asOf",
                      "revisions", "budget"), "context request")
    if request["protocolVersion"] != "1.0":
        raise ContextError("Unsupported context request version")
    target = request["target"]
    if not isinstance(target, dict) or target.get("type") not in ("task", "subject"):
        raise ContextError("A task or subject target is required")
    fields = ("type", "id") if target["type"] == "task" else ("type", "id", "question")
    _object(target, fields, "target")
    for field in fields:
        _text(target[field], "target")
    scopes = request["scopes"]
    if not isinstance(scopes, list) or not scopes or any(not isinstance(s, str) or not s for s in scopes):
        raise ContextError("Explicit context scopes are required")
    if len(scopes) != len(set(scopes)):
        raise ContextError("Duplicate context scope")
    _object(request["recipe"], ("id", "version", "sha256"), "recipe binding")
    for value in request["recipe"].values():
        _text(value, "recipe binding")
    revisions = request["revisions"]
    revision_fields = ("brain", "ontology", "policy", "bindings", "collection")
    if isinstance(revisions, dict) and "federation" in revisions:
        revision_fields += ("federation",)
    if isinstance(revisions, dict) and "freshness" in revisions:
        revision_fields += ("freshness",)
    _object(revisions, revision_fields, "source revisions")
    for key, value in request["revisions"].items():
        if key != "collection" or value is not None:
            _text(value, "source revision")
    timestamp(request["asOf"])
    budget = request["budget"]
    _object(budget, ("maxNodes", "maxEdges", "maxHops", "maxReferences", "maxQuestions", "maxBytes"), "budget")
    for key, value in budget.items():
        if type(value) is not int or value < (1 if key in ("maxNodes", "maxBytes") else 0):
            raise ContextError("Context budgets must be explicit nonnegative integers")


def recipe_binding(recipe):
    """Bind a context traversal recipe, distinct from the collection recipe."""
    _object(recipe, ("id", "version", "hops"), "context recipe")
    _text(recipe["id"], "recipe identity")
    _text(recipe["version"], "recipe version")
    if not isinstance(recipe["hops"], list):
        raise ContextError("Invalid context recipe hops")
    names = set()
    for hop in recipe["hops"]:
        _object(hop, ("rel", "direction", "transitive", "as"), "recipe hop")
        _text(hop["rel"], "hop relationship")
        _text(hop["as"], "hop group")
        if hop["direction"] not in ("in", "out") or type(hop["transitive"]) is not bool:
            raise ContextError("Invalid recipe traversal")
        if hop["as"] in names:
            raise ContextError("Duplicate recipe group")
        names.add(hop["as"])
    return {"id": recipe["id"], "version": recipe["version"], "sha256": fingerprint(recipe)}


def _evidence_gaps(record, identity, as_of):
    """Project existing evidence semantics; preserve the full bundle on records."""
    evidence = record.get("evidence")
    if not evidence:
        return [{"record": identity, "state": "unknown", "reason": "no-evidence"}]
    try:
        validate_record(record)
    except EvidenceError as exc:
        raise ContextError("Selected record has invalid evidence") from exc
    gaps = []

    def add(state, reason, assertion=None):
        gap = {"record": identity, "state": state, "reason": reason}
        if assertion:
            gap["assertion"] = assertion
        if gap not in gaps:
            gaps.append(gap)

    for claim in evidence["claims"]:
        if claim["matchesRecord"] is not True:
            add("contradiction" if claim["matchesRecord"] is False else "unknown",
                "claim-record-mismatch", claim["assertion"])
        if claim["contradictingLineages"]:
            add("contradiction", "contradicting-evidence", claim["assertion"])
        if not claim["supportingLineages"]:
            add("unknown", "no-available-support", claim["assertion"])
    for assertion in evidence["assertions"]:
        if assertion["contradicts"]:
            add("contradiction", "declared-contradiction", assertion["id"])
        if assertion["status"] != "active":
            add("stale", "assertion-" + assertion["status"], assertion["id"])
    for observation in evidence["observations"]:
        if observation["status"] != "available":
            add(observation["status"], "evidence-" + observation["status"])
    for attestation in evidence["attestations"]:
        start, end = attestation["validity"]["from"], attestation["validity"]["until"]
        if ((start and as_of < timestamp(start)) or (end and as_of >= timestamp(end))):
            add("stale", "outside-validity", attestation["assertion"])
        if not attestation["assertedAt"]:
            add("unknown", "assertion-time-unknown", attestation["assertion"])
        elif timestamp(attestation["assertedAt"]) > as_of:
            add("unknown", "asserted-after-as-of", attestation["assertion"])
        if attestation["review"]["state"] != "reviewed":
            add("unknown", "evidence-not-reviewed", attestation["assertion"])
    if evidence["unresolvedAssertions"]:
        add("unknown", "related-assertions-unresolved")
    return gaps


class ContextSnapshot:
    """Immutable authorized view with host-observed source and knowledge pins.

    ``brain_revision`` names the host's loaded graph snapshot. ``as_of`` is that
    snapshot's knowledge basis, not a request to reconstruct arbitrary history.
    Authorization always uses the boundary's current trusted time. The host must
    load and validate the ontology/graph and refresh evidence observations before
    constructing this snapshot. No request may replace any of those inputs.
    """

    def __init__(self, brain, *, boundary, brain_revision, as_of, recipe, collection=None, references=None,
                 freshness=None, corpus=None, usage_log_scope=None):
        _text(brain_revision, "brain revision")
        timestamp(as_of)
        self._boundary = boundary
        self._corpus = corpus
        self._usage_log_scope = usage_log_scope
        self._graph = boundary.graph(brain)
        self._recipe = deepcopy(recipe)
        self._recipe_binding = recipe_binding(recipe)
        self._scopes = sorted(boundary.scopes)
        self._as_of = as_of
        self._authorization = {"principal": boundary.actor, "evaluatedAt": boundary.now}
        if collection is not None and not collection.matches(boundary, as_of):
            raise ContextError("Collection view does not match the context authorization and knowledge basis")
        self._collection = collection.result() if collection is not None else None
        self._revisions = {"brain": brain_revision,
                           "ontology": boundary.policy.binding["ontologySha256"],
                           "policy": boundary.policy.binding["sha256"],
                           "bindings": fingerprint(boundary.bindings),
                           "collection": collection.binding if collection is not None else None}
        self._freshness = deepcopy(freshness)
        if freshness is not None:
            _object(freshness, ("scope", "state", "reason", "basis"), "projection freshness observation")
            if freshness["scope"] != "enriched-knowledge-graph" or freshness["state"] not in ("current", "stale", "unknown"):
                raise ContextError("Unsupported projection freshness observation")
            for field in ("reason", "basis"):
                _text(freshness[field], "projection freshness observation")
            self._revisions["freshness"] = fingerprint(freshness)
        self._references = None
        if references is not None:
            from context_references import ReferencePlan
            if not isinstance(references, ReferencePlan):
                raise ContextError("Invalid context reference plan")
            self._references = references.scoped(boundary, self._graph["references"])
            self._revisions["federation"] = self._references.binding

    @property
    def recipe(self):
        return deepcopy(self._recipe_binding)

    @property
    def revisions(self):
        return deepcopy(self._revisions)

    @property
    def audience_class(self):
        """The authenticated principal's policy-declared kind (human/agent/service); never its identity (#348)."""
        return self._boundary.policy.principals[self._boundary.principal]["kind"]

    @property
    def usage_log_scope(self):
        """The policy scope declaring this snapshot's usage-log retention/access, or None when unconfigured (#348)."""
        return self._usage_log_scope

    def basis(self):
        """Authenticated discovery for a request, without records or counts."""
        return {"protocolVersion": "1.0", "recipe": self.recipe, "revisions": self.revisions,
                "scopes": list(self._scopes), "asOf": self._as_of}

    def search(self, request):
        """Discover local candidates under this snapshot's existing read boundary."""
        from context_search import search, validate_search
        validate_search(request)
        if (request["revisions"] != self._revisions or request["recipe"] != self._recipe_binding
                or timestamp(request["asOf"]) != timestamp(self._as_of)
                or sorted(request["scopes"]) != self._scopes):
            raise ContextError("Context snapshot does not match the requested basis")
        return search(self._graph["nodes"], request, self._authorization, self._freshness)

    def documents(self, request):
        """Discover corpus documents through the same read boundary and search envelope (#284).

        The optional D1 corpus index (#64) is a projection of the markdown corpus, not
        an authority. A document is admitted only when its indexed path is bound to a
        permitted policy resource in the ``paths`` table that already gates a graph
        node's or edge's source paths; the corpus index's own restricted/readers
        metadata (the Worker's separate email-based lockdown) plays no role here. When
        no corpus is configured this returns an explicit empty, gapped result rather
        than refusing, matching the Worker's absent-index fallback.
        """
        from context_search import search, validate_search
        validate_search(request)
        if (request["revisions"] != self._revisions or request["recipe"] != self._recipe_binding
                or timestamp(request["asOf"]) != timestamp(self._as_of)
                or sorted(request["scopes"]) != self._scopes):
            raise ContextError("Context snapshot does not match the requested basis")
        if self._corpus is None:
            result = search([], request, self._authorization, self._freshness)
            result["gaps"] = [{"state": "unknown", "reason": "corpus-index-not-configured"}]
            if len(encode(result)) > request["budget"]["maxBytes"]:
                raise ContextError("maxBytes cannot hold the search response envelope")
            return result
        from context_corpus import document_records
        return search(document_records(self._corpus, self._boundary), request, self._authorization, self._freshness)

    def compile(self, request):
        validate_request(request)
        if (request["revisions"] != self._revisions or request["recipe"] != self._recipe_binding
                or timestamp(request["asOf"]) != timestamp(self._as_of)
                or sorted(request["scopes"]) != self._scopes
                or self._collection is not None and request["target"]["id"] != self._collection["subject"]):
            # Never return observed pins or scope details on a rejected request.
            raise ContextError("Context snapshot does not match the requested basis")
        return self._assemble(request)

    def _assemble(self, request):
        from context_access import edge_identity

        budget = request["budget"]
        nodes = {node["id"]: node for node in self._graph["nodes"]}
        result = {"protocolVersion": "1.0", "request": deepcopy(request),
                  "authorization": deepcopy(self._authorization),
                  "nodes": [], "edges": [], "references": [], "groups": {},
                  "gaps": [], "truncation": [], "coverage": {
                      "state": "not-assessed", "basis": None, "subject": None, "questions": [], "evidence": []}}
        if self._freshness is not None:
            result["projectionFreshness"] = {key: value for key, value in self._freshness.items() if key != "basis"}
            if self._freshness["state"] != "current":
                result["gaps"].append({"projection": self._freshness["scope"],
                                       "state": self._freshness["state"], "reason": self._freshness["reason"]})
        seen_nodes, seen_edges, seen_refs = set(), set(), set()
        as_of = timestamp(request["asOf"])

        def truncated(reason):
            if reason not in result["truncation"]:
                result["truncation"].append(reason)
                result["truncation"].sort()

        # Reserve the longest possible truncation list up front. This prevents
        # an omission notice itself breaking the promised byte bound later.
        reasons = ["maxBytes", "maxEdges", "maxHops", "maxNodes", "maxQuestions", "maxReferences"]

        def fits(candidate):
            measured = {**candidate, "truncation": reasons,
                        "coverage": {**candidate["coverage"], "state": "not-assessed"}}
            if self._references is not None:
                # Reserve enough room to explain any unresolved outcome even
                # when a resolved record cannot fit in the remaining budget.
                measured["references"] = [
                    {**row, "reason": "unsupported-transport"} if row["status"] == "unavailable" else row
                    for row in candidate["references"]]
            return len(encode(measured)) <= budget["maxBytes"]

        if not fits(result):
            raise ContextError("maxBytes cannot hold the context response envelope")

        def admit(node_id, *, edge=None, group=None):
            additions = []
            new_node = node_id in nodes and node_id not in seen_nodes
            new_reference = node_id not in nodes and node_id not in seen_refs
            if new_node:
                if len(seen_nodes) >= budget["maxNodes"]:
                    truncated("maxNodes")
                    return False
                additions.extend(_evidence_gaps(nodes[node_id], node_id, as_of))
            elif new_reference:
                if len(seen_refs) >= budget["maxReferences"]:
                    truncated("maxReferences")
                    return False
            key = edge_identity(edge) if edge is not None else None
            new_edge = edge is not None and key not in seen_edges
            if new_edge:
                if len(seen_edges) >= budget["maxEdges"]:
                    truncated("maxEdges")
                    return False
                additions.extend(_evidence_gaps(edge, key, as_of))
            # A large authorized neighborhood can keep offering records after
            # a count bound is reached. Reject those before copying the growing
            # result, while preserving evidence checks and truncation priority.
            candidate = deepcopy(result)
            if new_node:
                candidate["nodes"].append(nodes[node_id])
            elif new_reference:
                candidate["references"].append({"address": node_id, "status": "unavailable", "reason": "offline"})
            if new_edge:
                candidate["edges"].append(edge)
            if group:
                members = candidate["groups"].setdefault(group, [])
                if node_id not in members:
                    members.append(node_id)
                    members.sort()
            candidate["gaps"].extend(gap for gap in additions if gap not in candidate["gaps"])
            if not fits(candidate):
                truncated("maxBytes")
                return False
            result.update(candidate)
            (seen_nodes if node_id in nodes else seen_refs).add(node_id)
            if edge is not None:
                seen_edges.add(key)
            return True

        anchor = request["target"]["id"]
        if anchor not in nodes:
            result["gaps"].append({"state": "unknown", "reason": "target-unavailable"})
            if not fits(result):
                raise ContextError("maxBytes cannot hold the context response envelope")
            return result
        if not admit(anchor):
            return result
        if self._collection is not None:
            self._add_collection(result, budget, fits, truncated)
        outgoing, incoming = {}, {}
        for edge in self._graph["edges"]:
            outgoing.setdefault(edge["source"], []).append(edge)
            incoming.setdefault(edge["target"], []).append(edge)
        for hop in self._recipe["hops"]:
            index = outgoing if hop["direction"] == "out" else incoming
            other_key = "target" if hop["direction"] == "out" else "source"
            frontier, visited = deque([(anchor, 0)]), {anchor}
            while frontier:
                current, depth = frontier.popleft()
                for edge in index.get(current, []):
                    if edge["rel"] != hop["rel"]:
                        continue
                    if depth >= budget["maxHops"]:
                        # Only report bounds encountered on the authorized view.
                        if (edge_identity(edge) not in seen_edges
                                or edge[other_key] not in result["groups"].get(hop["as"], [])):
                            truncated("maxHops")
                        continue
                    other = edge[other_key]
                    if not admit(other, edge=edge, group=hop["as"]):
                        continue
                    if hop["transitive"] and other in nodes and other not in visited:
                        visited.add(other)
                        frontier.append((other, depth + 1))
        result["nodes"].sort(key=lambda n: n["id"])
        result["edges"].sort(key=edge_identity)
        result["references"].sort(key=lambda r: r["address"])
        if self._references is not None:
            self._resolve_references(result, budget, fits, truncated, as_of)
        result["gaps"].sort(key=lambda g: encode(g))
        return deepcopy(result)

    def _resolve_references(self, result, budget, fits, truncated, as_of):
        """Resolve only admitted references; peer rows never become local nodes."""
        resolved_rows = self._references.resolve_many(
            [row['address'] for row in result['references']], max_bytes=budget['maxBytes'])
        for index, (reference, resolved) in enumerate(zip(result['references'], resolved_rows)):
            candidate = deepcopy(result)
            candidate["references"][index] = resolved
            if resolved["status"] == "resolved":
                try:
                    gaps = _evidence_gaps(resolved["record"], resolved["target"], as_of)
                except ContextError:
                    # The source realm must validate records; a bad source cannot
                    # add unvalidated evidence to an otherwise useful context.
                    resolved = {"address": reference["address"], "status": "unavailable",
                                "reason": "invalid-evidence"}
                    candidate["references"][index] = resolved
                else:
                    candidate["gaps"].extend(gap for gap in gaps if gap not in candidate["gaps"])
            if not fits(candidate):
                resolved = {"address": reference["address"], "status": "unavailable", "reason": "maxBytes"}
                result["references"][index] = resolved
                truncated("maxBytes")
            else:
                result.update(candidate)
                if resolved.get("reason") == "maxBytes":
                    truncated("maxBytes")

    def _add_collection(self, result, budget, fits, truncated):
        """Keep each question with its evidence atomically, within wire bounds."""
        collection = self._collection
        candidate = deepcopy(result)
        candidate["coverage"] = {**deepcopy(collection), "questions": [], "evidence": []}
        if not fits(candidate):
            result["coverage"]["state"] = "truncated"
            truncated("maxBytes")
            return
        result.update(candidate)
        evidence = {row["id"]: row for row in collection["evidence"]}
        included = set()
        for question in collection["questions"]:
            if len(result["coverage"]["questions"]) >= budget["maxQuestions"]:
                result["coverage"]["state"] = "truncated"
                truncated("maxQuestions")
                break
            candidate = deepcopy(result)
            candidate["coverage"]["questions"].append(question)
            added = set(question["evidence"]) - included
            candidate["coverage"]["evidence"].extend(evidence[key] for key in sorted(added))
            if question["state"] in ("missing", "partial", "stale"):
                candidate["gaps"].append({"question": question["question"], "state": question["state"],
                                          "reason": "collection-requirement-" + question["state"]})
            if not fits(candidate):
                result["coverage"]["state"] = "truncated"
                truncated("maxBytes")
                continue
            result.update(candidate)
            included.update(added)
        result["coverage"]["evidence"].sort(key=lambda row: row["id"])
