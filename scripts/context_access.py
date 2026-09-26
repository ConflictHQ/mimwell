"""The trusted read boundary used before context traversal (#55).

Bindings come from the host's pinned collection/store configuration, never from
an imported graph or a context request. Authorization uses the host's current
time, independently of a question's historical as-of basis. A missing binding
denies the record. This module emits neither denied identities nor denied counts.
"""
from __future__ import annotations

from copy import deepcopy

from knowledge_policy import Policy, PolicyError, fingerprint, timestamp


class ContextAccessError(ValueError):
    pass


def edge_identity(edge):
    """Bind the exact edge snapshot, including its evidence and parallel identity."""
    return fingerprint(edge)


def record_paths(record, *, edge=False):
    """Match the compiled-record path surfaces used by the portal access seam."""
    paths = set()

    def add(value):
        if isinstance(value, str) and value:
            paths.add(value)
        elif isinstance(value, dict):
            add(value.get("path"))
        elif isinstance(value, list):
            for item in value:
                add(item)

    if not edge:
        add(record.get("source"))
    add(record.get("path"))
    data = record.get("data")
    if isinstance(data, dict):
        add(data.get("path"))
        add(data.get("sourcePaths"))
    evidence = record.get("evidence")
    if isinstance(evidence, dict):
        for field in ("sources", "representations"):
            add(evidence.get(field, []))
    return paths


def policy_principal(policy, actor):
    """The policy principal an authenticated actor reads as (#212).

    The actor's own id, or, when the host bound a pinned person register to the
    policy (``policy.register``), any policy principal (``person:<slug>``,
    ``oidc:<issuer>#<subject>``) that resolves to the same principal as
    ``consumer:<actor>``. None when nothing matches or more than one does.
    """
    register = getattr(policy, "register", None)
    bound = register.resolve("consumer:" + actor) if register is not None and isinstance(actor, str) else None
    matches = {key for key in policy.principals
               if key == actor or (bound is not None and register.resolve(key) == bound)}
    return matches.pop() if len(matches) == 1 else None


class ReadBoundary:
    """One authenticated principal, explicit scope set, and immutable bindings.

    Each binding table maps an identity to a policy resource: nodes by node ID,
    edges by ``edge_identity``, paths by exact source/representation path,
    assertions by evidence assertion ID, and references by external address.
    Scope inclusion is explicit, with no automatic descendant grant. The host
    loads the policy through ``load_policy`` to verify its practice/source pins.
    """

    def __init__(self, policy: Policy, *, actor: str, now: str, scopes, bindings):
        self.policy = policy
        self.actor = actor
        self.principal = policy_principal(policy, actor)
        self.now = now
        self.scopes = frozenset(scopes)
        self.bindings = deepcopy(bindings)
        self._decisions = {}
        at = timestamp(now)
        if (not self.scopes or self.principal is None
                or set(bindings) != {"nodes", "edges", "paths", "assertions", "references"}
                or any(not isinstance(table, dict) for table in bindings.values())):
            raise ContextAccessError("Context read configuration is invalid or unavailable")
        for table in bindings.values():
            if any(not isinstance(key, str) or not key or not isinstance(value, str) or not value
                   for key, value in table.items()):
                raise ContextAccessError("Context bindings must name policy resources")
        for scope in self.scopes:
            try:
                rules, _, _ = policy.effective(scope, at)
            except (KeyError, PolicyError) as exc:
                raise ContextAccessError("Requested context scope is unavailable") from exc
            if self.principal not in rules["readers"]:
                raise ContextAccessError("Requested context scope is unavailable")

    def permits(self, table, identity):
        resource_id = self.bindings[table].get(identity)
        return self.permits_resource(resource_id, identity)

    def permits_resource(self, resource_id, identity):
        """Evaluate an operator-bound resource, never a request-supplied grant."""
        if resource_id not in self._decisions:
            resource = self.policy.resources.get(resource_id)
            allowed = False
            if resource and resource["scope"] in self.scopes:
                request = {"id": "context-read", "resource": resource_id,
                           "record": identity, "mutation": "read", "expectedRevision": None,
                           "reason": "Assemble bounded context", "evidence": [], "sourceResource": None}
                allowed = self.policy.evaluate(request, {"actor": self.principal, "operation": "read",
                                                         "now": self.now})["allowed"]
            self._decisions[resource_id] = allowed
        return self._decisions[resource_id]

    def permits_record(self, table, identity, record):
        if not self.permits(table, identity):
            return False
        if any(not self.permits("paths", path) for path in record_paths(record, edge=table == "edges")):
            return False
        evidence = record.get("evidence")
        if evidence is not None:
            if not isinstance(evidence, dict):
                return False
            assertions = evidence.get("assertions", [])
            related = set(evidence.get("unresolvedAssertions", []))
            for assertion in assertions:
                if not isinstance(assertion, dict) or not isinstance(assertion.get("id"), str):
                    return False
                related.add(assertion["id"])
                for relation in ("contradicts", "supersedes", "retracts"):
                    related.update(assertion.get(relation, []))
            if any(not self.permits("assertions", item) for item in related):
                return False
        return True

    def graph(self, brain):
        """Return only traversable records, without source aggregate metadata.

        A relationship is independently authorized, as are both endpoints. An
        unresolved endpoint survives only with an explicit external-reference
        binding; a denied local node can never be reinterpreted as a remote one.
        """
        nodes = {}
        for node in brain["nodes"]:
            identity = node["id"]
            if identity in nodes:
                raise ContextAccessError("Context graph contains duplicate node identities")
            nodes[identity] = node
        visible = {identity: node for identity, node in nodes.items()
                   if self.permits_record("nodes", identity, node)}
        edges, references = {}, set()
        for edge in brain["edges"]:
            identity = edge_identity(edge)
            if not self.permits_record("edges", identity, edge):
                continue
            endpoints = (edge["source"], edge["target"])
            if any(endpoint not in visible and (endpoint in nodes or endpoint in self.bindings["nodes"]
                                               or not self.permits("references", endpoint))
                   for endpoint in endpoints):
                continue
            # An isolated external-to-external assertion has no local traversal
            # anchor and cannot expand the requested scope on its own.
            if not any(endpoint in visible for endpoint in endpoints):
                continue
            references.update(endpoint for endpoint in endpoints if endpoint not in visible)
            edges[identity] = edge
        return deepcopy({"nodes": [visible[key] for key in sorted(visible)],
                         "edges": [edges[key] for key in sorted(edges)],
                         "references": sorted(references)})
