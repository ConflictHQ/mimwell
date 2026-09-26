"""Explicit, bounded graph composition over independently published source snapshots.

Coordinates wrap source records; neither local IDs nor evidence assertions are
rewritten. The result is a projection, never a new authority or permission grant.
"""
from copy import deepcopy

from brain_federation import FederationError, fields, text
from context_access import edge_identity
from context_bundle import encode
from federation_resolution import LocalRecordSource, publication_key, unavailable
from knowledge_policy import fingerprint

METHOD = "authorized-graph-composition/v1"
LIMITS = {"maxSources": 64, "maxNodes": 10000, "maxEdges": 20000, "maxBytes": 16 * 1024 * 1024}


class _Wire:
    """Incremental accounting for this contract's canonical JSON array appends."""

    def __init__(self, result, reasons, maximum):
        self.result, self.maximum = result, maximum
        self.used = len(encode({**result, "truncation": reasons}))

    def fits(self):
        return self.used <= self.maximum

    def append(self, field, row):
        cost = len(encode(row)) - 1 + bool(self.result[field])
        if self.used + cost > self.maximum:
            return False
        self.result[field].append(row)
        self.used += cost
        return True


def coordinate(participant, realm, address):
    return {"participant": participant, "realm": realm, "address": address}


def coordinate_key(value):
    fields(value, ("participant", "realm", "address"))
    for item in value.values():
        text(item)
    return value["participant"], value["realm"], value["address"]


def edge_publication_key(participant, realm, authority, revision, edge):
    return publication_key(participant, realm, authority, revision, {"edge": edge})


def graph_revision(records, edges, references):
    return fingerprint({"nodes": {r["id"]: r for r in records},
                        "edges": {edge_identity(e): e for e in edges}, "references": references})


def budgets(value, *, source=False):
    expected = set(LIMITS) - ({"maxSources"} if source else set())
    fields(value, expected)
    for key in expected:
        if type(value[key]) is not int or not 1 <= value[key] <= LIMITS[key]:
            raise FederationError("Composition budget outside supported bounds")


def validate_request(request):
    fields(request, ("protocolVersion", "sources", "budget"))
    if request["protocolVersion"] not in ("1.0", "2.0") or not isinstance(request["sources"], list):
        raise FederationError("Unsupported composition request")
    if len(request["sources"]) > 1024:
        raise FederationError("Too many source selectors")
    budgets(request["budget"])
    selected = {}
    for target in request["sources"]:
        fields(target, ("participant", "realm", "revision"))
        for value in target.values():
            text(value)
        key = target["participant"], target["realm"]
        if key in selected and selected[key] != target:
            raise FederationError("Conflicting source revision selections")
        selected[key] = deepcopy(target)
    return [selected[k] for k in sorted(selected)]


def validate_snapshot(outcome, target, authority, ontology, budget, *, protection_sha256=None):
    """Validate remote structure, exact content/provenance and endpoint mappings.

    The authenticated source remains responsible for its access/publication
    decision. Recomputing fingerprints does not make untrusted receipts authentic.
    """
    from federation_http import validate_outcome
    if isinstance(outcome, dict) and outcome.get("status") == "unavailable":
        validate_outcome(outcome, target, authority, ontology, allow_protection=protection_sha256 is not None)
        return
    fields(outcome, ("status", "nodes", "edges", "truncation") +
           (('protection',) if protection_sha256 is not None else ()))
    protection = None
    if protection_sha256 is not None:
        from federation_protection import source_receipt
        protection = source_receipt(outcome['protection'], expected=protection_sha256)
    if outcome["status"] != "composed":
        raise FederationError("Unsupported graph snapshot")
    truncation = outcome["truncation"]
    if (not isinstance(truncation, list) or any(not isinstance(t, str) for t in truncation)
            or truncation != sorted(set(truncation))
            or set(truncation) - {"maxBytes", "maxNodes", "maxEdges", "endpointPartial"}):
        raise FederationError("Invalid graph truncation")
    from ontology import Registry
    registry = Registry(ontology) if target["realm"] == "brain" else None
    local_nodes = set()
    basis = None
    for table, limit in (("nodes", "maxNodes"), ("edges", "maxEdges")):
        rows = outcome[table]
        if not isinstance(rows, list) or len(rows) > budget[limit]:
            raise FederationError("Graph snapshot exceeded record budget")
        keys = []
        for row in rows:
            fields(row, ("coordinate", "record", "provenance") if table == "nodes" else
                   ("coordinate", "record", "provenance", "source", "target"))
            key = coordinate_key(row["coordinate"])
            if key[:2] != (target["participant"], target["realm"]):
                raise FederationError("Foreign graph coordinate")
            validate_outcome({"status": "resolved", "record": row["record"], "provenance": row["provenance"]},
                             {**target, "address": key[2]}, authority, ontology, edge=table == "edges", registry=registry,
                             protection=protection)
            current = {k: row["provenance"][k] for k in
                       ("policySha256", "ontologySha256", "bindingsSha256", "evaluatedAt")}
            if basis is not None and current != basis:
                raise FederationError("Mixed authorization within source snapshot")
            basis = current
            keys.append(key)
            if table == "nodes":
                local_nodes.add(key)
            else:
                endpoints = []
                for name in ("source", "target"):
                    endpoint = coordinate_key(row[name])
                    if endpoint[:2] == key[:2] and (
                            endpoint not in local_nodes or endpoint[2] != row["record"][name]):
                        raise FederationError("Graph edge endpoint mismatch")
                    expected = (*key[:2], row["record"][name])
                    if expected in local_nodes and endpoint != expected:
                        raise FederationError("Local endpoint was remapped to another participant")
                    endpoints.append(endpoint)
                if not any(e in local_nodes for e in endpoints):
                    raise FederationError("Graph edge has no local anchor")
        if keys != sorted(set(keys)):
            raise FederationError("Duplicate or unsorted graph coordinates")


class LocalGraphSource(LocalRecordSource):
    """Opt-in graph snapshot; caller validates records with the owning ontology.

    References are operator-owned mappings for exact nonlocal endpoint strings.
    An existing or bound local node can never be reinterpreted as a remote one.
    """

    def __init__(self, *, edges, references, **options):
        super().__init__(**options)
        self._configure_graph(edges, references)

    def _configure_graph(self, edges, references):
        if not isinstance(edges, list) or not isinstance(references, dict):
            raise FederationError("Invalid graph source")
        self._edges = {}
        for edge in edges:
            if not isinstance(edge, dict):
                raise FederationError("Invalid graph edge")
            for key in ("source", "target", "rel"):
                text(edge.get(key))
            self._edges[edge_identity(edge)] = deepcopy(edge)
        for address, target in references.items():
            text(address)
            coordinate_key(target)
            if (target["participant"], target["realm"]) == (self.participant, self.realm):
                raise FederationError("Remote references cannot alias the local realm")
            if address in self._records or address in self._boundary.bindings["nodes"]:
                raise FederationError("A local node cannot be mapped to a remote reference")
        self._references = deepcopy(references)
        self._revision = graph_revision(list(self._records.values()), list(self._edges.values()), references)

    def _revalidate_edge(self, row, options):
        identity = row['coordinate']['address']
        edge = self._edges.get(identity)
        if edge is None or edge != row['record']:
            return unavailable()
        resources = []
        for address in (edge['source'], edge['target']):
            if address in self._records:
                if self.resolve(address, **options)['status'] != 'resolved':
                    return unavailable()
            elif (address not in self._references or not self._boundary.permits('references', address)):
                return unavailable()
            else:
                resources.append(self._boundary.bindings['references'][address])
        return self._release(edge, 'edges', identity, **options, extra_resources=resources,
                             key=edge_publication_key(self.participant, self.realm, self.authority,
                                                      self.revision, edge))

    def snapshot(self, *, revision, audience, consumer, now, max_nodes, max_edges, max_bytes,
                 protection_sha256=None):
        budget = {"maxNodes": max_nodes, "maxEdges": max_edges, "maxBytes": max_bytes}
        budgets(budget, source=True)
        if consumer != self._consumer or now != self._boundary.now:
            return unavailable()
        if revision != self.revision:
            return unavailable("revision-changed")
        protected = protection_sha256 is not None
        if protected != (self._protection is not None):
            return unavailable('unsupported-contract')
        if protected and protection_sha256 != self._protection.sha256:
            return unavailable('protection-changed')
        result = {"status": "composed", "nodes": [], "edges": [], "truncation": []}
        if protected:
            result['protection'] = self._protection.receipt()
        reasons = ["maxBytes", "maxNodes", "maxEdges", "endpointPartial"]

        wire = _Wire(result, reasons, max_bytes)
        if not wire.fits():
            return unavailable("maxBytes")
        visible, included = set(), set()
        for address in sorted(self._records):
            outcome = self.resolve(address, revision=revision, audience=audience, consumer=consumer, now=now,
                                   protected=protected)
            if outcome["status"] != "resolved":
                continue
            visible.add(address)
            if len(result["nodes"]) >= max_nodes:
                result["truncation"].append("maxNodes")
                continue
            node = {"coordinate": coordinate(self.participant, self.realm, address),
                    "record": outcome["record"], "provenance": outcome["provenance"]}
            if wire.append("nodes", node):
                included.add(address)
            else:
                result["truncation"].append("maxBytes")
        for identity, edge in sorted(self._edges.items()):
            endpoints, resources = [], []
            allowed = True
            for address in (edge["source"], edge["target"]):
                if address in visible:
                    endpoints.append(coordinate(self.participant, self.realm, address))
                elif (address in self._records or address in self._boundary.bindings["nodes"]
                      or address not in self._references
                      or not self._boundary.permits("references", address)):
                    allowed = False
                    break
                else:
                    endpoints.append(deepcopy(self._references[address]))
                    resources.append(self._boundary.bindings["references"][address])
            if not allowed or not any(a in visible for a in (edge["source"], edge["target"])):
                continue
            key = edge_publication_key(self.participant, self.realm, self.authority, self.revision, edge)
            outcome = self._release(edge, "edges", identity, revision=revision, audience=audience,
                                    consumer=consumer, now=now, key=key, extra_resources=resources, protected=protected)
            if outcome["status"] != "resolved":
                continue
            # Only admitted edges affect partial/budget metadata.
            if any(a in visible and a not in included for a in (edge["source"], edge["target"])):
                result["truncation"].append("endpointPartial")
                continue
            if len(result["edges"]) >= max_edges:
                result["truncation"].append("maxEdges")
                continue
            row = {"coordinate": coordinate(self.participant, self.realm, identity),
                   "source": endpoints[0], "target": endpoints[1],
                   "record": outcome["record"], "provenance": outcome["provenance"]}
            if not wire.append("edges", row):
                result["truncation"].append("maxBytes")
        result["truncation"] = sorted(set(result["truncation"]))
        return deepcopy(result)


def compose(resolver, request):
    """Join only explicit coordinates whose independently released nodes exist.

    Independent source read points are not an atomic transaction. The host must
    create a fresh resolver for each operation; durable indexes need a separate
    refresh/withdrawal protocol and must not serve this output as a permission.
    """
    request = deepcopy(request)
    selected = validate_request(request)
    budget = request["budget"]
    protected = request['protocolVersion'] == '2.0'
    result = {"protocolVersion": request['protocolVersion'],
              "method": 'authorized-graph-composition/v2' if protected else METHOD, "federation": resolver.federation,
              "authorization": resolver.authorization, "sources": [], "nodes": [], "edges": [],
              "truncation": [], "coverage": {"state": "not-assessed"}}
    reasons = [*LIMITS, "sourcePartial", "endpointPartial"]

    wire = _Wire(result, reasons, budget["maxBytes"])
    if not wire.fits():
        raise FederationError("Composition budget cannot hold its envelope")
    if len(selected) > budget["maxSources"]:
        result["truncation"].append("maxSources")
    pending, pending_bytes = [], 0
    present = set()
    collected, limited = resolver._collect(selected[:budget['maxSources']],
        lambda target: resolver.compose_source(target, max_nodes=budget['maxNodes'], max_edges=budget['maxEdges'],
            max_bytes=budget['maxBytes'], protected=protected), max_bytes=budget['maxBytes'])
    if limited:
        result['truncation'].append('maxBytes')
    for target, outcome in collected:
        protection = None
        if protected and outcome['status'] == 'composed':
            from federation_protection import source_receipt, source_requirements
            selection = resolver._protection[(target['participant'], target['realm'])]
            try:
                protection = {'source': source_receipt(outcome['protection'], expected=selection['policySha256']),
                              'selected': deepcopy(selection['selected'])}
                source_requirements(protection, outcome['nodes'] + outcome['edges'])
            except (ValueError, KeyError, TypeError):
                outcome = unavailable('protection-unavailable')
        receipt = {"source": target, "status": outcome["status"]}
        if outcome["status"] == "composed":
            receipt["truncation"] = outcome["truncation"]
            receipt["snapshotSha256"] = fingerprint(outcome)
            if protected:
                receipt['protection'] = protection
            if outcome["truncation"]:
                result["truncation"].append("sourcePartial")
        else:
            receipt["reason"] = outcome["reason"]
        if not wire.append("sources", receipt):
            result["truncation"].append("maxBytes")
            continue
        for node in outcome.get("nodes", []):
            key = coordinate_key(node["coordinate"])
            if key in present:
                raise FederationError("Conflicting node coordinate")
            if len(result["nodes"]) >= budget["maxNodes"]:
                result["truncation"].append("maxNodes")
                continue
            if wire.append("nodes", node):
                present.add(key)
            else:
                result["truncation"].append("maxBytes")
        for edge in outcome.get("edges", []):
            size = len(encode(edge))
            if len(pending) >= budget["maxEdges"]:
                result["truncation"].append("maxEdges")
            elif pending_bytes + size > budget["maxBytes"]:
                result["truncation"].append("maxBytes")
            else:
                pending.append(edge)
                pending_bytes += size
    for edge in pending:
        if any(coordinate_key(edge[k]) not in present for k in ("source", "target")):
            result["truncation"].append("endpointPartial")
            continue
        if len(result["edges"]) >= budget["maxEdges"]:
            result["truncation"].append("maxEdges")
            continue
        if not wire.append("edges", edge):
            result["truncation"].append("maxBytes")
    result["truncation"] = sorted(set(result["truncation"]))
    return deepcopy(result)
