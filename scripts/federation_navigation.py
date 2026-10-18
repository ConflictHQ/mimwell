"""Bounded alternate paths over already-authorized federation discovery.

This projection names brains and realm authorities. It never resolves a record,
opens a source store, infers enrollment from a directory or grants query access.
"""
from collections import deque
from copy import deepcopy
from pathlib import Path

from brain_federation import FederationError, fields
from context_access import ReadBoundary
from context_bundle import encode
from context_host import _read, load_boundary, read_pinned
from federation_discovery_host import load_discovery
from knowledge_policy import fingerprint, timestamp

LIMITS = {"maxParticipants": 256, "maxLinks": 1024, "maxDepth": 16,
          "maxPaths": 16, "maxExpansions": 4096, "maxBytes": 1048576}
PATH_LIMITS = ["maxBytes", "maxDepth", "maxExpansions", "maxPaths"]


def identity(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 200:
        raise FederationError("Navigation identity must be a bounded nonempty string")


def validate_request(request, *, ceilings=None):
    fields(request, ("protocolVersion", "roots", "focus", "budget"))
    if request["protocolVersion"] != "1.0":
        raise FederationError("Unsupported navigation protocol")
    roots = request["roots"]
    if not isinstance(roots, list) or not 1 <= len(roots) <= 32:
        raise FederationError("Navigation requires explicit bounded roots")
    for root in roots:
        identity(root)
    if len(set(roots)) != len(roots):
        raise FederationError("Duplicate navigation root")
    if request["focus"] is not None:
        identity(request["focus"])
    fields(request["budget"], LIMITS)
    for key, value in request["budget"].items():
        minimum = 0 if key in ("maxLinks", "maxDepth") else 1
        if type(value) is not int or not minimum <= value <= LIMITS[key]:
            raise FederationError("Invalid navigation budget")
        if ceilings is not None and value > ceilings[key]:
            raise FederationError("Navigation exceeds host budget")
    return deepcopy(request)


def _participant(participant):
    # Storage paths, private realm handles and subject addresses are not needed
    # for navigation. A source coordinate remains distinct from a portal URL.
    identity(participant['id'])
    return {"id": participant["id"], "manifest": deepcopy(participant["manifest"]),
            "realms": [{key: realm[key] for key in ("realm", "authority", "revision", "store", "transport")}
                       for realm in participant["realms"]]}


def navigate(view, request):
    request = validate_request(request)
    budget, focus = request["budget"], request["focus"]
    result = {"protocolVersion": "1.0", "graph": {}, "focus": {"participant": focus, "state": "unavailable"},
              "paths": [], "cycleLinks": [], "truncation": []}

    def fits(candidate):
        return len(encode({**candidate, "truncation": PATH_LIMITS})) <= budget["maxBytes"]

    reserved = len(encode({**result, "truncation": PATH_LIMITS})) - 2
    available = budget["maxBytes"] - reserved
    if available <= 0:
        raise FederationError("Navigation budget cannot hold its envelope")
    graph = view.discover(request["roots"], max_participants=budget["maxParticipants"],
                          max_depth=budget["maxDepth"], max_links=budget["maxLinks"], max_bytes=available)
    graph["participants"] = [_participant(p) for p in graph["participants"]]
    result["graph"] = graph
    participants = {p["id"] for p in graph["participants"]}
    result["focus"]["state"] = "none" if focus is None else "available" if focus in participants else "unavailable"
    if not fits(result):
        raise FederationError("Navigation budget cannot hold its envelope")
    if focus is None or focus not in participants:
        return result
    outgoing = {}
    relations = {}
    for edge in graph["links"]:
        edge_id = fingerprint(edge)
        relations[edge_id] = edge['relation']
        outgoing.setdefault(edge["source"], []).append((edge, edge_id))
    queue = deque(((root,), ()) for root in sorted(request["roots"]) if root in participants)
    cycles, expansions = set(), 0

    def truncated(reason):
        if reason not in result["truncation"]:
            result["truncation"].append(reason)
            result["truncation"].sort()

    while queue:
        if expansions >= budget["maxExpansions"]:
            truncated("maxExpansions")
            break
        nodes, edges = queue.popleft()
        expansions += 1
        current = nodes[-1]
        if current == focus:
            if len(result["paths"]) >= budget["maxPaths"]:
                truncated("maxPaths")
                break
            path = {"participants": list(nodes), "links": list(edges),
                    "relations": [relations[edge_id] for edge_id in edges]}
            path["id"] = fingerprint(path)
            candidate = {**result, "paths": [*result["paths"], path]}
            if not fits(candidate):
                truncated("maxBytes")
                break
            result.update(candidate)
            continue
        for edge, edge_id in outgoing.get(current, []):
            if edge["target"] in nodes:
                if edge_id not in cycles:
                    candidate = {**result, "cycleLinks": sorted([*result["cycleLinks"], edge_id])}
                    if fits(candidate):
                        result.update(candidate)
                        cycles.add(edge_id)
                    else:
                        truncated("maxBytes")
                continue
            if len(edges) >= budget["maxDepth"]:
                truncated("maxDepth")
                continue
            if expansions + len(queue) >= budget["maxExpansions"]:
                truncated("maxExpansions")
                continue
            queue.append(((*nodes, edge["target"]), (*edges, edge_id)))
    return result


class NavigationSnapshot:
    """Pinned observations and policy, reevaluated at the final observed host time."""

    def __init__(self, boundary, discovery, request):
        self._boundary, self._discovery, self._request = boundary, discovery, deepcopy(request)
        self.result = self.project(boundary.now)

    def project(self, now):
        previous = self._boundary
        if timestamp(now) < timestamp(previous.now):
            raise FederationError('Navigation clock moved backwards')
        boundary = ReadBoundary(previous.policy, actor=previous.actor, now=now,
                                scopes=previous.scopes, bindings=previous.bindings)
        catalog, bindings, reviews = self._discovery
        return navigate(catalog.scoped(boundary, bindings=bindings, reviewed_subjects=reviews), self._request)


def load_navigation(root, config_path, *, actor, now, request, return_snapshot=False):
    """Host-owned paths/identity/time; no record or remote credential loader."""
    request = validate_request(request)
    root = Path(root)
    if root.is_symlink():
        raise FederationError("Navigation root cannot be a symlink")
    config = _read(root, config_path)
    fields(config, ("protocolVersion", "policy", "bindings", "scopes", "discovery"))
    if config["protocolVersion"] != "1.0":
        raise FederationError("Unsupported navigation host")
    boundary, _ = load_boundary(root, config, actor=actor, now=now)
    discovery = load_discovery(root, read_pinned(root, config["discovery"], max_bytes=65536),
                               max_metadata_bytes=8 * 1024 * 1024, max_manifests=256)
    snapshot = NavigationSnapshot(boundary, discovery, request)
    return snapshot if return_snapshot else snapshot.result
