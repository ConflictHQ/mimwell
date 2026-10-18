"""Shared read-only operating views over a brain's compiled snapshot (#91).

One host-selected interface for store/projection health, registered source
(connector) probes, federation coverage and upgrade differences. Every view reads
the compiled context snapshot that the context host already serves (pinned graph,
policy and bindings) plus existing observers; none opens a native authority, so a
file-only brain needs no database. Views never write, refresh, enroll, migrate or
authorize an upgrade. Configured, observed, stale, invalid and unknown stay
distinct, and unknown never becomes healthy.

Requests name a view only. The trusted host selects paths, roots, recipes, sources,
principals and grants; the caller cannot supply any of them.
"""

from copy import deepcopy
import json
from pathlib import Path
import re

from brain_federation import fields
from context_access import ContextAccessError, ReadBoundary
from context_bundle import encode
from context_host import _host_config, decode, load_boundary, read_pinned
from knowledge_operations import MAX_REQUEST_BYTES, private_path
from knowledge_policy import fingerprint, timestamp
from knowledge_store import StoreError, utcnow

VIEWS = ("store.health", "source.health", "federation.coverage", "upgrade.diff")
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
EMPTY_BINDINGS = ("nodes", "edges", "paths", "assertions", "references")


def load_host(root, relative):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise StoreError("Operating root must be a real directory")
    with private_path(root, relative).open("rb") as stream:
        raw = stream.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise StoreError("Operating host exceeds its limit")
    host = decode(raw)
    optional = tuple(key for key in ("sources", "federation", "upgrade") if key in host)
    fields(host, ("format", "principalsByUid", "snapshot", "grants", *optional))
    if (
        host["format"] != "operating-views-host/v1"
        or not isinstance(host["principalsByUid"], dict)
        or not isinstance(host["snapshot"], str)
        or not isinstance(host["grants"], dict)
    ):
        raise StoreError("Invalid operating host")
    for uid, actor in host["principalsByUid"].items():
        if not re.fullmatch(r"[0-9]+", uid) or not isinstance(actor, str) or not actor.strip():
            raise StoreError("Invalid local principal mapping")
    for actor, views in host["grants"].items():
        if (
            not isinstance(actor, str) or not actor.strip() or not isinstance(views, list)
            or any(view not in VIEWS for view in views) or len(views) != len(set(views))
        ):
            raise StoreError("Invalid operating grant")
    if "sources" in host:
        if not isinstance(host["sources"], dict) or len(host["sources"]) > 1000:
            raise StoreError("Invalid source registrations")
        for identity, source in host["sources"].items():
            fields(source, ("registration", "root", "scopes", "maxBytes"))
            if (
                not isinstance(source["registration"], dict) or source["registration"].get("id") != identity
                or not isinstance(source["root"], str) or not Path(source["root"]).is_absolute()
                or not isinstance(source["scopes"], list) or not source["scopes"]
                or any(not isinstance(scope, str) for scope in source["scopes"])
            ):
                raise StoreError("Invalid source registration")
    if "federation" in host:
        fields(host["federation"], ("host", "request"))
    if "upgrade" in host:
        fields(host["upgrade"], ("source", "target"))
        for side in ("source", "target"):
            fields(host["upgrade"][side], ("root", "catalogs", "recipe"))
            entry = host["upgrade"][side]
            if (
                not isinstance(entry["root"], str) or not Path(entry["root"]).is_absolute()
                or not isinstance(entry["catalogs"], list) or not 1 <= len(entry["catalogs"]) <= 16
            ):
                raise StoreError("Invalid upgrade selection")
            fields(entry["recipe"], ("id", "version"))
    return host


def validate_request(request):
    fields(request, ("format", "view"))
    if request["format"] != "operating-view-request/v1" or request["view"] not in VIEWS:
        raise StoreError("Unsupported operating view")


def snapshot(root, host, *, actor, now):
    """The compiled snapshot pins and a boundary that admits this actor, or a refusal."""
    root, config = _host_config(root, host["snapshot"], "graph")
    graph = config["graph"]
    fields(graph, ("path", "sha256", "asOf"))
    read_pinned(root, {"path": graph["path"], "sha256": graph["sha256"]}, raw=True)
    boundary, _ = load_boundary(root, config, actor=actor, now=now)
    return boundary, {"graph": graph["path"], "graphSha256": graph["sha256"], "asOf": graph["asOf"]}


def store_health(root, basis):
    """Declared authority plus delivered/regenerable projection observations from files."""
    from knowledge_store import adopted_authority
    from projection_freshness import observe, observe_delivered
    from projection_receipts import ProjectionError

    report = {"format": "store-health/v1", "snapshot": deepcopy(basis),
              "authority": {"store": "files", "binding": None, "projections": None, "state": "declared"},
              "delivered": {"state": "not-applicable", "reason": "no-committed-projections", "projections": []},
              "regenerable": observe(root, brain_sha256=basis["graphSha256"]),
              "authorityOpened": False, "executionAuthorized": False}
    try:
        config = json.loads((Path(root) / "client.config.json").read_text())
        authority = adopted_authority(config)
    except (OSError, ValueError, StoreError):
        report["authority"] = {"store": None, "binding": None, "projections": None, "state": "invalid"}
        report["delivered"] = {"state": "unknown", "reason": "authority-declaration-unavailable", "projections": []}
        return report
    if authority is None:
        return report
    report["authority"] = {"store": authority["store"], "binding": authority.get("binding"),
                           "projections": authority.get("projections"), "state": "declared"}
    if authority.get("projections") != "committed":
        report["delivered"]["reason"] = "live-projections-read-at-request-time"
        return report
    try:
        # The snapshot view never opens the authority: outbox lag stays unknown.
        observed = observe_delivered(root, authority.get("binding"), None)
    except (ProjectionError, OSError, ValueError, KeyError, TypeError):
        report["delivered"] = {"state": "invalid", "reason": "projection-receipts-invalid", "projections": []}
        return report
    report["delivered"] = {"state": "receipted" if observed else "empty", "reason": "receipts-verified-lag-unknown",
                           "projections": observed}
    return report


def source_health(host, policy, *, actor, clock):
    """Probe each registered source this actor may read; unreadable ones are not listed."""
    from intake_capture import CaptureError
    from source_health import observe_source

    observations = []
    for identity in sorted(host.get("sources", {})):
        source = host["sources"][identity]

        def boundary(source=source):
            return ReadBoundary(policy, actor=actor, now=clock(), scopes=source["scopes"],
                                bindings={key: {} for key in EMPTY_BINDINGS})

        try:
            observations.append(observe_source(boundary, deepcopy(source["registration"]),
                                               root=source["root"], max_bytes=source["maxBytes"]))
        except (ContextAccessError, CaptureError):
            continue
    return {"format": "source-health-list/v1", "sources": observations, "upstreamFreshness": "unknown"}


def federation_coverage(root, host, *, actor, now):
    """Declared topology visible under current policy; navigation is not a connector probe."""
    from federation_navigation import load_navigation

    settings = host["federation"]
    result = load_navigation(root, settings["host"], actor=actor, now=now, request=settings["request"])
    graph = result["graph"]
    # The evaluation time belongs to the response envelope; the view itself must be
    # comparable at the final gate.
    graph.pop("authorization", None)
    visible = [p["id"] for p in graph["participants"]]
    return {
        "format": "federation-coverage/v1",
        "roots": list(settings["request"]["roots"]),
        "visibleParticipants": [{"id": p["id"], "realms": deepcopy(p["realms"])} for p in graph["participants"]],
        "unavailableRoots": sorted(set(settings["request"]["roots"]) - set(visible)),
        "links": len(graph["links"]),
        "truncation": sorted(set(graph.get("truncation", [])) | set(result["truncation"])),
        "queriedParticipants": [],
        "coverage": "declared-topology-only",
        "navigationSha256": fingerprint(result),
    }


def upgrade_diff(host, *, as_of):
    """Existing recipe compatibility comparison; never authorizes execution."""
    from brain_upgrade import compare, observe

    observations = []
    for side in ("source", "target"):
        entry = host["upgrade"][side]
        side_root = Path(entry["root"])
        documents = [read_pinned(side_root, pin) for pin in entry["catalogs"]]
        observations.append(observe(documents, side_root, deepcopy(entry["recipe"]), as_of=as_of))
    return compare(*observations)


def observe_view(root, host, view, *, actor, clock, boundary, basis):
    if view == "store.health":
        return store_health(root, basis)
    if view == "source.health":
        return source_health(host, boundary.policy, actor=actor, clock=clock)
    if view.split(".")[0] not in host:
        raise StoreError("Operating view is not configured")
    if view == "federation.coverage":
        return federation_coverage(root, host, actor=actor, now=boundary.now)
    return upgrade_diff(host, as_of=basis["asOf"])


def run(root, host_config, request, *, actor, clock=utcnow, authorize=None, max_response_bytes=MAX_RESPONSE_BYTES):
    """Trusted identity/clock; authorize() refreshes transport identity at each gate."""
    if type(max_response_bytes) is not int or not 1 <= max_response_bytes <= MAX_RESPONSE_BYTES:
        raise StoreError("Invalid operating response bound")
    validate_request(request)
    root = Path(root).absolute()
    host = load_host(root, host_config)
    view = request["view"]
    if view not in host["grants"].get(actor, []):
        raise StoreError("Operating view unavailable")

    def guard():
        if authorize is not None and authorize() != actor:
            raise StoreError("Operating identity changed")
        if load_host(root, host_config) != host:
            raise StoreError("Operating host selection changed")

    guard()
    at = clock()
    boundary, basis = snapshot(root, host, actor=actor, now=at)  # Policy admits the actor before any read.
    native = observe_view(root, host, view, actor=actor, clock=clock, boundary=boundary, basis=basis)
    final_at = clock()
    if timestamp(final_at) < timestamp(at):
        raise StoreError("Operating clock moved backwards")
    guard()
    final, final_basis = snapshot(root, host, actor=actor, now=final_at)
    if final_basis != basis:
        raise StoreError("Compiled snapshot changed; observe again")
    # Probes already revalidate their own authorization; deterministic views must
    # still hold under the final selection or they are withheld.
    if view != "source.health" and observe_view(
            root, host, view, actor=actor, clock=clock, boundary=final, basis=final_basis) != native:
        raise StoreError("Operating view is no longer releasable")
    response = {
        "format": "operating-view/v1",
        "view": view,
        "snapshot": basis,
        "requestSha256": fingerprint(request),
        "authorization": {"principal": actor, "evaluatedAt": at, "revalidatedAt": final_at},
        "state": "completed",
        "native": native,
        "nativeSha256": fingerprint(native),
    }
    raw = encode(response)
    if len(raw) > max_response_bytes:
        raise StoreError("Operating view exceeds its limit")
    guard()
    return raw
