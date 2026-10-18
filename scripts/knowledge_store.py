"""Authoritative knowledge records, independent of compiled JSON/SQLite indexes.

The host supplies authenticated actor identities. SQL, configuration and backup
administration belong to the trusted operator, not to a claim or model tool.
"""

from __future__ import annotations

from collections import deque
from contextlib import contextmanager
from copy import deepcopy
import datetime as dt
from functools import cached_property
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

from jsonschema import Draft202012Validator
from knowledge_policy import (
    Policy, PolicyError, fingerprint, local_path, timestamp, validate as validate_policy_request,
)
from ontology import Registry
from blob_store import (
    DbBlobStore, decode as decode_blob, encode as encode_blob, open_blob_store, placement, record_locators,
    verify as verify_blob,
)
from sql_dialect import REVIEW_INDEX, MySQLDialect, PostgresDialect, SQLiteDialect, StoreError, unsupported

# Drivers whose state is a local file; a DSN driver has no private path.
LOCAL_DRIVERS = ("sqlite", "files")

ROOT = Path(__file__).resolve().parents[1]
DB_VERSION = 11


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


class LifecycleError(ValueError):
    pass


def _plus_days(value, days):
    return (timestamp(value) + dt.timedelta(days=days)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def lifecycle(record):
    result = record.get("content", {}).get("data", {}).get("lifecycle", {})
    if not isinstance(result, dict):
        raise LifecycleError("record lifecycle must be an object")
    for field in ("observedAt", "validFrom", "validUntil", "confirmedAt", "reviewAt", "expiresAt", "archivedAt", "supersededAt"):
        if field in result:
            try:
                timestamp(result[field])
            except PolicyError as exc:
                raise LifecycleError(f"invalid {field}: {exc}") from exc
    if "validFrom" in result and "validUntil" in result and timestamp(result["validFrom"]) >= timestamp(result["validUntil"]):
        raise LifecycleError("validFrom must precede validUntil")
    if result.get("state") == "archived" and "archivedAt" not in result:
        raise LifecycleError("archived records require archivedAt")
    if result.get("state") == "superseded" and not (result.get("supersededAt") and result.get("supersededBy")):
        raise LifecycleError("superseded records require supersededAt and supersededBy")
    return result


def apply_strategy(policy, resource, record, *, at):
    """Return a proposal payload; this never writes and never invents confirmation."""
    try:
        strategy = policy.lifecycle_strategy(resource, record)
    except PolicyError as exc:
        raise LifecycleError(str(exc)) from exc
    if strategy is None:
        raise LifecycleError("no lifecycle strategy matches this record's kind, source and scope")
    current = lifecycle(record)
    updated = deepcopy(record)
    state = deepcopy(current)
    state.setdefault("state", "current")
    state.setdefault("observedAt", at)
    if strategy["reviewAfterDays"] is not None and "reviewAt" not in state:
        state["reviewAt"] = _plus_days(state["observedAt"], strategy["reviewAfterDays"])
    if strategy["expiresAfterDays"] is not None and "expiresAt" not in state:
        state["expiresAt"] = _plus_days(state["observedAt"], strategy["expiresAfterDays"])
    state["strategyId"] = strategy["id"]
    state["strategySha256"] = fingerprint(strategy)
    updated["content"].setdefault("data", {})["lifecycle"] = state
    effects = evaluate(policy, resource, updated, at=at)
    return {"record": updated, "strategy": strategy, "basis": {"policy": policy.binding, "at": at},
            "effects": effects, "changed": current != state, "dryRun": True}


def evaluate(policy, resource, record, *, at):
    """Effects for ordinary context and operator review at a trusted timestamp."""
    now = timestamp(at)
    state = lifecycle(record)
    strategy = policy.lifecycle_strategy(resource, record)
    effective_until = state.get("validUntil")
    if state.get("expiresAt") and (effective_until is None or timestamp(state["expiresAt"]) < timestamp(effective_until)):
        effective_until = state["expiresAt"]
    valid_from = state.get("validFrom")
    expired = bool(effective_until and now >= timestamp(effective_until))
    not_yet_valid = bool(valid_from and now < timestamp(valid_from))
    archived = state.get("state") == "archived"
    superseded = state.get("state") == "superseded"
    review_due = bool(state.get("reviewAt") and now >= timestamp(state["reviewAt"]))
    action = strategy["expiryAction"] if strategy else "keep"
    excluded = archived or superseded or not_yet_valid or (expired and action in ("exclude", "archive-recommendation"))
    return {"at": at, "strategyId": strategy["id"] if strategy else None,
            "valid": not expired and not not_yet_valid, "expired": expired,
            "notYetValid": not_yet_valid, "reviewDue": review_due,
            "archived": archived, "superseded": superseded,
            "ordinaryContext": "excluded" if excluded else "included",
            "recommendedOperation": "archive" if expired and action == "archive-recommendation" and not archived else
                                    "review" if review_due else None}


def confirm(record, *, at):
    """Stamp a trusted confirmation time; caller must use a reviewed native operation."""
    timestamp(at)
    updated = deepcopy(record)
    state = deepcopy(lifecycle(record))
    state["confirmedAt"] = at
    state["state"] = "current"
    state.pop("archivedAt", None)
    updated["content"].setdefault("data", {})["lifecycle"] = state
    lifecycle(updated)
    return updated


def unarchive(record, *, at):
    if lifecycle(record).get("state") != "archived":
        raise LifecycleError("only an archived record can be unarchived")
    return confirm(record, at=at)


def confirm_with_strategy(policy, resource, record, *, at):
    updated = confirm(record, at=at)
    strategy = policy.lifecycle_strategy(resource, updated)
    if strategy is None:
        return updated
    state = updated["content"]["data"]["lifecycle"]
    if strategy["reviewAfterDays"] is not None:
        state["reviewAt"] = _plus_days(at, strategy["reviewAfterDays"])
    if strategy["expiresAfterDays"] is not None:
        state["expiresAt"] = _plus_days(at, strategy["expiresAfterDays"])
    state["strategyId"] = strategy["id"]
    state["strategySha256"] = fingerprint(strategy)
    lifecycle(updated)
    return updated


def unarchive_with_strategy(policy, resource, record, *, at):
    if lifecycle(record).get("state") != "archived":
        raise LifecycleError("only an archived record can be unarchived")
    return confirm_with_strategy(policy, resource, record, at=at)


def archive(record, *, at):
    timestamp(at)
    updated = deepcopy(record)
    state = deepcopy(lifecycle(record))
    if state.get("state") == "superseded":
        raise LifecycleError("superseded record cannot be archived through the active-record verb")
    state["state"] = "archived"
    state["archivedAt"] = at
    updated["content"].setdefault("data", {})["lifecycle"] = state
    lifecycle(updated)
    return updated


def mark_superseded(record, successor_id, *, at):
    timestamp(at)
    if not isinstance(successor_id, str) or not successor_id or successor_id == record.get("id"):
        raise LifecycleError("a distinct successor identity is required")
    updated = deepcopy(record)
    state = deepcopy(lifecycle(record))
    if state.get("state") == "archived":
        raise LifecycleError("archived record cannot be superseded")
    state.update(state="superseded", supersededAt=at, supersededBy=successor_id)
    updated["content"].setdefault("data", {})["lifecycle"] = state
    lifecycle(updated)
    return updated


def context_records(contract, records, *, at):
    """Filter a selected authority view by stored state and its pinned time policy."""
    visible = []
    for record in records:
        collection = contract.collections[record["collection"]]
        resource = collection["resource"]
        if evaluate(contract.policy, resource, record, at=at)["ordinaryContext"] == "included":
            visible.append(record)
    return visible


def schema_check(value, name):
    schema = json.loads((ROOT / "schemas" / (name + ".schema.json")).read_text())
    errors = list(Draft202012Validator(schema).iter_errors(value))
    if errors:
        raise StoreError("; ".join(f"/{'/'.join(map(str, e.path))}: {e.message}" for e in errors))


def unique(rows):
    result = {}
    for row in rows:
        if row["id"] in result:
            raise StoreError("duplicate contract identity")
        result[row["id"]] = row
    return result


# The substrate matrix (docs/design/substrate-matrix.md). A brain's cell is its authority
# driver (row), blob placement (column), vector/index placement (third axis) and the graph
# role its row serves. contract.json declares it: the authority store's driver, and the
# driver of the store holding the `blobs`, `vectors` or `graph` role (defaults below).
AXES = {
    "authority": ("files", "sqlite", "postgres", "mysql", "mongo", "d1"),
    "blobs": ("fs", "db-blob", "s3", "azure-blob"),
    "vectors": ("local", "in-db", "edge-db", "external"),
    "graph": ("edges-table", "age"),
}
DEFAULT_PLACEMENT = {"blobs": "fs", "vectors": "local", "graph": "edges-table"}
DATABASE_DRIVERS = ("sqlite", "postgres", "mysql")
# The authorities that can keep blobs in their own database (db-blob): mongo in chunked documents.
BLOB_DATABASE_DRIVERS = DATABASE_DRIVERS + ("mongo",)
# Placements with no implementation yet, and the issue that makes them supported.
PLANNED = {}


def cell_name(cell):
    return ", ".join(f"{axis}={cell[axis]}" for axis in AXES)


def cell_status(cell):
    """(status, reason) of one matrix cell: supported, planned (owning issues) or unsupported."""
    authority = cell["authority"]
    if authority == "d1":
        return "unsupported", "d1 is a projection target, never an authority"
    if cell["blobs"] == "db-blob" and authority not in BLOB_DATABASE_DRIVERS:
        return "unsupported", f"db-blob keeps blobs in the authority database and {authority} has none"
    if cell["vectors"] == "in-db" and authority == "mongo":
        return "unsupported", "in-db vectors are SQL vector columns (sqlite-vec, pgvector, MySQL) and mongo has none"
    if cell["vectors"] == "in-db" and authority not in DATABASE_DRIVERS:
        return "unsupported", f"in-db vectors live in the authority database and {authority} has none"
    if cell["graph"] == "age" and authority != "postgres":
        return "unsupported", "age is a Postgres extension"
    issues = sorted({PLANNED[(axis, cell[axis])] for axis in AXES if (axis, cell[axis]) in PLANNED})
    if issues:
        return "planned", " ".join(f"#{issue}" for issue in issues)
    return "supported", ""


def contract_cell(stores, authority):
    """The cell a contract declares; raises naming the cell unless it is supported."""
    cell = {"authority": stores[authority]["driver"], **DEFAULT_PLACEMENT}
    for axis in DEFAULT_PLACEMENT:
        placed = [store["driver"] for store in stores.values() if axis in store["roles"]]
        if len(placed) > 1:
            raise StoreError(f"contract declares more than one {axis} store")
        if placed:
            cell[axis] = placed[0]
    for axis, value in cell.items():
        if value not in AXES[axis]:
            raise StoreError(f"unsupported cell: {axis}={value} is not a {axis} placement (docs/design/substrate-matrix.md)")
    status, reason = cell_status(cell)
    if status == "planned":
        reason = f"no driver until {reason}"
    if status != "supported":
        raise StoreError(f"{status} cell: {cell_name(cell)}: {reason} (docs/design/substrate-matrix.md)")
    return cell


def _with_authority_driver(bundle, driver):
    """A shallow copy of `bundle` whose authority store runs on `driver`, or declares none (None)."""
    contract = bundle["contract"]
    stores = [{**{key: value for key, value in store.items() if key != "driver"},
               **({"driver": driver} if driver is not None else {})} if store["id"] == contract["authority"] else store
              for store in contract["stores"]]
    return {**bundle, "contract": {**contract, "stores": stores}}


def retarget(bundle, driver):
    """`bundle` with its authority store running on `driver`; nothing else changes."""
    return deepcopy(_with_authority_driver(bundle, driver))


def contract_binding(bundle):
    """The contract binding: the bundle's fingerprint with the authority store's `driver` left out.

    The driver is where the store runs, not what the brain declares (ADR #198; decision of
    2026-09-23 on #227), so a cutover between drivers keeps the binding and the journal that
    carries it. Schema 10 and earlier fingerprinted the whole bundle (`legacy_bindings`).
    """
    return fingerprint(_with_authority_driver(bundle, None))


def legacy_bindings(bundle):
    """The bindings schema 10 and earlier gave this bundle, one per authority driver."""
    return frozenset(fingerprint(_with_authority_driver(bundle, driver)) for driver in AXES["authority"])


def cutover_losses(bundle, driver):
    """What a store on `driver` could not hold of the brain `bundle` declares: one `{path, reason}`
    entry per placement the move would lose (the loss shape of knowledge_interchange.project()).
    Empty when the cutover is lossless."""
    stores = {store["id"]: store for store in bundle["contract"]["stores"]}
    cell = {**contract_cell(stores, bundle["contract"]["authority"]), "authority": driver}
    status, reason = cell_status({**DEFAULT_PLACEMENT, "authority": driver})
    if status != "supported":
        return [{"path": "/authority", "reason": reason}]
    losses = []
    for axis in DEFAULT_PLACEMENT:
        status, reason = cell_status({**DEFAULT_PLACEMENT, "authority": driver, axis: cell[axis]})
        if status != "supported":
            losses.append({"path": f"/{axis}", "reason": f"{axis}={cell[axis]}: {reason}"})
    return losses


def adopted_authority(settings):
    """`brain.authority`, after checking it and `brain.stores` against client.config.schema.json.

    The CLI reads client.config.json without validating the whole file, so the placement
    fields it relies on are checked here. Returns None when no authority is adopted.
    """
    brain = settings.get("brain") or {}
    if "path" in (brain.get("authority") or {}):
        raise StoreError("brain.authority.path was replaced by brain.authority.store and a brain.stores dsn; "
                         "see Adopt a local instance in docs/primitives/knowledge-stores.md")
    schema = json.loads((ROOT / "schemas" / "client.config.schema.json").read_text())["properties"]["brain"]
    for key in ("stores", "authority"):
        if key in brain:
            errors = list(Draft202012Validator(schema["properties"][key]).iter_errors(brain[key]))
            if errors:
                raise StoreError("; ".join(f"client.config.json brain.{key}/{'/'.join(map(str, e.path))}: {e.message}"
                                           for e in errors))
    store_ids = [store["id"] for store in brain.get("stores", [])]
    if len(store_ids) != len(set(store_ids)):
        raise StoreError("Duplicate store id in client.config.json brain.stores")
    return brain.get("authority")


def resolve_store_dsn(settings, store_id):
    """Resolve a contract store id to its connection through client.config.json `brain.stores`.

    contract.json declares the topology; `brain.stores[].dsn` only says where this
    environment finds a store: `{"env": NAME}` is read from that variable, `{"secret": REF}`
    names an out-of-band secret this local CLI cannot resolve.
    """
    adopted_authority(settings)
    stores = {store["id"]: store for store in (settings.get("brain") or {}).get("stores") or []}
    if store_id not in stores:
        raise StoreError(f"store not declared in brain.stores: {store_id}")
    dsn = stores[store_id]["dsn"]
    if "env" not in dsn:
        raise StoreError(f"store {store_id} uses a secret dsn, which the local CLI cannot resolve")
    value = os.environ.get(dsn["env"])
    if not value:
        raise StoreError(f"environment variable {dsn['env']} is not set for store {store_id}")
    return value


# The synthetic example policy lives with the practices in the private master; a
# public edition, which never ships practices/, carries the same example beside
# the store contract instead (#441).
EXAMPLE_POLICIES = ("practices/examples/policy.json", "stores/examples/policy.json")


def example_bundle(root, contract=None):
    ontology = json.loads((root / "brain-schema.json").read_text())
    kinds = {kind["id"] for kind in ontology["kinds"]}
    policy_path = next((root / p for p in EXAMPLE_POLICIES if (root / p).is_file()), None)
    if policy_path is None:
        raise StoreError("No example policy found; expected one of " + ", ".join(EXAMPLE_POLICIES))
    policy = json.loads(policy_path.read_text())
    # The example spans every overlay; keep only the resources the composed schema declares (#241).
    policy["resources"] = [r for r in policy["resources"] if r["kind"] in kinds]
    practices = {
        scope["practice"]["path"]: (root / scope["practice"]["path"]).read_text() for scope in policy["scopes"]
    }
    return {
        "contract": json.loads((contract or root / "stores/examples/contract.json").read_text()),
        "ontology": ontology,
        "policy": policy,
        "practices": practices,
    }


def private_path(root, relative, driver):
    if driver not in LOCAL_DRIVERS:
        raise unsupported(driver, "a private local path")
    path = local_path(relative)
    if path.parts[0] != "_internal" or any(
        (root / Path(*path.parts[:i])).is_symlink() for i in range(1, len(path.parts) + 1)
    ):
        raise StoreError("authority state must stay under a private _internal path without symlinks")
    return root / path


def blob_store_for(root, settings, contract):
    """The contract's blob store where this environment finds it; None when the bytes live in
    the authority database (db-blob) or no blobs store is declared. A legacy `brain.blobs`
    must map onto the declared driver."""
    declared = contract.blob_store is not None
    driver = placement(contract.cell["blobs"], declared, (settings.get("brain") or {}).get("blobs"))
    if not declared or driver == "db-blob":
        return None
    location = resolve_store_dsn(settings, contract.blob_store)
    return open_blob_store(driver, contract.blob_store, root / location if driver == "fs" else location)


def vector_store_for(root, settings, contract, authority_driver, authority_location):
    """The contract's vectors store where this environment finds it: the authority database
    itself for in-db, else the store's `brain.stores` dsn (a private directory for local).
    A legacy `semantic.substrate` must map onto the declared driver."""
    # Deferred: vector_role is not part of every catalog component's file pins that
    # ship knowledge_store.py (only the ones that actually reach vectors), so a
    # module-level import here would widen those components' isolated dependency set.
    import vector_role
    declared = contract.vector_store is not None
    driver = vector_role.placement(contract.cell["vectors"], declared, (settings.get("semantic") or {}).get("substrate"))
    if not declared:
        raise StoreError(f"contract.json declares no vectors store (semantic.substrate maps to vectors={driver})")
    if driver == "in-db":
        return vector_role.open_vector_store(driver, authority_location, authority_driver=authority_driver)
    location = resolve_store_dsn(settings, contract.vector_store)
    return vector_role.open_vector_store(driver, private_path(root, location, "files") if driver == "local" else location)


def conformance(root, store_id):
    """Run this engine's authority contract suite (tests/store_cells.py) against the cell of one
    store declared in `root`'s client.config.json; returns its receipt.

    The suite drops and recreates authority tables beside the store's dsn, so the adopted
    authority store is refused: name a disposable store of the same driver.
    """
    if not store_id:
        raise StoreError("conformance requires --store <id>")
    settings = json.loads((root / "client.config.json").read_text())
    if (adopted_authority(settings) or {}).get("store") == store_id:
        raise StoreError(f"store {store_id} is the adopted authority; conformance drops its tables, name a disposable store")
    dsn = resolve_store_dsn(settings, store_id)
    driver = authority_class(dsn).dialect_class.driver
    environment = {**os.environ, "BRAIN_TEST_STORES": driver, "PYTHONDONTWRITEBYTECODE": "1",
                   "PYTHONPATH": os.pathsep.join([str(ROOT / "scripts"), str(ROOT)])}
    if driver not in LOCAL_DRIVERS:
        environment[f"BRAIN_TEST_{driver.upper()}_DSN"] = dsn
    run = subprocess.run([sys.executable, "-m", "tests.store_cells", driver], cwd=ROOT, env=environment,
                         capture_output=True, text=True)
    if run.returncode:
        raise StoreError(f"conformance suite did not run: {run.stderr.strip().splitlines()[-1:]}")
    tests = json.loads(run.stdout)
    counts = {state: sum(outcome.split(":")[0] == state for outcome in tests.values())
              for state in ("passed", "skipped", "failed")}
    return {
        "format": "cell-conformance/v1",
        "store": store_id,
        "cell": cell_name({"authority": driver, **DEFAULT_PLACEMENT}),
        "suite": ["tests/test_knowledge_store.py", "tests/test_store_promotion.py", "tests/test_store_writer_upgrade.py",
                  "tests/test_store_cutover.py"],
        "result": "green" if counts["passed"] and not counts["failed"] else "red",
        "counts": counts,
        "tests": tests,
        "ranAt": utcnow(),
    }


def changed_paths(before, after, path=""):
    if isinstance(before, dict) and isinstance(after, dict):
        result = []
        for key in before.keys() | after.keys():
            child = path + "/" + key.replace("~", "~0").replace("/", "~1")
            if key not in before or key not in after:
                value = before.get(key, after.get(key))
                if isinstance(value, dict) and value:
                    result.extend(changed_paths(before.get(key, {}), after.get(key, {}), child))
                else:
                    result.append(child)
            else:
                result.extend(changed_paths(before[key], after[key], child))
        return result
    return [] if before == after else [path]


class Contract:
    def __init__(self, bundle):
        self.bundle = deepcopy(bundle)
        self.document = self.bundle["contract"]
        schema_check(self.document, "knowledge-store")
        self.registry = Registry(self.bundle["ontology"])
        overlays = self.registry.declaration.get("composition", {}).get("overlays", [])
        self.studio_apps_enabled = ("apps" in overlays and all(
            self.registry.kinds.get(identity, {}).get("node") == node
            for identity, node in (("studio.app", "App"), ("studio.component", "Component"),
                                   ("studio.app-query", "AppQuery"))))
        self.policy = Policy(self.bundle["policy"], self.bundle["ontology"])
        self.binding = contract_binding(self.bundle)
        self.stores = unique(self.document["stores"])
        self.collections = unique(self.document["collections"])
        self.authority = self.document["authority"]
        if self.authority not in self.stores or not {"records", "journal"}.issubset(
            self.stores[self.authority]["roles"]
        ):
            raise StoreError("authority must own records and journal")
        self.cell = contract_cell(self.stores, self.authority)
        # A blob store holds bytes behind locators; it is never an authority for a claim.
        self.blob_store = next((store["id"] for store in self.stores.values() if "blobs" in store["roles"]), None)
        if self.blob_store and self.stores[self.blob_store]["roles"] != ["blobs"]:
            raise StoreError("a blobs store holds only the blobs role; it is never an authority for a claim")
        # The edges table is the single relation authority; a graph store only ever holds a derived projection.
        self.graph_store = next((store["id"] for store in self.stores.values() if "graph" in store["roles"]), None)
        if self.graph_store and self.stores[self.graph_store]["roles"] != ["graph"]:
            raise StoreError("a graph store holds only the graph role; the edges table is the single relation authority")
        # The vector index is a derived projection of records; it is never an authority for a claim.
        self.vector_store = next((store["id"] for store in self.stores.values() if "vectors" in store["roles"]), None)
        if self.vector_store and self.stores[self.vector_store]["roles"] != ["vectors"]:
            raise StoreError("a vectors store holds only the vectors role; the index is a derived projection of records")
        for scope in self.policy.scopes.values():
            practice = scope["practice"]
            text = self.bundle["practices"].get(practice["path"])
            if not isinstance(text, str) or hashlib.sha256(text.encode()).hexdigest() != practice["sha256"]:
                raise StoreError("practice snapshot does not match policy pin")
        for collection in self.collections.values():
            if collection["schemaVersion"] != "1.0.0":
                raise StoreError("collection schema requires an explicit semantic migration")
            resource = self.policy.resources.get(collection["resource"])
            if not resource or resource["kind"] != collection["kind"]:
                raise StoreError("collection kind must match its governed resource")
            mapping = self.registry.kinds[collection["kind"]]["node"]
            if not isinstance(mapping, str):
                raise StoreError("collection requires one explicit compiled node mapping")
            paths = []
            for group in collection["fields"]:
                store = self.stores.get(group["store"])
                if group["store"] == self.graph_store:
                    raise StoreError("a graph store cannot own a field; the edges table is the single relation authority")
                if not store or not {"records", "external-authority"}.intersection(store["roles"]):
                    raise StoreError("projection or backup cannot own a field")
                for path in group["paths"]:
                    if any(path == old or path.startswith(old + "/") or old.startswith(path + "/") for old in paths):
                        raise StoreError("field authority overlaps")
                    paths.append(path)
            if not paths:
                raise StoreError("collection has no field authority")

    @cached_property
    def legacy_bindings(self):
        """History written before schema 11 carries the binding it was written with."""
        return legacy_bindings(self.bundle)

    def writable(self, before, after):
        record = after or before
        collection = self.collections[record["collection"]]
        for path in changed_paths(before or {}, after or {}):
            if path in ("/id", "/kind", "/collection"):
                if before and after:
                    raise StoreError("record identity and kind are immutable")
                continue
            owners = [
                group["store"]
                for group in collection["fields"]
                for root in group["paths"]
                if path == root or path.startswith(root + "/")
            ]
            if owners != [self.authority]:
                raise StoreError(f"field is not owned by this authority: {path}")

    def validate_record(self, record):
        schema_check(record, "knowledge-record")
        if "lifecycle" in record.get("content", {}).get("data", {}):
            lifecycle(record)
        record_kind = self.registry.kinds.get(record["kind"], {}).get("node")
        if self.studio_apps_enabled and record["kind"] == "studio.app":
            from studio_app_attachments import validate_app_attachments
            validate_app_attachments(record)
        elif (self.studio_apps_enabled and record["kind"] in ("studio.component", "studio.app-query")
              and record.get("blobs")):
            raise StoreError("Studio Components and App Queries cannot carry data attachments")
        if self.studio_apps_enabled and record["kind"] in ("studio.app", "studio.component", "studio.app-query"):
            # The enclosing record schema is the accepted content surface: title,
            # inert text/source/owner metadata and the strict profile payload only.
            allowed_content = {"title", "text", "data", "source", "labels", "owner", "status",
                               "durability", "derived"}
            if set(record.get("content", {})) - allowed_content:
                raise StoreError("Studio App records contain unsupported content fields")
            content = record.get("content", {})
            for field, limit in (("title", 512), ("text", 4096), ("owner", 256)):
                if field in content and (not isinstance(content[field], str) or len(content[field]) > limit):
                    raise StoreError("Studio App record exceeds its text field limit")
            if len(encoded(record).encode("utf-8")) > 256 * 1024:
                raise StoreError("Studio App record exceeds its byte limit")
        if record_kind == "Metric":
            content = record["content"]
            data = content.get("data", {})
            schema_check(data, "metric-definition")
            if not all(isinstance(content.get(key), str) and content[key].strip()
                       for key in ("title", "text", "owner")):
                raise StoreError("a governed Metric requires a name, business definition and owner")
        if record_kind == "Term":
            schema_check(record["content"].get("data", {}), "business-term")
            if not all(isinstance(record["content"].get(key), str) and record["content"][key].strip()
                       for key in ("title", "text", "owner")):
                raise StoreError("a governed business term requires a name, definition and owner")
        history = record.get("content", {}).get("data", {}).get("intakeHistory")
        if history is not None:
            from intake_contract import validate_history
            validate_history(history)
        origin = record.get("content", {}).get("data", {}).get("intakeDelivery")
        if origin is not None:
            from intake_delivery import check
            check(origin, 'origin')
        transfer = record.get("content", {}).get("data", {}).get("intakeTransfer")
        if transfer is not None:
            from intake_transfer_store import origin_check
            origin_check(transfer)
        release = record.get("content", {}).get("data", {}).get("intakeRelease")
        if release is not None:
            from intake_transfer import validate_release
            validate_release(release)
        for locator in record_locators(record):
            if locator["store"] != self.blob_store:
                raise StoreError(f"blob locator names {locator['store']}, which is not the contract's blobs store")
        collection = self.collections.get(record["collection"])
        if not collection or record["kind"] != collection["kind"]:
            raise StoreError("record collection/kind mismatch")
        node, edges = self.project(record)
        self.registry.validate_records([node], edges)

    def project(self, record):
        node = {"id": record["id"], "kind": self.registry.kinds[record["kind"]]["node"], **deepcopy(record["content"])}
        if "evidence" in record:
            node["evidence"] = deepcopy(record["evidence"])
        edges = [{"source": record["id"], **deepcopy(edge)} for edge in record["relations"]]
        return node, edges

    def graph(self, records):
        nodes, edges = [], []
        for record in sorted(records, key=lambda r: r["id"]):
            node, links = self.project(record)
            nodes.append(node)
            edges.extend(links)
        graph = {
            "meta": {"version": "1", "ontology": self.registry.binding()},
            "nodes": nodes,
            "edges": sorted(edges, key=lambda e: (e["source"], e["target"], e["rel"])),
        }
        self.registry.validate_graph(graph, require_binding=True)
        return graph

    def decision(
        self, request, actor, operation, revision, *, at=None, proposed_by=None, reviewed_by=None, retention_since=None,
        source_approved_by=None
    ):
        result = self.policy.evaluate(
            request,
            {
                "actor": actor,
                "operation": operation,
                "currentRevision": revision,
                "now": at or utcnow(),
                "proposedBy": proposed_by or actor,
                "approvedBy": reviewed_by,
                "appPrincipal": (getattr(self, "app_owned", {}).get(request["resource"])),
                "sourceApprovedBy": source_approved_by,
                "retentionSince": retention_since,
            },
        )
        if not result["allowed"]:
            raise PolicyError("; ".join(result["reasons"]))
        return result

    def can_read(self, collection, actor, at=None):
        request = {
            "id": "read",
            "resource": self.collections[collection]["resource"],
            "record": "read",
            "mutation": "read",
            "expectedRevision": None,
            "reason": "Read context",
            "evidence": [],
            "sourceResource": None,
        }
        try:
            self.decision(request, actor, "read", None, at=at)
            return True
        except PolicyError:
            return False

    def source_reviewer(self, resource, actor, proposer, *, at):
        scope = self.policy.resources[resource]['scope']
        rules, _, _ = self.policy.effective(scope, timestamp(at))
        if (actor not in rules['readers'] or actor not in rules['reviewers']
                or self.policy.principals[actor]['kind'] != 'human'
                or rules['separateReview'] and actor == proposer):
            raise PolicyError('An eligible independent human source reviewer is required')


def _review_index(dialect):
    return dialect.review_index()


def _table_schema(dialect, table):
    """The CREATE TABLE statement the dialect's authority DDL gives `table`."""
    for statement in dialect.authority_schema().split(";"):
        if statement.strip().startswith(f"CREATE TABLE {table} "):
            return statement.strip()
    raise StoreError(f"the {dialect.driver} authority schema has no table {table}")


def _schema(dialect, *, db_blob=False):
    """Authority DDL; a db-blob contract also gets its blob table, created with the rest.
    A document store has none: its create() makes its collections."""
    schema = dialect.authority_schema()
    return schema + ("\n" + DbBlobStore.ddl(dialect.driver) + ";\n" if db_blob and schema else "")


# Authority columns, in export order; server dialects add generated index columns that are not exported.
SNAPSHOT_COLUMNS = {
    "metadata": ("key", "value"),
    "records": ("id", "collection", "revision", "body", "deleted"),
    "edges": ("source", "target", "rel", "body"),
    "events": ("sequence", "previous", "digest", "body"),
    "receipts": ("actor", "request_id", "intent", "body"),
    "proposals": ("id", "body"),
    "outbox": ("sequence", "body"),
    "deliveries": ("consumer", "sequence"),
}


def _snapshot_locators(rows):
    """Every blob locator current records carry, one per key, ordered by key."""
    locators = {}
    for row in rows:
        if row["deleted"]:
            continue
        for locator in record_locators(json.loads(row["body"])):
            if locators.setdefault(locator["key"], locator) != locator:
                raise StoreError(f"records disagree on the blob behind key {locator['key']}")
    return [locators[key] for key in sorted(locators)]


def _check_blob_manifest(snapshot, contract):
    """A contract with a blobs store declares blob completeness and exactly the locators its
    records carry; a snapshot without one has no `blobs` key (and records carry no locator)."""
    if contract.blob_store is None:
        if "blobs" in snapshot:
            raise StoreError("backup declares blobs, but its contract has no blobs store")
        return
    blobs = snapshot.get("blobs")
    expected = _snapshot_locators(snapshot["tables"]["records"])
    included = contract.cell["blobs"] == "db-blob"
    keys = {"completeness", "locators"} | ({"content"} if included else set())
    if (not isinstance(blobs, dict) or set(blobs) != keys
            or blobs["completeness"] != ("included" if included else "referenced")):
        raise StoreError("backup blob completeness does not match the contract's blobs store")
    if blobs["locators"] != expected:
        raise StoreError("backup blob locators differ from the locators its records carry")
    if included:
        if not isinstance(blobs["content"], dict) or set(blobs["content"]) != {locator["key"] for locator in expected}:
            raise StoreError("backup includes blob content for other keys than its locators")
        for locator in expected:
            verify_blob(locator, decode_blob(blobs["content"][locator["key"]]))


class CutoverLoss(StoreError):
    """The target driver cannot hold what the source brain holds; `losses` names each part."""

    def __init__(self, driver, losses):
        self.losses = losses
        super().__init__(f"a {driver} authority cannot hold this brain without loss: "
                         + "; ".join(f"{loss['path']}: {loss['reason']}" for loss in losses))


def _restorable(snapshot, driver, blob_store):
    """The tables of a validated `snapshot` as a `driver` authority holds them, and its blob manifest.

    Only the `bundle` metadata row changes, to name `driver` as the authority store's; the binding
    leaves the driver out, so every journal event, receipt and proposal is kept byte for byte. A
    driver whose cell cannot hold the brain refuses with its losses before anything is written.
    """
    Authority.validate_snapshot(snapshot)
    metadata = {row["key"]: row["value"] for row in snapshot["tables"]["metadata"]}
    bundle = json.loads(metadata["bundle"])
    losses = cutover_losses(bundle, driver)
    if losses:
        raise CutoverLoss(driver, losses)
    blobs = snapshot.get("blobs", {"completeness": "referenced", "locators": []})
    if blobs["completeness"] == "referenced" and blobs["locators"]:
        if blob_store is None:
            raise StoreError(f"backup references {len(blobs['locators'])} blob(s); "
                             "restore needs their blob store to verify locator digests")
        for locator in blobs["locators"]:
            blob_store.get(locator)
    tables = deepcopy(snapshot["tables"])
    tables["metadata"] = [{**row, "value": encoded(retarget(bundle, driver))} if row["key"] == "bundle" else row
                          for row in tables["metadata"]]
    return tables, blobs


def _stored_version(dialect):
    """(version, legacy): legacy when only a pre-seam SQLite PRAGMA user_version holds it.

    A pre-seam file at DB_VERSION is current: it opens and reads as it is, and its
    `metadata.schema_version` row is written by migrate() or by its first write.
    """
    version = dialect.schema_version()
    if version is None and "legacy-schema-version" in dialect.capabilities():
        return dialect.legacy_schema_version(), True
    return version, False


def _migration_required(version, legacy):
    held = " (pre-seam: held in PRAGMA user_version)" if legacy else ""
    return StoreError(f"store schema {version}{held} requires explicit migration to {DB_VERSION}; "
                      "stop writers, back it up, then run `knowledge-store.py --root <brain> migrate`")


class Authority:
    """Indexed source records with transactional journal, receipts and outbox.

    Rules, digests, policy, outbox and receipts live here; connection, DDL,
    transactions and SQL syntax come from `dialect_class` (sql_dialect.py).
    """

    dialect_class = None

    def __init__(self, path, *, expected_binding=None, readonly=False, intake_sources=None, intake_clock=utcnow, intake_release_protection=None,
                 intake_processing_protection=None, intake_judgment_authorization=None, intake_processing_reuse=None,
                 intake_processing_reuse_selection=None):
        if not callable(intake_clock):
            raise StoreError("Trusted intake clock required")
        self.intake_sources, self.intake_clock = intake_sources, intake_clock
        self.intake_release_protection = intake_release_protection
        self.intake_processing_reuse_selection = intake_processing_reuse_selection
        self.intake_processing_reuse = intake_processing_reuse
        self.intake_processing_protection = intake_processing_protection
        self.intake_judgment_authorization = intake_judgment_authorization
        self.path = self.dialect_class.location(path)
        if not self.dialect_class.exists(self.path):
            raise StoreError("authority does not exist; initialize or restore explicitly")
        if readonly:
            self.dialect_class.require("read-only-session")
        self.dialect = self.dialect_class.open(self.path, readonly=readonly)
        self.db = self.dialect.db
        try:
            version, legacy = _stored_version(self.dialect)
            if version != DB_VERSION:
                raise _migration_required(version, legacy)
            self.contract = Contract(json.loads(self._meta("bundle")))
            self._require_driver(self.contract)
            if expected_binding is not None and expected_binding != self.contract.binding:
                raise StoreError("authority contract differs from the adopted binding")
        except BaseException:
            self.dialect.close()
            raise

    @classmethod
    def _require_driver(cls, contract):
        cls.dialect_class.require("authority")
        if contract.stores[contract.authority]["driver"] != cls.dialect_class.driver:
            raise StoreError(f"this adapter requires a declared {cls.dialect_class.driver} authority")

    def capabilities(self):
        return self.dialect.capabilities()

    def close(self):
        self.dialect.close()

    def schema_version(self):
        return _stored_version(self.dialect)[0]

    def _meta(self, key):
        value = self.dialect.meta(key)
        if value is None:
            raise StoreError(f"missing authority metadata: {key}")
        return value

    def _writer_ready(self):
        if self._meta("status") != "active":
            raise StoreError("authority is frozen; write through its declared successor")
        version, legacy = _stored_version(self.dialect)
        if version != DB_VERSION:
            raise StoreError("authority writer version changed; reopen explicitly")

    def _record_schema_version(self):
        """A pre-seam file at DB_VERSION gains its row as its first write transaction commits.

        This runs after the transaction body, so a body that compares the file with a
        snapshot taken before the transaction (freeze) still sees the file as it was.
        """
        if _stored_version(self.dialect)[1]:
            self.dialect.set_schema_version(DB_VERSION)

    @contextmanager
    def request_transaction(self, *, write=False):
        """Hold one native operation through host revalidation and response encoding.

        Only trusted adapters establish this scope. Existing native mutations use
        savepoints inside it; a response failure rolls back their changes too.
        On a driver without savepoints a failed mutation fails the whole request:
        nothing it did can be undone alone, so the request can only roll back.
        This is not a cross-authority or external-publication transaction.
        """
        if self.dialect.in_transaction:
            raise StoreError("An operation transaction is already active")
        self.dialect.begin(write=write)
        self._request_write = write
        self._request_checks = []
        self._request_graph = False
        self._request_failed = False
        try:
            if write:
                self._writer_ready()
            yield
            if write:
                self._request_intact()
                self._writer_ready()
                if self._request_graph:
                    # Once per request: the global rules the per-mutation checks leave out (#399).
                    self.contract.graph(self._all_records())
                self._record_schema_version()
            self.dialect.commit()
        except BaseException:
            if self.dialect.in_transaction:
                self.dialect.rollback()
            raise
        finally:
            self._request_write = False
            self._request_checks = []
            self._request_graph = False
            self._request_failed = False

    def _request_intact(self):
        if getattr(self, "_request_failed", False):
            raise StoreError("a mutation in this request failed without a savepoint; the request can only roll back")

    def revalidate_request(self, at):
        """Recheck original native mutation bases before a shared request commits."""
        if not self.dialect.in_transaction:
            raise StoreError('Request revalidation requires its original transaction')
        for check in tuple(getattr(self, '_request_checks', [])):
            check(at)

    @contextmanager
    def transaction(self):
        dialect = self.dialect
        nested = dialect.in_transaction and getattr(self, '_request_write', False)
        savepoint = nested and "savepoints" in dialect.capabilities()
        if savepoint:
            dialect.savepoint("native_mutation")
        elif nested:
            self._request_intact()
        else:
            dialect.begin(write=True)
        try:
            self._writer_ready()
            yield
            self._record_schema_version()
            if savepoint:
                dialect.release("native_mutation")
            elif not nested:
                dialect.commit()
        except BaseException:
            if savepoint:
                dialect.rollback_to("native_mutation")
                dialect.release("native_mutation")
            elif nested:
                self._request_failed = True
            else:
                dialect.rollback()
            raise

    @classmethod
    def initialize(cls, path, bundle, records=(), *, prior_history=None):
        contract = Contract(bundle)
        cls._require_driver(contract)
        records = list(records)
        for record in records:
            contract.validate_record(record)
            if (record.get('content', {}).get('data', {}).get('intakeHistory') or {}).get('format') in ('intake-history/v3', 'intake-history/v4'):
                raise StoreError('Initialize projected judgments through current proposals, or restore a complete historical snapshot')
        contract.graph(records)
        if contract.document["history"]["priorHistory"] == "included" and prior_history is None:
            raise StoreError("declared prior history must be supplied, not silently omitted")
        dialect = cls.dialect_class.create(path, _schema(cls.dialect_class, db_blob=contract.cell["blobs"] == "db-blob"))
        try:
            for key, value in (("bundle", encoded(bundle)), ("status", "active"), ("instance", secrets.token_hex(16)),
                               ("prior_history", encoded(prior_history))):
                dialect.add_meta(key, value)
            for record in records:
                dialect.add_record(record["id"], record["collection"], "1:" + fingerprint(record), encoded(record))
            for record in records:
                dialect.replace_edges(record["id"], [(edge["target"], edge["rel"], encoded(edge))
                                                     for edge in record["relations"]])
            event = {
                "operation": "import",
                "at": utcnow(),
                "contract": contract.binding,
                "records": records,
                "priorHistory": deepcopy(prior_history),
            }
            digest = fingerprint({"previous": None, "event": event})
            dialect.append_event(1, None, digest, encoded(event))
            dialect.add_outbox(1, encoded({"sequence": 1, "digest": digest}))
            dialect.set_schema_version(DB_VERSION)
            dialect.commit()
        except BaseException:
            if dialect.in_transaction:
                dialect.rollback()
            dialect.discard()
            raise
        dialect.close()
        return cls(path, expected_binding=contract.binding)

    def _row(self, identity):
        budget = getattr(self, "_inspection_budget", None)
        if budget is not None:
            budget.body(self.db, "records", "id", identity)
        return self.dialect.record(identity)

    def _record_metadata(self, identity):
        budget = getattr(self, "_inspection_budget", None)
        if budget is not None:
            budget.charge()
        return self.dialect.record_metadata(identity)

    def _live_record(self, identity):
        body = self.dialect.live_body(identity)
        return json.loads(body) if body is not None else None

    def _local_graph(self, identity, record):
        """Validate ``record`` (``None`` for a deletion) with its neighbours: the
        live records its relations name, and the live records whose relations
        name it, each carrying only the edges between them. Every node and edge
        rule is local; the one global rule, acyclic ``broader``, is left to the
        whole-graph check a request makes before it commits (#399)."""
        if record is None:
            return
        records = {identity: record}
        for edge in record["relations"]:
            target = edge["target"]
            if target not in records:
                value = self._live_record(target)
                if value is not None:
                    records[target] = {**value, "relations": []}
        for source in self.dialect.referencing_sources(identity):
            value = self._live_record(source)
            if value is not None:
                links = [edge for edge in value["relations"] if edge["target"] == identity]
                kept = records.get(source, {**value, "relations": []})
                records[source] = {**kept, "relations": kept["relations"] + links}
        self.contract.graph(list(records.values()))

    def _all_records(self):
        return [json.loads(body) for body in self.dialect.live_bodies()]

    def get(self, identity, actor, *, at=None):
        row = self._record_metadata(identity)
        if row is None or not self.contract.can_read(row["collection"], actor, at):
            return None
        if (not row["deleted"] and self.contract.studio_apps_enabled
                and self.contract.collections[row["collection"]]["kind"] in
                ("studio.app", "studio.component", "studio.app-query")):
            return self._get_studio_record(identity, actor, at)
        state = self._read_state()
        if not row["deleted"]:
            row = self._row(identity)
        record = None if row["deleted"] else json.loads(row["body"])
        withheld = False
        app_availability = None
        if record:
            original = deepcopy(record)
            visible = [edge for edge in record["relations"] if self._target_readable(edge["target"], actor, at)]
            withheld = len(visible) != len(record["relations"])
            record["relations"] = visible
            if (self.contract.studio_apps_enabled
                    and record.get("kind") in ("studio.app", "studio.component", "studio.app-query")):
                from studio_app_bindings import app_binding_status
                app_availability = app_binding_status(
                    original, self._readable_studio_binding_targets(original, actor, at))
        return {
            "record": record,
            "revision": row["revision"],
            "deleted": bool(row["deleted"]),
            "withheldRelations": withheld,
            "authorityState": state,
            **({"appAvailability": app_availability} if app_availability is not None else {}),
        }

    def _get_studio_record(self, identity, actor, at):
        opened = not self.dialect.in_transaction
        if opened:
            self.dialect.begin()
        try:
            state = self._read_state()
            metadata = self._record_metadata(identity)
            if (metadata is None or metadata["deleted"]
                    or not self.contract.can_read(metadata["collection"], actor, at)):
                return None
            row = self._row(identity)
            record = json.loads(row["body"])
            targets = self._readable_studio_binding_targets(record, actor, at)
            from studio_app_bindings import app_binding_status
            availability = app_binding_status(record, targets)
            visible = [edge for edge in record["relations"] if self._target_readable(edge["target"], actor, at)]
            withheld = len(visible) != len(record["relations"])
            record["relations"] = visible
            return {"record": record, "revision": row["revision"], "deleted": False,
                    "withheldRelations": withheld, "authorityState": state,
                    "appAvailability": availability}
        finally:
            if opened and self.dialect.in_transaction:
                self.dialect.rollback()

    def _readable_studio_binding_targets(self, record, actor, at):
        from studio_app_bindings import (MAX_APP_BINDING_BYTES, MAX_APP_BINDING_RECORDS,
                                         MAX_APP_BINDING_REFERENCES,
                                         binding_targets)
        targets = {}
        body_bytes = len(encoded(record).encode("utf-8"))
        if body_bytes > MAX_APP_BINDING_BYTES:
            raise StoreError("Studio App dependency budget exceeded")
        pending = list(binding_targets(record))
        total_references = len(pending)
        if total_references > MAX_APP_BINDING_REFERENCES:
            raise StoreError("Studio App dependency budget exceeded")
        visited = {record["id"]}
        total_bytes = body_bytes
        while pending:
            batch = []
            while pending:
                identity = pending.pop()
                if not isinstance(identity, str) or identity in visited:
                    continue
                visited.add(identity)  # Count before the access check, including denied references.
                if len(visited) > MAX_APP_BINDING_RECORDS:
                    raise StoreError("Studio App dependency budget exceeded")
                batch.append(identity)
            metadata = self.dialect.record_metadata_by_ids(batch)
            readable = [item["id"] for item in metadata if not item["deleted"]
                        and self.contract.can_read(item["collection"], actor, at)]
            count, size = self.dialect.live_volume_by_ids(readable)
            if count > MAX_APP_BINDING_RECORDS or total_bytes + size > MAX_APP_BINDING_BYTES:
                raise StoreError("Studio App dependency budget exceeded")
            total_bytes += size
            for item in self.dialect.live_records_by_ids(readable):
                value = json.loads(item["body"])
                value["revision"] = item["revision"]
                targets[item["id"]] = value
                next_targets = binding_targets(value)
                total_references += len(next_targets)
                if total_references > MAX_APP_BINDING_REFERENCES:
                    raise StoreError("Studio App dependency budget exceeded")
                pending.extend(next_targets)
        return targets

    def _require_studio_app_bindings(self, record, actor, at):
        if not self.contract.studio_apps_enabled or record.get("kind") not in ("studio.app", "studio.component", "studio.app-query"):
            return
        from studio_app_bindings import require_current_bindings
        try:
            require_current_bindings(record, self._readable_studio_binding_targets(record, actor, at))
        except ValueError as exc:
            raise StoreError(str(exc)) from exc

    def _read_state(self):
        state = self._meta("status")
        if state == "frozen":
            raise StoreError("source authority is frozen; read from its declared successor")
        return state

    def _target_readable(self, identity, actor, at):
        target = self._record_metadata(identity)
        return target is not None and not target["deleted"] and self.contract.can_read(target["collection"], actor, at)

    def history(self, identity, actor, *, at=None, limit=25):
        from record_history import inspect_history
        return inspect_history(self, identity, actor, at=at, limit=limit)

    def describe(self, actor, *, at=None):
        return {
            "protocolVersion": "1.0",
            "adapter": f"{self.dialect.driver}-authority",
            "adapterVersion": "1.2.0",
            "schemaVersion": DB_VERSION,
            "recordSchemaVersion": "1.0.0",
            "ontology": self.contract.registry.binding(),
            "binding": self.contract.binding,
            "state": self._meta("status"),
            "history": deepcopy(self.contract.document["history"]),
            "collections": [
                deepcopy(c) for key, c in self.contract.collections.items() if self.contract.can_read(key, actor, at)
            ],
            "capabilities": (["record-history-metadata"] if self.dialect.driver == 'sqlite' else []) + [
                "get",
                "search",
                "context",
                "path",
                "propose",
                "inspect",
                "proposal-disposition",
                "review",
                "commit",
                "export",
                "restore",
                "cutover",
                "migrate",
                "projection-delivery",
                "reviewed-publication",
                "lifecycle-strategy-preview",
                "reviewed-lifecycle-strategy",
                "reviewed-archive-unarchive",
                "reviewed-supersession",
                "intake-metadata-delivery",
                "intake-processed-delivery",
                "independent-intake-release",
                "independent-intake-transfer",
            ],
            "transactionBoundary": "one authority, one record and its outgoing relations, journal, receipt and outbox",
            "revision": "record sequence plus content SHA-256",
            "idempotency": "authenticated committer plus request id",
        }

    def inspect(self, identity, actor, *, at=None):
        proposal = self._proposal(identity, at, allow_expired=True, allow_disposed=True)
        request = proposal["request"]
        current = self._record_metadata(request["record"])
        collection = proposal["record"]["collection"] if proposal["record"] else current["collection"]
        if not self.contract.can_read(collection, actor, at):
            raise PolicyError("proposal read access denied")
        if request['mutation'] == 'promote':
            pin = proposal.get('promotion', {})
            source = self._record_metadata(pin.get('source'))
            if (not source or self.contract.collections[source['collection']]['resource'] != pin.get('resource')
                    or not self.contract.can_read(source['collection'], actor, at)):
                raise PolicyError('Publication proposal requires source read access')
            if 'representation' in pin:
                from intake_processed import authorize, current_protection
                current_protection(self, pin['representation'], actor=actor, at=at or utcnow())
                authorize(self.contract, pin['representation'], actor, at or utcnow(), pin['resource'])
        if any(
            not self._target_readable(edge["target"], actor, at) and edge["target"] != request["record"]
            for edge in (proposal["record"] or {}).get("relations", [])
        ):
            raise PolicyError("proposal includes relationships outside the caller's read scope")
        from proposal_disposition import observation
        return {
            "proposal": proposal,
            "proposalSha256": fingerprint(proposal),
            "lifecycle": observation(self, proposal),
            "current": self.get(request["record"], actor, at=at),
            "expired": timestamp(at or utcnow()) >= timestamp(proposal["expiresAt"]),
        }

    def preview_lifecycle(self, identity, actor, *, at=None):
        """Pinned read-only strategy preview; no proposal, journal, or record is written."""
        at = at or utcnow()
        observed = self.get(identity, actor, at=at)
        if observed is None or observed["record"] is None:
            raise PolicyError("lifecycle preview target is unavailable")
        record = observed["record"]
        resource = self.contract.collections[record["collection"]]["resource"]
        plan = apply_strategy(self.contract.policy, resource, record, at=at)
        return {"format": "lifecycle-preview/v1", "authorityBinding": self.contract.binding,
                "record": identity, "revision": observed["revision"], "resource": resource,
                **plan}

    def context(self, actor, *, at=None):
        at = at or utcnow()
        state = self._read_state()
        readable = {
            collection for collection in self.contract.collections if self.contract.can_read(collection, actor, at)
        }
        records = [record for record in self._all_records() if record["collection"] in readable]
        records = context_records(self.contract, records, at=at)
        ids = {record["id"] for record in records}
        for record in records:
            record["relations"] = [edge for edge in record["relations"] if edge["target"] in ids]
        graph = self.contract.graph(records)
        graph["meta"]["authority"] = {"binding": self.contract.binding, "state": state}
        graph["meta"]["lifecycle"] = {"policySha256": self.contract.policy.binding["sha256"]}
        return graph

    def read_snapshot(self, actor, *, at=None, max_records=None, max_body_bytes=None):
        """Host-only, scoped context and authority pins from one SQLite read view.

        This is not an administrative export. It selects only readable live
        collections and never reads journal bodies, proposals or receipts. The
        checkpoint is internal host metadata; consumers receive its fingerprint,
        not the global journal sequence or the instance identifier.
        """
        for limit in (max_records, max_body_bytes):
            if limit is not None and (type(limit) is not int or limit < 1):
                raise StoreError("Invalid snapshot bound")
        at = at or utcnow()
        self.dialect.begin()
        try:
            state = self._read_state()  # Establish the read snapshot first.
            if (self.schema_version() != DB_VERSION
                    or contract_binding(json.loads(self._meta("bundle"))) != self.contract.binding):
                raise StoreError("authority contract changed; reopen with its adopted binding")
            readable = sorted(key for key in self.contract.collections if self.contract.can_read(key, actor, at))
            rows = []
            if readable:
                if max_records is not None or max_body_bytes is not None:
                    count, size = self.dialect.live_volume(readable)
                    if (max_records is not None and count > max_records or
                            max_body_bytes is not None and size > max_body_bytes):
                        raise StoreError("Selected snapshot exceeds its bounds")
                rows = self.dialect.live_records(readable)
            records = [json.loads(row["body"]) for row in rows]
            records = context_records(self.contract, records, at=at)
            visible_ids = {record["id"] for record in records}
            rows = [row for row in rows if row["id"] in visible_ids]
            ids = {record["id"] for record in records}
            for record in records:
                record["relations"] = [edge for edge in record["relations"] if edge["target"] in ids]
            head = self.dialect.journal_head()
            if head is None:
                raise StoreError("authority journal has no import checkpoint")
            checkpoint = {"binding": self.contract.binding, "instance": self._meta("instance"),
                          "state": state, "sequence": head["sequence"], "digest": head["digest"]}
            # asOf: when the journal head was written, the knowledge basis of this read.
            graph = self.contract.graph(records)
            graph["meta"]["lifecycle"] = {"policySha256": self.contract.policy.binding["sha256"]}
            return {"graph": graph, "checkpoint": checkpoint, "asOf": head["head_at"],
                    "revisions": {row["id"]: row["revision"] for row in rows},
                    "resources": {row["id"]: self.contract.collections[row["collection"]]["resource"] for row in rows}}
        finally:
            self.dialect.rollback()

    def search(self, text, actor, *, at=None):
        query = text.strip().casefold()
        if not query:
            return []
        return [
            node
            for node in self.context(actor, at=at)["nodes"]
            if query in " ".join(str(node.get(k, "")) for k in ("id", "title", "text", "kind")).casefold()
        ]

    def path_between(self, source, target, actor, *, at=None):
        graph = self.context(actor, at=at)
        ids = {node["id"] for node in graph["nodes"]}
        if source not in ids or target not in ids:
            return None
        adjacent = {identity: set() for identity in ids}
        for edge in graph["edges"]:
            adjacent[edge["source"]].add(edge["target"])
        queue, seen = deque([[source]]), {source}
        while queue:
            path = queue.popleft()
            if path[-1] == target:
                return path
            for child in sorted(adjacent[path[-1]] - seen):
                seen.add(child)
                queue.append([*path, child])
        return None

    def walk(self, start, actor, *, depth, at=None, graph=None):
        """Readable nodes reachable from `start` over outgoing relations within `depth` hops (graph_role.py).

        Cypher on `graph` (an AgeGraph) when the contract declares graph=age and that
        projection's delivery is acknowledged at the outbox head and it holds this actor's
        readable node and edge sets; otherwise the
        edges table: a recursive CTE on a server, the Python frontier walk on SQLite.
        """
        from graph_role import check_depth, edges_table_walk, frontier_walk
        check_depth(depth)
        if graph is not None and self.contract.cell["graph"] != "age":
            raise StoreError("this contract declares no age graph store")
        own_transaction = not self.dialect.in_transaction
        if own_transaction:
            self.dialect.begin()
        try:
            self._read_state()
            readable = sorted(key for key in self.contract.collections if self.contract.can_read(key, actor, at))
            ids = set()
            if readable:
                ids = self.dialect.live_ids(readable)
            if start not in ids:
                return {"traversal": None, "nodes": []}
            if graph is not None:
                # AgeGraph.write checks only a payload's shape, so the projection is used only when
                # this authority acknowledged its delivery at the head and its node and edge sets match.
                head = self.dialect.outbox_head()
                consumer = encoded({"consumer": graph.consumer(self.contract.binding, actor), "actor": actor,
                                    "contract": self.contract.binding})
                if self.dialect.delivery(consumer) == head:
                    edges = [edge for edge in self.dialect.edges() if edge[0] in ids and edge[1] in ids]
                    nodes = graph.walk(self.contract.binding, actor, start, depth, sequence=head, ids=ids, edges=edges)
                    if nodes is not None:
                        return {"traversal": "age", "nodes": nodes}
            if self.dialect.driver in ("postgres", "mysql"):
                return {"traversal": "recursive-cte", "nodes": edges_table_walk(self.dialect, readable, start, depth)}
            edges = [(source, target) for source, target, _ in self.dialect.edges() if source in ids and target in ids]
            return {"traversal": "frontier", "nodes": frontier_walk(edges, start, depth)}
        finally:
            if own_transaction:
                self.dialect.rollback()

    def _prepare(self, request, record, actor, operation, *, proposal=None, at=None,
                 _basis=None, _history_at=None):
        row = self._row(request["record"]) if _basis is None else _basis[0]
        current = row["revision"] if row else None
        before = json.loads(row["body"]) if row and not row["deleted"] else None
        collection_id = record["collection"] if record else before["collection"] if before else None
        collection = self.contract.collections.get(collection_id)
        if not collection or collection["resource"] != request["resource"]:
            raise StoreError("mutation resource does not match its collection")
        if row and row["collection"] != collection_id:
            raise StoreError("record collection is immutable")
        importing = proposal is not None and 'transfer' in proposal
        if importing:
            from intake_transfer_store import prepare
            prepare(self, proposal, before, current, actor, operation, at or self.intake_clock())
        promotion = request['mutation'] == 'promote'
        if promotion:
            self._promotion_source(proposal, actor, at, _destination_basis=_basis)
        retention_since = None
        if request["mutation"] == "delete":
            event = self.dialect.retention_event(request["record"])
            if event:
                retention_since = json.loads(event)["at"]
            else:
                # A record brought in by initialize has no create or retain
                # event; its retention runs from that import (#400).
                first = self.dialect.event_body(1)
                imported = json.loads(first) if first else {}
                if imported.get("operation") == "import" and any(
                        value["id"] == request["record"] for value in imported.get("records", [])):
                    retention_since = imported["at"]
        result = self.contract.decision(
            request,
            actor,
            operation,
            current,
            at=at,
            proposed_by=proposal["actor"] if proposal else actor,
            reviewed_by=(proposal.get("review") or {}).get("actor") if proposal else None,
            retention_since=retention_since,
            source_approved_by=(proposal.get('sourceReview') or {}).get('actor') if promotion else None,
        )
        if importing:
            result['requiresReview'] = True
        if any(
            not self._target_readable(edge["target"], actor, at) and edge["target"] != request["record"]
            for value in (before, record)
            if value
            for edge in value["relations"]
        ):
            raise PolicyError("whole-record mutation requires read access to its relationship targets")
        lifecycle_ops = {"strategy", "confirm", "archive", "unarchive", "supersede"}
        if request["mutation"] not in ("create", "correct", "retract", "retain", "delete", "promote", *lifecycle_ops):
            raise StoreError("this adapter does not implement cross-record supersession")
        materializing = promotion and proposal['promotion'].get('projection') in ('intake-metadata-record/v1', 'intake-processed-record/v1')
        if (request["mutation"] == 'create' or promotion and not materializing) and row is not None:
            raise StoreError("identity already exists, including tombstoned identities")
        if request["mutation"] not in ("create", "promote") and before is None:
            raise StoreError("mutation requires a live record")
        if request.get("successor") is not None and request["mutation"] != "supersede":
            raise StoreError("successor is only valid for reviewed supersession")
        if request["mutation"] == "supersede":
            successor_id = request.get("successor")
            successor = self._live_record(successor_id) if successor_id else None
            if not successor or not any(edge["rel"] == "supersedes" and edge["target"] == request["record"]
                                        for edge in successor["relations"]):
                raise StoreError("reviewed supersession requires a successor linked to this predecessor")
        if request["mutation"] == "delete":
            if record is not None:
                raise StoreError("deletion must not carry a replacement record")
            if self.dialect.referencing_sources(request["record"]):
                raise StoreError("deletion would leave referenced knowledge unresolved")
        else:
            if not record or record["id"] != request["record"]:
                raise StoreError("replacement record identity does not match the request")
            self.contract.validate_record(record)
            from intake_text_write import current_judgment
            current_judgment(self, record, actor=actor, at=at or self.intake_clock())
            from intake_delivery import metadata_change
            metadata_change(before, record, materializing=promotion or importing)
            from intake_transfer_store import transfer_change
            transfer_change(before, record, importing=importing)
            from intake_transfer import release_change
            release_change(before, record, releasing=promotion and proposal['promotion'].get('projection') == 'intake-release/v1')
            from intake_contract import history_change
            if not promotion:
                history_change(before, record, actor=proposal["actor"] if proposal else actor,
                               at=proposal["at"] if proposal else _history_at or at)
            old_content = (before or {}).get("content", {})
            old_status, new_status = old_content.get("status"), record["content"].get("status")
            if old_status != new_status and {old_status, new_status}.intersection(
                {"retracted", "superseded", "deleted", "retained"}
            ):
                if request["mutation"] != "retract" or new_status != "retracted":
                    raise StoreError("lifecycle status cannot be changed through a generic correction")
            if (
                old_content.get("data", {}).get("retainedAt") != record["content"].get("data", {}).get("retainedAt")
                and request["mutation"] != "retain"
            ):
                raise StoreError("retention time is assigned only by the retain operation")
            previous_links = [edge for edge in (before or {}).get("relations", []) if edge["rel"] == "supersedes"]
            next_links = [edge for edge in record["relations"] if edge["rel"] == "supersedes"]
            if previous_links != next_links:
                allowed_successor_link = (request["mutation"] == "create" and not previous_links
                                           and len(next_links) == 1 and next_links[0]["target"] != record["id"])
                if not allowed_successor_link:
                    raise StoreError("supersession relations require a linked successor and reviewed predecessor transition")
                if allowed_successor_link:
                    target = self._live_record(next_links[0]["target"])
                    if not target or target.get("content", {}).get("data", {}).get("lifecycle", {}).get("state") in ("archived", "superseded"):
                        raise StoreError("a successor can link only to a live predecessor")
            old_lifecycle = (before or {}).get("content", {}).get("data", {}).get("lifecycle", {})
            new_lifecycle = record.get("content", {}).get("data", {}).get("lifecycle", {})
            if old_lifecycle != new_lifecycle and request["mutation"] not in lifecycle_ops:
                raise StoreError("lifecycle fields require a dedicated governed operation")
            if request["mutation"] == "supersede" and (
                new_lifecycle.get("state") != "superseded"
                or new_lifecycle.get("supersededBy") != request.get("successor")
            ):
                raise StoreError("supersession must mark the predecessor and name the linked successor")
            if request["mutation"] == "archive" and new_lifecycle.get("state") != "archived":
                raise StoreError("archive operation must derive archived state")
            if request["mutation"] == "unarchive" and new_lifecycle.get("state") != "current":
                raise StoreError("unarchive operation must derive current state")
            if request["mutation"] == "confirm" and not new_lifecycle.get("confirmedAt"):
                raise StoreError("confirmation must carry the trusted confirmation time")
            if request["mutation"] == "unarchive" and old_lifecycle.get("state") != "archived":
                raise StoreError("only archived records can be unarchived")
        self.contract.writable(before, record)
        if getattr(self, '_request_write', False):
            # Inside a request only what this mutation can change is checked
            # now; the whole graph is checked once before the request commits,
            # so a bulk change is linear, not quadratic (#399).
            self._local_graph(request["record"], record)
            self._request_graph = True
        else:
            records = [r for r in self._all_records() if r["id"] != request["record"]]
            if record:
                records.append(record)
            self.contract.graph(records)
        if _basis is None and getattr(self, '_request_write', False):
            captured = deepcopy((request, record, proposal, dict(row) if row is not None else None))
            def recheck(now):
                wanted, value, original, prior_row = captured
                if original and timestamp(now) >= timestamp(original['expiresAt']):
                    raise StoreError('Proposal expired during the shared operation')
                self._prepare(wanted, value, actor, operation, proposal=original, at=now,
                              _basis=(prior_row,), _history_at=at)
            self._request_checks.append(recheck)
        return current, before, result

    def _promotion_source(self, proposal, actor, at, *, _destination_basis=None):
        """Validate the exact local source inside the destination transaction.

        Imported descriptors cannot invoke promotion. Only propose_promotion
        constructs this stored proposal, and source review is a separate action.
        """
        if not proposal or 'promotion' not in proposal:
            raise StoreError('Promotion requires an authority-bound source proposal')
        pin = proposal['promotion']
        if not isinstance(pin, dict) or set(pin) != ({'source', 'revision', 'sha256', 'resource', 'projection', 'destination'} |
                ({'representation'} if pin.get('projection') == 'intake-processed-record/v1' or
                    pin.get('projection') == 'intake-release/v1' and 'representation' in pin else set()) |
                ({'release'} if pin.get('projection') == 'intake-release/v1' else set())):
            raise StoreError('Invalid promotion source binding')
        source = self.get(pin['source'], actor, at=at)
        if (not source or not source['record'] or source['withheldRelations']
                or source['revision'] != pin['revision'] or fingerprint(source['record']) != pin['sha256']):
            raise StoreError('Promotion source unavailable or changed')
        original = source['record']
        if 'representation' in pin:
            from intake_processed import authorize, current_protection
            if pin['representation']['receipt']['principal'] != proposal['actor']:
                raise StoreError('Processed representation principal differs from its adopter')
            current_protection(self, pin['representation'], actor=actor, at=at or utcnow())
            authorize(self.contract, pin['representation'], actor, at or utcnow(), pin['resource'])
        resource = self.contract.collections[original['collection']]['resource']
        request, record = proposal['request'], proposal['record']
        if (resource != pin['resource'] or resource != request['sourceResource'] or pin['source'] == request['record']
                or request['evidence'] != ['promotion-source:' + fingerprint(pin)]):
            raise StoreError('Promotion source binding differs from its request')
        if pin['projection'] == 'copy/v1' and pin['destination'] is None:
            if (original['kind'] != record['kind'] or self.contract.policy.resources[resource]['scope'] ==
                    self.contract.policy.resources[request['resource']]['scope']):
                raise StoreError('Exact promotion requires matching kinds and distinct scopes')
            expected = {**deepcopy(original), 'id': request['record'], 'collection': record['collection']}
        elif pin['projection'] in ('intake-metadata-record/v1', 'intake-processed-record/v1'):
            self._reviewed_intake(pin)
            row = self._row(request['record']) if _destination_basis is None else _destination_basis[0]
            before = json.loads(row['body']) if row and not row['deleted'] else None
            from intake_delivery import project
            expected = project(self.contract, original, pin, request['record'], record['collection'], before)
        elif pin['projection'] == 'intake-release/v1':
            from intake_transfer import authority_binding, current_release_protection, release_project
            self._reviewed_intake(pin)
            current_release_protection(self, pin, record['collection'])
            if (pin['release']['source'] != authority_binding(self, pin['release']['source']['participant'])
                    or timestamp(at or utcnow()) >= timestamp(pin['release']['expiresAt'])):
                raise StoreError('Source release instance changed or expired')
            expected = release_project(self.contract, original, pin, request['record'], record['collection'])
        else:
            raise StoreError('Unsupported promotion projection')
        if record != expected:
            raise StoreError('Promotion differs from its exact source projection')
        approved = proposal.get('sourceReview')
        if approved is not None:
            if (not isinstance(approved, dict) or set(approved) != {'actor', 'reason', 'at'}
                    or not isinstance(approved['reason'], str) or not approved['reason'].strip()
                    or not timestamp(proposal['at']) <= timestamp(approved['at']) <= timestamp(at or utcnow())):
                raise StoreError('Invalid source release review')
            self._check_source_reviewer(proposal, approved['actor'], at)
        return original

    def _check_source_reviewer(self, proposal, actor, at):
        if 'representation' in proposal['promotion']:
            from intake_processed import authorize, current_protection
            current_protection(self, proposal['promotion']['representation'], actor=actor, at=at or utcnow())
            authorize(self.contract, proposal['promotion']['representation'], actor, at or utcnow(),
                      proposal['promotion']['resource'])
        resources = {proposal['promotion']['resource']}
        if 'representation' in proposal['promotion']:
            from intake_processed import source_dependencies
            resources.update(row[1] for row in source_dependencies(proposal['promotion']['representation']))
        for resource in sorted(resources):
            self.contract.source_reviewer(resource, actor, proposal['actor'], at=at or utcnow())

    def _reviewed_intake(self, pin):
        body = self.dialect.revision_event(pin['source'], pin['revision'])
        event = json.loads(body) if body else None
        if not event or not event.get('review') or fingerprint(event['after']) != pin['sha256']:
            raise StoreError('Intake requires a natively reviewed current history revision')
        self.contract.source_reviewer(pin['resource'], event['review']['actor'], event['proposedBy'], at=event['review']['at'])

    def propose_intake(self, history_id, history_revision, destination, identity, collection, actor, *,
                       expected_revision=None, request_id, reason, at=None, destination_target=None):
        """Publish a typed metadata projection; both native reviews remain required."""
        return self._propose_publication(history_id, history_revision, identity, collection, actor,
            request_id=request_id, reason=reason, at=at, projection='intake-metadata-record/v1',
            destination=destination, expected_revision=expected_revision, destination_target=destination_target)

    def propose_processed_intake(self, history_id, history_revision, destination, identity, collection, actor, *,
                                 representation, expected_sha256, boundary, expected_revision=None,
                                 request_id, reason, at=None, destination_target=None):
        """Host-adopted extraction receipt; exact source and destination reviews required.

        boundary is the host's processing binding, refreshed to the current time.
        The protected digest must come from the processing receipt, not its payload.
        Neither parameter is an imported-document grant.
        """
        from intake_processed import PROFILE, adopt
        at = at or utcnow()
        selected = adopt(representation, expected_sha256, boundary, self.contract, actor, at)
        return self._propose_publication(history_id, history_revision, identity, collection, actor,
            request_id=request_id, reason=reason, at=at, projection=PROFILE,
            destination=destination, expected_revision=expected_revision, destination_target=destination_target,
            representation=selected)

    def propose_intake_release(self, history_id, history_revision, destination, identity, collection, actor, *,
                               release, request_id, reason, at=None, representation=None,
                               expected_sha256=None, boundary=None):
        """Source-owned immutable release; never grants destination write permission.

        release is host configuration: exact source/destination bindings, lifetime
        and protection selection. Receipt adoption uses the actual host boundary.
        Both source and release-collection native reviews remain mandatory.
        """
        from intake_transfer import RELEASE, release_options
        at = at or utcnow()
        selected = None
        if representation is not None:
            from intake_processed import adopt
            selected = adopt(representation, expected_sha256, boundary, self.contract, actor, at)
        elif expected_sha256 is not None or boundary is not None:
            raise StoreError('Processing adoption requires its representation')
        return self._propose_publication(history_id, history_revision, identity, collection, actor,
            request_id=request_id, reason=reason, at=at, projection=RELEASE, destination=destination,
            expected_revision=None, representation=selected, release=release_options(release))

    def propose_promotion(self, source_id, source_revision, identity, collection, actor, *,
                          request_id, reason, at=None):
        """Reviewable copy across local scopes; the original is never moved/deleted.

        This is an atomic single-authority primitive. Cross-authority delivery
        requires an independently authenticated source release adapter.
        """
        return self._propose_publication(source_id, source_revision, identity, collection, actor,
            request_id=request_id, reason=reason, at=at, projection='copy/v1', destination=None, expected_revision=None)

    def _propose_publication(self, source_id, source_revision, identity, collection, actor, *,
                             request_id, reason, at, projection, destination, expected_revision, destination_target=None, representation=None, release=None):
        at = at or utcnow()
        with self.transaction():
            key = fingerprint({'publicationRequest': request_id, 'actor': actor, 'contract': self.contract.binding})[:32]
            existing = self.dialect.proposal(key)
            if existing:
                proposal = json.loads(existing)
                pin, previous = proposal.get('promotion', {}), proposal['request']
                if pin.get('representation') != representation or pin.get('release') != release:
                    raise StoreError('Publication request ID was reused with different representation')
                if (pin.get('source'), pin.get('revision'), pin.get('projection'), pin.get('destination'),
                        previous['record'], proposal['record']['collection'], previous['expectedRevision'],
                        previous['reason'], proposal['actor']) != (
                        source_id, source_revision, projection, destination, identity, collection,
                        expected_revision, reason, actor):
                    raise StoreError('Publication request ID was reused with different intent')
                if not self.contract.can_read(collection, actor, at):
                    raise StoreError('Publication destination is unavailable')
                self._intake_target(proposal['record'], destination_target)
                committed = self.dialect.receipt(actor, request_id)
                if committed:
                    receipt = json.loads(committed['body'])
                    if (receipt.get('promotion') != pin or receipt['request'] != previous
                            or receipt['after'] != proposal['record']):
                        raise StoreError('Publication completion differs from its proposal')
                    if any(not self._target_readable(edge['target'], actor, at) and edge['target'] != identity
                           for value in (receipt['before'], receipt['after']) if value for edge in value['relations']):
                        raise PolicyError('Publication receipt contains unavailable relationships')
                    return {'proposal': key, 'status': 'committed', 'receipt': receipt}
                self._proposal(key, at)
                current, before, decision = self._prepare(previous, proposal['record'], actor, 'propose', proposal=proposal, at=at)
                return {'proposal': key, 'status': 'prepared', 'before': before, 'after': deepcopy(proposal['record']),
                        'decision': decision, 'revision': current, 'source': deepcopy(pin)}
            source = self.get(source_id, actor, at=at)
            if not source or not source['record'] or source['withheldRelations'] or source['revision'] != source_revision:
                raise StoreError('Promotion source unavailable or changed')
            original = source['record']
            target = self.contract.collections.get(collection)
            if not target:
                raise StoreError('Unknown promotion destination collection')
            pin = {'source': source_id, 'revision': source_revision, 'sha256': fingerprint(original),
                   'resource': self.contract.collections[original['collection']]['resource'],
                   'projection': projection, 'destination': destination}
            if representation is not None:
                pin['representation'] = deepcopy(representation)
            if release is not None:
                pin['release'] = deepcopy(release)
            request = {'id': request_id, 'record': identity, 'resource': target['resource'],
                       'mutation': 'promote', 'expectedRevision': expected_revision, 'reason': reason,
                       'evidence': ['promotion-source:' + fingerprint(pin)], 'sourceResource': pin['resource']}
            validate_policy_request(request, 'mutation-request')
            record = {**deepcopy(original), 'id': identity, 'collection': collection}
            if projection in ('intake-metadata-record/v1', 'intake-processed-record/v1'):
                self._reviewed_intake(pin)
                row = self._row(identity)
                if row and (row['deleted'] or not self.contract.can_read(row['collection'], actor, at)):
                    raise StoreError('Intake destination is unavailable')
                before = json.loads(row['body']) if row else None
                from intake_delivery import project
                record = project(self.contract, original, pin, identity, collection, before)
                self._intake_target(record, destination_target)
            if projection == 'intake-release/v1':
                from intake_transfer import release_project
                self._reviewed_intake(pin)
                record = release_project(self.contract, original, pin, identity, collection)
            payload = {'id': key, 'request': request, 'record': record, 'actor': actor,
                       'at': at, 'contract': self.contract.binding, 'review': None, 'promotion': pin,
                       'sourceReview': None,
                       'expiresAt': (timestamp(at) + dt.timedelta(minutes=10)).isoformat(timespec='milliseconds')}
            current, before, decision = self._prepare(request, record, actor, 'propose', proposal=payload, at=at)
            self.dialect.add_proposal(payload['id'], encoded(payload))
            return {'proposal': payload['id'], 'status': 'prepared', 'before': before, 'after': deepcopy(record),
                    'decision': decision, 'revision': current, 'source': deepcopy(pin)}

    @staticmethod
    def _intake_target(record, target):
        if target is not None and record['content'].get('data', {}).get('intakeDelivery', {}).get(
                'destination', {}).get('target') != target:
            raise StoreError('Destination registration differs from the reviewed decision')

    def review_source(self, identity, actor, reason, *, at=None):
        """Approve this exact source revision for this exact destination copy."""
        if not isinstance(reason, str) or not reason.strip():
            raise StoreError('Source release review requires a reason')
        at = at or utcnow()
        with self.transaction():
            proposal = self._proposal(identity, at, allow_deferred=True)
            if proposal['request']['mutation'] != 'promote':
                raise StoreError('Source release review requires a promotion proposal')
            if timestamp(at) < timestamp(proposal['at']):
                raise StoreError('Source release review precedes its proposal')
            row = self._row(proposal['request']['record'])
            if (row['revision'] if row else None) != proposal['request']['expectedRevision']:
                raise StoreError('Destination already exists; this source release is no longer pending')
            self._promotion_source(proposal, actor, at)
            self._check_source_reviewer(proposal, actor, at)
            proposal['sourceReview'] = {'actor': actor, 'reason': reason, 'at': at}
            self.dialect.update_proposal(identity, encoded(proposal))
            return deepcopy(proposal['sourceReview'])

    def revoke_source_review(self, identity, actor, reason, *, at=None):
        """Withdraw a pending release; this cannot recall a committed publication."""
        if not isinstance(reason, str) or not reason.strip():
            raise StoreError('Revocation requires a reason')
        at = at or utcnow()
        with self.transaction():
            proposal = self._proposal(identity, at, allow_deferred=True)
            if proposal['request']['mutation'] != 'promote':
                raise StoreError('Revocation requires a promotion proposal')
            if timestamp(at) < timestamp(proposal['at']):
                raise StoreError('Source release revocation precedes its proposal')
            row = self._row(proposal['request']['record'])
            if (row['revision'] if row else None) != proposal['request']['expectedRevision']:
                raise StoreError('Destination already exists; use its governed lifecycle')
            self._check_source_reviewer(proposal, actor, at)
            revoked = {'actor': actor, 'reason': reason, 'at': at}
            proposal.update(sourceReview=None, sourceRevocation=revoked)
            self.dialect.update_proposal(identity, encoded(proposal))
            return deepcopy(revoked)

    def propose_transfer(self, peer, release, release_revision, identity, collection, actor, *,
                         expected_revision=None, request_id, reason):
        """Prepare an independent release using host-registered peers and time."""
        from intake_transfer_store import propose
        return propose(self, peer, release, release_revision, identity, collection, actor,
                       expected_revision=expected_revision, request_id=request_id, reason=reason)

    def propose(self, request, record, actor, *, at=None):
        validate_policy_request(request, "mutation-request")
        if record is not None:
            schema_check(record, "knowledge-record")
        at = at or utcnow()
        with self.transaction():
            mutation = request.get("mutation")
            if mutation in ("retract", "retain", "strategy", "confirm", "archive", "unarchive", "supersede"):
                if record is not None:
                    raise StoreError("lifecycle operations derive their record; do not supply replacement content")
                row = self._row(request["record"])
                if row is None or row["deleted"]:
                    raise StoreError("lifecycle operation requires a live record")
                record = json.loads(row["body"])
                if mutation == "retract":
                    record["content"]["status"] = "retracted"
                elif mutation == "retain":
                    record["content"].setdefault("data", {})["retainedAt"] = at
                elif mutation == "strategy":
                    resource = request["resource"]
                    record = apply_strategy(self.contract.policy, resource, record, at=at)["record"]
                elif mutation == "confirm":
                    record = confirm_with_strategy(self.contract.policy, request["resource"], record, at=at)
                elif mutation == "archive":
                    record = archive(record, at=at)
                elif mutation == "unarchive":
                    record = unarchive_with_strategy(self.contract.policy, request["resource"], record, at=at)
                elif mutation == "supersede":
                    successor_id = request.get("successor")
                    successor = self._live_record(successor_id) if successor_id else None
                    if not successor or not any(edge["rel"] == "supersedes" and edge["target"] == request["record"]
                                                for edge in successor["relations"]):
                        raise StoreError("create and review a linked successor before superseding this record")
                    record = mark_superseded(record, successor_id, at=at)
            elif request.get("successor") is not None:
                raise StoreError("successor is only valid for supersession")
            current, before, decision = self._prepare(request, record, actor, "propose", at=at)
            if record is not None:
                self._require_studio_app_bindings(record, actor, at)
            payload = {
                "id": secrets.token_hex(16),
                "request": deepcopy(request),
                "record": deepcopy(record),
                "actor": actor,
                "at": at or utcnow(),
                "contract": self.contract.binding,
                "review": None,
                "expiresAt": (timestamp(at or utcnow()) + dt.timedelta(minutes=10)).isoformat(timespec="milliseconds"),
            }
            self.dialect.add_proposal(payload["id"], encoded(payload))
            return {
                "proposal": payload["id"],
                "before": before,
                "after": deepcopy(record),
                "decision": decision,
                "revision": current,
            }

    def _proposal(self, identity, at, *, allow_expired=False, allow_deferred=False, allow_disposed=False):
        budget = getattr(self, "_inspection_budget", None)
        if budget is not None:
            budget.body(self.db, "proposals", "id", identity)
        body = self.dialect.proposal(identity)
        if body is None:
            raise StoreError("unknown proposal")
        proposal = json.loads(body)
        if (
            proposal["contract"] != self.contract.binding
            or not allow_expired
            and timestamp(at or utcnow()) >= timestamp(proposal["expiresAt"])
        ):
            raise StoreError("proposal expired or authority contract changed")
        from proposal_disposition import state, CLOSED
        status = state(proposal)
        if not allow_disposed and (status in CLOSED or status == 'deferred' and not allow_deferred):
            raise StoreError('Proposal disposition prevents this operation')
        return proposal

    def dispose(self, identity, actor, action, reason, *, expected_proposal_sha256, at=None):
        from proposal_disposition import dispose
        return dispose(self, identity, actor, action, reason,
                       expected_proposal_sha256=expected_proposal_sha256, at=at or self.intake_clock())

    def review(self, identity, actor, reason, *, at=None, expected_proposal_sha256=None):
        if not isinstance(reason, str) or not reason.strip():
            raise StoreError("review requires a reason")
        with self.transaction():
            proposal = self._proposal(identity, at, allow_expired=True, allow_deferred=True)
            if expected_proposal_sha256 is not None and fingerprint(proposal) != expected_proposal_sha256:
                raise StoreError('Proposal changed; inspect its current intent before deciding')
            if "transfer" in proposal:
                at = self.intake_clock()
            self._proposal(identity, at, allow_deferred=True)
            self._prepare(proposal["request"], proposal["record"], actor, "review", proposal=proposal, at=at)
            from proposal_disposition import approve
            approve(self, proposal, actor, reason, at or utcnow())
            self.dialect.update_proposal(identity, encoded(proposal))
            return deepcopy(proposal["review"])

    def commit(self, identity, actor, *, at=None, fault=None, expected_proposal_sha256=None):
        with self.transaction():
            proposal = self._proposal(identity, at, allow_expired=True)
            if "transfer" in proposal:
                at = self.intake_clock()
            if expected_proposal_sha256 is not None and fingerprint(proposal) != expected_proposal_sha256:
                raise StoreError('Proposal changed; inspect its current intent before committing')
            request, record = proposal["request"], proposal["record"]
            intent = fingerprint(
                {"request": request, "record": record, "proposer": proposal["actor"], "contract": proposal["contract"]}
            )
            previous = self.dialect.receipt(actor, request["id"])
            if previous:
                collection = record["collection"] if record else self._row(request["record"])["collection"]
                if previous["intent"] != intent or not self.contract.can_read(collection, actor, at):
                    raise StoreError("idempotency key reused with different intent or inaccessible result")
                receipt = json.loads(previous["body"])
                if any(
                    not self._target_readable(edge["target"], actor, at) and edge["target"] != request["record"]
                    for value in (receipt["before"], receipt["after"])
                    if value
                    for edge in value["relations"]
                ):
                    raise PolicyError("retry receipt includes relationships outside the caller's read scope")
                return receipt
            self._proposal(identity, at)
            current, before, decision = self._prepare(request, record, actor, "commit", proposal=proposal, at=at)
            if record is not None:
                self._require_studio_app_bindings(record, actor, at)
            transfer_witness = None
            if "transfer" in proposal:
                from intake_transfer_store import witness
                transfer_witness = witness(self, proposal, actor)
                at = self.intake_clock()
                current, before, decision = self._prepare(request, record, actor, "commit", proposal=proposal, at=at)
            sequence = self.dialect.next_sequence("events")
            revision = f"{sequence}:" + fingerprint(record)
            self.dialect.put_record(request["record"], (record or before)["collection"], revision, encoded(record),
                                    int(record is None))
            self.dialect.replace_edges(request["record"], [(edge["target"], edge["rel"], encoded(edge))
                                                           for edge in (record or {}).get("relations", [])])
            if fault:
                fault("after-record")
            receipt = {
                "sequence": sequence,
                "proposal": identity,
                "request": request,
                "actor": actor,
                "proposedBy": proposal["actor"],
                "review": proposal["review"],
                "contract": self.contract.binding,
                "at": at or utcnow(),
                "previousRevision": current,
                "revision": revision,
                "before": before,
                "after": record,
            }
            if transfer_witness is not None:
                receipt.update(transfer=deepcopy(proposal['transfer']), transferWitness=transfer_witness)
                if len(encoded(receipt).encode('utf-8')) > 16 * 1024 * 1024:
                    raise StoreError('Transfer journal event exceeds its byte budget')
            if request['mutation'] == 'promote':
                receipt.update(promotion=deepcopy(proposal['promotion']), sourceReview=deepcopy(proposal['sourceReview']))
            head = self.dialect.journal_head()["digest"]
            digest = fingerprint({"previous": head, "event": receipt})
            self.dialect.append_event(sequence, head, digest, encoded(receipt))
            self.dialect.add_receipt(actor, request["id"], intent, encoded(receipt))
            self.dialect.add_outbox(sequence, encoded({"sequence": sequence, "digest": digest}))
            if fault:
                fault("before-commit")
            if record:
                from intake_text_write import current_judgment
                current_judgment(self, record, actor=actor, at=at or self.intake_clock())
            if transfer_witness is not None:
                from intake_transfer_store import verify_current_witness
                verify_current_witness(self, proposal, actor, transfer_witness)
            representation = proposal.get('promotion', {}).get('representation')
            if representation and representation['receipt']['format'] in ('intake-recording-transcription/v1', 'intake-processing-reuse/v1'):
                from intake_processed import authorize, current_protection
                current_protection(self, representation, actor=actor, at=at or utcnow())
                authorize(self.contract, representation, actor, at or utcnow(),
                          proposal['promotion']['resource'])
                if representation['receipt']['format'] == 'intake-processing-reuse/v1':
                    for reviewer in {proposal['review']['actor'], proposal['sourceReview']['actor']}:
                        current_protection(self, representation, actor=reviewer, at=at or utcnow())
                        authorize(self.contract, representation, reviewer, at or utcnow(),
                                  proposal['promotion']['resource'])
                    self._check_source_reviewer(proposal, proposal['sourceReview']['actor'], at or utcnow())
                    self.contract.decision(request, actor, 'commit', request['expectedRevision'],
                        at=at or utcnow(), proposed_by=proposal['actor'], reviewed_by=proposal['review']['actor'],
                        source_approved_by=proposal['sourceReview']['actor'])
                if proposal['promotion']['projection'] == 'intake-release/v1':
                    from intake_transfer import current_release_protection
                    current_release_protection(self, proposal['promotion'], record['collection'])
        if fault:
            fault("after-commit")
        return receipt

    def export(self):
        """Administrative full-fidelity backup, including private history and pending work."""
        self.dialect.begin()
        try:
            return self._snapshot()
        finally:
            self.dialect.rollback()

    def _snapshot(self):
        tables = {}
        for table, ordering in (
            ("metadata", "key"),
            ("records", "id"),
            ("edges", "source,target,rel"),
            ("events", "sequence"),
            ("receipts", "actor,request_id"),
            ("proposals", "id"),
            ("outbox", "sequence"),
            ("deliveries", "consumer"),
        ):
            tables[table] = self.dialect.table_rows(table, SNAPSHOT_COLUMNS[table], ordering.split(","))
        snapshot = {"format": "knowledge-authority/v1", "schemaVersion": DB_VERSION, "tables": tables}
        contract = getattr(self, "contract", None) or Contract(json.loads(self._meta("bundle")))
        if contract.blob_store is not None:
            snapshot["blobs"] = self._blob_manifest(contract, tables["records"])
        snapshot["sha256"] = fingerprint(snapshot)
        return snapshot

    def _blob_manifest(self, contract, rows):
        """Blob completeness: `included` carries the bytes (db-blob keeps them in this database);
        `referenced` lists locators whose bytes stay in their blob store."""
        locators = _snapshot_locators(rows)
        if contract.cell["blobs"] != "db-blob":
            return {"completeness": "referenced", "locators": locators}
        store = DbBlobStore(contract.blob_store, self.dialect)
        return {"completeness": "included", "locators": locators,
                "content": {locator["key"]: encode_blob(store.get(locator)) for locator in locators}}

    @classmethod
    def restore(cls, path, snapshot, *, blob_store=None):
        """Restore standby. Activation requires the matching source fence.

        The snapshot may come from any authority driver: its contract is restored running on
        this one, and `restoredFrom` names the source snapshot. Included blobs are verified with
        the snapshot. Referenced blobs are read back from `blob_store` and must match their
        locator digests before anything is written.
        """
        tables, blobs = _restorable(snapshot, cls.dialect_class.driver, blob_store)
        dialect = cls.dialect_class.create(path, _schema(cls.dialect_class, db_blob=blobs["completeness"] == "included"))
        try:
            for table, rows in tables.items():
                for row in rows:
                    dialect.insert_row(table, row)
            if blobs["completeness"] == "included":
                for locator in blobs["locators"]:
                    dialect.add_blob(locator["key"], decode_blob(blobs["content"][locator["key"]]))
            dialect.set_meta("status", "standby")
            dialect.set_meta("instance", secrets.token_hex(16))
            dialect.set_meta("restoredFrom", snapshot["sha256"])
            dialect.set_schema_version(DB_VERSION)
            dialect.commit()
        except BaseException:
            if dialect.in_transaction:
                dialect.rollback()
            dialect.discard()
            raise
        dialect.close()
        return cls(path)

    @staticmethod
    def validate_snapshot(snapshot):
        content = {key: value for key, value in snapshot.items() if key != "sha256"}
        if (
            snapshot.get("format") != "knowledge-authority/v1"
            or snapshot.get("schemaVersion") != DB_VERSION
            or fingerprint(content) != snapshot.get("sha256")
        ):
            raise StoreError("unsupported or corrupt authority backup")
        columns = {table: set(names) for table, names in SNAPSHOT_COLUMNS.items()}
        if set(snapshot["tables"]) != set(columns):
            raise StoreError("backup must include every authority table")
        for table, rows in snapshot["tables"].items():
            if not isinstance(rows, list) or any(set(row) != columns[table] for row in rows):
                raise StoreError("backup contains unsupported table columns")
        metadata = {row["key"]: row["value"] for row in snapshot["tables"]["metadata"]}
        contract = Contract(json.loads(metadata["bundle"]))
        records = [json.loads(row["body"]) for row in snapshot["tables"]["records"] if not row["deleted"]]
        for record in records:
            contract.validate_record(record)
        contract.graph(records)
        _check_blob_manifest(snapshot, contract)
        previous = legacy = None
        neutral = False
        replay = {}
        reviewed_events = {}
        events = snapshot["tables"]["events"]
        if not events:
            raise StoreError("backup is missing its import history")
        for sequence, row in enumerate(events, 1):
            body = json.loads(row["body"])
            if (
                row["sequence"] != sequence
                or row["previous"] != previous
                or row["digest"] != fingerprint({"previous": previous, "event": body})
            ):
                raise StoreError("authority journal is incomplete or corrupt")
            if body.get("contract") == contract.binding:
                neutral = True
            else:
                # Events from before schema 11 keep their driver-inclusive binding: one binding, and
                # only as a prefix of the journal, since every later writer records the neutral one.
                if neutral or body.get("contract") not in contract.legacy_bindings or legacy not in (None, body["contract"]):
                    raise StoreError("journal references a different authority contract")
                legacy = body["contract"]
            if sequence == 1:
                if body.get("operation") != "import" or body.get("priorHistory") != json.loads(
                    metadata["prior_history"]
                ):
                    raise StoreError("import history is missing or inconsistent")
                for record in body["records"]:
                    if record["id"] in replay:
                        raise StoreError("duplicate imported identity")
                    replay[record["id"]] = {
                        "id": record["id"],
                        "collection": record["collection"],
                        "body": encoded(record),
                        "revision": "1:" + fingerprint(record),
                        "deleted": 0,
                    }
            else:
                identity = body["request"]["record"]
                old = replay.get(identity)
                if body["before"] != (json.loads(old["body"]) if old and not old["deleted"] else None) or body[
                    "previousRevision"
                ] != (old["revision"] if old else None):
                    raise StoreError("journal before-state or revision is inconsistent")
                after = body["after"]
                if body['request']['mutation'] == 'promote':
                    pin, release = body.get('promotion'), body.get('sourceReview')
                    if (not isinstance(pin, dict) or set(pin) != (
                            {'source', 'revision', 'sha256', 'resource', 'projection', 'destination'} |
                            ({'representation'} if pin.get('projection') == 'intake-processed-record/v1' or
                    pin.get('projection') == 'intake-release/v1' and 'representation' in pin else set()) |
                ({'release'} if pin.get('projection') == 'intake-release/v1' else set()))
                            or not isinstance(release, dict) or set(release) != {'actor', 'reason', 'at'}
                            or not isinstance(release['reason'], str) or not release['reason'].strip()
                            or timestamp(release['at']) > timestamp(body['at'])):
                        raise StoreError('Journal promotion lacks its exact source release')
                    source = replay.get(pin['source'])
                    if not source or source['deleted'] or source['revision'] != pin['revision']:
                        raise StoreError('Journal promotion source or destination revision is inconsistent')
                    original = json.loads(source['body'])
                    resource = contract.collections[original['collection']]['resource']
                    if (resource != pin['resource'] or resource != body['request']['sourceResource']
                            or fingerprint(original) != pin['sha256'] or not after or pin['source'] == identity
                            or body['request']['evidence'] != ['promotion-source:' + fingerprint(pin)]):
                        raise StoreError('Journal promotion differs from its declared source')
                    if pin['projection'] == 'copy/v1' and pin['destination'] is None:
                        if (old is not None or contract.policy.resources[resource]['scope'] ==
                                contract.policy.resources[body['request']['resource']]['scope']):
                            raise StoreError('Journal copy requires a new identity in a distinct scope')
                        projected = {**original, 'id': identity, 'collection': after['collection']}
                    elif pin['projection'] in ('intake-metadata-record/v1', 'intake-processed-record/v1', 'intake-release/v1'):
                        event = reviewed_events.get((pin['source'], pin['revision']))
                        if not event or not event.get('review'):
                            raise StoreError('Journal intake requires reviewed source history')
                        contract.source_reviewer(resource, event['review']['actor'], event['proposedBy'], at=event['review']['at'])
                        if 'representation' in pin:
                            from intake_processed import authorize
                            if pin['representation']['receipt']['principal'] != body['proposedBy']:
                                raise StoreError('Processed representation principal differs from its adopter')
                            authorize(contract, pin['representation'], body['actor'], body['at'], resource)
                            authorize(contract, pin['representation'], release['actor'], release['at'], resource)
                            authorize(contract, pin['representation'], release['actor'], body['at'], resource)
                        from intake_delivery import project
                        if pin['projection'] == 'intake-release/v1':
                            from intake_transfer import release_project
                            if old is not None or timestamp(body['at']) >= timestamp(pin['release']['expiresAt']):
                                raise StoreError('Journal release must be new and unexpired')
                            projected = release_project(contract, original, pin, identity, after['collection'])
                        else:
                            projected = project(contract, original, pin, identity, after['collection'], body['before'])
                    else:
                        raise StoreError('Unsupported journal promotion projection')
                    if after != projected:
                        raise StoreError('Journal promotion differs from its source projection')
                    contract.source_reviewer(resource, release['actor'], body['proposedBy'], at=release['at'])
                    contract.source_reviewer(resource, release['actor'], body['proposedBy'], at=body['at'])
                    contract.decision(body['request'], body['actor'], 'commit', body['previousRevision'], at=body['at'],
                        proposed_by=body['proposedBy'], reviewed_by=(body.get('review') or {}).get('actor'),
                        source_approved_by=release['actor'])
                mutation = body['request']['mutation']
                if mutation in ('strategy', 'confirm', 'archive', 'unarchive', 'supersede'):
                    if not body.get('before') or not after:
                        raise StoreError('lifecycle journal operation requires a live before and after record')
                    resource = body['request']['resource']
                    if mutation == 'strategy':
                        expected = apply_strategy(contract.policy, resource, body['before'], at=body['at'])['record']
                    elif mutation == 'confirm':
                        expected = confirm_with_strategy(contract.policy, resource, body['before'], at=body['at'])
                    elif mutation == 'archive':
                        expected = archive(body['before'], at=body['at'])
                    elif mutation == 'unarchive':
                        expected = unarchive_with_strategy(contract.policy, resource, body['before'], at=body['at'])
                    else:
                        expected = mark_superseded(body['before'], body['request'].get('successor'), at=body['at'])
                        successor = replay.get(body['request'].get('successor'))
                        successor_record = json.loads(successor['body']) if successor and not successor['deleted'] else None
                        if not successor_record or not any(edge['rel'] == 'supersedes' and edge['target'] == identity
                                                            for edge in successor_record['relations']):
                            raise StoreError('journal supersession lacks its committed successor link')
                    if after != expected:
                        raise StoreError('lifecycle journal effect differs from the pinned operation and time')
                    decision = contract.decision(body['request'], body['actor'], 'commit', body['previousRevision'],
                        at=body['at'], proposed_by=body['proposedBy'],
                        reviewed_by=(body.get('review') or {}).get('actor'))
                    if not decision['allowed'] or not decision['requiresReview'] or not body.get('review'):
                        raise StoreError('lifecycle journal operation lacks its governed independent review')
                if mutation == 'create' and after:
                    predecessor_links = [edge for edge in after['relations'] if edge['rel'] == 'supersedes']
                    if predecessor_links:
                        if len(predecessor_links) != 1:
                            raise StoreError('successor must name exactly one predecessor')
                        predecessor = replay.get(predecessor_links[0]['target'])
                        predecessor_record = json.loads(predecessor['body']) if predecessor and not predecessor['deleted'] else None
                        if not predecessor_record or predecessor_record.get('content', {}).get('data', {}).get('lifecycle', {}).get('state') in ('archived', 'superseded'):
                            raise StoreError('successor link must target a live predecessor')
                if "transfer" in body:
                    from intake_transfer_store import validate_event
                    validate_event(contract, body)
                else:
                    from intake_transfer_store import transfer_change
                    if after is not None:
                        transfer_change(body["before"], after)
                if after is not None:
                    from intake_delivery import metadata_change
                    metadata_change(body['before'], after, materializing=body['request']['mutation'] == 'promote' or 'transfer' in body)
                if after is not None and body['request']['mutation'] != 'promote':
                    from intake_transfer import release_change
                    release_change(body['before'], after)
                if body["revision"] != f"{sequence}:" + fingerprint(after):
                    raise StoreError("journal revision does not bind its resulting record")
                replay[identity] = {
                    "id": identity,
                    "collection": (after or body["before"])["collection"],
                    "body": encoded(after),
                    "revision": body["revision"],
                    "deleted": int(after is None),
                }
                reviewed_events[(identity, body['revision'])] = body
            previous = row["digest"]
        if sorted(replay.values(), key=lambda row: row["id"]) != snapshot["tables"]["records"]:
            raise StoreError("current records do not match the complete declared history")
        projected_edges = sorted(
            [
                {"source": record["id"], "target": edge["target"], "rel": edge["rel"], "body": encoded(edge)}
                for record in records
                for edge in record["relations"]
            ],
            key=lambda e: (e["source"], e["target"], e["rel"]),
        )
        if projected_edges != snapshot["tables"]["edges"]:
            raise StoreError("relationship index does not match its canonical records")
        expected_outbox = [
            {"sequence": row["sequence"], "body": encoded({"sequence": row["sequence"], "digest": row["digest"]})}
            for row in events
        ]
        if expected_outbox != snapshot["tables"]["outbox"]:
            raise StoreError("projection outbox has lost committed events")
        if any(not 0 <= row["sequence"] <= len(events) for row in snapshot["tables"]["deliveries"]):
            raise StoreError("projection acknowledgment is ahead of committed history")
        event_receipts = [json.loads(row["body"]) for row in events[1:]]
        if sorted(encoded(json.loads(row["body"])) for row in snapshot["tables"]["receipts"]) != sorted(
            encoded(row) for row in event_receipts
        ):
            raise StoreError("retry receipts do not cover the complete mutation history")
        for row in snapshot["tables"]["receipts"]:
            receipt = json.loads(row["body"])
            intent = fingerprint(
                {
                    "request": receipt["request"],
                    "record": receipt["after"],
                    "proposer": receipt["proposedBy"],
                    "contract": receipt["contract"],
                }
            )
            if (row["actor"], row["request_id"], row["intent"]) != (receipt["actor"], receipt["request"]["id"], intent):
                raise StoreError("retry receipt identity is corrupt")

        from proposal_disposition import validate_history, commitment, intent as proposal_intent, CLOSED
        by_intent = {}
        for row in snapshot['tables']['receipts']:
            by_intent.setdefault(row['intent'], []).append(json.loads(row['body']))
        identities = set()
        proposals = {}
        for row in snapshot['tables']['proposals']:
            proposal = json.loads(row['body'])
            if proposal['id'] != row['id'] or row['id'] in identities:
                raise StoreError('Backup proposal identity is inconsistent')
            identities.add(row['id'])
            proposals[row['id']] = proposal
            status = validate_history(contract, proposal)
            if commitment(proposal, by_intent.get(proposal_intent(proposal), [])) and (status in CLOSED or status == 'deferred'):
                raise StoreError('Backup committed proposal has an incompatible disposition')
        receipt_proposals = [receipt['proposal'] for receipt in event_receipts if 'proposal' in receipt]
        if len(receipt_proposals) != len(set(receipt_proposals)) or not set(receipt_proposals).issubset(identities):
            raise StoreError('Commit receipt lacks a unique stored proposal')
        for receipt in event_receipts:
            if 'proposal' in receipt:
                commitment(proposals[receipt['proposal']], [receipt])

    def delivery_preview(self, actor, *, at=None):
        """Native policy-filtered outbox projection from one read transaction."""
        own_transaction = not self.dialect.in_transaction
        if own_transaction:
            self.dialect.begin()
        try:
            head = self.dialect.outbox_head()
            payload = {
                "protocolVersion": "1.0",
                "authority": self.contract.document["id"],
                "contract": self.contract.binding,
                "sequence": head,
                "audience": actor,
                "observedAt": at or utcnow(),
                "graph": self.context(actor, at=at),
            }
        finally:
            if own_transaction:
                self.dialect.rollback()
        return payload

    def observe(self, *, at=None):
        """Observe (docs/patterns/knowledge-stores.md): health, delivery lag per consumer and
        rejected proposals, from one read transaction. Operational metadata only, no record content;
        a frozen authority reports its state instead of refusing."""
        from proposal_disposition import state
        own_transaction = not self.dialect.in_transaction
        if own_transaction:
            self.dialect.begin()
        try:
            status, version = self._meta("status"), self.schema_version()
            head = self.dialect.outbox_head()
            delivered = self.dialect.deliveries()
            rejected = [identity for identity, body in self.dialect.proposals() if state(json.loads(body)) == "rejected"]
        finally:
            if own_transaction:
                self.dialect.rollback()
        lag = sorted(({"consumer": json.loads(row[0])["consumer"], "sequence": row[1], "behind": head - row[1]}
                      for row in delivered), key=lambda entry: entry["consumer"])
        return {
            "observedAt": at or utcnow(),
            "health": {"state": status, "schemaVersion": version, "writable": status == "active" and version == DB_VERSION},
            "head": head,
            "lag": lag,
            "rejected": {"count": len(rejected), "proposals": rejected},
        }

    def deliver(self, consumer, actor, write, *, at=None, fault=None, expected_projection_sha256=None, acknowledge_guard=None):
        """Publish a native projection, then acknowledge its exact outbox head.

        Destination side effects precede acknowledgement. A failed acknowledgement
        can leave a valid prior copy; retry uses the native monotonic sink contract.
        """
        if acknowledge_guard is not None and not callable(acknowledge_guard):
            raise StoreError("Invalid trusted acknowledgement guard")
        if not consumer:
            raise StoreError("projection consumer identity is required")
        payload = self.delivery_preview(actor, at=at)
        if expected_projection_sha256 is not None and projection_basis(payload) != expected_projection_sha256:
            raise StoreError('Projection changed; inspect its current basis before publication')
        head = payload['sequence']
        write(deepcopy(payload))
        if fault:
            fault("after-delivery")
        with self.transaction():
            if acknowledge_guard:
                acknowledge_guard()
            self.dialect.acknowledge(encoded({"consumer": consumer, "actor": actor, "contract": self.contract.binding}), head)
            if acknowledge_guard:
                acknowledge_guard()
        return {"delivered": True, "sequence": head}

    def freeze(self, successor, *, expected_snapshot, store=None):
        """Fence this source for the successor instance `successor`; cutover() and resume() also
        name the successor's store id, `store`, which the frozen source keeps as `successorStore`."""
        fence = _fence(successor, expected_snapshot, store)
        with self.transaction():
            if self._snapshot()["sha256"] != expected_snapshot:
                raise StoreError("source changed since backup; make a new cutover snapshot")
            self.dialect.set_meta("status", "frozen")
            for key, value in fence.items():
                self.dialect.add_meta(key, value)

    def activate_from(self, source):
        """Finish an interrupted cutover only after the exact source snapshot is frozen."""
        self.dialect.begin(write=True)
        try:
            if (
                source._meta("status") != "frozen"
                or source._meta("successor") != self._meta("instance")
                or source._meta("frozenSnapshot") != self._meta("restoredFrom")
                or source.contract.binding != self.contract.binding
            ):
                raise StoreError("source is not frozen for this restored successor")
            if self._meta("status") not in ("standby", "active"):
                raise StoreError("successor cannot be activated")
            self.validate_snapshot(self._snapshot())
            self.dialect.set_meta("status", "active")
            self.dialect.commit()
        except BaseException:
            self.dialect.rollback()
            raise

    def cutover(self, target, *, store, adapter=None, fault=None, blob_store=None):
        """Graduate into a new `adapter` store (default: this driver) at `target`; see cutover()."""
        return cutover(self, adapter or type(self), target, store=store, fault=fault, blob_store=blob_store)

    @classmethod
    def migrate(cls, path, *, expected_binding=None):
        """Explicitly adopt the writer guard, preserving and validating complete history.

        Version 2 added the durable outbox. Versions 3 and 4 require metadata and
        processed-promotion enforcement. Version 5 adds independent-release and
        destination-transfer enforcement. Version 6 validates explicit transcription
        timing uncertainty. Version 7 validates parent-linked recording ranges
        and immutable inference provenance. Version 8 adds current source/model/
        protection approval for text-projected judgment writes. Version 9 adds current
        original/new source and cache gates for processing reuse. Version 10 enforces
        durable proposal disposition and its recorded history. Version 11 leaves the
        authority driver out of the contract binding (`contract_binding`); history
        written before it keeps the binding it was written with, which validation
        accepts as the journal's prefix, and the adopted pin moves to the new binding.
        These do not change table shapes. Stop existing writers before migration; old
        open processes cannot be retroactively taught a new gate.

        The schema version lives in the `metadata.schema_version` row. A pre-seam
        SQLite file holds it only in PRAGMA user_version; migration moves it to
        the row. A pre-seam file already at the current version only gains the
        row: nothing is recorded in `schemaMigrations`, because no schema changed.
        Every write goes through the dialect, so a postgres or mysql authority
        migrates in its writer transaction; those are born past version 1, so the
        version-1 DDL (which MySQL would commit implicitly) never runs on them.
        """
        if not cls.dialect_class.exists(path):
            raise StoreError("migration source does not exist")
        dialect = cls.dialect_class.open(path)
        db = dialect.db
        try:
            dialect.begin(write=True)
            version, legacy = _stored_version(dialect)
            if version not in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10) and not (legacy and version == DB_VERSION):
                raise StoreError(f"only schema 1, 2, 3, 4, 5, 6, 7, 8, 9 or 10 -> {DB_VERSION} migration is supported")
            declaration = Contract(json.loads(dialect.meta("bundle")))
            # The adopted pin may still be the binding schema 10 and earlier computed.
            if expected_binding is not None and expected_binding not in {declaration.binding, *declaration.legacy_bindings}:
                raise StoreError("authority contract differs from adopted migration binding")
            if version == 1:
                dialect.apply_schema("".join(_table_schema(dialect, table) + ";\n" for table in ("outbox", "deliveries")))
                for sequence, digest in dialect.event_digests():
                    dialect.add_outbox(sequence, encoded({"sequence": sequence, "digest": digest}))
            if version != DB_VERSION:
                old = dialect.meta("schemaMigrations")
                migrations = json.loads(old) if old else []
                migrations.append({"from": version, "to": DB_VERSION, "at": utcnow()})
                dialect.set_meta("schemaMigrations", encoded(migrations))
            if not dialect.has_index(REVIEW_INDEX):
                db.execute(_review_index(dialect))
            dialect.set_schema_version(DB_VERSION)
            candidate = cls.__new__(cls)
            candidate.dialect, candidate.db = dialect, db
            cls.validate_snapshot(candidate._snapshot())
            dialect.commit()
        except BaseException:
            if dialect.in_transaction:
                dialect.rollback()
            raise
        finally:
            dialect.close()
        return cls(path)


def _fence(successor, snapshot, store):
    """The metadata rows a freeze adds to its source."""
    if not isinstance(successor, str) or not successor:
        raise StoreError("cutover requires an explicit successor")
    if store is not None:
        _check_store(store)
    return {"successor": successor, "frozenSnapshot": snapshot, **({"successorStore": store} if store else {})}


def _check_store(store):
    if not isinstance(store, str) or not store:
        raise StoreError("cutover requires the successor's store id")


def cutover(source, adapter, target, *, store, fault=None, blob_store=None):
    """Graduate `source` (any authority, or a files authority) into a new `adapter` store at `target`.

    Exports the source, restores the snapshot into the target driver in standby (refusing with
    `CutoverLoss` when that driver cannot hold the brain), freezes the source for the target
    instance held by `store` (refusing if the source changed since the snapshot), then activates
    the target. A fault after the restore or after the freeze leaves a standby target that
    `resume()` completes.
    """
    _check_store(store)
    if source._meta("status") != "active":
        raise StoreError(f"cutover needs an active source; this authority is {source._meta('status')}")
    snapshot = source.export()
    successor = adapter.restore(target, snapshot, blob_store=blob_store)
    try:
        if fault:
            fault("after-restore")
        source.freeze(successor._meta("instance"), expected_snapshot=snapshot["sha256"], store=store)
        if fault:
            fault("after-freeze")
        successor.activate_from(source)
        return successor
    except BaseException:
        successor.close()
        raise


def resume(source, successor, *, store):
    """Finish a cutover into `successor` (held by `store`) interrupted at either fault point.

    Before the freeze, the source is frozen for the successor only if it still holds exactly
    the snapshot the successor was restored from; after it, the successor is activated.
    """
    if source._meta("status") == "active":
        source.freeze(successor._meta("instance"), expected_snapshot=successor._meta("restoredFrom"), store=store)
    successor.activate_from(source)


class SQLiteAuthority(Authority):
    dialect_class = SQLiteDialect


class PostgresAuthority(Authority):
    dialect_class = PostgresDialect


class MySQLAuthority(Authority):
    dialect_class = MySQLDialect


class _MongoDialectClass:
    """mongo_dialect.MongoDialect, imported when a mongo authority is first used, so packages
    that never open one need not carry the module."""

    def __get__(self, instance, owner):
        from mongo_dialect import MongoDialect
        return MongoDialect


class MongoAuthority(Authority):
    dialect_class = _MongoDialectClass()


def authority_class(dsn):
    """The adapter a resolved store dsn names: a postgres, mysql or mongodb URL, a `.json` files
    authority snapshot, otherwise a SQLite path."""
    if "://" not in dsn:
        return FileReference if dsn.endswith(".json") else SQLiteAuthority
    scheme = dsn.split("://", 1)[0]
    adapters = {"postgres": PostgresAuthority, "postgresql": PostgresAuthority, "mysql": MySQLAuthority,
                "mongodb": MongoAuthority, "mongodb+srv": MongoAuthority}
    if scheme not in adapters:
        raise StoreError(f"no authority driver for store dsn scheme {scheme}")
    return adapters[scheme]


class FileReference:
    """Read-only, policy-filtered reference over a complete file authority snapshot.

    The `files` authority driver: its state is one snapshot file. It is never written through,
    only cut over: `restore` writes a standby file, and `freeze` and `activate_from` rewrite it
    whole, under a lock, with its digest recomputed.
    """

    driver = "files"
    CAPABILITIES = frozenset({"authority", "read-only-session"})

    def __init__(self, path, *, expected_binding=None):
        self.path = Path(path)
        if not self.path.is_file():
            raise StoreError("authority does not exist; initialize or restore explicitly")
        self._load(json.loads(self.path.read_text()))
        if expected_binding is not None and expected_binding != self.contract.binding:
            raise StoreError("authority contract differs from the adopted binding")

    def _load(self, snapshot):
        Authority.validate_snapshot(snapshot)
        self.snapshot = snapshot
        self.metadata = {row["key"]: row["value"] for row in snapshot["tables"]["metadata"]}
        self.contract = Contract(json.loads(self.metadata["bundle"]))
        self.state = self.metadata["status"]
        self.records = {row["id"]: row for row in snapshot["tables"]["records"]}

    def _meta(self, key):
        if key not in self.metadata:
            raise StoreError(f"missing authority metadata: {key}")
        return self.metadata[key]

    def close(self):
        pass

    def export(self):
        """The snapshot file as it is now."""
        with self._locked():
            self._load(json.loads(self.path.read_text()))
        return deepcopy(self.snapshot)

    @contextmanager
    def _locked(self):
        import fcntl
        with open(str(self.path) + ".lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def _rewrite(self, snapshot, metadata):
        """Replace the file with `snapshot` holding `metadata`, digest recomputed."""
        snapshot = deepcopy(snapshot)
        snapshot["tables"]["metadata"] = [{"key": key, "value": metadata[key]} for key in sorted(metadata)]
        snapshot.pop("sha256")
        snapshot["sha256"] = fingerprint(snapshot)
        Authority.validate_snapshot(snapshot)
        fd, temporary = tempfile.mkstemp(prefix=".authority-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write(encoded(snapshot) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        self._load(snapshot)

    @classmethod
    def restore(cls, path, snapshot, *, blob_store=None):
        """Write a standby files authority from a snapshot of any driver (see Authority.restore)."""
        tables, _ = _restorable(snapshot, cls.driver, blob_store)
        metadata = {row["key"]: row["value"] for row in tables["metadata"]}
        metadata.update(status="standby", instance=secrets.token_hex(16), restoredFrom=snapshot["sha256"])
        metadata["schema_version"] = str(DB_VERSION)
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        try:
            restored = cls.__new__(cls)
            restored.path = path
            with restored._locked():
                restored._rewrite({**snapshot, "tables": tables}, metadata)
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return cls(path)

    def freeze(self, successor, *, expected_snapshot, store=None):
        """Fence this source for `successor`, as Authority.freeze."""
        fence = _fence(successor, expected_snapshot, store)
        with self._locked():
            current = json.loads(self.path.read_text())
            if current.get("sha256") != expected_snapshot:
                raise StoreError("source changed since backup; make a new cutover snapshot")
            self._load(current)
            if self.state != "active":
                raise StoreError("authority is frozen; write through its declared successor")
            self._rewrite(current, {**self.metadata, "status": "frozen", **fence})

    def activate_from(self, source):
        """Finish a cutover into this file only after the exact source snapshot is frozen."""
        with self._locked():
            self._load(json.loads(self.path.read_text()))
            if (
                source._meta("status") != "frozen"
                or source._meta("successor") != self._meta("instance")
                or source._meta("frozenSnapshot") != self._meta("restoredFrom")
                or source.contract.binding != self.contract.binding
            ):
                raise StoreError("source is not frozen for this restored successor")
            if self.state not in ("standby", "active"):
                raise StoreError("successor cannot be activated")
            self._rewrite(self.snapshot, {**self.metadata, "status": "active"})

    def cutover(self, target, *, store, adapter, fault=None, blob_store=None):
        return cutover(self, adapter, target, store=store, fault=fault, blob_store=blob_store)

    @classmethod
    def capabilities(cls):
        return cls.CAPABILITIES

    @classmethod
    def require(cls, capability):
        if capability not in cls.CAPABILITIES:
            raise unsupported(cls.driver, capability)

    def get(self, identity, actor, *, at=None):
        if self.state == "frozen":
            raise StoreError("source authority is frozen; read from its declared successor")
        row = self.records.get(identity)
        if row is None or not self.contract.can_read(row["collection"], actor, at):
            return None
        record = None if row["deleted"] else json.loads(row["body"])
        withheld = False
        if record:
            visible = [
                edge
                for edge in record["relations"]
                if edge["target"] in self.records
                and not self.records[edge["target"]]["deleted"]
                and self.contract.can_read(self.records[edge["target"]]["collection"], actor, at)
            ]
            withheld = len(visible) != len(record["relations"])
            record["relations"] = visible
        return {
            "record": record,
            "revision": row["revision"],
            "deleted": bool(row["deleted"]),
            "withheldRelations": withheld,
            "authorityState": self.state,
        }

    def context(self, actor, *, at=None):
        if self.state == "frozen":
            raise StoreError("source authority is frozen; read from its declared successor")
        at = at or utcnow()
        readable = {
            collection for collection in self.contract.collections if self.contract.can_read(collection, actor, at)
        }
        records = [
            json.loads(row["body"])
            for row in self.records.values()
            if not row["deleted"] and row["collection"] in readable
        ]
        records = context_records(self.contract, records, at=at)
        ids = {record["id"] for record in records}
        for record in records:
            record["relations"] = [edge for edge in record["relations"] if edge["target"] in ids]
        graph = self.contract.graph(records)
        graph["meta"]["authority"] = {"binding": self.contract.binding, "state": self.state}
        graph["meta"]["lifecycle"] = {"policySha256": self.contract.policy.binding["sha256"]}
        return graph

    def walk(self, start, actor, *, depth, at=None):
        """The Python frontier walk over the snapshot's edges, as Authority.walk (graph_role.py)."""
        from graph_role import check_depth, frontier_walk
        check_depth(depth)
        graph = self.context(actor, at=at)
        if start not in {node["id"] for node in graph["nodes"]}:
            return {"traversal": None, "nodes": []}
        edges = [(edge["source"], edge["target"]) for edge in graph["edges"]]
        return {"traversal": "frontier", "nodes": frontier_walk(edges, start, depth)}


def projection_basis(payload):
    """Publication selection binds content/scope/head; evaluation time is refreshed."""
    return fingerprint({key: value for key, value in payload.items() if key != 'observedAt'})


def atomic_projection(path, payload):
    """Local projection sink: never replace a newer sequence with an older delivery."""
    import fcntl

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(str(path) + ".lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if path.exists():
            previous = json.loads(path.read_text())
            if (previous["contract"], previous["audience"]) != (payload["contract"], payload["audience"]):
                raise StoreError("projection path belongs to another contract or audience")
            if (previous["sequence"], timestamp(previous["observedAt"])) >= (
                payload["sequence"],
                timestamp(payload["observedAt"]),
            ):
                return
        fd, temporary = tempfile.mkstemp(prefix=".projection-", dir=path.parent)
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write(encoded(payload) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
