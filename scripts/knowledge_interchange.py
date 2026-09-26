"""Loss-aware, read-only interchange. Archives never confer destination authority.

The archive preserves JSON values; graph projection is a separate, explicit
operation. Native journal replay and destination policy remain adapter duties.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sqlite3

import rfc8785

ALIASES = ("conflict-kg/v1", "calliope-kg/v1")
FORMAT = "brain-exchange/v1"
PORTABLE_FORMAT = "brain-exchange/v2"
COMPILED = "compiled-brain/v1"
JOURNAL = "calliope.brain/v1"
MAX_BYTES = 64 * 1024 * 1024


class InterchangeError(ValueError):
    pass


def canonical(value):
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise InterchangeError("expected finite JSON values") from exc


def portable_canonical(value):
    """JCS with a shared safe-integer restriction (large exact values use strings)."""
    def check(item):
        if isinstance(item, (int, float)) and not isinstance(item, bool):
            if item == int(item) and abs(item) > 9007199254740991:
                raise InterchangeError("exchange v2: unsafe integer; encode large exact values as strings")
        elif isinstance(item, dict):
            for child in item.values():
                check(child)
        elif isinstance(item, list):
            for child in item:
                check(child)
    try:
        check(value)
        return rfc8785.dumps(value).decode("utf-8")
    except (ValueError, OverflowError, UnicodeError, rfc8785.CanonicalizationError) as exc:
        raise InterchangeError(f"exchange v2 canonical JSON: {exc}") from exc


def digest(value, format=FORMAT):
    encode = portable_canonical if format == PORTABLE_FORMAT else canonical
    return hashlib.sha256(encode(value).encode("utf-8")).hexdigest()


def _object(value, where):
    if not isinstance(value, dict):
        raise InterchangeError(f"{where}: expected an object")


def _shape(value, required, optional=()):
    _object(value, "shape")
    if set(required) - value.keys() or value.keys() - set(required) - set(optional):
        raise InterchangeError(f"expected fields {required}; optional {optional}")


def _text(value, where):
    if not isinstance(value, str) or not value.strip():
        raise InterchangeError(f"{where}: expected a nonempty string")


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise InterchangeError(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise InterchangeError("input exceeds 64 MiB")
    try:
        result = json.loads(raw, object_pairs_hook=unique)
        canonical(result)
        return result
    except (ValueError, UnicodeError) as exc:
        raise InterchangeError(str(exc)) from exc


def _graph(value, kind, edge_kind):
    if not isinstance(value.get("nodes"), list) or not isinstance(value.get("edges"), list):
        raise InterchangeError("graph requires node and edge arrays")
    ids = set()
    for node in value["nodes"]:
        _object(node, "node")
        _text(node.get("id"), "node.id")
        _text(node.get(kind), f"node.{kind}")
        if node["id"] in ids:
            raise InterchangeError("duplicate node identity")
        ids.add(node["id"])
    for edge in value["edges"]:
        _object(edge, "edge")
        for endpoint in ("source", "target"):
            _text(edge.get(endpoint), f"edge.{endpoint}")
            if edge[endpoint] not in ids:
                raise InterchangeError("edge endpoint is absent; export a closed graph or an explicit boundary node")
        _text(edge.get(edge_kind), f"edge.{edge_kind}")


def portable(value):
    """Normalize legacy top-level props without losing or guessing collisions."""
    _shape(value, ("format", "nodes", "edges"))
    if value["format"] not in ALIASES:
        raise InterchangeError("unsupported portable graph version")
    _graph(value, "type", "type")
    result = deepcopy(value)
    for group, keys in (("nodes", ("id", "name", "type")), ("edges", ("source", "target", "type"))):
        for item in result[group]:
            if any(key not in item for key in keys):
                raise InterchangeError(f"{group}: missing required fields")
            if group == "nodes" and not isinstance(item["name"], str):
                raise InterchangeError("node.name must be a string")
            props = item.setdefault("props", {})
            _object(props, "props")
            for key in list(item):
                if key not in (*keys, "props"):
                    if key in props:
                        raise InterchangeError(f"ambiguous legacy property {key}")
                    props[key] = item.pop(key)
    canonical(result)
    return result


def graph_identity(value):
    """Content identity ignores alias spelling and object key order, not array order."""
    graph = portable(value)
    graph["format"] = ALIASES[0]
    return digest(graph)


def source_format(value):
    _object(value, "source")
    canonical(value)
    if value.get("format") in ALIASES:
        portable(value)
        return value["format"]
    if "format" in value:
        raise InterchangeError("unsupported source format; refusing to reinterpret its envelope")
    if value.get("kind") == "calliope.brain":
        _shape(value, ("version", "kind", "journal", "checksum"))
        _object(value["journal"], "journal")
        if type(value["version"]) is not int or value["version"] != 1 or type(value["journal"].get("version")) is not int or value["journal"].get("version") != 1:
            raise InterchangeError("unsupported CLI bundle version")
        # This is transport recognition, not journal authentication/replay.
        _shape(value["journal"], ("version", "header", "events", "hash"))
        _object(value["journal"]["header"], "journal.header")
        if not isinstance(value["journal"]["events"], list):
            raise InterchangeError("journal.events must be an array")
        return JOURNAL
    if isinstance(value.get("meta"), dict) and value["meta"].get("version") == "1":
        _graph(value, "kind", "rel")
        for node in value["nodes"]:
            if "data" in node:
                _object(node["data"], "node.data")
        return COMPILED
    raise InterchangeError("unsupported source envelope/version; migrations must be explicit")


def pack(value, origin, manifest=None, *, format=FORMAT):
    """Archive an already authorized source. Does not read locators or infer scope."""
    if format not in (FORMAT, PORTABLE_FORMAT):
        raise InterchangeError("unsupported exchange version")
    _shape(origin, ("id", "revision"))
    for key in origin:
        _text(origin[key], f"origin.{key}")
    if manifest is not None:
        _object(manifest, "manifest")
    body = {"format": format, "sourceFormat": source_format(value), "origin": deepcopy(origin),
            "manifest": deepcopy(manifest), "payload": deepcopy(value)}
    return {**body, "sha256": digest(body, format)}


def validate(package):
    _shape(package, ("format", "sourceFormat", "origin", "manifest", "payload", "sha256"))
    if package["format"] not in (FORMAT, PORTABLE_FORMAT):
        raise InterchangeError("unsupported exchange version")
    expected = pack(package["payload"], package["origin"], package["manifest"], format=package["format"])
    if canonical(package) != canonical(expected):
        raise InterchangeError("exchange digest or source format mismatch")
    return deepcopy(package)


def unpack(package):
    return validate(package)["payload"]


def inspect(package):
    package = validate(package)
    journal = package["sourceFormat"] == JOURNAL
    return {"format": package["format"], "sourceFormat": package["sourceFormat"], "origin": package["origin"],
            "sha256": package["sha256"], "fidelity": "exact-json-value",
            "history": "native-journal-retained-unverified" if journal else "not-present-in-source",
            "validation": "transport-only; destination native schema/replay and policy required",
            "authority": "none", "manifest": "retained-as-source-claim" if package["manifest"] is not None else "absent"}


def project(package, alias=ALIASES[0]):
    """Return a graph plus an unavoidable report of what that graph omits."""
    package = validate(package)
    if alias not in ALIASES:
        raise InterchangeError("unsupported output alias")
    value, kind = package["payload"], package["sourceFormat"]
    if kind == JOURNAL:
        raise InterchangeError("CLI journal projection requires its native replay adapter; archive/unpack preserves the bundle")
    losses = [{"path": "/origin", "reason": "exchange origin and revision require the archive"}]
    if package["manifest"] is not None:
        losses.append({"path": "/manifest", "reason": "scope/profile/capability metadata requires the archive"})
    if kind in ALIASES:
        graph = portable(value)
    else:
        graph = {"nodes": [], "edges": []}
        for node in value["nodes"]:
            # props is the complete compiled record minus id/kind; no reserved
            # user key is overwritten, and data remains a distinct nested object.
            name = node.get("title") or node.get("text") or node["id"]
            if not isinstance(name, str):
                raise InterchangeError("compiled title/text must be strings")
            graph["nodes"].append({"id": node["id"], "name": name, "type": node["kind"],
                                   "props": {k: deepcopy(v) for k, v in node.items() if k not in ("id", "kind")}})
        for edge in value["edges"]:
            graph["edges"].append({"source": edge["source"], "target": edge["target"], "type": edge["rel"],
                                   "props": {k: deepcopy(v) for k, v in edge.items() if k not in ("source", "target", "rel")}})
        for key in value:
            if key not in ("nodes", "edges"):
                losses.append({"path": "/payload/" + key.replace("~", "~0").replace("/", "~1"),
                               "reason": "compiled envelope metadata requires the archive"})
    graph["format"] = alias
    return {"graph": portable(graph), "report": {"projection": True, "history": "not-transferred",
            "authority": "none", "losses": losses, "sourceDigest": package["sha256"],
            "mapping": "compiled-record-props/v1" if kind == COMPILED else "portable-kg/v1"}}


def compiled_from_projection(graph, envelope, *, mapping):
    """Explicit inverse mapping with the separately retained compiled envelope.

    Arbitrary portable KGs cannot be guessed into a compiled ontology. This
    inverse requires our mapping label and native schema validation after it.
    """
    if mapping != "compiled-record-props/v1":
        raise InterchangeError("an explicit compiled-record-props/v1 mapping is required")
    graph = portable(graph)
    _object(envelope, "compiled envelope")
    if "nodes" in envelope or "edges" in envelope:
        raise InterchangeError("compiled envelope sidecar must not contain graph records")
    result = deepcopy(envelope)
    result.update(nodes=[], edges=[])
    for node in graph["nodes"]:
        if {"id", "kind"} & node["props"].keys():
            raise InterchangeError("compiled node property collides with identity/kind")
        record = {"id": node["id"], "kind": node["type"], **node["props"]}
        if node["name"] != (record.get("title") or record.get("text") or record["id"]):
            raise InterchangeError("display name changed outside the declared compiled mapping")
        result["nodes"].append(record)
    for edge in graph["edges"]:
        if {"source", "target", "rel"} & edge["props"].keys():
            raise InterchangeError("compiled edge property collides with endpoints/relation")
        result["edges"].append({"source": edge["source"], "target": edge["target"], "rel": edge["type"], **edge["props"]})
    if source_format(result) != COMPILED:
        raise InterchangeError("compiled envelope sidecar is missing its supported version")
    return deepcopy(result)


def exclusive_json(path, value):
    """New private artifact only. No overwriting documents or generated outputs."""
    data = (canonical(value) + "\n").encode("utf-8")
    if len(data) > MAX_BYTES:
        raise InterchangeError("output exceeds the 64 MiB exchange limit")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise


def write_sqlite(path, package):
    """Private immutable exchange: native archive plus queryable graph projection."""
    package = validate(package)
    if len(canonical(package).encode("utf-8")) + 1 > MAX_BYTES:
        raise InterchangeError("archive exceeds the 64 MiB exchange limit")
    projection = None if package["sourceFormat"] == JOURNAL else project(package)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    try:
        with sqlite3.connect(path) as db:
            db.executescript("""
                CREATE TABLE exchange (id INTEGER PRIMARY KEY CHECK(id=1), archive TEXT NOT NULL);
                CREATE TABLE nodes (ordinal INTEGER UNIQUE NOT NULL, id TEXT PRIMARY KEY,
                                    name TEXT NOT NULL, type TEXT NOT NULL, props TEXT NOT NULL);
                CREATE TABLE edges (ordinal INTEGER PRIMARY KEY, source TEXT NOT NULL,
                                    target TEXT NOT NULL, type TEXT NOT NULL, props TEXT NOT NULL);
                CREATE INDEX edge_source ON edges(source);
                CREATE INDEX edge_target ON edges(target);
                PRAGMA user_version=1;
            """)
            db.execute("INSERT INTO exchange VALUES (1,?)", (canonical(package),))
            if projection:
                graph = projection["graph"]
                db.executemany("INSERT INTO nodes VALUES (?,?,?,?,?)", [(i, n["id"], n["name"], n["type"], canonical(n["props"])) for i, n in enumerate(graph["nodes"])])
                db.executemany("INSERT INTO edges VALUES (?,?,?,?,?)", [(i, e["source"], e["target"], e["type"], canonical(e["props"])) for i, e in enumerate(graph["edges"])])
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise
    finally:
        if "db" in locals():
            db.close()


def read_sqlite(path):
    """Reject stale/tampered projection rows; never execute source schema code."""
    if Path(path).stat().st_size > MAX_BYTES * 3:
        raise InterchangeError("SQLite exchange exceeds its size limit")
    db = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    try:
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA query_only=ON")
        if db.execute("PRAGMA user_version").fetchone()[0] != 1:
            raise InterchangeError("unsupported exchange SQLite version")
        # Tables must be literal tables, not views that run attacker-selected SQL.
        rows = db.execute("SELECT name,type FROM sqlite_master WHERE name IN ('exchange','nodes','edges')").fetchall()
        if dict(rows) != {"exchange": "table", "nodes": "table", "edges": "table"}:
            raise InterchangeError("unexpected exchange table schema")
        archive = db.execute("SELECT archive FROM exchange ORDER BY id").fetchall()
        if len(archive) != 1:
            raise InterchangeError("expected exactly one exchange archive")
        package = validate(json.loads(archive[0][0]))
        nodes = [{"id": n[1], "name": n[2], "type": n[3], "props": json.loads(n[4])} for n in db.execute("SELECT ordinal,id,name,type,props FROM nodes ORDER BY ordinal")]
        edges = [{"source": e[1], "target": e[2], "type": e[3], "props": json.loads(e[4])} for e in db.execute("SELECT ordinal,source,target,type,props FROM edges ORDER BY ordinal")]
        expected = {"nodes": [], "edges": []} if package["sourceFormat"] == JOURNAL else project(package)["graph"]
        if canonical(nodes) != canonical(expected["nodes"]) or canonical(edges) != canonical(expected["edges"]):
            raise InterchangeError("SQLite projection differs from its archive")
        return package
    finally:
        db.close()
