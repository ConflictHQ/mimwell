"""The contract role `vectors` (#258): where the vector index lives, as a derived projection of records.

The index is never an authority. `rebuild()` embeds the policy-filtered nodes one audience
may read (`context(actor)` of an authority or a file snapshot) with one embedder and
replaces that audience's index in the vectors store. Rebuilding from the same authority
with the same embedder yields the same `index_digest()`, in every driver: vectors are
rounded to float32 before they are stored, and the digest is taken over what the store
reads back.

Drivers are the `vectors` axis of the substrate matrix (docs/design/substrate-matrix.md):

- `local`: today's index, a JSON sidecar per audience in embed-brain.py's format,
  built with its deterministic char-ngram embedder by default. No extra.
- `in-db`: tables `vector_indexes` and `vector_entries` in the authority database.
  SQLite through sqlite-vec (`pip install -r requirements-store-sqlite-vec.txt`),
  PostgreSQL through pgvector (the `vector` extension; psycopg from
  requirements-store-postgres.txt), MySQL 9.0 or later through its VECTOR type (PyMySQL
  from requirements-store-mysql.txt). MySQL Community has no vector distance function,
  so a MySQL search ranks the stored vectors in the client.
- `edge-db`: Cloudflare Vectorize through its v2 REST API
  (`pip install -r requirements-store-vectorize.txt`), one index per audience.
- `external`: a Qdrant server (`pip install -r requirements-store-qdrant.txt`), one
  collection per audience.

Each extra is imported only when a store of that driver opens.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import struct
import time
from urllib.parse import urlsplit
import uuid

from sql_dialect import MySQLDialect, PostgresDialect, StoreError

# Legacy client.config.json `semantic.substrate` -> the `vectors` driver it maps onto.
LEGACY_DRIVERS = {None: "local", "local": "local", "edge-db": "edge-db", "external": "external"}
EXTRAS = {"sqlite": ("sqlite_vec", "requirements-store-sqlite-vec.txt"),
          "edge-db": ("requests", "requirements-store-vectorize.txt"),
          "external": ("qdrant_client", "requirements-store-qdrant.txt")}
MYSQL_MAX_DIM = 16383
_NAMESPACE = re.compile(r"^vectors_[0-9a-f]{24}$")


def legacy_driver(value):
    """The `vectors` driver a legacy `semantic.substrate` value maps onto."""
    if value not in LEGACY_DRIVERS:
        raise StoreError(f"semantic.substrate={value} has no vectors placement")
    return LEGACY_DRIVERS[value]


def placement(cell_vectors, declared, legacy):
    """The vectors driver: the contract's, which a set legacy `semantic.substrate` must agree with."""
    if legacy is None:
        return cell_vectors
    mapped = legacy_driver(legacy)
    if declared and mapped != cell_vectors:
        raise StoreError(f"semantic.substrate={legacy} maps to vectors={mapped}, "
                         f"but contract.json declares vectors={cell_vectors}")
    return cell_vectors if declared else mapped


def _extra(name):
    module, requirements = EXTRAS[name]
    try:
        return importlib.import_module(module)
    except ImportError as exc:
        raise StoreError(f"the {name} vectors driver needs `pip install -r {requirements}`") from exc


def _embed_brain():
    from brain_store import _embed_module
    module = _embed_module()
    if module is None:
        raise StoreError("scripts/embed-brain.py is missing; it defines the local index and embedder")
    return module


def default_embedder():
    """The deterministic local char-ngram embedder (decision on #220: hosted models are opt-in)."""
    return _embed_brain().LocalCharNgramEmbedder()


def f32(values):
    return list(struct.unpack(f"<{len(values)}f", struct.pack(f"<{len(values)}f", *values)))


def namespace(contract, audience):
    """One index per (contract binding, audience), as the AGE projection has one graph per audience."""
    return "vectors_" + hashlib.sha256(f"{contract}\0{audience}".encode()).hexdigest()[:24]


def _check_namespace(name):
    if not isinstance(name, str) or not _NAMESPACE.match(name):
        raise StoreError(f"not a vectors namespace: {name!r}")
    return name


def project(nodes, embedder):
    """The index of `nodes` (compiled graph nodes) under `embedder`, in embed-brain.py's format."""
    from brain_store import search_fingerprint, search_haystack
    nodes = sorted(nodes, key=lambda node: node["id"])
    vectors = embedder.embed([search_haystack(node) for node in nodes]) if nodes else []
    index = {"version": 2, "embedder": {"id": embedder.id, "dim": embedder.dim},
             "node_ids": [node["id"] for node in nodes],
             "node_text_sha256": [search_fingerprint(node) for node in nodes],
             "vectors": [f32(vector) for vector in vectors]}
    if not _embed_brain().valid_index(index):
        raise StoreError("the embedder returned an invalid vector collection")
    return index


def index_digest(index):
    """sha256 over the embedder and each (id, text hash, float32 little-endian vector), in id order."""
    entries = sorted(zip(index["node_ids"], index["node_text_sha256"], index["vectors"]))
    body = {"embedder": {"id": index["embedder"]["id"], "dim": index["embedder"]["dim"]},
            "entries": [[identity, text, struct.pack(f"<{len(vector)}f", *vector).hex()]
                        for identity, text, vector in entries]}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _index(embedder, dim, rows):
    rows = sorted(rows)
    return {"version": 2, "embedder": {"id": embedder, "dim": dim}, "node_ids": [row[0] for row in rows],
            "node_text_sha256": [row[1] for row in rows], "vectors": [f32(row[2]) for row in rows]}


def rebuild(source, actor, store, *, embedder=None, at=None):
    """Replace `actor`'s index in `store` from the authority (or file snapshot) `source`.

    Returns the namespace, the digest computed from the authority and the digest of what
    the store reads back; the two are equal when the store holds the projection intact.
    """
    graph = source.context(actor, at=at)
    name = namespace(source.contract.binding, actor)
    index = project(graph["nodes"], embedder or default_embedder())
    store.replace(name, index)
    stored = store.read(name)
    return {"namespace": name, "nodes": len(index["node_ids"]), "digest": index_digest(index),
            "stored": None if stored is None else index_digest(stored)}


def search(store, name, query, k, *, embedder=None):
    """The `k` nearest nodes to `query` text: [{id, score}], by score (to 4 places) then id.

    Drivers score in their own precision, so near ties are cut at 4 places and broken by
    identity; every driver then returns the same order.
    """
    if type(k) is not int or not 1 <= k <= 100:
        raise StoreError("search k must be an integer from 1 to 100")
    vector = f32((embedder or default_embedder()).embed([query])[0])
    hits = store.nearest(_check_namespace(name), vector, k + 8)
    hits = sorted(((-round(score, 4), identity) for identity, score in hits))[:k]
    return [{"id": identity, "score": -score} for score, identity in hits]


def _rank(index, vector, limit):
    """Client-side ranking by dot product, which is the cosine for the unit vectors an index holds."""
    if index is None:
        return []
    scored = [(identity, sum(a * b for a, b in zip(values, vector)))
              for identity, values in zip(index["node_ids"], index["vectors"])]
    return sorted(scored, key=lambda hit: (-hit[1], hit[0]))[:limit]


class LocalVectors:
    """`local`: one embed-brain.py index file per audience under a directory."""

    driver = "local"

    def __init__(self, root):
        self.root = Path(root)

    def _path(self, name):
        return self.root / f"{_check_namespace(name)}.vec.json"

    def replace(self, name, index):
        self.root.mkdir(parents=True, exist_ok=True)
        _embed_brain().write_index(index, str(self._path(name)))

    def read(self, name):
        path = self._path(name)
        return _embed_brain().load_index(str(path)) if path.is_file() else None

    def nearest(self, name, vector, limit):
        return _rank(self.read(name), vector, limit)

    def drop(self, name):
        self._path(name).unlink(missing_ok=True)

    def close(self):
        pass


class InDbVectors:
    """`in-db`: the index in the authority database, beside the records it projects."""

    driver = "in-db"

    def __init__(self, authority_driver, location):
        self.kind = authority_driver
        if authority_driver == "sqlite":
            import sqlite3
            sqlite_vec = _extra("sqlite")
            self.db = sqlite3.connect(location, isolation_level=None, timeout=10)
            try:
                self.db.enable_load_extension(True)
                sqlite_vec.load(self.db)
                self.db.enable_load_extension(False)
            except BaseException:
                self.db.close()
                raise
            self._ddl("TEXT", "TEXT", "BLOB", "")
        elif authority_driver == "postgres":
            psycopg = PostgresDialect.module()
            self.db = psycopg.connect(location, autocommit=True)
            self.db.execute("CREATE EXTENSION IF NOT EXISTS vector")
            schema = self.db.execute(
                "SELECT extnamespace::regnamespace::text FROM pg_extension WHERE extname='vector'").fetchone()[0]
            self.vector_type, self.distance = f"{schema}.vector", f"OPERATOR({schema}.<=>)"
            self._ddl('TEXT COLLATE "C"', 'TEXT COLLATE "C"', self.vector_type, "")
        elif authority_driver == "mysql":
            dialect = MySQLDialect.open(location)
            self.db = dialect.db.raw
            version = self._rows("SELECT VERSION()")[0][0]
            if int(version.split(".")[0]) < 9:
                self.db.close()
                raise StoreError(f"in-db vectors on mysql need MySQL 9.0 or later (the VECTOR type); this is {version}")
            self._ddl("VARCHAR(64)", "VARCHAR(255)", f"VECTOR({MYSQL_MAX_DIM})",
                      " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin")
        else:
            raise StoreError(f"in-db vectors need a database authority, not {authority_driver}")

    def _sql(self, sql):
        return sql if self.kind == "sqlite" else sql.replace("?", "%s")

    def _rows(self, sql, parameters=()):
        if self.kind == "mysql":
            with self.db.cursor() as cursor:
                cursor.execute(self._sql(sql), parameters or None)
                return cursor.fetchall()
        return self.db.execute(self._sql(sql), parameters).fetchall()

    def _run(self, sql, parameters=()):
        if self.kind == "mysql":
            with self.db.cursor() as cursor:
                cursor.execute(self._sql(sql), parameters or None)
        else:
            self.db.execute(self._sql(sql), parameters)

    def _ddl(self, name, key, vector, options):
        self._run(f"CREATE TABLE IF NOT EXISTS vector_indexes (namespace {name} PRIMARY KEY, "
                  f"embedder TEXT NOT NULL, dim INTEGER NOT NULL){options}")
        self._run(f"CREATE TABLE IF NOT EXISTS vector_entries (namespace {name} NOT NULL, node_id {key} NOT NULL, "
                  f"text_sha256 CHAR(64) NOT NULL, embedding {vector} NOT NULL, PRIMARY KEY (namespace, node_id)){options}")

    def _encode(self, vector):
        if self.kind == "sqlite":
            return struct.pack(f"<{len(vector)}f", *vector)
        return "[" + ",".join(repr(value) for value in vector) + "]"

    def _decode(self, value):
        if self.kind == "postgres":
            return [float(part) for part in value.strip("[]").split(",")] if value != "[]" else []
        value = bytes.fromhex(value) if self.kind == "mysql" else bytes(value)
        return list(struct.unpack(f"<{len(value) // 4}f", value))

    def _value(self):
        if self.kind == "postgres":
            return f"?::{self.vector_type}"
        return "STRING_TO_VECTOR(?)" if self.kind == "mysql" else "?"

    def _column(self):
        # VECTOR_TO_STRING keeps six significant digits, so MySQL returns the float32 bytes in hex.
        return {"sqlite": "embedding", "postgres": "embedding::text", "mysql": "HEX(embedding)"}[self.kind]

    def replace(self, name, index):
        _check_namespace(name)
        if self.kind == "mysql" and index["embedder"]["dim"] > MYSQL_MAX_DIM:
            raise StoreError(f"MySQL VECTOR holds at most {MYSQL_MAX_DIM} dimensions")
        self._run({"sqlite": "BEGIN IMMEDIATE", "postgres": "BEGIN", "mysql": "START TRANSACTION"}[self.kind])
        try:
            self._run("DELETE FROM vector_entries WHERE namespace=?", (name,))
            self._run("DELETE FROM vector_indexes WHERE namespace=?", (name,))
            self._run("INSERT INTO vector_indexes (namespace, embedder, dim) VALUES (?,?,?)",
                      (name, index["embedder"]["id"], index["embedder"]["dim"]))
            for identity, text, vector in zip(index["node_ids"], index["node_text_sha256"], index["vectors"]):
                self._run(f"INSERT INTO vector_entries (namespace, node_id, text_sha256, embedding) "
                          f"VALUES (?,?,?,{self._value()})", (name, identity, text, self._encode(f32(vector))))
            self._run("COMMIT")
        except BaseException:
            self._run("ROLLBACK")
            raise

    def read(self, name):
        meta = self._rows("SELECT embedder, dim FROM vector_indexes WHERE namespace=?", (_check_namespace(name),))
        if not meta:
            return None
        rows = self._rows(f"SELECT node_id, text_sha256, {self._column()} FROM vector_entries WHERE namespace=?", (name,))
        return _index(meta[0][0], int(meta[0][1]), [(row[0], row[1], self._decode(row[2])) for row in rows])

    def nearest(self, name, vector, limit):
        if self.kind == "mysql":
            return _rank(self.read(name), vector, limit)
        distance = ("vec_distance_cosine(embedding, ?)" if self.kind == "sqlite"
                    else f"(embedding {self.distance} {self._value()})")
        rows = self._rows(f"SELECT node_id, 1 - {distance} AS score FROM vector_entries WHERE namespace=? "
                          "ORDER BY score DESC, node_id LIMIT ?", (self._encode(vector), name, limit))
        return [(row[0], float(row[1])) for row in rows]

    def drop(self, name):
        self._run("DELETE FROM vector_entries WHERE namespace=?", (_check_namespace(name),))
        self._run("DELETE FROM vector_indexes WHERE namespace=?", (name,))

    def close(self):
        self.db.close()


def _point(name, identity):
    """A stable 64-character vector id (Vectorize's limit) or UUID (Qdrant's) for a node."""
    return hashlib.sha256(f"{name}\0{identity}".encode()).hexdigest()


class EdgeDbVectors:
    """`edge-db`: Cloudflare Vectorize (v2 REST API), one dot-product index per audience.

    `vectorize://<account id>/<index prefix>`; the token comes from `CLOUDFLARE_API_TOKEN`.
    Vectorize applies mutations asynchronously, and its listing and vector reads trail the index
    info; `replace` returns once the info reports its last mutation processed and STABLE_READS
    reads in a row hold the new index's digest, so a read straight after it holds the new index.
    """

    driver = "edge-db"
    API = "https://api.cloudflare.com/client/v4"
    SETTLE_SECONDS, POLL_SECONDS, STABLE_READS = 300, 2, 8

    def __init__(self, account, prefix, *, session=None, base=None):
        token = os.environ.get("CLOUDFLARE_API_TOKEN")
        if session is None:
            if not token:
                raise StoreError("the edge-db vectors driver needs CLOUDFLARE_API_TOKEN")
            session = _extra("edge-db").Session()
            session.headers["Authorization"] = f"Bearer {token}"
        self.session, self.prefix = session, prefix
        self.base = f"{base or os.environ.get('CLOUDFLARE_API_BASE_URL') or self.API}/accounts/{account}/vectorize/v2/indexes"

    def _call(self, method, path, **options):
        response = self.session.request(method, self.base + path, **options)
        body = response.json() if response.content else {}
        if response.status_code == 404:
            return None
        if response.status_code >= 400 or not body.get("success", False):
            raise StoreError(f"Vectorize {method} {path or '/'} failed: {response.status_code} {body.get('errors')}")
        return body.get("result")

    def _name(self, name):
        return f"{self.prefix}-{_check_namespace(name)}".replace("_", "-")

    def _ids(self, index):
        ids, cursor = [], None
        while True:
            page = self._call("GET", f"/{index}/list", params={"count": 1000, **({"cursor": cursor} if cursor else {})})
            ids += [vector["id"] for vector in page.get("vectors", [])]
            cursor = page.get("nextCursor")
            if not page.get("isTruncated") or not cursor:
                return ids

    def replace(self, name, index):
        target, dim = self._name(name), index["embedder"]["dim"]
        info = self._call("GET", f"/{target}")
        if info is not None and info["config"]["dimensions"] != dim:
            self._call("DELETE", f"/{target}")
            info = None
        if info is None:
            self._call("POST", "", json={"name": target, "config": {"dimensions": dim, "metric": "dot-product"}})
        keep = {_point(name, identity) for identity in index["node_ids"]}
        stale = [identity for identity in self._ids(target) if identity not in keep]
        mutation = None
        for start in range(0, len(stale), 1000):
            mutation = self._call("POST", f"/{target}/delete_by_ids", json={"ids": stale[start:start + 1000]})["mutationId"]
        lines = [json.dumps({"id": _point(name, identity), "values": f32(vector),
                             "metadata": {"node": identity, "text_sha256": text, "embedder": index["embedder"]["id"]}})
                 for identity, text, vector in zip(index["node_ids"], index["node_text_sha256"], index["vectors"])]
        for start in range(0, len(lines), 1000):
            mutation = self._call("POST", f"/{target}/upsert", data="\n".join(lines[start:start + 1000]).encode(),
                                  headers={"Content-Type": "application/x-ndjson"})["mutationId"]
        if mutation is not None:
            self._settle(name, mutation, index_digest(index))

    def _settle(self, name, mutation, digest):
        """Wait until Vectorize has processed `mutation`, the last of a replace (mutations apply in
        order), and STABLE_READS reads in a row hold `digest`: straight after one read holds it, the
        next can still miss the rebuilt vectors."""
        target, deadline, held = self._name(name), time.monotonic() + self.SETTLE_SECONDS, 0
        while True:
            held = held + 1 if ((self._call("GET", f"/{target}/info") or {}).get("processedUpToMutation") == mutation
                                and index_digest(self.read(name)) == digest) else 0
            if held >= self.STABLE_READS:
                return
            if time.monotonic() >= deadline:
                raise StoreError(f"Vectorize index {target} did not process mutation {mutation} "
                                 f"and read back the rebuilt index within {self.SETTLE_SECONDS}s")
            time.sleep(self.POLL_SECONDS)

    def read(self, name):
        target = self._name(name)
        info = self._call("GET", f"/{target}")
        if info is None:
            return None
        ids, rows, embedders = self._ids(target), [], set()
        for start in range(0, len(ids), 20):
            for vector in self._call("POST", f"/{target}/get_by_ids", json={"ids": ids[start:start + 20]}):
                meta = vector.get("metadata") or {}
                embedders.add(meta.get("embedder"))
                rows.append((meta.get("node"), meta.get("text_sha256"), vector["values"]))
        if len(embedders) > 1:
            raise StoreError(f"Vectorize index {target} mixes embedders")
        return _index(next(iter(embedders), None), info["config"]["dimensions"], rows)

    def nearest(self, name, vector, limit):
        result = self._call("POST", f"/{self._name(name)}/query",
                            json={"vector": vector, "topK": min(limit, 100), "returnMetadata": "all"})
        return [((match.get("metadata") or {}).get("node"), float(match["score"])) for match in (result or {}).get("matches", [])]

    def drop(self, name):
        self._call("DELETE", f"/{self._name(name)}")

    def close(self):
        self.session.close()


class ExternalVectors:
    """`external`: a Qdrant server, one dot-product collection per audience.

    `qdrant://host:port` (http) or `qdrants://host:port` (https); an API key comes from `QDRANT_API_KEY`.
    """

    driver = "external"

    def __init__(self, url, *, client=None):
        self.models = _extra("external").models
        if client is None:
            client = _extra("external").QdrantClient(url=url, api_key=os.environ.get("QDRANT_API_KEY") or None)
        self.client = client

    def replace(self, name, index):
        _check_namespace(name)
        if self.client.collection_exists(name):
            self.client.delete_collection(name)
        self.client.create_collection(name, vectors_config=self.models.VectorParams(
            size=index["embedder"]["dim"], distance=self.models.Distance.DOT))
        points = [self.models.PointStruct(id=str(uuid.UUID(_point(name, identity)[:32])), vector=f32(vector),
                                          payload={"node": identity, "text_sha256": text,
                                                   "embedder": index["embedder"]["id"]})
                  for identity, text, vector in zip(index["node_ids"], index["node_text_sha256"], index["vectors"])]
        for start in range(0, len(points), 256):
            self.client.upsert(name, points=points[start:start + 256], wait=True)

    def read(self, name):
        if not self.client.collection_exists(_check_namespace(name)):
            return None
        dim = self.client.get_collection(name).config.params.vectors.size
        rows, embedders, offset = [], set(), None
        while True:
            points, offset = self.client.scroll(name, limit=256, offset=offset, with_payload=True, with_vectors=True)
            for point in points:
                embedders.add(point.payload.get("embedder"))
                rows.append((point.payload.get("node"), point.payload.get("text_sha256"), point.vector))
            if offset is None:
                break
        if len(embedders) > 1:
            raise StoreError(f"Qdrant collection {name} mixes embedders")
        return _index(next(iter(embedders), None), dim, rows)

    def nearest(self, name, vector, limit):
        if not self.client.collection_exists(_check_namespace(name)):
            return []
        hits = self.client.query_points(name, query=vector, limit=limit, with_payload=True).points
        return [(hit.payload.get("node"), float(hit.score)) for hit in hits]

    def drop(self, name):
        self.client.delete_collection(_check_namespace(name))

    def close(self):
        self.client.close()


def open_vector_store(driver, location, *, authority_driver=None):
    """A vectors store from its resolved location: a directory (`local`), the authority's own
    path or DSN (`in-db`), `vectorize://<account>/<index prefix>` (`edge-db`) or
    `qdrant://host:port` / `qdrants://host:port` (`external`)."""
    if driver == "local":
        return LocalVectors(location)
    if driver == "in-db":
        return InDbVectors(authority_driver, location)
    if driver == "edge-db":
        parts = urlsplit(location)
        prefix = parts.path.strip("/")
        if parts.scheme != "vectorize" or not parts.netloc or not re.match(r"^[a-z][a-z0-9-]{0,22}$", prefix):
            raise StoreError("an edge-db vectors location is vectorize://<account id>/<index prefix>")
        return EdgeDbVectors(parts.netloc, prefix)
    if driver == "external":
        parts = urlsplit(location)
        if parts.scheme not in ("qdrant", "qdrants") or not parts.netloc:
            raise StoreError("an external vectors location is qdrant://host:port or qdrants://host:port")
        return ExternalVectors(("https" if parts.scheme == "qdrants" else "http") + "://" + parts.netloc)
    raise StoreError(f"{driver} is not a vectors placement")
