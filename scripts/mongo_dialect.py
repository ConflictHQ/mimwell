"""The MongoDB authority dialect: the authority's named storage operations (sql_dialect.AuthorityRows), natively.

A `mongodb://` (or `mongodb+srv://`) DSN names one database. That database holds one
authority, or several when the DSN names each with `?authority=<name>`: the collections
of one are then `<name>.records`, `<name>.events` and so on, as a Postgres schema keeps
one authority among others in a database. A collection per authority table, the same
rows as documents. Bodies stay JSON
text, so digests, receipts and exports are byte-identical to the SQL drivers' and a snapshot
restores across them. Strings compare in byte order, SQLite's, so exports order rows alike.

Transactions need a replica set (a single-node one is enough). Every transaction reads one
snapshot. A writer takes the `writer` document first: a second writer conflicts on it, aborts
and retries until the first ends, so writers are serialized as the SQL drivers' locks
serialize them. A SQL lock ends with its connection; a MongoDB transaction does not, so a
writer that dies mid-transaction holds the `writer` document until the server aborts it at
`transactionLifetimeLimitSeconds` (60 by default), and the next writer waits that long. Collections and indexes are made outside the first transaction (create()),
and a failed create drops them again. A read-only session refuses every write itself.

Blobs (db-blob) are kept in `blob_chunks`, each blob split into chunks of at most 4 MiB
written in the same transaction, since a document caps at 16 MiB and db-blob promises a
blob that size. Savepoints are not implemented: MongoDB has no nested transaction. Tools that still issue
SQL against the authority (the brain-app host, intake completion and transfer) refuse a
mongo authority by name.

`pymongo` is an optional extra (`requirements-store-mongo.txt`), imported only when a
mongo store opens.
"""

from __future__ import annotations

import importlib
import json
import re
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sql_dialect import REVIEW_INDEX, StoreError, unsupported

# Authority collections; `writer` is the writer-exclusion document, never exported.
COLLECTIONS = ("metadata", "records", "edges", "events", "receipts", "proposals", "outbox", "deliveries", "blob_chunks",
               "writer")
# One blob chunk's bytes: well under the 16 MiB document cap with its key and index beside it.
BLOB_CHUNK = 4 * 1024 * 1024
# Each table's columns: the first is `_id` where a column is the document key.
# The DSN query parameter naming one authority among several in a database; never sent to the driver.
AUTHORITY_PARAMETER = "authority"
_AUTHORITY_NAME = re.compile(r"^[A-Za-z0-9_]{1,63}$")
KEYS = {"metadata": "key", "records": "id", "events": "sequence", "proposals": "id", "outbox": "sequence",
        "deliveries": "consumer"}


class _NoSQL:
    """`Authority.db` on a document store: the SQL-only tools refuse it by name."""

    in_transaction = False

    def execute(self, *_):
        raise unsupported("mongo", "SQL")

    executemany = execute


def _dotted(value, path):
    """`value` at a dotted JSON path, or None where any step is missing, as SQL's JSON paths read."""
    for step in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(step)
    return value


class MongoDialect:
    driver = "mongo"
    module_name = "pymongo"
    requirements = "requirements-store-mongo.txt"
    CAPABILITIES = frozenset({"authority", "transactions", "writer-exclusion", "read-only-session", "upsert",
                              "sequence", "db-blob"})
    SCHEMA_VERSION_KEY = "schema_version"
    # How long a writer waits for another's transaction to end: past MongoDB's default
    # transactionLifetimeLimitSeconds (60), which ends a dead writer's transaction too.
    WRITER_WAIT = 75.0

    def __init__(self, client, database, *, readonly=False, prefix=""):
        self.client, self.database, self.readonly, self.prefix = client, database, readonly, prefix
        self.session = client.start_session()
        self.db = _NoSQL()

    def collection(self, name):
        """One of this authority's collections, under its `?authority=` prefix when it has one."""
        return self.database[self.prefix + name]

    @classmethod
    def capabilities(cls):
        return cls.CAPABILITIES

    @classmethod
    def require(cls, capability):
        if capability not in cls.CAPABILITIES:
            raise unsupported(cls.driver, capability)

    @staticmethod
    def location(target):
        return str(target)

    @classmethod
    def module(cls):
        try:
            return importlib.import_module(cls.module_name)
        except ImportError:
            raise StoreError(f"the {cls.driver} driver is an optional extra: pip install -r {cls.requirements}") from None

    @classmethod
    def open(cls, target, *, readonly=False, authority=True):
        pymongo = cls.module()
        url = urlsplit(target)
        name = url.path.strip("/")
        if url.scheme not in ("mongodb", "mongodb+srv") or not name:
            raise StoreError("a mongo store dsn is mongodb://user:password@host:port/database")
        query = parse_qsl(url.query, keep_blank_values=True)
        authority = [value for key, value in query if key == AUTHORITY_PARAMETER]
        if len(authority) > 1 or authority and not _AUTHORITY_NAME.match(authority[0]):
            raise StoreError("a mongo store's ?authority= is one name of 1 to 63 letters, digits or underscores")
        driver_url = urlunsplit(url._replace(query=urlencode([(k, v) for k, v in query if k != AUTHORITY_PARAMETER])))
        client = pymongo.MongoClient(driver_url, tz_aware=False, uuidRepresentation="standard")
        return cls(client, client[name], readonly=readonly, prefix=f"{authority[0]}." if authority else "")

    @classmethod
    def exists(cls, target):
        dialect = cls.open(target)
        try:
            return dialect.prefix + "metadata" in dialect.database.list_collection_names()
        finally:
            dialect.close()

    @classmethod
    def authority_schema(cls):
        """No DDL: create() makes the collections and their indexes."""
        return ""

    @classmethod
    def create(cls, target, schema):
        """Make the authority's collections and indexes, then begin their writer transaction."""
        dialect = cls.open(target)
        dialect.created = []
        try:
            if dialect.prefix + "metadata" in dialect.database.list_collection_names():
                raise StoreError("an authority already exists at this mongo store; use an empty one")
            for name in COLLECTIONS:
                dialect.database.create_collection(dialect.prefix + name)
                dialect.created.append(name)
            database = dialect.collection
            database("records").create_index([("collection", 1), ("_id", 1)], name="records_collection")
            database("edges").create_index([("source", 1), ("target", 1), ("rel", 1)], name="edges_key", unique=True)
            database("edges").create_index([("target", 1), ("source", 1)], name="edges_target")
            database("events").create_index("digest", name="events_digest", unique=True)
            database("events").create_index([("record", 1), ("revision", 1)], name=REVIEW_INDEX)
            database("events").create_index([("record", 1), ("mutation", 1), ("_id", -1)], name="events_record_mutation")
            database("receipts").create_index([("actor", 1), ("request_id", 1)], name="receipts_key", unique=True)
            database("receipts").create_index("intent", name="receipts_intent")
            database("blob_chunks").create_index([("key", 1), ("n", 1)], name="blob_chunks_key", unique=True)
            database("writer").insert_one({"_id": "writer", "held": 0})
            dialect.begin(write=True)
        except BaseException:
            dialect.discard()
            raise
        return dialect

    def discard(self):
        """Drop what create() made: collection creation is not part of the transaction."""
        try:
            if self.in_transaction:
                self.rollback()
            for name in getattr(self, "created", ()):
                self.database.drop_collection(self.prefix + name)
        finally:
            self.close()

    def close(self):
        self.session.end_session()
        self.client.close()

    @property
    def in_transaction(self):
        return self.session.in_transaction

    def begin(self, *, write=False):
        pymongo = self.module()
        from pymongo.errors import OperationFailure
        from pymongo.read_concern import ReadConcern
        from pymongo.write_concern import WriteConcern

        options = dict(read_concern=ReadConcern("snapshot"), write_concern=WriteConcern("majority"),
                       read_preference=pymongo.ReadPreference.PRIMARY)
        if write:
            self._writable()
        deadline = time.monotonic() + self.WRITER_WAIT
        while True:
            self.session.start_transaction(**options)
            if not write:
                return
            try:
                self.collection("writer").update_one({"_id": "writer"}, {"$inc": {"held": 1}}, session=self.session)
                return
            except OperationFailure as error:
                self.session.abort_transaction()
                if not error.has_error_label("TransientTransactionError") or time.monotonic() > deadline:
                    raise StoreError("another writer holds this mongo authority") from error
                time.sleep(0.02)

    def commit(self):
        self.session.commit_transaction()

    def rollback(self):
        self.session.abort_transaction()

    def execute(self, *_):
        raise unsupported(self.driver, "SQL")

    rows = execute

    def savepoint(self, name):
        raise unsupported(self.driver, "savepoints")

    release = rollback_to = savepoint

    def _writable(self):
        if self.readonly:
            raise StoreError("this mongo authority session is read-only")

    def _find_one(self, collection, query, projection=None):
        return self.collection(collection).find_one(query, projection, session=self.session)

    def _find(self, collection, query, projection=None, sort=None):
        cursor = self.collection(collection).find(query, projection, session=self.session)
        return cursor.sort(sort) if sort else cursor

    def _last(self, collection, projection, query=None):
        """The document of `collection` matching `query` with the highest `_id`."""
        return next(iter(self._find(collection, query or {}, projection, [("_id", -1)]).limit(1)), None)

    def _insert(self, collection, document):
        self._writable()
        self.collection(collection).insert_one(document, session=self.session)

    def _set(self, collection, identity, fields):
        self._writable()
        self.collection(collection).update_one({"_id": identity}, {"$set": fields}, upsert=True, session=self.session)

    def next_sequence(self, table):
        """MAX+1 under the writer document, gapless as the SQL drivers' journals are."""
        last = self._last(table, {"_id": 1})
        return 1 if last is None else last["_id"] + 1

    def schema_version(self):
        value = self.meta(self.SCHEMA_VERSION_KEY)
        return None if value is None else int(value)

    def set_schema_version(self, version):
        self.set_meta(self.SCHEMA_VERSION_KEY, str(version))

    def has_index(self, name):
        return name in self.collection("events").index_information()

    # The named operations, as sql_dialect.AuthorityRows defines them.

    def meta(self, key):
        document = self._find_one("metadata", {"_id": key})
        return None if document is None else document["value"]

    def add_meta(self, key, value):
        self._insert("metadata", {"_id": key, "value": value})

    def set_meta(self, key, value):
        self._set("metadata", key, {"value": value})

    @staticmethod
    def _record(document, body=True):
        if document is None:
            return None
        row = {"id": document["_id"], "collection": document["collection"], "revision": document["revision"]}
        if body:
            row["body"] = document["body"]
        row["deleted"] = document["deleted"]
        return row

    def record(self, identity):
        return self._record(self._find_one("records", {"_id": identity}))

    def record_metadata(self, identity):
        return self._record(self._find_one("records", {"_id": identity}, {"body": 0}), body=False)

    def record_metadata_by_ids(self, identities):
        if not identities:
            return []
        return [self._record(document, body=False) for document in
                self._find("records", {"_id": {"$in": list(identities)}}, {"body": 0})]

    def live_body(self, identity):
        document = self._find_one("records", {"_id": identity, "deleted": 0}, {"body": 1})
        return None if document is None else document["body"]

    def live_bodies(self):
        return [document["body"] for document in self._find("records", {"deleted": 0}, {"body": 1}, [("_id", 1)])]

    def live_records(self, collections):
        return [{key: row[key] for key in ("id", "collection", "revision", "body")} for row in (
            self._record(document) for document in
            self._find("records", {"deleted": 0, "collection": {"$in": list(collections)}}, None, [("_id", 1)]))]

    def live_ids(self, collections):
        return {document["_id"] for document in
                self._find("records", {"deleted": 0, "collection": {"$in": list(collections)}}, {"_id": 1})}

    def live_volume(self, collections):
        result = list(self.collection("records").aggregate([
            {"$match": {"deleted": 0, "collection": {"$in": list(collections)}}},
            {"$group": {"_id": None, "count": {"$sum": 1}, "bytes": {"$sum": {"$strLenBytes": "$body"}}}},
        ], session=self.session))
        return (result[0]["count"], result[0]["bytes"]) if result else (0, 0)

    def live_volume_by_ids(self, identities):
        if not identities:
            return 0, 0
        result = list(self.collection("records").aggregate([
            {"$match": {"deleted": 0, "_id": {"$in": list(identities)}}},
            {"$group": {"_id": None, "count": {"$sum": 1}, "bytes": {"$sum": {"$strLenBytes": "$body"}}}},
        ], session=self.session))
        return (result[0]["count"], result[0]["bytes"]) if result else (0, 0)

    def live_records_by_ids(self, identities):
        if not identities:
            return []
        return [{key: row[key] for key in ("id", "collection", "revision", "body")} for row in (
            self._record(document) for document in
            self._find("records", {"deleted": 0, "_id": {"$in": list(identities)}}, None, [("_id", 1)]))]

    def live_rows(self):
        return [(document["_id"], document["revision"], document["body"]) for document in
                self._find("records", {"deleted": 0}, {"revision": 1, "body": 1}, [("_id", 1)])]

    def add_record(self, identity, collection, revision, body):
        self._insert("records", {"_id": identity, "collection": collection, "revision": revision, "body": body,
                                 "deleted": 0})

    def put_record(self, identity, collection, revision, body, deleted):
        self._set("records", identity, {"collection": collection, "revision": revision, "body": body,
                                        "deleted": deleted})

    def referencing_sources(self, identity):
        return sorted(self.collection("edges").distinct("source", {"target": identity, "source": {"$ne": identity}},
                                                   session=self.session))

    def edges(self):
        return [(document["source"], document["target"], document["rel"]) for document in
                self._find("edges", {}, {"source": 1, "target": 1, "rel": 1})]

    def replace_edges(self, source, edges):
        self._writable()
        self.collection("edges").delete_many({"source": source}, session=self.session)
        if edges:
            self.collection("edges").insert_many(
                [{"source": source, "target": target, "rel": rel, "body": body} for target, rel, body in edges],
                session=self.session)

    def journal_head(self):
        document = self._last("events", {"digest": 1, "at": 1})
        return None if document is None else {"sequence": document["_id"], "digest": document["digest"],
                                              "head_at": document.get("at")}

    def event_body(self, sequence):
        document = self._find_one("events", {"_id": sequence}, {"body": 1})
        return None if document is None else document["body"]

    def events(self):
        return [(document["_id"], document["body"]) for document in self._find("events", {}, {"body": 1}, [("_id", 1)])]

    def event_fields(self, paths):
        """The SQL drivers read these paths in the database; here each body is parsed once."""
        rows = []
        for document in self._find("events", {}, {"digest": 1, "body": 1}, [("_id", 1)]):
            body = json.loads(document["body"])
            rows.append((document["_id"], document["digest"], *(_dotted(body, path) for path in paths)))
        return rows

    def event_digests(self):
        return [(document["_id"], document["digest"]) for document in
                self._find("events", {}, {"digest": 1}, [("_id", 1)])]

    def append_event(self, sequence, previous, digest, body):
        """The journal paths the authority looks events up by are kept beside the body, indexed."""
        value = json.loads(body)
        request = value.get("request") or {}
        self._insert("events", {"_id": sequence, "previous": previous, "digest": digest, "body": body,
                                "record": request.get("record"), "mutation": request.get("mutation"),
                                "revision": value.get("revision"), "at": value.get("at")})

    def retention_event(self, record):
        document = self._last("events", {"body": 1}, {"record": record, "mutation": {"$in": ["create", "retain"]}})
        return None if document is None else document["body"]

    def revision_event(self, record, revision):
        document = self._find_one("events", {"record": record, "revision": revision}, {"body": 1})
        return None if document is None else document["body"]

    def receipt(self, actor, request_id):
        document = self._find_one("receipts", {"actor": actor, "request_id": request_id}, {"intent": 1, "body": 1})
        return None if document is None else {"intent": document["intent"], "body": document["body"]}

    def receipts_for(self, intent):
        return [document["body"] for document in self._find("receipts", {"intent": intent}, {"body": 1})]

    def add_receipt(self, actor, request_id, intent, body):
        self._insert("receipts", {"actor": actor, "request_id": request_id, "intent": intent, "body": body})

    def proposal(self, identity):
        document = self._find_one("proposals", {"_id": identity})
        return None if document is None else document["body"]

    def proposals(self):
        return [(document["_id"], document["body"]) for document in self._find("proposals", {}, None, [("_id", 1)])]

    def add_proposal(self, identity, body):
        self._insert("proposals", {"_id": identity, "body": body})

    def update_proposal(self, identity, body):
        self._writable()
        self.collection("proposals").update_one({"_id": identity}, {"$set": {"body": body}}, session=self.session)

    def outbox_head(self):
        document = self._last("outbox", {"_id": 1})
        return None if document is None else document["_id"]

    def add_outbox(self, sequence, body):
        self._insert("outbox", {"_id": sequence, "body": body})

    def delivery(self, consumer):
        document = self._find_one("deliveries", {"_id": consumer})
        return None if document is None else document["sequence"]

    def deliveries(self):
        return [(document["_id"], document["sequence"]) for document in self._find("deliveries", {})]

    def acknowledge(self, consumer, sequence):
        self._writable()
        self.collection("deliveries").update_one({"_id": consumer}, {"$max": {"sequence": sequence}}, upsert=True,
                                            session=self.session)

    def table_rows(self, table, columns, ordering):
        key = KEYS.get(table)
        sort = [("_id" if column == key else column, 1) for column in ordering]
        return [{column: document["_id"] if column == key else document.get(column) for column in columns}
                for document in self._find(table, {}, None, sort)]

    def insert_row(self, table, row):
        if table == "events":
            self.append_event(row["sequence"], row["previous"], row["digest"], row["body"])
            return
        key = KEYS.get(table)
        self._insert(table, {"_id" if column == key else column: value for column, value in row.items()})

    def blob(self, key):
        chunks = list(self._find("blob_chunks", {"key": key}, {"data": 1}, [("n", 1)]))
        return b"".join(bytes(chunk["data"]) for chunk in chunks) if chunks else None

    def add_blob(self, key, data):
        """One document per BLOB_CHUNK of `data`; an empty blob is one empty chunk, so it still exists."""
        self._writable()
        data = bytes(data)
        pieces = [data[start:start + BLOB_CHUNK] for start in range(0, len(data), BLOB_CHUNK)] or [b""]
        self.collection("blob_chunks").insert_many(
            [{"key": key, "n": n, "data": piece} for n, piece in enumerate(pieces)], session=self.session)
