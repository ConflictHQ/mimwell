"""Storage dialects behind the record authority and the compiled read store.

A dialect owns what differs between SQL engines: the connection, DDL, parameter
style, writer exclusion, savepoints, the read-only session, JSON path syntax,
upserts, sequence generation and where the schema version lives. Authority
rules, digests, policy, the outbox and receipts stay in knowledge_store.py and
never branch on a driver. `files` has no SQL dialect: it is served from a
complete snapshot (knowledge_store.FileReference).

`postgres` (psycopg 3) and `mysql` (PyMySQL) are optional extras, imported only
when a store of that driver opens: `requirements-store-postgres.txt` and
`requirements-store-mysql.txt`. `sqlite3` is imported the same way, when a SQLite
store opens, so modules that only need StoreError (blob_store.py, and through it
the access and corpus tools) run on a Python built without _sqlite3 (#362).
"""

from __future__ import annotations

import importlib
import os
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit


class StoreError(ValueError):
    pass


def unsupported(driver, capability):
    """The capability error every driver raises for an operation it lacks."""
    return StoreError(f"this adapter does not implement {capability} on {driver}")


def driver_errors():
    """Database error classes of the optional drivers already imported, for callers that report them."""
    return tuple(sys.modules[name].Error for name in ("psycopg", "pymysql") if name in sys.modules)


# The index serving the authority's record/revision lookups over `events`.
REVIEW_INDEX = "events_record_revision"

# Authority tables, dependants first.
AUTHORITY_TABLES = ("blob_objects", "outbox", "deliveries", "receipts", "proposals", "edges", "records", "events", "metadata")

_SQLITE_AUTHORITY_SCHEMA = """
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE records (id TEXT PRIMARY KEY, collection TEXT NOT NULL, revision TEXT NOT NULL, body TEXT, deleted INTEGER NOT NULL DEFAULT 0);
CREATE INDEX records_collection ON records(collection, id);
CREATE TABLE edges (source TEXT NOT NULL REFERENCES records(id), target TEXT NOT NULL, rel TEXT NOT NULL, body TEXT NOT NULL,
                    PRIMARY KEY(source, target, rel));
CREATE INDEX edges_target ON edges(target, source);
CREATE TABLE events (sequence INTEGER PRIMARY KEY, previous TEXT, digest TEXT NOT NULL UNIQUE, body TEXT NOT NULL);
CREATE TABLE receipts (actor TEXT NOT NULL, request_id TEXT NOT NULL, intent TEXT NOT NULL, body TEXT NOT NULL, PRIMARY KEY(actor, request_id));
CREATE TABLE proposals (id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE outbox (sequence INTEGER PRIMARY KEY REFERENCES events(sequence), body TEXT NOT NULL);
CREATE TABLE deliveries (consumer TEXT PRIMARY KEY, sequence INTEGER NOT NULL);
"""


class SQLiteDialect:
    """One SQLite connection shared by an authority and a compiled projection."""

    driver = "sqlite"
    CAPABILITIES = frozenset({
        "authority", "projection", "transactions", "writer-exclusion", "savepoints",
        "read-only-session", "json-path", "upsert", "sequence", "legacy-schema-version",
    })
    SCHEMA_VERSION_KEY = "schema_version"

    def __init__(self, connection):
        import sqlite3

        self.db = connection
        self.db.row_factory = sqlite3.Row

    @classmethod
    def capabilities(cls):
        return cls.CAPABILITIES

    @classmethod
    def require(cls, capability):
        if capability not in cls.CAPABILITIES:
            raise unsupported(cls.driver, capability)

    @staticmethod
    def location(target):
        return Path(target)

    @staticmethod
    def exists(target):
        return Path(target).is_file()

    @classmethod
    def authority_schema(cls):
        return _SQLITE_AUTHORITY_SCHEMA + cls.review_index() + ";"

    @classmethod
    def review_index(cls):
        return (f"CREATE INDEX IF NOT EXISTS {REVIEW_INDEX} ON events "
                f"({cls.json_path('body', 'request.record')},{cls.json_path('body', 'revision')})")

    @classmethod
    def open(cls, path, *, readonly=False, authority=True):
        """Open a session. The compiled read store opens without authority pragmas."""
        import sqlite3

        if not authority:
            return cls(sqlite3.connect(path, isolation_level=None))
        target = Path(path).resolve().as_uri() + "?mode=ro" if readonly else path
        dialect = cls(sqlite3.connect(target, uri=readonly, timeout=10, isolation_level=None))
        try:
            dialect.execute("PRAGMA foreign_keys=ON")
            if readonly:
                dialect.execute("PRAGMA query_only=ON")
            else:
                dialect.execute("PRAGMA journal_mode=WAL")
                dialect.execute("PRAGMA synchronous=FULL")
        except BaseException:
            dialect.close()
            raise
        return dialect

    @classmethod
    def create(cls, path, schema):
        """Create a new store file, never an existing one, and begin its writer transaction with `schema`."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        import sqlite3

        dialect = cls(sqlite3.connect(path, isolation_level=None))
        dialect.created = path
        dialect.begin(write=True)
        dialect.apply_schema(schema)
        return dialect

    def discard(self):
        """Close and remove a store create() made, after its transaction rolled back."""
        self.close()
        self.created.unlink()

    def apply_schema(self, schema):
        """Run DDL inside the caller's transaction; authority and projection DDL both go here.

        executescript() would commit the open transaction first, so statements run one by one.
        """
        import sqlite3

        statement = ""
        for line in schema.splitlines(keepends=True):
            statement += line
            if sqlite3.complete_statement(statement):
                self.db.execute(statement)
                statement = ""
        if statement.strip():
            raise StoreError("schema ends with an incomplete statement")

    def close(self):
        self.db.close()

    def execute(self, sql, parameters=()):
        return self.db.execute(sql, parameters)

    def rows(self, sql, parameters=()):
        return self.db.execute(sql, parameters).fetchall()

    @staticmethod
    def placeholders(count):
        return ",".join("?" for _ in range(count))

    @property
    def in_transaction(self):
        return self.db.in_transaction

    def begin(self, *, write=False):
        self.db.execute("BEGIN IMMEDIATE" if write else "BEGIN")

    def commit(self):
        self.db.execute("COMMIT")

    def rollback(self):
        self.db.execute("ROLLBACK")

    def savepoint(self, name):
        self.db.execute(f"SAVEPOINT {name}")

    def release(self, name):
        self.db.execute(f"RELEASE {name}")

    def rollback_to(self, name):
        self.db.execute(f"ROLLBACK TO {name}")

    @staticmethod
    def json_path(column, path):
        return f"json_extract({column},'$.{path}')"

    @staticmethod
    def byte_length(column):
        return f"length(CAST({column} AS BLOB))"

    @classmethod
    def upsert(cls, table, columns, key, *, monotonic=()):
        """INSERT that replaces non-key columns, never lowering `monotonic` ones."""
        updates = ",".join(
            f"{column}=MAX({column},excluded.{column})" if column in monotonic else f"{column}=excluded.{column}"
            for column in columns if column != key
        )
        return (f"INSERT INTO {table} ({','.join(columns)}) VALUES ({cls.placeholders(len(columns))}) "
                f"ON CONFLICT({key}) DO UPDATE SET {updates}")

    def next_sequence(self, table):
        return self.db.execute(f"SELECT COALESCE(MAX(sequence),0)+1 FROM {table}").fetchone()[0]

    def schema_version(self):
        row = self.db.execute("SELECT value FROM metadata WHERE key=?", (self.SCHEMA_VERSION_KEY,)).fetchone()
        return None if row is None else int(row[0])

    def set_schema_version(self, version):
        """The row is authoritative; PRAGMA user_version mirrors it for SQLite-native readers."""
        self.db.execute(self.upsert("metadata", ("key", "value"), "key"), (self.SCHEMA_VERSION_KEY, str(version)))
        self.db.execute(f"PRAGMA user_version={int(version)}")

    def has_index(self, name):
        return self.db.execute("SELECT 1 FROM sqlite_master WHERE type='index' AND name=?", (name,)).fetchone() is not None

    def legacy_schema_version(self):
        """Pre-seam SQLite authorities kept the version in PRAGMA user_version."""
        return self.db.execute("PRAGMA user_version").fetchone()[0]


class Row(tuple):
    """A result row readable by position and by column name, like sqlite3.Row."""

    def __new__(cls, names, values):
        row = super().__new__(cls, values)
        row.names = names
        return row

    def keys(self):
        return list(self.names)

    def __getitem__(self, key):
        return super().__getitem__(self.names.index(key) if isinstance(key, str) else key)


class _Cursor:
    def __init__(self, cursor):
        self.cursor = cursor
        self.names = tuple(column[0] for column in cursor.description or ())

    def fetchone(self):
        values = self.cursor.fetchone()
        return None if values is None else Row(self.names, values)

    def fetchall(self):
        return [Row(self.names, values) for values in self.cursor.fetchall()]

    def __iter__(self):
        return iter(self.fetchall())


class _Connection:
    """A DB-API connection behind the sqlite3-style calls the authority makes.

    Statements keep `?` parameters and rows read by index or name; `translate`
    rewrites each statement for its driver.
    """

    def __init__(self, raw, translate):
        self.raw, self.translate = raw, translate

    def execute(self, sql, parameters=()):
        cursor = self.raw.cursor()
        parameters = tuple(parameters)
        cursor.execute(self.translate(sql, bool(parameters)), parameters or None)
        return _Cursor(cursor)

    def executemany(self, sql, rows):
        for parameters in rows:
            self.execute(sql, parameters)

    def close(self):
        self.raw.close()


def _parameters(sql, parameterized):
    """`?` to the `%s` both server drivers use; a literal `%` is doubled only when parameters format."""
    return sql.replace("%", "%%").replace("?", "%s") if parameterized else sql


class _ServerDialect:
    """What the SQL server drivers share: a DSN target, `?` statements, SQL savepoints.

    Bodies stay text. The JSON paths the authority queries are generated columns
    on `events` (JSON_COLUMNS), so the review index serves those queries.
    """

    CAPABILITIES = frozenset({
        "authority", "transactions", "writer-exclusion", "savepoints", "read-only-session",
        "json-path", "upsert", "sequence",
    })
    SCHEMA_VERSION_KEY = "schema_version"
    JSON_COLUMNS = {
        ("body", "request.record"): "request_record",
        ("body", "revision"): "event_revision",
        ("body", "request.mutation"): "request_mutation",
    }

    def __init__(self, connection, *, readonly=False):
        self.db = connection
        self.readonly = readonly

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
        """The driver module, imported only when a store of this driver opens."""
        try:
            return importlib.import_module(cls.module_name)
        except ImportError:
            raise StoreError(f"the {cls.driver} driver is an optional extra: pip install -r {cls.requirements}") from None

    @classmethod
    def exists(cls, target):
        dialect = cls.open(target)
        try:
            return dialect.has_table("metadata")
        finally:
            dialect.close()

    def _refuse_existing(self):
        if self.has_table("metadata"):
            raise StoreError(f"an authority already exists at this {self.driver} store; use an empty one")

    @classmethod
    def review_index(cls):
        return (f"CREATE INDEX {REVIEW_INDEX} ON events "
                f"({cls.json_path('body', 'request.record')},{cls.json_path('body', 'revision')})")

    def apply_schema(self, schema):
        for statement in schema.split(";"):
            if statement.strip():
                self.execute(statement)

    def close(self):
        self.db.close()

    def execute(self, sql, parameters=()):
        return self.db.execute(sql, parameters)

    def rows(self, sql, parameters=()):
        return self.execute(sql, parameters).fetchall()

    @staticmethod
    def placeholders(count):
        return ",".join("?" for _ in range(count))

    def commit(self):
        self.execute("COMMIT")

    def rollback(self):
        self.execute("ROLLBACK")

    def savepoint(self, name):
        self.execute(f"SAVEPOINT {name}")

    def release(self, name):
        self.execute(f"RELEASE SAVEPOINT {name}")

    def rollback_to(self, name):
        self.execute(f"ROLLBACK TO SAVEPOINT {name}")

    @classmethod
    def json_path(cls, column, path):
        return cls.JSON_COLUMNS.get((column, path)) or cls.json_expression(column, path)

    def next_sequence(self, table):
        """MAX+1 under the writer lock: gapless, because a rolled-back commit must leave no hole
        in the journal, and a sequence's nextval is not rolled back."""
        return self.execute(f"SELECT COALESCE(MAX(sequence),0)+1 FROM {table}").fetchone()[0]

    def schema_version(self):
        row = self.execute("SELECT value FROM metadata WHERE key=?", (self.SCHEMA_VERSION_KEY,)).fetchone()
        return None if row is None else int(row[0])

    def set_schema_version(self, version):
        self.execute(self.upsert("metadata", ("key", "value"), "key"), (self.SCHEMA_VERSION_KEY, str(version)))


class PostgresDialect(_ServerDialect):
    """PostgreSQL through psycopg 3: a `postgresql://` DSN, one authority per schema.

    Writers hold `pg_advisory_xact_lock` on the schema's key; reads run REPEATABLE
    READ; a read-only session sets every transaction READ ONLY. Keyed text columns
    use COLLATE "C", SQLite's byte order, so exports order rows identically.
    `events.sequence` is a plain BIGINT, not an identity: next_sequence allocates it
    as MAX+1 under the writer lock, which stays gapless where an identity would not.
    """

    driver = "postgres"
    module_name = "psycopg"
    requirements = "requirements-store-postgres.txt"
    WRITER_LOCK = "SELECT pg_advisory_xact_lock(hashtextextended(current_schema() || '.knowledge-authority', 0))"

    @classmethod
    def open(cls, target, *, readonly=False, authority=True):
        psycopg = cls.module()
        dialect = cls(_Connection(psycopg.connect(target, autocommit=True), _parameters), readonly=readonly)
        if readonly:
            dialect.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
        return dialect

    @classmethod
    def create(cls, target, schema):
        """Create the authority tables in the writer transaction; DDL is transactional here."""
        dialect = cls.open(target)
        try:
            dialect.begin(write=True)
            dialect._refuse_existing()
            dialect.apply_schema(schema)
        except BaseException:
            if dialect.in_transaction:
                dialect.rollback()
            dialect.close()
            raise
        return dialect

    def discard(self):
        """The rollback already removed what create() made."""
        self.close()

    def has_table(self, name):
        return self.execute("SELECT to_regclass(?) IS NOT NULL", (name,)).fetchone()[0]

    def has_index(self, name):
        return self.has_table(name)

    @classmethod
    def authority_schema(cls):
        text = 'TEXT COLLATE "C"'
        return f"""
CREATE TABLE metadata (key {text} PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE records (id {text} PRIMARY KEY, collection {text} NOT NULL, revision TEXT NOT NULL, body TEXT,
                      deleted INTEGER NOT NULL DEFAULT 0);
CREATE INDEX records_collection ON records(collection, id);
CREATE TABLE edges (source {text} NOT NULL REFERENCES records(id), target {text} NOT NULL, rel {text} NOT NULL,
                    body TEXT NOT NULL, PRIMARY KEY(source, target, rel));
CREATE INDEX edges_target ON edges(target, source);
CREATE TABLE events (sequence BIGINT PRIMARY KEY, previous TEXT, digest TEXT NOT NULL UNIQUE,
                     body TEXT NOT NULL,
                     request_record {text} GENERATED ALWAYS AS ((body::jsonb) #>> '{{request,record}}') STORED,
                     event_revision {text} GENERATED ALWAYS AS ((body::jsonb) #>> '{{revision}}') STORED,
                     request_mutation {text} GENERATED ALWAYS AS ((body::jsonb) #>> '{{request,mutation}}') STORED);
CREATE TABLE receipts (actor {text} NOT NULL, request_id {text} NOT NULL, intent {text} NOT NULL, body TEXT NOT NULL,
                       PRIMARY KEY(actor, request_id));
CREATE TABLE proposals (id {text} PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE outbox (sequence BIGINT PRIMARY KEY REFERENCES events(sequence), body TEXT NOT NULL);
CREATE TABLE deliveries (consumer {text} PRIMARY KEY, sequence BIGINT NOT NULL);
{cls.review_index()};
"""

    @property
    def in_transaction(self):
        return self.db.raw.info.transaction_status != self.module().pq.TransactionStatus.IDLE

    def begin(self, *, write=False):
        self.execute("BEGIN ISOLATION LEVEL READ COMMITTED" if write else "BEGIN ISOLATION LEVEL REPEATABLE READ")
        if self.readonly:
            self.execute("SET TRANSACTION READ ONLY")
        if write:
            self.execute(self.WRITER_LOCK)

    @staticmethod
    def json_expression(column, path):
        return f"(({column})::jsonb #>> '{{{','.join(path.split('.'))}}}')"

    @staticmethod
    def byte_length(column):
        return f"octet_length({column})"

    @classmethod
    def upsert(cls, table, columns, key, *, monotonic=()):
        updates = ",".join(
            f"{column}=GREATEST({table}.{column},EXCLUDED.{column})" if column in monotonic
            else f"{column}=EXCLUDED.{column}"
            for column in columns if column != key
        )
        return (f"INSERT INTO {table} ({','.join(columns)}) VALUES ({cls.placeholders(len(columns))}) "
                f"ON CONFLICT({key}) DO UPDATE SET {updates}")


class MySQLDialect(_ServerDialect):
    """MySQL 8.4 / InnoDB through PyMySQL: a `mysql://user:password@host:port/database` DSN.

    Writers lock `metadata.status` with SELECT ... FOR UPDATE; reads use a
    consistent snapshot; a read-only session is SET SESSION TRANSACTION READ ONLY.
    Tables use utf8mb4_0900_bin (code-point order, no pad), SQLite's comparison
    and order. `key` is reserved in MySQL and is quoted on the way through. Keyed
    text columns are VARCHAR(255), so a longer identity is refused. DDL commits
    implicitly, so a failed create drops the tables it made.
    """

    driver = "mysql"
    module_name = "pymysql"
    requirements = "requirements-store-mysql.txt"
    WRITER_LOCK = "SELECT value FROM metadata WHERE key='status' FOR UPDATE"
    TABLE_OPTIONS = " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin"

    @staticmethod
    def translate(sql, parameterized):
        """Quote the `key` column outside string literals, so JSON paths and values keep theirs."""
        parts = re.split(r"('(?:[^']|'')*')", sql)
        parts[::2] = (re.sub(r"\bkey\b", "`key`", part) for part in parts[::2])
        return _parameters("".join(parts), parameterized)

    @classmethod
    def open(cls, target, *, readonly=False, authority=True):
        pymysql = cls.module()
        url = urlsplit(target)
        if url.scheme != "mysql" or not url.path.strip("/"):
            raise StoreError("a mysql store dsn is mysql://user:password@host:port/database")
        connection = pymysql.connect(
            host=url.hostname or "localhost", port=url.port or 3306, user=unquote(url.username or ""),
            password=unquote(url.password or ""), database=unquote(url.path.strip("/")), charset="utf8mb4",
            autocommit=True,
        )
        dialect = cls(_Connection(connection, cls.translate), readonly=readonly)
        if readonly:
            dialect.execute("SET SESSION TRANSACTION READ ONLY")
        return dialect

    @classmethod
    def create(cls, target, schema):
        """Create the authority tables, then begin their writer transaction; DDL commits as it runs."""
        dialect = cls.open(target)
        dialect.created = []
        try:
            dialect._refuse_existing()
            for statement in schema.split(";"):
                if statement.strip():
                    dialect.execute(statement)
                    table = re.match(r"\s*CREATE TABLE (\w+)", statement)
                    if table:
                        dialect.created.append(table[1])
            dialect.begin(write=True)
        except BaseException:
            dialect.discard()
            raise
        return dialect

    def discard(self):
        """Drop the tables create() made, dependants first: MySQL DDL is not transactional."""
        try:
            if self.in_transaction:
                self.rollback()
            for table in AUTHORITY_TABLES:
                if table in self.created:
                    self.execute(f"DROP TABLE {table}")
        finally:
            self.close()

    def has_table(self, name):
        return bool(self.execute("SELECT COUNT(*) FROM information_schema.tables "
                                 "WHERE table_schema=DATABASE() AND table_name=?", (name,)).fetchone()[0])

    def has_index(self, name):
        return bool(self.execute("SELECT COUNT(*) FROM information_schema.statistics "
                                 "WHERE table_schema=DATABASE() AND index_name=?", (name,)).fetchone()[0])

    @classmethod
    def authority_schema(cls):
        key, options = "VARCHAR(255)", cls.TABLE_OPTIONS
        return f"""
CREATE TABLE metadata (key {key} PRIMARY KEY, value LONGTEXT NOT NULL){options};
CREATE TABLE records (id {key} PRIMARY KEY, collection {key} NOT NULL, revision {key} NOT NULL, body LONGTEXT,
                      deleted INTEGER NOT NULL DEFAULT 0, INDEX records_collection (collection, id)){options};
CREATE TABLE edges (source {key} NOT NULL, target {key} NOT NULL, rel {key} NOT NULL, body LONGTEXT NOT NULL,
                    PRIMARY KEY(source, target, rel), INDEX edges_target (target, source),
                    FOREIGN KEY (source) REFERENCES records(id)){options};
CREATE TABLE events (sequence BIGINT PRIMARY KEY, previous {key}, digest {key} NOT NULL UNIQUE, body LONGTEXT NOT NULL,
                     request_record {key} GENERATED ALWAYS AS (body->>'$.request.record') STORED,
                     event_revision {key} GENERATED ALWAYS AS (body->>'$.revision') STORED,
                     request_mutation {key} GENERATED ALWAYS AS (body->>'$.request.mutation') STORED){options};
CREATE TABLE receipts (actor {key} NOT NULL, request_id {key} NOT NULL, intent {key} NOT NULL, body LONGTEXT NOT NULL,
                       PRIMARY KEY(actor, request_id)){options};
CREATE TABLE proposals (id {key} PRIMARY KEY, body LONGTEXT NOT NULL){options};
CREATE TABLE outbox (sequence BIGINT PRIMARY KEY, body LONGTEXT NOT NULL,
                     FOREIGN KEY (sequence) REFERENCES events(sequence)){options};
CREATE TABLE deliveries (consumer VARCHAR(768) PRIMARY KEY, sequence BIGINT NOT NULL){options};
{cls.review_index()};
"""

    @property
    def in_transaction(self):
        return bool(self.db.raw.server_status & self.module().constants.SERVER_STATUS.SERVER_STATUS_IN_TRANS)

    def begin(self, *, write=False):
        self.execute("START TRANSACTION" if write else "START TRANSACTION WITH CONSISTENT SNAPSHOT")
        if write:
            self.execute(self.WRITER_LOCK)

    @staticmethod
    def json_expression(column, path):
        return f"({column}->>'$.{path}')"

    @staticmethod
    def byte_length(column):
        return f"LENGTH({column})"

    @classmethod
    def upsert(cls, table, columns, key, *, monotonic=()):
        updates = ",".join(
            f"{column}=GREATEST({table}.{column},new.{column})" if column in monotonic else f"{column}=new.{column}"
            for column in columns if column != key
        )
        return (f"INSERT INTO {table} ({','.join(columns)}) VALUES ({cls.placeholders(len(columns))}) AS new "
                f"ON DUPLICATE KEY UPDATE {updates}")


class D1Dialect:
    """A Cloudflare D1 binding: a projection target only, never an authority."""

    driver = "d1"
    CAPABILITIES = frozenset({"projection"})

    def __init__(self, handle):
        self.handle = handle

    @classmethod
    def capabilities(cls):
        return cls.CAPABILITIES

    @classmethod
    def require(cls, capability):
        if capability not in cls.CAPABILITIES:
            raise unsupported(cls.driver, capability)

    @staticmethod
    def placeholders(count):
        return ",".join("?" for _ in range(count))

    def rows(self, sql, parameters=()):
        result = self.handle.prepare(sql).bind(*parameters).all()
        return (result.get("results") if isinstance(result, dict) else result) or []
