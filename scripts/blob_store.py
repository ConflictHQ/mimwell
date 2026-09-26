"""Blob stores: evidence and originals behind the contract's `blobs` role (#226).

A record carries a locator `{store, key, sha256, bytes, mediaType}` for each blob
in its `blobs` list. The blob store holds the bytes and nothing else: it owns no
record field and is never an authority for a claim. Every read verifies the bytes
against the locator digest.

Drivers are the `blobs` column of the substrate matrix (docs/design/substrate-matrix.md):

- `fs`: a filesystem path (the working tree, a block volume or EFS).
- `db-blob`: a `blob_objects` table in the authority database, bounded in size.
- `s3`: S3, R2, GCS interop, MinIO or Garage through `boto3`
  (`pip install -r requirements-store-s3.txt`).
- `azure-blob`: Azure Blob Storage through `azure-storage-blob`
  (`pip install -r requirements-store-azure-blob.txt`).

The SDKs are imported only when a store of that driver opens.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
from urllib.parse import urlsplit

from sql_dialect import StoreError

LOCATOR_KEYS = ("store", "key", "sha256", "bytes", "mediaType")
DB_BLOB_MAX_BYTES = 16 * 1024 * 1024
# Legacy client.config.json `brain.blobs` -> the `blobs` driver it maps onto.
LEGACY_DRIVERS = {None: "fs", "git": "fs", "lfs": "fs", "efs": "fs", "s3": "s3", "external": "fs"}
EXTRAS = {"s3": ("boto3", "requirements-store-s3.txt"),
          "azure-blob": ("azure.storage.blob", "requirements-store-azure-blob.txt")}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MEDIA_TYPE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$", re.I)


def check_key(key):
    """A relative POSIX key with no empty, `.` or `..` segment."""
    if (not isinstance(key, str) or not key or len(key) > 1024 or "\\" in key or "\x00" in key
            or key.startswith("/") or any(part in ("", ".", "..") for part in key.split("/"))):
        raise StoreError(f"blob key must be a relative path without empty, . or .. segments: {key!r}")
    return key


def check_locator(locator):
    if not isinstance(locator, dict) or set(locator) != set(LOCATOR_KEYS):
        raise StoreError(f"blob locator must have exactly {', '.join(LOCATOR_KEYS)}")
    check_key(locator["key"])
    if (not isinstance(locator["store"], str) or not locator["store"]
            or not isinstance(locator["sha256"], str) or not _SHA256.match(locator["sha256"])
            or type(locator["bytes"]) is not int or locator["bytes"] < 0
            or not isinstance(locator["mediaType"], str) or not _MEDIA_TYPE.match(locator["mediaType"])):
        raise StoreError(f"blob locator is malformed: {locator['key']}")
    return locator


def record_locators(record):
    """The locators a record carries in `blobs`."""
    blobs = record.get("blobs", [])
    if not isinstance(blobs, list):
        raise StoreError("record blobs must be a list of blob locators")
    return [check_locator(locator) for locator in blobs]


def locator(store, key, data, media_type):
    return check_locator({"store": store, "key": key, "sha256": hashlib.sha256(data).hexdigest(),
                          "bytes": len(data), "mediaType": media_type})


def verify(locator, data):
    if data is None:
        raise StoreError(f"blob is missing from store {locator['store']}: {locator['key']}")
    if len(data) != locator["bytes"] or hashlib.sha256(data).hexdigest() != locator["sha256"]:
        raise StoreError(f"blob digest does not match its locator: {locator['key']}")
    return data


def encode(data):
    return base64.b64encode(data).decode("ascii")


def decode(text):
    try:
        return base64.b64decode(text, validate=True)
    except (TypeError, ValueError) as exc:
        raise StoreError("included blob content is not base64") from exc


def legacy_driver(value):
    """The `blobs` driver a legacy `brain.blobs` value maps onto."""
    if value not in LEGACY_DRIVERS:
        raise StoreError(f"brain.blobs={value} has no blobs placement")
    return LEGACY_DRIVERS[value]


def placement(cell_blobs, declared, legacy):
    """The blobs driver: the contract's, which a set legacy `brain.blobs` must agree with."""
    if legacy is None:
        return cell_blobs
    mapped = legacy_driver(legacy)
    if declared and mapped != cell_blobs:
        raise StoreError(f"brain.blobs={legacy} maps to blobs={mapped}, but contract.json declares blobs={cell_blobs}")
    return cell_blobs if declared else mapped


def _sdk(driver):
    module, requirements = EXTRAS[driver]
    try:
        return importlib.import_module(module)
    except ImportError as exc:
        raise StoreError(f"the {driver} blob driver needs `pip install -r {requirements}`") from exc


class BlobStore:
    """Write-once keys; `get` returns bytes only after they match the locator."""

    driver = None

    def __init__(self, store_id):
        self.store_id = store_id

    def put(self, key, data, media_type):
        value = locator(self.store_id, check_key(key), bytes(data), media_type)
        existing = self._read(key)
        if existing is None:
            self._write(key, bytes(data), media_type)
        elif existing != bytes(data):
            raise StoreError(f"blob key already holds different content: {key}")
        return value

    def get(self, locator):
        check_locator(locator)
        if locator["store"] != self.store_id:
            raise StoreError(f"locator names store {locator['store']}, not {self.store_id}")
        return verify(locator, self._read(locator["key"]))

    def _read(self, key):
        raise NotImplementedError

    def _write(self, key, data, media_type):
        raise NotImplementedError


class FsBlobStore(BlobStore):
    driver = "fs"

    def __init__(self, store_id, root):
        super().__init__(store_id)
        self.root = Path(root)

    def _path(self, key):
        return self.root.joinpath(*PurePosixPath(key).parts)

    def _read(self, key):
        path = self._path(key)
        return path.read_bytes() if path.is_file() else None

    def _write(self, key, data, media_type):
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".blob-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


class DbBlobStore(BlobStore):
    """Blobs in the authority database: SQLite BLOB, PostgreSQL bytea, MySQL LONGBLOB."""

    driver = "db-blob"
    # Keys compare in byte order on every engine, as the authority's own keyed columns do.
    TYPES = {"sqlite": ("TEXT", "BLOB", ""), "postgres": ('TEXT COLLATE "C"', "BYTEA", ""),
             "mysql": ("VARCHAR(255)", "LONGBLOB", " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin")}

    def __init__(self, store_id, dialect, *, max_bytes=DB_BLOB_MAX_BYTES):
        super().__init__(store_id)
        self.dialect, self.max_bytes = dialect, max_bytes

    @classmethod
    def ddl(cls, driver):
        if driver not in cls.TYPES:
            raise StoreError(f"db-blob needs a database authority, not {driver}")
        key, content, options = cls.TYPES[driver]
        return f"CREATE TABLE blob_objects (blob_key {key} PRIMARY KEY, content {content} NOT NULL){options}"

    def put(self, key, data, media_type):
        if len(data) > self.max_bytes:
            raise StoreError(f"db-blob holds at most {self.max_bytes} bytes per blob; {key} is {len(data)}")
        return super().put(key, data, media_type)

    def _read(self, key):
        row = self.dialect.execute("SELECT content FROM blob_objects WHERE blob_key=?", (key,)).fetchone()
        return None if row is None else bytes(row[0])

    def _write(self, key, data, media_type):
        self.dialect.execute("INSERT INTO blob_objects (blob_key, content) VALUES (?,?)", (key, data))


class S3BlobStore(BlobStore):
    """`s3://bucket/prefix`; the endpoint (R2, GCS interop, MinIO, Garage) and credentials come
    from the standard AWS environment (`AWS_ENDPOINT_URL`, `AWS_ACCESS_KEY_ID`, ...)."""

    driver = "s3"

    def __init__(self, store_id, bucket, prefix="", *, client=None):
        super().__init__(store_id)
        self.bucket, self.prefix = bucket, prefix
        self.client = client if client is not None else _sdk("s3").client("s3")

    def _read(self, key):
        try:
            return self.client.get_object(Bucket=self.bucket, Key=self.prefix + key)["Body"].read()
        except self.client.exceptions.NoSuchKey:
            return None

    def _write(self, key, data, media_type):
        self.client.put_object(Bucket=self.bucket, Key=self.prefix + key, Body=data, ContentType=media_type)


class AzureBlobStore(BlobStore):
    """`azure-blob://container/prefix`; the connection string comes from
    `AZURE_STORAGE_CONNECTION_STRING`."""

    driver = "azure-blob"

    def __init__(self, store_id, container, prefix="", *, client=None):
        super().__init__(store_id)
        self.prefix = prefix
        if client is None:
            connection = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
            if not connection:
                raise StoreError("the azure-blob driver needs AZURE_STORAGE_CONNECTION_STRING")
            client = _sdk("azure-blob").ContainerClient.from_connection_string(connection, container)
        self.client = client

    def _read(self, key):
        blob = self.client.get_blob_client(self.prefix + key)
        return blob.download_blob().readall() if blob.exists() else None

    def _write(self, key, data, media_type):
        self.client.get_blob_client(self.prefix + key).upload_blob(data, overwrite=False)


def open_blob_store(driver, store_id, location):
    """A blob store from its resolved location: a path (`fs`), `s3://bucket/prefix` or
    `azure-blob://container/prefix`. db-blob opens as DbBlobStore on the authority's dialect."""
    if driver == "fs":
        return FsBlobStore(store_id, location)
    if driver in ("s3", "azure-blob"):
        parts = urlsplit(location)
        if parts.scheme != driver or not parts.netloc:
            raise StoreError(f"a {driver} store location is {driver}://<bucket or container>/<prefix>")
        prefix = parts.path.lstrip("/")
        prefix = prefix + "/" if prefix and not prefix.endswith("/") else prefix
        cls = S3BlobStore if driver == "s3" else AzureBlobStore
        return cls(store_id, parts.netloc, prefix)
    raise StoreError(f"{driver} is not a blobs placement")
