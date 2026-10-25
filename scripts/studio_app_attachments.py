"""Strict bounds and locator binding for optional Studio App data attachments.

This validates metadata against the record's native blob locators. It does not
fetch, execute, decrypt, install or authorize a blob; those remain host duties.
"""

import hashlib
import zlib

from blob_store import check_locator
from sql_dialect import StoreError

MAX_ATTACHMENTS = 8
MAX_ATTACHMENT_BYTES = 16 * 1024 * 1024
MAX_APP_ATTACHMENT_BYTES = 16 * 1024 * 1024
MAX_EXPANDED_SNAPSHOT_BYTES = 64 * 1024 * 1024
PGLITE_METADATA_FIELDS = ("postgresMajor", "pgliteVersion", "compression", "expandedBytes", "expandedSha256")
MAX_PGLITE_VERSION_LENGTH = 128


def validate_pglite_snapshot_metadata(value):
    """Validate bounded snapshot declarations without interpreting database bytes."""
    version = value.get("pgliteVersion") if isinstance(value, dict) else None
    expanded = value.get("expandedBytes") if isinstance(value, dict) else None
    digest = value.get("expandedSha256") if isinstance(value, dict) else None
    if type(expanded) is not int or not 1 <= expanded <= MAX_EXPANDED_SNAPSHOT_BYTES:
        raise StoreError("PGlite snapshot expanded bytes are invalid or exceed their limit")
    if (not isinstance(value, dict)
            or type(value.get("postgresMajor")) is not int
            or not 1 <= value["postgresMajor"] <= 1000
            or not isinstance(version, str) or not version.strip()
            or len(version) > MAX_PGLITE_VERSION_LENGTH
            or any(ord(char) < 0x20 or ord(char) == 0x7f for char in version)
            or value.get("compression") != "gzip"
            or not isinstance(digest, str) or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)):
        raise StoreError("PGlite snapshot metadata is invalid or exceeds its limit")
    return {key: value[key] for key in PGLITE_METADATA_FIELDS}


def verify_pglite_snapshot_bytes(metadata, compressed):
    """Verify one compressed snapshot's declared bounds and expanded digest."""
    checked = validate_pglite_snapshot_metadata(metadata)
    if not isinstance(compressed, bytes) or len(compressed) > MAX_ATTACHMENT_BYTES:
        raise StoreError("PGlite snapshot compressed bytes exceed their limit")
    expected_bytes = checked["expandedBytes"]
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    total = 0
    digest = hashlib.sha256()

    def account(part):
        nonlocal total
        total += len(part)
        if total > expected_bytes or total > MAX_EXPANDED_SNAPSHOT_BYTES:
            raise StoreError("PGlite snapshot exceeds its declared expanded byte limit")
        digest.update(part)

    try:
        for offset in range(0, len(compressed), 64 * 1024):
            pending = compressed[offset:offset + 64 * 1024]
            while pending:
                piece = decoder.decompress(pending, expected_bytes - total + 1)
                account(piece)
                pending = decoder.unconsumed_tail
                if pending and total >= expected_bytes:
                    raise StoreError("PGlite snapshot exceeds its declared expanded byte limit")
        account(decoder.flush(expected_bytes - total + 1))
    except zlib.error as exc:
        raise StoreError("PGlite snapshot compression is invalid") from exc
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise StoreError("PGlite snapshot compressed stream is incomplete or has trailing bytes")
    if total != expected_bytes or digest.hexdigest() != checked["expandedSha256"]:
        raise StoreError("PGlite snapshot expanded bytes differ from their pinned size or digest")
    return checked


def validate_app_attachments(record):
    data = record.get("content", {}).get("data", {})
    attachments = data.get("attachments", [])
    if not isinstance(attachments, list) or len(attachments) > MAX_ATTACHMENTS:
        raise StoreError("Studio App attachments exceed the count limit")
    locators = record.get("blobs", [])
    if not isinstance(locators, list) or len(locators) > MAX_ATTACHMENTS:
        raise StoreError("Studio App blob locators exceed the count limit")
    checked = {}
    locator_total = 0
    for value in locators:
        locator = check_locator(value)
        if locator["key"] != "sha256/" + locator["sha256"]:
            raise StoreError("Studio App attachment blob keys must be content addressed")
        if locator["bytes"] > MAX_ATTACHMENT_BYTES:
            raise StoreError("Studio App attachment exceeds the per-blob byte limit")
        if locator["key"] in checked:
            raise StoreError("Studio App blob locators must be unique")
        locator_total += locator["bytes"]
        if locator_total > MAX_APP_ATTACHMENT_BYTES:
            raise StoreError("Studio App attachments exceed the total byte limit")
        checked[locator["key"]] = locator

    total = 0
    expanded_total = 0
    roles = set()
    for attachment in attachments:
        if not isinstance(attachment, dict) or not isinstance(attachment.get("blob"), dict):
            raise StoreError("Studio App attachment must name a pinned blob locator")
        locator = check_locator(attachment["blob"])
        if locator["key"] != "sha256/" + locator["sha256"]:
            raise StoreError("Studio App attachment blob keys must be content addressed")
        if checked.get(locator["key"]) != locator:
            raise StoreError("Studio App attachment must match a locator on its native record")
        total += locator["bytes"]
        if total > MAX_APP_ATTACHMENT_BYTES:
            raise StoreError("Studio App attachments exceed the total byte limit")
        role = attachment.get("role")
        fmt = attachment.get("format")
        protected = attachment.get("protection")
        if protected is not None and (
                not isinstance(protected, dict) or set(protected) != {"format", "contentBytes", "contentSha256"}
                or protected.get("format") != "protected-bytes/v1"
                or type(protected.get("contentBytes")) is not int
                or not 1 <= protected["contentBytes"] <= MAX_ATTACHMENT_BYTES
                or not isinstance(protected.get("contentSha256"), str)
                or len(protected["contentSha256"]) != 64
                or any(char not in "0123456789abcdef" for char in protected["contentSha256"])):
            raise StoreError("Studio App protected attachment metadata is invalid")
        expected = {"pglite-snapshot": "pglite-snapshot", "sql-fallback": "sql", "csv-fallback": "csv"}
        if role not in expected or fmt != expected[role] or role in roles:
            raise StoreError("Studio App attachment role/format is invalid or duplicated")
        media_types = {"pglite-snapshot": {"application/octet-stream"},
                       "sql-fallback": {"application/sql", "text/plain"},
                       "csv-fallback": {"text/csv"}}
        if locator["mediaType"] not in media_types[role]:
            raise StoreError("Studio App attachment media type does not match its declared format")
        roles.add(role)
        if role == "pglite-snapshot":
            metadata = validate_pglite_snapshot_metadata(attachment)
            expanded_total += metadata["expandedBytes"]
            if expanded_total > MAX_EXPANDED_SNAPSHOT_BYTES:
                raise StoreError("Studio App expanded attachments exceed the byte limit")
        elif any(key in attachment for key in PGLITE_METADATA_FIELDS):
            raise StoreError("only a PGlite snapshot may declare runtime version metadata")
    if "pglite-snapshot" in roles and not roles.intersection({"sql-fallback", "csv-fallback"}):
        raise StoreError("PGlite snapshot requires a plain SQL or CSV fallback")
    if {locator["key"] for locator in checked.values()} != {item["blob"]["key"] for item in attachments}:
        raise StoreError("Studio App native blobs must be enumerated exactly by attachment metadata")
    return total


def verify_app_attachment_bytes(record, contents):
    """Verify selected bytes and boundedly validate compressed snapshots before runtime use.

    `contents` is a host-fetched mapping from exact content-addressed locator keys to
    bytes. This function never fetches, writes, opens or executes an attachment.
    """
    validate_app_attachments(record)
    if not isinstance(contents, dict):
        raise StoreError("Studio App attachment bytes must be an explicit mapping")
    locators = {item["key"]: item for item in record.get("blobs", [])}
    if set(contents) != set(locators):
        raise StoreError("Studio App attachment bytes do not match the exact locator set")
    for key, locator in locators.items():
        value = contents[key]
        if not isinstance(value, bytes) or len(value) != locator["bytes"]:
            raise StoreError("Studio App attachment bytes differ from their pinned size")
        if hashlib.sha256(value).hexdigest() != locator["sha256"]:
            raise StoreError("Studio App attachment bytes differ from their pinned digest")

    for attachment in record.get("content", {}).get("data", {}).get("attachments", []):
        # Protected bytes are authenticated and expanded only after the host
        # decrypts them. Ciphertext is never treated as a compressed snapshot.
        if attachment.get("protection") is not None:
            continue
        if attachment.get("role") != "pglite-snapshot":
            continue
        locator = attachment["blob"]
        verify_pglite_snapshot_bytes(attachment, contents[locator["key"]])
    return {key: contents[key] for key in locators}
