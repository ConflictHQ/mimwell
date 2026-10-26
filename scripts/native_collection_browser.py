"""Opt-in SQLite collection pages over the existing authorized native reader.

Cursors carry navigation/currentness, never permission. No cache, count query,
new connection, schema migration, historic content or canonical mutation.
"""

from datetime import timedelta
import re

from brain_federation import fields
from knowledge_policy import PolicyError, fingerprint, timestamp
from knowledge_store import StoreError, context_records

MAX_CANDIDATES = 1000
CURSOR_LIFETIME = timedelta(minutes=5)


def validate_arguments(operation, args):
    if operation == "authority.inspect":
        fields(args, ())
        return
    if operation != "collection.browse":
        raise StoreError("Unsupported collection browser operation")
    fields(args, ("collection", "limit", "cursor"))
    if (not isinstance(args["collection"], str) or not 1 <= len(args["collection"]) <= 2000
            or type(args["limit"]) is not int or not 1 <= args["limit"] <= 100):
        raise StoreError("Invalid collection browser selection")
    cursor = args["cursor"]
    if cursor is not None:
        fields(cursor, ("basisSha256", "after", "asOf"))
        if (not isinstance(cursor["basisSha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", cursor["basisSha256"])
                or not isinstance(cursor["after"], str) or not 1 <= len(cursor["after"]) <= 2000
                or not isinstance(cursor["asOf"], str)):
            raise StoreError("Invalid collection browser cursor")
        timestamp(cursor["asOf"])


def browse(store, args, *, actor, at, as_of, registration):
    validate_arguments("collection.browse", args)
    budget = getattr(store, "_inspection_budget", None)
    if store.dialect.driver != "sqlite" or not store.db.in_transaction or budget is None:
        raise StoreError("Collection browser requires a bounded SQLite read transaction")
    store._read_state()
    collection, limit, cursor = args["collection"], args["limit"], args["cursor"]
    if collection not in store.contract.collections or not store.contract.can_read(collection, actor, at):
        raise PolicyError("Collection browser unavailable")
    owner = {"contract": store.contract.document["id"], "authority": store.contract.authority}
    if any(not isinstance(value, str) or not 1 <= len(value) <= 2000 for value in owner.values()):
        raise StoreError("Collection browser owner metadata exceeds its response bound")
    as_of = cursor["asOf"] if cursor else as_of
    if not timestamp(as_of) <= timestamp(at) <= timestamp(as_of) + CURSOR_LIFETIME:
        raise StoreError("Collection browser expired; refresh the selection")
    head = store.db.execute(
        "SELECT sequence, typeof(sequence), typeof(digest), length(CAST(digest AS BLOB)) "
        "FROM events ORDER BY sequence DESC LIMIT 1").fetchone()
    if not head or head[1] != "integer" or head[2] != "text" or head[3] != 64:
        raise StoreError("Collection browser authority basis unavailable")
    digest = store.db.execute("SELECT digest FROM events WHERE sequence=?", (head[0],)).fetchone()[0]
    basis = fingerprint({"contract": store.contract.binding, "instance": store._meta("instance"),
                         "head": [head[0], digest], "actor": actor, "registration": registration, "collection": collection,
                         "asOf": as_of})

    def visible(identity):
        observed = store.get(identity, actor, at=at)
        value = observed and observed.get("record")
        if not value or value.get("collection") != collection or observed["deleted"]:
            return None
        old = bool(context_records(store.contract, [value], at=as_of))
        current = bool(context_records(store.contract, [value], at=at))
        if old != current:
            raise StoreError("Collection browser membership changed; refresh the selection")
        if not current:
            return None
        title = value.get("content", {}).get("title")
        if (value.get("id") != identity or any(not isinstance(item, str) or not 1 <= len(item.encode("utf-8")) <= 2000
                for item in (value.get("kind"), observed.get("revision")))
                or title is not None and (not isinstance(title, str) or len(title.encode("utf-8")) > budget.max_row_bytes)):
            raise StoreError("Collection browser metadata unavailable within its bounds")
        return {"record": value["id"], "collection": collection, "kind": value["kind"],
                "title": title, "revision": observed["revision"],
                "editableWholeRecord": not observed["withheldRelations"]}

    after = ""
    if cursor:
        if cursor["basisSha256"] != basis or visible(cursor["after"]) is None:
            raise StoreError("Collection browser changed; refresh the selection")
        after = cursor["after"]
    rows = []
    for _ in range(MAX_CANDIDATES):
        # Indexed keyset scan. Length/type preflight precedes fetching an ID or
        # native body. Hidden IDs and inspected counts never enter the response.
        row = store.db.execute(
            "SELECT CASE WHEN typeof(id)='text' AND length(CAST(id AS BLOB))<=2000 THEN id END, "
            "typeof(revision), length(CAST(revision AS BLOB)), length(CAST(body AS BLOB)) "
            "FROM records WHERE collection=? AND deleted=0 AND id>? ORDER BY id LIMIT 1",
            (collection, after)).fetchone()
        if row is None:
            break
        budget.charge()
        if row[0] is None or row[1] != "text" or not 1 <= row[2] <= 2000 or row[3] is None:
            raise StoreError("Collection browser row unavailable within its bounds")
        # Enforce the body bound before get() or any JSON decoding. get() then
        # charges actual bytes and retains its normal policy/relationship gates.
        if row[3] > budget.max_row_bytes or row[3] > budget.remaining_bytes:
            raise StoreError("Collection browser row exceeds its read budget")
        after = row[0]
        value = visible(after)
        if value is not None:
            rows.append(value)
            if len(rows) > limit:
                break
    else:
        raise StoreError("Collection browser unavailable within its inspection bounds")
    page = rows[:limit]
    return {"format": "native-collection-page/v1", "collection": collection,
            "owner": owner,
            "basisSha256": basis, "asOf": as_of, "rows": page,
            "nextCursor": {"basisSha256": basis, "after": page[-1]["record"], "asOf": as_of}
                          if len(rows) > limit else None,
            "scope": "current-readable-ordinary-context-records-at-asOf",
            "executionAuthorized": False}
