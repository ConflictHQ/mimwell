"""Bounded discovery over native proposals; inspection remains the access gate.

No queue state or canonical writes are stored here. Pagination addresses only the
visible result and is invalidated when that result changes. A queue digest is not
the proposal digest required by the native disposition/commit operations.
"""

from knowledge_policy import PolicyError, fingerprint
from knowledge_store import StoreError, encoded
from native_inspection import inspection_budget

MAX_CANDIDATES = 1000
MAX_READ_BYTES = 8 * 1024 * 1024
MAX_PROPOSAL_BYTES = 2 * 1024 * 1024


def inspect_queue(store, collections, actor, *, at, limit=50, cursor=None):
    existing = getattr(store, "_inspection_budget", None)
    if existing is not None:
        return _inspect_queue(store, collections, actor, at=at, limit=limit, cursor=cursor, budget=existing)
    with inspection_budget(store, max_bytes=MAX_READ_BYTES, max_row_bytes=MAX_PROPOSAL_BYTES) as budget:
        return _inspect_queue(store, collections, actor, at=at, limit=limit, cursor=cursor, budget=budget)


def _inspect_queue(store, collections, actor, *, at, limit, cursor, budget):
    """Inspect one bounded selection inside the caller's native read transaction.

    Collection selection must be readable in full; denied selections refuse.
    Native inspection independently checks proposal/source/relationship access.
    Bounds refuse the operation rather than return a falsely complete queue.
    No withheld counts, scan offsets or inaccessible proposal IDs are returned.
    """
    if not store.db.in_transaction:
        raise StoreError("Proposal queue requires a native read transaction")
    if (not isinstance(collections, list) or not 1 <= len(collections) <= 16
            or any(not isinstance(key, str) or not key for key in collections)
            or len(set(collections)) != len(collections)
            or type(limit) is not int or not 1 <= limit <= 100):
        raise StoreError("Invalid proposal queue selection")
    if cursor is not None and (
        not isinstance(cursor, dict) or set(cursor) != {"basisSha256", "after"}
        or any(not isinstance(value, str) or not value for value in cursor.values())
    ):
        raise StoreError("Invalid proposal queue cursor")
    store._read_state()
    collections = sorted(collections)
    if any(key not in store.contract.collections or not store.contract.can_read(key, actor, at)
           for key in collections):
        raise PolicyError("Proposal queue unavailable")
    placeholders = ",".join("?" for _ in collections)
    # The native table has no collection index. Bound its complete inventory before
    # JSON predicates run, including bodies outside the caller's selected scope.
    # Refuse an oversized inventory rather than silently omit an unknown collection.
    sizes = store.db.execute(
        "SELECT length(CAST(body AS BLOB)) AS bytes FROM proposals ORDER BY id LIMIT ?",
        (MAX_CANDIDATES + 1,),
    ).fetchall()
    if len(sizes) > MAX_CANDIDATES:
        raise StoreError("Proposal queue unavailable within its inspection bounds")
    for row in sizes:
        budget.charge(row["bytes"])
    # Delete proposals retain their collection on the native record row. Metadata
    # selection never substitutes for the current inspection access checks below.
    candidates = store.db.execute(
        "SELECT p.id, length(CAST(p.body AS BLOB)) AS bytes FROM proposals p "
        "LEFT JOIN records r ON r.id=json_extract(p.body, '$.request.record') "
        f"WHERE COALESCE(json_extract(p.body, '$.record.collection'), r.collection) IN ({placeholders}) "
        "ORDER BY p.id LIMIT ?", (*collections, MAX_CANDIDATES + 1),
    ).fetchall()
    if (len(candidates) > MAX_CANDIDATES or sum(row["bytes"] for row in candidates) > MAX_READ_BYTES
            or any(row["bytes"] > MAX_PROPOSAL_BYTES for row in candidates)):
        raise StoreError("Proposal queue unavailable within its inspection bounds")
    visible = []
    for candidate in candidates:
        try:
            observed = store.inspect(candidate["id"], actor, at=at)
        except PolicyError:
            continue
        proposal = observed["proposal"]
        request = proposal["request"]
        value = proposal["record"] or (observed["current"] or {}).get("record")
        visible.append({
            "proposal": proposal["id"], "proposalSha256": observed["proposalSha256"],
            "record": request["record"], "collection": value["collection"] if value else None,
            "kind": value["kind"] if value else None,
            "title": value.get("content", {}).get("title") if value else None,
            "mutation": request["mutation"], "expectedRevision": request["expectedRevision"],
            "currentRevision": observed["current"]["revision"] if observed["current"] else None,
            "lifecycle": observed["lifecycle"], "expired": observed["expired"],
            "proposedAt": proposal["at"], "expiresAt": proposal["expiresAt"],
        })
    basis = fingerprint({"contract": store.contract.binding, "instance": store._meta("instance"), "actor": actor,
                         "collections": collections, "rows": visible})
    start = 0
    if cursor is not None:
        ids = [row["proposal"] for row in visible]
        if cursor["basisSha256"] != basis or cursor["after"] not in ids:
            raise StoreError("Proposal queue changed; refresh the selection")
        start = ids.index(cursor["after"]) + 1
    page = visible[start:start + limit]
    result = {
        "format": "native-proposal-queue/v1", "collections": collections,
        "basisSha256": basis, "rows": page, "visibleTotal": len(visible),
        "nextCursor": {"basisSha256": basis, "after": page[-1]["proposal"]}
                      if start + len(page) < len(visible) else None,
        "scope": "currently-readable-native-proposals-in-selected-collections",
        "executionAuthorized": False,
    }
    if len(encoded(result).encode()) > MAX_READ_BYTES:
        raise StoreError("Proposal queue exceeds its response bound")
    return result
