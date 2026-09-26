"""Corpus documents as search-shaped records, gated by the existing read boundary (#284).

The optional D1 corpus index (#64, ``corpus_index.py``) is a projection of the
markdown corpus, not an authority. Reached through the Worker, it filters with its
own email/owner permission metadata (``restricted``/``readers``). Reached through
the #55 context contract instead, a document is admitted only when its indexed
path is bound to a permitted policy resource in the ``paths`` table that already
gates a graph node's or edge's source paths (``context_access.ReadBoundary``); the
index's own permission metadata plays no role here. Term ranking is then whatever
``context_search.search`` already does for any authorized record.
"""
from __future__ import annotations

import sqlite3
from contextlib import closing


def document_records(db_path, boundary):
    """Every corpus document at ``db_path`` whose exact path the boundary permits.

    Each record is the whole document (not the Worker's best-chunk snippet), shaped
    like a search record: ``id``, ``title``, ``text``, plus ``path`` and
    ``revision`` for a caller that wants to attribute or re-fetch it.
    """
    with closing(sqlite3.connect(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        docs = {row["source_id"]: dict(row) for row in connection.execute(
            "SELECT source_id, path, title, revision FROM corpus_doc")}
        texts = {}
        for row in connection.execute("SELECT source_id, ord, text FROM corpus_chunk ORDER BY source_id, ord"):
            texts.setdefault(row["source_id"], []).append(row["text"])
    records = []
    for source_id, doc in docs.items():
        if not boundary.permits("paths", doc["path"]):
            continue
        records.append({"id": "corpus:" + doc["path"], "path": doc["path"], "title": doc["title"],
                        "revision": doc["revision"], "text": "\n\n".join(texts.get(source_id, []))})
    return sorted(records, key=lambda record: record["path"])
