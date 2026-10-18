"""Bounded revision metadata under the record's current native read policy.

No historic content, actor list, global journal count or administrative export.
The packaged pilot supports SQLite; other adapters explicitly refuse this view.
"""
from contextlib import nullcontext

from native_inspection import inspection_budget
from knowledge_store import StoreError


def inspect_history(store, identity, actor, *, at=None, limit=25):
    if store.dialect.driver != 'sqlite':
        raise StoreError('Record history browsing requires the SQLite pilot')
    if not isinstance(identity, str) or not 1 <= len(identity) <= 2000 or type(limit) is not int or not 1 <= limit <= 50:
        raise StoreError('Invalid bounded record history request')
    own_transaction = not store.dialect.in_transaction
    if own_transaction:
        store.dialect.begin()
    try:
        budget_context = (inspection_budget(store, max_rows=1000, max_bytes=1024 * 1024)
                          if getattr(store, '_inspection_budget', None) is None else nullcontext())
        with budget_context:
            current = store.get(identity, actor, at=at)
            if current is None:
                return None
            if current['withheldRelations']:
                raise StoreError('Record history unavailable in this read scope')
            # Select only metadata in SQL; do not deserialize historical bodies.
            columns = ('revision', 'previousRevision', 'at', 'request.mutation', 'proposal')
            selections = ', '.join(store.dialect.json_path('body', name) for name in columns)
            record_path = store.dialect.json_path('body', 'request.record')
            rows = store.dialect.execute(
                f'SELECT {selections} FROM events WHERE {record_path}=? ORDER BY sequence DESC LIMIT ?',
                (identity, limit + 1)).fetchall()
            entries = [dict(zip(('revision', 'previousRevision', 'at', 'mutation', 'proposal'), row))
                       for row in rows[:limit]]
            for entry in entries:
                store._inspection_budget.charge(sum(len(str(value).encode('utf-8')) for value in entry.values()))
            return {'format': 'record-history/v1', 'record': identity, 'revision': current['revision'],
                    'entries': entries, 'limit': limit, 'truncated': len(rows) > limit,
                    'scope': 'revision-metadata-since-import; no historic content',
                    'priorHistory': store.contract.document['history']['priorHistory']}
    finally:
        if own_transaction:
            store.dialect.rollback()
