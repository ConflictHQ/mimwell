"""One read budget shared by native proposal discovery and dependent inspection.

The trusted adapter owns this short-lived connection and read transaction. Bounds
cover native bodies released into Python, row/relationship work and SQLite VM work.
They are not a claim about filesystem page-cache use or external provider latency.
"""

from contextlib import contextmanager
import sqlite3

from knowledge_store import StoreError


class InspectionBudget:
    def __init__(self, *, max_bytes=8 * 1024 * 1024, max_row_bytes=2 * 1024 * 1024,
                 max_rows=10000, max_sql_steps=1000000):
        values = (max_bytes, max_row_bytes, max_rows, max_sql_steps)
        if any(type(value) is not int or value < 1 for value in values):
            raise StoreError("Invalid native inspection budget")
        self.remaining_bytes, self.max_row_bytes = max_bytes, max_row_bytes
        self.remaining_rows, self.remaining_steps = max_rows, max_sql_steps

    def charge(self, size=0, rows=1):
        if (size > self.max_row_bytes or size > self.remaining_bytes or rows > self.remaining_rows):
            raise StoreError("Native inspection exceeds its read budget")
        self.remaining_bytes -= size
        self.remaining_rows -= rows

    def progress(self):
        self.remaining_steps -= 1000
        return int(self.remaining_steps < 0)

    def body(self, db, table, column, value):
        if (table, column) not in (("records", "id"), ("proposals", "id")):
            raise StoreError("Unsupported native inspection lookup")
        row = db.execute(f"SELECT length(CAST(body AS BLOB)) FROM {table} WHERE {column}=?", (value,)).fetchone()
        self.charge((row[0] or 0) if row else 0)

    def receipts(self, db, intent):
        sizes = db.execute(
            "SELECT length(CAST(body AS BLOB)) FROM receipts WHERE intent=? LIMIT ?",
            (intent, self.remaining_rows + 1),
        ).fetchall()
        for row in sizes:
            self.charge(row[0])
        return db.execute("SELECT body FROM receipts WHERE intent=?", (intent,)).fetchall()


@contextmanager
def inspection_budget(store, **options):
    if not store.db.in_transaction or getattr(store, "_inspection_budget", None) is not None:
        raise StoreError("Inspection budget requires one unnested native transaction")
    budget = InspectionBudget(**options)
    previous_length = store.db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, budget.max_row_bytes)
    store._inspection_budget = budget
    store.db.set_progress_handler(budget.progress, 1000)
    try:
        yield budget
    except sqlite3.DatabaseError as exc:
        raise StoreError("Native inspection unavailable within its database bounds") from exc
    finally:
        store.db.set_progress_handler(None, 0)
        store.db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, previous_length)
        store._inspection_budget = None
