"""Rebuildable native intake-completion index; never an authority or source cache.

The host owns this private SQLite file, the canonical authority and registrations.
Journal replay is bounded. Every reuse rechecks the exact native receipt, source
history, destination and current read boundary from one authority read snapshot.
"""
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import sqlite3
import stat

from intake_contract import IntakeError
from intake_delivery import PROFILE, check
from intake_keys import completion_key
from knowledge_policy import fingerprint
from knowledge_store import DB_VERSION, contract_binding, encoded


class CompletionUnavailable(IntakeError):
    """No usable completion observation; do not silently assume new work."""


def registrations_check(authority, registrations):
    if not isinstance(registrations, dict) or not 1 <= len(registrations) <= 64:
        raise IntakeError('Explicit bounded destination registrations required')
    for identity, target in registrations.items():
        check(target, 'registration')
        if (not isinstance(identity, str) or not identity.strip()
                or target['authority'] != authority.contract.authority
                or target['collection'] not in authority.contract.collections):
            raise IntakeError('Invalid completion destination registration')


def charge(budget, size):
    if size > budget[0]:
        raise CompletionUnavailable('Completion lookup exceeds its aggregate read bound')
    budget[0] -= size


SCHEMA = """
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE completions (record TEXT PRIMARY KEY, completion_key TEXT NOT NULL,
 sequence INTEGER NOT NULL, digest TEXT NOT NULL);
CREATE INDEX completions_key ON completions(completion_key,record);
PRAGMA user_version=1;
"""


class CompletionIndex:
    def __init__(self, path, authority, registrations):
        self.path, self.authority = Path(path), authority
        if (self.path.is_symlink() or not self.path.is_file()
                or stat.S_IMODE(self.path.stat().st_mode) & 0o077):
            raise CompletionUnavailable('Completion index must be a private regular file')
        registrations_check(authority, registrations)
        self.registrations = deepcopy(registrations)
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            if self.db.execute('PRAGMA user_version').fetchone()[0] != 1:
                raise CompletionUnavailable('Unsupported completion index version')
            self._binding()
        except BaseException:
            self.db.close()
            raise

    @classmethod
    def initialize(cls, path, authority, registrations):
        registrations_check(authority, registrations)
        if authority._meta('status') != 'active':
            raise CompletionUnavailable('Completion authority is inactive')
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        db = sqlite3.connect(path)
        try:
            db.executescript(SCHEMA)
            with db:
                db.executemany('INSERT INTO metadata VALUES (?,?)', [
                    ('instance', authority._meta('instance')), ('contract', authority.contract.binding),
                    ('sequence', '0'), ('digest', 'null')])
        finally:
            db.close()
        try:
            return cls(path, authority, registrations)
        except BaseException:
            path.unlink()
            raise

    def close(self):
        self.db.close()

    def _meta(self, name):
        row = self.db.execute('SELECT value FROM metadata WHERE key=?', (name,)).fetchone()
        if row is None:
            raise CompletionUnavailable('Incomplete completion index')
        return row[0]

    def _binding(self):
        authority = self.authority
        if (self._meta('instance') != authority._meta('instance')
                or self._meta('contract') != authority.contract.binding
                or contract_binding(json.loads(authority._meta('bundle'))) != authority.contract.binding
                or authority.schema_version() != DB_VERSION
                or authority._meta('status') != 'active'):
            raise CompletionUnavailable('Completion authority changed or is inactive')

    @contextmanager
    def _snapshot(self, *, write=False):
        self.db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        try:
            self.authority.db.execute('BEGIN')
            try:
                self._binding()
                yield
            finally:
                self.authority.db.execute('ROLLBACK')
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def _checkpoint(self):
        sequence, digest = int(self._meta('sequence')), json.loads(self._meta('digest'))
        row = self.authority.db.execute('SELECT digest FROM events WHERE sequence=?', (sequence,)).fetchone()
        if sequence < 0 or (sequence == 0 and digest is not None) or (sequence and (not row or row[0] != digest)):
            raise CompletionUnavailable('Completion checkpoint no longer matches native history')
        return sequence, digest

    def refresh(self, *, max_events=1000, max_bytes=1048576, fault=None):
        """Host-only bounded journal catch-up. Checkpoint and index commit together."""
        if (type(max_events) is not int or not 1 <= max_events <= 1000
                or type(max_bytes) is not int or not 1 <= max_bytes <= 16777216):
            raise IntakeError('Invalid completion replay budget')
        with self._snapshot(write=True):
            sequence, digest = self._checkpoint()
            head = self.authority.db.execute('SELECT max(sequence) FROM events').fetchone()[0]
            rows = self.authority.db.execute('SELECT sequence,previous,digest,length(CAST(body AS BLOB)) AS bytes '
                'FROM events WHERE sequence>? ORDER BY sequence LIMIT ?', (sequence, max_events)).fetchall()
            used, count, truncation = 0, 0, []
            for row in rows:
                if row['sequence'] != sequence + 1 or row['previous'] != digest:
                    raise CompletionUnavailable('Native journal is discontinuous')
                # Import cannot attest to native delivery, and may contain a large corpus.
                # Its digest is the trusted authority checkpoint, not a delivery receipt.
                if row['sequence'] != 1:
                    if used + row['bytes'] > max_bytes:
                        truncation = ['maxBytes']
                        break
                    raw = self.authority.db.execute('SELECT body FROM events WHERE sequence=?',
                                                    (row['sequence'],)).fetchone()[0]
                    receipt = json.loads(raw)
                    if fingerprint({'previous': digest, 'event': receipt}) != row['digest']:
                        raise CompletionUnavailable('Native journal receipt changed')
                    used += row['bytes']
                    record = receipt['request']['record']
                    after = receipt.get('after')
                    if not after or after.get('content', {}).get('status') in ('retracted', 'superseded', 'deleted'):
                        self.db.execute('DELETE FROM completions WHERE record=?', (record,))
                    elif receipt.get('promotion', {}).get('projection') in (PROFILE, 'intake-processed-record/v1'):
                        origin = after['content']['data']['intakeDelivery']
                        check(origin, 'origin')
                        processing = 'metadata' if origin['format'] == PROFILE else 'extract'
                        key = completion_key(origin['item'], origin['destination']['target'], processing,
                                             origin['labels'], origin['basis'])
                        self.db.execute('INSERT INTO completions VALUES (?,?,?,?) ON CONFLICT(record) DO UPDATE SET '
                            'completion_key=excluded.completion_key,sequence=excluded.sequence,digest=excluded.digest',
                            (record, key, row['sequence'], row['digest']))
                sequence, digest = row['sequence'], row['digest']
                count += 1
                if fault:
                    fault('after-event')
            if sequence < head and not truncation:
                truncation = ['maxEvents']
            self.db.execute("UPDATE metadata SET value=? WHERE key='sequence'", (str(sequence),))
            self.db.execute("UPDATE metadata SET value=? WHERE key='digest'", (encoded(digest),))
            if fault:
                fault('before-commit')
            return {'format': 'intake-completion-refresh/v1', 'processed': count, 'inputBytes': used,
                    'complete': sequence == head, 'truncation': truncation}

    def lookup(self, planner, item, destination, processing, labels):
        """Planner callback. Only the opaque receipt hash crosses this boundary.

        A stale index refuses rather than silently scheduling duplicate work.
        A result is a read-point observation, never a publication or training grant.
        """
        boundary, authority = planner.boundary, self.authority
        target = self.registrations.get(destination['id'])
        if (processing not in ('metadata', 'extract') or target != destination['target']
                or destination != planner.destinations.get(destination['id'])
                or boundary.policy.binding != authority.contract.policy.binding
                or not planner.authorized(item) or item['source']['reference']['availability'] != 'available'
                or not boundary.permits_resource(destination['resource'], destination['id'])
                or destination['mode'] != 'write'
                or authority.contract.collections[target['collection']]['resource'] != destination['resource']):
            return None
        key = completion_key(item, target, processing, labels, planner.basis)
        with self._snapshot():
            if not authority.contract.can_read(target['collection'], boundary.actor, boundary.now):
                return None
            sequence, _ = self._checkpoint()
            if sequence != authority.db.execute('SELECT max(sequence) FROM events').fetchone()[0]:
                raise CompletionUnavailable('Completion index requires bounded refresh')
            rows = self.db.execute('SELECT * FROM completions WHERE completion_key=? ORDER BY record LIMIT 65',
                                   (key,)).fetchall()
            budget = [33554432, 256]
            for row in rows[:64]:
                result = self._current(row, planner, item, destination, labels, budget)
                if result:
                    return result
            if len(rows) > 64:
                raise CompletionUnavailable('Completion candidate budget exhausted')
            return None

    def _current(self, candidate, planner, item, destination, labels, budget):
        observed = self._observe(candidate, planner, item, destination, labels, budget)
        return fingerprint(observed['receipt']) if observed else None

    def _observe(self, candidate, planner, item, destination, labels, budget):
        """Private authorized evidence for derived completion; no new read grant."""
        authority, boundary = self.authority, planner.boundary
        current = self._record(candidate['record'], boundary, budget)
        if (not current or not current['record'] or current['withheldRelations']
                or current['record']['collection'] != destination['target']['collection']
                or current['record']['content'].get('status') in ('retracted', 'superseded', 'deleted')):
            return None
        size = authority.db.execute('SELECT length(CAST(body AS BLOB)) FROM events WHERE sequence=?',
                                    (candidate['sequence'],)).fetchone()
        if size:
            charge(budget, size[0])
        native = authority.db.execute('SELECT body,digest,previous FROM events WHERE sequence=?',
                                      (candidate['sequence'],)).fetchone()
        if not native or native['digest'] != candidate['digest']:
            raise CompletionUnavailable('Indexed completion receipt changed')
        receipt = json.loads(native['body'])
        if fingerprint({'previous': native['previous'], 'event': receipt}) != native['digest']:
            raise CompletionUnavailable('Native completion receipt changed')
        pin, after = receipt.get('promotion', {}), receipt.get('after')
        origin = (after or {}).get('content', {}).get('data', {}).get('intakeDelivery')
        if (pin.get('projection') not in (PROFILE, 'intake-processed-record/v1')
                or not receipt.get('sourceReview') or not receipt.get('review')
                or receipt['contract'] != authority.contract.binding or receipt['request']['record'] != candidate['record']
                or not origin or origin['item'] != item or origin['basis'] != planner.basis
                or origin['labels'] != sorted(labels) or origin['destination']['id'] != destination['id']
                or origin['destination']['target'] != destination['target']
                or current['record']['content'].get('data', {}).get('intakeDelivery') != origin):
            return None
        source = self._record(pin['source'], boundary, budget)
        if (not source or not source['record'] or source['withheldRelations'] or source['revision'] != pin['revision']
                or fingerprint(source['record']) != pin['sha256']
                or source['record']['content'].get('status') in ('retracted', 'superseded', 'deleted')):
            return None
        size = authority.db.execute("SELECT length(CAST(body AS BLOB)) FROM events WHERE "
            "json_extract(body,'$.request.record')=? AND json_extract(body,'$.revision')=?",
            (pin['source'], pin['revision'])).fetchone()
        if size:
            charge(budget, size[0])
        authority._reviewed_intake(pin)
        if pin['projection'] == 'intake-processed-record/v1':
            from intake_processed import authorize, current_protection, dependencies, is_reuse
            representation = pin['representation']
            reused = is_reuse(representation['receipt'])
            if not reused and boundary.bindings['references'].get(fingerprint(item)) != representation['sourceResource']:
                return None
            for identity, resource, _ in dependencies(representation):
                if (boundary.bindings['references'].get(identity) != resource
                        or not boundary.permits('references', identity)):
                    if reused:
                        raise CompletionUnavailable('Current processing dependency unavailable')
                    return None
            try:
                current_protection(authority, representation, actor=boundary.actor, at=boundary.now)
            except (ValueError, OSError) as exc:
                raise CompletionUnavailable('Current processing protection unavailable') from exc
            authorize(authority.contract, representation, boundary.actor, boundary.now, pin['resource'])
        return {'receipt': receipt, 'record': current['record'], 'revision': current['revision'],
                'readDependencies': current['readDependencies'] + source['readDependencies']}

    def _record(self, identity, boundary, budget):
        authority = self.authority
        row = authority.db.execute('SELECT collection,revision,deleted,length(CAST(body AS BLOB)) AS bytes '
                                   'FROM records WHERE id=?', (identity,)).fetchone()
        if not row or row['deleted'] or not self._readable(row['collection'], identity, boundary):
            return None
        if row['bytes'] > 4194304:
            raise CompletionUnavailable('Canonical completion record exceeds its read bound')
        charge(budget, row['bytes'])
        record = json.loads(authority.db.execute('SELECT body FROM records WHERE id=?', (identity,)).fetchone()[0])
        withheld = False
        dependencies = [(row['collection'], identity)]
        for edge in record['relations']:
            if budget[1] == 0:
                raise CompletionUnavailable('Completion relationship budget exhausted')
            budget[1] -= 1
            # Authorizing a link must never fetch the target body. Its collection
            # and live status suffice; both request scopes and native grants apply.
            target = authority.db.execute('SELECT collection,deleted FROM records WHERE id=?',
                                          (edge['target'],)).fetchone()
            if not target or target['deleted'] or not self._readable(target['collection'], edge['target'], boundary):
                withheld = True
                break
            dependencies.append((target['collection'], edge['target']))
        return {'record': record, 'revision': row['revision'], 'withheldRelations': withheld,
                'readDependencies': dependencies}

    def _readable(self, collection, identity, boundary):
        return (boundary.permits_resource(self.authority.contract.collections[collection]['resource'], identity)
                and self.authority.contract.can_read(collection, boundary.actor, boundary.now))
