"""Host-owned, conservative SQLite reservations for synchronous intake adapters.

Only registered adapter callbacks are supported. This is not a sandbox: trusted
host code must pass the callback through every stage and attest quiescent recovery.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading
import time
from urllib.parse import quote
import uuid


class BudgetError(ValueError):
    """Invalid host configuration, callback, or ledger state."""


class BudgetExhausted(BudgetError):
    """Admission refused before work; no automatic retry or refund."""


class BudgetUnavailable(BudgetError):
    """The ledger cannot safely admit work (including a bounded lock timeout)."""


LIMITS = ('maxConcurrentOperations', 'maxOperations', 'maxStages',
          'maxProcessAttempts', 'maxModelAttempts')
APPLICATION_ID = 1112688452
SCHEMA = """
CREATE TABLE budget (
 id INTEGER PRIMARY KEY CHECK(id=1), config TEXT NOT NULL, digest TEXT NOT NULL,
 operations INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 0,
 stages INTEGER NOT NULL DEFAULT 0, processes INTEGER NOT NULL DEFAULT 0,
 models INTEGER NOT NULL DEFAULT 0, known_processes INTEGER NOT NULL DEFAULT 0,
 known_models INTEGER NOT NULL DEFAULT 0);
CREATE TABLE operations (
 id TEXT PRIMARY KEY, actor TEXT NOT NULL, request TEXT NOT NULL, token TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('open','completed','failed','recovered')),
 created INTEGER NOT NULL, closed INTEGER, sequence INTEGER NOT NULL DEFAULT 0);
CREATE TABLE stages (
 id TEXT PRIMARY KEY, operation TEXT NOT NULL REFERENCES operations(id),
 kind TEXT NOT NULL, subject TEXT NOT NULL, admitted TEXT NOT NULL,
 terminal TEXT, audit_failure TEXT,
 processes INTEGER NOT NULL, models INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('active','completed','failed','recovered-unknown')),
 created INTEGER NOT NULL, closed INTEGER);
CREATE INDEX stage_operations ON stages(operation,created,id);
CREATE UNIQUE INDEX one_active_stage ON stages(operation) WHERE state='active';
CREATE TABLE recoveries (
 operation TEXT PRIMARY KEY REFERENCES operations(id), actor TEXT NOT NULL,
 reason TEXT NOT NULL, evidence TEXT NOT NULL, previous TEXT NOT NULL,
 quiescent INTEGER NOT NULL CHECK(quiescent=1), created INTEGER NOT NULL);
"""
ADMISSIONS = {
    'classifier.admitted': 'classifier',
    'extraction.admitted': 'extraction',
    'media.decode.admitted': 'media.decode',
    'media.transcribe.admitted': 'media.transcribe',
    'recording.decode.admitted': 'recording.decode',
    'recording.transcribe.admitted': 'recording.transcribe',
}
TERMINALS = {f'{prefix}.{ending}': (kind, ending)
             for prefix, kind in (('classifier', 'classifier'), ('extraction', 'extraction'),
                                  ('media.decode', 'media.decode'), ('media.transcribe', 'media.transcribe'),
                                  ('recording.prepare', 'recording.decode'),
                                  ('recording.transcribe', 'recording.transcribe'))
             for ending in ('completed', 'failed')}
REUSE_EVENTS = frozenset(('processing.cache.admitted', 'processing.cache.completed',
                          'processing.reuse.admitted', 'processing.reuse.completed', 'processing.reuse.miss'))
PASS = REUSE_EVENTS | frozenset(('capture.admitted', 'capture.completed', 'capture.failed', 'capture.bound',
                  'intake.planned', 'intake.rejected', 'intake.proposing', 'intake.proposed',
                  'intake.classified', 'media.completed', 'media.withheld',
                  'recording.prepare.admitted', 'recording.chunk.admitted',
                  'recording.chunk.completed', 'recording.chunk.failed', 'recording.transcribe.released'))


def encoded(value):
    try:
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise BudgetError('Invalid budget JSON') from exc
    return raw


def fingerprint(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def digest(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise BudgetError('Expected SHA-256 digest')
    return value


def label(value):
    if not isinstance(value, str) or not value.strip() or len(value.encode()) > 4096:
        raise BudgetError('Expected bounded nonempty host label')
    return value


def configuration(value):
    if (not isinstance(value, dict) or set(value) != {'format', 'id', *LIMITS}
            or value['format'] != 'execution-budget/v1'):
        raise BudgetError('Invalid execution budget configuration')
    label(value['id'])
    for key in LIMITS:
        minimum = 0 if key in ('maxProcessAttempts', 'maxModelAttempts') else 1
        if type(value[key]) is not int or not minimum <= value[key] <= 1_000_000:
            raise BudgetError('Invalid bounded execution budget limit')
    return deepcopy(value)


def units(detail, key, allowed):
    value = detail.get(key)
    if type(value) is not int or value not in allowed:
        raise BudgetError('Invalid stage units: ' + key)
    return value


def private_path(path, *, exists=True):
    path = Path(path)
    if not path.is_absolute() or path.parent.resolve() != path.parent or path.name in ('', '.', '..'):
        raise BudgetError('Budget requires an absolute canonical private path')
    parent = path.parent.stat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
        raise BudgetError('Budget directory must be private and owned by the current user')
    if exists:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise BudgetError('Budget must be an owned single-link regular 0600 file')
        return path, (info.st_dev, info.st_ino)
    return path, None


class ExecutionBudget:
    """A pinned existing ledger. Each operation owns its own connection."""

    @classmethod
    def initialize(cls, path, config, *, timeout_seconds=0.25):
        config = configuration(config)
        cls._timeout(timeout_seconds)
        path, _ = private_path(path, exists=False)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        db = sqlite3.connect(str(path), isolation_level=None, timeout=timeout_seconds)
        try:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('PRAGMA synchronous=FULL')
            db.executescript('BEGIN IMMEDIATE;\n' + SCHEMA)
            db.execute('INSERT INTO budget(id, config, digest) VALUES(1,?,?)',
                       (encoded(config).decode(), fingerprint(config)))
            db.execute(f'PRAGMA application_id={APPLICATION_ID}')
            db.execute('PRAGMA user_version=1')
            db.commit()
        finally:
            db.close()
        return cls(path, expected_config_sha256=fingerprint(config), timeout_seconds=timeout_seconds)

    @staticmethod
    def _timeout(value):
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 10:
            raise BudgetError('SQLite timeout must be finite and between 0 and 10 seconds')

    def __init__(self, path, *, expected_config_sha256, timeout_seconds=0.25):
        self._timeout(timeout_seconds)
        self.path, self.identity = private_path(path)
        self.pin = digest(expected_config_sha256)
        self.timeout = timeout_seconds
        with self._transaction() as db:
            self._config = configuration(json.loads(db.execute('SELECT config FROM budget WHERE id=1').fetchone()[0]))

    @property
    def config(self):
        return deepcopy(self._config)

    @contextmanager
    def _transaction(self):
        db = None
        try:
            _, identity = private_path(self.path)
            if identity != self.identity:
                raise BudgetError('Budget file identity changed')
            db = sqlite3.connect('file:' + quote(str(self.path), safe='/') + '?mode=rw',
                                 uri=True, isolation_level=None, timeout=self.timeout)
            db.row_factory = sqlite3.Row
            if private_path(self.path)[1] != identity:
                raise BudgetError('Budget file changed while opening')
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('PRAGMA synchronous=FULL')
            if (db.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID
                    or db.execute('PRAGMA user_version').fetchone()[0] != 1
                    or db.execute('PRAGMA journal_mode').fetchone()[0] != 'wal'):
                raise BudgetError('Incompatible execution budget schema or journal mode')
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT config, digest FROM budget WHERE id=1').fetchone()
            if row is None or row['digest'] != self.pin or fingerprint(configuration(json.loads(row['config']))) != self.pin:
                raise BudgetError('Execution budget configuration pin changed')
            yield db
            db.commit()
        except sqlite3.Error as exc:
            raise BudgetUnavailable('Execution budget ledger unavailable; prior reservations and work may exist') from exc
        finally:
            if db is not None:
                db.close()  # rolls back on any error; never refund committed reservations

    def operation(self, *, actor, request_sha256, audit):
        return Operation(self, actor, digest(request_sha256), audit)

    @staticmethod
    def _snapshot(db, operation_id):
        row = db.execute('SELECT * FROM operations WHERE id=?', (operation_id,)).fetchone()
        if row is None:
            raise BudgetError('Unknown operation')
        operation = dict(row)
        del operation['token']
        stages = [dict(r) for r in db.execute('SELECT * FROM stages WHERE operation=? ORDER BY created,id', (operation_id,))]
        recovery = db.execute('SELECT * FROM recoveries WHERE operation=?', (operation_id,)).fetchone()
        return {'format': 'execution-budget-operation/v1', 'operation': operation,
                'stages': stages, 'recovery': dict(recovery) if recovery else None}

    def inspect(self, operation_id):
        with self._transaction() as db:
            snapshot = self._snapshot(db, label(operation_id))
            return {**snapshot, 'stateSha256': fingerprint(snapshot)}

    def report(self):
        with self._transaction() as db:
            row = db.execute('SELECT * FROM budget WHERE id=1').fetchone()
            return {'format': 'execution-budget-report/v1', 'configSha256': self.pin,
                    'config': deepcopy(self.config), 'operations': row['operations'],
                    'activeOperations': row['active'], 'stages': row['stages'],
                    'processAttemptsReserved': row['processes'], 'modelAttemptsReserved': row['models'],
                    'knownProcessCalls': row['known_processes'], 'knownModelCalls': row['known_models'],
                    'pendingOrUnknownProcessAttempts': row['processes'] - row['known_processes'],
                    'pendingOrUnknownModelAttempts': row['models'] - row['known_models']}

    def recover(self, operation_id, *, expected_state_sha256, evidence_sha256, actor, reason, quiescent):
        """Host attests the operation AND descendants stopped; this does not stop them."""
        label(operation_id)
        digest(expected_state_sha256)
        digest(evidence_sha256)
        actor_hash, reason_hash = fingerprint(label(actor)), fingerprint(label(reason))
        if quiescent is not True:
            raise BudgetError('Recovery requires explicit operation/descendant quiescence attestation')
        with self._transaction() as db:
            snapshot = self._snapshot(db, operation_id)
            if snapshot['operation']['state'] != 'open' or fingerprint(snapshot) != expected_state_sha256:
                raise BudgetError('Operation changed or is already closed')
            now = time.time_ns()
            db.execute("UPDATE stages SET state='recovered-unknown',closed=? WHERE operation=? AND state='active'",
                       (now, operation_id))
            db.execute("UPDATE operations SET state='recovered',closed=? WHERE id=?", (now, operation_id))
            db.execute('UPDATE budget SET active=active-1 WHERE id=1')
            db.execute('INSERT INTO recoveries VALUES(?,?,?,?,?,1,?)',
                       (operation_id, actor_hash, reason_hash, evidence_sha256, expected_state_sha256, now))
        return self.inspect(operation_id)


class Operation:
    """Single-use callback scope confined to its creating PID and thread."""

    def __init__(self, budget, actor, request_sha256, audit):
        if not callable(audit):
            raise BudgetError('A durable host audit callback is required')
        self.budget, self.actor, self.request, self.audit = budget, label(actor), request_sha256, audit
        self.id, self._token = str(uuid.uuid4()), str(uuid.uuid4())
        self._owner = (os.getpid(), threading.get_ident())
        self._entered, self._closed = False, False
        self._audit_failed = None
        self._admission_failed = None
        self._preparation_subject = None
        self._invalid_terminal = False
        self._logging = False

    def _thread(self):
        if self._owner != (os.getpid(), threading.get_ident()):
            raise BudgetError('Operation callback belongs to a different process/thread')

    def _open(self, db):
        self._thread()
        if not self._entered or self._closed:
            raise BudgetError('Operation scope is not active')
        row = db.execute('SELECT state,token FROM operations WHERE id=?', (self.id,)).fetchone()
        if row is None or row['state'] != 'open' or row['token'] != fingerprint(self._token):
            raise BudgetError('Operation closed or recovered')

    def __enter__(self):
        self._thread()
        if self._entered or self._closed:
            raise BudgetError('Operation scope is single-use')
        with self.budget._transaction() as db:
            row = db.execute('SELECT operations,active FROM budget WHERE id=1').fetchone()
            if row['operations'] >= self.budget.config['maxOperations'] or row['active'] >= self.budget.config['maxConcurrentOperations']:
                raise BudgetExhausted('Execution operation capacity exhausted')
            db.execute('INSERT INTO operations(id,actor,request,token,state,created) VALUES(?,?,?,?,?,?)',
                       (self.id, fingerprint(self.actor), self.request, fingerprint(self._token), 'open', time.time_ns()))
            db.execute('UPDATE budget SET operations=operations+1,active=active+1 WHERE id=1')
        self._entered = True
        return self

    def __exit__(self, exception_type, exception, traceback):
        self._thread()
        try:
            with self.budget._transaction() as db:
                self._open(db)
                if db.execute("SELECT 1 FROM stages WHERE operation=? AND state='active'", (self.id,)).fetchone():
                    if exception_type is None:
                        raise BudgetError('Unresolved stage retains operation capacity; quiescent recovery required')
                else:
                    state = 'failed' if exception_type else 'completed'
                    db.execute('UPDATE operations SET state=?,closed=? WHERE id=?', (state, time.time_ns(), self.id))
                    db.execute('UPDATE budget SET active=active-1 WHERE id=1')
        finally:
            self._closed = True
        return False

    @staticmethod
    def _reserved(kind, detail):
        if kind == 'classifier':
            return 1, units(detail, 'embeddingCallsReserved', (0, 1))
        if kind == 'extraction':
            return units(detail, 'processCallsReserved', (0, 1)), units(detail, 'modelCallsReserved', (0,))
        return (units(detail, 'processCallsReserved', (1,)),
                units(detail, 'modelExecutionsReserved', (int(kind in ('media.transcribe', 'recording.transcribe')),)))

    def _terminal(self, row, ending, detail):
        if ending == 'completed':
            usage = detail.get('usage')
            if not isinstance(usage, dict):
                raise BudgetError('Missing stage completion usage')
            if row['kind'] == 'classifier':
                units(usage, 'embeddingCalls', (row['models'],))
            else:
                units(usage, 'processCalls', (row['processes'],))
                units(usage, 'modelCalls' if row['kind'] == 'extraction' else 'modelExecutions', (row['models'],))
        else:
            key = 'executionUsage' if row['kind'] == 'classifier' else 'processingUsage'
            if detail.get(key) != 'unknown' or detail.get('reservationRetained') is not True:
                raise BudgetError('Failure must retain unknown reservations')
            if row['kind'] == 'extraction':
                units(detail, 'modelCalls', (0,))
            elif row['kind'] != 'classifier':
                units(detail, 'modelExecutionsReserved', (row['models'],))
            if row['kind'] == 'recording.decode':
                allowed = (0, 1) if self._admission_failed == row['id'] else (1,)
                units(detail, 'processCallsReserved', allowed)

    def log(self, event, actor, subject, detail):
        self._thread()
        if self._logging:
            raise BudgetError('Operation audit callback cannot reenter execution accounting')
        self._logging = True
        try:
            return self._log(event, actor, subject, detail)
        finally:
            self._logging = False

    def _log(self, event, actor, subject, detail):
        self._thread()
        if actor != self.actor or not isinstance(detail, dict):
            raise BudgetError('Wrong operation actor or detail')
        if event in REUSE_EVENTS:
            units(detail, 'processCalls', (0,))
            units(detail, 'modelExecutions', (0,))
        if len(encoded(detail)) > 65536:
            raise BudgetError('Budget metadata exceeds 64 KiB')
        subject_hash, detail_hash = fingerprint(label(subject)), fingerprint(detail)
        stage_id, terminal = None, False
        with self.budget._transaction() as db:
            self._open(db)
            if self._invalid_terminal:
                raise BudgetError('Invalid terminal accounting requires quiescent recovery')
            db.execute('UPDATE operations SET sequence=sequence+1 WHERE id=?', (self.id,))
            if event == 'recording.prepare.admitted':
                if self._preparation_subject is not None:
                    raise BudgetError('Recording preparation already active')
                units(detail, 'modelExecutionsReserved', (0,))
            if event in ADMISSIONS:
                kind = ADMISSIONS[event]
                process, model = self._reserved(kind, detail)
                if kind == 'recording.decode' and self._preparation_subject != subject_hash:
                    raise BudgetError('Recording decode does not match preparation')
                if db.execute("SELECT 1 FROM stages WHERE operation=? AND state='active'", (self.id,)).fetchone():
                    raise BudgetError('Operation already has an active stage')
                counters = db.execute('SELECT stages,processes,models FROM budget WHERE id=1').fetchone()
                if (counters['stages'] + 1 > self.budget.config['maxStages']
                        or counters['processes'] + process > self.budget.config['maxProcessAttempts']
                        or counters['models'] + model > self.budget.config['maxModelAttempts']):
                    raise BudgetExhausted('Execution stage capacity exhausted')
                stage_id = str(uuid.uuid4())
                db.execute('INSERT INTO stages VALUES(?,?,?,?,?,NULL,NULL,?,?,?, ?,NULL)',
                           (stage_id, self.id, kind, subject_hash, detail_hash, process, model, 'active', time.time_ns()))
                db.execute('UPDATE budget SET stages=stages+1,processes=processes+?,models=models+? WHERE id=1', (process, model))
                self._audit_failed = None
                self._admission_failed = None
            elif event in TERMINALS:
                kind, ending = TERMINALS[event]
                row = db.execute("SELECT * FROM stages WHERE operation=? AND state='active'", (self.id,)).fetchone()
                if row is None and ending == 'failed' and self._audit_failed:
                    row = db.execute('SELECT * FROM stages WHERE id=? AND operation=?', (self._audit_failed, self.id)).fetchone()
                    if row is None or row['kind'] != kind or row['subject'] != subject_hash:
                        raise BudgetError('Audit failure does not match completed stage')
                    self._terminal(row, ending, detail)
                    db.execute('UPDATE stages SET audit_failure=? WHERE id=?', (detail_hash, row['id']))
                    self._audit_failed = None
                elif row is None and event == 'recording.prepare.failed' and self._preparation_subject == subject_hash:
                    # Source preparation can fail before a decoder is admitted.
                    units(detail, 'processCallsReserved', (0,))
                    units(detail, 'modelExecutionsReserved', (0,))
                    if detail.get('processingUsage') != 'unknown' or detail.get('reservationRetained') is not True:
                        raise BudgetError('Invalid recording preparation failure')
                else:
                    if row is None or row['kind'] != kind or row['subject'] != subject_hash:
                        self._invalid_terminal = True
                        raise BudgetError('Terminal event does not match active stage')
                    try:
                        self._terminal(row, ending, detail)
                    except BudgetError:
                        self._invalid_terminal = True
                        raise
                    stage_id, terminal = row['id'], True
                    db.execute('UPDATE stages SET state=?,terminal=?,closed=? WHERE id=?',
                               (ending, detail_hash, time.time_ns(), stage_id))
                    if ending == 'completed':
                        db.execute('UPDATE budget SET known_processes=known_processes+?,known_models=known_models+? WHERE id=1',
                                   (row['processes'], row['models']))
            elif event not in PASS:
                raise BudgetError('Unregistered intake event')
        if event == 'recording.prepare.admitted':
            self._preparation_subject = subject_hash
        elif event in ('recording.prepare.completed', 'recording.prepare.failed'):
            self._preparation_subject = None
        try:
            self.audit(event, actor, subject, detail)
        except BaseException:
            if event in ADMISSIONS:
                self._admission_failed = stage_id
            elif terminal:
                self._audit_failed = stage_id
            raise
