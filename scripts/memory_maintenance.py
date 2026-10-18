"""Construct the host-selected private derived cache for physical maintenance."""
from pathlib import Path
from contextlib import contextmanager
import json
import os
import sqlite3
import time
from urllib.parse import quote

from brain_federation import fields
from context_host import _read, load_boundary, read_pinned
from federation_protection import SourceProtection
from execution_budget import private_path
from intake_processing_cache import APPLICATION_ID, SCHEMA, ProcessingCache, configuration, validator as cache_validator
from knowledge_policy import fingerprint, local_path


MAX_SCHEMA_OBJECTS = 3
MAX_SCHEMA_SQL_BYTES = 16384
MAX_MAINTENANCE_ENTRIES = 10000
MAX_MAINTENANCE_BYTES = 32 * 1024 * 1024
MAX_ENTRY_ID_BYTES = 64
MAX_ENTRY_KEY_BYTES = 64
MAX_ENTRY_HEADER_BYTES = 16384
MAX_ENTRY_PROTECTION_BYTES = 16384
MAX_ENTRY_BODY_BYTES = 4194304
MAX_INSPECTION_VM_STEPS = 5000000
MAX_INSPECTION_SECONDS = 5


def load_processing_cache(root, config_path, *, actor, now):
    """Return only the exact cache selected by a protected protocol-4 host."""
    root = Path(root)
    if root.is_symlink():
        raise ValueError('Intake root cannot be a symlink')
    config = _read(root, config_path)
    version = config.get('protocolVersion')
    required = ('protocolVersion', 'policy', 'bindings', 'scopes', 'intake', 'completed', 'limits',
                'classifier', 'projection')
    fields(config, required)
    if version != '4.0':
        raise ValueError('Physical cache maintenance requires a protocol-4 intake host')
    current_time = now() if callable(now) else now
    load_boundary(root, config, actor=actor, now=current_time)
    projection = read_pinned(root, config['projection'])
    fields(projection, ('profile', 'catalog', 'protection', 'reuse'))
    reuse = read_pinned(root, projection['reuse'])
    fields(reuse, ('cache', 'registrations'))
    fields(reuse['cache'], ('path', 'configSha256'))
    cache_path = root.resolve() / local_path(reuse['cache']['path'])
    fingerprint(reuse['cache']['configSha256'])
    registrations = read_pinned(root, reuse['registrations'])
    if not isinstance(registrations, dict) or not 1 <= len(registrations) <= 10000:
        raise ValueError('Bounded independent processing registrations required')
    for identity, registration in registrations.items():
        fingerprint(identity)
        fields(registration, ('original',))
        original = registration['original']
        if original is not None and (not cache_validator('header').is_valid(original)
                                     or original['itemSha256'] != identity):
            raise ValueError('Independent processing registration differs from original')

    def revalidate():
        if (_read(root, config_path) != config or read_pinned(root, config['projection']) != projection
                or read_pinned(root, projection['reuse']) != reuse
                or read_pinned(root, reuse['registrations']) != registrations):
            raise ValueError('Processing maintenance host selection changed')
        fresh_time = now() if callable(now) else now
        load_boundary(root, config, actor=actor, now=fresh_time)

    def authorization(identity, *, actor, at):
        if identity not in registrations:
            raise ValueError('Processing source is not registered by the selected host')
        revalidate()
        current, _ = load_boundary(root, config, actor=actor, now=at)
        protection = SourceProtection(read_pinned(root, projection['protection']), resources=current.policy.resources)
        return current, protection, registrations.get(identity, {}).get('original')

    cache = ProcessingCache(cache_path, expected_config_sha256=reuse['cache']['configSha256'],
                            authorization=authorization)
    return cache, revalidate


def maintain_processing_cache(cache, *, authority_path, revalidate=None):
    """Losslessly maintain the pinned derived cache without changing its API."""
    authority = Path(authority_path).resolve(strict=True)
    selected = cache.path.resolve(strict=True)
    if selected == authority or os.path.samefile(selected, authority):
        raise ValueError('Canonical authority cannot be physically maintained by cache tooling')
    if revalidate:
        revalidate()
    if private_path(cache.path)[1] != cache.identity:
        raise ValueError('Processing cache file identity changed')
    with cache._file_lock(exclusive=True):
        return _maintain_processing_cache_locked(cache, revalidate=revalidate)


def _maintain_processing_cache_locked(cache, *, revalidate=None):
    db = sqlite3.connect('file:' + quote(str(cache.path), safe='/') + '?mode=rw', uri=True,
                         isolation_level=None, timeout=0.25)
    try:
        with _inspection_budget(db):
            if (db.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID
                    or db.execute('PRAGMA user_version').fetchone()[0] != 1
                    or db.execute('PRAGMA journal_mode').fetchone()[0] != 'wal'):
                raise ValueError('Processing cache identity or schema changed')
            _check_schema(db)
            if _configuration_preflight(db):
                raise ValueError('Processing cache configuration exceeds its read bound')
            raw = db.execute('SELECT body FROM configuration WHERE id=1').fetchone()
            config = configuration(json.loads(raw[0]))
            if fingerprint(config) != cache.pin:
                raise ValueError('Processing cache configuration changed')
            count, actual_bytes, payload_bytes, largest_payload, invalid = _entry_preflight(db)
            if (count > config['maxEntries'] or count > MAX_MAINTENANCE_ENTRIES
                    or payload_bytes > config['maxBytes'] or payload_bytes > MAX_MAINTENANCE_BYTES
                    or actual_bytes > MAX_MAINTENANCE_BYTES
                    or largest_payload > config['maxReadBytes'] or invalid):
                raise ValueError('Processing cache exceeds its registered maintenance bounds')
        before = fingerprint(_logical_state(db, max_entries=config['maxEntries'], max_bytes=config['maxBytes'],
                                            max_read_bytes=config['maxReadBytes'], expected_pin=cache.pin))
        size_before = _database_bytes(cache.path)
        checkpoint = db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
        if checkpoint[0] or checkpoint[1] != checkpoint[2]:
            raise ValueError('Processing cache has an active or incomplete WAL checkpoint')
        # Keep WAL mode for existing readers. The shared file lock coordinates
        # cooperating cache users; the bounded checkpoint refuses only when it
        # cannot complete while preserving an uncoordinated reader's snapshot.
        _run_vacuum(db)
        after = fingerprint(_logical_state(db, max_entries=config['maxEntries'], max_bytes=config['maxBytes'],
                                           max_read_bytes=config['maxReadBytes'], expected_pin=cache.pin))
        with _inspection_budget(db):
            integrity = db.execute('PRAGMA integrity_check').fetchone()[0]
        if before != after or integrity != 'ok':
            raise ValueError('Lossless cache maintenance verification failed')
        if revalidate:
            revalidate()
        if (private_path(cache.path)[1] != cache.identity
                or db.execute('PRAGMA journal_mode').fetchone()[0] != 'wal'):
            raise ValueError('Processing cache identity or journal mode changed during maintenance')
        size_after = _database_bytes(cache.path)
        return {'format': 'processing-cache-maintenance/v1', 'cacheIdentity': cache.identity,
                'logicalStateSha256': after, 'integrity': integrity,
                'sizeBeforeBytes': size_before, 'sizeAfterBytes': size_after,
                'sizeDeltaBytes': size_after - size_before,
                'changedBytes': size_before != size_after, 'canonicalAuthorityTouched': False}
    except sqlite3.Error as exc:
        raise ValueError('Processing cache is busy or unavailable for maintenance') from exc
    finally:
        db.close()


def _logical_state(db, *, max_entries, max_bytes, max_read_bytes, expected_pin):
    with _inspection_budget(db):
        schema = _check_schema(db)
        if _configuration_preflight(db):
            raise ValueError('Processing cache configuration exceeds its read bound')
        raw_config = db.execute('SELECT body FROM configuration WHERE id=1').fetchone()[0]
        if fingerprint(configuration(json.loads(raw_config))) != expected_pin:
            raise ValueError('Processing cache configuration changed')
        count, actual_bytes, payload_bytes, largest_payload, invalid = _entry_preflight(db)
        if (count > min(max_entries, MAX_MAINTENANCE_ENTRIES)
                or payload_bytes > max_bytes or payload_bytes > MAX_MAINTENANCE_BYTES
                or actual_bytes > MAX_MAINTENANCE_BYTES or largest_payload > max_read_bytes or invalid):
            raise ValueError('Processing cache exceeds its registered maintenance bounds')
        config_rows = [[[type(value).__name__, value] for value in row]
                       for row in db.execute('SELECT id,body FROM configuration ORDER BY id')]
        entry_rows = []
        for row in db.execute('SELECT id,lookup_key,header,protection,body,bytes FROM entries ORDER BY id'):
            entry_rows.append([[type(value).__name__, value] for value in row])
        if len(entry_rows) != count:
            raise ValueError('Processing cache changed during bounded inspection')
        return {'schema': schema,
                'tables': {'configuration': {'columns': ['id', 'body'], 'rows': config_rows},
                           'entries': {'columns': ['id', 'lookup_key', 'header', 'protection', 'body', 'bytes'],
                                       'rows': entry_rows}},
                'applicationId': db.execute('PRAGMA application_id').fetchone()[0],
                'userVersion': db.execute('PRAGMA user_version').fetchone()[0]}


def _configuration_preflight(db):
    count, invalid = db.execute(
        "SELECT count(*),coalesce(sum(CASE WHEN id!=1 OR typeof(body)!='text' "
        "OR length(CAST(body AS BLOB))>16384 THEN 1 ELSE 0 END),0) FROM configuration").fetchone()
    return count != 1 or bool(invalid)


@contextmanager
def _inspection_budget(db):
    steps = 0
    deadline = time.monotonic() + MAX_INSPECTION_SECONDS

    def progress():
        nonlocal steps
        steps += 1000
        return int(steps > MAX_INSPECTION_VM_STEPS or time.monotonic() > deadline)

    db.set_progress_handler(progress, 1000)
    try:
        yield
    finally:
        db.set_progress_handler(None, 0)


def _check_schema(db):
    count, largest, total = db.execute(
        "SELECT count(*),coalesce(max(length(CAST(sql AS BLOB))),0),"
        "coalesce(sum(length(CAST(sql AS BLOB))),0) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchone()
    if count != MAX_SCHEMA_OBJECTS or largest > MAX_SCHEMA_SQL_BYTES or total > MAX_SCHEMA_SQL_BYTES:
        raise ValueError('Processing cache schema exceeds its fixed maintenance bounds')
    actual = [tuple(row) for row in db.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")]
    expected_db = sqlite3.connect(':memory:')
    try:
        expected_db.executescript(SCHEMA)
        expected = [tuple(row) for row in expected_db.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")]
    finally:
        expected_db.close()
    if actual != expected:
        raise ValueError('Processing cache schema changed')
    return actual


def _entry_preflight(db):
    query = f'''SELECT count(*),
        coalesce(sum(length(CAST(id AS BLOB))+length(CAST(lookup_key AS BLOB))+
                      length(CAST(header AS BLOB))+length(CAST(protection AS BLOB))+
                      length(CAST(body AS BLOB))),0),
        coalesce(sum(length(CAST(header AS BLOB))+length(CAST(protection AS BLOB))+
                      length(CAST(body AS BLOB))),0),
        coalesce(max(length(CAST(header AS BLOB))+length(CAST(protection AS BLOB))+
                     length(CAST(body AS BLOB))),0),
        coalesce(sum(CASE WHEN typeof(id)!='text' OR typeof(lookup_key)!='text'
                          OR typeof(header)!='text' OR typeof(protection)!='text'
                          OR typeof(body)!='text' OR typeof(bytes)!='integer'
                          OR length(CAST(id AS BLOB))>{MAX_ENTRY_ID_BYTES}
                          OR length(CAST(lookup_key AS BLOB))>{MAX_ENTRY_KEY_BYTES}
                          OR length(CAST(header AS BLOB))>{MAX_ENTRY_HEADER_BYTES}
                          OR length(CAST(protection AS BLOB))>{MAX_ENTRY_PROTECTION_BYTES}
                          OR length(CAST(body AS BLOB))>{MAX_ENTRY_BODY_BYTES}
                          OR bytes != length(CAST(header AS BLOB))+length(CAST(protection AS BLOB))+
                                     length(CAST(body AS BLOB)) THEN 1 ELSE 0 END),0)
        FROM entries'''
    count, actual_bytes, payload_bytes, largest_payload, invalid = db.execute(query).fetchone()
    return count, actual_bytes, payload_bytes, largest_payload, invalid


def _run_vacuum(db):
    db.execute('VACUUM')
    db.execute('REINDEX')


def _database_bytes(path):
    total = 0
    for suffix in ('', '-wal', '-shm'):
        try:
            total += Path(str(path) + suffix).stat().st_size
        except FileNotFoundError:
            pass
    return total
