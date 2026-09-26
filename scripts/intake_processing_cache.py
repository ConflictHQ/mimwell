"""Private completed-artifact reuse; never a processing scheduler or writer grant.

The host independently selects current source registrations, protection and the
original body-free representation header. Cache state cannot authorize itself. Only completed
whole-source document/short-media representations can be adopted.
"""
from contextlib import contextmanager
from copy import deepcopy
from functools import lru_cache
import json
import os
from pathlib import Path
import sqlite3
import time
from urllib.parse import quote

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from brain_protection import assess, combine, fields, requirements
from context_access import ReadBoundary
from context_bundle import encode
from execution_budget import digest, private_path
from federation_protection import SourceProtection, plaintext_profile
from intake_capture import bind_capture
from intake_contract import IntakeError
from intake_extraction import profile_check
from intake_media import DEMUXERS, check_capsule, check_profile, model_identity
from intake_processed import bounded, check as representation_check
from knowledge_policy import fingerprint, timestamp

FORMAT = 'intake-processing-reuse/v1'
SUPPORTED = ('intake-extraction/v1', 'intake-transcription/v1', 'intake-transcription/v2')
APPLICATION_ID = 1112688453
SCHEMA = """
CREATE TABLE configuration (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL);
CREATE TABLE entries (id TEXT PRIMARY KEY, lookup_key TEXT NOT NULL,
 header TEXT NOT NULL, protection TEXT NOT NULL, body TEXT NOT NULL, bytes INTEGER NOT NULL);
CREATE INDEX entry_keys ON entries(lookup_key,id);
PRAGMA user_version=1;
"""


class ReuseUnavailable(IntakeError):
    """Do not silently turn unavailable or corrupt retained work into a cache miss."""


@lru_cache(maxsize=None)
def validator(name):
    root = Path(__file__).resolve().parents[1] / 'schemas'
    registry = Registry()
    for filename in ('intake.schema.json', 'intake-extraction.schema.json', 'intake-transcription.schema.json',
                     'intake-transcription-v2.schema.json', 'intake-recording.schema.json',
                     'intake-recording-transcription.schema.json', 'intake-processed-delivery-v3.schema.json'):
        document = json.loads((root / filename).read_text())
        registry = registry.with_resource(document['$id'], Resource.from_contents(document))
    schema = json.loads((root / 'intake-processing-reuse.schema.json').read_text())
    if name == 'selection':
        registry = registry.with_resource(schema['$id'], Resource.from_contents(schema))
        return Draft202012Validator(json.loads((root / 'intake-reuse-selection.schema.json').read_text()), registry=registry)
    return Draft202012Validator({'$ref': '#/$defs/' + name, '$defs': schema['$defs']}, registry=registry)


def require_retention(required):
    if not assess(required, plaintext_profile(), operation='derive', offline=True)['supported']:
        raise ReuseUnavailable('Private persistent cache cannot satisfy source protection')


def configuration(value):
    bounded(value)
    if not validator('configuration').is_valid(value) or len(encode(value)) > 16384:
        raise IntakeError('Invalid processing cache configuration')
    return deepcopy(value)


def header(representation):
    representation_check(representation, 'representation')
    receipt = representation['receipt']
    if receipt['format'] not in SUPPORTED:
        raise IntakeError('Processing cache does not support this receipt format')
    source = receipt['item']['source']
    model = None
    if receipt['format'] != 'intake-extraction/v1':
        model = {key: receipt['dependencies'][key] for key in ('modelIdentity', 'modelResource')}
    return {'representationSha256': fingerprint(representation), 'receiptSha256': representation['sha256'],
            'itemSha256': fingerprint(receipt['item']), 'sourceResource': representation['sourceResource'],
            'scope': representation['scope'], 'policySha256': receipt['policySha256'],
            'profileSha256': receipt['profileSha256'], 'processingFormat': receipt['format'],
            'content': {key: source[key] for key in ('sha256', 'byteLength', 'mediaType')}, 'model': model}


def key_for(content, profile_sha256, policy_sha256, scope, producer_sha256):
    return fingerprint({'content': content, 'profileSha256': profile_sha256, 'policySha256': policy_sha256,
                        'scope': scope, 'producerSha256': producer_sha256})


def check_receipt(receipt):
    """Historical consistency only. Live use additionally requires cache.authorize()."""
    bounded(receipt)
    if not validator('receipt').is_valid(receipt):
        raise IntakeError('Invalid processing reuse receipt')
    origin = header(receipt['original'])
    source = receipt['item']['source']
    content = {key: source[key] for key in ('sha256', 'byteLength', 'mediaType')}
    key = key_for(content, origin['profileSha256'], receipt['policySha256'], receipt['scope'],
                  receipt['cache']['producerSha256'])
    requirements(receipt['retainedProtection']['requirements'])
    requirements(receipt['protection']['requirements'])
    if (content != origin['content'] or receipt['cache']['entrySha256'] != origin['representationSha256']
            or receipt['cache']['keySha256'] != key or receipt['scope'] != origin['scope']
            or receipt['scope'] not in receipt['scopes'] or receipt['policySha256'] != origin['policySha256']
            or receipt['usage']['sourceBytes'] != source['byteLength']
            or timestamp(receipt['original']['receipt']['evaluatedAt']) > timestamp(receipt['evaluatedAt'])
            or combine(receipt['retainedProtection']['requirements'], receipt['protection']['requirements'])
                != receipt['protection']['requirements']):
        raise IntakeError('Processing reuse content, lineage or protection changed')
    require_retention(receipt['protection']['requirements'])


class ProcessingCache:
    """Adopt explicit completed receipts; bounded lookup, eviction and exact reopen.

    authorization(item_sha256, actor=..., at=...) must reload independent host state
    and return (ReadBoundary, SourceProtection, selected_original_header).
    The independently selected header is required for origins; it may be None for a new
    captured reference. Unknown/withdrawn references must refuse. A received item,
    cache header or reuse receipt must never populate that host registry implicitly.
    """

    @classmethod
    def initialize(cls, path, config, *, authorization):
        config = configuration(config)
        if not callable(authorization):
            raise IntakeError('Current processing cache authorization provider required')
        path, _ = private_path(path, exists=False)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        db = sqlite3.connect(path, isolation_level=None)
        try:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('PRAGMA synchronous=FULL')
            db.executescript('BEGIN IMMEDIATE;\n' + SCHEMA)
            db.execute('INSERT INTO configuration VALUES (1,?)', (encode(config).decode(),))
            db.execute(f'PRAGMA application_id={APPLICATION_ID}')
            db.commit()
        finally:
            db.close()
        return cls(path, expected_config_sha256=fingerprint(config), authorization=authorization)

    def __init__(self, path, *, expected_config_sha256, authorization):
        if not callable(authorization):
            raise IntakeError('Current processing cache authorization provider required')
        self.path, self.identity = private_path(path)
        self.pin, self.authorization = digest(expected_config_sha256), authorization
        with self._transaction() as db:
            self._config = configuration(json.loads(db.execute('SELECT body FROM configuration WHERE id=1').fetchone()[0]))

    @property
    def config(self):
        return deepcopy(self._config)

    @contextmanager
    def _transaction(self, *, write=False):
        db = None
        try:
            if private_path(self.path)[1] != self.identity:
                raise ReuseUnavailable('Processing cache file identity changed')
            db = sqlite3.connect('file:' + quote(str(self.path), safe='/') + '?mode=rw',
                                 uri=True, isolation_level=None, timeout=0.25)
            db.row_factory = sqlite3.Row
            db.execute('PRAGMA synchronous=FULL')
            if (private_path(self.path)[1] != self.identity
                    or db.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID
                    or db.execute('PRAGMA user_version').fetchone()[0] != 1
                    or db.execute('PRAGMA journal_mode').fetchone()[0] != 'wal'):
                raise ReuseUnavailable('Processing cache identity or schema changed')
            db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
            size = db.execute('SELECT length(CAST(body AS BLOB)) FROM configuration WHERE id=1').fetchone()
            if size is None or size[0] > 16384:
                raise ReuseUnavailable('Processing cache configuration exceeds its read bound')
            row = db.execute('SELECT body FROM configuration WHERE id=1').fetchone()
            if fingerprint(configuration(json.loads(row[0]))) != self.pin:
                raise ReuseUnavailable('Processing cache configuration changed')
            yield db
            db.commit()
        except sqlite3.Error as exc:
            raise ReuseUnavailable('Processing cache unavailable; no new execution is authorized') from exc
        finally:
            if db is not None:
                db.close()

    def _state(self, item_sha256, actor, at):
        boundary, protection, selected = self.authorization(item_sha256, actor=actor, at=at)
        if (not isinstance(boundary, ReadBoundary) or not isinstance(protection, SourceProtection)
                or boundary.actor != actor or boundary.now != at
                or not boundary.permits('references', item_sha256)):
            raise ReuseUnavailable('Current processing source unavailable')
        return boundary, protection, selected

    def _original(self, selected, actor, at):
        boundary, protection, current_header = self._state(selected['itemSha256'], actor, at)
        references = {selected['itemSha256']: selected['sourceResource']}
        if selected['model']:
            references[selected['model']['modelIdentity']] = selected['model']['modelResource']
        if (current_header != selected or boundary.policy.binding['sha256'] != selected['policySha256']
                or any(boundary.bindings['references'].get(identity) != resource
                       or boundary.policy.resources.get(resource, {}).get('scope') != selected['scope']
                       or not boundary.permits('references', identity) for identity, resource in references.items())):
            raise ReuseUnavailable('Current original processing selection or dependencies unavailable')
        required = protection.for_resources(list(references.values()))
        require_retention(required)
        return boundary, {'policySha256': protection.sha256, 'requirements': required}

    def remember(self, representation, *, expected_sha256, producer_sha256, actor, at, log, fault=None):
        """Host adopts successful processing only; failed/unknown work has no entry."""
        selected = header(representation)
        if (selected['representationSha256'] != digest(expected_sha256)
                or digest(producer_sha256) != self._config['producerSha256'] or not callable(log)
                or timestamp(representation['receipt']['evaluatedAt']) > timestamp(at)):
            raise IntakeError('Processing adoption pin or producer changed')
        representation = deepcopy(representation)
        _, protection = self._original(selected, actor, at)
        key = key_for(selected['content'], selected['profileSha256'], selected['policySha256'], selected['scope'], producer_sha256)
        body = encode(representation).decode()
        encoded_header, encoded_protection = encode(selected).decode(), encode(protection).decode()
        if len(encoded_header.encode()) > 16384 or len(encoded_protection.encode()) > 16384:
            raise IntakeError('Processing cache metadata exceeds its read bound')
        size = len(body.encode()) + len(encoded_header.encode()) + len(encoded_protection.encode())
        identity = selected['representationSha256']
        log('processing.cache.admitted', actor, identity, {'producerSha256': producer_sha256,
            'processCalls': 0, 'modelExecutions': 0})
        with self._transaction(write=True) as db:
            sizes = self._rows(db, 'id=?', (identity,), 1)
            if sizes and (sizes[0]['header_bytes'] > 16384 or sizes[0]['protection_bytes'] > 16384
                          or sizes[0]['body_bytes'] > 4194304):
                raise ReuseUnavailable('Existing processing cache entry exceeds its read bound')
            old = db.execute('SELECT * FROM entries WHERE id=?', (identity,)).fetchone()
            if old is not None:
                if (old['lookup_key'], old['header'], old['body'], old['bytes']) != (key, encoded_header, body,
                        len(body.encode()) + len(encoded_header.encode()) + len(old['protection'].encode())):
                    raise ReuseUnavailable('Existing processing entry changed')
                require_retention(combine(json.loads(old['protection'])['requirements'], protection['requirements']))
            else:
                count, used = db.execute('SELECT count(*),coalesce(sum(length(CAST(body AS BLOB))+length(CAST(header AS BLOB))+length(CAST(protection AS BLOB))),0) FROM entries').fetchone()
                if count >= self._config['maxEntries'] or used + size > self._config['maxBytes']:
                    raise ReuseUnavailable('Processing cache capacity exhausted; explicit eviction required')
                db.execute('INSERT INTO entries VALUES (?,?,?,?,?,?)',
                           (identity, key, encoded_header, encoded_protection, body, size))
            if fault:
                fault('before-commit')
            _, current = self._original(selected, actor, at)
            if current != protection:
                raise ReuseUnavailable('Processing protection changed before cache commit')
        if fault:
            fault('after-commit')
        log('processing.cache.completed', actor, identity, {'entrySha256': identity,
            'processCalls': 0, 'modelExecutions': 0})
        return identity

    def evict(self, identity):
        """Host-only exact eviction; never deletes an external source or budget row."""
        with self._transaction(write=True) as db:
            return db.execute('DELETE FROM entries WHERE id=?', (digest(identity),)).rowcount == 1

    def _load(self, db, row, actor, at, before_body, budget):
        if row['header_bytes'] > 16384 or row['protection_bytes'] > 16384 or row['body_bytes'] > 4194304:
            raise ReuseUnavailable('Processing cache entry exceeds its read bound')
        size = row['header_bytes'] + row['protection_bytes'] + row['body_bytes']
        if size > budget[0]:
            raise ReuseUnavailable('Processing candidate bytes exceeded')
        budget[0] -= size
        metadata = db.execute('SELECT header,protection FROM entries WHERE id=?', (row['id'],)).fetchone()
        selected, protection = json.loads(metadata['header']), json.loads(metadata['protection'])
        if not validator('header').is_valid(selected) or selected['representationSha256'] != row['id']:
            raise ReuseUnavailable('Invalid processing cache header')
        fields(protection, ('policySha256', 'requirements'))
        digest(protection['policySha256'])
        requirements(protection['requirements'])
        _, current = self._original(selected, actor, at)  # before reading retained text
        require_retention(combine(protection['requirements'], current['requirements']))
        before_body()
        representation = self._body(db, row['id'])
        if header(representation) != selected:
            raise ReuseUnavailable('Processing body differs from independently selected origin')
        return representation, selected, protection

    @staticmethod
    def _body(db, identity):
        return json.loads(db.execute('SELECT body FROM entries WHERE id=?', (identity,)).fetchone()[0])

    @staticmethod
    def _rows(db, where, args, limit):
        return db.execute('SELECT id,lookup_key,length(CAST(header AS BLOB)) AS header_bytes,'
            'length(CAST(protection AS BLOB)) AS protection_bytes,length(CAST(body AS BLOB)) AS body_bytes '
            'FROM entries WHERE ' + where + ' ORDER BY id LIMIT ?', (*args, limit)).fetchall()

    def _target(self, item, profile, actor, at):
        model = model_identity(profile['model']['sha256']) if profile.get('format', '').startswith('intake-media-profile/') else None
        return self._target_reference(fingerprint(item), model, actor, at)

    def _target_reference(self, identity, model, actor, at):
        boundary, protection, _ = self._state(identity, actor, at)
        source = boundary.bindings['references'][identity]
        scope = boundary.policy.resources[source]['scope']
        resources = [source]
        if model:
            resource = boundary.bindings['references'].get(model)
            if (not resource or not boundary.permits('references', model)
                    or boundary.policy.resources.get(resource, {}).get('scope') != scope):
                raise ReuseUnavailable('Current processing model unavailable or cross-scope')
            resources.append(resource)
        required = protection.for_resources(resources)
        require_retention(required)
        return boundary, source, scope, {'policySha256': protection.sha256, 'requirements': required}

    def reuse(self, registration, capsule, *, expected_sha256, profile, actor, at, log):
        """Return a new reference-bound receipt or a true miss; never execute work."""
        if not callable(log):
            raise IntakeError('Durable processing reuse audit required')
        if isinstance(profile, dict) and profile.get('adapter') in ('utf8-text/v1', 'poppler-text/v1'):
            profile_check(profile)
        else:
            check_profile(profile)
        check_capsule(capsule, registration, profile['maxSourceBytes'])
        registration, capsule, profile = deepcopy(registration), deepcopy(capsule), deepcopy(profile)
        item = capsule['receipt']['item']
        media = item['source']['mediaType']
        allowed = (('application/pdf',) if profile.get('adapter') == 'poppler-text/v1' else
                   ('text/plain', 'text/markdown')) if 'adapter' in profile else DEMUXERS
        if media not in allowed:
            raise IntakeError('Processing reuse profile does not accept declared media type')
        initial, source, scope, protection = self._target(item, profile, actor, at)
        bound, observed, _ = bind_capture(initial, registration, capsule, expected_sha256=expected_sha256, log=log)
        if bound.bindings != initial.bindings or observed != item:
            raise ReuseUnavailable('New source differs from independent host registration')
        content = {key: item['source'][key] for key in ('sha256', 'byteLength', 'mediaType')}
        key = key_for(content, fingerprint(profile), initial.policy.binding['sha256'], scope, self._config['producerSha256'])
        log('processing.reuse.admitted', actor, fingerprint(item), {'keySha256': key,
            'processCalls': 0, 'modelExecutions': 0})
        started = time.perf_counter_ns()
        result = None
        budget = [self._config['maxReadBytes']]
        def current_target():
            current, current_source, current_scope, current_protection = self._target(item, profile, actor, at)
            if (current.policy.binding != initial.policy.binding or current.bindings != initial.bindings
                    or current.scopes != initial.scopes
                    or (current_source, current_scope, current_protection) != (source, scope, protection)):
                raise ReuseUnavailable('New source changed before processing body read')
        with self._transaction() as db:
            rows = self._rows(db, 'lookup_key=?', (key,), self._config['maxCandidates'] + 1)
            if len(rows) > self._config['maxCandidates']:
                raise ReuseUnavailable('Processing candidate limit exceeded')
            for row in rows:
                original, selected, retained = self._load(db, row, actor, at, current_target, budget)
                if key_for(selected['content'], selected['profileSha256'], selected['policySha256'],
                           selected['scope'], self._config['producerSha256']) != key:
                    raise ReuseUnavailable('Processing index key changed')
                _, original_protection = self._original(selected, actor, at)
                result = {'format': FORMAT, 'cache': {'id': self._config['id'], 'configSha256': self.pin,
                    'producerSha256': self._config['producerSha256'], 'entrySha256': row['id'], 'keySha256': key},
                    'item': deepcopy(item), 'captureSha256': expected_sha256, 'original': original,
                    'principal': actor, 'evaluatedAt': at, 'policySha256': initial.policy.binding['sha256'],
                    'bindingsSha256': fingerprint(initial.bindings), 'scopes': sorted(initial.scopes),
                    'sourceResource': source, 'scope': scope, 'retainedProtection': retained,
                    'protection': {'originalPolicySha256': original_protection['policySha256'],
                        'sourcePolicySha256': protection['policySha256'],
                        'requirements': combine(retained['requirements'], original_protection['requirements'], protection['requirements'])},
                    'usage': {'sourceBytes': content['byteLength'], 'processCalls': 0, 'modelExecutions': 0,
                              'elapsedMs': (time.perf_counter_ns()-started)/1e6}}
                check_receipt(result)
                break
        current, new_source, new_scope, new_protection = self._target(item, profile, actor, at)
        if (current.policy.binding != initial.policy.binding or current.bindings != initial.bindings
                or current.scopes != initial.scopes or (new_source, new_scope, new_protection) != (source, scope, protection)):
            raise ReuseUnavailable('New source authorization changed during processing reuse')
        if result is not None:
            self._authorize(result, actor=actor, at=at, budget=budget)
        log('processing.reuse.completed' if result is not None else 'processing.reuse.miss', actor,
            fingerprint(item), {'receiptSha256': fingerprint(result) if result is not None else None,
                'processCalls': 0, 'modelExecutions': 0})
        if result is not None:
            self._authorize(result, actor=actor, at=at, budget=budget)
        else:
            current_target()
        return result

    def authorize_selection(self, value, *, actor, at):
        """Live body-free dependency gate for an independently selected text header."""
        check_selection(value)
        value = deepcopy(value)
        original = value['original']
        selected_cache = value['cache']
        key = key_for(original['content'], original['profileSha256'], value['policySha256'],
                      value['scope'], self._config['producerSha256'])
        if (selected_cache != {'id':self._config['id'], 'configSha256':self.pin,
                'producerSha256':self._config['producerSha256'], 'entrySha256':original['representationSha256'],
                'keySha256':key} or value['policySha256'] != original['policySha256']
                or value['scope'] != original['scope'] or timestamp(value['evaluatedAt']) > timestamp(at)):
            raise ReuseUnavailable('Processing reuse selection pins changed')
        model = original['model']['modelIdentity'] if original['model'] else None
        initial = self._target_reference(value['itemSha256'], model, actor, at)
        def target():
            current = self._target_reference(value['itemSha256'], model, actor, at)
            if (current[0].policy.binding != initial[0].policy.binding
                    or current[0].bindings != initial[0].bindings or current[0].scopes != initial[0].scopes
                    or current[1:] != initial[1:] or current[1:3] != (value['sourceResource'], value['scope'])
                    or current[0].policy.binding['sha256'] != value['policySha256']):
                raise ReuseUnavailable('Processing reuse target selection changed')
            return current
        target()
        with self._transaction() as db:
            rows = self._rows(db, 'id=?', (selected_cache['entrySha256'],), 1)
            if not rows or rows[0]['lookup_key'] != key:
                raise ReuseUnavailable('Processing reuse selected entry unavailable')
            representation, observed, retained = self._load(db, rows[0], actor, at, target, [self._config['maxReadBytes']])
            if (observed != original or retained != value['retainedProtection']
                    or timestamp(representation['receipt']['evaluatedAt']) > timestamp(value['evaluatedAt'])):
                raise ReuseUnavailable('Processing reuse selected origin changed')
        _, source_protection = self._original(original, actor, at)
        current = target()
        required = combine(retained['requirements'], source_protection['requirements'], current[3]['requirements'])
        if value['protection'] != {'originalPolicySha256':source_protection['policySha256'],
                'sourcePolicySha256':current[3]['policySha256'], 'requirements':required}:
            raise ReuseUnavailable('Processing reuse selected protection changed')
        return current[0]

    def authorize(self, receipt, *, actor, at):
        """Fresh origin availability and all current grants; returns no cached body."""
        return self._authorize(receipt, actor=actor, at=at, budget=[self._config['maxReadBytes']])

    def _authorize(self, receipt, *, actor, at, budget):
        check_receipt(receipt)
        if receipt['cache']['configSha256'] != self.pin or receipt['cache']['id'] != self._config['id']:
            raise ReuseUnavailable('Reuse receipt belongs to another cache configuration')
        if receipt['cache']['producerSha256'] != self._config['producerSha256']:
            raise ReuseUnavailable('Reuse producer differs from cache configuration')
        selected = header(receipt['original'])
        initial, initial_source, initial_scope, initial_protection = self._target(
            receipt['item'], receipt['original']['receipt']['profile'], actor, at)
        def current_target():
            current, source, scope, protection = self._target(
                receipt['item'], receipt['original']['receipt']['profile'], actor, at)
            if (current.policy.binding != initial.policy.binding or current.bindings != initial.bindings
                    or current.scopes != initial.scopes
                    or (source, scope, protection) != (initial_source, initial_scope, initial_protection)):
                raise ReuseUnavailable('Reuse target changed before cached body read')
        with self._transaction() as db:
            rows = self._rows(db, 'id=?', (receipt['cache']['entrySha256'],), 1)
            if not rows or rows[0]['lookup_key'] != receipt['cache']['keySha256']:
                raise ReuseUnavailable('Original processing cache entry unavailable')
            original, observed, retained = self._load(db, rows[0], actor, at, current_target, budget)
            if original != receipt['original'] or observed != selected or retained != receipt['retainedProtection']:
                raise ReuseUnavailable('Original processing dependency changed')
        _, original_protection = self._original(selected, actor, at)
        boundary, source, scope, protection = self._target(receipt['item'], receipt['original']['receipt']['profile'], actor, at)
        required = combine(retained['requirements'], original_protection['requirements'], protection['requirements'])
        if (boundary.bindings != initial.bindings or boundary.policy.binding != initial.policy.binding
                or boundary.scopes != initial.scopes
                or (source, scope, protection) != (initial_source, initial_scope, initial_protection)
                or timestamp(receipt['evaluatedAt']) > timestamp(at)
                or source != receipt['sourceResource'] or scope != receipt['scope']
                or boundary.policy.binding['sha256'] != receipt['policySha256']
                or required != receipt['protection']['requirements']
                or original_protection['policySha256'] != receipt['protection']['originalPolicySha256']
                or protection['policySha256'] != receipt['protection']['sourcePolicySha256']):
            raise ReuseUnavailable('Current processing reuse protection or source binding changed')
        return boundary


def selection(receipt):
    """Body-free commitment; the host must select it independently of a request."""
    check_receipt(receipt)
    return {'format':'intake-reuse-selection/v1', 'itemSha256':fingerprint(receipt['item']),
            'original':header(receipt['original']), **{key:deepcopy(receipt[key]) for key in
            ('cache','sourceResource','scope','policySha256','retainedProtection','protection','evaluatedAt')}}


def check_selection(value):
    """Historical commitment consistency; no source or cache availability claim."""
    bounded(value)
    if not validator('selection').is_valid(value):
        raise IntakeError('Invalid processing reuse selection')
    original, cache = value['original'], value['cache']
    requirements(value['retainedProtection']['requirements'])
    requirements(value['protection']['requirements'])
    timestamp(value['evaluatedAt'])
    key = key_for(original['content'], original['profileSha256'], value['policySha256'],
                  value['scope'], cache['producerSha256'])
    if (cache['entrySha256'] != original['representationSha256'] or cache['keySha256'] != key
            or value['scope'] != original['scope'] or value['policySha256'] != original['policySha256']
            or combine(value['retainedProtection']['requirements'], value['protection']['requirements'])
                != value['protection']['requirements']):
        raise IntakeError('Processing reuse selection lineage or protection changed')
    require_retention(value['protection']['requirements'])
