"""Mechanical mapping for bounded connector export JSONL; no host or writer authority."""
import base64
from copy import deepcopy
import contextlib
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import fcntl

from context_bundle import encode
from context_access import ReadBoundary
from intake_capture import CaptureError, open_directory
from intake_contract import IntakeError
from knowledge_policy import fingerprint

MAX_LINE_BYTES = 1_048_576
MAX_EVENTS = 1000
MAX_LEDGER_EVENTS = 10000
MAX_LEDGER_BYTES = 8 * 1024 * 1024


class ConnectorEventError(ValueError):
    pass


@lru_cache(maxsize=1)
def _validator():
    from jsonschema import Draft202012Validator
    schema = json.loads((Path(__file__).resolve().parents[1] / 'schemas/connector-event.schema.json').read_text())
    return Draft202012Validator(schema)


@lru_cache(maxsize=1)
def _capture_validator():
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    root = Path(__file__).resolve().parents[1] / 'schemas'
    schema = json.loads((root / 'connector-capture.schema.json').read_text())
    intake = json.loads((root / 'intake.schema.json').read_text())
    registry = Registry().with_resource(intake['$id'], Resource.from_contents(intake))
    return Draft202012Validator(schema, registry=registry)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConnectorEventError('Duplicate JSON field')
        result[key] = value
    return result


def validate(value):
    if not isinstance(value, dict) or not _validator().is_valid(value):
        raise ConnectorEventError('Invalid connector event')
    payload = value['payload']
    try:
        raw = base64.b64decode(payload['data'], validate=True)
    except (ValueError, TypeError) as exc:
        raise ConnectorEventError('Invalid connector payload encoding') from exc
    if (base64.b64encode(raw).decode('ascii') != payload['data']
            or len(raw) != payload['byteLength']
            or hashlib.sha256(raw).hexdigest() != payload['sha256']):
        raise ConnectorEventError('Connector payload digest or length changed')
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise ConnectorEventError('Pilot accepts UTF-8 text payloads only') from exc
    if value['operation'] in ('upsert', 'edit') and text != value['text']:
        raise ConnectorEventError('Connector text differs from exported source bytes')
    if value['operation'] in ('delete', 'access-change') and raw:
        raise ConnectorEventError('Control events must not carry replacement content')
    return raw


def decode_line(raw):
    if not isinstance(raw, bytes) or not raw.endswith(b'\n') or len(raw) > MAX_LINE_BYTES:
        raise ConnectorEventError('Connector JSONL requires bounded LF-terminated records')
    try:
        value = json.loads(raw[:-1].decode('utf-8'), object_pairs_hook=_pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(
                               ConnectorEventError('Non-finite JSON number')))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConnectorEventError('Invalid connector JSONL record') from exc
    validate(value)
    return value


class EventLedger:
    """Replay/order check with explicit native receipt progress."""
    def __init__(self, state=None):
        self.last = {}
        self.seen = {}
        self.progress = {}
        self.checkpoints = {}
        self.dead_letters = []
        if state is not None:
            if (not isinstance(state, dict) or state.get('format') not in ('connector-ledger/v1', 'connector-ledger/v2', 'connector-ledger/v3')
                    or set(state) != ({'format', 'last', 'seen', 'progress'} if state['format'] == 'connector-ledger/v1'
                                      else {'format', 'last', 'seen', 'progress', 'checkpoints', 'deadLetters'})
                    or not isinstance(state['last'], dict) or not isinstance(state['seen'], dict)
                    or not isinstance(state['progress'], dict)
                    or len(state['seen']) > MAX_LEDGER_EVENTS or set(state['progress']) != set(state['seen'])):
                raise ConnectorEventError('Invalid connector ledger')
            self.last = dict(state['last'])
            self.seen = dict(state['seen'])
            self.progress = dict(state['progress'])
            if (any(not isinstance(key, str) or not key or not isinstance(value, str)
                    or not value.isdecimal() or len(value) > 128 for key, value in self.last.items())
                    or any(not isinstance(key, str) or not isinstance(value, str)
                           or len(value) != 64 or set(value) - set('0123456789abcdef')
                           for key, value in self.seen.items())
                    or any(not isinstance(value, dict) or set(value) != {
                        'stages', 'expectedDelivery', 'delivery', 'deliveryComplete', 'controlPending'}
                        or not isinstance(value['stages'], dict) or not isinstance(value['expectedDelivery'], list)
                        or not isinstance(value['delivery'], dict) or type(value['deliveryComplete']) is not bool
                        or type(value['controlPending']) is not bool for value in self.progress.values())):
                raise ConnectorEventError('Invalid connector ledger progress')
            if state['format'] in ('connector-ledger/v2', 'connector-ledger/v3'):
                self.checkpoints = state['checkpoints']
                self.dead_letters = state['deadLetters']
                if (not isinstance(self.checkpoints, dict) or len(self.checkpoints) > 128
                        or any(not isinstance(key, str) or not 1 <= len(key) <= 4096 or not isinstance(value, dict)
                               or set(value) != {'exportSha256', 'nextLine'}
                               or not isinstance(value['exportSha256'], str) or len(value['exportSha256']) != 64
                               or set(value['exportSha256']) - set('0123456789abcdef')
                               or type(value['nextLine']) is not int or not 0 <= value['nextLine'] <= MAX_EVENTS
                               for key, value in self.checkpoints.items())
                        or not isinstance(self.dead_letters, list) or len(self.dead_letters) > 1000
                        or any(not isinstance(item, dict) or set(item) != {
                            'connector', 'exportSha256', 'line', 'lineSha256', 'reason'}
                            or not isinstance(item['connector'], str) or not 1 <= len(item['connector']) <= 2000
                            or not isinstance(item['exportSha256'], str) or len(item['exportSha256']) != 64
                            or set(item['exportSha256']) - set('0123456789abcdef')
                            or type(item['line']) is not int or item['line'] < 1
                            or not isinstance(item['lineSha256'], str) or len(item['lineSha256']) != 64
                            or set(item['lineSha256']) - set('0123456789abcdef')
                            or item['reason'] not in ('invalid-record', 'out-of-order', 'source-unavailable')
                            for item in self.dead_letters)):
                    raise ConnectorEventError('Invalid connector host checkpoint')
            for progress in self.progress.values():
                intent = progress['stages'].get('proposal-intent')
                if intent is not None and (not isinstance(intent, str) or len(intent) != 64
                                           or set(intent) - set('0123456789abcdef')):
                    raise ConnectorEventError('Invalid connector native-effect intent')

    @staticmethod
    def object_key(event):
        return event['namespace'] + '\0' + event['objectId']

    @staticmethod
    def event_key(event):
        return event['namespace'] + '\0' + event['eventId'] + '\0' + event['revision']

    def accept(self, event):
        validate(event)
        key, obj = self.event_key(event), self.object_key(event)
        digest = fingerprint(event)
        if key in self.seen:
            if self.seen[key] != digest:
                raise ConnectorEventError('Conflicting replay for connector event revision')
            progress = self.progress[key]
            if not progress['deliveryComplete'] and not progress['controlPending']:
                latest = self.last.get(obj)
                if latest is not None and int(event['order']) < int(latest):
                    return 'out-of-order'
            return 'duplicate' if progress['deliveryComplete'] or progress['controlPending'] else 'retry'
        order = int(event['order'])
        previous = self.last.get(obj)
        if previous is not None and order <= int(previous):
            return 'out-of-order'
        if len(self.seen) >= MAX_LEDGER_EVENTS:
            raise ConnectorEventError('Connector ledger capacity reached; archive or review before continuing')
        self.last[obj] = event['order']
        self.seen[key] = digest
        self.progress[key] = {'stages': {}, 'expectedDelivery': [], 'delivery': {},
                              'deliveryComplete': False, 'controlPending': False}
        return 'accepted'

    def record_receipt(self, event, stage, receipt, *, expected_delivery=None):
        validate(event)
        if stage not in ('capture', 'planning', 'proposal', 'history', 'delivery-proposal', 'delivery'):
            raise ConnectorEventError('Unknown connector progress stage')
        key = self.event_key(event)
        if key not in self.seen or self.seen[key] != fingerprint(event):
            raise ConnectorEventError('Connector progress requires an admitted event revision')
        latest = self.last.get(self.object_key(event))
        if latest is not None and int(event['order']) < int(latest):
            raise ConnectorEventError('Superseded connector events cannot advance writer progress')
        if not isinstance(receipt, dict):
            raise ConnectorEventError('A native stage receipt is required')
        progress = self.progress[key]
        if stage == 'capture':
            if not _capture_validator().is_valid(receipt) or receipt['eventSha256'] != fingerprint(event):
                raise ConnectorEventError('Host-bound capture receipt does not match this event')
        elif stage == 'planning':
            if not (receipt.get('protocolVersion') in ('1.0', '2.0', '3.0', '4.0')
                    or receipt.get('format') in ('intake-stream-result/v1', 'intake-stream-result/v2',
                                                 'intake-stream-result/v3')):
                raise ConnectorEventError('Native intake planning receipt required')
        elif stage in ('proposal', 'history'):
            valid_receipt = (isinstance(receipt.get('proposal'), str) if stage == 'proposal' else
                             isinstance(receipt.get('actor'), str) and isinstance(receipt.get('revision'), str))
            if not valid_receipt:
                raise ConnectorEventError('Native proposal or history writer receipt required')
            if stage == 'proposal' and event['operation'] in ('delete', 'access-change'):
                progress['controlPending'] = True
        elif stage == 'delivery-proposal':
            if receipt.get('format') != 'intake-delivery-result/v1' or receipt.get('operation') != 'prepare':
                raise ConnectorEventError('Native delivery proposal receipt required')
            expected = expected_delivery or [(row['destination'], row['record']) for row in receipt.get('items', [])]
            if not isinstance(expected, list) or not expected or any(
                    not isinstance(row, (tuple, list)) or len(row) != 2
                    or any(not isinstance(part, str) or not part for part in row) for row in expected):
                raise ConnectorEventError('Expected per-item delivery identities required')
            progress['expectedDelivery'] = sorted(set(a + '\0' + b for a, b in expected))
        else:
            if receipt.get('format') != 'intake-delivery-result/v1' or receipt.get('operation') != 'commit':
                raise ConnectorEventError('Native delivery commit receipt required')
            for row in receipt.get('items', []):
                identity = row.get('destination', '') + '\0' + row.get('record', '')
                if identity not in progress['expectedDelivery']:
                    raise ConnectorEventError('Delivery result contains an unregistered destination item')
                previous = progress['delivery'].get(identity)
                sha = row.get('receiptSha256') if row.get('status') == 'committed' else None
                if row.get('status') == 'committed' and (not isinstance(sha, str) or len(sha) != 64):
                    raise ConnectorEventError('Committed delivery requires its native receipt hash')
                if previous and previous.get('status') == 'committed' and (sha != previous.get('receiptSha256')):
                    raise ConnectorEventError('Native delivery receipt changed across replay')
                progress['delivery'][identity] = {'status': row.get('status'), 'receiptSha256': sha}
            progress['deliveryComplete'] = bool(progress['expectedDelivery']) and all(
                progress['delivery'].get(identity, {}).get('status') == 'committed'
                for identity in progress['expectedDelivery'])
        progress['stages'][stage] = fingerprint(receipt)

    def proposal_intent(self, event, request_sha256):
        """Record admission before a native proposal call; this is not a receipt."""
        validate(event)
        key = self.event_key(event)
        if (self.seen.get(key) != fingerprint(event) or not isinstance(request_sha256, str)
                or len(request_sha256) != 64 or set(request_sha256) - set('0123456789abcdef')):
            raise ConnectorEventError('Native-effect intent requires an admitted exact event and request hash')
        if self.progress[key]['stages'].get('proposal-intent') is not None:
            raise ConnectorEventError('Native proposal attempt already admitted; reconcile before retry')
        self.progress[key]['stages']['proposal-intent'] = request_sha256

    def snapshot(self):
        return {'format': 'connector-ledger/v3', 'last': dict(self.last), 'seen': dict(self.seen),
                'progress': deepcopy(self.progress), 'checkpoints': deepcopy(self.checkpoints),
                'deadLetters': deepcopy(self.dead_letters)}

    def checkpoint(self, connector, export_sha256, next_line):
        if (not isinstance(connector, str) or not 1 <= len(connector) <= 4096 or not isinstance(export_sha256, str)
                or len(export_sha256) != 64 or set(export_sha256) - set('0123456789abcdef')
                or type(next_line) is not int or not 0 <= next_line <= MAX_EVENTS):
            raise ConnectorEventError('Invalid connector checkpoint')
        self.checkpoints[connector] = {'exportSha256': export_sha256, 'nextLine': next_line}

    def dead_letter(self, connector, export_sha256, line, raw, reason):
        if (not isinstance(connector, str) or not 1 <= len(connector) <= 2000
                or not isinstance(export_sha256, str) or len(export_sha256) != 64
                or set(export_sha256) - set('0123456789abcdef')
                or type(line) is not int or not 1 <= line <= MAX_EVENTS
                or not isinstance(raw, bytes) or len(raw) > MAX_LINE_BYTES
                or reason not in ('invalid-record', 'out-of-order', 'source-unavailable')):
            raise ConnectorEventError('Invalid connector dead-letter category')
        item = {'connector': connector, 'exportSha256': export_sha256, 'line': line,
                'lineSha256': hashlib.sha256(raw).hexdigest(), 'reason': reason}
        if item not in self.dead_letters:
            if len(self.dead_letters) >= 1000:
                raise ConnectorEventError('Connector dead-letter capacity reached; inspect and clear entries')
            self.dead_letters.append(item)

    def clear_dead_letter(self, connector, export_sha256, line):
        self.dead_letters = [item for item in self.dead_letters if not (
            item['connector'] == connector and item['exportSha256'] == export_sha256 and item['line'] == line)]


class ConnectorLedgerStore:
    """Bounded, private host cursor ledger with exclusive locking and atomic saves."""
    def __init__(self, root):
        # Resolve an operator-selected root once, then traverse the resulting
        # absolute path with no-follow descriptors for each operational child.
        self.root = Path(root).expanduser().resolve(strict=True)
        self.directory = self.root / '_internal/intake/connector-events'
        self.path = self.directory / 'ledger.json'
        self.lock_path = self.directory / 'ledger.lock'

    @contextlib.contextmanager
    def transaction(self):
        try:
            directory_fd = open_directory(self.root)
        except CaptureError as exc:
            raise ConnectorEventError('Connector ledger root must be a no-follow absolute directory') from exc
        lock_fd = None
        try:
            for part in ('_internal', 'intake', 'connector-events'):
                try:
                    os.mkdir(part, 0o700, dir_fd=directory_fd)
                except FileExistsError:
                    pass
                child_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
                info = os.fstat(child_fd)
                os.close(directory_fd)
                directory_fd = child_fd
                if (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077):
                    raise ConnectorEventError('Connector ledger ancestors must be private and host-owned')
            flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
            lock_fd = os.open('ledger.lock', flags, 0o600, dir_fd=directory_fd)
            lock_info = os.fstat(lock_fd)
            if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.geteuid()
                    or stat.S_IMODE(lock_info.st_mode) & 0o077):
                raise ConnectorEventError('Connector ledger lock must be a private host-owned file')
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                ledger_fd = os.open('ledger.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                    dir_fd=directory_fd)
            except FileNotFoundError:
                ledger_fd = None
            if ledger_fd is not None:
                try:
                    file_info = os.fstat(ledger_fd)
                    if (not stat.S_ISREG(file_info.st_mode) or file_info.st_uid != os.geteuid()
                            or stat.S_IMODE(file_info.st_mode) & 0o077):
                        raise ConnectorEventError('Connector ledger file must be a private host-owned file')
                    if file_info.st_size > MAX_LEDGER_BYTES:
                        raise ConnectorEventError('Connector ledger exceeds its private storage bound')
                    chunks, size = [], 0
                    while chunk := os.read(ledger_fd, min(65536, MAX_LEDGER_BYTES + 1 - size)):
                        chunks.append(chunk)
                        size += len(chunk)
                        if size > MAX_LEDGER_BYTES:
                            raise ConnectorEventError('Connector ledger exceeds its private storage bound')
                    raw = b''.join(chunks)
                finally:
                    os.close(ledger_fd)
                if len(raw) > MAX_LEDGER_BYTES:
                    raise ConnectorEventError('Connector ledger exceeds its private storage bound')
                try:
                    state = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ConnectorEventError('Connector ledger is not valid JSON') from exc
                ledger = EventLedger(state)
            else:
                ledger = EventLedger()

            def save():
                raw = json.dumps(ledger.snapshot(), sort_keys=True, separators=(',', ':')).encode() + b'\n'
                if len(raw) > MAX_LEDGER_BYTES or len(ledger.seen) > MAX_LEDGER_EVENTS:
                    raise ConnectorEventError('Connector ledger capacity reached; archive or review before continuing')
                temporary = '.ledger-' + secrets.token_hex(12) + '.tmp'
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0),
                             0o600, dir_fd=directory_fd)
                try:
                    with os.fdopen(fd, 'wb') as handle:
                        handle.write(raw)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(temporary, 'ledger.json', src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                    os.fsync(directory_fd)
                finally:
                    try:
                        os.unlink(temporary, dir_fd=directory_fd)
                    except FileNotFoundError:
                        pass
            yield ledger, save
        finally:
            try:
                if lock_fd is not None:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    os.close(lock_fd)
            finally:
                os.close(directory_fd)


def map_event(event):
    """Return a capture observation and either a native item or a review-only control."""
    raw = validate(event)
    identity = 'connector:' + fingerprint({'namespace': event['namespace'], 'object': event['objectId']})
    item = None
    if event['operation'] in ('upsert', 'edit'):
        metadata = {
            'actor': event['actor'] or '', 'thread': event['thread'] or '',
            'eventTime': event['eventTime'] or '', 'observedAt': event['observedAt'] or '',
            'language': event['language'] or '', 'text': event['text'],
            'visibility': event['visibility'] or '', 'attachments': encode(event['attachments']).decode('utf-8'),
            'eventId': event['eventId'], 'eventOrder': event['order'],
        }
        item = {'id': identity, 'source': {'id': event['namespace'], 'revision': event['revision'],
                'sha256': event['payload']['sha256'], 'mediaType': event['payload']['mediaType'],
                'byteLength': len(raw), 'reference': {'backend': 'connector-export',
                'object': event['objectId'], 'locator': event['locator'], 'availability': 'available'}},
                'metadata': metadata}
    return {'format': 'connector-map/v1', 'eventSha256': fingerprint(event),
            'idempotencyKey': fingerprint({'namespace': event['namespace'], 'object': event['objectId'],
                                           'event': event['eventId'], 'revision': event['revision']}),
            'sourceBytesSha256': hashlib.sha256(raw).hexdigest(), 'sourceByteLength': len(raw),
            'body': {'encoding': 'base64', 'data': base64.b64encode(raw).decode('ascii')},
            'sourceAuthenticity': 'unverified-export-observation', 'importedActor': event['actor'],
            'operation': event['operation'], 'order': event['order'], 'locator': event['locator'],
            'item': item, 'requiresSourceReview': event['operation'] in ('delete', 'access-change'),
            'withdrawalLimit': ('External deletion/access change does not recall previously authorized copies'
                                if event['operation'] in ('delete', 'access-change') else None)}


def capture_event(boundary, resource, event, *, log):
    """Bind an export snapshot to a fresh host read grant and return its boundary.

    The resource is host-selected configuration. Event actor/visibility never
    supply the principal, resource, scope, or reference binding.
    """
    if not isinstance(boundary, ReadBoundary) or not isinstance(resource, str) or not resource.strip() or not callable(log):
        raise ConnectorEventError('Current host boundary, resource registration and audit logger required')
    raw = validate(event)
    mapped = map_event(event)
    identity = mapped['item']['id'] if mapped['item'] is not None else 'connector-control:' + mapped['idempotencyKey']
    basis = fingerprint({'event': mapped['eventSha256'], 'resource': resource})
    log('connector.capture.admitted', boundary.actor, basis,
        {'policySha256': boundary.policy.binding['sha256'], 'sourceBytes': len(raw)})
    if not boundary.permits_resource(resource, identity):
        log('connector.capture.denied', boundary.actor, basis, {'sourceBytes': 0})
        raise ConnectorEventError('Connector source is unavailable under current host policy')
    bindings = deepcopy(boundary.bindings)
    if mapped['item'] is not None:
        item_hash = fingerprint(mapped['item'])
        old = bindings['references'].get(item_hash)
        if old is not None and old != resource:
            raise ConnectorEventError('Imported item is already bound to a different resource')
        bindings['references'][item_hash] = resource
    selected = ReadBoundary(boundary.policy, actor=boundary.actor, now=boundary.now,
                            scopes=boundary.scopes, bindings=bindings)
    receipt = {**mapped, 'format': 'connector-capture/v1', 'principal': boundary.actor,
               'policySha256': boundary.policy.binding['sha256'], 'capturedAt': boundary.now,
               'hostAuthorization': 'current-read-grant'}
    if not _capture_validator().is_valid(receipt):
        raise ConnectorEventError('Connector capture receipt failed its schema')
    log('connector.capture.completed', boundary.actor, basis,
        {'captureSha256': fingerprint(receipt), 'sourceSha256': hashlib.sha256(raw).hexdigest(),
         'sourceBytes': len(raw)})
    return selected, receipt


def propose_source_control_review(authority, capture, collection, actor, at):
    """Create a native pending review task; never mutate or revoke a source copy."""
    from knowledge_store import StoreError
    if (not isinstance(capture, dict) or not _capture_validator().is_valid(capture)
            or capture['operation'] not in ('delete', 'access-change') or capture['item'] is not None
            or not capture['requiresSourceReview'] or not isinstance(actor, str) or not actor.strip()
            or not isinstance(at, str) or not at.strip()):
        raise ConnectorEventError('A host-bound source-control capture and authenticated actor are required')
    target = authority.contract.collections.get(collection)
    if target is None:
        raise ConnectorEventError('Host-registered source-control review collection required')
    identity = 'connector-review:' + capture['idempotencyKey']
    request_id = 'connector-review:' + capture['idempotencyKey']
    record = {'id': identity, 'collection': collection, 'kind': target['kind'],
              'content': {'title': 'Review imported source-control event',
                          'text': ('An exported deletion/access-change event needs review. This proposal does not '
                                   'change local access or prove that previous copies were recalled.'),
                          'data': {'connectorSourceControl': {
                              'format': 'connector-source-control-review/v1',
                              'eventSha256': capture['eventSha256'],
                              'idempotencyKey': capture['idempotencyKey'],
                              'operation': capture['operation'], 'order': capture['order'],
                              'locator': capture['locator'], 'importedActor': capture['importedActor'],
                              'sourceAuthenticity': capture['sourceAuthenticity'],
                              'sourceBytesSha256': capture['sourceBytesSha256'],
                              'principal': capture['principal'], 'policySha256': capture['policySha256']}}},
              'relations': []}
    request = {'id': request_id, 'record': identity, 'resource': target['resource'],
               'mutation': 'create', 'expectedRevision': None,
               'reason': 'Review exported source-control event before any local action',
               'evidence': ['connector-event:' + capture['eventSha256']], 'sourceResource': None}
    try:
        return {'record': identity, **authority.propose(request, record, actor, at=at)}
    except StoreError as exc:
        raise ConnectorEventError('Native source-control review proposal was refused') from exc


def frame(stream, sequence, previous, items, *, final):
    """Wrap mapped items in the existing intake stream frame without granting authority."""
    if (not isinstance(stream, str) or type(sequence) is not int
            or not 0 <= sequence <= 9007199254740991 or not isinstance(items, list)
            or len(items) > 1000 or type(final) is not bool):
        raise ConnectorEventError('Invalid bounded stream frame request')
    result = {'format': 'intake-stream-frame/v1', 'stream': stream, 'sequence': sequence,
              'previous': previous, 'items': items, 'final': final}
    try:
        from intake_stream import check
        check(result, 'frame')
    except (IntakeError, KeyError, TypeError) as exc:
        raise ConnectorEventError('Mapped items do not satisfy native intake stream schema') from exc
    if len(encode(result)) > MAX_LINE_BYTES - 1:
        raise ConnectorEventError('Mapped intake frame exceeds JSONL bound')
    return result
