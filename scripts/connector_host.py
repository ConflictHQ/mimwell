"""Local, host-authenticated file/export connector adapter.

This host admits only exact registered JSONL snapshots. It creates native intake
history proposals, never approves them, and leaves delivery to the existing
reviewed native writer path.
"""
import hashlib
import json
import os
from pathlib import Path

from connector_events import ConnectorEventError, ConnectorLedgerStore, capture_event, decode_line, map_event
from intake_capture import CaptureError, read_stable
from intake_host import load_planner
from knowledge_operations import load_host, run as run_operation
from knowledge_store import SQLiteAuthority, StoreError, utcnow

MAX_EXPORT_BYTES = 16777216
MAX_EXPORT_LINES = 1000


class ConnectorHostError(ValueError):
    pass


def capabilities():
    return {
        'format': 'connector-host-capabilities/v1',
        'supported': ['file-export-import', 'stdin-exact-registered-snapshot', 'bounded-jsonl', 'bounded-admission-backpressure',
                      'checkpoint-resume', 'retry',
                      'dead-letter-inspect-replay', 'thread-metadata', 'edit-delete-events',
                      'native-pending-proposals'],
        'unsupported': ['polling', 'push', 'webhooks', 'http', 'platform-clients',
                        'attachments-as-content', 'automatic-review', 'automatic-delivery'],
        'authority': 'local-uid-mapped-host-registration',
        'importedActorAuthority': False,
    }


class ConnectorHost:
    def __init__(self, root, host_config, authority, *, uid=None, clock=utcnow):
        self.root = Path(root).resolve(strict=True)
        self.host_config = host_config
        self.authority = authority
        self.uid = os.geteuid() if uid is None else uid
        self.clock = clock

    def _selection(self, namespace, export_path):
        if os.geteuid() != self.uid:
            raise ConnectorHostError('Connector local identity is unavailable')
        host = load_host(self.root, self.host_config)
        actor = host['principalsByUid'].get(str(self.uid))
        selected = host['authorities'].get(self.authority)
        if not actor or selected is None or 'intake' not in selected:
            raise ConnectorHostError('No current host principal or intake authority registration')
        registration = selected['intake'].get('connectors', {}).get(namespace)
        if registration is None:
            raise ConnectorHostError('Connector namespace is not registered')
        snapshot = next((row for row in registration['snapshots'] if row['path'] == export_path), None)
        if snapshot is None:
            raise ConnectorHostError('Export path is not pinned in the current host registration')
        return host, selected, actor, registration, snapshot

    def _metadata_selection(self):
        if os.geteuid() != self.uid:
            raise ConnectorHostError('Connector local identity is unavailable')
        host = load_host(self.root, self.host_config)
        actor = host['principalsByUid'].get(str(self.uid))
        selected = host['authorities'].get(self.authority)
        if not actor or selected is None or 'intake' not in selected:
            raise ConnectorHostError('No current connector principal or intake authority')
        self._metadata_guard(host, actor)
        return host, selected, actor

    def _host_guard(self, host, actor):
        if (os.geteuid() != self.uid or load_host(self.root, self.host_config) != host
                or host['principalsByUid'].get(str(self.uid)) != actor):
            raise ConnectorHostError('Connector host or local identity changed before release')

    def _metadata_guard(self, host, actor):
        self._host_guard(host, actor)
        native = self._run({'format': 'knowledge-operation-request/v1', 'authority': self.authority,
                            'operation': 'authority.inspect', 'arguments': {}}, actor)
        collection = host['authorities'][self.authority]['intake']['collection']
        if (not isinstance(native, dict) or collection not in
                {item.get('id') for item in native.get('collections', []) if isinstance(item, dict)}):
            raise ConnectorHostError('Connector operational metadata is unavailable')
        self._host_guard(host, actor)

    def import_stdin(self, namespace, export_path, stream, *, timeout=5):
        """Observe exact registered bytes from stdin, then use the native file host.

        Stdin cannot enroll an export or replace its independently selected file.
        Both observations must match the same host pin before any native effect.
        """
        from connector_pipe import read_pipe
        host, _selected, actor, _registration, snapshot = self._selection(namespace, export_path)
        self._metadata_guard(host, actor)
        raw = read_pipe(stream, min(snapshot['maxBytes'], MAX_EXPORT_BYTES), timeout=timeout)
        if hashlib.sha256(raw).hexdigest() != snapshot['sha256']:
            raise ConnectorHostError('Connector stdin differs from the exact registered export')
        self._host_guard(host, actor)
        return self.import_export(namespace, export_path, expected_host=host)

    def capability_report(self, namespace=None):
        host, selected, actor = self._metadata_selection()
        registrations = selected['intake'].get('connectors', {})
        if namespace is not None:
            registrations = {namespace: registrations[namespace]} if namespace in registrations else {}
        result = {**capabilities(), 'authority': self.authority,
                'connectors': [{'namespace': key, 'snapshots': [row['path'] for row in value['snapshots']]}
                               for key, value in sorted(registrations.items())]}
        self._metadata_guard(host, actor)
        return result

    def dead_letters(self):
        host, selected, actor = self._metadata_selection()
        with ConnectorLedgerStore(self.root).transaction() as (ledger, _save):
            namespaces = selected['intake'].get('connectors', {})
            result = [item for item in ledger.dead_letters if item['connector'] in namespaces]
        self._metadata_guard(host, actor)
        return result

    def import_export(self, namespace, export_path, *, expected_host=None):
        host, selected, actor, registration, snapshot = self._selection(namespace, export_path)
        if expected_host is not None and host != expected_host:
            raise ConnectorHostError('Connector stdin host registration changed before admission')
        self._metadata_guard(host, actor)
        try:
            raw, _ = read_stable(self.root, snapshot['path'], min(snapshot['maxBytes'], MAX_EXPORT_BYTES))
        except (CaptureError, OSError, ValueError) as exc:
            raise ConnectorHostError('Registered connector export is unavailable') from exc
        digest = hashlib.sha256(raw).hexdigest()
        if digest != snapshot['sha256']:
            raise ConnectorHostError('Registered connector export pin changed')
        lines = raw.splitlines(keepends=True)
        if len(lines) > MAX_EXPORT_LINES:
            raise ConnectorHostError('Connector export exceeds its event bound')
        connector_key = namespace + '\0' + snapshot['path']
        result = {'format': 'connector-import-result/v1', 'connector': namespace,
                  'exportSha256': digest, 'seen': 0, 'proposed': 0, 'duplicate': 0,
                  'deadLettered': 0, 'nextLine': 0}
        with ConnectorLedgerStore(self.root).transaction() as (ledger, save):
            checkpoint = ledger.checkpoints.get(connector_key)
            start = checkpoint['nextLine'] if checkpoint and checkpoint['exportSha256'] == digest else 0
            if start > len(lines):
                raise ConnectorHostError('Connector checkpoint is outside this exact export snapshot')
            for index in range(start, len(lines)):
                self._host_guard(host, actor)
                line_number = index + 1
                line = lines[index]
                result['seen'] += 1
                try:
                    event = decode_line(line)
                    if event['namespace'] != namespace:
                        raise ConnectorEventError('Event namespace differs from its host registration')
                except (ConnectorEventError, ValueError, KeyError, TypeError):
                    ledger.dead_letter(namespace, digest, line_number, line, 'invalid-record')
                    result['deadLettered'] += 1
                else:
                    try:
                        outcome = self._admit(ledger, event, actor, selected, registration,
                                              expected_host=host, save=save)
                    except (ConnectorEventError, StoreError, CaptureError, OSError, ConnectorHostError):
                        ledger.dead_letter(namespace, digest, line_number, line, 'source-unavailable')
                        result['deadLettered'] += 1
                    else:
                        if outcome == 'out-of-order':
                            ledger.dead_letter(namespace, digest, line_number, line, 'out-of-order')
                            result['deadLettered'] += 1
                        elif outcome == 'duplicate':
                            result['duplicate'] += 1
                        else:
                            result['proposed'] += outcome == 'proposed'
                ledger.checkpoint(connector_key, digest, line_number)
                save()
            result['nextLine'] = len(lines)
        self._metadata_guard(host, actor)
        return result

    def replay_dead_letter(self, namespace, export_path, line_number):
        host, selected, actor, registration, snapshot = self._selection(namespace, export_path)
        self._metadata_guard(host, actor)
        raw, _ = read_stable(self.root, snapshot['path'], min(snapshot['maxBytes'], MAX_EXPORT_BYTES))
        digest = hashlib.sha256(raw).hexdigest()
        if digest != snapshot['sha256']:
            raise ConnectorHostError('Registered connector export pin changed')
        lines = raw.splitlines(keepends=True)
        if type(line_number) is not int or not 1 <= line_number <= len(lines) <= MAX_EXPORT_LINES:
            raise ConnectorHostError('Dead-letter line is outside the registered export')
        line = lines[line_number - 1]
        with ConnectorLedgerStore(self.root).transaction() as (ledger, save):
            entry = next((row for row in ledger.dead_letters if row['connector'] == namespace
                          and row['exportSha256'] == digest and row['line'] == line_number
                          and row['lineSha256'] == hashlib.sha256(line).hexdigest()), None)
            if entry is None:
                raise ConnectorHostError('No exact dead-letter entry matches this export line')
            event = decode_line(line)
            if event['namespace'] != namespace:
                raise ConnectorHostError('Event namespace differs from its host registration')
            outcome = self._admit(ledger, event, actor, selected, registration,
                                  expected_host=host, save=save)
            if outcome == 'out-of-order':
                raise ConnectorHostError('Out-of-order event remains ineligible for replay')
            ledger.clear_dead_letter(namespace, digest, line_number)
            save()
            self._metadata_guard(host, actor)
            return {'format': 'connector-dead-letter-replay/v1', 'line': line_number,
                    'result': outcome}

    def _admit(self, ledger, event, actor, selected, registration, *, expected_host=None, save=None):
        outcome = ledger.accept(event)
        if outcome == 'out-of-order':
            return outcome
        if outcome == 'duplicate':
            return outcome
        # The file host stops at native proposal creation. A later registered
        # snapshot containing the same event must not mint another proposal.
        # This is prior-stage deduplication, not proof of current approval,
        # proposal liveness or canonical delivery.
        if ledger.progress[ledger.event_key(event)]['stages'].get('proposal'):
            return 'duplicate'
        if ledger.progress[ledger.event_key(event)]['stages'].get('proposal-intent'):
            raise ConnectorHostError('A native proposal outcome is unknown; reconcile before retry')

        def submit(request):
            # A denied host verb is known before native I/O and remains replayable
            # after an explicit grant correction. Once native I/O is admitted,
            # failures are conservative unknown outcomes, never blind retries.
            if request['operation'] not in selected['grants'].get(actor, []):
                raise ConnectorHostError('Native proposal operation is unavailable')
            if not callable(save):
                raise ConnectorHostError('Durable native-effect admission requires the host ledger writer')
            if expected_host is not None:
                self._host_guard(expected_host, actor)
            from knowledge_policy import fingerprint
            ledger.proposal_intent(event, fingerprint({'request': request, 'principal': actor,
                                                       'host': expected_host}))
            save()
            return self._run(request, actor, expected_host=expected_host)
        mapped = map_event(event)
        pin = selected['intake']['planner']
        planner = load_planner(self.root, pin['path'], actor=actor, now=self.clock(), log=lambda *_: None)
        resource = registration['resource']
        boundary, capture = capture_event(planner.boundary, resource, event, log=lambda *_: None)
        ledger.record_receipt(event, 'capture', capture)
        if mapped['item'] is None:
            native = self._source_control_proposal(event, capture, actor, selected, submit=submit)
        else:
            planner.boundary = boundary
            plan = planner.plan({'protocolVersion': '1.0', 'items': [mapped['item']], 'offset': 0,
                                 'inputSha256': None, 'budget': planner.limits})
            ledger.record_receipt(event, 'planning', plan)
            idem = mapped['idempotencyKey']
            request = {'format': 'knowledge-operation-request/v4', 'authority': self.authority,
                       'operation': 'intake.history-propose', 'arguments': {
                           'record': 'connector-history:' + idem, 'expectedRevision': None,
                           'item': mapped['item'], 'intent': None, 'requestId': 'connector-event:' + idem,
                           'reason': 'Review exact registered connector export event'}}
            native = submit(request)
        if not isinstance(native, dict) or not isinstance(native.get('proposal'), str):
            raise ConnectorHostError('Native writer did not return a pending proposal receipt')
        ledger.record_receipt(event, 'proposal', {'proposal': native['proposal']})
        return 'proposed'

    def _source_control_proposal(self, event, capture, actor, selected, *, submit):
        path = self.root / selected['path']
        store = SQLiteAuthority(path, expected_binding=selected['binding'], readonly=True)
        try:
            collection = selected['intake']['collection']
            target = store.contract.collections.get(collection)
            if target is None:
                raise ConnectorHostError('Source-control review collection is unavailable')
            identity = 'connector-review:' + capture['idempotencyKey']
            record = {'id': identity, 'collection': collection, 'kind': target['kind'],
                      'content': {'title': 'Review imported source-control event',
                                  'text': ('An exported deletion/access-change event needs review. This proposal does not '
                                           'change local access or prove that previous copies were recalled.'),
                                  'data': {'connectorSourceControl': {
                                      'format': 'connector-source-control-review/v1',
                                      'eventSha256': capture['eventSha256'], 'idempotencyKey': capture['idempotencyKey'],
                                      'operation': capture['operation'], 'order': capture['order'],
                                      'locator': capture['locator'], 'importedActor': capture['importedActor'],
                                      'sourceAuthenticity': capture['sourceAuthenticity'],
                                      'sourceBytesSha256': capture['sourceBytesSha256'],
                                      'principal': capture['principal'], 'policySha256': capture['policySha256']}}},
                      'relations': []}
            request = {'format': 'knowledge-operation-request/v1', 'authority': self.authority,
                       'operation': 'proposal.propose', 'arguments': {'request': {
                           'id': identity, 'record': identity, 'resource': target['resource'],
                           'mutation': 'create', 'expectedRevision': None,
                           'reason': 'Review exported source-control event before any local action',
                           'evidence': ['connector-event:' + capture['eventSha256']], 'sourceResource': None},
                           'record': record}}
            return submit(request)
        finally:
            store.close()

    def _run(self, request, actor, *, expected_host=None):
        def current_actor():
            if os.geteuid() != self.uid:
                return None
            try:
                current = load_host(self.root, self.host_config)
            except (OSError, StoreError, ValueError):
                return None
            if expected_host is not None and current != expected_host:
                return None
            return current['principalsByUid'].get(str(self.uid))

        raw = run_operation(self.root, self.host_config, request, actor=actor, clock=self.clock,
                            authorize=current_actor)
        response = json.loads(raw)
        return response.get('native')
