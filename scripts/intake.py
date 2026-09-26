"""Deterministic metadata intake proposals; no model, source I/O or destination writes."""
from copy import deepcopy
import time

from context_access import ReadBoundary
from context_bundle import encode
from knowledge_policy import fingerprint
from intake_contract import IntakeError as IntakeError, check as check, event as event, validate_history as validate_history
from intake_keys import completion_key


def unique(rows):
    index = {row['id']: row for row in rows}
    if len(index) != len(rows):
        raise IntakeError('Duplicate intake identity')
    return index


class IntakePlanner:
    """One fresh host boundary. Source grants bind exact descriptors, not IDs alone.

    Completed keys/receipt hashes come from the operator's verified writer receipts,
    never a caller's batch. They are not a global cache of content existence.
    """
    def __init__(self, boundary, configuration, *, completed=None, completion_lookup=None, limits=None, log):
        check(configuration, 'configuration')
        if not isinstance(boundary, ReadBoundary) or not callable(log):
            raise IntakeError('Intake requires an authenticated boundary and audit sink')
        self.boundary, self.log = boundary, log
        self.config = deepcopy(configuration)
        self.limits = deepcopy(limits or {'maxItems': 1000, 'maxInputBytes': 1048576, 'maxOutputBytes': 1048576})
        check(self.limits, 'limits')
        self.completed = deepcopy(completed or {})
        if completion_lookup is not None and (not callable(completion_lookup) or completed):
            raise IntakeError('Select one host-owned completion source')
        self.completion_lookup = completion_lookup
        if (not isinstance(self.completed, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                or len(k) != 64 or len(v) != 64 or set(k + v) - set('0123456789abcdef') for k, v in self.completed.items())):
            raise IntakeError('Invalid completed intake receipts')
        taxonomy = self.config['taxonomy']
        if taxonomy['ontologySha256'] != boundary.policy.binding['ontologySha256']:
            raise IntakeError('Taxonomy ontology pin changed')
        self.labels = unique(taxonomy['labels'])
        self.destinations = unique(self.config['destinations'])
        unique(self.config['rules'])
        for label in self.labels.values():
            if set(label['kinds']) - set(boundary.policy.kinds):
                raise IntakeError('Taxonomy maps an unknown semantic kind')
        seen = set()
        for destination in self.destinations.values():
            key = fingerprint(destination['target'])
            if key in seen or set(destination['kinds']) - set(boundary.policy.kinds):
                raise IntakeError('Ambiguous destination or semantic kind')
            seen.add(key)
        for rule in self.config['rules']:
            self.validate_intent(rule['intent'])
            for condition in rule['conditions']:
                field, op, value = condition['field'], condition['operator'], condition['value']
                if (field not in ('mediaType', 'byteLength') and not field.startswith('metadata.')
                        or field == 'metadata.' or op in ('equals', 'prefix') and not isinstance(value, str)
                        or op == 'atMost' and type(value) is not int):
                    raise IntakeError('Invalid deterministic condition')
        self.basis = {'configurationSha256': fingerprint(self.config), 'taxonomySha256': fingerprint(taxonomy),
                      'ontologySha256': taxonomy['ontologySha256'], 'policySha256': boundary.policy.binding['sha256']}

    def validate_intent(self, intent):
        check(intent, 'intent')
        if set(intent['labels']) - set(self.labels) or set(intent['destinations']) - set(self.destinations):
            raise IntakeError('Intent references an undeclared label or destination')
        if (intent['action'] == 'keep' and (not intent['destinations'] or intent['processing'] == 'none')
                or intent['action'] != 'keep' and (intent['destinations'] or intent['processing'] != 'none')):
            raise IntakeError('Intake action and processing disagree')

    def authorized(self, item):
        return self.boundary.permits('references', fingerprint(item))

    def completion_key(self, item, destination, processing, labels):
        # Completion is the exact delivered descriptor, not reusable byte processing.
        # Older content-only keys cannot attest that another reference was delivered.
        return completion_key(item, destination, processing, labels, self.basis)

    def decision(self, item, intent):
        self.validate_intent(intent)
        labels = sorted(intent['labels'])
        kinds = sorted({kind for label in labels for kind in self.labels[label]['kinds']})
        decision = {'action': intent['action'], 'labels': labels, 'kinds': kinds, 'processing': intent['processing'],
                    'destinations': [], 'gaps': [], 'confidence': None, 'requiresReview': True}
        boundary = self.boundary
        for identity in sorted(intent['destinations']):
            destination = self.destinations[identity]
            if not boundary.permits_resource(destination['resource'], identity):
                decision['gaps'].append('destination-unavailable')
                continue
            request = {'id': 'intake-proposal-check', 'resource': destination['resource'], 'record': item['id'],
                       'mutation': 'create', 'expectedRevision': None, 'reason': 'Plan source intake',
                       'evidence': ['intake:' + fingerprint(item)], 'sourceResource': None}
            allowed = boundary.policy.evaluate(request, {'actor': boundary.actor, 'now': boundary.now,
                'operation': 'propose', 'currentRevision': None})['allowed']
            status = ('read-only' if destination['mode'] == 'read' else 'kind-mismatch'
                      if set(kinds) - set(destination['kinds']) else 'proposal-denied' if not allowed else 'proposed')
            receipt = None
            if status == 'proposed':
                if self.completion_lookup is None:
                    receipt = self.completed.get(self.completion_key(item, destination['target'], intent['processing'], labels))
                else:
                    from intake_completion import CompletionUnavailable
                    try:
                        receipt = self.completion_lookup(self, item, destination, intent['processing'], labels)
                    except CompletionUnavailable:
                        decision['gaps'].append('completion-unavailable')
                    if receipt is not None and (not isinstance(receipt, str) or len(receipt) != 64
                                                or set(receipt) - set('0123456789abcdef')):
                        raise IntakeError('Invalid completion observation')
                if receipt:
                    status = 'already-ingested'
            decision['destinations'].append({'id': identity, 'target': deepcopy(destination['target']),
                                             'status': status, 'completionSha256': receipt})
        decision['gaps'] = sorted(set(decision['gaps']))
        if intent['action'] == 'keep' and (decision['gaps'] or any(
                row['status'] not in ('proposed', 'already-ingested') for row in decision['destinations'])):
            decision['action'] = 'review'
        if item['source']['reference']['availability'] == 'unavailable' and intent['action'] == 'keep':
            decision['action'] = 'review'
            decision['gaps'].append('source-unavailable')
        return decision

    def history(self, item):
        check(item, 'item')
        if not self.authorized(item):
            raise IntakeError('Intake source unavailable')
        chosen = None
        for rule in self.config['rules']:
            matches = True
            for c in rule['conditions']:
                value = item['metadata'].get(c['field'][9:]) if c['field'].startswith('metadata.') else item['source'][c['field']]
                expected, op = c['value'], c['operator']
                matches = matches and (value == expected if op == 'equals' and isinstance(value, str)
                    else value.startswith(expected) if op == 'prefix' and isinstance(value, str)
                    else value <= expected if op == 'atMost' and type(value) is int else False)
            if matches:
                chosen = rule
                break
        intent = chosen['intent'] if chosen else {'action': 'review', 'labels': [], 'destinations': [], 'processing': 'none'}
        decision = self.decision(item, intent)
        if chosen is None:
            decision['gaps'].append('no-rule-or-judgment-engine')
        initial = {'format': 'intake-history/v1', 'item': deepcopy(item), 'basis': deepcopy(self.basis), 'events': []}
        return event(initial, decision, actor=self.boundary.actor, at=self.boundary.now,
                     reason=chosen['reason'] if chosen else 'No deterministic rule matched; judgment is not configured',
                     mechanism={'tier': 'rules' if chosen else 'unassisted', 'rule': chosen['id'] if chosen else None})

    def correct(self, history, intent, *, reason):
        validate_history(history)
        if history['basis'] != self.basis or not self.authorized(history['item']):
            raise IntakeError('Intake source or planning basis changed')
        return event(history, self.decision(history['item'], intent), actor=self.boundary.actor,
                     at=self.boundary.now, reason=reason, mechanism={'tier': 'correction', 'rule': None})

    def plan(self, request):
        started = time.perf_counter_ns()
        try:
            check(request, 'request')
            limits = {key: min(value, request['budget'][key]) for key, value in self.limits.items()}
            if len(encode(request)) > limits['maxInputBytes']:
                raise IntakeError('Intake input budget exceeded')
            items = request['items']
            unique(items)
            digest, offset = fingerprint(items), request['offset']
            if offset > len(items) or request['inputSha256'] not in (digest, None) or offset and request['inputSha256'] != digest:
                raise IntakeError('Invalid or changed batch continuation')
            result = {'protocolVersion': '1.0', 'inputSha256': digest, 'basis': deepcopy(self.basis),
                      'authorization': {'principal': self.boundary.actor, 'evaluatedAt': self.boundary.now},
                      'limits': limits, 'offset': offset, 'nextOffset': None, 'results': [], 'truncation': [],
                      'usage': {'modelCalls': 0, 'inputTokens': 0, 'outputTokens': 0, 'elapsedMicros': 0}}
            # Compact encode() uses one comma between rows. Count each row once;
            # repeatedly serializing the entire prefix makes large batches quadratic.
            reserve = {**result, 'nextOffset': len(items), 'truncation': ['maxItems', 'maxBytes'],
                       'usage': {**result['usage'], 'elapsedMicros': 9007199254740991}}
            reserved_bytes = len(encode(reserve))
            if reserved_bytes > limits['maxOutputBytes']:
                raise IntakeError('Intake output budget cannot hold envelope')
            for index in range(offset, len(items)):
                if len(result['results']) == limits['maxItems']:
                    result.update(nextOffset=index, truncation=['maxItems'])
                    break
                item = items[index]
                row = {'item': item['id'], 'status': 'unavailable'}
                if self.authorized(item):
                    row = {'item': item['id'], 'status': 'planned', 'history': self.history(item)}
                row_bytes = len(encode(row)) - 1 + bool(result['results'])
                if reserved_bytes + row_bytes > limits['maxOutputBytes']:
                    result.update(nextOffset=index, truncation=['maxBytes'])
                    break
                reserved_bytes += row_bytes
                result['results'].append(row)
            result['usage']['elapsedMicros'] = min(9007199254740991, (time.perf_counter_ns() - started) // 1000)
            self.log('intake.planned', self.boundary.actor, digest,
                     {'processed': len(result['results']), 'nextOffset': result['nextOffset'], 'modelCalls': 0})
            return result
        except (ValueError, KeyError, TypeError):
            self.log('intake.rejected', self.boundary.actor, 'batch', {'reason': 'invalid-or-unavailable-input'})
            raise


class IntakeAuthority:
    """Persist one history through the existing authority proposal/review/commit path.

    The adapter only proposes history creation/correction. The canonical writer
    owns transactional storage and review. Intake target delivery is separate.
    """
    def __init__(self, authority, factory, *, collection):
        self.authority, self.factory, self.collection = authority, factory, collection
        selected = authority.contract.collections.get(collection)
        if not callable(factory) or not selected or selected['kind'] != 'memory-note':
            raise IntakeError('Intake history requires an explicit memory-note collection')

    def propose(self, identity, expected_revision, item=None, *, intent=None, actor, at, request_id, reason):
        planner = self.factory(actor, at)
        if (not isinstance(planner, IntakePlanner) or planner.boundary.actor != actor or planner.boundary.now != at
                or planner.boundary.policy.binding != self.authority.contract.policy.binding):
            raise IntakeError('History and intake must share the selected policy boundary')
        current = self.authority.get(identity, actor, at=at)
        if (current and (current['revision'] != expected_revision or current['withheldRelations'] or current['record'] is None)
                or not current and expected_revision is not None):
            raise IntakeError('Intake history changed; inspect its current revision')
        if current:
            record = current['record']
            if record['collection'] != self.collection or item is not None or intent is None:
                raise IntakeError('An existing intake history requires an explicit correction')
            history = record['content'].get('data', {}).get('intakeHistory')
            if history is None:
                raise IntakeError('Record has no intake history')
            history = planner.correct(history, intent, reason=reason)
        else:
            if item is None or intent is not None:
                raise IntakeError('New intake history requires an original source item')
            history = planner.history(item)
            record = {'id': identity, 'collection': self.collection, 'kind': 'memory-note',
                      'content': {'title': 'Intake decision history', 'text': 'Proposals and corrections; not ground truth.'},
                      'relations': []}
        resource = self.authority.contract.collections[self.collection]['resource']
        source_resource = planner.boundary.policy.resources.get(
            planner.boundary.bindings['references'].get(fingerprint(history['item'])))
        if (not source_resource or source_resource['scope'] != planner.boundary.policy.resources[resource]['scope']
                or not planner.boundary.permits_resource(resource, identity)):
            raise IntakeError('Cross-scope intake history requires a publication/promotion adapter')
        replacement = deepcopy(record)
        replacement['content'].setdefault('data', {})['intakeHistory'] = history
        request = {'id': request_id, 'record': identity, 'resource': resource, 'mutation': 'correct' if current else 'create',
                   'expectedRevision': expected_revision, 'reason': reason,
                   'evidence': ['intake-event:' + history['events'][-1]['id']], 'sourceResource': None}
        planner.log('intake.proposing', actor, identity, {'event': history['events'][-1]['id']})
        result = self.authority.propose(request, replacement, actor, at=at)
        planner.log('intake.proposed', actor, identity, {'proposal': result['proposal']})
        return result
