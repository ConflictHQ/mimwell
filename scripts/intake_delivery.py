"""Deterministic metadata materialization from a natively reviewed intake history.

This projection performs no model calls, source I/O, extraction or training export.
The canonical writer supplies current records, review evidence and permissions.
"""
from copy import deepcopy
from functools import lru_cache
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from context_bundle import encode
from intake_contract import IntakeError, validate_history
from knowledge_policy import fingerprint

PROFILE = 'intake-metadata-record/v1'


@lru_cache(maxsize=None)
def validator(name):
    root = Path(__file__).resolve().parents[1] / 'schemas'
    schema = json.loads((root / 'intake-delivery.schema.json').read_text())
    intake = json.loads((root / 'intake.schema.json').read_text())
    registry = Registry().with_resource(intake['$id'], Resource.from_contents(intake))
    return Draft202012Validator({'$ref': '#/$defs/' + name, '$defs': schema['$defs']}, registry=registry)


def check(value, name):
    if name == 'origin' and isinstance(value, dict) and value.get('format') == 'intake-processed-record/v1':
        from intake_processed import check as processed_check
        processed_check(value, name)
        return
    if not validator(name).is_valid(value):
        raise IntakeError('Invalid intake delivery ' + name)


def project(contract, source, pin, identity, collection, before=None):
    if (before or {}).get('content', {}).get('data', {}).get('intakeTransfer') is not None:
        raise IntakeError('An independently imported record requires its registered source peer')
    return project_destination(contract, source, pin, identity, collection,
                               contract.authority, contract.collections[collection]['kind'], before)


def project_destination(contract, source, pin, identity, collection, authority, kind, before=None):
    """Pure projection; a different authority is a target, never a permission grant."""
    if source.get('content', {}).get('status') in ('retracted', 'superseded', 'deleted'):
        raise IntakeError('Withdrawn intake history cannot authorize new delivery')
    history = source.get('content', {}).get('data', {}).get('intakeHistory')
    if len(encode(history)) > 1024 * 1024:
        raise IntakeError('Intake history exceeds the materialization bound')
    validate_history(history)
    if (history['basis']['policySha256'] != contract.policy.binding['sha256']
            or history['basis']['ontologySha256'] != contract.policy.binding['ontologySha256']):
        raise IntakeError('Intake history policy or ontology differs from this authority')
    event = history['events'][-1]
    decision = event['decision']
    representation = pin.get('representation')
    processing = 'extract' if representation is not None else 'metadata'
    if decision['action'] != 'keep' or decision['processing'] != processing or decision['gaps']:
        raise IntakeError('Only an explicit compatible keep decision can be materialized')
    selected = [row for row in decision['destinations'] if row['id'] == pin['destination']]
    if (len(selected) != 1 or selected[0]['status'] != 'proposed'
            or selected[0]['target']['authority'] != authority
            or selected[0]['target']['collection'] != collection
            or kind not in decision['kinds']):
        raise IntakeError('Intake decision does not propose this typed destination')
    item = history['item']
    if item['source']['reference']['availability'] != 'available':
        raise IntakeError('Unavailable source requires a new reviewed decision')
    title = item['metadata'].get('title', item['id'])
    if not isinstance(title, str) or not title.strip():
        title = item['id']
    text = encode(item['metadata']).decode('utf-8')
    profile = PROFILE
    if representation is not None:
        from intake_processed import PROFILE as processed_profile, check as processed_check, text as processed_text
        processed_check(representation, 'representation')
        if representation['receipt']['item'] != item:
            raise IntakeError('Processed representation belongs to another intake item')
        text, profile = processed_text(representation), processed_profile
    origin = {'format': profile, 'history': {'id': pin['source'], 'revision': pin['revision'],
              'sha256': pin['sha256'], 'event': event['id']}, 'basis': deepcopy(history['basis']),
              'item': deepcopy(item), 'labels': deepcopy(decision['labels']),
              'destination': deepcopy(selected[0]),
              'generated': {'title': fingerprint(title), 'text': fingerprint(text)}}
    if representation is not None:
        origin['representation'] = deepcopy(representation)
    record = {'id': identity, 'collection': collection, 'kind': kind,
              'content': {'title': title, 'text': text, 'data': {'intakeDelivery': origin}}, 'relations': []}
    if before is not None:
        old = before.get('content', {}).get('data', {}).get('intakeDelivery')
        if (not isinstance(old, dict) or old.get('format') not in (PROFILE, 'intake-processed-record/v1')
                or old['item']['id'] != item['id'] or old['item']['source']['id'] != item['source']['id']
                or any(old['item']['source']['reference'][key] != item['source']['reference'][key]
                       for key in ('backend', 'object'))
                or old['destination']['id'] != selected[0]['id']
                or old['destination']['target'] != selected[0]['target']):
            raise IntakeError('Existing record belongs to a different source or destination; reconcile explicitly')
        record = deepcopy(before)
        for field, value in (('title', title), ('text', text)):
            if fingerprint(before['content'].get(field)) == old['generated'][field]:
                record['content'][field] = value
            else:
                # Human ownership persists on subsequent refreshes too.
                origin['generated'][field] = old['generated'][field]
        record['content']['data']['intakeDelivery'] = origin
    check(origin, 'origin')
    if representation is not None:
        from intake_processed import MAX_BYTES
        if len(encode(record)) > MAX_BYTES or before is not None and len(encode(before)) > MAX_BYTES:
            raise IntakeError('Processed canonical record exceeds its byte budget')
    return record


def metadata_change(before, after, *, materializing):
    old = (before or {}).get('content', {}).get('data', {}).get('intakeDelivery')
    new = (after or {}).get('content', {}).get('data', {}).get('intakeDelivery')
    if old != new and not materializing:
        raise IntakeError('Intake delivery provenance changes require the native materialization operation')


class DeliveryBatch:
    """Bounded host coordinator for explicitly registered local destinations.

    Registrations bind logical participants to this exact authority instance;
    request data cannot select databases or confer review/source-release approval.
    Source and destination currently share this authority. Independent stores
    require a separate authenticated release adapter, never a fallback here.
    """
    def __init__(self, authority, registrations, *, clock, representation=None,
                 representation_sha256=None, boundary_factory=None):
        if not callable(clock) or not isinstance(registrations, dict) or not 1 <= len(registrations) <= 64:
            raise IntakeError('Explicit bounded destination registrations and clock required')
        for identity, target in registrations.items():
            if not isinstance(identity, str) or not identity.strip():
                raise IntakeError('Explicit destination identity required')
            check(target, 'registration')
            if target['authority'] != authority.contract.authority or target['collection'] not in authority.contract.collections:
                raise IntakeError('Registration belongs to another authority or collection')
        self.authority, self.registrations, self.clock = authority, deepcopy(registrations), clock
        self.binding = {'instance': authority._meta('instance'), 'contract': authority.contract.binding}
        if representation is not None:
            from intake_processed import bounded
            bounded(representation)
            if fingerprint(representation) != representation_sha256 or not callable(boundary_factory):
                raise IntakeError('Processed batch requires a pinned receipt and current host boundary')
        elif representation_sha256 is not None or boundary_factory is not None:
            raise IntakeError('Processed batch requires its representation')
        self.representation = deepcopy(representation)
        self.representation_sha256, self.boundary_factory = representation_sha256, boundary_factory

    def run(self, request, *, actor):
        import sqlite3
        if len(encode(request)) > 65536:
            raise IntakeError('Delivery request exceeds its byte bound')
        check(request, 'request')
        items, budget = request['items'], request['budget']
        if (type(budget['maxItems']) is not int or type(budget['maxBytes']) is not int
                or type(request['offset']) is not int or request['offset'] > len(items)):
            raise IntakeError('Invalid bounded delivery batch')
        seen = set()
        for item in items:
            for key, value in item.items():
                if key == 'expectedRevision' and value is None:
                    continue
                if len(value.encode('utf-8')) > 256:
                    raise IntakeError('Delivery identities exceed their bound')
            identity = item['destination'], item['record']
            if identity in seen:
                raise IntakeError('Duplicate delivery destination record')
            seen.add(identity)
        digest = fingerprint({'actor': actor, 'operation': request['operation'], 'history': request['history'],
                              'items': items, 'binding': self.binding, 'registrations': self.registrations,
                              **({'representationSha256': self.representation_sha256}
                                 if self.representation is not None else {})})
        if (request['inputSha256'] not in (None, digest) or request['offset'] and request['inputSha256'] != digest
                or self.binding != {'instance': self.authority._meta('instance'), 'contract': self.authority.contract.binding}):
            raise IntakeError('Delivery continuation or authority binding changed')
        result = {'format': 'intake-delivery-result/v1', 'operation': request['operation'], 'inputSha256': digest,
                  'binding': deepcopy(self.binding), 'offset': request['offset'], 'nextOffset': None,
                  'items': [], 'truncation': []}
        reserve = {**result, 'nextOffset': len(items), 'truncation': ['maxItems', 'maxBytes']}
        used = len(encode(reserve))
        if used > budget['maxBytes']:
            raise IntakeError('Output budget cannot hold a delivery envelope')
        for index in range(request['offset'], len(items)):
            if len(result['items']) == budget['maxItems']:
                result.update(nextOffset=index, truncation=['maxItems'])
                break
            item = items[index]
            outcome = {'destination': item['destination'], 'record': item['record'], 'status': 'unavailable'}
            reserved = len(encode({**outcome, 'proposal': 'a' * 32, 'receiptSha256': 'a' * 64, 'revision': 'a' * 256})) + 1
            if used + reserved > budget['maxBytes']:
                result.update(nextOffset=index, truncation=['maxBytes'])
                break  # Reserve a complete receipt before performing any write.
            target = self.registrations.get(item['destination'])
            at = self.clock()
            if target and self.authority.contract.can_read(target['collection'], actor, at):
                try:
                    if request['operation'] == 'prepare':
                        writer, options = self.authority.propose_intake, {}
                        if self.representation is not None:
                            writer = self.authority.propose_processed_intake
                            options = {'representation': self.representation,
                                       'expected_sha256': self.representation_sha256,
                                       'boundary': self.boundary_factory(actor, at)}
                        prepared = writer(request['history']['id'], request['history']['revision'],
                            item['destination'], item['record'], target['collection'], actor,
                            expected_revision=item['expectedRevision'], request_id=item['requestId'],
                            reason=('Materialize the reviewed metadata decision' if self.representation is None
                                    else 'Materialize the reviewed processed decision'),
                            at=at, destination_target=target, **options)
                        receipt = prepared.get('receipt')
                        outcome.update(status=prepared['status'], proposal=prepared['proposal'])
                    else:
                        proposal = self.authority._proposal(item['proposal'], at, allow_expired=True)
                        pin = proposal.get('promotion', {})
                        origin = proposal['record']['content'].get('data', {}).get('intakeDelivery', {})
                        profile = PROFILE if self.representation is None else 'intake-processed-record/v1'
                        if (pin.get('source') != request['history']['id'] or pin.get('revision') != request['history']['revision']
                                or pin.get('projection') != profile or pin.get('destination') != item['destination']
                                or proposal['request']['record'] != item['record'] or proposal['actor'] != actor
                                or proposal['record']['collection'] != target['collection']
                                or origin.get('destination', {}).get('target') != target):
                            raise IntakeError('Proposal belongs to another delivery intent')
                        if self.representation is not None:
                            from intake_processed import adopt
                            adopted = adopt(self.representation, self.representation_sha256,
                                self.boundary_factory(actor, at), self.authority.contract, actor, at)
                            if pin.get('representation') != adopted:
                                raise IntakeError('Proposal belongs to another representation')
                        receipt = self.authority.commit(item['proposal'], actor, at=at)
                        outcome.update(status='committed', proposal=item['proposal'])
                    if receipt is not None:
                        outcome.update(receiptSha256=fingerprint(receipt), revision=receipt['revision'])
                except (ValueError, KeyError, TypeError, OSError, sqlite3.Error):
                    outcome = {'destination': item['destination'], 'record': item['record'], 'status': 'unavailable'}
            used += len(encode(outcome)) + 1
            result['items'].append(outcome)
        return result
