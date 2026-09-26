"""Native destination integration for independently authenticated intake releases."""
from copy import deepcopy
import datetime as dt
import json
import secrets

from context_bundle import encode
from intake_contract import IntakeError
from intake_delivery import check as delivery_check
from intake_processed import bounded
from intake_transfer import (BINDING_FIELDS, MAX_WIRE, authority_binding, binding, digest,
                             peer_descriptor, read_offer, read_witness, require_retention, text)
from knowledge_policy import fingerprint, timestamp, validate as validate_request

ORIGIN = 'intake-transfer-origin/v1'


class LocalReleasePeer:
    """Trusted host registration; neither principal nor source handle is request data."""
    def __init__(self, source, *, descriptor, consumer, audience):
        self.source, self.descriptor = source, peer_descriptor(descriptor)
        self.consumer, self.audience = text(consumer), binding(audience)

    def offer(self, release, revision):
        return self.source.offer(release, revision, consumer=self.consumer)

    def witness(self, release, revision, *, offer, intent, nonce):
        return self.source.witness(release, revision, consumer=self.consumer, offer=offer, intent=intent, nonce=nonce)


def current_peer(store, identity, adopted=None):
    if not callable(store.intake_sources):
        raise IntakeError('Independent source registration unavailable')
    sources = store.intake_sources()
    if not isinstance(sources, dict) or not 1 <= len(sources) <= 64:
        raise IntakeError('Bounded source registrations required')
    peer = sources.get(text(identity))
    if peer is None:
        raise IntakeError('Independent source registration unavailable')
    descriptor = peer_descriptor(peer.descriptor)
    audience = binding(peer.audience)
    if audience != authority_binding(store, audience['participant']):
        raise IntakeError('Registered destination authority changed')
    if adopted is not None and (descriptor != adopted['descriptor'] or audience != adopted['audience']):
        raise IntakeError('Current source trust or audience differs from adopted transfer')
    return peer


def origin_check(value):
    from brain_protection import fields
    fields(value, ('format', 'source', 'peer', 'release', 'revision', 'offerSha256', 'requirements'))
    if value['format'] != ORIGIN:
        raise IntakeError('Unsupported transfer provenance')
    binding(value['source'])
    for key in ('peer', 'release', 'revision'):
        text(value[key])
    digest(value['offerSha256'])
    require_retention(value['requirements'])


def transfer_change(before, after, *, importing=False):
    old = (before or {}).get('content', {}).get('data', {}).get('intakeTransfer')
    new = (after or {}).get('content', {}).get('data', {}).get('intakeTransfer')
    if old != new and not importing:
        raise IntakeError('Transfer provenance requires the registered source writer')


def open_pin(pin):
    from brain_protection import fields
    fields(pin, ('peer', 'descriptor', 'audience', 'release', 'revision', 'offer'))
    for key in ('peer', 'release', 'revision'):
        text(pin[key])
    peer_descriptor(pin['descriptor'])
    binding(pin['audience'])
    offer = read_offer(pin['offer'], pin['descriptor'], pin['release'], pin['revision'])
    if {key:offer['grant']['target'][key] for key in BINDING_FIELDS} != pin['audience']:
        raise IntakeError('Source offer belongs to another destination')
    return offer


def project_import(pin, before):
    offer = open_pin(pin)
    record = deepcopy(offer['grant']['payload'])
    origin = {'format': ORIGIN, 'source': deepcopy(pin['descriptor']['source']), 'peer': pin['peer'],
              'release': pin['release'], 'revision': pin['revision'], 'offerSha256': fingerprint(pin['offer']),
              'requirements': deepcopy(offer['requirements'])}
    generated = record['content']['data']['intakeDelivery']
    if before is not None:
        old_transfer = before.get('content', {}).get('data', {}).get('intakeTransfer')
        old = before.get('content', {}).get('data', {}).get('intakeDelivery')
        if not isinstance(old_transfer, dict) or not isinstance(old, dict):
            raise IntakeError('Destination record is not owned by this transfer source')
        origin_check(old_transfer)
        delivery_check(old, 'origin')
        if (old_transfer['source'] != origin['source'] or old_transfer['peer'] != origin['peer']
                or any(before[k] != record[k] for k in ('id', 'collection', 'kind'))
                or old['destination']['id'] != generated['destination']['id']
                or old['destination']['target'] != generated['destination']['target']
                or old['item']['id'] != generated['item']['id']
                or old['item']['source']['id'] != generated['item']['source']['id']
                or any(old['item']['source']['reference'][k] != generated['item']['source']['reference'][k]
                       for k in ('backend', 'object'))):
            raise IntakeError('Destination record belongs to another qualified source')
        result = deepcopy(before)
        for field in ('title', 'text'):
            if fingerprint(before['content'].get(field)) == old['generated'][field]:
                result['content'][field] = record['content'][field]
            else:
                generated['generated'][field] = old['generated'][field]
        result['content']['data']['intakeDelivery'] = generated
        record = result
    record['content']['data']['intakeTransfer'] = origin
    bounded(record)
    return record


def validate_projection(contract, proposal, before, revision):
    pin = proposal['transfer']
    offer = open_pin(pin)
    to, request, record = offer['grant']['target'], proposal['request'], proposal['record']
    if (to['authority'] != contract.authority or to['contract'] != contract.binding
            or to['ontology'] != contract.policy.binding['ontologySha256']
            or to['collection'] not in contract.collections
            or to['kind'] != contract.collections[to['collection']]['kind']
            or to['record'] != request['record'] or to['expectedRevision'] != request['expectedRevision']
            or revision != request['expectedRevision'] or request['sourceResource'] is not None
            or request['resource'] != contract.collections[to['collection']]['resource']
            or request['mutation'] != ('create' if before is None else 'correct')
            or request['evidence'] != ['intake-transfer:' + fingerprint(pin)]
            or record != project_import(pin, before)):
        raise IntakeError('Transfer differs from source release or destination intent')
    return offer


def prepare(store, proposal, before, revision, actor, operation, at):
    current_peer(store, proposal['transfer']['peer'], proposal['transfer'])
    offer = validate_projection(store.contract, proposal, before, revision)
    if timestamp(at) >= timestamp(offer['grant']['expiresAt']):
        raise IntakeError('Source release expired')
    resource = proposal['request']['resource']
    if operation == 'review':
        store.contract.source_reviewer(resource, actor, proposal['actor'], at=at)
    if operation == 'commit':
        review = proposal.get('review')
        if not review or not timestamp(proposal['at']) <= timestamp(review['at']) <= timestamp(at):
            raise IntakeError('Independent destination review is required')
        store.contract.source_reviewer(resource, review['actor'], proposal['actor'], at=review['at'])
        store.contract.source_reviewer(resource, review['actor'], proposal['actor'], at=at)


def intent(proposal, actor):
    return fingerprint({'request': proposal['request'], 'record': proposal['record'], 'proposer': proposal['actor'],
                        'contract': proposal['contract'], 'committer': actor, 'transfer': proposal['transfer']})


def witness(store, proposal, actor):
    pin = proposal['transfer']
    peer = current_peer(store, pin['peer'], pin)
    nonce, digest_value = secrets.token_hex(16), intent(proposal, actor)
    signed = peer.witness(pin['release'], pin['revision'], offer=pin['offer'], intent=digest_value, nonce=nonce)
    evidence = {'nonce': nonce, 'intent': digest_value, 'signed': signed}
    verify_current_witness(store, proposal, actor, evidence)
    return evidence


def verify_current_witness(store, proposal, actor, evidence):
    pin = proposal['transfer']
    current_peer(store, pin['peer'], pin)
    if evidence['intent'] != intent(proposal, actor):
        raise IntakeError('Witness differs from destination commit intent')
    at = store.intake_clock()
    store._proposal(proposal['id'], at)
    store.contract.decision(proposal['request'], actor, 'commit', proposal['request']['expectedRevision'],
        at=at, proposed_by=proposal['actor'], reviewed_by=proposal['review']['actor'])
    store.contract.source_reviewer(proposal['request']['resource'], proposal['review']['actor'], proposal['actor'], at=at)
    return read_witness(evidence['signed'], pin['descriptor'], pin['offer'], intent=evidence['intent'],
                        nonce=evidence['nonce'], at=at)


def propose(store, peer_id, release_id, release_revision, identity, collection, actor, *,
            expected_revision, request_id, reason):
    for value in (peer_id, release_id, release_revision, identity, collection, request_id, actor):
        text(value)
    if expected_revision is not None:
        text(expected_revision)
    with store.transaction():
        at = store.intake_clock()
        if collection not in store.contract.collections or not store.contract.can_read(collection, actor, at):
            raise IntakeError('Destination unavailable')
        request = {'id': request_id, 'record': identity, 'resource': store.contract.collections[collection]['resource'],
                   'mutation': 'create' if expected_revision is None else 'correct', 'expectedRevision': expected_revision,
                   'reason': reason, 'evidence': ['pending-transfer'], 'sourceResource': None}
        validate_request(request, 'mutation-request')
        key = fingerprint({'transferRequest': request_id, 'actor': actor, 'contract': store.contract.binding})[:32]
        existing = store.db.execute('SELECT body FROM proposals WHERE id=?', (key,)).fetchone()
        if existing:
            proposal = json.loads(existing['body'])
            pin = proposal['transfer']
            compared = {**request, 'evidence':proposal['request']['evidence']}
            if ((pin['peer'], pin['release'], pin['revision']) != (peer_id, release_id, release_revision)
                    or compared != proposal['request'] or collection != proposal['record']['collection']
                    or proposal['actor'] != actor):
                raise IntakeError('Transfer request ID reused with different intent')
            previous = store.db.execute('SELECT body FROM receipts WHERE actor=? AND request_id=?', (actor, request_id)).fetchone()
            if previous:
                receipt = json.loads(previous['body'])
                if receipt.get('transfer') != pin or receipt['request'] != compared or receipt['after'] != proposal['record']:
                    raise IntakeError('Committed transfer differs from adopted intent')
                if any(not store._target_readable(edge['target'], actor, at) and edge['target'] != identity
                       for value in (receipt['before'], receipt['after']) if value for edge in value['relations']):
                    raise IntakeError('Transfer receipt relationships unavailable')
                return {'proposal': key, 'status':'committed', 'receipt':receipt}
            store._proposal(key, at)
            current, before, decision = store._prepare(proposal['request'], proposal['record'], actor, 'propose', proposal=proposal, at=at)
            return {'proposal':key, 'status':'prepared', 'before':before, 'after':deepcopy(proposal['record']),
                    'revision':current, 'decision':decision}
        row = store._row(identity)
        revision = row['revision'] if row else None
        if row and (row['collection'] != collection or row['deleted']):
            raise IntakeError('Destination identity unavailable')
        # Check local proposal permission and expected revision before requesting
        # source bytes. Source-side recipient checks remain separate.
        store.contract.decision(request, actor, 'propose', revision, at=at)
        peer = current_peer(store, peer_id)
        descriptor, audience = deepcopy(peer.descriptor), deepcopy(peer.audience)
        signed = peer.offer(release_id, release_revision)
        pin = {'peer':peer_id, 'descriptor':descriptor, 'audience':audience,
               'release':release_id, 'revision':release_revision, 'offer':signed}
        before = json.loads(row['body']) if row else None
        record = project_import(pin, before)
        if record['id'] != identity or record['collection'] != collection:
            raise IntakeError('Offer belongs to another requested destination')
        request['evidence'] = ['intake-transfer:' + fingerprint(pin)]
        at = store.intake_clock()
        proposal = {'id':key, 'request':request, 'record':record, 'actor':actor, 'at':at,
                    'contract':store.contract.binding, 'review':None, 'transfer':pin,
                    'expiresAt':(timestamp(at) + dt.timedelta(minutes=10)).isoformat(timespec='milliseconds')}
        if len(encode(proposal)) > MAX_WIRE * 2:
            raise IntakeError('Transfer proposal exceeds combined evidence budget')
        current, before, decision = store._prepare(request, record, actor, 'propose', proposal=proposal, at=at)
        from knowledge_store import encoded
        store.db.execute('INSERT INTO proposals VALUES (?,?)', (key, encoded(proposal)))
        return {'proposal':key, 'status':'prepared', 'before':before, 'after':deepcopy(record),
                'revision':current, 'decision':decision}


def validate_event(contract, event):
    from brain_protection import fields
    proposal = {'request':event['request'], 'record':event['after'], 'actor':event['proposedBy'],
                'contract':event['contract'], 'transfer':event['transfer']}
    validate_projection(contract, proposal, event['before'], event['previousRevision'])
    contract.writable(event['before'], event['after'])
    review = event.get('review')
    if not review or timestamp(review['at']) > timestamp(event['at']):
        raise IntakeError('Transfer journal requires independent destination review')
    contract.source_reviewer(event['request']['resource'], review['actor'], event['proposedBy'], at=review['at'])
    contract.source_reviewer(event['request']['resource'], review['actor'], event['proposedBy'], at=event['at'])
    contract.decision(event['request'], event['actor'], 'commit', event['previousRevision'], at=event['at'],
                      proposed_by=event['proposedBy'], reviewed_by=review['actor'])
    evidence = event['transferWitness']
    fields(evidence, ('nonce', 'intent', 'signed'))
    if evidence['intent'] != intent(proposal, event['actor']):
        raise IntakeError('Historical transfer intent differs from its witness')
    pin = event['transfer']
    read_witness(evidence['signed'], pin['descriptor'], pin['offer'], intent=evidence['intent'],
                 nonce=evidence['nonce'], at=event['at'])
