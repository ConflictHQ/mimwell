"""Independent intake release: native source approval and pinned signed evidence.

The host supplies identities, keys, recipient mappings, protection and trusted time.
A signed offer is immutable evidence; only a fresh source witness authorizes a new
release. Neither is permission to write the independently governed destination.
"""
from copy import deepcopy
import datetime as dt
import json
import re

from brain_protection import (DEFAULT_REQUIREMENTS, MAX_BODY, ProtectionHost, assess,
                              combine, fields, opaque, profile, requirements,
                              retention_requirements)
from context_bundle import encode
from intake_contract import IntakeError
from intake_delivery import check as delivery_check, project_destination
from intake_processed import bounded, dependencies, retained_requirements, source_dependencies
from knowledge_policy import fingerprint, timestamp

RELEASE = 'intake-release/v1'
OFFER = 'intake-offer/v1'
WITNESS = 'intake-witness/v1'
BINDING_FIELDS = ('participant', 'authority', 'instance', 'contract', 'ontology')
TARGET_FIELDS = (*BINDING_FIELDS, 'collection', 'revision', 'kind', 'record', 'expectedRevision')
MAX_WIRE = MAX_BODY
MAX_WITNESS_AGE = 5


def text(value):
    if not isinstance(value, str) or not value.strip() or len(value.encode('utf-8')) > 256:
        raise IntakeError('Invalid bounded transfer identity')
    return value


def digest(value):
    if not isinstance(value, str) or re.fullmatch('[a-f0-9]{64}', value) is None:
        raise IntakeError('Invalid transfer digest')
    return value


def binding(value):
    fields(value, BINDING_FIELDS)
    for key in ('participant', 'authority'):
        text(value[key])
    opaque(value['instance'])
    for key in ('contract', 'ontology'):
        digest(value[key])
    return deepcopy(value)


def authority_binding(store, participant):
    return binding({'participant': participant, 'authority': store.contract.authority,
                    'instance': store._meta('instance'), 'contract': store.contract.binding,
                    'ontology': store.contract.policy.binding['ontologySha256']})


def target(value):
    fields(value, TARGET_FIELDS)
    binding({key: value[key] for key in BINDING_FIELDS})
    for key in ('collection', 'revision', 'kind', 'record'):
        text(value[key])
    if value['expectedRevision'] is not None:
        text(value['expectedRevision'])
    return deepcopy(value)


def route(value):
    return {key: value[key] for key in ('participant', 'authority', 'collection', 'revision')}


def release_options(value):
    fields(value, ('source', 'target', 'expiresAt', 'requirements', 'selected'))
    binding(value['source'])
    target(value['target'])
    timestamp(value['expiresAt'])
    requirements(value['requirements'])
    profile(value['selected'])
    # The released canonical payload and journal use plaintext. Transport signing
    # cannot make those stores encrypted, mediated, opaque, or derivative-free.
    require_retention(retention_requirements(value['requirements'], value['selected']))
    return deepcopy(value)


def require_retention(required):
    selected = {'mode': 'plaintext', 'key': None, 'resolver': None, 'signer': None,
                'recipientPolicy': '2' * 32, 'trust': 'reviewed'}
    if not assess(required, selected, operation='derive', offline=True)['supported']:
        raise IntakeError('Native plaintext destination cannot satisfy source protection')


def current_release_protection(store, pin, collection):
    """Before plaintext native source storage, re-read source-owned protection."""
    if not callable(store.intake_release_protection):
        raise IntakeError('Current native source protection provider required')
    resources = [pin['resource'], store.contract.collections[collection]['resource']]
    retained = None
    if 'representation' in pin:
        resources.extend(row[1] for row in dependencies(pin['representation']))
        retained = retained_requirements(pin['representation'])
    from federation_protection import SourceProtection
    current = store.intake_release_protection()
    if not isinstance(current, SourceProtection):
        raise IntakeError('Current native source protection provider required')
    required = combine(retention_requirements(pin['release']['requirements'], pin['release']['selected']),
                       current.for_resources(resources), *([retained] if retained else []))
    require_retention(required)
    return required


def release_project(contract, original, pin, identity, collection):
    options = release_options(pin['release'])
    if (options['source']['authority'] != contract.authority
            or options['source']['contract'] != contract.binding
            or options['source']['ontology'] != contract.policy.binding['ontologySha256']):
        raise IntakeError('Release source authority changed')
    to = options['target']
    if to['ontology'] != contract.policy.binding['ontologySha256']:
        raise IntakeError('Release requires an explicit compatible ontology')
    outgoing = project_destination(contract, original, pin, to['record'], to['collection'], to['authority'], to['kind'])
    if outgoing['content']['data']['intakeDelivery']['destination']['target'] != route(to):
        raise IntakeError('Release target differs from the reviewed route')
    grant = {'format': RELEASE, **options, 'payload': outgoing}
    value = {'id': identity, 'collection': collection, 'kind': contract.collections[collection]['kind'],
             'content': {'title': 'Intake release: ' + to['record'], 'data': {'intakeRelease': grant}}, 'relations': []}
    validate_release(grant)
    bounded(value)
    return value


def validate_release(value):
    bounded(value)
    fields(value, ('format', 'source', 'target', 'expiresAt', 'requirements', 'selected', 'payload'))
    if value['format'] != RELEASE:
        raise IntakeError('Unsupported intake release')
    release_options({key: value[key] for key in ('source', 'target', 'expiresAt', 'requirements', 'selected')})
    payload, to = value['payload'], value['target']
    fields(payload, ('id', 'collection', 'kind', 'content', 'relations'))
    fields(payload['content'], ('title', 'text', 'data'))
    fields(payload['content']['data'], ('intakeDelivery',))
    origin = payload['content']['data']['intakeDelivery']
    delivery_check(origin, 'origin')
    if ((payload['id'], payload['collection'], payload['kind']) != (to['record'], to['collection'], to['kind'])
            or payload['relations'] or origin['destination']['target'] != route(to)
            or origin['generated'] != {key: fingerprint(payload['content'][key]) for key in ('title', 'text')}):
        raise IntakeError('Released payload differs from its exact destination')


def release_change(before, after, *, releasing=False):
    old = (before or {}).get('content', {}).get('data', {}).get('intakeRelease')
    new = (after or {}).get('content', {}).get('data', {}).get('intakeRelease')
    if old != new and not releasing:
        raise IntakeError('Source releases require native reviewed construction')


def peer_descriptor(value):
    fields(value, ('source', 'selected', 'publicKey'))
    binding(value['source'])
    selected = profile(value['selected'])
    if (selected['signer'] is None or selected['mode'] != 'plaintext'
            or selected['trust'] != 'reviewed'):
        raise IntakeError('Transfer requires an independently pinned signing key')
    digest(value['publicKey'])
    return deepcopy(value)


def verifier(descriptor):
    """Historical verification only. Live callers must independently adopt this pin."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    peer_descriptor(descriptor)
    return ProtectionHost(actor='historical-transfer-verifier', authorize=lambda _r: True,
        keys=lambda _r: None, resolvers={}, verifiers={descriptor['selected']['signer']:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(descriptor['publicKey']))})


def object_pin(release_id):
    return fingerprint({'intakeRelease': text(release_id)})[:32]


def signed_open(entry, descriptor, release_id, release_revision):
    bounded(entry)
    # This format supports only inline signed JSON. No imported resolver/key handle
    # can cause I/O, and unsigned protected-record profiles are not accepted.
    peer_descriptor(descriptor)
    if len(encode(entry)) > MAX_WIRE:
        raise IntakeError('Signed transfer exceeds wire budget')
    return verifier(descriptor).open(entry, expected_object=object_pin(release_id),
        expected_revision=fingerprint(text(release_revision))[:32], expected_profile=descriptor['selected'],
        required={**DEFAULT_REQUIREMENTS, 'verifiedAuthorship': True})


def read_offer(entry, descriptor, release_id, release_revision):
    value = signed_open(entry, descriptor, release_id, release_revision)
    fields(value, ('format', 'source', 'release', 'revision', 'grant', 'review', 'sourceReview', 'issuedAt', 'requirements'))
    if (value['format'] != OFFER or value['source'] != descriptor['source']
            or value['release'] != release_id or value['revision'] != release_revision):
        raise IntakeError('Offer source or release binding changed')
    grant = value['grant']
    validate_release(grant)
    if grant['source'] != descriptor['source']:
        raise IntakeError('Offer authority differs from its released payload')
    if combine(retention_requirements(grant['requirements'], grant['selected']), value['requirements']) != value['requirements']:
        raise IntakeError('Offer weakened reviewed source protection')
    require_retention(value['requirements'])
    timestamp(value['issuedAt'])
    if timestamp(value['issuedAt']) >= timestamp(grant['expiresAt']):
        raise IntakeError('Offer expired before release')
    for key in ('review', 'sourceReview'):
        fields(value[key], ('actor', 'reason', 'at'))
        text(value[key]['actor'])
        if not isinstance(value[key]['reason'], str) or not value[key]['reason'].strip():
            raise IntakeError('Offer requires native review evidence')
        if timestamp(value[key]['at']) > timestamp(value['issuedAt']):
            raise IntakeError('Offer predates its review')
    return value


class ReleaseSource:
    """Source-owned recipient mapping, native release history and signing host.

    A recipient is {actor, audience}. Its actor belongs to the source policy;
    its audience is the independently adopted destination authority binding.
    Suppliers are reloaded on every operation and must be host-controlled.
    """
    def __init__(self, store, descriptor, *, host, recipients, protection, clock):
        self.store, self.descriptor = store, peer_descriptor(descriptor)
        if (not isinstance(host, ProtectionHost) or not callable(recipients)
                or not callable(protection) or not callable(clock)):
            raise IntakeError('Current source host dependencies required')
        key = host.verifiers.get(descriptor['selected']['signer'])
        if key is None or key.public_bytes_raw().hex() != descriptor['publicKey']:
            raise IntakeError('Source signer differs from its adopted peer')
        host.available(descriptor['selected'])
        self.host, self.recipients, self.protection, self.clock = host, recipients, protection, clock

    def _current(self, release_id, release_revision, consumer, at):
        if (self.store._meta('status') != 'active'
                or authority_binding(self.store, self.descriptor['source']['participant']) != self.descriptor['source']):
            raise IntakeError('Source authority is unavailable or changed')
        recipient = self.recipients().get(consumer)
        if not recipient:
            raise IntakeError('Source recipient unavailable')
        fields(recipient, ('actor', 'audience'))
        text(recipient['actor'])
        binding(recipient['audience'])
        current = self.store.get(release_id, recipient['actor'], at=at)
        if (not current or not current['record'] or current['withheldRelations']
                or current['revision'] != release_revision
                or current['record']['content'].get('status') in ('retracted', 'superseded', 'deleted')):
            raise IntakeError('Source release unavailable or changed')
        record = current['record']
        grant = record['content'].get('data', {}).get('intakeRelease')
        validate_release(grant)
        if ({key: grant['target'][key] for key in BINDING_FIELDS} != recipient['audience']
                or grant['source'] != self.descriptor['source'] or timestamp(at) >= timestamp(grant['expiresAt'])):
            raise IntakeError('Release audience changed or release expired')
        row = self.store.db.execute("SELECT body FROM events WHERE json_extract(body,'$.request.record')=? "
            "AND json_extract(body,'$.revision')=?", (release_id, release_revision)).fetchone()
        event = json.loads(row['body']) if row else None
        if (not event or event['request']['mutation'] != 'promote'
                or event.get('promotion', {}).get('projection') != RELEASE
                or event.get('after') != record or not event.get('review') or not event.get('sourceReview')):
            raise IntakeError('A release needs native source approval, not an imported claim')
        pin = event['promotion']
        original = self.store.get(pin['source'], recipient['actor'], at=at)
        if (not original or not original['record'] or original['withheldRelations']
                or original['revision'] != pin['revision'] or fingerprint(original['record']) != pin['sha256']):
            raise IntakeError('Released history unavailable or changed')
        self.store._reviewed_intake(pin)
        if release_project(self.store.contract, original['record'], pin, release_id, record['collection']) != record:
            raise IntakeError('Native release projection changed')
        # Current source/model access belongs to the mapped destination principal,
        # not just the signer. Both original reviewers must remain eligible.
        if 'representation' in pin:
            from intake_processed import authorize, current_protection
            for actor in {recipient['actor'], event['sourceReview']['actor'], event['review']['actor']}:
                current_protection(self.store, pin['representation'], actor=actor, at=at)
                authorize(self.store.contract, pin['representation'], actor, at, pin['resource'])
            for _, source_resource, _ in source_dependencies(pin['representation']):
                self.store.contract.source_reviewer(source_resource, event['sourceReview']['actor'], event['proposedBy'], at=at)
        self.store.contract.source_reviewer(pin['resource'], event['sourceReview']['actor'], event['proposedBy'], at=at)
        resource = self.store.contract.collections[record['collection']]['resource']
        self.store.contract.source_reviewer(resource, event['review']['actor'], event['proposedBy'], at=at)
        resources = [pin['resource'], resource]
        retained = None
        if 'representation' in pin:
            resources.extend(row[1] for row in dependencies(pin['representation']))
            retained = retained_requirements(pin['representation'])
        current_protection = self.protection().for_resources(resources)
        effective = combine(retention_requirements(grant['requirements'], grant['selected']), current_protection,
                            *([retained] if retained else []))
        require_retention(effective)
        return event, effective

    def _seal(self, value, release_id, release_revision):
        signed = self.host.seal(value, object_id=object_pin(release_id),
            revision=fingerprint(release_revision)[:32], required={**DEFAULT_REQUIREMENTS, 'verifiedAuthorship': True},
            selected=self.descriptor['selected'])
        bounded(signed)
        if len(encode(signed)) > MAX_WIRE:
            raise IntakeError('Signed transfer exceeds wire budget')
        return signed

    def offer(self, release_id, release_revision, *, consumer):
        # A native read transaction stabilizes the local journal. It is not a
        # distributed lease over the independent destination.
        with self.store.transaction():
            at = self.clock()
            event, effective = self._current(release_id, release_revision, consumer, at)
            value = {'format': OFFER, 'source': deepcopy(self.descriptor['source']), 'release': release_id,
                     'revision': release_revision, 'grant': deepcopy(event['after']['content']['data']['intakeRelease']),
                     'review': event['review'], 'sourceReview': event['sourceReview'], 'issuedAt': at,
                     'requirements': effective}
            signed = self._seal(value, release_id, release_revision)
            _, final = self._current(release_id, release_revision, consumer, self.clock())
            if final != effective:
                raise IntakeError('Protection changed while supplying offer')
            return signed

    def witness(self, release_id, release_revision, *, consumer, offer, intent, nonce):
        digest(intent)
        opaque(nonce)
        adopted = read_offer(offer, self.descriptor, release_id, release_revision)
        with self.store.transaction():
            at = self.clock()
            event, effective = self._current(release_id, release_revision, consumer, at)
            if adopted['grant'] != event['after']['content']['data']['intakeRelease']:
                raise IntakeError('Offer differs from current native release')
            effective = combine(adopted['requirements'], effective)
            require_retention(effective)
            expires = min(timestamp(at) + dt.timedelta(seconds=MAX_WITNESS_AGE), timestamp(adopted['grant']['expiresAt']))
            value = {'format': WITNESS, 'source': deepcopy(self.descriptor['source']), 'release': release_id,
                     'revision': release_revision, 'offerSha256': fingerprint(offer), 'intent': intent,
                     'nonce': nonce, 'issuedAt': at, 'expiresAt': expires.isoformat(timespec='milliseconds'),
                     'requirements': effective}
            signed = self._seal(value, release_id, release_revision)
            _, final = self._current(release_id, release_revision, consumer, self.clock())
            if combine(effective, final) != effective:
                raise IntakeError('Protection changed while releasing witness')
            return signed


def read_witness(entry, descriptor, offer, *, intent, nonce, at):
    release_id, release_revision = offer['storage']['body']['release'], offer['storage']['body']['revision']
    adopted = read_offer(offer, descriptor, release_id, release_revision)
    value = signed_open(entry, descriptor, release_id, release_revision)
    fields(value, ('format', 'source', 'release', 'revision', 'offerSha256', 'intent', 'nonce',
                   'issuedAt', 'expiresAt', 'requirements'))
    if (value['format'] != WITNESS or value['source'] != descriptor['source']
            or value['release'] != release_id or value['revision'] != release_revision
            or value['offerSha256'] != fingerprint(offer) or value['intent'] != digest(intent)
            or value['nonce'] != opaque(nonce)):
        raise IntakeError('Source witness differs from exact pending intent')
    issued, expires, now = timestamp(value['issuedAt']), timestamp(value['expiresAt']), timestamp(at)
    if (not timestamp(adopted['issuedAt']) <= issued <= now < expires
            or expires > issued + dt.timedelta(seconds=MAX_WITNESS_AGE)
            or expires > timestamp(adopted['grant']['expiresAt'])):
        raise IntakeError('Source witness is stale or outside its release lifetime')
    if combine(adopted['requirements'], value['requirements']) != value['requirements']:
        raise IntakeError('Witness weakened source protection')
    require_retention(value['requirements'])
    return value
