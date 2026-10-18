"""Explicit learned corrections enter the existing native review queue only.

Imported source coordinates describe an observation. They confer no identity,
authority or proof that a conversation/query really occurred. Native policy and
independent review govern the supplied desired record and evidence references.
"""
from copy import deepcopy
import os
import re

from context_bundle import encode
from context_host import decode
from knowledge_operations import MAX_REQUEST_BYTES, load_host, run
from knowledge_store import StoreError, utcnow


FIELDS = {'format', 'requestId', 'authority', 'resource', 'expectedRevision', 'record', 'source', 'reason', 'evidence'}
MAX_BASIS_BYTES = 48 * 1024


def correction_basis(root, host_config, authority, identity, *, binding, actor, authorize, clock=utcnow):
    """Read a complete correction basis from a trusted host-selected authority.

    The transport selects authority/binding and authenticates actor. A tool grant
    never supplies the native reader or proposal grants checked here.
    """
    if (not isinstance(identity, str) or not identity.strip() or len(identity) > 512
            or not isinstance(actor, str) or not actor or not callable(authorize)
            or authorize() != actor):
        raise StoreError('Correction basis unavailable')
    host = load_host(root, host_config)
    selected = host['authorities'].get(authority)
    if (selected is None or selected['binding'] != binding
            or not {'record.get', 'proposal.propose'} <= set(selected['grants'].get(actor, []))):
        raise StoreError('Correction basis unavailable')

    def guard():
        if authorize() != actor or load_host(root, host_config) != host:
            raise StoreError('Correction basis authorization changed')

    request = {'format': 'knowledge-operation-request/v1', 'authority': authority,
               'operation': 'record.get', 'arguments': {'record': identity}}

    def read():
        result = decode(run(root, host_config, request, actor=actor, authorize=authorize,
                            clock=clock, max_response_bytes=MAX_BASIS_BYTES))['native']
        if (not result or result.get('deleted') or result.get('withheldRelations')
                or not isinstance(result.get('record'), dict)):
            raise StoreError('Complete correction basis unavailable')
        return result

    before = read()
    from operation_backend import select_backend

    adapter, target, _, store_id, current = select_backend(root, selected)
    store = adapter(target, expected_binding=binding, readonly=True)
    try:
        if store_id is not None and store.contract.authority != store_id:
            raise StoreError('Correction basis authority changed')
        resource = store.contract.collections[before['record']['collection']]['resource']
        current()
        guard()
    finally:
        store.close()
    # Metadata and the first read confer no durable permission. Re-read through
    # the governed operation before releasing a bounded record/revision pair.
    after = read()
    if before != after:
        raise StoreError('Correction basis changed during read')
    result = {'format': 'mimwell-correction-basis/v1', 'authority': authority,
              'resource': resource, 'expectedRevision': after['revision'], 'record': after['record']}
    if len(encode(result)) > MAX_BASIS_BYTES:
        raise StoreError('Correction basis exceeds its limit')
    guard()
    current()
    return result


def validate(change):
    if not isinstance(change, dict) or set(change) != FIELDS or change['format'] != 'learned-change/v1':
        raise StoreError('Invalid learned change envelope')
    if len(encode(change)) > MAX_REQUEST_BYTES:
        raise StoreError('Learned change exceeds its limit')
    for key in ('requestId', 'authority', 'resource'):
        if not isinstance(change[key], str) or not change[key].strip() or len(change[key]) > 256:
            raise StoreError('Invalid learned change coordinate')
    if (change['expectedRevision'] is not None
            and (not isinstance(change['expectedRevision'], str) or not change['expectedRevision'].strip()
                 or len(change['expectedRevision']) > 256)):
        raise StoreError('Invalid learned change revision')
    if not isinstance(change['reason'], str) or not change['reason'].strip() or len(change['reason']) > 700:
        raise StoreError('A bounded correction reason is required')
    if (not isinstance(change['evidence'], list) or not 1 <= len(change['evidence']) <= 128
            or any(not isinstance(value, str) or not value.strip() or len(value) > 2000
                   for value in change['evidence'])):
        raise StoreError('Bounded native evidence references are required')
    value = change['record']
    if not isinstance(value, dict) or not isinstance(value.get('id'), str) or not value['id'].strip():
        raise StoreError('A desired native record is required')
    source = change['source']
    if (not isinstance(source, dict) or set(source) != {'kind', 'id', 'revision', 'observationSha256'}
            or source['kind'] not in ('conversation', 'run', 'app')
            or not isinstance(source['id'], str) or not source['id'].strip() or len(source['id']) > 256
            or not isinstance(source['revision'], str) or not source['revision'].strip() or len(source['revision']) > 128
            or not isinstance(source['observationSha256'], str)
            or not re.fullmatch(r'[a-f0-9]{64}', source['observationSha256'])):
        raise StoreError('A bounded attributed source observation is required')


def propose(root, host_config, change, *, actor=None, authorize=None, clock=utcnow):
    """Host-authenticated adapter: never review, commit, publish, or run a query.

    Default local identity comes from the protected host UID map. Transport
    callers supply both their trusted mapped actor and a fresh authorize callback.
    The native writer retains exact proposal/replay/CAS semantics and receipts.
    """
    change = deepcopy(change)
    validate(change)
    if actor is None:
        def local_identity():
            return load_host(root, host_config)['principalsByUid'].get(str(os.geteuid()))
        authorize = local_identity
        actor = authorize()
    if not isinstance(actor, str) or not actor or not callable(authorize) or authorize() != actor:
        raise StoreError('Learned change principal unavailable')

    def call(operation, arguments):
        request = {'format': 'knowledge-operation-request/v1', 'authority': change['authority'],
                   'operation': operation, 'arguments': arguments}
        return run(root, host_config, request, actor=actor, authorize=authorize, clock=clock)

    observed = decode(call('record.get', {'record': change['record']['id']}))['native']
    before = observed['record'] if observed else None
    revision = observed['revision'] if observed else None
    if (observed and observed.get('withheldRelations') or revision != change['expectedRevision']
            or before is None and change['expectedRevision'] is not None):
        raise StoreError('Learned change record unavailable or changed')
    if before is not None and any(change['record'].get(k) != before.get(k) for k in ('id', 'kind', 'collection')):
        raise StoreError('A correction cannot move the native record identity or collection')
    # Bind attribution into the existing native proposal request, so the queue,
    # replay checks and durable audit preserve it without a second journal/schema.
    reason = change['reason'] + '\nAttributed source observation (unverified): ' + encode(change['source']).decode().rstrip('\n')
    mutation = {'id': change['requestId'], 'record': change['record']['id'], 'resource': change['resource'],
                'mutation': 'create' if before is None else 'correct', 'expectedRevision': revision,
                'reason': reason, 'evidence': deepcopy(change['evidence']), 'sourceResource': None}
    return call('proposal.propose', {'request': mutation, 'record': change['record']})
