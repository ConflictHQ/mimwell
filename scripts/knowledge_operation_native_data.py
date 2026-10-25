"""Bounded domain-data transformation, never an authority or a second writer.

The only write remains knowledge_operations.execute -> store.propose. Actual
Contract validation, field authority, policy, protection and review still decide.
"""
from copy import deepcopy
import hashlib
import re

from context_host import decode
from knowledge_operation_record_patch import patched_record, validate_patch
from knowledge_policy import fingerprint
from knowledge_store import ROOT, StoreError, encoded

MAX_WIRE = 131072
MAX_SCHEMA = 262144


def _bounded(value):
    pending, count = [(value, 0)], 0
    while pending:
        child, depth = pending.pop()
        count += 1
        if count > 16384 or depth > 64:
            raise StoreError('Native data structure exceeds bound')
        if isinstance(child, str):
            child.encode('utf-8', 'strict')
        elif isinstance(child, dict):
            pending.extend((x, depth + 1) for pair in child.items() for x in pair)
        elif isinstance(child, list):
            pending.extend((x, depth + 1) for x in child)


def data_patch(wire):
    try:
        if not isinstance(wire, str) or not 1 <= len(wire.encode('utf-8', 'strict')) <= MAX_WIRE:
            raise StoreError('Exact bounded native data patch wire required')
        value = decode(wire.encode('utf-8', 'strict'))
        _bounded(value)
        if (not isinstance(value, dict) or set(value) != {'set', 'remove'}
                or not isinstance(value['set'], dict) or not isinstance(value['remove'], list)
                or not 1 <= len(value['set']) + len(value['remove']) <= 256
                or any(not isinstance(x, str) or len(x) > 2000
                       for x in [*value['set'], *value['remove']])
                or len(set(value['remove'])) != len(value['remove'])
                or set(value['set']) & set(value['remove'])):
            raise StoreError('Native data patch requires distinct set/remove fields')
        encoded(value).encode('utf-8', 'strict')
        return value
    except (UnicodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, StoreError):
            raise
        raise StoreError('Native data patch must be bounded finite UTF-8 JSON') from exc


def validate_native_patch(patch):
    if not isinstance(patch, dict) or not patch or set(patch) - {
            'title', 'text', 'addRelations', 'removeRelations', 'dataPatchWire'}:
        raise StoreError('Unsupported native data correction')
    ordinary = {k: v for k, v in patch.items() if k != 'dataPatchWire'}
    if ordinary:
        validate_patch(ordinary)
    if 'dataPatchWire' in patch:
        data_patch(patch['dataPatchWire'])


def validate_arguments(operation, args):
    if operation == 'authority.inspect' and args == {}:
        return
    if operation == 'collection.semantic-inspect' and isinstance(args, dict) and set(args) == {'collection'}:
        if isinstance(args['collection'], str) and 1 <= len(args['collection']) <= 2000:
            return
        raise StoreError('An exact native collection is required')
    if (operation != 'record.patch-propose' or not isinstance(args, dict) or set(args) != {
            'record', 'expectedRevision', 'requestId', 'patch', 'reason', 'evidence', 'expectedDataSchemaSha256'}):
        raise StoreError('Unsupported native payload operation')
    for key, limit in [('record', 2000), ('expectedRevision', 256), ('requestId', 2000), ('reason', 2000)]:
        if not isinstance(args[key], str) or not args[key].strip() or len(args[key]) > limit:
            raise StoreError('Bounded native identity/revision/reason required')
    if not isinstance(args['expectedDataSchemaSha256'], str) or re.fullmatch(r'[a-f0-9]{64}', args['expectedDataSchemaSha256']) is None:
        raise StoreError('Exact current native data schema required')
    if (not isinstance(args['evidence'], list) or not 1 <= len(args['evidence']) <= 128
            or any(not isinstance(x, str) or not x.strip() or len(x) > 2000 for x in args['evidence'])):
        raise StoreError('Native correction requires bounded evidence references')
    validate_native_patch(args['patch'])


def _engine_schema(name):
    # Same fixed installed-engine schema files used by Contract.validate_record;
    # never a caller path, DSN, instance module or new native database descriptor.
    with (ROOT / 'schemas' / (name + '.schema.json')).open('rb') as stream:
        raw = stream.read(MAX_SCHEMA + 1)
    if len(raw) > MAX_SCHEMA:
        raise StoreError('Canonical native schema exceeds presentation bound')
    return decode(raw)


def schema_profile(store, collection, *, actor, at):
    from knowledge_operation_semantics import inspect_collection
    semantics = inspect_collection(store, collection, actor=actor, at=at)
    kind = semantics['kind']
    schemas = [('native-record-data', _engine_schema('knowledge-record')['properties']['content']['properties']['data'])]
    if 'payloadSchema' in kind:
        schemas.append(('adopted-kind-payload', kind['payloadSchema']))
    if kind.get('node') == 'Metric':
        schemas.append(('canonical-metric-definition', _engine_schema('metric-definition')))
    if kind.get('node') == 'Term' and semantics['collection']['resource'] == 'business-terms':
        schemas.append(('canonical-business-term', _engine_schema('business-term')))
    # Keep independent schema roots so local $refs retain their actual scope.
    rows = []
    for source, schema in schemas:
        wire = encoded(schema)
        rows.append({'source': source, 'wire': wire, 'sha256': hashlib.sha256(wire.encode()).hexdigest()})
    profile = {'format': 'native-domain-data-schema/v1', 'collection': collection,
               'kind': semantics['collection']['kind'], 'authority': store.contract.authority,
               'contract': store.contract.binding, 'pointer': '/content/data', 'schemas': rows,
               'fieldAuthorities': deepcopy(semantics['collection']['fields']),
               'writer': 'record.patch-propose', 'authorization': 'none; existing-native-policy-required',
               'limits': 'Schema guidance is not permission; canonical correct/propose/review checks all metadata and field ownership.'}
    if len(encoded(profile).encode()) > MAX_SCHEMA:
        raise StoreError('Native data schema profile exceeds bound')
    profile['sha256'] = fingerprint(profile)
    return semantics, profile


def inspect_data_schema(store, collection, *, actor, at):
    semantics, profile = schema_profile(store, collection, actor=actor, at=at)
    return {**semantics, 'dataProfile': profile}


def corrected_record(store, current, args, *, actor, at):
    _, profile = schema_profile(store, current['collection'], actor=actor, at=at)
    if profile['sha256'] != args['expectedDataSchemaSha256']:
        raise StoreError('Native data schema changed; inspect before correcting')
    validate_native_patch(args['patch'])
    ordinary = {k: v for k, v in args['patch'].items() if k != 'dataPatchWire'}
    value = patched_record(current, ordinary) if ordinary else deepcopy(current)
    if 'dataPatchWire' in args['patch']:
        patch = data_patch(args['patch']['dataPatchWire'])
        data = deepcopy(current['content'].get('data', {}))
        if any(name not in data for name in patch['remove']):
            raise StoreError('Native data field changed or is absent')
        for name in patch['remove']:
            del data[name]
        data.update(deepcopy(patch['set']))
        value['content']['data'] = data
    if encoded(value) == encoded(current):
        raise StoreError('Native correction does not change the record')
    if len(encoded(value).encode('utf-8')) > MAX_SCHEMA:
        raise StoreError('Corrected native record exceeds editor bound')
    # The unmodified execute tail calls the SAME store.propose once. Its
    # canonical _prepare validates the actual Contract/Registry, field owner,
    # policy, protection, lifecycle, immutable identity, exact revision and graph.
    # Do not create a second validator/writer or duplicate its blob/native reads.
    return value
