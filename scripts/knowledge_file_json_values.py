"""Typed JSON field values through the existing selected-file writer, never a grant.

Field values cross JavaScript as exact JSON strings. The canonical parser and
whole selected schema decide acceptance; fractional numbers keep the existing
writer's explicit refusal. Other fields/records are not transformed by a model.
"""
from copy import deepcopy
import json

from git_file_authoring import _document, _parse_document, _reject_decimals, _revision
from knowledge_policy import fingerprint
from knowledge_store import StoreError

MAX_CORRECTION = 131072
MAX_PROFILE = 196608


def _bounded(value):
    pending, count = [(value, 0)], 0
    while pending:
        child, depth = pending.pop()
        count += 1
        if depth > 64 or count > 16384:
            raise StoreError('JSON field structure exceeds bound')
        if isinstance(child, str):
            try:
                child.encode('utf-8', 'strict')
            except UnicodeError as exc:
                raise StoreError('JSON field text requires UTF-8') from exc
        if isinstance(child, dict):
            pending.extend((v, depth + 1) for pair in child.items() for v in pair)
        elif isinstance(child, list):
            pending.extend((v, depth + 1) for v in child)


def decode_field_wires(wires):
    if not isinstance(wires, dict) or not 1 <= len(wires) <= 64:
        raise StoreError('A bounded JSON field correction is required')
    result, total = {}, 0
    try:
        for name, wire in wires.items():
            if not isinstance(name, str) or not 1 <= len(name) <= 2000 or not isinstance(wire, str):
                raise StoreError('JSON fields require exact value wires')
            raw = wire.encode('utf-8', 'strict')
            total += len(name.encode('utf-8', 'strict')) + len(raw)
            if not raw or len(raw) > 65536 or total > MAX_CORRECTION:
                raise StoreError('JSON field wires exceed bound')
            # The canonical parser rejects duplicate keys, nonfinite values and
            # excessive parser recursion. Wrapping allows every JSON value type.
            wrapper = _parse_document(b'{"value":' + raw + b'}')
            if set(wrapper) != {'value'}:
                raise StoreError('A field wire must contain exactly one JSON value')
            value = wrapper['value']
            _bounded(value)
            _reject_decimals(value)
            result[name] = value
    except (UnicodeError, RecursionError) as exc:
        raise StoreError('JSON field wires require bounded UTF-8') from exc
    return result


def _resolve(schema, root):
    """Direct profile shape only; the actual whole schema still validates values."""
    seen = set()
    while isinstance(schema, dict) and '$ref' in schema:
        ref = schema['$ref']
        if not isinstance(ref, str) or not ref.startswith('#/') or ref in seen or len(seen) >= 32:
            raise StoreError('Direct JSON editor schema reference is unavailable')
        # Do not pretend to merge schema-composition siblings into a form.
        if set(schema) - {'$ref', 'description', 'title', '$comment'}:
            raise StoreError('Use the existing full-document writer for composed profile schemas')
        seen.add(ref)
        schema = root
        try:
            for token in ref[2:].split('/'):
                schema = schema[token.replace('~1', '/').replace('~0', '~')]
        except (KeyError, TypeError) as exc:
            raise StoreError('Direct JSON editor schema reference is unavailable') from exc
    return schema


def _selected(pin, raw, index):
    if pin['entry']['writer'] != 'json-commit' or not isinstance(raw, bytes) or len(raw) > pin['entry']['maxBytes']:
        raise StoreError('JSON values require the selected bounded JSON writer')
    document = _document(pin, raw)
    arrays = []
    for key, declaration in pin['schema'].get('properties', {}).items():
        shape = _resolve(declaration, pin['schema'])
        if key != 'changelog' and isinstance(shape, dict) and shape.get('type') == 'array':
            arrays.append((key, shape))
    if len(arrays) != 1:
        raise StoreError('Select one registered records collection')
    key, declaration = arrays[0]
    records = document.get(key)
    item = _resolve(declaration.get('items'), pin['schema'])
    if (type(index) is not int or not isinstance(records, list) or not 0 <= index < len(records)
            or not isinstance(records[index], dict) or not isinstance(item, dict)
            or item.get('type') != 'object' or not isinstance(item.get('properties'), dict)):
        raise StoreError('Selected JSON record profile unavailable')
    supported = {}
    for name, field in item['properties'].items():
        if not isinstance(name, str) or not 1 <= len(name) <= 2000:
            raise StoreError('Declared JSON field names exceed editor bound')
        if not isinstance(field, (dict, bool)) or field is False:
            continue
        resolved = _resolve(field, pin['schema'])
        if isinstance(resolved, dict) and resolved.get('readOnly') is True:
            continue
        supported[name] = deepcopy(field)
    if not 1 <= len(supported) <= 64:
        raise StoreError('Selected JSON field profile exceeds bound')
    return document, key, records[index], supported


def _wire(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def value_profile(pin, raw, index):
    _, key, record, supported = _selected(pin, raw, index)
    result = {'format': 'registered-json-record-values/v1', 'writer': 'json-commit',
              'sourcePath': pin['path'], 'sourceCommit': pin['sourceCommit'],
              'sourceRevision': _revision(pin['sourceCommit'], raw),
              'sourceSchemaSha256': pin['entry']['schemaSha256'],
              'recordKey': key, 'recordIndex': index, 'recordSha256': fingerprint(record),
              'recordWire': _wire(record), 'schemaWire': pin['schemaBytes'].decode('utf-8', 'strict'),
              'fields': {name: {'schemaWire': _wire(field), 'present': name in record,
                                'valueWire': _wire(record[name]) if name in record else None}
                         for name, field in supported.items()},
              'authorization': 'none; canonical-host-and-writer-required',
              'fractionalNumbers': 'existing-file-writer-refuses'}
    if len(_wire(result).encode('utf-8')) > MAX_PROFILE:
        raise StoreError('Selected JSON record/profile exceeds draft context bound')
    return result


def apply_field_wires(pin, raw, index, expected_record_sha256, wires):
    document, key, record, supported = _selected(pin, raw, index)
    if expected_record_sha256 != fingerprint(record):
        raise StoreError('Selected JSON record changed')
    changes = decode_field_wires(wires)
    if set(changes) - set(supported):
        raise StoreError('JSON correction includes an undeclared or read-only field')
    candidate = deepcopy(document)
    candidate[key][index].update(changes)
    if _wire(candidate[key][index]) == _wire(record):
        raise StoreError('JSON correction does not change the selected record')
    encoded = (_wire(candidate) + '\n').encode('utf-8')
    if len(encoded) > pin['entry']['maxBytes']:
        raise StoreError('Corrected JSON source exceeds registered bound')
    _document(pin, encoded)  # Actual whole selected schema, including local refs.
    return candidate


def preview_field_wires(pin, raw, args):
    if args['expectedRevision'] != _revision(pin['sourceCommit'], raw):
        raise StoreError('Selected JSON source changed before preview')
    candidate = apply_field_wires(pin, raw, args['recordIndex'], args['expectedRecordSha256'], args['fieldWires'])
    profile = value_profile(pin, raw, args['recordIndex'])
    return {'format': 'registered-json-record-values-preview/v1', 'sourceRevision': profile['sourceRevision'],
            'sourceCommit': profile['sourceCommit'],
            'sourcePath': profile['sourcePath'], 'sourceSchemaSha256': profile['sourceSchemaSha256'],
            'recordIndex': profile['recordIndex'], 'recordSha256': profile['recordSha256'],
            'changesSha256': fingerprint(args['fieldWires']), 'beforeRecordWire': profile['recordWire'],
            'afterRecordWire': _wire(candidate[profile['recordKey']][args['recordIndex']]),
            'proposalCreated': False, 'sourceWritten': False, 'approval': None}
