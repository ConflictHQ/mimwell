"""Internal selected-file transformation, not authorization or a second writer.

Call only with the CURRENT pin returned by canonical git_file_authoring._load_pins
and exact source blob bytes. Returned candidates still go through that writer's
ordinary propose/review/publication/CAS path. No file, ref, network or native DB
is opened by this module. It does not edit an ontology declaration.
"""
from copy import deepcopy
import json

from git_file_authoring import _document, _revision
from knowledge_policy import fingerprint
from knowledge_store import StoreError


def _selected(pin, raw, index):
    if pin['entry']['writer'] != 'json-commit':
        raise StoreError('Structured corrections require the registered JSON writer')
    if not isinstance(raw, bytes) or len(raw) > pin['entry']['maxBytes']:
        raise StoreError('Selected source exceeds registered bound')
    document = _document(pin, raw)
    arrays = [(key, value) for key, value in pin['schema'].get('properties', {}).items()
              if key != 'changelog' and isinstance(value, dict) and value.get('type') == 'array']
    if len(arrays) != 1:
        raise StoreError('Selected source must declare one records collection')
    key, schema = arrays[0]
    records = document.get(key)
    item_schema = schema.get('items')
    if (not isinstance(records, list) or type(index) is not int or not 0 <= index < len(records)
            or not isinstance(records[index], dict) or not isinstance(item_schema, dict)
            or item_schema.get('type') != 'object' or not isinstance(item_schema.get('properties'), dict)):
        raise StoreError('Selected record/profile is unavailable')
    properties = item_schema['properties']
    supported = {}
    for name, declaration in properties.items():
        if not isinstance(declaration, dict) or declaration.get('readOnly') is True:
            continue
        if declaration.get('type') == 'string':
            supported[name] = declaration
        elif (declaration.get('type') == 'array' and isinstance(declaration.get('items'), dict)
              and declaration['items'].get('type') == 'string'):
            supported[name] = declaration
    if not supported or len(supported) > 64:
        raise StoreError('Selected scalar-field profile exceeds supported scope')
    return document, key, records[index], supported


def record_profile(pin, raw, index):
    _, key, record, supported = _selected(pin, raw, index)
    wire = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
    profile = {'format': 'registered-json-record-edit/v1', 'sourcePath': pin['path'],
               'sourceSchemaSha256': pin['entry']['schemaSha256'], 'sourceCommit': pin['sourceCommit'],
               'sourceRevision': _revision(pin['sourceCommit'], raw), 'recordKey': key,
               'recordIndex': index, 'recordSha256': fingerprint(record),
               'recordWire': wire, 'fields': deepcopy(supported),
               'writer': 'json-commit', 'authorization': 'none; canonical-host-and-writer-required'}
    if len(json.dumps(profile, ensure_ascii=False, allow_nan=False).encode('utf-8')) > 131072:
        raise StoreError('Selected record/profile exceeds bounded draft context')
    return profile


def apply_record_fields(pin, raw, index, expected_record_sha256, changes):
    document, key, record, supported = _selected(pin, raw, index)
    if expected_record_sha256 != fingerprint(record):
        raise StoreError('Selected record changed; inspect before correcting')
    if not isinstance(changes, dict) or not 1 <= len(changes) <= 64 or set(changes) - set(supported):
        raise StoreError('Correction fields are not declared editable scalar fields')
    total = 0
    for name, value in changes.items():
        declaration = supported[name]
        if declaration['type'] == 'string':
            if not isinstance(value, str):
                raise StoreError('Correction field requires text')
            values = [value]
        else:
            if not isinstance(value, list) or len(value) > 256 or any(not isinstance(item, str) for item in value):
                raise StoreError('Correction field requires bounded text values')
            values = value
        total += len(name.encode('utf-8'))
        for item in values:
            if len(item) > 65536:
                raise StoreError('Correction text exceeds bound')
            total += len(item.encode('utf-8'))
            if total > pin['entry']['maxBytes']:
                raise StoreError('Correction exceeds registered source bound')
    candidate = deepcopy(document)
    candidate[key][index].update(deepcopy(changes))
    if candidate[key][index] == record:
        raise StoreError('Correction does not change the selected record')
    encoded = (json.dumps(candidate, ensure_ascii=False, allow_nan=False, indent=2) + '\n').encode('utf-8')
    if len(encoded) > pin['entry']['maxBytes']:
        raise StoreError('Corrected source exceeds registered bound')
    _document(pin, encoded)  # Actual selected schema/local refs; never a parallel schema.
    return candidate
