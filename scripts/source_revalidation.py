"""Bounded fingerprints for reauthorizing previously released source rows.

Witnesses carry no record bodies and grant no access. The authenticated authority
must resolve each coordinate again and compare both native content and provenance.
"""
import re

from brain_federation import FederationError, fields, text
from context_bundle import encode
from context_host import MAX_INPUT_BYTES
from knowledge_policy import fingerprint

MAX_WITNESSES = 30000


def row_digest(row):
    return fingerprint({'record': row['record'],
                        'provenance': {k: v for k, v in row['provenance'].items() if k != 'evaluatedAt'}})


def validate_witnesses(value):
    if not isinstance(value, list) or len(value) > MAX_WITNESSES:
        raise FederationError('Invalid source witness bound')
    keys = []
    for row in value:
        fields(row, ('kind', 'address', 'sha256'))
        if row['kind'] not in ('node', 'edge'):
            raise FederationError('Unsupported source witness kind')
        text(row['address'])
        if not isinstance(row['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', row['sha256']):
            raise FederationError('Invalid source witness digest')
        keys.append((row['kind'], row['address']))
    if keys != sorted(set(keys)) or len(encode(value)) > MAX_INPUT_BYTES:
        raise FederationError('Source witnesses must be unique, sorted and bounded')


def witnesses(outcome):
    status = outcome['status']
    if status == 'resolved':
        nodes, edges = [outcome], []
    elif status == 'searched':
        nodes, edges = outcome['matches'], []
    elif status == 'composed':
        nodes, edges = outcome['nodes'], outcome['edges']
    else:
        raise FederationError('Unsupported source outcome')
    result = [{'kind': 'node', 'address': row['record']['id'], 'sha256': row_digest(row)} for row in nodes]
    result.extend({'kind': 'edge', 'address': row['coordinate']['address'], 'sha256': row_digest(row)} for row in edges)
    result.sort(key=lambda row: (row['kind'], row['address']))
    validate_witnesses(result)
    return result
