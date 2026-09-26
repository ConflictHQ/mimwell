"""Protection obligations travel with authorized data; they are never grants.

Source policies and consumer selections are independent host configuration. The
wire carries effective restrictions and opaque pins, not keys or policy resources.
Composition is a transient authorized read, not permission to retain its JSON.
"""
from copy import deepcopy
import re

from brain_federation import FederationError, fields, text
from brain_protection import (assess, combine, profile, requirements,
                              retention_requirements)
from knowledge_policy import fingerprint


def digest(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise FederationError('Invalid protection policy pin')
    return value


class SourceProtection:
    """An explicit immutable source-policy snapshot, reloaded by the source host."""

    def __init__(self, document, *, resources):
        fields(document, ('format', 'requirements', 'resources'))
        if document['format'] != 'source-protection/v1' or not isinstance(document['resources'], dict):
            raise FederationError('Unsupported source protection policy')
        requirements(document['requirements'])
        if not set(document['resources']) <= set(resources):
            raise FederationError('Unknown protection resource')
        for key, value in document['resources'].items():
            text(key)
            requirements(value)
        self._document = deepcopy(document)
        self.sha256 = fingerprint(document)

    def for_resources(self, resources):
        return combine(self._document['requirements'],
                       *(self._document['resources'][r] for r in resources if r in self._document['resources']))

    def receipt(self):
        return {'format': 'source-protection/v1', 'policySha256': self.sha256,
                'requirements': deepcopy(self._document['requirements'])}


def mount(value):
    fields(value, ('policySha256', 'selected'))
    digest(value['policySha256'])
    profile(value['selected'])
    return deepcopy(value)


def source_receipt(value, *, expected):
    fields(value, ('format', 'policySha256', 'requirements'))
    if value['format'] != 'source-protection/v1' or digest(value['policySha256']) != digest(expected):
        raise FederationError('Source protection changed')
    requirements(value['requirements'])
    return deepcopy(value)


def record_receipt(value, source):
    fields(value, ('policySha256', 'requirements'))
    if value['policySha256'] != source['policySha256']:
        raise FederationError('Record protection pin mismatch')
    if combine(source['requirements'], value['requirements']) != value['requirements']:
        raise FederationError('Record weakened source protection')
    return deepcopy(value)


def source_requirements(receipt, rows):
    """Conservative whole-source retention envelope for this selected projection.

    The shared index's dependency unit is a source. A restrictive released record
    therefore restricts the whole retained source, including transitive derivatives.
    No protected record is discarded to make an import appear complete.
    """
    fields(receipt, ('source', 'selected'))
    source = source_receipt(receipt['source'], expected=receipt['source']['policySha256'])
    selected = profile(receipt['selected'])
    values = [source['requirements']]
    for row in rows:
        values.append(record_receipt(row['provenance']['protection'], source)['requirements'])
    return retention_requirements(combine(*values), selected)


def plaintext_profile():
    # A capability description, never a real recipient policy or permission.
    return {'mode': 'plaintext', 'key': None, 'resolver': None, 'signer': None,
            'recipientPolicy': '0' * 32, 'trust': 'untrusted'}


def require_plaintext(required, *, derive=False):
    result = assess(required, plaintext_profile(), operation='derive' if derive else 'retain')
    if not result['supported']:
        raise FederationError('Selected destination cannot satisfy protection requirements')


def composition_sources(composition):
    """Reconstruct each source's inherited requirements without changing its rows."""
    if composition['protocolVersion'] != '2.0':
        raise FederationError('Explicit protection-aware composition required')
    result = {}
    for receipt in composition['sources']:
        if receipt['status'] != 'composed':
            continue
        target = receipt['source']
        key = (target['participant'], target['realm'])
        if key in result:
            raise FederationError('Duplicate protected source')
        rows = [r for table in ('nodes', 'edges') for r in composition[table]
                if (r['coordinate']['participant'], r['coordinate']['realm']) == key]
        result[key] = {**deepcopy(receipt['protection']),
                       'requirements': source_requirements(receipt['protection'], rows)}
    return result


def require_plaintext_composition(composition):
    """CLI/file sinks refuse incompatible selected profiles before serializing."""
    if composition['protocolVersion'] == '2.0':
        for value in composition_sources(composition).values():
            require_plaintext(value['requirements'])


def record_retention(composition, row):
    """Carry an exact composed row to another adapter with every endpoint source.

    The result describes restrictions only. The chosen destination must still
    enforce its own fresh retention/read grants and selected capabilities.
    """
    if not any(row == candidate for table in ('nodes', 'edges') for candidate in composition[table]):
        raise FederationError('Record is not part of this composition')
    sources = composition_sources(composition)
    coordinates = [row['coordinate']]
    if 'source' in row:
        nodes = [n['coordinate'] for n in composition['nodes']]
        for name in ('source', 'target'):
            if row[name] not in nodes:
                raise FederationError('Retained edge endpoint unavailable')
            coordinates.append(row[name])
    dependencies = {(c['participant'], c['realm']) for c in coordinates}
    return derivative_protection([{'participant': p, 'realm': r, 'protection': sources[(p, r)]}
                                  for p, r in dependencies])


def index_requirements(descriptor, current):
    """Independent fresh host state is mandatory, even if authorize returns True."""
    fields(current, ('policySha256', 'snapshotSha256', 'requirements', 'selected'))
    carried = descriptor['protection']
    if (digest(current['policySha256']) != carried['source']['policySha256']
            or digest(current['snapshotSha256']) != descriptor['snapshotSha256']
            or profile(current['selected']) != carried['selected']):
        raise FederationError('Retained protection selection changed')
    effective = combine(carried['requirements'],
                        retention_requirements(current['requirements'], current['selected']))
    if effective != carried['requirements']:
        raise FederationError('Current requirements require a fresh composition')
    # This index also creates lexical text at import. Read-only graph copies with
    # derivation forbidden require a different, explicitly selected adapter.
    require_plaintext(effective, derive=True)
    return effective


def derivative_protection(descriptors):
    """All declared source dependencies survive repeated mixed derivation."""
    entries = sorted(descriptors, key=lambda d: (d['participant'], d['realm']))
    return {'requirements': combine(*(d['protection']['requirements'] for d in entries)),
            'sources': [{'participant': d['participant'], 'realm': d['realm'],
                         'policySha256': d['protection']['source']['policySha256'],
                         'selected': deepcopy(d['protection']['selected'])} for d in entries]}
