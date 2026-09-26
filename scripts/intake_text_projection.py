"""Bounded extracted-text inputs and body-free commitments, never source locators.

Catalog headers/pins, loaders and live authorization belong to the trusted host.
Structural consistency is not processing/inference authenticity or training consent.
"""
from copy import deepcopy
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from brain_protection import assess, combine
from context_access import ReadBoundary
from context_bundle import encode
from federation_protection import SourceProtection, plaintext_profile
from intake_contract import IntakeError
from intake_processed import bounded, check as representation_check, effective_receipt, is_reuse
from intake_timing import is_transcription
from knowledge_policy import fingerprint, timestamp

FORMATS = ('intake-extraction/v1', 'intake-transcription/v1', 'intake-transcription/v2',
           'intake-recording-transcription/v1')
COORDINATES = ('locator', 'reportedLocator', 'sourceWindow', 'parentWindow', 'timingStatus')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@lru_cache(maxsize=None)
def validator(name, version=1):
    root = Path(__file__).resolve().parents[1] / 'schemas'
    registry = Registry()
    for filename in ('intake-text-projection.schema.json', 'intake-processing-reuse.schema.json',
                     'intake-reuse-selection.schema.json'):
        document = json.loads((root / filename).read_text())
        registry = registry.with_resource(document['$id'], Resource.from_contents(document))
    schema = json.loads((root / ('intake-text-projection-v2.schema.json' if version == 2 else
                                  'intake-text-projection.schema.json')).read_text())
    return Draft202012Validator({'$ref': '#/$defs/' + name, '$defs': schema['$defs']}, registry=registry)


def check(value, name):
    bounded(value)
    version = 2 if isinstance(value, dict) and ('reuse' in value or value.get('format') == 'intake-text-projection/v2') else 1
    if not validator(name, version).is_valid(value):
        raise IntakeError('Invalid intake text ' + name)
    if name == 'entry':
        document = processing_format(value) == 'intake-extraction/v1'
        recording = processing_format(value) == 'intake-recording-transcription/v1'
        coverage = ('utf8-source', 'pdf-text-layer') if document else (
            'selected-recording-range-transcript' if recording else 'selected-audio-transcript',)
        if ((value['processingModel'] is None) != document
                or (value['inheritedProtection'] is not None) != (recording or 'reuse' in value)
                or value['coverage'] not in coverage):
            raise IntakeError('Projection processing dependency or coverage changed')
        if 'reuse' in value:
            from intake_processing_cache import check_selection
            selected = value['reuse']
            check_selection(selected)
            original = selected['original']
            model = original['model']
            if (value['itemSha256'] != selected['itemSha256'] or value['sourceResource'] != selected['sourceResource']
                    or value['scope'] != selected['scope'] or value['processingPolicySha256'] != selected['policySha256']
                    or value['processingProfileSha256'] != original['profileSha256']
                    or value['processingModel'] != ({'identity':model['modelIdentity'], 'resource':model['modelResource']} if model else None)
                    or value['inheritedProtection'] != {'policySha256':selected['protection']['sourcePolicySha256'],
                                                       'requirements':selected['protection']['requirements']}):
                raise IntakeError('Projection reuse header dependencies changed')


def entry_for(representation, *, expected_sha256):
    """Derive a body-free header from an already authorized host representation."""
    representation_check(representation, 'representation')
    if fingerprint(representation) != expected_sha256:
        raise IntakeError('Selected representation pin changed')
    outer = representation['receipt']
    receipt = effective_receipt(outer)
    model = None
    if is_transcription(receipt):
        model = {'identity': receipt['dependencies']['modelIdentity'],
                 'resource': receipt['dependencies']['modelResource']}
    entry = {'itemSha256': fingerprint(outer['item']), 'representationSha256': expected_sha256,
             'receiptSha256': representation['sha256'], 'processingProfileSha256': receipt['profileSha256'],
             'processingPolicySha256': outer['policySha256'], 'processingFormat': outer['format'],
             'sourceResource': representation['sourceResource'], 'scope': representation['scope'],
             'processingModel': model, 'inheritedProtection': deepcopy(receipt.get('protection')),
             'coverage': receipt['coverage']}
    if is_reuse(outer):
        from intake_processing_cache import selection
        entry['reuse'] = selection(outer)
        entry['inheritedProtection'] = {'policySha256':outer['protection']['sourcePolicySha256'],
                                        'requirements':deepcopy(outer['protection']['requirements'])}
    check(entry, 'entry')
    return entry


class ProjectionCatalog:
    """Immutable body-free host index; the loader is invoked only for admitted input.

    Reuse the catalog between page factories. Its digest binds up to 10,000 exact
    headers without reading any body at construction. Larger jobs choose explicit
    catalog/stream partitions, not silent continuation across changing catalog pins.
    """

    def __init__(self, entries, *, expected_sha256, load):
        if not isinstance(entries, dict) or not 0 <= len(entries) <= 10000 or not callable(load):
            raise IntakeError('Invalid text projection host catalog')
        for identity, entry in entries.items():
            check(entry, 'entry')
            if identity != entry['itemSha256']:
                raise IntakeError('Projection catalog key differs from exact item')
        if fingerprint(entries) != expected_sha256:
            raise IntakeError('Projection catalog pin changed')
        self._entries, self._load = deepcopy(entries), load
        self._sha256 = expected_sha256

    @property
    def sha256(self):
        return self._sha256

    def entry(self, item):
        return deepcopy(self._entries.get(fingerprint(item)))

    def representation(self, item, entry):
        identity = fingerprint(item)
        if self._entries.get(identity) != entry:
            raise IntakeError('Projection catalog selection changed')
        # Caller must authorize header dependencies before crossing this host seam.
        representation = self._load(identity)
        bounded(representation)
        if (entry_for(representation, expected_sha256=entry['representationSha256']) != entry
                or representation['receipt']['item'] != item):
            raise IntakeError('Representation differs from selected source/header')
        return deepcopy(representation)


def source_kind(entry, item):
    from intake_media import DEMUXERS
    media = item['source']['mediaType']
    if 'reuse' in entry and entry['reuse']['original']['content'] != {
            key:item['source'][key] for key in ('sha256','byteLength','mediaType')}:
        raise IntakeError('Projected reuse source bytes differ from original processing')
    document = processing_format(entry) == 'intake-extraction/v1'
    expected = (('application/pdf',) if entry['coverage'] == 'pdf-text-layer' else
                ('text/plain', 'text/markdown')) if document else DEMUXERS
    if media not in expected:
        raise IntakeError('Projection processing format differs from original source media')


def authorize(entry, item, classifier_identity, boundary, protection, *, retained=None, reuse_authorization=None):
    """Live dependency/derivation gate shared by planner and native writer."""
    check(entry, 'entry')
    source_kind(entry, item)
    if (not isinstance(boundary, ReadBoundary) or not isinstance(protection, SourceProtection)
            or fingerprint(item) != entry['itemSha256']
            or boundary.policy.binding['sha256'] != entry['processingPolicySha256']):
        raise IntakeError('Projection source or current policy differs from selected processing')
    dependencies = {entry['itemSha256']: entry['sourceResource']}
    if 'reuse' in entry:
        original = entry['reuse']['original']
        dependencies[original['itemSha256']] = original['sourceResource']
    processing = entry['processingModel']
    if processing:
        dependencies[processing['identity']] = processing['resource']
    classifier_resource = boundary.bindings['references'].get(classifier_identity)
    if not classifier_resource:
        raise IntakeError('Projected classifier model unavailable')
    if classifier_identity in dependencies and dependencies[classifier_identity] != classifier_resource:
        raise IntakeError('Ambiguous projection model binding')
    dependencies[classifier_identity] = classifier_resource
    for identity, resource in dependencies.items():
        if (boundary.bindings['references'].get(identity) != resource
                or boundary.policy.resources.get(resource, {}).get('scope') != entry['scope']
                or not boundary.permits('references', identity)):
            raise IntakeError('Projection source/model unavailable or cross-scope')
    inherited = entry['inheritedProtection']
    required = combine(protection.for_resources(list(dependencies.values())),
                       *([inherited['requirements']] if inherited else []),
                       *([retained] if retained is not None else []))
    # Native execution and history can create crash-surviving plaintext derivatives.
    if not assess(required, plaintext_profile(), offline=True, operation='derive')['supported']:
        raise IntakeError('Plaintext projection cannot satisfy source/model protection')
    if 'reuse' in entry:
        if not callable(reuse_authorization):
            raise IntakeError('Current processing reuse selection authorization required')
        current = reuse_authorization(deepcopy(entry['reuse']), actor=boundary.actor, at=boundary.now)
        if (not isinstance(current, ReadBoundary) or current.actor != boundary.actor or current.now != boundary.now
                or current.policy.binding != boundary.policy.binding
                or current.bindings != boundary.bindings or current.scopes != boundary.scopes):
            raise IntakeError('Processing reuse selection authority changed')
    return {'identity': classifier_identity, 'resource': classifier_resource}, {
        'policySha256': protection.sha256, 'requirements': required}


def select_text(representation, profile):
    """Exact UTF-8-safe prefix of LF-joined segments, preserving native coordinates."""
    check(profile, 'profile')
    representation_check(representation, 'representation')
    original = effective_receipt(representation['receipt'])
    segments = original['segments']
    total_bytes = sum(len(segment['text'].encode('utf-8')) for segment in segments) + max(0, len(segments) - 1)
    remaining, pieces, selected = profile['maxTextBytes'], [], []
    for index, segment in enumerate(segments[:profile['maxSegments']]):
        separator = 1 if index else 0
        if remaining < separator:
            break
        remaining -= separator
        raw = segment['text'].encode('utf-8')
        prefix = raw[:remaining].decode('utf-8', errors='ignore').encode('utf-8')
        pieces.append(prefix.decode('utf-8'))
        selected.append({'index': index, 'coordinates': {key: deepcopy(segment[key]) for key in COORDINATES if key in segment},
                         'segmentTextBytes': len(raw), 'startByte': 0, 'endByte': len(prefix),
                         'textSha256': sha(prefix), 'gaps': deepcopy(segment.get('gaps', []))})
        remaining -= len(prefix)
        if len(prefix) < len(raw):
            break
    text = '\n'.join(pieces)
    truncated = len(selected) < len(segments) or len(text.encode('utf-8')) < total_bytes
    gaps = set(original['gaps'])
    gaps.update(gap for segment in segments for gap in segment.get('gaps', []))
    if truncated:
        gaps.add('projection-truncated')
    if not text.strip():
        gaps.add('projection-empty-window')
    return text, {'segments': selected, 'totalSegments': len(segments), 'totalTextBytes': total_bytes,
                  'textBytes': len(text.encode('utf-8')), 'textSha256': sha(text.encode('utf-8')),
                  'truncated': truncated, 'gaps': sorted(gaps)}


def project(item, representation, entry, profile, boundary, classifier, protection, *, projection_format=None):
    """Build exact model input and commitment after the caller's live read gate."""
    if (entry_for(representation, expected_sha256=entry['representationSha256']) != entry
            or representation['receipt']['item'] != item
            or timestamp(representation['receipt']['evaluatedAt']) > timestamp(boundary.now)):
        raise IntakeError('Projection representation source or observation changed')
    text, selection = select_text(representation, profile)
    source = {'id': 'intake-text:' + fingerprint(item), 'text': text}
    raw = encode({'protocolVersion': '1.0', 'items': [source]})
    descriptor = {'format': projection_format or ('intake-text-projection/v2' if 'reuse' in entry else 'intake-text-projection/v1'), 'profile': deepcopy(profile),
                  'profileSha256': fingerprint(profile), 'entry': deepcopy(entry),
                  'classifier': deepcopy(classifier), 'protection': deepcopy(protection),
                  'authorization': {'principal': boundary.actor, 'evaluatedAt': boundary.now,
                      'policySha256': boundary.policy.binding['sha256'],
                      'bindingsSha256': fingerprint(boundary.bindings), 'scopes': sorted(boundary.scopes)},
                  'modelInputId': source['id'], 'requestSha256': sha(raw), 'inputBytes': len(raw), **selection}
    validate_descriptor(descriptor, item)
    return source, descriptor


def validate_descriptor(value, item):
    """Body-free consistency; exact replay requires the separately pinned receipt."""
    check(value, 'projection')
    entry, profile, segments = value['entry'], value['profile'], value['segments']
    check(entry, 'entry')
    source_kind(entry, item)
    timestamp(value['authorization']['evaluatedAt'])
    if (value['modelInputId'] != 'intake-text:' + fingerprint(item)
            or value['profileSha256'] != fingerprint(profile) or entry['itemSha256'] != fingerprint(item)
            or entry['processingPolicySha256'] != value['authorization']['policySha256']
            or entry['scope'] not in value['authorization']['scopes']
            or len(segments) > profile['maxSegments'] or len(segments) > value['totalSegments']
            or value['textBytes'] > profile['maxTextBytes'] or value['textBytes'] > value['totalTextBytes']
            or value['textBytes'] != sum(row['endByte'] for row in segments) + max(0, len(segments) - 1)
            or value['truncated'] != (len(segments) < value['totalSegments'] or value['textBytes'] < value['totalTextBytes'])
            or ('projection-truncated' in value['gaps']) != value['truncated']
            or value['gaps'] != sorted(set(value['gaps']))):
        raise IntakeError('Projection profile, selection or source commitment changed')
    for index, row in enumerate(segments):
        if (row['index'] != index or row['startByte'] != 0 or row['endByte'] > row['segmentTextBytes']
                or index < len(segments) - 1 and row['endByte'] != row['segmentTextBytes']
                or not set(row['gaps']).issubset(value['gaps'])):
            raise IntakeError('Projection segment byte range changed')
        coordinates = row['coordinates']
        expected = ({'locator'} if processing_format(entry) in ('intake-extraction/v1', 'intake-transcription/v1')
                    else {'reportedLocator', 'sourceWindow', 'timingStatus'} |
                    ({'parentWindow'} if processing_format(entry) == 'intake-recording-transcription/v1' else set()))
        if set(coordinates) != expected:
            raise IntakeError('Projection native coordinate kind changed')
    if entry['inheritedProtection'] and combine(value['protection']['requirements'], entry['inheritedProtection']['requirements']) != value['protection']['requirements']:
        raise IntakeError('Projection weakened retained processing requirements')


def replay(value, item, representation):
    """Consistency-only replay using already available authorized body bytes."""
    validate_descriptor(value, item)
    if (entry_for(representation, expected_sha256=value['entry']['representationSha256']) != value['entry']
            or representation['receipt']['item'] != item):
        raise IntakeError('Projection replay representation changed')
    text, selected = select_text(representation, value['profile'])
    source = {'id': 'intake-text:' + fingerprint(item), 'text': text}
    raw = encode({'protocolVersion': '1.0', 'items': [source]})
    if (any(value[key] != expected for key, expected in selected.items())
            or value['requestSha256'] != sha(raw) or value['inputBytes'] != len(raw)):
        raise IntakeError('Projection replay differs from exact submitted input')
    return source


def digest(value):
    if not isinstance(value, str) or re.fullmatch('[a-f0-9]{64}', value) is None:
        raise IntakeError('Expected projection SHA-256 pin')
    return value


def processing_format(entry):
    return entry['reuse']['original']['processingFormat'] if 'reuse' in entry else entry['processingFormat']
