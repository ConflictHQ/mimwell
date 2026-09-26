"""Pinned processing receipts adopted by the native reviewed publication writer.

The host supplies the actual processing boundary and a separately retained receipt
digest. Validation is consistency and current authorization, not proof of authentic
inference, current upstream availability, or permission to train on the result.
"""
from copy import deepcopy
from functools import lru_cache
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from context_access import ReadBoundary
from context_bundle import encode
from intake_contract import IntakeError
from intake_timing import is_transcription, timed_segment
from knowledge_policy import fingerprint, timestamp

PROFILE = 'intake-processed-record/v1'
MAX_BYTES = 4_194_304


def bounded(value):
    """Cap JSON before deepcopy, hashing or schema traversal, including cyclic input."""
    remaining = [64000, MAX_BYTES]

    def visit(node, depth):
        remaining[0] -= 1
        if depth > 16 or remaining[0] < 0:
            raise IntakeError('Processed representation structural budget exceeded')
        if isinstance(node, str):
            remaining[1] -= len(node)
        elif isinstance(node, dict):
            if len(node) > 128:
                raise IntakeError('Processed representation object budget exceeded')
            for key, child in node.items():
                if not isinstance(key, str):
                    raise IntakeError('Processed representation keys must be strings')
                visit(key, depth + 1)
                visit(child, depth + 1)
        elif isinstance(node, list):
            if len(node) > 1000:
                raise IntakeError('Processed representation array budget exceeded')
            for child in node:
                visit(child, depth + 1)
        elif node is not None and type(node) not in (bool, int, float):
            raise IntakeError('Processed representation must be JSON')
        if remaining[1] < 0:
            raise IntakeError('Processed representation text budget exceeded')

    visit(value, 0)
    if len(encode(value)) > MAX_BYTES:
        raise IntakeError('Processed representation byte budget exceeded')


@lru_cache(maxsize=None)
def validator(name, version=4):
    root = Path(__file__).resolve().parents[1] / 'schemas'
    registry = Registry()
    for filename in ('intake.schema.json', 'intake-extraction.schema.json', 'intake-transcription.schema.json',
                     'intake-transcription-v2.schema.json', 'intake-recording.schema.json',
                     'intake-recording-transcription.schema.json', 'intake-processed-delivery-v3.schema.json',
                     'intake-processing-reuse.schema.json'):
        schema = json.loads((root / filename).read_text())
        registry = registry.with_resource(schema['$id'], Resource.from_contents(schema))
    schema = json.loads((root / ('intake-processed-delivery-v3.schema.json' if version == 3 else 'intake-processed-delivery-v4.schema.json')).read_text())
    return Draft202012Validator({'$ref': '#/$defs/' + name, '$defs': schema['$defs']}, registry=registry)


def check(value, name):
    bounded(value)
    if not validator(name).is_valid(value):
        raise IntakeError('Invalid processed delivery ' + name)
    representation = value['representation'] if name == 'origin' else value
    receipt = representation['receipt']
    if is_reuse(receipt):
        from intake_processing_cache import check_receipt
        check_receipt(receipt)
        if (fingerprint(receipt) != representation['sha256']
                or representation['sourceResource'] != receipt['sourceResource']
                or representation['scope'] != receipt['scope']
                or name == 'origin' and value['item'] != receipt['item']):
            raise IntakeError('Reused representation source binding changed')
        return
    if (fingerprint(receipt) != representation['sha256']
            or fingerprint(receipt['profile']) != receipt['profileSha256']
            or representation['scope'] not in receipt['scopes']
            or receipt['usage']['sourceBytes'] != receipt['item']['source']['byteLength']):
        raise IntakeError('Processing receipt or profile binding changed')
    segments = receipt['segments']
    if not any(s['text'].strip() for s in segments) or receipt['gaps']:
        raise IntakeError('Empty processed content is not completed delivery')
    if receipt['format'] == 'intake-extraction/v1':
        profile = receipt['profile']
        pdf = profile['adapter'] == 'poppler-text/v1'
        output_bytes = sum(len(s['text'].encode('utf-8')) for s in segments) + (len(segments) if pdf else 0)
        if (receipt['coverage'] != ('pdf-text-layer' if pdf else 'utf8-source')
                or receipt['item']['source']['mediaType'] not in
                    (('application/pdf',) if pdf else ('text/plain', 'text/markdown'))
                or receipt['usage']['processCalls'] != int(pdf)
                or receipt['usage']['outputBytes'] != output_bytes
                or output_bytes > profile['maxTextBytes'] or len(segments) > profile['maxPages']
                or receipt['usage']['sourceBytes'] > profile['maxSourceBytes']):
            raise IntakeError('Document processing coverage or accounting changed')
        if receipt['coverage'] == 'utf8-source':
            raw = segments[0]['text'].encode('utf-8') if len(segments) == 1 else b''
            if (len(segments) != 1 or segments[0]['locator'] !=
                    {'kind': 'bytes', 'start': 0, 'end': len(raw)}
                    or len(raw) != receipt['item']['source']['byteLength']
                    or hashlib.sha256(raw).hexdigest() != receipt['item']['source']['sha256']):
                raise IntakeError('UTF-8 representation differs from exact source bytes')
        else:
            if any(s['locator'] != {'kind': 'page', 'number': i + 1} for i, s in enumerate(segments)):
                raise IntakeError('Physical PDF page identity changed')
        if any(s['gaps'] != ([] if s['text'].strip() else ['no-text']) for s in segments):
            raise IntakeError('Document coverage gaps changed')
    elif receipt['format'] == 'intake-recording-transcription/v1':
        from recording_transcript import check_receipt
        from intake_recording import require_spool
        check_receipt(receipt)
        require_spool(receipt['protection']['requirements'])
        if (receipt['dependencies']['sourceResource'] != representation['sourceResource']
                or receipt['dependencies']['scope'] != representation['scope']):
            raise IntakeError('Recording transcript source resource or scope changed')
    else:
        profile = receipt['profile']
        dependencies = receipt['dependencies']
        if (dependencies['sourceResource'] != representation['sourceResource']
                or dependencies['scope'] != representation['scope']
                or dependencies['modelIdentity'] != fingerprint(
                    {'transcriptionModelSha256': receipt['profile']['model']['sha256']})):
            raise IntakeError('Transcription dependency binding changed')
        text_bytes = sum(len(s['text'].encode('utf-8')) for s in segments)
        if (receipt['usage']['textBytes'] != text_bytes or text_bytes > profile['maxTextBytes']
                or len(segments) > profile['maxSegments']
                or receipt['usage']['sourceBytes'] > profile['maxSourceBytes']
                or receipt['audio']['sampleFrames'] > profile['maxAudioSeconds'] * 16000
                or receipt['usage']['normalizedBytes'] != 44 + receipt['audio']['sampleFrames'] * 2):
            raise IntakeError('Transcription budget or accounting changed')
        end = 0
        for segment in segments:
            version2 = receipt['format'] == 'intake-transcription/v2'
            locator = segment['reportedLocator' if version2 else 'locator']
            if not end <= locator['start'] <= locator['end']:
                raise IntakeError('Transcription timestamps are not ordered')
            if version2:
                try:
                    expected = timed_segment(locator['start'], locator['end'], segment['text'],
                        receipt['audio']['sampleFrames'], profile['maxTimestampOverrunMs'])
                except ValueError as exc:
                    raise IntakeError('Invalid transcription source window') from exc
                if segment != expected:
                    raise IntakeError('Transcription reported timing or source window changed')
            elif locator['end'] * 16 > receipt['audio']['sampleFrames']:
                raise IntakeError('Transcription timestamps exceed normalized audio')
            end = locator['end']
    if name == 'origin' and value['item'] != receipt['item']:
        raise IntakeError('Delivered representation belongs to another item')


def adopt(receipt, expected_sha256, boundary, contract, actor, at):
    bounded(receipt)
    if fingerprint(receipt) != expected_sha256 or not isinstance(boundary, ReadBoundary):
        raise IntakeError('Protected representation pin or processing boundary unavailable')
    if (boundary.actor != actor or boundary.policy.binding != contract.policy.binding
            or boundary.actor != receipt.get('principal') or boundary.now != at
            or fingerprint(boundary.bindings) != receipt.get('bindingsSha256')
            or sorted(boundary.scopes) != receipt.get('scopes')):
        raise IntakeError('Representation boundary differs from processing receipt')
    source = boundary.bindings['references'].get(fingerprint(receipt['item']))
    if not source or not boundary.permits('references', fingerprint(receipt['item'])):
        raise IntakeError('Representation source unavailable')
    representation = {'sha256': expected_sha256, 'receipt': deepcopy(receipt),
                      'sourceResource': source, 'scope': boundary.policy.resources[source]['scope']}
    check(representation, 'representation')
    for identity, resource, _ in dependencies(representation):
        if (boundary.bindings['references'].get(identity) != resource
                or not boundary.permits('references', identity)):
            raise IntakeError('Representation source/model unavailable')
    authorize(contract, representation, actor, at, source)
    return representation


def authorize(contract, representation, actor, at, source_resource):
    """Current native policy for the exact adopted resource bindings; no external I/O."""
    check(representation, 'representation')
    receipt = representation['receipt']
    if (source_resource != representation['sourceResource']
            or receipt['policySha256'] != contract.policy.binding['sha256']
            or timestamp(receipt['evaluatedAt']) > timestamp(at)):
        raise IntakeError('Representation source policy, resource or time changed')
    boundary = ReadBoundary(contract.policy, actor=actor, now=at, scopes=[representation['scope']],
        bindings={'nodes': {}, 'edges': {}, 'paths': {}, 'assertions': {}, 'references': {}})
    for _, resource, subject in dependencies(representation):
        if (contract.policy.resources.get(resource, {}).get('scope') != representation['scope']
                or not boundary.permits_resource(resource, subject)):
            raise IntakeError('Representation source/model protection unavailable')


def text(representation):
    return '\n'.join(segment['text'] for segment in effective_receipt(representation['receipt'])['segments'])


def current_protection(authority, representation, *, actor=None, at=None):
    """Live recording publication/completion gate; never used by historical validation.

    The callback is host-owned and must reload current source/model protection.
    Reopening an authority does not restore this registration from stored receipts.
    """
    receipt = representation['receipt']
    if is_reuse(receipt):
        provider = authority.intake_processing_reuse
        if not callable(provider) or actor is None or at is None:
            raise IntakeError('Current processing reuse authorization provider required')
        current = provider(deepcopy(receipt), actor=actor, at=at)
        if (not isinstance(current, ReadBoundary) or current.actor != actor or current.now != at
                or current.policy.binding != authority.contract.policy.binding):
            raise IntakeError('Processing reuse current actor, time or policy changed')
        for identity, resource, _ in dependencies(representation):
            if (current.bindings['references'].get(identity) != resource
                    or current.policy.resources.get(resource, {}).get('scope') != representation['scope']
                    or not current.permits('references', identity)):
                raise IntakeError('Processing reuse current dependencies unavailable')
        return
    if receipt['format'] != 'intake-recording-transcription/v1':
        return
    from federation_protection import SourceProtection
    from intake_recording import require_spool
    provider = authority.intake_processing_protection
    if not callable(provider):
        raise IntakeError('Current recording processing protection provider required')
    current = provider()
    if not isinstance(current, SourceProtection):
        raise IntakeError('Invalid current recording processing protection')
    recorded = receipt['dependencies']
    required = current.for_resources([recorded['sourceResource'], recorded['modelResource']])
    require_spool(required)
    if {'policySha256': current.sha256, 'requirements': required} != receipt['protection']:
        raise IntakeError('Recording source/model protection differs from its processing pin')


def is_reuse(receipt):
    return receipt.get('format') == 'intake-processing-reuse/v1'


def effective_receipt(receipt):
    """Original segment/profile interpretation only; never substitute its item."""
    return receipt['original']['receipt'] if is_reuse(receipt) else receipt


def source_dependencies(representation):
    """Reference hash, native resource, own item ID for each contributing source."""
    receipt = representation['receipt']
    values = [(fingerprint(receipt['item']), representation['sourceResource'], receipt['item']['id'])]
    if is_reuse(receipt):
        original = receipt['original']
        values.append((fingerprint(original['receipt']['item']), original['sourceResource'],
                       original['receipt']['item']['id']))
    return values


def dependencies(representation):
    values = source_dependencies(representation)
    receipt = effective_receipt(representation['receipt'])
    if is_transcription(receipt):
        model = receipt['dependencies']
        values.append((model['modelIdentity'], model['modelResource'], receipt['item']['id']))
    return values


def retained_requirements(representation):
    receipt = representation['receipt']
    return receipt['protection']['requirements'] if is_reuse(receipt) else None
