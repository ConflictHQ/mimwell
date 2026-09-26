"""Parent-linked range transcripts with immutable inference and fresh release."""
from copy import deepcopy
from functools import lru_cache
import json
import math
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from brain_protection import combine
from intake_media import artifact, fields
from intake_recording_ranges import RecordingError, check as recording_check, integer
from intake_timing import timed_segment
from knowledge_policy import fingerprint, timestamp

FORMAT = 'intake-recording-transcription/v1'
IMMUTABLE = ('format', 'item', 'sourceChunk', 'profile', 'profileSha256', 'dependencies',
             'protection', 'language', 'coverage', 'requiresReview', 'timingSemantics', 'segments', 'gaps', 'usage', 'execution')


def check_profile(profile):
    fields(profile, ('format', 'whisper', 'model', 'language', 'threads', 'maxTextBytes',
                     'maxSegments', 'modelTimeoutSeconds', 'maxTimestampOverrunMs'))
    if profile['format'] != 'intake-recording-transcriber/v1':
        raise RecordingError('Unsupported recording transcriber profile')
    artifact(profile['whisper'], libraries=True)
    artifact(profile['model'])
    for key, cap in (('threads', 8), ('maxTextBytes', 1_048_576), ('maxSegments', 1000)):
        integer(profile[key], 1, cap)
    integer(profile['maxTimestampOverrunMs'], 0, 30000)
    deadline = profile['modelTimeoutSeconds']
    if type(deadline) not in (int, float) or not math.isfinite(deadline) or not 0 < deadline <= 120:
        raise RecordingError('Invalid recording model deadline')
    if not validator('profile').is_valid(profile):
        raise RecordingError('Invalid recording transcription profile')


@lru_cache(maxsize=None)
def validator(name='receipt'):
    root = Path(__file__).resolve().parents[1] / 'schemas'
    registry = Registry()
    for filename in ('intake.schema.json', 'intake-recording.schema.json'):
        schema = json.loads((root / filename).read_text())
        registry = registry.with_resource(schema['$id'], Resource.from_contents(schema))
    schema = json.loads((root / 'intake-recording-transcription.schema.json').read_text())
    return Draft202012Validator({'$ref': '#/$defs/' + name, '$defs': schema['$defs']}, registry=registry)


def range_item(descriptor):
    parent = descriptor['normalization']['item']
    value = deepcopy(parent)
    value['id'] = 'recording-range:' + descriptor['chunk']['id']
    interval = descriptor['chunk']['range']
    value['source']['reference']['locator'] = (
        'normalized-audio:' + descriptor['normalizationSha256'] + ':frames:'
        + str(interval['start']) + '-' + str(interval['end']))
    return value


def inference_digest(receipt):
    return fingerprint({k: receipt[k] for k in IMMUTABLE})


def check_chunk(descriptor):
    from intake_processed import bounded
    bounded(descriptor)
    recording_check(descriptor, 'chunk')
    normalization = descriptor['normalization']
    chunk, audio = descriptor['chunk'], descriptor['audio']
    interval = chunk['range']
    frames = interval['end'] - interval['start']
    if (fingerprint(normalization) != descriptor['normalizationSha256']
            or fingerprint({'normalizationSha256': descriptor['normalizationSha256'], 'range': interval}) != chunk['id']
            or not 1 <= frames <= 9_600_000 or interval['end'] > normalization['audio']['sampleFrames']
            or audio['sampleFrames'] != frames or audio['byteLength'] != frames * 2 + 44
            or descriptor['usage'] != {'sourceBytes': frames * 2, 'modelExecutions': 0}):
        raise RecordingError('Recording chunk identity, frame range or accounting changed')
    parent = normalization['item']['source']
    if parent['revision'] != 'sha256:' + parent['sha256']:
        raise RecordingError('Recording parent source revision changed')


def check_receipt(receipt):
    # Shared native-delivery limits; import lazily to avoid a validator cycle.
    from intake_processed import bounded
    bounded(receipt)
    if not validator().is_valid(receipt):
        raise RecordingError('Invalid recording transcription receipt')
    check_chunk(receipt['sourceChunk'])
    if (receipt['item'] != range_item(receipt['sourceChunk'])
            or fingerprint(receipt['profile']) != receipt['profileSha256']
            or inference_digest(receipt) != receipt['inferenceSha256']):
        raise RecordingError('Recording inference identity or immutable provenance changed')
    source_protection = receipt['sourceChunk']['protection']
    if (receipt['protection']['policySha256'] != source_protection['policySha256']
            or combine(receipt['protection']['requirements'], source_protection['requirements'])
                != receipt['protection']['requirements']):
        raise RecordingError('Recording transcript weakened its source protection')
    profile, usage, execution = receipt['profile'], receipt['usage'], receipt['execution']
    frames = receipt['sourceChunk']['audio']['sampleFrames']
    text_bytes = sum(len(s['text'].encode('utf-8')) for s in receipt['segments'])
    if (usage['sourceBytes'] != receipt['item']['source']['byteLength']
            or usage['normalizedBytes'] != frames * 2 + 44 or usage['textBytes'] != text_bytes
            or text_bytes > profile['maxTextBytes'] or len(receipt['segments']) > profile['maxSegments']
            or execution['sourceChunkSha256'] != fingerprint(receipt['sourceChunk'])
            or execution['profileSha256'] != receipt['profileSha256']
            or execution['principal'] != receipt['principal']
            or timestamp(execution['startedAt']) < timestamp(receipt['sourceChunk']['evaluatedAt'])
            or timestamp(execution['startedAt']) > timestamp(receipt['evaluatedAt'])
            or receipt['dependencies']['modelIdentity'] != fingerprint(
                {'transcriptionModelSha256': profile['model']['sha256']})
            or receipt['dependencies']['scope'] not in receipt['scopes']
            or receipt['gaps'] != ([] if any(s['text'].strip() for s in receipt['segments']) else ['no-transcript'])):
        raise RecordingError('Recording transcript accounting or execution binding changed')
    end = 0
    offset = receipt['sourceChunk']['chunk']['range']['start']
    for segment in receipt['segments']:
        locator = segment['reportedLocator']
        if locator['start'] < end:
            raise RecordingError('Recording estimates overlap or run backwards within a chunk')
        expected = timed_segment(locator['start'], locator['end'], segment['text'], frames,
                                 profile['maxTimestampOverrunMs'])
        expected['parentWindow'] = {'kind': 'audio-frames',
            'start': offset + expected['sourceWindow']['start'], 'end': offset + expected['sourceWindow']['end']}
        if segment != expected:
            raise RecordingError('Recording local-to-parent timing mapping changed')
        end = locator['end']
