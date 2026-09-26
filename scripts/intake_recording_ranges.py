"""Deterministic plans over normalized audio; coverage is not transcription."""
from copy import deepcopy
from functools import lru_cache
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from intake_extraction import bounded_metadata
from intake_media import fields
from knowledge_policy import fingerprint


class RecordingError(ValueError):
    pass


@lru_cache(maxsize=None)
def validator(name):
    root = Path(__file__).resolve().parents[1] / 'schemas'
    schema = json.loads((root / 'intake-recording.schema.json').read_text())
    intake = json.loads((root / 'intake.schema.json').read_text())
    registry = Registry().with_resource(intake['$id'], Resource.from_contents(intake))
    return Draft202012Validator({'$ref': '#/$defs/' + name, '$defs': schema['$defs']}, registry=registry)


def check(value, name):
    if not validator(name).is_valid(value):
        raise RecordingError('Invalid recording ' + name)


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise RecordingError('Invalid recording range or budget')
    return value


def plan(normalization, *, ranges=None, window_frames=9_600_000, overlap_frames=0,
         max_chunks=256):
    """Half-open decoded sample ranges. Explicit ranges may leave declared gaps."""
    bounded_metadata(normalization)
    check(normalization, 'normalization')
    frames = integer(normalization['audio']['sampleFrames'], 1, 345_600_000)
    window_frames = integer(window_frames, 1, 9_600_000)
    overlap_frames = integer(overlap_frames, 0, window_frames - 1)
    max_chunks = integer(max_chunks, 1, 256)
    if ranges is None:
        ranges, start = [], 0
        while start < frames:
            if len(ranges) == max_chunks:
                raise RecordingError('Recording range count exceeds budget')
            end = min(start + window_frames, frames)
            ranges.append({'start': start, 'end': end})
            if end == frames:
                break
            start = end - overlap_frames
    if not isinstance(ranges, list) or not 1 <= len(ranges) <= max_chunks:
        raise RecordingError('Invalid recording range count')
    chunks, union, gaps, overlaps = [], [], [], []
    previous_start, previous_end = -1, 0
    identity = fingerprint(normalization)
    for interval in ranges:
        fields(interval, ('start', 'end'))
        start = integer(interval['start'], 0, frames - 1)
        end = integer(interval['end'], start + 1, frames)
        if (end - start > window_frames or start <= previous_start or end <= previous_end
                or previous_end - start > overlap_frames):
            raise RecordingError('Unordered, contained or excessive recording range')
        if start > previous_end:
            gaps.append({'start': previous_end, 'end': start})
        if start < previous_end:
            overlaps.append({'start': start, 'end': previous_end})
        if union and start <= union[-1]['end']:
            union[-1]['end'] = end
        else:
            union.append({'start': start, 'end': end})
        locator = {'kind': 'audio-frames', 'start': start, 'end': end}
        chunks.append({'id': fingerprint({'normalizationSha256': identity, 'range': locator}),
                       'range': locator})
        previous_start, previous_end = start, end
    if previous_end < frames:
        gaps.append({'start': previous_end, 'end': frames})
    return {'format': 'intake-recording-plan/v1', 'normalization': deepcopy(normalization),
            'normalizationSha256': identity, 'windowFrames': window_frames,
            'maxOverlapFrames': overlap_frames, 'maxChunks': max_chunks, 'chunks': chunks,
            'coverage': {'status': 'partial' if gaps else 'complete', 'union': union,
                         'gaps': gaps, 'overlaps': overlaps,
                         'coveredFrames': sum(r['end'] - r['start'] for r in union)}}


def verify_plan(value, normalization, *, expected_sha256):
    """Recompute identities and coverage, even when a producer supplied a pin."""
    fields(value, ('format', 'normalization', 'normalizationSha256', 'windowFrames',
                   'maxOverlapFrames', 'maxChunks', 'chunks', 'coverage'))
    chunks = value['chunks']
    if not isinstance(chunks, list) or not 1 <= len(chunks) <= 256:
        raise RecordingError('Invalid recording range count')
    ranges = []
    for chunk in chunks:
        fields(chunk, ('id', 'range'))
        fields(chunk['range'], ('kind', 'start', 'end'))
        ranges.append({k: chunk['range'][k] for k in ('start', 'end')})
    canonical = plan(normalization, ranges=ranges, window_frames=value['windowFrames'],
                     overlap_frames=value['maxOverlapFrames'], max_chunks=value['maxChunks'])
    # Compare to bounded canonical data before hashing any untrusted extra data.
    if value != canonical or fingerprint(canonical) != expected_sha256:
        raise RecordingError('Recording plan differs from its retained pin or source')
    return canonical
