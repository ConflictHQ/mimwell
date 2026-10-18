"""One-frame/one-page intake transport with backpressure and explicit resumption."""
from copy import deepcopy
from functools import lru_cache
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from classified_intake import ClassifiedIntakePlanner
from context_bundle import encode
from context_host import decode
from intake import IntakePlanner
from intake_contract import IntakeError, check as batch_check
from knowledge_policy import fingerprint

MAX_FRAME_BYTES = 1048576
MAX_RESULT_BYTES = MAX_FRAME_BYTES + 4096
MAX_SEQUENCE = 9007199254740991


@lru_cache(maxsize=None)
def validator(name, projected=False):
    root = Path(__file__).resolve().parents[1] / 'schemas'
    schema = json.loads((root / ('intake-stream-v3.schema.json' if projected == 'reuse' else
                                  'intake-stream-v2.schema.json' if projected else 'intake-stream.schema.json')).read_text())
    registry = Registry()
    for dependency in ('intake.schema.json', 'classifier.schema.json', 'classified-intake.schema.json') + (
            ('intake-text-projection.schema.json', 'projected-intake.schema.json',
             'intake-processing-reuse.schema.json', 'intake-reuse-selection.schema.json',
             'intake-text-projection-v2.schema.json', 'projected-intake-v2.schema.json') if projected else ()):
        document = json.loads((root / dependency).read_text())
        registry = registry.with_resource(document['$id'], Resource.from_contents(document))
    return Draft202012Validator({'$ref': '#/$defs/' + name, '$defs': schema['$defs']}, registry=registry)


def check(value, name, *, projected=False):
    if not validator(name, projected).is_valid(value) or len(value['stream'].encode('utf-8')) > 256:
        raise IntakeError('Invalid intake stream ' + name)
    if name == 'cursor':
        if ((value['sequence'] == 0) != (value['previous'] is None)
                or (value['frameSha256'] is None) != (value['inputSha256'] is None)
                or value['frameSha256'] is None and value['offset'] != 0):
            raise IntakeError('Invalid intake stream cursor position')


def cursor(frame, basis, *, offset=0, within=False):
    return {'format': 'intake-stream-cursor/v1', 'stream': frame['stream'],
            'sequence': frame['sequence'] if within else frame['sequence'] + 1,
            'previous': frame['previous'] if within else fingerprint(frame),
            'frameSha256': fingerprint(frame) if within else None,
            'offset': offset, 'inputSha256': fingerprint(frame['items']) if within else None,
            'planningSha256': basis}


def emit(output, value):
    raw = encode(value)
    if len(raw) > MAX_RESULT_BYTES:
        raise IntakeError('Intake stream output exceeds frame bound')
    remaining = memoryview(raw)
    while remaining:
        written = output.write(remaining)
        if type(written) is not int or not 0 < written <= len(remaining):
            raise OSError('Incomplete intake stream write')
        remaining = remaining[written:]
    output.flush()


def run(source, output, planner_factory, *, resume=None, max_frames=1000, max_pages=1000):
    """Plan and synchronously deliver pages; return complete or a bounded stop.

    The trusted factory owns current policy/time/actor and optional completion.
    Cursors position a producer; they never confer access or attest a write.
    A write/flush failure stops before another page/model/input frame is admitted.
    """
    if (not callable(planner_factory) or type(max_frames) is not int or not 1 <= max_frames <= 1000
            or type(max_pages) is not int or not 1 <= max_pages <= 1000):
        raise IntakeError('Invalid intake stream host limits')
    state = deepcopy(resume)
    if state is not None:
        check(state, 'cursor')
    frames = pages = 0

    def stop(reason):
        result = {'format': 'intake-stream-stop/v1', 'stream': state['stream'],
                  'reason': reason, 'cursor': deepcopy(state)}
        check(result, 'stop')
        emit(output, result)
        return result

    while True:
        if frames == max_frames:
            return stop('maxFrames')
        if pages == max_pages:
            return stop('maxPages')
        raw = source.readline(MAX_FRAME_BYTES + 1)
        if not raw:
            raise IntakeError('Intake stream interrupted before final frame')
        if not isinstance(raw, bytes) or len(raw) > MAX_FRAME_BYTES or not raw.endswith(b'\n'):
            raise IntakeError('Intake stream requires a bounded LF-terminated frame')
        frame = decode(raw.decode('utf-8'))
        check(frame, 'frame')
        if (len({item['id'] for item in frame['items']}) != len(frame['items'])
                or frame['sequence'] == MAX_SEQUENCE and not frame['final']):
            raise IntakeError('Duplicate item or exhausted stream sequence')
        frame_hash, input_hash = fingerprint(frame), fingerprint(frame['items'])
        if state is None:
            if frame['sequence'] != 0 or frame['previous'] is not None:
                raise IntakeError('Initial stream frame must start at zero')
            offset, basis = 0, None
        else:
            if (frame['stream'] != state['stream'] or frame['sequence'] != state['sequence']
                    or frame['previous'] != state['previous']
                    or state['frameSha256'] is not None and
                    (frame_hash != state['frameSha256'] or input_hash != state['inputSha256'])
                    or state['offset'] > len(frame['items'])):
                raise IntakeError('Intake stream continuation changed')
            offset, basis = state['offset'], state['planningSha256']
        frames += 1
        while True:
            if pages == max_pages:
                return stop('maxPages')
            planner = planner_factory()
            if not isinstance(planner, IntakePlanner):
                raise IntakeError('Intake stream requires a current native planner')
            classified = isinstance(planner, ClassifiedIntakePlanner)
            protocol = planner.PROTOCOL if classified else '1.0'
            projected = 'reuse' if protocol == '4.0' else protocol == '3.0'
            limits = {key: min(value, 1000 if key == 'maxItems' else MAX_FRAME_BYTES)
                      for key, value in planner.limits.items()}
            current_basis = fingerprint({'protocolVersion': protocol, 'basis': planner.basis,
                'classifier': planner.profile_sha256 if classified else None,
                'limits': planner.limits, 'actor': planner.boundary.actor})
            if basis is not None and basis != current_basis:
                raise IntakeError('Intake stream planning basis changed')
            basis = current_basis
            state = cursor(frame, basis, offset=offset, within=True)
            request = {'protocolVersion': protocol, 'items': frame['items'], 'offset': offset,
                       'inputSha256': input_hash, 'budget': limits}
            if classified:
                request['planningSha256'] = planner.planning_sha256
            page = planner.plan(request)
            batch_check(page, 'result', classified=planner.SCHEMA if classified else False)
            following = page['nextOffset']
            processed = offset + len(page['results'])
            if (len(encode(page)) > limits['maxOutputBytes'] or page['offset'] != offset
                    or page['inputSha256'] != input_hash or processed > len(frame['items'])
                    or following is None and processed != len(frame['items'])
                    or following is not None and following != processed):
                raise IntakeError('Invalid native stream page progression')
            next_state = (None if frame['final'] else cursor(frame, basis)) if following is None else cursor(
                frame, basis, offset=following, within=True)
            result = {'format': 'intake-stream-result/v3' if projected == 'reuse' else
                                'intake-stream-result/v2' if projected else 'intake-stream-result/v1', 'stream': frame['stream'],
                      'sequence': frame['sequence'], 'frameSha256': frame_hash,
                      'page': page, 'cursor': next_state}
            check(result, 'result', projected=projected)
            emit(output, result)
            pages += 1
            if next_state is None:
                return {'complete': True, 'frames': frames, 'pages': pages}
            state = next_state
            if following is None:
                break
            if following == offset:
                return stop('no-progress')
            offset = following
