"""Accounted local audio decoding/transcription of protected historical captures."""
from copy import deepcopy
from functools import lru_cache
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import selectors
import subprocess
import tempfile
import time
import wave

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from context_access import ReadBoundary
from context_bundle import encode
from intake_capture import bind_capture
from intake_extraction import bounded_metadata
from intake_timing import timed_segment
from knowledge_policy import fingerprint
from local_classifier import document, pinned


class MediaError(ValueError):
    pass


DEMUXERS = {'audio/wav': 'wav', 'audio/x-wav': 'wav', 'audio/mpeg': 'mp3',
            'audio/mp4': 'mov', 'video/mp4': 'mov', 'audio/webm': 'matroska', 'video/webm': 'matroska'}


def model_identity(model_sha256):
    return fingerprint({'transcriptionModelSha256': model_sha256})


def fields(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise MediaError('Invalid media contract fields')


def artifact(value, *, libraries=False):
    fields(value, ('path', 'sha256', 'libraryDirectories') if libraries else ('path', 'sha256'))
    if (not isinstance(value['path'], str) or not 1 <= len(value['path']) <= 4096
            or '\x00' in value['path'] or not Path(value['path']).is_absolute()
            or not isinstance(value['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', value['sha256'])):
        raise MediaError('Invalid media artifact pin')
    if libraries:
        paths = value['libraryDirectories']
        if (not isinstance(paths, list) or len(paths) > 8
                or any(not isinstance(p, str) or not 1 <= len(p) <= 4096 or ':' in p or '\x00' in p
                       or not Path(p).is_absolute() for p in paths)):
            raise MediaError('Invalid media library directories')
        for p in paths:
            path = Path(p)
            if path != path.resolve(strict=True) or not path.is_dir():
                raise MediaError('Media library directory must be canonical')


def check_profile(profile):
    version = profile.get('format') if isinstance(profile, dict) else None
    extra = ('maxTimestampOverrunMs',) if version == 'intake-media-profile/v2' else ()
    fields(profile, ('format', 'ffmpeg', 'whisper', 'model', 'language', 'threads', 'maxSourceBytes',
                     'maxAudioSeconds', 'maxTextBytes', 'maxSegments', 'decodeTimeoutSeconds', 'modelTimeoutSeconds') + extra)
    if version not in ('intake-media-profile/v1', 'intake-media-profile/v2'):
        raise MediaError('Unsupported media profile')
    if extra and (type(profile['maxTimestampOverrunMs']) is not int
                  or not 0 <= profile['maxTimestampOverrunMs'] <= 30000):
        raise MediaError('Invalid model timestamp overrun budget')
    artifact(profile['ffmpeg'], libraries=True)
    artifact(profile['whisper'], libraries=True)
    artifact(profile['model'])
    if not isinstance(profile['language'], str) or not re.fullmatch('auto|[a-z]{2,3}', profile['language']):
        raise MediaError('Invalid transcription language')
    for name, cap in (('threads', 8), ('maxSourceBytes', 67_108_864), ('maxAudioSeconds', 600),
                      ('maxTextBytes', 1_048_576), ('maxSegments', 1000)):
        if type(profile[name]) is not int or not 1 <= profile[name] <= cap:
            raise MediaError('Invalid media budget')
    for name in ('decodeTimeoutSeconds', 'modelTimeoutSeconds'):
        if type(profile[name]) not in (int, float) or not math.isfinite(profile[name]) or not 0 < profile[name] <= 120:
            raise MediaError('Invalid media deadline')


def check_capsule(capsule, registration, cap):
    fields(capsule, ('format', 'receipt', 'body'))
    fields(capsule['body'], ('encoding', 'data'))
    if capsule['format'] != 'intake-capsule/v1' or capsule['body']['encoding'] != 'base64':
        raise MediaError('Invalid media capsule')
    try:
        data, size = capsule['body']['data'], capsule['receipt']['item']['source']['byteLength']
        if (not isinstance(data, str) or type(size) is not int or not 0 <= size <= cap
                or len(data) > ((cap + 2) // 3) * 4):
            raise MediaError('Media source budget exceeded')
    except (KeyError, TypeError) as exc:
        raise MediaError('Invalid media capsule') from exc
    bounded_metadata(registration)
    bounded_metadata(capsule['receipt'])


def authorization(boundary, item, model_sha256):
    if (not isinstance(boundary, ReadBoundary) or not boundary.permits('references', fingerprint(item))
            or not boundary.permits('references', model_identity(model_sha256))):
        raise MediaError('Media source or model unavailable')
    source = boundary.bindings['references'][fingerprint(item)]
    model = boundary.bindings['references'][model_identity(model_sha256)]
    if boundary.policy.resources[source]['scope'] != boundary.policy.resources[model]['scope']:
        raise MediaError('Cross-scope model-derived content requires explicit publication')
    return {'sourceResource': source, 'modelResource': model,
            'scope': boundary.policy.resources[source]['scope'], 'modelIdentity': model_identity(model_sha256)}


def execute(binary, files, argv, *, library_directories, timeout, output_cap, reject_diagnostics):
    """Private copied inputs; fixed caller-owned argv; bounded stdout/stderr/deadline.

    This POSIX process boundary is not a native memory/network sandbox. File I/O
    before launch is outside the child deadline. JSON is stdout, never a result file.
    """
    if os.name != 'posix':
        raise MediaError('Media process boundary requires POSIX')
    with tempfile.TemporaryDirectory(prefix='brain-media-') as temp:
        executable = Path(temp) / 'engine'
        executable.write_bytes(binary)
        executable.chmod(0o500)
        for name, content in files.items():
            if name not in ('source.bin', 'audio.wav', 'model.bin'):
                raise MediaError('Invalid media working input')
            path = Path(temp) / name
            path.write_bytes(content)
            path.chmod(0o600)
        env = {'HOME': temp, 'LC_ALL': 'C'}
        if library_directories:
            selected = ':'.join(library_directories)
            env.update(DYLD_LIBRARY_PATH=selected, LD_LIBRARY_PATH=selected)
        with selectors.DefaultSelector() as selector:
            process = subprocess.Popen([str(executable), *argv], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=temp, env=env, start_new_session=True)
            output, errors = bytearray(), bytearray()
            deadline = time.monotonic() + timeout
            try:
                selector.register(process.stdout, selectors.EVENT_READ, (output, output_cap))
                selector.register(process.stderr, selectors.EVENT_READ, (errors, 65_536))
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise MediaError('Media process deadline exceeded')
                    for key, _ in selector.select(min(.1, remaining)):
                        chunk = os.read(key.fileobj.fileno(), 65_536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        target, cap = key.data
                        target.extend(chunk)
                        if len(target) > cap:
                            raise MediaError('Media process output budget exceeded')
                remaining = deadline - time.monotonic()
                if remaining <= 0 or process.wait(timeout=remaining) != 0 or reject_diagnostics and errors:
                    raise MediaError('Media process failed')
                return bytes(output)
            except subprocess.TimeoutExpired as exc:
                raise MediaError('Media process deadline exceeded') from exc
            finally:
                try:
                    os.killpg(process.pid, 9)
                except ProcessLookupError:
                    pass
                process.wait()
                process.stdout.close()
                process.stderr.close()


def wav_bytes(pcm):
    if not pcm or len(pcm) % 2:
        raise MediaError('Decoded audio is empty or incomplete')
    stream = io.BytesIO()
    with wave.open(stream, 'wb') as audio:
        audio.setnchannels(1)
        audio.setsampwidth(2)
        audio.setframerate(16000)
        audio.writeframes(pcm)
    return stream.getvalue()


def segments_from_native(output, profile, frames):
    value = document(output.decode('utf-8'))
    fields(value, ('systeminfo', 'model', 'params', 'result', 'transcription'))
    fields(value['params'], ('model', 'language', 'translate'))
    fields(value['result'], ('language',))
    language = value['result']['language']
    if (value['params'] != {'model': 'model.bin', 'language': profile['language'], 'translate': False}
            or not isinstance(language, str) or not re.fullmatch('[a-z]{2,3}', language)
            or profile['language'] != 'auto' and language != profile['language']):
        raise MediaError('Native transcription parameters changed')
    rows = value['transcription']
    if not isinstance(rows, list) or len(rows) > profile['maxSegments']:
        raise MediaError('Native transcription segment budget exceeded')
    version2 = profile['format'] == 'intake-media-profile/v2'
    segments, last, size = [], 0, 0
    for row in rows:
        fields(row, ('timestamps', 'offsets', 'text'))
        fields(row['offsets'], ('from', 'to'))
        fields(row['timestamps'], ('from', 'to'))
        start, end = row['offsets']['from'], row['offsets']['to']
        if (type(start) is not int or type(end) is not int or not last <= start <= end
                or (not version2 and end * 16 > frames) or not isinstance(row['text'], str)):
            raise MediaError('Invalid native transcription offsets or text')
        # Native printable timestamps must agree with the authoritative ms fields.
        for key, milliseconds in (('from', start), ('to', end)):
            h, remain = divmod(milliseconds, 3_600_000)
            m, remain = divmod(remain, 60_000)
            s, ms = divmod(remain, 1000)
            if row['timestamps'][key] != f'{h:02}:{m:02}:{s:02},{ms:03}':
                raise MediaError('Native transcription timestamps disagree')
        size += len(row['text'].encode('utf-8'))
        if size > profile['maxTextBytes']:
            raise MediaError('Transcript text budget exceeded')
        if version2:
            try:
                segment = timed_segment(start, end, row['text'], frames, profile['maxTimestampOverrunMs'])
            except ValueError as exc:
                raise MediaError('Invalid native model timing window') from exc
        else:
            segment = {'locator': {'kind': 'audio-ms', 'start': start, 'end': end}, 'text': row['text']}
        segments.append(segment)
        last = end
    return segments, language, size


@lru_cache(maxsize=None)
def validator(version=1):
    root = Path(__file__).resolve().parents[1] / 'schemas'
    intake = json.loads((root / 'intake.schema.json').read_text())
    registry = Registry().with_resource(intake['$id'], Resource.from_contents(intake))
    if version not in (1, 2):
        raise MediaError('Unsupported transcription receipt version')
    name = 'intake-transcription.schema.json' if version == 1 else 'intake-transcription-v2.schema.json'
    return Draft202012Validator(json.loads((root / name).read_text()), registry=registry)


def transcribe_capture(boundary_factory, registration, capsule, *, expected_sha256, profile, log):
    """One explicitly admitted model process, after successful bounded decoding.

    log must durably admit each stage before execution. Factories must reload
    current policy/time and model/source bindings; captures remain historical.
    """
    if not callable(boundary_factory) or not callable(log):
        raise MediaError('Invalid media host')
    profile = deepcopy(profile)
    check_profile(profile)
    check_capsule(capsule, registration, profile['maxSourceBytes'])
    registration, capsule = deepcopy(registration), deepcopy(capsule)
    initial = boundary_factory()
    boundary, item, raw = bind_capture(initial, registration, capsule, expected_sha256=expected_sha256, log=log)
    if len(raw) > profile['maxSourceBytes'] or item['source']['mediaType'] not in DEMUXERS:
        raise MediaError('Unsupported media input or source budget')
    dependencies = authorization(boundary, item, profile['model']['sha256'])
    ffmpeg = pinned(profile['ffmpeg']['path'], profile['ffmpeg']['sha256'], 67_108_864)
    whisper = pinned(profile['whisper']['path'], profile['whisper']['sha256'], 67_108_864)
    model = pinned(profile['model']['path'], profile['model']['sha256'], 536_870_912)
    subject = fingerprint({'captureSha256': expected_sha256, 'profileSha256': fingerprint(profile)})

    def fresh():
        current = boundary_factory()
        if (not isinstance(current, ReadBoundary) or current.actor != initial.actor
                or current.scopes != initial.scopes):
            raise MediaError('Media authorization principal or request scopes changed')
        selected, observed, _ = bind_capture(current, registration, capsule, expected_sha256=expected_sha256, log=log)
        if observed != item or authorization(selected, item, profile['model']['sha256']) != dependencies:
            raise MediaError('Media source or model protection binding changed')
        return selected

    def stage(name, selected, operation, timeout, calls):
        log('media.' + name + '.admitted', selected.actor, subject,
            {'captureSha256': expected_sha256, 'profileSha256': fingerprint(profile),
             'policySha256': selected.policy.binding['sha256'], 'bindingsSha256': fingerprint(selected.bindings),
             'modelExecutionsReserved': calls, 'processCallsReserved': 1, 'deadlineSeconds': timeout})
        started = time.monotonic()
        try:
            output = operation()
            usage = {'modelExecutions': calls, 'processCalls': 1, 'elapsedMs': (time.monotonic() - started) * 1000}
            log('media.' + name + '.completed', selected.actor, subject, {'usage': usage})
            return output, usage
        except (ValueError, OSError, KeyError, TypeError) as exc:
            log('media.' + name + '.failed', selected.actor, subject,
                {'processingUsage': 'unknown', 'modelExecutionsReserved': calls, 'reservationRetained': True})
            raise MediaError('Media stage failed; no representation accepted') from exc

    demuxer = DEMUXERS[item['source']['mediaType']]
    decode_argv = ['-nostdin', '-hide_banner', '-loglevel', 'error', '-xerror', '-err_detect', 'explode',
                   '-protocol_whitelist', 'file,pipe', '-threads', str(profile['threads']), '-f', demuxer]
    if demuxer == 'mov':
        decode_argv += ['-enable_drefs', '0', '-use_absolute_path', '0']
    decode_argv += ['-i', 'source.bin', '-map', '0:a:0', '-vn', '-sn', '-dn', '-threads', str(profile['threads']),
                    '-ac', '1', '-ar', '16000', '-f', 's16le', 'pipe:1']

    def decode():
        pcm = execute(ffmpeg, {'source.bin': raw}, decode_argv,
            library_directories=profile['ffmpeg']['libraryDirectories'], timeout=profile['decodeTimeoutSeconds'],
            output_cap=profile['maxAudioSeconds'] * 32000, reject_diagnostics=True)
        return wav_bytes(pcm), len(pcm) // 2

    (audio, frames), decode_usage = stage('decode', boundary, decode, profile['decodeTimeoutSeconds'], 0)
    current = fresh()
    model_argv = ['-m', 'model.bin', '-f', 'audio.wav', '-oj', '-of', '-', '-np', '-ng',
                  '-l', profile['language'], '-t', str(profile['threads'])]

    def infer():
        output = execute(whisper, {'audio.wav': audio, 'model.bin': model}, model_argv,
            library_directories=profile['whisper']['libraryDirectories'], timeout=profile['modelTimeoutSeconds'],
            output_cap=2_097_152, reject_diagnostics=False)
        return segments_from_native(output, profile, frames)

    (segments, language, text_bytes), model_usage = stage('transcribe', current, infer, profile['modelTimeoutSeconds'], 1)
    try:
        current = fresh()
        version = 2 if profile['format'] == 'intake-media-profile/v2' else 1
        result = {'format': 'intake-transcription/v' + str(version), 'item': item, 'captureSha256': expected_sha256,
                  'profile': profile, 'profileSha256': fingerprint(profile), 'dependencies': dependencies,
                  'principal': current.actor, 'evaluatedAt': current.now, 'scopes': sorted(current.scopes),
                  'policySha256': current.policy.binding['sha256'], 'bindingsSha256': fingerprint(current.bindings),
                  'audio': {'selector': '0:a:0', 'origin': 'decoded-audio-start', 'sampleRate': 16000,
                            'channels': 1, 'sampleFrames': frames, 'sha256': hashlib.sha256(audio).hexdigest()},
                  'language': language, 'coverage': 'selected-audio-transcript', 'requiresReview': True,
                  'segments': segments, 'gaps': [] if any(s['text'].strip() for s in segments) else ['no-transcript'],
                  'usage': {'sourceBytes': len(raw), 'normalizedBytes': len(audio), 'textBytes': text_bytes,
                            'modelExecutions': 1, 'processCalls': 2, 'decode': decode_usage, 'transcribe': model_usage}}
        if version == 2:
            result['timingSemantics'] = 'model-estimate-with-source-window-not-alignment'
        if not validator(version).is_valid(result) or len(encode(result)) > 16_777_216:
            raise MediaError('Invalid transcription receipt')
        log('media.completed', current.actor, subject, {'resultSha256': fingerprint(result), 'usage': result['usage']})
        return result
    except (ValueError, OSError, KeyError, TypeError) as exc:
        log('media.withheld', initial.actor, subject, {'modelExecutions': 1, 'processCalls': 2})
        raise MediaError('Transcription withheld; no representation accepted') from exc
