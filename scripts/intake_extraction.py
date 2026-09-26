"""Source-bound local document extraction; no routing, publication or model calls."""
from copy import deepcopy
from functools import lru_cache
import json
import math
import os
from pathlib import Path
import selectors
import subprocess
import tempfile
import time

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from context_access import ReadBoundary
from context_bundle import encode
from intake_capture import bind_capture
from knowledge_policy import fingerprint
from local_classifier import pinned


class ExtractionError(ValueError):
    pass


def bounded_metadata(value):
    """Bound caller-owned JSON before copying/encoding metadata, excluding bytes."""
    remaining = [2048, 1_048_576]

    def visit(node, depth):
        remaining[0] -= 1
        if remaining[0] < 0 or depth > 12:
            raise ExtractionError('Extraction metadata budget exceeded')
        if isinstance(node, str):
            remaining[1] -= len(node)
        elif isinstance(node, dict):
            if len(node) > 128:
                raise ExtractionError('Extraction metadata budget exceeded')
            for key, child in node.items():
                if not isinstance(key, str):
                    raise ExtractionError('Invalid extraction metadata key')
                visit(key, depth + 1)
                visit(child, depth + 1)
        elif isinstance(node, list):
            if len(node) > 128:
                raise ExtractionError('Extraction metadata budget exceeded')
            for child in node:
                visit(child, depth + 1)
        elif node is not None and type(node) not in (int, bool):
            raise ExtractionError('Invalid extraction metadata value')
        elif type(node) is int and abs(node) > 9_007_199_254_740_991:
            raise ExtractionError('Extraction metadata integer budget exceeded')
        if remaining[1] < 0:
            raise ExtractionError('Extraction metadata budget exceeded')

    visit(value, 0)
    if len(encode(value)) > 1_048_576:
        raise ExtractionError('Extraction metadata byte budget exceeded')


@lru_cache(maxsize=None)
def validator():
    path = Path(__file__).resolve().parents[1] / 'schemas/intake-extraction.schema.json'
    intake = json.loads((path.parent / 'intake.schema.json').read_text())
    registry = Registry().with_resource(intake['$id'], Resource.from_contents(intake))
    return Draft202012Validator(json.loads(path.read_text()), registry=registry)


def profile_check(profile):
    if not isinstance(profile, dict):
        raise ExtractionError('Invalid extraction profile')
    fields = {'adapter', 'maxSourceBytes', 'maxTextBytes', 'maxPages', 'timeoutSeconds'}
    if profile.get('adapter') == 'poppler-text/v1':
        fields |= {'binary', 'binarySha256', 'libraryDirectories'}
    if set(profile) != fields or profile.get('adapter') not in ('utf8-text/v1', 'poppler-text/v1'):
        raise ExtractionError('Unsupported extraction profile')
    for key, cap in (('maxSourceBytes', 67_108_864), ('maxTextBytes', 2_097_152), ('maxPages', 1000)):
        if type(profile[key]) is not int or not 1 <= profile[key] <= cap:
            raise ExtractionError('Invalid extraction budget')
    deadline = profile['timeoutSeconds']
    if type(deadline) not in (int, float) or not math.isfinite(deadline) or not 0 < deadline <= 60:
        raise ExtractionError('Invalid extraction deadline')
    if profile['adapter'] == 'poppler-text/v1':
        if (not isinstance(profile['binary'], str) or len(profile['binary']) > 4096
                or '\x00' in profile['binary'] or not Path(profile['binary']).is_absolute()):
            raise ExtractionError('Invalid extraction executable')
        pin = profile['binarySha256']
        if not isinstance(pin, str) or len(pin) != 64 or set(pin) - set('0123456789abcdef'):
            raise ExtractionError('Invalid extraction executable pin')
        directories = profile['libraryDirectories']
        if (not isinstance(directories, list) or len(directories) > 8
                or any(not isinstance(p, str) or not p or len(p) > 4096 or ':' in p or '\x00' in p
                       or not Path(p).is_absolute() for p in directories)):
            raise ExtractionError('Invalid extraction library directories')
        for directory in directories:
            path = Path(directory)
            if path != path.resolve(strict=True) or not path.is_dir():
                raise ExtractionError('Extraction library directory must be canonical')


def pdf_text(executable, raw, *, timeout, max_output, library_directories=()):
    """Fixed argv; bounded streams/deadline. This is not an OS sandbox."""
    if os.name != 'posix':
        raise ExtractionError('Local PDF extraction requires POSIX')
    with tempfile.TemporaryDirectory(prefix='brain-extraction-') as temp:
        binary, source = Path(temp) / 'pdftotext', Path(temp) / 'input.pdf'
        binary.write_bytes(executable)
        binary.chmod(0o500)
        source.write_bytes(raw)
        source.chmod(0o600)
        environment = {'HOME': temp, 'LC_ALL': 'C'}
        if library_directories:
            # Explicit host runtime dependencies; never inherit loader overrides.
            selected = ':'.join(library_directories)
            environment.update(DYLD_LIBRARY_PATH=selected, LD_LIBRARY_PATH=selected)
        with source.open('rb') as incoming, selectors.DefaultSelector() as selector:
            process = subprocess.Popen([str(binary), '-enc', 'UTF-8', '-layout', '-', '-'],
                stdin=incoming, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=temp, env=environment, start_new_session=True)
            output, errors = bytearray(), bytearray()
            deadline = time.monotonic() + timeout
            try:
                selector.register(process.stdout, selectors.EVENT_READ, (output, max_output))
                selector.register(process.stderr, selectors.EVENT_READ, (errors, 65_536))
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ExtractionError('PDF extraction deadline exceeded')
                    for key, _ in selector.select(min(remaining, 0.1)):
                        chunk = os.read(key.fileobj.fileno(), 65_536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        target, cap = key.data
                        target.extend(chunk)
                        if len(target) > cap:
                            raise ExtractionError('PDF extraction output budget exceeded')
                remaining = deadline - time.monotonic()
                if remaining <= 0 or process.wait(timeout=remaining) != 0 or errors:
                    raise ExtractionError('PDF extraction failed')
                return bytes(output)
            except subprocess.TimeoutExpired as exc:
                raise ExtractionError('PDF extraction deadline exceeded') from exc
            finally:
                try:
                    os.killpg(process.pid, 9)
                except ProcessLookupError:
                    pass
                process.wait()
                process.stdout.close()
                process.stderr.close()


def extract_capture(boundary_factory, registration, capsule, *, expected_sha256, profile, log):
    """Explicit host execution of a protected capture, with fresh output authorization.

    Factories reload current policy/time/scopes. They must not reuse a stale
    boundary. The caller must protect the returned representation like its source;
    this operation supplies neither publication nor destination write permission.
    """
    if not callable(boundary_factory) or not callable(log):
        raise ExtractionError('Invalid extraction host')
    profile = deepcopy(profile)
    profile_check(profile)
    # Bound the large encoded payload before bind_capture copies/decodes it.
    # Transport JSON parsing remains the host's separate input boundary.
    try:
        if (not isinstance(capsule, dict) or set(capsule) != {'format', 'receipt', 'body'}
                or not isinstance(capsule['body'], dict) or set(capsule['body']) != {'encoding', 'data'}
                or capsule['format'] != 'intake-capsule/v1' or capsule['body']['encoding'] != 'base64'):
            raise ExtractionError('Invalid extraction capsule envelope')
        data = capsule['body']['data']
        size = capsule['receipt']['item']['source']['byteLength']
        if (not isinstance(data, str) or type(size) is not int
                or not 0 <= size <= profile['maxSourceBytes']
                or len(data) > ((profile['maxSourceBytes'] + 2) // 3) * 4):
            raise ExtractionError('Extraction capsule budget exceeded')
    except (KeyError, TypeError) as exc:
        raise ExtractionError('Invalid extraction capsule') from exc
    bounded_metadata(registration)
    bounded_metadata(capsule['receipt'])
    registration, capsule = deepcopy(registration), deepcopy(capsule)
    initial = boundary_factory()
    if not isinstance(initial, ReadBoundary):
        raise ExtractionError('Invalid extraction read boundary')
    boundary, item, raw = bind_capture(initial, registration, capsule,
                                      expected_sha256=expected_sha256, log=log)
    if len(raw) > profile['maxSourceBytes']:
        raise ExtractionError('Extraction source budget exceeded')
    adapter, media = profile['adapter'], item['source']['mediaType']
    if ((adapter == 'utf8-text/v1' and media not in ('text/plain', 'text/markdown'))
            or (adapter == 'poppler-text/v1' and media != 'application/pdf')):
        raise ExtractionError('Extraction profile does not accept declared media type')
    executable = None
    if adapter == 'poppler-text/v1':
        if not raw.startswith(b'%PDF-'):
            raise ExtractionError('PDF signature missing')
        executable = pinned(profile['binary'], profile['binarySha256'], 67_108_864)
    subject = fingerprint({'captureSha256': expected_sha256, 'profileSha256': fingerprint(profile)})
    log('extraction.admitted', boundary.actor, subject,
        {'captureSha256': expected_sha256, 'itemSha256': fingerprint(item),
         'profileSha256': fingerprint(profile), 'policySha256': boundary.policy.binding['sha256'],
         'sourceBytes': len(raw), 'modelCallsReserved': 0,
         'processCallsReserved': int(executable is not None), 'deadlineSeconds': profile['timeoutSeconds']})
    started = time.monotonic()
    try:
        output = raw if executable is None else pdf_text(executable, raw,
            timeout=profile['timeoutSeconds'], max_output=profile['maxTextBytes'],
            library_directories=profile['libraryDirectories'])
        if len(output) > profile['maxTextBytes']:
            raise ExtractionError('Extraction text budget exceeded')
        text = output.decode('utf-8')
        if executable is None:
            segments = [{'locator': {'kind': 'bytes', 'start': 0, 'end': len(raw)}, 'text': text}]
            coverage = 'utf8-source'
        else:
            # pdftotext terminates every page with FF. Refuse incomplete framing;
            # do not invent physical page numbers from an unterminated stream.
            if not text.endswith('\f'):
                raise ExtractionError('Incomplete PDF page framing')
            pages = text[:-1].split('\f')
            if len(pages) > profile['maxPages']:
                raise ExtractionError('Extraction page budget exceeded')
            segments = [{'locator': {'kind': 'page', 'number': n}, 'text': page}
                        for n, page in enumerate(pages, 1)]
            coverage = 'pdf-text-layer'
        elapsed = (time.monotonic() - started) * 1000
        current = boundary_factory()
        if (not isinstance(current, ReadBoundary) or current.actor != initial.actor
                or set(current.scopes) != set(initial.scopes)):
            raise ExtractionError('Extraction authorization principal or scope changed')
        current, current_item, _ = bind_capture(current, registration, capsule,
                                               expected_sha256=expected_sha256, log=log)
        if current_item != item:
            raise ExtractionError('Extraction source changed')
        for segment in segments:
            segment['gaps'] = [] if segment['text'].strip() else ['no-text']
        result = {'format': 'intake-extraction/v1', 'captureSha256': expected_sha256,
                  'item': item, 'profile': profile, 'profileSha256': fingerprint(profile),
                  'principal': current.actor, 'evaluatedAt': current.now,
                  'policySha256': current.policy.binding['sha256'],
                  'bindingsSha256': fingerprint(current.bindings), 'scopes': sorted(current.scopes),
                  'coverage': coverage, 'segments': segments,
                  'gaps': ([] if any(s['text'].strip() for s in segments) else ['no-text']),
                  'usage': {'sourceBytes': len(raw), 'outputBytes': len(output),
                            'modelCalls': 0, 'processCalls': int(executable is not None),
                            'elapsedMs': elapsed}}
        if not validator().is_valid(result) or len(encode(result)) > 16_777_216:
            raise ExtractionError('Invalid extraction result')
        log('extraction.completed', current.actor, subject,
            {'resultSha256': fingerprint(result), 'usage': result['usage']})
        return result
    except (ValueError, OSError, TypeError, KeyError) as exc:
        log('extraction.failed', boundary.actor, subject,
            {'processingUsage': 'unknown', 'modelCalls': 0, 'reservationRetained': True})
        raise ExtractionError('Extraction failed; no representation accepted') from exc
