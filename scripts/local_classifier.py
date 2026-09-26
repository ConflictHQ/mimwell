"""Bounded, source-authorized invocation of the explicitly selected local classifier.

No executable, bundle, principal or budget is accepted from a model/request. The
host provides these and a fresh ReadBoundary. Results remain review proposals.
"""
from copy import deepcopy
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import selectors
import subprocess
import tempfile
import threading
import time

from context_access import ReadBoundary
from context_bundle import encode
from knowledge_policy import fingerprint


class ClassifierError(ValueError):
    pass


_EMBEDDED = {}
_EMBEDDED_LOCK = threading.Lock()
MAX_EMBEDDED_ENGINES = 8


def execution_profile(mode, timeout):
    """An embedded call cannot promise the process host's hard deadline."""
    if mode == 'embedded':
        if timeout is not None:
            raise ClassifierError('Embedded classification requires an explicit null deadline')
    elif (mode != 'process' or type(timeout) not in (int, float)
          or not math.isfinite(timeout) or not 0 < timeout <= 60):
        raise ClassifierError('Invalid classifier execution mode or deadline')


def execute_embedded(artifact, bundle, bundle_sha256, raw):
    """Load the verified bytes once per pin, in a private immutable location.

    Cache at most eight loaded engines for this process. Using distinct private
    files avoids an OS loader reusing an older library after an installed path
    is replaced. Handles stay alive until process exit; native unloading is not
    assumed safe. The host still bounds concurrency and overall memory.
    """
    if os.name != 'posix':
        raise ClassifierError('Embedded classifier host currently requires POSIX')
    pin = hashlib.sha256(artifact).hexdigest()
    with _EMBEDDED_LOCK:
        if pin not in _EMBEDDED:
            if len(_EMBEDDED) >= MAX_EMBEDDED_ENGINES:
                raise ClassifierError('Embedded engine limit reached; start a fresh host')
            path = Path(__file__).resolve().parents[1] / 'runtime/brain-classifier/bindings/python/brain_classifier_native.py'
            spec = importlib.util.spec_from_file_location('brain_classifier_native', path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            directory = tempfile.TemporaryDirectory(prefix='brain-embedded-engine-')
            try:
                library = Path(directory.name).resolve() / 'engine'
                library.write_bytes(artifact)
                library.chmod(0o500)
                loaded = module.NativeClassifier(library, sha256=pin)
                _EMBEDDED[pin] = (directory, loaded)
            except BaseException:
                directory.cleanup()
                raise
        loaded = _EMBEDDED[pin][1]
    return loaded.classify(bundle, sha256=bundle_sha256, request=raw)


def bundle_identity(bundle_sha256, taxonomy_sha256):
    """Host reference binding for access to a model's labels and learned scores."""
    return fingerprint({'classifierBundleSha256': bundle_sha256, 'taxonomySha256': taxonomy_sha256})


def pinned(path, expected, cap):
    path = Path(path)
    if not isinstance(expected, str) or len(expected) != 64 or set(expected) - set('0123456789abcdef'):
        raise ClassifierError('Invalid classifier pin')
    if path != path.resolve() or not path.is_file():
        raise ClassifierError('Classifier path must be a canonical regular file')
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    if len(raw) > cap or hashlib.sha256(raw).hexdigest() != expected:
        raise ClassifierError('Classifier artifact changed or exceeded its budget')
    return raw


def execute(executable, bundle, bundle_sha256, raw, timeout):
    """Bound both output streams while enforcing a deadline; reap on every exit."""
    if os.name != 'posix':
        raise ClassifierError('Classifier process boundary requires a POSIX host')
    with tempfile.TemporaryDirectory(prefix='brain-classifier-') as temp:
        binary = Path(temp) / 'classifier'
        binary.write_bytes(executable)
        binary.chmod(0o500)
        # A file descriptor avoids blocking while writing a full stdin pipe before
        # the child is ready. The private input file is removed on success/failure.
        source = Path(temp) / 'input.json'
        source.write_bytes(raw)
        source.chmod(0o600)
        with source.open('rb') as incoming, selectors.DefaultSelector() as selector:
            process = subprocess.Popen([str(binary), str(bundle), bundle_sha256], stdin=incoming,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=temp,
                env={'TOKENIZERS_PARALLELISM': 'false'}, start_new_session=True)
            output, errors = bytearray(), bytearray()
            selector.register(process.stdout, selectors.EVENT_READ, (output, 2_097_152))
            selector.register(process.stderr, selectors.EVENT_READ, (errors, 65_536))
            deadline = time.monotonic() + timeout
            try:
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ClassifierError('Classifier deadline exceeded')
                    for key, _ in selector.select(min(remaining, 0.1)):
                        data = os.read(key.fileobj.fileno(), 65_536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        target, cap = key.data
                        target.extend(data)
                        if len(target) > cap:
                            raise ClassifierError('Classifier output budget exceeded')
                remaining = deadline - time.monotonic()
                if remaining <= 0 or process.wait(timeout=remaining) != 0:
                    raise ClassifierError('Classifier execution failed')
                return bytes(output)
            except subprocess.TimeoutExpired as exc:
                raise ClassifierError('Classifier deadline exceeded') from exc
            finally:
                # Kill the process group too: a misbehaving selected binary must
                # not leave descendants running after deadline/output rejection.
                try:
                    os.killpg(process.pid, 9)
                except ProcessLookupError:
                    pass
                process.wait()
                process.stdout.close()
                process.stderr.close()


def document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ClassifierError('Duplicate classifier field')
            result[key] = value
        return result

    def invalid(_):
        raise ClassifierError('Non-finite classifier value')

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def check(value, name):
    from jsonschema import Draft202012Validator
    schema = document((Path(__file__).resolve().parents[1] / 'schemas/classifier.schema.json').read_bytes())
    if not Draft202012Validator({'$ref': '#/$defs/' + name, '$defs': schema['$defs']}).is_valid(value):
        raise ClassifierError('Invalid classifier ' + name)


def verify_result(result, manifest, request, raw, bundle_sha256):
    """Validate the fixed native contract, then bind its claims to this invocation."""
    check(result, 'result')
    head, usage = manifest['head'], result['usage']
    if (result['bundleSha256'] != bundle_sha256 or result['taxonomySha256'] != manifest['taxonomySha256']
            or result['inputSha256'] != hashlib.sha256(raw).hexdigest() or result['labels'] != head['labels']
            or result['calibration'] != head['calibration'] or usage['inputBytes'] != len(raw)
            or usage['maxTokensPerItem'] != manifest['embedding']['maxTokens']
            or usage['classifiedItems'] != len(request['items'])
            or usage['embeddingCalls'] != int(bool(request['items']))
            or [r['id'] for r in result['results']] != [i['id'] for i in request['items']]):
        raise ClassifierError('Classifier response basis changed')
    for row in result['results']:
        scores = row['probabilities']
        if row['label'] is None:
            if scores or row['confidence'] is not None or row['gaps'] != ['empty-embedding']:
                raise ClassifierError('Invalid classifier abstention')
            continue
        if (len(scores) != len(head['labels']) or any(not math.isfinite(v) for v in scores)
                or abs(sum(scores) - 1) > 1e-8):
            raise ClassifierError('Invalid classifier probabilities')
        selected = max(range(len(scores)), key=scores.__getitem__)
        calibrated = head['calibration']['method'] == 'temperature'
        if (row['label'] != head['labels'][selected]
                or row['confidence'] != (scores[selected] if calibrated else None)
                or row['gaps'] != ([] if calibrated else ['uncalibrated'])):
            raise ClassifierError('Invalid classifier score interpretation')


def classify(boundary, items, *, binary, binary_sha256, bundle, bundle_sha256,
             taxonomy_sha256, timeout_seconds, log, execution_mode='process'):
    """Classify exact source-bound text records through operator-selected artifacts.

    Bind fingerprint({'id': ..., 'text': ...}) in boundary.references. Source
    acquisition/verification is the host's responsibility; this reads no source
    locator. Also bind bundle_identity(bundle_sha256, taxonomy_sha256) to a
    readable resource: source access alone must not reveal a private taxonomy.
    The result does not route, write, delete, train or modify permissions.
    """
    if not isinstance(boundary, ReadBoundary) or not callable(log):
        raise ClassifierError('Invalid classifier host boundary')
    execution_profile(execution_mode, timeout_seconds)
    items = deepcopy(items)
    if (not isinstance(items, list) or len(items) > 64
            or any(not isinstance(i, dict) or set(i) != {'id', 'text'}
                   or not isinstance(i['id'], str) or not isinstance(i['text'], str) for i in items)):
        raise ClassifierError('Invalid classifier input')
    if any(not boundary.permits('references', fingerprint(i)) for i in items):
        raise ClassifierError('Classifier source unavailable')
    if not boundary.permits('references', bundle_identity(bundle_sha256, taxonomy_sha256)):
        raise ClassifierError('Classifier model or taxonomy unavailable')
    request = {'protocolVersion': '1.0', 'items': items}
    check(request, 'request')
    if len({i['id'] for i in items}) != len(items):
        raise ClassifierError('Duplicate classifier item identity')
    raw = encode(request)
    if len(raw) > 1_048_576 or any(len(i['text'].encode()) > 16_384 for i in items):
        raise ClassifierError('Classifier input budget exceeded')
    executable = pinned(binary, binary_sha256, 67_108_864)
    manifest = document(pinned(bundle, bundle_sha256, 4_194_304))
    check(manifest, 'bundle')
    if manifest.get('format') != 'brain-classifier/v1' or manifest.get('taxonomySha256') != taxonomy_sha256:
        raise ClassifierError('Classifier taxonomy or format changed')
    subject = hashlib.sha256(raw).hexdigest()
    reservation = {'bundleSha256': bundle_sha256, 'binarySha256': binary_sha256,
                   'policySha256': boundary.policy.binding['sha256'], 'evaluatedAt': boundary.now,
                   'bindingsSha256': fingerprint(boundary.bindings), 'scopes': sorted(boundary.scopes),
                   'taxonomySha256': taxonomy_sha256,
                   'embeddingCallsReserved': int(bool(items)), 'items': len(items),
                   'inputBytes': len(raw), 'deadlineSeconds': timeout_seconds}
    if execution_mode == 'embedded':
        reservation['executionMode'] = 'embedded'
    # A failed admission audit prevents execution. Failure after launch is not
    # reported as zero work: only a verified receipt establishes actual usage.
    log('classifier.admitted', boundary.actor, subject, reservation)
    try:
        output = (execute_embedded(executable, bundle, bundle_sha256, raw)
                  if execution_mode == 'embedded'
                  else execute(executable, bundle, bundle_sha256, raw, timeout_seconds))
        result = document(output)
        verify_result(result, manifest, request, raw, bundle_sha256)
        log('classifier.completed', boundary.actor, subject,
            {'bundleSha256': bundle_sha256, 'usage': result['usage']})
        return result
    except (ValueError, KeyError, TypeError, OSError, AttributeError, ImportError) as exc:
        log('classifier.failed', boundary.actor, subject,
            {'bundleSha256': bundle_sha256, 'executionUsage': 'unknown', 'reservationRetained': True})
        raise ClassifierError('Classifier failed; no decisions accepted') from exc
