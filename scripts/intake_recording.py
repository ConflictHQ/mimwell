"""Streaming preparation of authorized long recordings into private bounded PCM.

Host-only API: factories, registered paths, decoder and spool root are trusted
configuration. No inference, durable resume or canonical transcript publication.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import math
import os
from pathlib import Path
import selectors
import subprocess
import tempfile
import time

from context_access import ReadBoundary
from brain_protection import assess
from federation_protection import SourceProtection, plaintext_profile
from intake_capture import authorize, observation, open_directory, open_regular
from intake_extraction import bounded_metadata
from intake_media import DEMUXERS, artifact, fields, wav_bytes
from intake_recording_ranges import RecordingError, check, integer, plan, verify_plan
from knowledge_policy import fingerprint
from local_classifier import pinned


def require_spool(required):
    # Disk snapshots can survive a process crash; transient intent is not an
    # online-only storage capability. Derivation includes retention constraints.
    if not assess(required, plaintext_profile(), offline=True, operation='derive')['supported']:
        raise RecordingError('Recording spool cannot satisfy source protection')


def check_profile(profile):
    fields(profile, ('format', 'ffmpeg', 'threads', 'maxSourceBytes', 'maxAudioSeconds',
                     'maxSpoolBytes', 'decodeTimeoutSeconds'))
    if profile['format'] != 'intake-recording-profile/v1':
        raise RecordingError('Unsupported recording profile')
    artifact(profile['ffmpeg'], libraries=True)
    for key, cap in (('threads', 8), ('maxSourceBytes', 1_073_741_824),
                     ('maxAudioSeconds', 21600), ('maxSpoolBytes', 2_147_483_648)):
        integer(profile[key], 1, cap)
    timeout = profile['decodeTimeoutSeconds']
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 600:
        raise RecordingError('Invalid recording decoder deadline')
    check(profile, 'profile')


def stream_source(root, registration, output, *, cap, expected_sha256):
    """Fixed-buffer source snapshot with full-path replacement detection."""
    fd = open_regular(root, registration['path'])
    try:
        before = observation(os.fstat(fd))
        if before['size'] > cap:
            raise RecordingError('Recording source exceeds byte or spool budget')
        size, digest = 0, hashlib.sha256()
        while raw := os.read(fd, min(65536, cap + 1 - size)):
            size += len(raw)
            if size > cap:
                raise RecordingError('Recording source exceeds byte or spool budget')
            output.write(raw)
            digest.update(raw)
        after = observation(os.fstat(fd))
        current = open_regular(root, registration['path'])
        try:
            resolved = observation(os.fstat(current))
        finally:
            os.close(current)
        if before != after or after != resolved or size != before['size']:
            raise RecordingError('Recording original changed during capture')
        digest = digest.hexdigest()
        if any(pin is not None and pin != digest for pin in (registration['sha256'], expected_sha256)):
            raise RecordingError('Recording original differs from its expected revision')
        return digest, after
    finally:
        os.close(fd)


def kill_decoder_group(process):
    """Kill descendants too; tolerate only a confirmed vanished process group."""
    try:
        os.killpg(process.pid, 9)
    except ProcessLookupError:
        pass
    except PermissionError:
        # Some hosts report EPERM while the last process in the group is a
        # zombie. Reap an exited leader, then independently confirm the group
        # disappeared. A live or still-inaccessible group remains an error.
        if process.poll() is None:
            raise
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return
        raise


def decode_to_disk(executable, directory, output, *, media_type, profile, cap):
    """Fixed FFmpeg selection; stream PCM, bound stderr, kill/reap on every exit."""
    demuxer = DEMUXERS[media_type]
    argv = ['-nostdin', '-hide_banner', '-loglevel', 'error', '-xerror', '-err_detect', 'explode',
            '-protocol_whitelist', 'file,pipe', '-threads', str(profile['threads']), '-f', demuxer]
    if demuxer == 'mov':
        argv += ['-enable_drefs', '0', '-use_absolute_path', '0']
    argv += ['-i', 'source.bin', '-map', '0:a:0', '-vn', '-sn', '-dn', '-threads', str(profile['threads']),
             '-ac', '1', '-ar', '16000', '-f', 's16le', 'pipe:1']
    env = {'HOME': str(directory), 'LC_ALL': 'C', 'TMPDIR': str(directory)}
    libraries = profile['ffmpeg']['libraryDirectories']
    if libraries:
        env.update(LD_LIBRARY_PATH=':'.join(libraries), DYLD_LIBRARY_PATH=':'.join(libraries))
    with selectors.DefaultSelector() as selector:
        process = subprocess.Popen([str(executable), *argv], cwd=directory, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        size, errors, digest = 0, 0, hashlib.sha256()
        deadline = time.monotonic() + profile['decodeTimeoutSeconds']
        try:
            selector.register(process.stdout, selectors.EVENT_READ, 'pcm')
            selector.register(process.stderr, selectors.EVENT_READ, 'errors')
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RecordingError('Recording decoder deadline exceeded')
                for key, _ in selector.select(min(.1, remaining)):
                    raw = os.read(key.fileobj.fileno(), 65536)
                    if not raw:
                        selector.unregister(key.fileobj)
                    elif key.data == 'pcm':
                        size += len(raw)
                        if size > cap:
                            raise RecordingError('Recording audio or spool budget exceeded')
                        output.write(raw)
                        digest.update(raw)
                    else:
                        errors += len(raw)
                        if errors > 65536:
                            raise RecordingError('Recording decoder diagnostic budget exceeded')
            remaining = deadline - time.monotonic()
            if (remaining <= 0 or process.wait(timeout=remaining) != 0 or errors
                    or not size or size % 2):
                raise RecordingError('Recording decoder failed or returned incomplete audio')
            return size, digest.hexdigest()
        except subprocess.TimeoutExpired as exc:
            raise RecordingError('Recording decoder deadline exceeded') from exc
        finally:
            kill_decoder_group(process)
            process.wait()
            process.stdout.close()
            process.stderr.close()


class PreparedRecording:
    """An ephemeral host-owned handle. Portable plans contain no spool paths."""

    def __init__(self, manifest, audio_fd, fresh, log):
        self._manifest = deepcopy(manifest)
        self._fd, self._fresh, self._log = audio_fd, fresh, log
        self._observation = observation(os.fstat(audio_fd))
        self._closed = False

    @property
    def manifest(self):
        self._available()
        self._fresh(self._manifest['normalization']['item'])
        return deepcopy(self._manifest)

    def _available(self):
        if self._closed:
            raise RecordingError('Recording snapshot is closed')

    def make_plan(self, **options):
        self._available()
        self._fresh(self._manifest['normalization']['item'])
        return plan(self._manifest['normalization'], **options)

    def read_chunk(self, value, chunk_id, *, expected_plan_sha256):
        self._available()
        normalized = self._manifest['normalization']
        selected = self._fresh(normalized['item'])
        value = verify_plan(value, normalized, expected_sha256=expected_plan_sha256)
        matches = [row for row in value['chunks'] if row['id'] == chunk_id]
        if len(matches) != 1:
            raise RecordingError('Unknown recording chunk')
        row = matches[0]
        start, end = row['range']['start'], row['range']['end']
        self._log('recording.chunk.admitted', selected.actor, chunk_id,
                  {'planSha256': expected_plan_sha256, 'sourceBytesReserved': (end - start) * 2,
                   'policySha256': selected.policy.binding['sha256'], 'modelExecutionsReserved': 0})
        try:
            if observation(os.fstat(self._fd)) != self._observation:
                raise RecordingError('Private recording snapshot changed')
            parts, remaining, offset = [], (end - start) * 2, start * 2
            while remaining:
                raw = os.pread(self._fd, min(remaining, 65536), offset)
                if not raw:
                    raise RecordingError('Private recording snapshot was truncated')
                parts.append(raw)
                remaining -= len(raw)
                offset += len(raw)
            audio = wav_bytes(b''.join(parts))
            if observation(os.fstat(self._fd)) != self._observation:
                raise RecordingError('Private recording snapshot changed')
            selected = self._fresh(normalized['item'])
            descriptor = {'format': 'intake-recording-chunk/v1',
                'normalization': deepcopy(normalized), 'normalizationSha256': value['normalizationSha256'],
                'preparationSha256': fingerprint(self._manifest), 'planSha256': expected_plan_sha256,
                'chunk': deepcopy(row), 'principal': selected.actor, 'evaluatedAt': selected.now,
                'policySha256': selected.policy.binding['sha256'], 'bindingsSha256': fingerprint(selected.bindings),
                'protection': deepcopy(self._manifest['protection']),
                'audio': {'mediaType': 'audio/wav', 'sampleFrames': end - start,
                          'sha256': hashlib.sha256(audio).hexdigest(), 'byteLength': len(audio)},
                'usage': {'sourceBytes': (end - start) * 2, 'modelExecutions': 0}}
            check(descriptor, 'chunk')
            self._log('recording.chunk.completed', selected.actor, chunk_id,
                      {'descriptorSha256': fingerprint(descriptor), 'usage': descriptor['usage']})
            return descriptor, audio, selected
        except BaseException:
            self._log('recording.chunk.failed', selected.actor, chunk_id,
                      {'processingUsage': 'unknown', 'modelExecutionsReserved': 0, 'reservationRetained': True})
            raise


@contextmanager
def prepare_recording(boundary_factory, protection_factory, registration, *, root,
                      spool_root, profile, log, expected_sha256=None):
    """Prepare a historical snapshot. The factories must reload current state.

    Plaintext retention/derivation must be explicitly supported. A source grant
    alone does not override those obligations. The private spool is not a native
    process sandbox, and filesystem I/O has no hard wall-clock timeout.
    """
    if not all(callable(v) for v in (boundary_factory, protection_factory, log)):
        raise RecordingError('Invalid recording host')
    bounded_metadata(registration)
    check_profile(profile)
    registration, profile = deepcopy(registration), deepcopy(profile)
    if (expected_sha256 is not None and (not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64 or set(expected_sha256) - set('0123456789abcdef'))):
        raise RecordingError('Invalid recording source pin')
    if registration['mediaType'] not in DEMUXERS:
        raise RecordingError('Unsupported recording media type')
    initial = boundary_factory()
    authorize(initial, registration)
    initial_scope = initial.policy.resources[registration['resource']]['scope']
    protection = protection_factory()
    if not isinstance(protection, SourceProtection):
        raise RecordingError('Explicit recording source protection required')
    required = protection.for_resources([registration['resource']])
    require_spool(required)

    def fresh(item=None):
        current, current_protection = boundary_factory(), protection_factory()
        authorize(current, registration)
        if (current.actor != initial.actor or current.scopes != initial.scopes
                or current.policy.resources[registration['resource']]['scope'] != initial_scope
                or not isinstance(current_protection, SourceProtection)
                or current_protection.sha256 != protection.sha256):
            raise RecordingError('Recording source principal, scope or protection changed')
        obligations = current_protection.for_resources([registration['resource']])
        require_spool(obligations)
        if item is not None:
            bindings = deepcopy(current.bindings)
            identity = fingerprint(item)
            if bindings['references'].get(identity) not in (None, registration['resource']):
                raise RecordingError('Recording source item already binds another resource')
            bindings['references'][identity] = registration['resource']
            current = ReadBoundary(current.policy, actor=current.actor, now=current.now,
                                   scopes=current.scopes, bindings=bindings)
        return current

    # The spool root and its ancestors are host-controlled, canonical and private.
    spool_root = Path(spool_root)
    spool_fd = open_directory(spool_root)
    try:
        info = os.fstat(spool_fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise RecordingError('Recording spool root must be owner-only')
        spool_identity = (info.st_dev, info.st_ino)
    finally:
        os.close(spool_fd)
    binary = pinned(profile['ffmpeg']['path'], profile['ffmpeg']['sha256'], 67_108_864)
    if len(binary) >= profile['maxSpoolBytes']:
        raise RecordingError('Recording executable exceeds spool budget')
    subject = fingerprint({'registrationSha256': fingerprint(registration), 'profileSha256': fingerprint(profile)})
    handle = None
    with tempfile.TemporaryDirectory(prefix='recording-', dir=spool_root) as temporary:
        directory = Path(temporary)
        reopened = open_directory(spool_root)
        try:
            info = os.fstat(reopened)
            if (info.st_dev, info.st_ino) != spool_identity or info.st_mode & 0o077:
                raise RecordingError('Recording spool root changed')
        finally:
            os.close(reopened)
        def create(name):
            return os.fdopen(os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     0o600), 'wb')

        selected = fresh()
        log('recording.prepare.admitted', selected.actor, subject,
            {'registrationSha256': fingerprint(registration), 'profileSha256': fingerprint(profile),
             'policySha256': selected.policy.binding['sha256'], 'maxSpoolBytes': profile['maxSpoolBytes'],
             'sourceBytesReserved': profile['maxSourceBytes'], 'modelExecutionsReserved': 0})
        started, process_calls = time.monotonic(), 0
        try:
            with create('decoder') as output:
                output.write(binary)
            (directory / 'decoder').chmod(0o500)
            binary_size = len(binary)
            del binary
            with create('source.bin') as output:
                digest, observed = stream_source(root, registration, output,
                    cap=min(profile['maxSourceBytes'], profile['maxSpoolBytes'] - binary_size),
                    expected_sha256=expected_sha256)
            (directory / 'source.bin').chmod(0o400)
            item = {'id': registration['itemId'], 'source': {'id': registration['sourceId'],
                'revision': 'sha256:' + digest, 'sha256': digest, 'mediaType': registration['mediaType'],
                'byteLength': observed['size'], 'reference': {'backend': 'local-file', 'object': registration['id'],
                'locator': 'whole', 'availability': 'available'}}, 'metadata': deepcopy(registration['metadata'])}
            selected = fresh(item)
            audio_cap = min(profile['maxAudioSeconds'] * 32000,
                            profile['maxSpoolBytes'] - binary_size - observed['size'])
            if audio_cap < 2:
                raise RecordingError('Recording spool has no audio budget')
            log('recording.decode.admitted', selected.actor, subject,
                {'processCallsReserved': 1, 'modelExecutionsReserved': 0, 'maxOutputBytes': audio_cap,
                 'deadlineSeconds': profile['decodeTimeoutSeconds']})
            process_calls = 1
            with create('audio.pcm') as output:
                size, pcm_digest = decode_to_disk(directory / 'decoder', directory, output,
                    media_type=registration['mediaType'], profile=profile, cap=audio_cap)
            (directory / 'audio.pcm').chmod(0o400)
            selected = fresh(item)
            normalization = {'format': 'intake-recording-normalization/v1', 'item': item,
                'profileSha256': fingerprint(profile), 'decoderSha256': profile['ffmpeg']['sha256'],
                'audio': {'selector': '0:a:0', 'origin': 'decoded-audio-start', 'sampleRate': 16000,
                          'channels': 1, 'encoding': 's16le', 'sampleFrames': size // 2, 'sha256': pcm_digest}}
            manifest = {'format': 'intake-recording-preparation/v1', 'normalization': normalization,
                'normalizationSha256': fingerprint(normalization), 'registrationSha256': fingerprint(registration),
                'rootSha256': fingerprint({'id': registration['root'], 'path': str(Path(root))}),
                'observation': observed, 'principal': selected.actor, 'preparedAt': selected.now,
                'policySha256': selected.policy.binding['sha256'], 'bindingsSha256': fingerprint(selected.bindings),
                'protection': {'policySha256': protection.sha256, 'requirements': required},
                'usage': {'sourceBytes': observed['size'], 'normalizedBytes': size,
                          'spoolBytes': binary_size + observed['size'] + size, 'processCalls': 1,
                          'modelExecutions': 0, 'elapsedMs': (time.monotonic() - started) * 1000}}
            check(manifest, 'preparation')
            fd = open_regular(directory, 'audio.pcm')
            handle = PreparedRecording(manifest, fd, fresh, log)
            log('recording.prepare.completed', selected.actor, subject,
                {'preparationSha256': fingerprint(manifest), 'usage': manifest['usage']})
        except BaseException:
            if handle is not None:
                handle._closed = True
                os.close(handle._fd)
            log('recording.prepare.failed', initial.actor, subject,
                {'processingUsage': 'unknown', 'processCallsReserved': process_calls,
                 'modelExecutionsReserved': 0, 'reservationRetained': True})
            raise
        try:
            yield handle
        finally:
            handle._closed = True
            os.close(handle._fd)
