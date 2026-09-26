"""Authorized local byte capture; no extraction, inference or destination writes."""
import base64
from copy import deepcopy
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from context_access import ReadBoundary
from knowledge_policy import fingerprint, local_path, timestamp


class CaptureError(ValueError):
    pass


@lru_cache(maxsize=None)
def validator(name):
    root = Path(__file__).resolve().parents[1] / 'schemas'
    schema = json.loads((root / 'intake-capture.schema.json').read_text())
    intake = json.loads((root / 'intake.schema.json').read_text())
    registry = Registry().with_resource(intake['$id'], Resource.from_contents(intake))
    return Draft202012Validator({'$ref': '#/$defs/' + name, '$defs': schema['$defs']}, registry=registry)


def check(value, name):
    if not validator(name).is_valid(value):
        raise CaptureError('Invalid capture ' + name)


def authorize(boundary, registration):
    check(registration, 'registration')
    local_path(registration['path'])
    if (not isinstance(boundary, ReadBoundary)
            or not boundary.permits_resource(registration['resource'], registration['id'])):
        raise CaptureError('Capture source unavailable')


def observation(info):
    # Decimal strings preserve filesystem-width integers across JSON consumers
    # that otherwise round values above 2**53 (including nanosecond timestamps).
    return {'device': str(info.st_dev), 'inode': str(info.st_ino), 'size': info.st_size,
            'modifiedNs': str(info.st_mtime_ns), 'changedNs': str(info.st_ctime_ns)}


def open_directory(root):
    root = Path(root)
    if os.name != 'posix' or not root.is_absolute() or '..' in root.parts:
        raise CaptureError('Capture requires an absolute POSIX source root')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in root.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        return directory
    except BaseException:
        os.close(directory)
        raise


def open_regular(root, relative):
    """Descriptor-relative no-follow traversal, including the absolute root chain.

    Nonblocking open avoids waiting on a substituted FIFO before fstat rejects it.
    Regular-file I/O itself is not a hard wall-clock deadline on a stalled mount.
    """
    path = local_path(relative)
    directory = open_directory(root)
    try:
        for part in path.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise CaptureError('Capture source must be a regular file')
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(directory)


def read_stable(root, relative, max_bytes):
    fd = open_regular(root, relative)
    try:
        before = observation(os.fstat(fd))
        if before['size'] > max_bytes:
            raise CaptureError('Capture source exceeds its byte budget')
        chunks, size = [], 0
        while chunk := os.read(fd, min(65536, max_bytes + 1 - size)):
            chunks.append(chunk)
            size += len(chunk)
            if size > max_bytes:
                raise CaptureError('Capture source exceeds its byte budget')
        after = observation(os.fstat(fd))
        # Re-traverse every ancestor: an open descriptor alone would miss a
        # directory replacement that changes what the external reference names.
        current = open_regular(root, relative)
        try:
            resolved = observation(os.fstat(current))
        finally:
            os.close(current)
        if before != after or after != resolved or size != before['size']:
            raise CaptureError('Capture source changed during observation')
        return b''.join(chunks), after
    finally:
        os.close(fd)


def capture(boundary, registration, *, root, max_bytes, expected_sha256=None, log):
    """The host selects registration/root/budget; callers may add a stricter pin.

    The registration's media type/metadata are operator declarations. Only source
    bytes, length and the observed content revision are verified by this adapter.
    """
    registration = deepcopy(registration)
    authorize(boundary, registration)
    if (type(max_bytes) is not int or not 1 <= max_bytes <= 67108864 or not callable(log)
            or expected_sha256 is not None and (not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64 or set(expected_sha256) - set('0123456789abcdef'))):
        raise CaptureError('Invalid capture budget or expected revision')
    basis = fingerprint(registration)
    log('capture.admitted', boundary.actor, basis,
        {'policySha256': boundary.policy.binding['sha256'], 'maxBytes': max_bytes})
    try:
        raw, observed = read_stable(root, registration['path'], max_bytes)
        digest = hashlib.sha256(raw).hexdigest()
        if any(pin is not None and pin != digest for pin in (registration['sha256'], expected_sha256)):
            raise CaptureError('Capture source revision differs from its expected hash')
        item = {'id': registration['itemId'], 'source': {'id': registration['sourceId'],
                'revision': 'sha256:' + digest, 'sha256': digest, 'mediaType': registration['mediaType'],
                'byteLength': len(raw), 'reference': {'backend': 'local-file', 'object': registration['id'],
                'locator': 'whole', 'availability': 'available'}}, 'metadata': deepcopy(registration['metadata'])}
        receipt = {'format': 'intake-capture/v1', 'registrationSha256': basis, 'item': item,
                   'rootSha256': fingerprint({'id': registration['root'], 'path': str(Path(root))}),
                   'capturedAt': boundary.now, 'principal': boundary.actor,
                   'policySha256': boundary.policy.binding['sha256'], 'observation': observed,
                   'usage': {'sourceBytes': len(raw), 'modelCalls': 0}}
        capsule = {'format': 'intake-capsule/v1', 'receipt': receipt,
                   'body': {'encoding': 'base64', 'data': base64.b64encode(raw).decode('ascii')}}
        check(capsule, 'capsule')
        log('capture.completed', boundary.actor, basis,
            {'captureSha256': fingerprint(capsule), 'itemSha256': fingerprint(item),
             'sourceSha256': digest, 'sourceBytes': len(raw), 'modelCalls': 0})
        return capsule
    except (ValueError, OSError, TypeError) as exc:
        log('capture.failed', boundary.actor, basis, {'sourceBytesRead': 'unknown', 'modelCalls': 0})
        raise CaptureError('Capture failed; no source snapshot accepted') from exc


def bind_capture(boundary, registration, capsule, *, expected_sha256, log):
    """Verify an operator-pinned capsule and bind its exact item for intake.

    The expected digest comes from protected capture completion/host configuration,
    not from the same untrusted producer as the capsule. This is a historical
    captured snapshot: loading it does not attest to the original's current state.
    No original is opened, overwritten, moved or deleted.
    """
    registration, capsule = deepcopy(registration), deepcopy(capsule)
    authorize(boundary, registration)
    check(capsule, 'capsule')
    if not callable(log) or fingerprint(capsule) != expected_sha256:
        raise CaptureError('Capture capsule pin changed')
    receipt, item = capsule['receipt'], capsule['receipt']['item']
    source = item['source']
    if (receipt['registrationSha256'] != fingerprint(registration)
            or item['id'] != registration['itemId'] or source['id'] != registration['sourceId']
            or source['mediaType'] != registration['mediaType'] or item['metadata'] != registration['metadata']
            or source['reference'] != {'backend': 'local-file', 'object': registration['id'],
                                       'locator': 'whole', 'availability': 'available'}
            or timestamp(receipt['capturedAt']) > timestamp(boundary.now)):
        raise CaptureError('Capture source identity or metadata changed')
    try:
        raw = base64.b64decode(capsule['body']['data'], validate=True)
    except ValueError as exc:
        raise CaptureError('Invalid capture byte encoding') from exc
    digest = hashlib.sha256(raw).hexdigest()
    if (digest != source['sha256'] or source['revision'] != 'sha256:' + digest
            or registration['sha256'] not in (None, digest)
            or len(raw) != source['byteLength'] or len(raw) != receipt['observation']['size']
            or len(raw) != receipt['usage']['sourceBytes']):
        raise CaptureError('Capture content or length changed')
    bindings = deepcopy(boundary.bindings)
    identity = fingerprint(item)
    old = bindings['references'].get(identity)
    if old is not None and old != registration['resource']:
        raise CaptureError('Capture item already binds a different resource')
    bindings['references'][identity] = registration['resource']
    selected = ReadBoundary(boundary.policy, actor=boundary.actor, now=boundary.now,
                            scopes=boundary.scopes, bindings=bindings)
    log('capture.bound', boundary.actor, expected_sha256,
        {'policySha256': boundary.policy.binding['sha256'], 'itemSha256': identity, 'modelCalls': 0})
    return selected, deepcopy(item), raw


def save_capture(root, capsule):
    """Atomic, non-overwriting private cache under the host's _internal tree.

    This caches a snapshot; it is not destination intake or a completion receipt.
    A crash after publication may leave a valid private orphan, never a partial
    accepted capsule. Repeating the same capsule reuses only exact pinned bytes.
    """
    from context_bundle import encode
    capsule = deepcopy(capsule)
    check(capsule, 'capsule')
    directory = open_directory(root)
    temp = None
    try:
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise CaptureError('Unsafe capture host directory')
        for part in ('_internal', 'intake', 'captures'):
            try:
                os.mkdir(part, mode=0o700, dir_fd=directory)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
            info = os.fstat(directory)
            if info.st_uid != os.geteuid() or info.st_mode & (0o022 if part == '_internal' else 0o077):
                raise CaptureError('Unsafe private capture directory')
        raw = encode(capsule)
        name = fingerprint(capsule) + '.json'
        candidate = '.pending-' + secrets.token_hex(16)
        fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        temp = candidate
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temp, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        except FileExistsError:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or info.st_mode & 0o077 or info.st_nlink != 1 or stream.read(len(raw) + 1) != raw):
                    raise CaptureError('Existing capture differs or is not private')
        os.fsync(directory)
        return '_internal/intake/captures/' + name
    finally:
        try:
            if temp is not None:
                os.unlink(temp, dir_fd=directory)
        finally:
            os.close(directory)


def load_capture(boundary, registration, *, root, path, expected_sha256, max_bytes, log):
    """Authorize before loading a host-selected cache path, then verify every byte."""
    authorize(boundary, registration)
    if (type(max_bytes) is not int or not 1 <= max_bytes <= 67108864
            or not isinstance(expected_sha256, str) or len(expected_sha256) != 64
            or set(expected_sha256) - set('0123456789abcdef')
            or path != '_internal/intake/captures/' + expected_sha256 + '.json'):
        raise CaptureError('Invalid capture load budget')
    raw, _ = read_stable(root, path, (max_bytes + 2) // 3 * 4 + 2097152)

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise CaptureError('Duplicate capture JSON field')
            result[key] = value
        return result

    capsule = json.loads(raw, object_pairs_hook=pairs)
    check(capsule, 'capsule')
    if capsule['receipt']['usage']['sourceBytes'] > max_bytes:
        raise CaptureError('Cached capture exceeds its byte budget')
    # No output bytes are exposed until fresh authorization, the trusted capsule
    # pin and all descriptor/representation invariants have been checked.
    selected, item, content = bind_capture(boundary, registration, capsule,
                                         expected_sha256=expected_sha256, log=log)
    if len(content) > max_bytes:
        raise CaptureError('Cached capture exceeds its byte budget')
    return selected, item, content
