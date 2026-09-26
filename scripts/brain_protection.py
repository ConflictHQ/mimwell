"""Portable protection requirements and strict, opt-in protected-record adapters.

Host identities, current source policy, keys and resolvers never come from record
content. Ciphertext integrity is not authorship, factual truth or permission.
"""
import base64
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat

from context_bundle import encode
from knowledge_policy import fingerprint

FORMAT = 'protected-record/v1'
MAX_BODY = 4 * 1024 * 1024
MAX_EXCHANGE = 32 * 1024 * 1024
MAX_ROOT = 32 * 1024 * 1024
ROOT_FORMAT = 'root-files/v1'
SQLITE_HEADER = b'SQLite format 3\x00'
MODES = ('plaintext', 'whole-root', 'per-record', 'hybrid-pointer', 'served')
DEFAULT_REQUIREMENTS = {'encryption': False, 'mediation': False, 'opaqueMetadata': False,
                        'offline': True, 'plaintextCopies': True, 'derivatives': True,
                        'verifiedAuthorship': False}
CAPABILITIES = {
    'plaintext': {'implemented': True, 'encrypted': False, 'mediated': False, 'opaque': False, 'offline': True,
                  'losses': ['plaintext-at-rest-and-history']},
    'whole-root': {'implemented': True, 'encrypted': True, 'mediated': False, 'opaque': True, 'offline': True,
                   'losses': ['opaque-diffs', 'external-tools-unavailable', 'key-required', 'reseal-per-write',
                              'sqlite-in-memory-only']},
    'per-record': {'implemented': True, 'encrypted': True, 'mediated': False, 'opaque': True, 'offline': True,
                   'losses': ['protected-record-diffs-opaque', 'key-required', 'metadata-size-and-linkability']},
    'hybrid-pointer': {'implemented': True, 'encrypted': True, 'mediated': True, 'opaque': True, 'offline': False,
                       'losses': ['resolver-required', 'key-required', 'metadata-size-and-linkability', 'offline-unavailable']},
    'served': {'implemented': True, 'encrypted': False, 'mediated': True, 'opaque': True, 'offline': False,
               'losses': ['service-required', 'offline-unavailable', 'server-storage-requires-separate-proof']},
}


class ProtectionError(ValueError):
    """Only a stable reason code; never include source bodies or key material."""


def fields(value, names):
    if not isinstance(value, dict) or set(value) != set(names):
        raise ProtectionError('invalid-descriptor')


def opaque(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{32}', value) is None:
        raise ProtectionError('opaque-identifier-required')
    return value


def new_id():
    return secrets.token_hex(16)


def requirements(value):
    fields(value, DEFAULT_REQUIREMENTS)
    if any(type(v) is not bool for v in value.values()):
        raise ProtectionError('invalid-requirements')
    return deepcopy(value)


def combine(*values):
    """Record/mount constraints only strengthen the independently supplied source."""
    result = deepcopy(DEFAULT_REQUIREMENTS)
    for value in values:
        value = requirements(value)
        for key in result:
            result[key] = (result[key] and value[key]) if key in ('offline', 'plaintextCopies', 'derivatives') else (result[key] or value[key])
    return result


def profile(value):
    fields(value, ('mode', 'key', 'resolver', 'signer', 'recipientPolicy', 'trust'))
    if value['mode'] not in MODES or value['trust'] not in ('untrusted', 'reviewed'):
        raise ProtectionError('invalid-profile')
    opaque(value['recipientPolicy'])
    for key in ('key', 'resolver', 'signer'):
        if value[key] is not None:
            opaque(value[key])
    mode = value['mode']
    if (mode == 'plaintext' and (value['key'] is not None or value['resolver'] is not None)
            or mode in ('per-record', 'whole-root') and (value['key'] is None or value['resolver'] is not None)
            or mode == 'hybrid-pointer' and (value['key'] is None or value['resolver'] is None)
            or mode == 'served' and (value['key'] is not None or value['resolver'] is None)):
        raise ProtectionError('invalid-profile-handles')
    return deepcopy(value)


def assess(required, selected, *, offline=False, operation='read'):
    required, selected = requirements(required), profile(selected)
    cap = CAPABILITIES[selected['mode']]
    reasons = []
    if not cap['implemented']:
        reasons.append('unsupported-adapter')
    if required['encryption'] and not cap['encrypted']:
        reasons.append('encryption-required')
    if required['mediation'] and not cap['mediated']:
        reasons.append('mediation-required')
    if required['opaqueMetadata'] and not cap['opaque']:
        reasons.append('opaque-metadata-required')
    if required['verifiedAuthorship'] and selected['signer'] is None:
        reasons.append('verified-authorship-required')
    if offline and (not required['offline'] or not cap['offline']):
        reasons.append('offline-unavailable')
    if selected['mode'] == 'plaintext' and not required['plaintextCopies']:
        reasons.append('plaintext-retention-forbidden')
    if operation == 'derive' and not required['derivatives']:
        reasons.append('derivatives-forbidden')
    return {'supported': not reasons, 'reasons': sorted(reasons), 'losses': list(cap['losses']),
            'permissions': 'not-evaluated', 'trust': selected['trust']}


def retention_requirements(required, selected):
    """Propagate selected protections to caches/indexes, not only source minima.

    A mount choosing encryption cannot silently place decrypted copies into a
    plaintext derivative merely because its source allowed the weaker mode.
    """
    required, selected = requirements(required), profile(selected)
    cap = CAPABILITIES[selected['mode']]
    if not assess(required, selected)['supported']:
        raise ProtectionError('source-requirements-unsatisfied')
    return combine(required, {**DEFAULT_REQUIREMENTS, 'encryption': cap['encrypted'],
                             'mediation': cap['mediated'], 'opaqueMetadata': cap['opaque'],
                             'verifiedAuthorship': selected['signer'] is not None})


def _binary(value, *, maximum):
    if not isinstance(value, str) or len(value) > (maximum + 2) // 3 * 4:
        raise ProtectionError('invalid-binary-envelope')
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise ProtectionError('invalid-binary-envelope') from None
    if len(raw) > maximum or base64.b64encode(raw).decode() != value:
        raise ProtectionError('invalid-binary-envelope')
    return raw


def _b64(raw):
    return base64.b64encode(raw).decode('ascii')


def validate(entry, *, protected_only=False):
    fields(entry, ('format', 'object', 'revision', 'requirements', 'profile', 'storage', 'signature'))
    if entry['format'] != FORMAT:
        raise ProtectionError('unsupported-record-format')
    opaque(entry['object'])
    opaque(entry['revision'])
    requirements(entry['requirements'])
    p = profile(entry['profile'])
    storage = entry['storage']
    if p['mode'] == 'plaintext':
        if protected_only:
            raise ProtectionError('plaintext-export-forbidden')
        fields(storage, ('encoding', 'body'))
        if storage['encoding'] != 'json' or len(encode(storage['body'])) > MAX_BODY:
            raise ProtectionError('invalid-plaintext-body')
    elif p['mode'] == 'per-record':
        _ciphertext(storage)
    elif p['mode'] == 'whole-root':
        _ciphertext(storage, maximum=MAX_ROOT)
    elif p['mode'] == 'hybrid-pointer':
        fields(storage, ('encoding', 'object', 'revision', 'sha256'))
        if storage['encoding'] != 'external/v1':
            raise ProtectionError('invalid-external-reference')
        opaque(storage['object'])
        opaque(storage['revision'])
        if not isinstance(storage['sha256'], str) or re.fullmatch('[a-f0-9]{64}', storage['sha256']) is None:
            raise ProtectionError('invalid-ciphertext-digest')
    else:
        fields(storage, ('encoding', 'object', 'revision'))
        if storage['encoding'] != 'served/v1':
            raise ProtectionError('invalid-served-reference')
        opaque(storage['object'])
        opaque(storage['revision'])
    if (p['signer'] is None) != (entry['signature'] is None):
        raise ProtectionError('signature-required')
    if entry['signature'] is not None:
        fields(entry['signature'], ('algorithm', 'value'))
        if entry['signature']['algorithm'] != 'ed25519/v1' or len(_binary(entry['signature']['value'], maximum=64)) != 64:
            raise ProtectionError('invalid-signature')
    if not assess(entry['requirements'], p)['supported']:
        raise ProtectionError('source-requirements-unsatisfied')
    return deepcopy(entry)


def _ciphertext(storage, *, maximum=MAX_BODY):
    fields(storage, ('encoding', 'nonce', 'ciphertext'))
    if storage['encoding'] != 'aes256gcm/v1':
        raise ProtectionError('protected-body-required')
    if len(_binary(storage['nonce'], maximum=12)) != 12:
        raise ProtectionError('invalid-nonce')
    if len(_binary(storage['ciphertext'], maximum=maximum + 16)) < 16:
        raise ProtectionError('invalid-ciphertext')


def _root_files(body):
    """A whole-root body: every file of one root, by relative POSIX path."""
    if (not isinstance(body, dict) or set(body) != {'format', 'files'} or body['format'] != ROOT_FORMAT
            or not isinstance(body['files'], dict) or not body['files']):
        raise ProtectionError('invalid-root-files')
    for path, value in body['files'].items():
        parts = path.split('/') if isinstance(path, str) and len(path) <= 1024 else []
        if not parts or any(p in ('', '.', '..') or '\\' in p or '\x00' in p for p in parts):
            raise ProtectionError('invalid-root-path')
        _binary(value, maximum=MAX_ROOT)
    return body


def root_body(files):
    """Build a whole-root body from {relative path: bytes}."""
    if not isinstance(files, dict) or any(not isinstance(v, bytes) for v in files.values()):
        raise ProtectionError('invalid-root-files')
    return _root_files({'format': ROOT_FORMAT, 'files': {k: _b64(v) for k, v in sorted(files.items())}})


def _sqlite_sidecar(path):
    """A -wal, -shm or -journal file beside the SQLite database it belongs to."""
    for suffix in ('-wal', '-shm', '-journal'):
        if path.name.endswith(suffix) and len(path.name) > len(suffix):
            database = path.with_name(path.name[:-len(suffix)])
            if database.is_file():
                with open(database, 'rb') as f:
                    return f.read(16) == SQLITE_HEADER
    return False


def pack_root(directory):
    """Read every regular file under a brain root into one whole-root body.

    Symlinks and special files refuse, as do SQLite journal/WAL sidecars: a root
    with an open or uncheckpointed database is not a consistent snapshot. Empty
    directories are not kept. The caller decides what the root is (a `.git`
    directory inside it is packed like any other file).
    """
    root, files = Path(directory), {}
    for base, dirs, names in os.walk(root):
        for name in dirs + names:
            path = Path(base, name)
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                continue
            if not stat.S_ISREG(mode):
                raise ProtectionError('root-entry-unsupported')
            if _sqlite_sidecar(path):
                raise ProtectionError('sqlite-sidecar-present')
            files[path.relative_to(root).as_posix()] = path.read_bytes()
    return root_body(files)


class RootFiles:
    """In-memory read view of an opened whole-root body; writes no plaintext to disk.

    `sqlite` opens a database file as an in-memory copy (no temporary file; its
    temporary storage is held in memory too, so sorts and temp tables never spill
    to TMPDIR). Changes to it or to any file are not persisted: serialize,
    `root_body` and seal a new revision to write.
    """

    def __init__(self, body):
        self._files = {k: base64.b64decode(v) for k, v in _root_files(body)['files'].items()}

    def paths(self):
        return sorted(self._files)

    def read(self, path):
        if path not in self._files:
            raise ProtectionError('root-file-unavailable')
        return self._files[path]

    def sqlite(self, path):
        raw = bytearray(self.read(path))
        if raw[:16] != SQLITE_HEADER:
            raise ProtectionError('invalid-sqlite-file')
        raw[18:20] = b'\x01\x01'  # A checkpointed WAL database reads as rollback-journal in memory.
        db = sqlite3.connect(':memory:')
        # Sorts, transient indices and temp tables would otherwise spill decrypted
        # rows to files under TMPDIR (the usual build default is TEMP_STORE=1).
        # A TEMP_STORE=0 build ignores the pragma and always uses files.
        db.execute('PRAGMA temp_store=MEMORY')
        if ('TEMP_STORE=0',) in db.execute('PRAGMA compile_options').fetchall():
            db.close()
            raise ProtectionError('sqlite-temp-store-unavailable')
        try:
            db.deserialize(bytes(raw))
        except sqlite3.DatabaseError:
            db.close()
            raise ProtectionError('invalid-sqlite-file') from None
        return db


def _crypto():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM
    except ImportError:
        raise ProtectionError('crypto-adapter-unavailable') from None


def _signing_type(*, private):
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        return Ed25519PrivateKey if private else Ed25519PublicKey
    except ImportError:
        raise ProtectionError('crypto-adapter-unavailable') from None


def _header(entry):
    return {k: deepcopy(entry[k]) for k in ('format', 'object', 'revision', 'requirements', 'profile')}


def _signed(entry):
    return encode({k: v for k, v in entry.items() if k != 'signature'})


class ProtectionHost:
    """Host-owned callbacks, authenticated actor, current policy and opaque handles.

    authorize receives actor, operation and the complete immutable header. It must
    enforce every referenced recipient policy and current source access. Keys must
    be purpose-specific random 32-byte data keys; passphrases/KDFs and key storage
    are host responsibilities. Public verification keys must be independently pinned.
    """

    def __init__(self, *, actor, authorize, keys, resolvers, signers=None, verifiers=None):
        if not isinstance(actor, str) or not actor or not callable(authorize) or not callable(keys):
            raise ProtectionError('invalid-protection-host')
        self.actor, self.authorize, self.keys = actor, authorize, keys
        self.resolvers = dict(resolvers)
        self.signers, self.verifiers = dict(signers or {}), dict(verifiers or {})

    def permit(self, header, operation):
        try:
            allowed = self.authorize({'actor': self.actor, 'operation': operation, 'record': deepcopy(header)}) is True
        except Exception:
            allowed = False
        if not allowed:
            raise ProtectionError('permission-unavailable')

    def key(self, reference):
        try:
            key = self.keys(reference)
        except Exception:
            key = None
        if not isinstance(key, bytes) or len(key) != 32:
            raise ProtectionError('key-unavailable')
        return key

    def resolver(self, reference):
        result = self.resolvers.get(reference)
        if result is None:
            raise ProtectionError('resolver-unavailable')
        return result

    def available(self, selected):
        """Preflight selected local handles; it never grants access or reads bodies."""
        selected = profile(selected)
        if not CAPABILITIES[selected['mode']]['implemented']:
            raise ProtectionError('unsupported-adapter')
        if selected['mode'] in ('per-record', 'hybrid-pointer', 'whole-root'):
            _crypto()
            self.key(selected['key'])
        if selected['mode'] in ('hybrid-pointer', 'served'):
            self.resolver(selected['resolver'])
        if selected['signer'] is not None:
            signer = self.signers.get(selected['signer'])
            if not isinstance(signer, _signing_type(private=True)):
                raise ProtectionError('signing-key-unavailable')
            verifier = self.verifiers.get(selected['signer'])
            if not isinstance(verifier, _signing_type(private=False)):
                raise ProtectionError('verification-key-unavailable')
            if signer.public_key().public_bytes_raw() != verifier.public_bytes_raw():
                raise ProtectionError('verification-key-mismatch')

    def seal(self, body, *, object_id, revision, required, selected):
        opaque(object_id)
        opaque(revision)
        required, selected = requirements(required), profile(selected)
        checked = assess(required, selected)
        if not checked['supported']:
            raise ProtectionError(checked['reasons'][0])
        if selected['mode'] == 'whole-root':
            _root_files(body)
        raw = encode(body)
        if len(raw) > (MAX_ROOT if selected['mode'] == 'whole-root' else MAX_BODY):
            raise ProtectionError('body-budget-exceeded')
        entry = {'format': FORMAT, 'object': object_id, 'revision': revision,
                 'requirements': required, 'profile': selected}
        self.permit(entry, 'retain')
        self.available(selected)
        if selected['mode'] == 'plaintext':
            storage = {'encoding': 'json', 'body': deepcopy(body)}
        elif selected['mode'] == 'served':
            # The body stays with the mediator; the envelope holds only a reference.
            ref = {'object': new_id(), 'revision': new_id()}
            try:
                self.resolver(selected['resolver']).put(ref, deepcopy(body))
            except ProtectionError:
                raise
            except Exception:
                raise ProtectionError('resolver-unavailable') from None
            storage = {'encoding': 'served/v1', **ref}
        else:
            nonce = secrets.token_bytes(12)
            encrypted = _crypto()(self.key(selected['key'])).encrypt(nonce, raw, encode(entry))
            storage = {'encoding': 'aes256gcm/v1', 'nonce': _b64(nonce), 'ciphertext': _b64(encrypted)}
            if selected['mode'] == 'hybrid-pointer':
                ref = {'object': new_id(), 'revision': new_id()}
                try:
                    self.resolver(selected['resolver']).put(ref, deepcopy(storage))
                except ProtectionError:
                    raise
                except Exception:
                    raise ProtectionError('resolver-unavailable') from None
                storage = {'encoding': 'external/v1', **ref, 'sha256': fingerprint(storage)}
        entry.update(storage=storage, signature=None)
        if selected['signer'] is not None:
            signer = self.signers.get(selected['signer'])
            if not isinstance(signer, _signing_type(private=True)):
                raise ProtectionError('signing-key-unavailable')
            try:
                entry['signature'] = {'algorithm': 'ed25519/v1', 'value': _b64(signer.sign(_signed(entry)))}
            except Exception:
                raise ProtectionError('signing-key-unavailable') from None
        self.permit(_header(entry), 'retain')
        return validate(entry)

    def open(self, entry, *, expected_object, expected_revision, expected_profile, required, offline=False):
        entry = validate(entry)
        if (entry['object'], entry['revision']) != (expected_object, expected_revision):
            raise ProtectionError('protected-revision-changed')
        if entry['profile'] != profile(expected_profile):
            raise ProtectionError('selected-protection-changed')
        effective = combine(required, entry['requirements'])
        check = assess(effective, entry['profile'], offline=offline)
        if not check['supported']:
            raise ProtectionError(check['reasons'][0])
        header = _header(entry)
        # Host also sees the independently required restrictions, preventing an
        # imported header from substituting its weaker policy for the source.
        authorization = {**header, 'requirements': effective}
        self.permit(authorization, 'read')
        signer = entry['profile']['signer']
        if signer is not None:
            verifier = self.verifiers.get(signer)
            if not isinstance(verifier, _signing_type(private=False)):
                raise ProtectionError('verification-key-unavailable')
            try:
                verifier.verify(_binary(entry['signature']['value'], maximum=64), _signed(entry))
            except Exception:
                raise ProtectionError('signature-invalid') from None
        storage = entry['storage']
        if storage['encoding'] == 'served/v1':
            # The mediator authorizes and logs this read itself; a denial there
            # (revocation, withdrawal) stops the read even with a host grant.
            try:
                body = self.resolver(entry['profile']['resolver']).read(
                    {k: storage[k] for k in ('object', 'revision')},
                    {'actor': self.actor, 'operation': 'read', 'record': deepcopy(authorization)})
            except ProtectionError:
                raise
            except Exception:
                raise ProtectionError('resolver-unavailable') from None
        elif storage['encoding'] == 'external/v1':
            try:
                resolved = self.resolver(entry['profile']['resolver']).get({k: storage[k] for k in ('object', 'revision')})
            except ProtectionError:
                raise
            except Exception:
                raise ProtectionError('resolver-unavailable') from None
            if resolved is None:
                raise ProtectionError('body-unavailable')
            if fingerprint(resolved) != storage['sha256']:
                raise ProtectionError('external-body-changed')
            storage = resolved
        if entry['profile']['mode'] == 'plaintext':
            body = deepcopy(storage['body'])
        elif entry['profile']['mode'] == 'served':
            pass
        else:
            maximum = MAX_ROOT if entry['profile']['mode'] == 'whole-root' else MAX_BODY
            _ciphertext(storage, maximum=maximum)
            key = self.key(entry['profile']['key'])
            cipher = _crypto()(key)
            try:
                raw = cipher.decrypt(_binary(storage['nonce'], maximum=12),
                                     _binary(storage['ciphertext'], maximum=maximum + 16), encode(header))
                body = json.loads(raw)
                if encode(body) != raw:
                    raise ProtectionError('invalid-protected-json')
            except Exception:
                raise ProtectionError('body-authentication-failed') from None
            if entry['profile']['mode'] == 'whole-root':
                _root_files(body)
        self.permit(authorization, 'read')
        return body


class ServedMediator:
    """Reference `served` mediator: bodies stay here, every read is authorized and logged.

    `authorize` receives the reader's actor, operation and record header and must
    apply current grants; only literal True permits. `log` receives one entry per
    read attempt (actor, operation, opaque object/revision, outcome), never a body.
    A log failure refuses the read. Bodies are held in process memory: server-side
    storage protection is a separate property this reference does not provide.
    """

    def __init__(self, *, authorize, log):
        if not callable(authorize) or not callable(log):
            raise ProtectionError('invalid-served-mediator')
        self._authorize, self._log, self._bodies = authorize, log, {}

    @staticmethod
    def _key(ref):
        fields(ref, ('object', 'revision'))
        return opaque(ref['object']), opaque(ref['revision'])

    def put(self, ref, body):
        key, raw = self._key(ref), encode(body)
        if self._bodies.setdefault(key, raw) != raw:
            raise ProtectionError('immutable-body-conflict')

    def remove(self, ref):
        self._bodies.pop(self._key(ref), None)

    def read(self, ref, request):
        key = self._key(ref)
        try:
            allowed = self._authorize(deepcopy(request)) is True
        except Exception:
            allowed = False
        raw = self._bodies.get(key) if allowed else None
        outcome = 'denied' if not allowed else 'unavailable' if raw is None else 'released'
        try:
            self._log({'actor': request['actor'], 'operation': request['operation'],
                       'object': key[0], 'revision': key[1], 'outcome': outcome})
        except Exception:
            raise ProtectionError('access-log-unavailable') from None
        if not allowed:
            raise ProtectionError('permission-unavailable')
        if raw is None:
            raise ProtectionError('body-unavailable')
        return json.loads(raw)


def export_records(entries, *, host):
    """Opaque protected transport only; does not export keys or resolve bodies."""
    if not isinstance(entries, list) or len(entries) > 1024:
        raise ProtectionError('exchange-budget-exceeded')
    entries = [validate(e, protected_only=True) for e in entries]
    if len({e['object'] for e in entries}) != len(entries):
        raise ProtectionError('duplicate-protected-object')
    for entry in entries:
        host.permit(_header(entry), 'export')
    body = {'format': 'protected-exchange/v1', 'records': sorted(entries, key=lambda e: e['object'])}
    result = {**body, 'sha256': fingerprint(body)}
    if len(encode(result)) > MAX_EXCHANGE:
        raise ProtectionError('exchange-budget-exceeded')
    return result


def import_records(package):
    """Validate transport only; destination policy and native record checks remain."""
    fields(package, ('format', 'records', 'sha256'))
    if package['format'] != 'protected-exchange/v1' or len(encode(package)) > MAX_EXCHANGE:
        raise ProtectionError('unsupported-protected-exchange')
    if not isinstance(package['records'], list) or len(package['records']) > 1024:
        raise ProtectionError('exchange-budget-exceeded')
    records = [validate(e, protected_only=True) for e in package['records']]
    if len({e['object'] for e in records}) != len(records):
        raise ProtectionError('duplicate-protected-object')
    expected = {'format': 'protected-exchange/v1', 'records': sorted(records, key=lambda e: e['object'])}
    if package != {**expected, 'sha256': fingerprint(expected)}:
        raise ProtectionError('protected-exchange-mismatch')
    return deepcopy(records)
