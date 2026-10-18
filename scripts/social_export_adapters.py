"""Bounded local social-export mappings into connector-event/v1.

This module never contacts a platform, evaluates archive code, fetches media, or
grants authority. The registered connector host remains the only proposal writer.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import stat
import zipfile

from connector_events import MAX_LINE_BYTES, validate

MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 2000
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_EVENTS = 1000
MAX_JSON_DEPTH = 64
MAX_MAPPING_BYTES = 16384

CAPABILITIES = {
    'format': 'social-export-capabilities/v1',
    'transport': 'operator-selected-local-snapshot',
    'liveApi': False,
    'polling': False,
    'push': False,
    'attachmentFetch': False,
    'automaticReviewOrDelivery': False,
    'deletionFromAbsence': False,
    'adapters': {
        'x': {'profile': 'x-archive-tweets-js/v1', 'support': 'fixture-qualified-local-profile',
              'supported': ['archiveImport', 'postText', 'nativeId', 'authoredTime', 'explicitReply'],
              'unavailable': ['stableOfficialMemberSchema', 'liveApi', 'editHistory', 'deletionHistory', 'mediaBytes', 'membership']},
        'reddit': {'profile': 'operator-json-map/v1', 'support': 'operator-bridge',
                   'supported': ['mappedJsonRecords', 'sourceEvidenceLocator'],
                   'unavailable': ['officialArchiveSchema', 'liveApi', 'editHistory', 'deletions', 'mediaBytes']},
        'facebook': {'profile': 'operator-json-map/v1', 'support': 'operator-bridge',
                     'supported': ['mappedJsonRecords', 'sourceEvidenceLocator'],
                     'unavailable': ['stableOfficialMemberSchema', 'liveApi', 'editHistory', 'deletions', 'mediaBytes']},
        'instagram': {'profile': 'operator-json-map/v1', 'support': 'operator-bridge',
                      'supported': ['mappedJsonRecords', 'sourceEvidenceLocator'],
                      'unavailable': ['stableOfficialMemberSchema', 'liveApi', 'editHistory', 'deletions', 'mediaBytes']},
        'tiktok': {'profile': 'operator-json-map/v1', 'support': 'operator-bridge',
                   'supported': ['mappedJsonRecords', 'sourceEvidenceLocator'],
                   'unavailable': ['stableOfficialMemberSchema', 'liveApi', 'mediaBytes', 'deletions']},
        'bluesky': {'profile': 'bluesky-post-snapshot/v1', 'support': 'qualified-local-profile',
                    'supported': ['postText', 'uriCid', 'authoredTime', 'languageTags', 'explicitReply'],
                    'unavailable': ['liveApi', 'editHistory', 'deletions', 'mediaBytes', 'membership']},
        'mastodon': {'profile': 'mastodon-status-snapshot/v1', 'support': 'qualified-local-profile',
                     'supported': ['statusText', 'nativeId', 'authoredTime', 'explicitReply', 'visibility', 'language'],
                     'unavailable': ['liveApi', 'editHistory', 'deletions', 'mediaBytes', 'membership'],
                     'limits': ['content is retained as inert source text; downstream must not render it as HTML']},
    },
}


class SocialExportError(ValueError):
    """The selected export is malformed, ambiguous, or outside safe bounds."""


def read_stable_file(path, maximum):
    """Read one regular file only when descriptor and pathname stay unchanged."""
    def signature(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    initial = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(initial.st_mode) or initial.st_size > maximum:
        raise SocialExportError('Selected input must be a bounded regular file')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or signature(initial) != signature(before):
            raise SocialExportError('Selected input changed before it could be read')
        chunks, size = [], 0
        while size <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        after = os.fstat(descriptor)
        final_path = os.stat(path, follow_symlinks=False)
        if (not stat.S_ISREG(after.st_mode) or not stat.S_ISREG(final_path.st_mode)
                or signature(before) != signature(after) or signature(after) != signature(final_path)
                or size != after.st_size or size > maximum):
            raise SocialExportError('Selected input changed during its stable read')
        return b''.join(chunks)
    finally:
        os.close(descriptor)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SocialExportError('Duplicate JSON property')
        result[key] = value
    return result


def _depth(value, depth=0):
    if depth > MAX_JSON_DEPTH:
        raise SocialExportError('JSON nesting exceeds the adapter bound')
    if isinstance(value, dict):
        for child in value.values():
            _depth(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _depth(child, depth + 1)


def _json(raw, label):
    if not isinstance(raw, bytes) or len(raw) > MAX_MEMBER_BYTES:
        raise SocialExportError(f'{label} exceeds the source-byte bound')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(
                               SocialExportError('Non-finite JSON value')))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SocialExportError(f'{label} is not UTF-8 JSON') from exc
    _depth(value)
    return value


def read_archive(raw):
    """Read a bounded ZIP in memory without extracting any member to disk."""
    if not isinstance(raw, bytes) or len(raw) > MAX_ARCHIVE_BYTES:
        raise SocialExportError('Archive exceeds the compressed-byte bound')
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
        infos = archive.infolist()
    except (zipfile.BadZipFile, OSError) as exc:
        raise SocialExportError('Invalid ZIP archive') from exc
    if len(infos) > MAX_ARCHIVE_ENTRIES:
        raise SocialExportError('Archive entry count exceeds the bound')
    names, members, expanded = set(), {}, 0
    for info in infos:
        name = info.filename
        parts = name.split('/')
        if info.is_dir() and parts[-1] == '':
            parts = parts[:-1]
        mode = info.external_attr >> 16
        if (not name or len(name) > 1024 or '\\' in name or name.startswith('/')
                or re.match(r'^[A-Za-z]:', name) or any(ord(ch) < 0x20 for ch in name)
                or any(part in ('', '.', '..') for part in parts) or name in names
                or info.flag_bits & 1 or (mode and (mode & 0o170000) == 0o120000)):
            raise SocialExportError('Archive contains a duplicate, unsafe, encrypted, or linked path')
        names.add(name)
        if info.is_dir():
            continue
        if name.lower().endswith(('.zip', '.7z', '.tar', '.gz')):
            raise SocialExportError('Nested archives are not supported')
        if info.file_size > MAX_MEMBER_BYTES:
            raise SocialExportError('Archive member exceeds the per-file bound')
        if info.file_size and (not info.compress_size or info.file_size > info.compress_size * 200):
            raise SocialExportError('Archive member compression ratio exceeds the bound')
        expanded += info.file_size
        if expanded > MAX_EXPANDED_BYTES:
            raise SocialExportError('Archive expanded size exceeds the total bound')
        try:
            with archive.open(info, 'r') as handle:
                data = handle.read(MAX_MEMBER_BYTES + 1)
        except (zipfile.BadZipFile, RuntimeError, OSError, NotImplementedError) as exc:
            raise SocialExportError('Archive member failed integrity validation') from exc
        if len(data) != info.file_size:
            raise SocialExportError('Archive member size differs from its directory entry')
        members[name] = data
    return members


def _pointer(value, pointer):
    if not isinstance(pointer, str) or len(pointer) > 2048:
        raise SocialExportError('JSON field path must be a bounded JSON Pointer')
    if pointer == '':
        return value
    if not pointer.startswith('/'):
        raise SocialExportError('JSON field path must be an absolute JSON Pointer')
    current = value
    for raw_part in pointer[1:].split('/'):
        if re.search(r'~(?![01])', raw_part):
            raise SocialExportError('Invalid JSON Pointer escape')
        part = raw_part.replace('~1', '/').replace('~0', '~')
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdecimal() and int(part) < len(current):
            current = current[int(part)]
        else:
            raise SocialExportError('Configured JSON field path does not exist')
    return current


def _mapping(value, platform):
    expected = {'format', 'platform', 'records', 'id', 'text', 'eventTime', 'thread', 'language', 'actor', 'visibility'}
    if (not isinstance(value, dict) or set(value) != expected or value.get('format') != 'operator-json-map/v1'
            or value.get('platform') != platform):
        raise SocialExportError('Operator map must match the bounded operator-json-map/v1 contract')
    for field in ('records', 'id', 'text'):
        if not isinstance(value[field], str) or len(value[field]) > 2048:
            raise SocialExportError('Operator map paths must be bounded JSON Pointers')
    for field in ('eventTime', 'thread', 'language', 'actor', 'visibility'):
        if value[field] is not None and (not isinstance(value[field], str) or len(value[field]) > 2048):
            raise SocialExportError('Optional operator map paths must be null or bounded JSON Pointers')
    for field in ('records', 'id', 'text', 'eventTime', 'thread', 'language', 'actor', 'visibility'):
        path = value[field]
        if path is not None and (path != '' and (not path.startswith('/') or re.search(r'~(?![01])', path))):
            raise SocialExportError('Operator mapping contains a non-pointer expression or invalid escape')
    return value


def _field(row, path, *, optional=False):
    if path is None and optional:
        return None
    value = _pointer(row, path)
    if optional and value is None:
        return None
    return value


def _event(*, platform, namespace, native_id, order, revision, text, locator,
           event_time=None, thread=None, language=None, actor=None, visibility=None):
    if type(native_id) is int:
        native_id = str(native_id)
    if not isinstance(native_id, str) or not native_id or len(native_id) > 900:
        raise SocialExportError('A bounded native record ID is required')
    if not isinstance(text, str) or len(text.encode('utf-8')) > 65536:
        raise SocialExportError('A bounded UTF-8 text field is required')
    if event_time is not None:
        if isinstance(event_time, int) and not isinstance(event_time, bool):
            event_time = str(event_time)
        if not isinstance(event_time, str) or len(event_time) > 128:
            raise SocialExportError('Event time must be a bounded string or exact integer')
    if thread is not None:
        if type(thread) is int:
            thread = str(thread)
        if not isinstance(thread, str) or len(thread) > 900:
            raise SocialExportError('Thread reference must be a bounded string or exact integer')
        thread = platform + ':' + thread
    for name, value, maximum in (('language', language, 64), ('actor', actor, 1024),
                                 ('visibility', visibility, 256)):
        if value is not None and (not isinstance(value, str) or len(value) > maximum):
            raise SocialExportError(f'{name} must be a bounded string')
    object_id = platform + ':' + native_id
    raw = text.encode('utf-8')
    value = {
        'format': 'connector-event/v1', 'namespace': namespace,
        'objectId': object_id, 'eventId': 'source-record:' + object_id,
        'revision': revision, 'order': str(order), 'operation': 'upsert',
        'actor': actor, 'thread': thread, 'eventTime': event_time, 'observedAt': None,
        'language': language, 'text': text, 'attachments': [], 'locator': locator,
        'visibility': visibility,
        'payload': {'encoding': 'base64', 'mediaType': 'text/plain; charset=utf-8',
                    'byteLength': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                    'data': base64.b64encode(raw).decode('ascii')},
    }
    validate(value)
    return value


def _serialize(events):
    if len(events) > MAX_EVENTS:
        raise SocialExportError('Selected export exceeds the event-count bound')
    output = []
    objects = set()
    for event in events:
        identity = (event['namespace'], event['objectId'])
        if identity in objects:
            raise SocialExportError('Selected snapshot repeats a platform object ID')
        objects.add(identity)
        line = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8') + b'\n'
        if len(line) > MAX_LINE_BYTES:
            raise SocialExportError('Normalized event exceeds the connector line bound')
        output.append(line)
    return output


def _base(platform, namespace, source_sha, ordinal, record, *, member, pointer,
          id_path, text_path, time_path=None, thread_path=None, language_path=None,
          actor_path=None, visibility_path=None):
    native_id = _field(record, id_path)
    text = _field(record, text_path)
    def optional(path):
        return _field(record, path, optional=True) if path is not None else None
    locator = f'{member}#{pointer};source-sha256={source_sha}'
    # Snapshot adapters do not invent a total event order. Fixed order zero lets
    # exact replay be stable and makes every changed snapshot refuse as stale.
    return _event(platform=platform, namespace=namespace, native_id=native_id, order=0,
                  revision=f'snapshot:{source_sha}:{ordinal}', text=text, locator=locator,
                  event_time=optional(time_path), thread=optional(thread_path),
                  language=optional(language_path), actor=optional(actor_path),
                  visibility=optional(visibility_path))


def _operator_rows(platform, value, mapping, namespace, source_sha, *, member):
    mapping = _mapping(mapping, platform)
    records = _pointer(value, mapping['records'])
    if not isinstance(records, list) or len(records) > MAX_EVENTS:
        raise SocialExportError('Mapped record path must select a bounded array')
    events = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise SocialExportError('Mapped record must be an object')
        pointer = mapping['records'].rstrip('/') + '/' + str(index)
        event = _base(platform, namespace, source_sha, index, record, member=member, pointer=pointer,
                      id_path=mapping['id'], text_path=mapping['text'], time_path=mapping['eventTime'],
                      thread_path=mapping['thread'], language_path=mapping['language'],
                      actor_path=mapping['actor'], visibility_path=mapping['visibility'])
        events.append(event)
    return events


def _x_archive(members, namespace, source_sha, member):
    if member not in members or not member.endswith('.js'):
        raise SocialExportError('Select a documented X archive JavaScript JSON wrapper member')
    raw = members[member]
    prefix = re.match(rb'^window\.YTD\.tweets\.part[0-9]+\s*=\s*', raw)
    if prefix is None:
        raise SocialExportError('X archive wrapper is not the qualified tweets assignment form')
    body = raw[prefix.end():].strip()
    if body.endswith(b';'):
        body = body[:-1].rstrip()
    value = _json(body, 'X tweets assignment JSON')
    if not isinstance(value, list) or len(value) > MAX_EVENTS:
        raise SocialExportError('X tweets wrapper must contain a bounded array')
    events = []
    for index, row in enumerate(value):
        if not isinstance(row, dict) or set(row) != {'tweet'} or not isinstance(row['tweet'], dict):
            raise SocialExportError('X tweets wrapper row has an unsupported shape')
        tweet = row['tweet']
        required = {'id_str', 'full_text', 'created_at'}
        if not required <= set(tweet):
            raise SocialExportError('X tweet row is missing required source fields')
        events.append(_base('x', namespace, source_sha, index, tweet, member=member,
                            pointer=f'/{index}/tweet', id_path='/id_str', text_path='/full_text',
                            time_path='/created_at', thread_path='/in_reply_to_status_id_str',
                            language_path='/lang', actor_path='/user_id_str'))
    return events


def _bluesky(value, namespace, source_sha):
    rows = value if isinstance(value, list) else [value]
    if len(rows) > MAX_EVENTS:
        raise SocialExportError('Bluesky snapshot exceeds the event bound')
    events = []
    for index, row in enumerate(rows):
        if (not isinstance(row, dict) or not isinstance(row.get('uri'), str)
                or not isinstance(row.get('cid'), str) or not isinstance(row.get('value'), dict)):
            raise SocialExportError('Bluesky snapshot requires URI, CID and record value')
        record = row['value']
        if record.get('$type') != 'app.bsky.feed.post':
            raise SocialExportError('Bluesky snapshot contains a non-post record')
        reply = record.get('reply')
        thread = None
        if reply is not None:
            if not isinstance(reply, dict) or not isinstance(reply.get('parent'), dict):
                raise SocialExportError('Bluesky reply reference is malformed')
            thread = reply['parent'].get('uri')
            if not isinstance(thread, str):
                raise SocialExportError('Bluesky parent URI is required when reply is present')
        langs = record.get('langs')
        if langs is not None and (not isinstance(langs, list) or any(not isinstance(x, str) for x in langs)):
            raise SocialExportError('Bluesky language tags must be strings')
        language = ','.join(langs) if langs else None
        event = _event(platform='bluesky', namespace=namespace, native_id=row['uri'], order=0,
                       revision=f"{row['cid']}:{source_sha}", text=record.get('text'),
                       locator=f'/{index};source-sha256={source_sha};uri={row["uri"]};cid={row["cid"]}',
                       event_time=record.get('createdAt'), thread=thread, language=language)
        events.append(event)
    return events


def _mastodon(value, namespace, source_sha):
    rows = value if isinstance(value, list) else [value]
    if len(rows) > MAX_EVENTS:
        raise SocialExportError('Mastodon snapshot exceeds the event bound')
    events = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise SocialExportError('Mastodon Status must be an object')
        # The API's Status `content` is HTML. It remains a source string and must be
        # treated as inert text by every downstream renderer.
        events.append(_base('mastodon', namespace, source_sha, index, row, member='saved-status-json',
                            pointer=f'/{index}', id_path='/id', text_path='/content',
                            time_path='/created_at', thread_path='/in_reply_to_id',
                            language_path='/language', actor_path='/account/acct',
                            visibility_path='/visibility'))
    return events


def normalize(platform, raw, namespace, *, member=None, mapping=None):
    if platform not in CAPABILITIES['adapters']:
        raise SocialExportError('Unknown social platform profile')
    if not isinstance(namespace, str) or not 1 <= len(namespace) <= 256 or not namespace.strip():
        raise SocialExportError('An operator-selected bounded namespace is required')
    if not isinstance(raw, bytes) or len(raw) > MAX_ARCHIVE_BYTES:
        raise SocialExportError('Selected source exceeds the byte bound')
    source_sha = hashlib.sha256(raw).hexdigest()
    if platform in ('x', 'tiktok', 'reddit', 'facebook', 'instagram'):
        if raw.startswith(b'PK\x03\x04'):
            members = read_archive(raw)
            if not isinstance(member, str) or member not in members:
                raise SocialExportError('Select one exact archive member')
            selected = members[member]
        else:
            if member not in (None, ''):
                raise SocialExportError('A member path is valid only for ZIP input')
            member, selected = 'saved-json', raw
        if platform == 'x':
            return _serialize(_x_archive(members if raw.startswith(b'PK\x03\x04') else {member: selected},
                                         namespace, source_sha, member))
        value = _json(selected, f'{platform} selected JSON')
        if platform == 'tiktok':
            if not isinstance(mapping, dict) or mapping.get('platform') != 'tiktok':
                raise SocialExportError('TikTok currently requires an explicit operator JSON map')
        return _serialize(_operator_rows(platform, value, mapping, namespace, source_sha, member=member))
    value = _json(raw, f'{platform} snapshot')
    if platform == 'bluesky':
        return _serialize(_bluesky(value, namespace, source_sha))
    if platform == 'mastodon':
        return _serialize(_mastodon(value, namespace, source_sha))
    raise SocialExportError('No adapter implementation is qualified for this source')


def load_mapping(raw, platform):
    if not isinstance(raw, bytes) or len(raw) > MAX_MAPPING_BYTES:
        raise SocialExportError('Operator mapping exceeds its byte bound')
    return _mapping(_json(raw, 'operator mapping'), platform)
