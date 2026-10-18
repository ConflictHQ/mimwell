"""Bounded, local-only messaging export adapters for connector-event/v1.

Source authenticity remains an operator observation. The returned JSONL must be
registered separately by an operator in the protected connector host config.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import io
import json
import re
from pathlib import PurePosixPath
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from connector_events import ConnectorEventError, decode_line

MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_EVENTS = 1000
MAX_EVENT_LINE_BYTES = 1024 * 1024
MAX_PAYLOAD_BYTES = 65536


class ExportAdapterError(ValueError):
    pass


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ExportAdapterError('Duplicate JSON field in export')
        result[key] = value
    return result


def _constant(_value):
    raise ExportAdapterError('Non-finite JSON number in export')


def _json(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_SOURCE_BYTES:
        raise ExportAdapterError('Source export exceeds the 16 MiB byte bound')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs, parse_constant=_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ExportAdapterError('Export must be valid UTF-8 JSON') from exc


def _namespace(value):
    if (not isinstance(value, str) or not value.strip() or len(value) > 256
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ExportAdapterError('Operator namespace must be a non-empty string of at most 256 characters')
    return value


def _observed(value=None):
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 128:
        raise ExportAdapterError('Observed time must be an RFC 3339 timestamp')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ExportAdapterError('Observed time must be an RFC 3339 timestamp') from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ExportAdapterError('Observed time must include a timezone')
    utc = parsed.astimezone(timezone.utc)
    precision = 'microseconds' if utc.microsecond else 'seconds'
    return utc.isoformat(timespec=precision).replace('+00:00', 'Z')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _event(*, namespace, object_id, event_id, revision, order, actor, thread,
           event_time, observed_at, language, text, attachments, locator,
           visibility=None, operation='upsert'):
    raw = text.encode('utf-8') if operation in ('upsert', 'edit') and text is not None else b''
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise ExportAdapterError('Message text exceeds the 64 KiB payload bound')
    event = {
        'format': 'connector-event/v1', 'namespace': namespace, 'objectId': object_id,
        'eventId': event_id, 'revision': revision, 'order': str(order), 'operation': operation,
        'actor': actor, 'thread': thread, 'eventTime': event_time, 'observedAt': observed_at,
        'language': language, 'text': text if operation in ('upsert', 'edit') else None,
        'attachments': attachments if operation in ('upsert', 'edit') else [],
        'locator': locator, 'visibility': visibility,
        'payload': {'encoding': 'base64', 'mediaType': 'text/plain; charset=utf-8' if raw else 'application/octet-stream',
                    'byteLength': len(raw), 'sha256': _sha(raw), 'data': base64.b64encode(raw).decode('ascii')},
    }
    try:
        decode_line((json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8'))
    except (ConnectorEventError, TypeError, ValueError) as exc:
        raise ExportAdapterError('Mapped event exceeds connector-event/v1 constraints') from exc
    return event


def _finish(events):
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise ExportAdapterError('Export exceeds the 1000 event bound')
    lines = []
    total = 0
    for event in events:
        line = (json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')
        if len(line) > MAX_EVENT_LINE_BYTES:
            raise ExportAdapterError('Mapped event exceeds the 1 MiB JSONL line bound')
        decode_line(line)
        total += len(line)
        if total > MAX_SOURCE_BYTES:
            raise ExportAdapterError('Normalized event export exceeds the 16 MiB byte bound')
        lines.append(line)
    if not lines:
        raise ExportAdapterError('Export contains no supported messages; no deletion is inferred')
    return b''.join(lines)


def _local_candidates(value, zone):
    candidates = []
    for fold in (0, 1):
        aware = value.replace(tzinfo=zone, fold=fold)
        utc = aware.astimezone(timezone.utc)
        if utc.astimezone(zone).replace(tzinfo=None) == value and utc not in candidates:
            candidates.append(utc)
    return candidates


def _zone(name):
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, TypeError) as exc:
        raise ExportAdapterError('An explicit valid IANA timezone is required') from exc


_WA_FORMATS = {
    'android-en-US': (re.compile(r'^[\u200e\u200f]*(?P<stamp>\d{1,2}/\d{1,2}/\d{2},\s+\d{1,2}:\d{2}\s+[AP]M)\s+-\s+(?:(?P<sender>.*?):\s)?(?P<body>.*)$'), '%m/%d/%y, %I:%M %p'),
    'ios-en-US': (re.compile(r'^\[(?P<stamp>\d{1,2}/\d{1,2}/\d{2},\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M)\]\s+(?:(?P<sender>.*?):\s)?(?P<body>.*)$'), '%m/%d/%y, %I:%M:%S %p'),
}


def _local_to_utc(naive, zone):
    choices = _local_candidates(naive, zone)
    if not choices:
        raise ExportAdapterError('WhatsApp timestamp falls in a nonexistent local DST time')
    if len(choices) != 1:
        raise ExportAdapterError('WhatsApp timestamp is ambiguous at a local DST transition')
    return choices[0].isoformat(timespec='seconds').replace('+00:00', 'Z')


def parse_whatsapp_text(raw, *, namespace, profile, timezone_name, observed_at=None):
    """Parse one explicitly profiled WhatsApp text export; IDs are snapshot-local."""
    namespace = _namespace(namespace)
    if profile not in _WA_FORMATS:
        raise ExportAdapterError('Unsupported WhatsApp profile; choose android-en-US or ios-en-US')
    pattern, time_format = _WA_FORMATS[profile]
    zone = _zone(timezone_name)
    observed = _observed(observed_at)
    if not isinstance(raw, bytes) or len(raw) > MAX_SOURCE_BYTES:
        raise ExportAdapterError('Source export exceeds the 16 MiB byte bound')
    try:
        content = raw.decode('utf-8-sig')
    except UnicodeDecodeError as exc:
        raise ExportAdapterError('WhatsApp export must be UTF-8 text') from exc
    digest = _sha(raw)
    rows = []
    current = None
    for line_number, line in enumerate(io.StringIO(content), 1):
        line = line.rstrip('\r\n')
        match = pattern.fullmatch(line)
        if match:
            if current is not None:
                if len(rows) >= MAX_EVENTS:
                    raise ExportAdapterError('WhatsApp export exceeds the 1000 message bound')
                rows.append(current)
            try:
                stamp = datetime.strptime(match.group('stamp'), time_format)
            except ValueError as exc:
                raise ExportAdapterError(f'Invalid WhatsApp timestamp at source line {line_number}') from exc
            current = {'stamp': stamp, 'sender': match.group('sender'), 'body': match.group('body')}
        elif current is not None:
            current['body'] += '\n' + line
        else:
            raise ExportAdapterError(f'Unrecognized WhatsApp export header at source line {line_number}')
        if current is not None and len(current['body'].encode('utf-8')) > MAX_PAYLOAD_BYTES:
            raise ExportAdapterError(f'WhatsApp message at source line {line_number} exceeds the 64 KiB payload bound')
    if current is not None:
        if len(rows) >= MAX_EVENTS:
            raise ExportAdapterError('WhatsApp export exceeds the 1000 message bound')
        rows.append(current)
    events = []
    for ordinal, row in enumerate(rows, 1):
        event_time = _local_to_utc(row['stamp'], zone)
        body = row['body']
        row_digest = _sha((row['stamp'].isoformat() + '\0' + (row['sender'] or '') + '\0' + body).encode('utf-8'))
        snapshot_id = f'whatsapp:{digest}:row:{ordinal}'
        events.append(_event(namespace=namespace, object_id=snapshot_id, event_id=snapshot_id,
            revision='sha256:' + row_digest, order=ordinal, actor=row['sender'], thread=None,
            event_time=event_time, observed_at=observed, language=None, text=body,
            attachments=[], locator=f'whatsapp-export://sha256/{digest}/row/{ordinal}'))
    return _finish(events)


def _exact_id(value, label, *, allow_negative=False):
    if type(value) is int:
        text = str(value)
    elif isinstance(value, str):
        text = value
    else:
        raise ExportAdapterError(f'Telegram {label} must be an integer or decimal string')
    pattern = r'-?(0|[1-9][0-9]{0,127})' if allow_negative else r'(0|[1-9][0-9]{0,127})'
    if not re.fullmatch(pattern, text):
        raise ExportAdapterError(f'Telegram {label} must be a bounded decimal identifier')
    return text


def _epoch(value):
    if type(value) is int:
        text = str(value)
    elif isinstance(value, str):
        text = value
    else:
        raise ExportAdapterError('Telegram date_unixtime must be an exact decimal value')
    if not re.fullmatch(r'-?[0-9]{1,12}', text):
        raise ExportAdapterError('Telegram date_unixtime must be a bounded decimal value')
    try:
        return datetime.fromtimestamp(int(text), timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise ExportAdapterError('Telegram date_unixtime is outside supported range') from exc


def _telegram_time(message, timezone_name):
    date = message.get('date')
    epoch_value = message.get('date_unixtime')
    epoch_time = _epoch(epoch_value) if epoch_value is not None else None
    date_time = None
    if date is not None:
        if not isinstance(date, str) or len(date) > 64:
            raise ExportAdapterError('Telegram date must be a bounded ISO timestamp')
        try:
            parsed = datetime.fromisoformat(date.replace('Z', '+00:00'))
        except ValueError as exc:
            raise ExportAdapterError('Telegram date must be an ISO timestamp') from exc
        if parsed.tzinfo is not None and parsed.utcoffset() is not None:
            date_time = parsed.astimezone(timezone.utc)
        else:
            if not timezone_name:
                raise ExportAdapterError('Telegram local date requires an explicit IANA timezone')
            zone = _zone(timezone_name)
            if epoch_time is not None:
                if epoch_time.astimezone(zone).replace(tzinfo=None) != parsed:
                    raise ExportAdapterError('Telegram date and date_unixtime do not agree in the selected timezone')
                date_time = epoch_time
            else:
                choices = _local_candidates(parsed, zone)
                if not choices:
                    raise ExportAdapterError('Telegram local date falls in a nonexistent DST time')
                if len(choices) != 1:
                    raise ExportAdapterError('Telegram local date is ambiguous without a matching date_unixtime')
                date_time = choices[0]
    if epoch_time is not None and date_time is not None and epoch_time != date_time:
        raise ExportAdapterError('Telegram date and date_unixtime disagree')
    result = epoch_time or date_time
    if result is None:
        return None
    precision = 'microseconds' if result.microsecond else 'seconds'
    return result.isoformat(timespec=precision).replace('+00:00', 'Z')


def _telegram_text(value):
    if isinstance(value, str):
        text = value
    elif isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and set(item) >= {'type', 'text'} and isinstance(item['text'], str):
                parts.append(item['text'])
            else:
                raise ExportAdapterError('Telegram rich text contains an unsupported segment')
        text = ''.join(parts)
    else:
        raise ExportAdapterError('Telegram message text must be a string or ordered text segments')
    if len(text.encode('utf-8')) > MAX_PAYLOAD_BYTES:
        raise ExportAdapterError('Telegram message exceeds the 64 KiB payload bound')
    return text


def _safe_attachment(message, digest):
    file_value = message.get('file')
    if file_value is None:
        return []
    if not isinstance(file_value, str) or len(file_value) > 4096 or '\\' in file_value or any(ord(c) < 32 for c in file_value):
        raise ExportAdapterError('Telegram attachment locator is invalid')
    components = file_value.split('/')
    path = PurePosixPath(file_value)
    if (path.is_absolute() or not path.parts
            or any(part in ('', '.', '..') for part in components)):
        raise ExportAdapterError('Telegram attachment locator must be an export-relative path')
    media_type = message.get('media_type')
    if not isinstance(media_type, str) or not media_type.strip() or len(media_type) > 256:
        media_type = 'application/octet-stream'
    locator = 'telegram-export://sha256/' + digest + '/file/' + '/'.join(path.parts)
    return [{'id': 'file:' + file_value, 'locator': locator, 'mediaType': media_type}]


def _reject_float(value):
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, float):
            raise ExportAdapterError('Telegram JSON decimal numbers are unsupported; exact identifiers must not round')
        if isinstance(current, dict):
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)


def parse_telegram_json(raw, *, namespace, timezone_name=None, observed_at=None):
    """Parse one single-chat Telegram Desktop JSON export without extraction/network."""
    namespace = _namespace(namespace)
    observed = _observed(observed_at)
    digest = _sha(raw) if isinstance(raw, bytes) else ''
    document = _json(raw)
    _reject_float(document)
    if not isinstance(document, dict) or 'messages' not in document or 'chats' in document:
        raise ExportAdapterError('Only a single-chat Telegram Desktop JSON result is supported')
    chat_id = _exact_id(document.get('id'), 'chat id', allow_negative=True)
    chat_type = document.get('type')
    if not isinstance(chat_type, str) or not chat_type or len(chat_type) > 128:
        raise ExportAdapterError('Telegram export requires a chat type')
    rows = document['messages']
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_EVENTS:
        raise ExportAdapterError('Telegram export must contain 1 to 1000 messages')
    events, previous_order, seen = [], None, set()
    for index, message in enumerate(rows, 1):
        if not isinstance(message, dict) or message.get('type') != 'message':
            raise ExportAdapterError(f'Telegram export row {index} is not a supported message; no rows are skipped')
        native_id = _exact_id(message.get('id'), f'message id at row {index}')
        if int(native_id) <= 0 or native_id in seen:
            raise ExportAdapterError(f'Telegram message id at row {index} is non-positive or duplicated')
        seen.add(native_id)
        order = int(native_id)
        if previous_order is not None and order <= previous_order:
            raise ExportAdapterError('Telegram messages are not in strictly increasing native ID order')
        previous_order = order
        text = _telegram_text(message.get('text', ''))
        event_time = _telegram_time(message, timezone_name)
        sender = message.get('from_id', message.get('from'))
        if sender is not None and (not isinstance(sender, str) or len(sender) > 1024):
            raise ExportAdapterError(f'Telegram sender at row {index} is invalid')
        reply = message.get('reply_to_message_id')
        thread = None if reply is None else _exact_id(reply, f'reply id at row {index}')
        serialized = json.dumps(message, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
        revision = 'sha256:' + _sha(serialized)
        message_ref = f'telegram:{chat_id}:message:{native_id}'
        locator = f'telegram-export://sha256/{digest}/chat/{chat_id}/message/{native_id}'
        events.append(_event(namespace=namespace, object_id=message_ref, event_id=message_ref,
            revision=revision, order=native_id, actor=sender, thread=thread, event_time=event_time,
            observed_at=observed, language=None, text=text, attachments=_safe_attachment(message, digest),
            locator=locator))
    return _finish(events)


def parse_signal_bridge(raw, *, namespace, observed_at=None):
    """Parse an operator-produced bridge manifest; this is not a Signal export/API."""
    namespace = _namespace(namespace)
    observed = _observed(observed_at)
    digest = _sha(raw) if isinstance(raw, bytes) else ''
    document = _json(raw)
    if not isinstance(document, dict) or set(document) != {'format', 'messages'} or document['format'] != 'signal-operator-bridge/v1':
        raise ExportAdapterError('Expected a signal-operator-bridge/v1 operator-produced manifest')
    rows = document['messages']
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_EVENTS:
        raise ExportAdapterError('Signal bridge must contain 1 to 1000 explicit rows')
    allowed = {'messageId', 'order', 'revision', 'operation', 'actor', 'replyTo', 'eventTime', 'language', 'text', 'visibility'}
    events, previous_order = [], 0
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict) or set(row) - allowed or 'text' not in row:
            raise ExportAdapterError(f'Signal bridge row {index} has unsupported or missing fields')
        operation = row.get('operation', 'upsert')
        if operation not in ('upsert', 'edit', 'delete', 'access-change'):
            raise ExportAdapterError(f'Signal bridge row {index} has an unsupported operation')
        order = _exact_id(row.get('order', str(index)), f'bridge order at row {index}')
        if int(order) <= previous_order:
            raise ExportAdapterError('Signal bridge order must be strictly increasing')
        previous_order = int(order)
        message_id = row.get('messageId')
        if message_id is not None and (not isinstance(message_id, str) or not message_id.strip() or len(message_id) > 1024):
            raise ExportAdapterError(f'Signal bridge message ID at row {index} is invalid')
        actor = row.get('actor')
        if actor is not None and (not isinstance(actor, str) or len(actor) > 1024):
            raise ExportAdapterError(f'Signal bridge actor at row {index} is invalid')
        reply = row.get('replyTo')
        if reply is not None and (not isinstance(reply, str) or len(reply) > 1024):
            raise ExportAdapterError(f'Signal bridge reply ID at row {index} is invalid')
        event_time = row.get('eventTime')
        if event_time is not None:
            if not isinstance(event_time, str) or len(event_time) > 128:
                raise ExportAdapterError(f'Signal bridge event time at row {index} is invalid')
            try:
                parsed_time = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
            except ValueError as exc:
                raise ExportAdapterError(f'Signal bridge event time at row {index} is invalid') from exc
            if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
                raise ExportAdapterError('Signal bridge timestamps must include a timezone')
        text = row['text']
        if operation in ('upsert', 'edit'):
            if not isinstance(text, str):
                raise ExportAdapterError(f'Signal bridge text at row {index} must be a string')
        elif text is not None:
            raise ExportAdapterError(f'Signal bridge control event at row {index} must not carry text')
        row_bytes = json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
        revision = row.get('revision') or 'sha256:' + _sha(row_bytes)
        if not isinstance(revision, str) or not revision.strip() or len(revision) > 256:
            raise ExportAdapterError(f'Signal bridge revision at row {index} is invalid')
        object_id = ('signal-bridge:native:' + message_id if message_id is not None
                     else f'signal-bridge:sha256:{digest}:row:{index}')
        event_id = ('signal-bridge:event:' + message_id if message_id is not None
                    else f'signal-bridge:event:sha256:{digest}:row:{index}')
        events.append(_event(namespace=namespace, object_id=object_id, event_id=event_id,
            revision=revision, order=order, actor=actor, thread=reply, event_time=event_time,
            observed_at=observed, language=row.get('language'), text=text, attachments=[],
            locator=f'signal-operator-bridge://sha256/{digest}/row/{index}',
            visibility=row.get('visibility'), operation=operation))
    return _finish(events)
