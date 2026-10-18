"""Small local-client SDK for the registered Mimwell connector export host.

Client configuration is operator supplied. Event fields never choose the host,
brain root, authority, namespace, or export path.
"""
import base64
import hashlib
import json
import math
import os
import re
import signal
import subprocess
import threading
import time

MAX_RECEIPT_BYTES = 1_048_576
HOST_TIMEOUT_SECONDS = 10

MAX_LINE = 1_048_576
MAX_EVENTS = 1000
_FIELDS = {'format', 'namespace', 'objectId', 'eventId', 'revision', 'order', 'operation',
           'actor', 'thread', 'eventTime', 'observedAt', 'language', 'text', 'attachments',
           'locator', 'visibility', 'payload'}


class ClientError(ValueError):
    pass


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ClientError('Duplicate JSON field')
        result[key] = value
    return result


def validate_jsonl(raw):
    """Validate without re-encoding; each event retains its exact source bytes."""
    if not isinstance(raw, bytes) or len(raw) > 16 * 1024 * 1024:
        raise ClientError('Export exceeds the 16 MiB client bound')
    lines = raw.splitlines(keepends=True)
    if len(lines) > MAX_EVENTS:
        raise ClientError('Export exceeds the 1000 event bound')
    events = []
    for line in lines:
        if len(line) > MAX_LINE or not line.endswith(b'\n') or line.endswith(b'\r\n'):
            raise ClientError('Events must be bounded LF-terminated JSONL lines')
        try:
            event = json.loads(line[:-1].decode('utf-8'), object_pairs_hook=_object,
                               parse_constant=lambda _value: (_ for _ in ()).throw(ClientError('Invalid JSON number')))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ClientError('Invalid UTF-8 JSONL event') from exc
        if not isinstance(event, dict) or set(event) != _FIELDS:
            raise ClientError('Event fields differ from connector-event/v1')
        if event['format'] != 'connector-event/v1' or event['operation'] not in ('upsert', 'edit', 'delete', 'access-change'):
            raise ClientError('Unsupported connector event')
        for key, maximum in (('namespace', 256), ('objectId', 1024), ('eventId', 1024), ('revision', 256), ('locator', 4096)):
            if not isinstance(event[key], str) or not event[key].strip() or len(event[key]) > maximum:
                raise ClientError('Invalid event identity or locator')
        if not isinstance(event['order'], str) or not re.fullmatch(r'(0|[1-9][0-9]{0,127})', event['order']):
            raise ClientError('Order must be a bounded decimal string')
        if not isinstance(event['attachments'], list) or len(event['attachments']) > 64:
            raise ClientError('Invalid attachment list')
        for attachment in event['attachments']:
            if (not isinstance(attachment, dict) or set(attachment) != {'id', 'locator', 'mediaType'}
                    or not isinstance(attachment['id'], str) or not attachment['id'].strip()
                    or len(attachment['id']) > 1024
                    or not isinstance(attachment['locator'], str) or len(attachment['locator']) > 4096
                    or not isinstance(attachment['mediaType'], str) or not attachment['mediaType'].strip()
                    or len(attachment['mediaType']) > 256):
                raise ClientError('Invalid attachment metadata')
        for key, maximum in (('actor', 1024), ('thread', 1024), ('eventTime', 128),
                             ('observedAt', 128), ('language', 64), ('visibility', 256)):
            if event[key] is not None and (not isinstance(event[key], str) or len(event[key]) > maximum):
                raise ClientError('Invalid optional event metadata')
        if event['text'] is not None and (not isinstance(event['text'], str) or len(event['text']) > 65536):
            raise ClientError('Invalid event text')
        payload = event['payload']
        if not isinstance(payload, dict) or set(payload) != {'encoding', 'mediaType', 'byteLength', 'sha256', 'data'}:
            raise ClientError('Invalid payload envelope')
        if (payload['encoding'] != 'base64' or not isinstance(payload['mediaType'], str)
                or not payload['mediaType'].strip() or len(payload['mediaType']) > 256
                or not isinstance(payload['data'], str) or len(payload['data']) > 87384
                or type(payload['byteLength']) is not int or not 0 <= payload['byteLength'] <= 65536):
            raise ClientError('Invalid payload encoding or length')
        try:
            content = base64.b64decode(payload['data'], validate=True)
            text = content.decode('utf-8')
        except (ValueError, TypeError, UnicodeDecodeError) as exc:
            raise ClientError('Payload is not canonical base64 UTF-8') from exc
        if (base64.b64encode(content).decode('ascii') != payload['data']
                or len(content) != payload['byteLength']
                or hashlib.sha256(content).hexdigest() != payload['sha256']):
            raise ClientError('Payload bytes do not match their declared digest')
        if event['operation'] in ('upsert', 'edit') and event['text'] != text:
            raise ClientError('Text differs from exact payload bytes')
        if event['operation'] in ('delete', 'access-change') and (content or event['text'] is not None or event['attachments']):
            raise ClientError('Control events cannot carry replacement content')
        events.append({'event': event, 'eventBytes': line, 'payloadBytes': content})
    if not events and raw:
        raise ClientError('Invalid JSONL export')
    return events


def plan(raw):
    events = validate_jsonl(raw)
    counts = {operation: 0 for operation in ('upsert', 'edit', 'delete', 'access-change')}
    for row in events:
        counts[row['event']['operation']] += 1
    return {'format': 'connector-client-plan/v1', 'events': len(events), 'operations': counts,
            'exportSha256': hashlib.sha256(raw).hexdigest(), 'authority': 'host-review-required'}


class HostClient:
    def __init__(self, *, python, host_script, root, host_config, authority, namespace, export,
                 timeout=HOST_TIMEOUT_SECONDS, max_receipt_bytes=MAX_RECEIPT_BYTES):
        self.python, self.host_script, self.root = python, host_script, root
        self.host_config, self.authority = host_config, authority
        self.namespace, self.export = namespace, export
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0 or timeout > 300:
            raise ClientError('Host timeout must be between 0 and 300 seconds')
        if isinstance(max_receipt_bytes, bool) or not isinstance(max_receipt_bytes, int) or not 1 <= max_receipt_bytes <= MAX_RECEIPT_BYTES:
            raise ClientError('Receipt bound must be between 1 and 1048576 bytes')
        self.timeout, self.max_receipt_bytes = timeout, max_receipt_bytes

    def _call(self, *operation):
        command = [self.python, self.host_script, '--root', self.root, '--host-config', self.host_config,
                   '--authority', self.authority, *operation]
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=(os.name == 'posix'))
        except OSError as exc:
            raise ClientError('Connector host could not start') from exc
        streams = {'stdout': bytearray(), 'stderr': bytearray(), 'overflow': False}
        streams['read_error'] = False

        def drain(name, stream):
            while True:
                try:
                    block = stream.read(65536)
                except OSError:
                    streams['read_error'] = True
                    return
                if not block:
                    return
                output = streams[name]
                room = self.max_receipt_bytes + 1 - len(output)
                if room > 0:
                    output.extend(block[:room])
                if len(output) > self.max_receipt_bytes or len(block) > room:
                    streams['overflow'] = True

        readers = [threading.Thread(target=drain, args=('stdout', process.stdout), daemon=True),
                   threading.Thread(target=drain, args=('stderr', process.stderr), daemon=True)]
        for reader in readers:
            reader.start()
        deadline = time.monotonic() + self.timeout
        while process.poll() is None or any(reader.is_alive() for reader in readers):
            if time.monotonic() >= deadline:
                if os.name == 'posix':
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    process.kill()
                process.wait()
                for stream in (process.stdout, process.stderr):
                    stream.close()
                for reader in readers:
                    reader.join(timeout=1)
                raise ClientError('Connector host timed out')
            time.sleep(0.01)
        process.wait()
        for reader in readers:
            reader.join()
        process.stdout.close()
        process.stderr.close()
        if streams['overflow']:
            raise ClientError(f'Connector host output exceeds the {self.max_receipt_bytes}-byte receipt bound')
        if streams['read_error']:
            raise ClientError('Connector host output could not be read completely')
        if process.returncode:
            raise ClientError('Connector host failed')
        return bytes(streams['stdout'])  # Native host receipt bytes are returned unchanged.

    def submit(self):
        return self._call('--namespace', self.namespace, '--export', self.export)

    def submit_stdin(self):
        """Submit process stdin; the host still requires an exact registered export.

        The child inherits descriptor zero. The host owns bounded admission,
        current authorization, digest matching and checkpoint/replay semantics.
        """
        return self._call('--namespace', self.namespace, '--export', self.export, '--stdin')

    def resume(self):
        return self.submit()  # Exact pinned export; host checkpoint and ledger own replay.

    def status(self):
        return self._call('--dead-letters')

    def replay(self, line):
        if type(line) is not int or line < 1:
            raise ClientError('Replay line must be a positive integer')
        return self._call('--namespace', self.namespace, '--export', self.export, '--replay-line', str(line))
