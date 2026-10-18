"""Bounded, offline adapters for documented collaboration-platform exports.

These adapters only normalize operator-selected local archives/responses into
connector-event/v1 JSONL. They do not contact platforms, download attachments,
or grant the imported actor any host authority.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import io
import json
import re
import zipfile
from pathlib import PurePosixPath
from urllib.parse import quote

from connector_events import MAX_LINE_BYTES, validate

MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 2000
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_EVENTS = 1000
MAX_JSONL_BYTES = 16 * 1024 * 1024
MAX_JSON_DEPTH = 64


def _unavailable(**reasons):
    return [{"capability": capability, "status": "unavailable", "reason": reason}
            for capability, reason in reasons.items()]

CAPABILITIES = {
    "format": "platform-export-capabilities/v1",
    "transport": "operator-selected-local-export",
    "liveApi": False,
    "attachmentFetch": False,
    "automaticReviewOrDelivery": False,
    "adapters": {
        "slack": {
            "input": "official-slack-json-export-zip",
            "supported": ["exportImport", "backfill", "explicitThreadReference",
                          "editedMessageMetadata", "retainedEditAndDeleteEvents",
                          "explicitMembershipEvents"],
            "unavailable": _unavailable(
                completeThreadTree="export-may-flatten-thread-replies",
                completeEditDeleteHistory="scope-and-retention-dependent",
                attachmentBytes="export-contains-links-only",
                membershipSnapshot="event-subset-is-not-a-membership-snapshot"),
            "limits": ["ordinary edited rows are current snapshots; only subtype rows with explicit previous content are change events",
                       "edit/delete and private-message availability depend on export scope and retention",
                       "thread relation is emitted only when an explicit source field is present",
                       "message exports may flatten thread replies into conversation order"],
        },
        "teams": {
            "input": "microsoft-graph-teams-export-json-response",
            "supported": ["exportImport", "backfill", "replyToId", "messageRevisionMetadata",
                          "explicitDeletedDateTime", "attachmentMetadata"],
            "unavailable": _unavailable(
                revisionHistory="selected-response-is-a-snapshot",
                attachmentBytes="metadata-only-no-fetch",
                membershipSnapshot="not-derived-from-exported-messages"),
            "limits": ["message collection and deletion visibility depend on tenant authorization and retention",
                       "HTML message bodies are retained as untrusted text, never rendered"],
        },
        "zoom": {
            "input": "zoom-chat-api-list-users-chat-messages-json-response",
            "supported": ["exportImport", "backfill", "replyReferenceWhenPresent",
                          "explicitEditedOrDeletedStatus", "fileMetadata"],
            "unavailable": _unavailable(
                completeThreadTree="reply-reference-does-not-prove-complete-thread",
                completeEditDeleteHistory="selected-response-does-not-provide-a-complete-change-log",
                attachmentBytes="metadata-only-no-fetch",
                membershipSnapshot="not-present-in-selected-message-snapshot"),
            "limits": ["only documented Team Chat message/report response shapes are accepted",
                       "no capability is inferred from missing API fields"],
        },
        "discord": {
            "input": "current-official-discord-data-package-json",
            "supported": ["backfillAuthoredMessages", "inertAttachmentLinks"],
            "unavailable": _unavailable(
                otherAuthorsMessages="package-contains-requesting-account-authored-messages",
                threadTree="thread-relationship-is-not-included",
                edits="no-edit-history-in-package",
                deletes="deleted-messages-are-omitted",
                completeMembership="package-membership-is-current-or-recent-only",
                attachmentBytes="package-provides-inert-links"),
            "limits": ["package contains messages sent by requesting account",
                       "deleted messages and departed-server membership can be absent",
                       "CSV and third-party exporter formats are not accepted"],
        },
    },
}


class ExportAdapterError(ValueError):
    """The selected export is malformed, ambiguous, or outside safe bounds."""


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ExportAdapterError("Duplicate JSON property")
        result[key] = value
    return result


def _depth(value, depth=0):
    if depth > MAX_JSON_DEPTH:
        raise ExportAdapterError("JSON nesting exceeds the adapter bound")
    if isinstance(value, dict):
        for child in value.values():
            _depth(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _depth(child, depth + 1)


def _json(raw, label):
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(
                               ExportAdapterError("Non-finite JSON value")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExportAdapterError(f"Invalid UTF-8 JSON in {label}") from exc
    _depth(value)
    return value


def read_archive(raw):
    """Read a ZIP without extracting paths and with compressed/expanded bounds."""
    if not isinstance(raw, bytes) or len(raw) > MAX_ARCHIVE_BYTES:
        raise ExportAdapterError("Archive exceeds the compressed-byte bound")
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
        infos = archive.infolist()
    except (zipfile.BadZipFile, OSError) as exc:
        raise ExportAdapterError("Invalid ZIP archive") from exc
    if len(infos) > MAX_ARCHIVE_ENTRIES:
        raise ExportAdapterError("Archive entry count exceeds the bound")
    names = set()
    expanded = 0
    members = {}
    for info in infos:
        name = info.filename
        path = PurePosixPath(name)
        raw_parts = name.split("/")
        if info.is_dir() and raw_parts[-1] == "":
            raw_parts = raw_parts[:-1]
        mode = info.external_attr >> 16
        if (not name or len(name) > 1024 or any(ord(char) < 0x20 for char in name)
                or "\\" in name or name.startswith("/") or re.match(r"^[A-Za-z]:", name)
                or any(part in ("", ".", "..") for part in raw_parts)
                or any(part in ("", ".", "..") for part in path.parts)
                or name in names or info.flag_bits & 1
                or (mode and (mode & 0o170000) == 0o120000)):
            raise ExportAdapterError("Archive has duplicate, unsafe, encrypted, or linked entries")
        names.add(name)
        if info.is_dir():
            continue
        if name.lower().endswith((".zip", ".7z", ".tar", ".gz")):
            raise ExportAdapterError("Nested archives are not supported")
        if info.file_size > MAX_MEMBER_BYTES:
            raise ExportAdapterError("Archive member exceeds the per-file bound")
        if info.file_size and (info.compress_size == 0
                               or info.file_size > max(1, info.compress_size) * 200):
            raise ExportAdapterError("Archive member compression ratio exceeds the bound")
        expanded += info.file_size
        if expanded > MAX_EXPANDED_BYTES:
            raise ExportAdapterError("Archive expanded size exceeds the total bound")
        try:
            with archive.open(info, "r") as stream:
                data = stream.read(MAX_MEMBER_BYTES + 1)
        except (zipfile.BadZipFile, RuntimeError, OSError, NotImplementedError) as exc:
            raise ExportAdapterError("Archive member failed integrity validation") from exc
        if len(data) != info.file_size:
            raise ExportAdapterError("Archive member size differs from its directory entry")
        members[name] = data
    return members


def _timestamp_order(value):
    """Convert a source timestamp to exact decimal microseconds without floats."""
    if not isinstance(value, str) or not value:
        raise ExportAdapterError("A source timestamp is required for ordering")
    if re.fullmatch(r"[0-9]{1,16}(?:\.[0-9]{1,6})?", value):
        whole, dot, fraction = value.partition(".")
        return str(int(whole) * 1_000_000 + int((fraction + "000000")[:6] if dot else "0"))
    fractional = re.search(r"[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}\.([0-9]+)", value)
    if fractional and len(fractional.group(1)) > 6:
        raise ExportAdapterError("Timestamp precision exceeds exact microsecond ordering")
    try:
        stamp = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ExportAdapterError("Unsupported source timestamp") from exc
    if stamp.tzinfo is None:
        raise ExportAdapterError("Naive timestamps require an explicit source timezone")
    epoch = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    delta = stamp.astimezone(dt.timezone.utc) - epoch
    return str((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds)


def _milliseconds_iso(value):
    if type(value) is not int or value < 0:
        raise ExportAdapterError("Timestamp milliseconds must be an exact nonnegative integer")
    try:
        stamp = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(milliseconds=value)
    except OverflowError as exc:
        raise ExportAdapterError("Timestamp milliseconds are outside the supported range") from exc
    return stamp.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _json_pointer(value):
    return str(value).replace("~", "~0").replace("/", "~1")


def _event(*, namespace, object_id, revision, order, actor=None, thread=None,
           event_time=None, language=None, text=None, locator, visibility=None,
           attachments=(), operation="upsert", media_type="text/plain; charset=utf-8"):
    if operation in ("delete", "access-change"):
        text = None
        raw = b""
        attachments = ()
    else:
        if not isinstance(text, str):
            raise ExportAdapterError("Message body must be text")
        raw = text.encode("utf-8")
        if len(raw) > 65536:
            raise ExportAdapterError("Message text exceeds connector-event/v1 bound")
    if not object_id or not revision:
        raise ExportAdapterError("Native message ID and source revision are required")
    payload = {"encoding": "base64", "mediaType": media_type, "byteLength": len(raw),
               "sha256": hashlib.sha256(raw).hexdigest(),
               "data": base64.b64encode(raw).decode("ascii")}
    event_id = "message:" + object_id
    value = {"format": "connector-event/v1", "namespace": namespace,
             "objectId": object_id, "eventId": event_id, "revision": revision,
             "order": order, "operation": operation, "actor": actor, "thread": thread,
             "eventTime": event_time, "observedAt": None, "language": language,
             "text": text, "attachments": list(attachments), "locator": locator,
             "visibility": visibility, "payload": payload}
    validate(value)
    return value


def _attachment_rows(rows, id_key, url_key, type_key=None):
    result = []
    if rows is None:
        return result
    if not isinstance(rows, list) or len(rows) > 64:
        raise ExportAdapterError("Attachment metadata exceeds connector-event/v1 bound")
    for row in rows:
        if not isinstance(row, dict):
            raise ExportAdapterError("Invalid attachment metadata")
        attachment_id = row.get(id_key)
        locator = row.get(url_key) or row.get("url") or ""
        media = row.get(type_key) if type_key else None
        media = media or row.get("mime_type") or row.get("contentType") or "application/octet-stream"
        if not isinstance(attachment_id, str) or not attachment_id or not isinstance(locator, str):
            raise ExportAdapterError("Attachment ID and locator must be strings")
        result.append({"id": attachment_id, "locator": locator, "mediaType": media})
    return result


def _locator(archive_sha, member, pointer):
    return f"zip:sha256:{archive_sha}!{quote(member, safe='/._-')}#{pointer}"


def _message_list(value, label):
    if not isinstance(value, list) or len(value) > MAX_EVENTS:
        raise ExportAdapterError(f"Expected a bounded message array in {label}")
    if any(not isinstance(row, dict) for row in value):
        raise ExportAdapterError(f"Invalid message row in {label}")
    return value


def _slack(raw, namespace):
    members = read_archive(raw)
    archive_sha = hashlib.sha256(raw).hexdigest()
    conversations = {}
    for filename, data in members.items():
        if PurePosixPath(filename).name not in ("channels.json", "groups.json", "dms.json", "mpims.json"):
            continue
        rows = _json(data, filename)
        if not isinstance(rows, list):
            raise ExportAdapterError(f"Expected conversation index array in {filename}")
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                raise ExportAdapterError(f"Invalid conversation index row in {filename}")
            conversations.setdefault(row.get("name", ""), set()).add(row["id"])
            conversations.setdefault(row["id"], set()).add(row["id"])
    events = []
    for filename, data in members.items():
        path = PurePosixPath(filename)
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\.json", path.name):
            continue
        if len(path.parts) == 2:
            folder = path.parts[0]
        elif len(path.parts) == 3 and path.parts[0] == "channels":
            # Slack documents this nested form for single-user JSON exports.
            folder = path.parts[1]
        else:
            raise ExportAdapterError("Slack dated transcript is outside a documented conversation folder")
        ids = conversations.get(folder, set())
        if len(ids) != 1:
            raise ExportAdapterError("Slack conversation folder cannot be resolved to one native ID")
        channel_id = next(iter(ids))
        value = _json(data, filename)
        if not isinstance(value, list):
            raise ExportAdapterError(f"Slack dated transcript must be a JSON message array: {filename}")
        rows = _message_list(value, filename)
        for index, row in enumerate(rows):
            source = row
            operation = "upsert"
            object_ts = row.get("original_ts") or row.get("ts")
            order_source = row.get("ts")
            revision = object_ts
            actor = row.get("user")
            if row.get("subtype") == "message_changed":
                nested = row.get("message")
                if isinstance(nested, dict):
                    source = nested
                    object_ts = nested.get("ts")
                    edit = nested.get("edited") or {}
                    order_source = edit.get("ts") or row.get("event_ts") or row.get("ts")
                    actor = edit.get("user") or row.get("editor_id") or row.get("user")
                    has_previous = isinstance(nested.get("previous"), dict)
                else:
                    source = row
                    object_ts = row.get("original_ts")
                    order_source = row.get("ts") or row.get("event_ts")
                    actor = row.get("editor_id") or row.get("user")
                    has_previous = isinstance(row.get("previous"), dict)
                if not has_previous:
                    # A changed snapshot without old content is not a retained edit event.
                    operation = "upsert"
                    order_source = (source.get("edited") or {}).get("ts") or source.get("ts")
                    revision = order_source or object_ts
                else:
                    operation = "edit"
                    revision = order_source
            elif row.get("subtype") == "message_deleted":
                source = row.get("previous_message") or row.get("previous")
                object_ts = row.get("original_ts") or (source.get("ts") if isinstance(source, dict) else None)
                order_source = row.get("event_ts") or row.get("ts")
                actor = row.get("editor_id") or row.get("user")
                operation = "delete"
                revision = order_source
            elif isinstance(row.get("edited"), dict):
                # Ordinary export rows expose an edited snapshot, not prior revision content.
                order_source = row["edited"].get("ts") or row.get("ts")
                revision = order_source or object_ts
                actor = row["edited"].get("user") or actor
            elif row.get("subtype") in ("channel_join", "channel_leave", "group_join", "group_leave"):
                operation = "access-change"
                member = row.get("user")
                order_source = row.get("ts") or row.get("event_ts")
                if not isinstance(member, str) or not isinstance(order_source, str):
                    raise ExportAdapterError("Slack membership event lacks member or timestamp")
                order = _timestamp_order(order_source)
                events.append(_event(namespace=namespace,
                    object_id=f"{channel_id}/member/{member}", revision=order, order=order,
                    actor=member, event_time=order_source, operation=operation,
                    locator=_locator(archive_sha, filename, f"/{index}")))
                if len(events) > MAX_EVENTS:
                    raise ExportAdapterError("Export event count exceeds the bound")
                continue
            if not isinstance(source, dict):
                raise ExportAdapterError("Slack control or revision row lacks its source message")
            if not isinstance(object_ts, str):
                raise ExportAdapterError("Slack message lacks native timestamp ID")
            order_source = order_source or object_ts
            order = _timestamp_order(order_source)
            revision = revision or object_ts
            text = source.get("text") if operation in ("upsert", "edit") else None
            files = source.get("files", [])
            attachments = _attachment_rows(files, "id", "url_private")
            event_time = order_source if operation in ("edit", "delete") else object_ts
            events.append(_event(namespace=namespace, object_id=f"{channel_id}/{object_ts}",
                revision=revision, order=order, actor=actor or source.get("user"),
                thread=source.get("thread_ts"), event_time=event_time, text=text,
                attachments=attachments, operation=operation,
                locator=_locator(archive_sha, filename, f"/{index}")))
            if len(events) > MAX_EVENTS:
                raise ExportAdapterError("Export event count exceeds the bound")
    return events


def _teams(raw, namespace):
    value = _json(raw, "Teams Graph export response")
    rows = value if isinstance(value, list) else value.get("value") if isinstance(value, dict) else None
    messages = _message_list(rows, "Teams Graph export response")
    events = []
    for index, row in enumerate(messages):
        message_id = row.get("id")
        channel_identity = row.get("channelIdentity")
        if channel_identity is not None and not isinstance(channel_identity, dict):
            raise ExportAdapterError("Invalid Teams channel identity")
        container = row.get("chatId")
        if container is None and channel_identity:
            team_id = channel_identity.get("teamId")
            channel_id = channel_identity.get("channelId")
            if isinstance(team_id, str) and isinstance(channel_id, str):
                container = f"{team_id}/{channel_id}"
            else:
                container = channel_id
        if not isinstance(message_id, str) or not isinstance(container, str):
            raise ExportAdapterError("Teams message requires native message and chat/channel IDs")
        created = row.get("createdDateTime")
        modified = row.get("lastModifiedDateTime") or created
        if not isinstance(modified, str):
            raise ExportAdapterError("Teams message requires created or modified timestamp")
        sender = row.get("from") or {}
        user = sender.get("user") if isinstance(sender, dict) else None
        actor = user.get("id") if isinstance(user, dict) else None
        deleted = row.get("deletedDateTime")
        operation = "delete" if isinstance(deleted, str) else "upsert"
        body = row.get("body") or {}
        if not isinstance(body, dict) or (operation == "upsert" and not isinstance(body.get("content"), str)):
            raise ExportAdapterError("Teams message body content must be a string")
        body_type = body.get("contentType")
        media_type = "text/html; charset=utf-8" if body_type == "html" else "text/plain; charset=utf-8"
        attachments = _attachment_rows(row.get("attachments", []), "id", "contentUrl", "contentType")
        if operation == "delete":
            modified = deleted
        events.append(_event(namespace=namespace, object_id=f"{container}/{message_id}",
            revision=str(row.get("etag") or modified), order=_timestamp_order(modified),
            actor=actor, thread=row.get("replyToId"), event_time=created,
            language=row.get("locale"), text=body.get("content") if operation == "upsert" else None,
            attachments=attachments if operation == "upsert" else (), operation=operation,
            media_type=media_type,
            locator=(f"json:sha256:{hashlib.sha256(raw).hexdigest()}#/value/{index}"
                     if isinstance(value, dict) else
                     f"json:sha256:{hashlib.sha256(raw).hexdigest()}#/{index}")))
    return events


def _zoom(raw, namespace):
    value = _json(raw, "Zoom Chat API response")
    rows = value.get("messages") if isinstance(value, dict) else None
    messages = _message_list(rows, "Zoom Chat response")
    events = []
    archive_sha = hashlib.sha256(raw).hexdigest()
    conversation = value.get("to_channel") or value.get("to_contact")
    if not isinstance(conversation, str) or not conversation:
        raise ExportAdapterError("Zoom response requires its native to_channel or to_contact ID")
    for index, row in enumerate(messages):
        message_id = row.get("id")
        date_time = row.get("date_time")
        text = row.get("message")
        if not isinstance(message_id, str) or not isinstance(text, str):
            raise ExportAdapterError("Zoom message requires its native ID and message text")
        if not isinstance(date_time, str):
            raise ExportAdapterError("Zoom message requires date_time")
        sender = row.get("sender")
        attachments = _attachment_rows(row.get("files", []), "file_id", "download_url")
        timestamp = row.get("timestamp")
        if timestamp is not None:
            if type(timestamp) is not int or timestamp < 0:
                raise ExportAdapterError("Zoom timestamp must be an exact nonnegative integer")
            order = str(timestamp * 1000)
        else:
            order = _timestamp_order(date_time)
        action_time = row.get("action_timestamp")
        event_time = date_time
        if action_time is not None:
            if type(action_time) is not int or action_time < 0:
                raise ExportAdapterError("Zoom action_timestamp must be an exact nonnegative integer")
            order = str(action_time * 1000)
            event_time = _milliseconds_iso(action_time)
        status = row.get("status", "Normal")
        if status not in ("Normal", "Edited", "Deleted"):
            raise ExportAdapterError("Unsupported Zoom message status")
        operation = {"Normal": "upsert", "Edited": "edit", "Deleted": "delete"}[status]
        revision = str(row.get("revision") or f"{status}:{order}")
        events.append(_event(namespace=namespace, object_id=f"{conversation}/{message_id}",
            revision=revision, order=order, actor=sender,
            thread=row.get("reply_main_message_id"), event_time=event_time,
            text=text if operation != "delete" else None,
            attachments=attachments if operation != "delete" else (), operation=operation,
            locator=f"json:sha256:{archive_sha}#/messages/{index}"))
    return events


def _discord(raw, namespace):
    members = read_archive(raw)
    archive_sha = hashlib.sha256(raw).hexdigest()
    events = []
    channels = set()
    transcripts = set()
    for filename, data in members.items():
        path = PurePosixPath(filename)
        if (len(path.parts) < 3 or path.parts[0].lower() != "messages"
                or not path.parts[1].isdecimal() or path.suffix.lower() != ".json"):
            continue
        channel_id = path.parts[1]
        if len(path.parts) != 3 or path.name not in ("channel.json", "messages.json"):
            raise ExportAdapterError("Discord package has an unsupported channel folder shape")
        value = _json(data, filename)
        if path.name == "channel.json":
            if not isinstance(value, dict) or value.get("channel_id") != channel_id:
                raise ExportAdapterError("Discord channel.json must match its channel ID folder")
            channels.add(channel_id)
            continue
        if path.name != "messages.json":
            continue
        if not isinstance(value, list):
            raise ExportAdapterError("Discord messages.json must be a JSON message array")
        rows = _message_list(value, filename)
        transcripts.add(channel_id)
        if any(not all(key in row for key in ("ID", "Timestamp", "Contents")) for row in rows):
            raise ExportAdapterError("Discord messages.json row lacks ID, Timestamp, or Contents")
        for index, row in enumerate(rows):
            message_id = row.get("ID")
            timestamp = row.get("Timestamp")
            text = row.get("Contents")
            if not isinstance(message_id, str) or not isinstance(text, str):
                raise ExportAdapterError("Discord package message requires ID and Contents")
            if not isinstance(timestamp, str):
                raise ExportAdapterError("Discord package message requires Timestamp")
            attachments = []
            for item in row.get("Attachments", []):
                if not isinstance(item, str):
                    raise ExportAdapterError("Discord attachments must be URL strings")
                attachments.append({"id": item, "locator": item,
                                    "mediaType": "application/octet-stream"})
            events.append(_event(namespace=namespace, object_id=f"{channel_id}/{message_id}",
                revision=message_id, order=_timestamp_order(timestamp), actor=None, thread=None,
                event_time=timestamp, text=text, attachments=attachments,
                locator=_locator(archive_sha, filename, f"/{index}")))
            if len(events) > MAX_EVENTS:
                raise ExportAdapterError("Export event count exceeds the bound")
    if transcripts - channels:
        raise ExportAdapterError("Discord message transcript is missing its matching channel.json")
    if not events:
        raise ExportAdapterError("Discord JSON package contains no supported message transcript")
    if len(events) > MAX_EVENTS:
        raise ExportAdapterError("Export event count exceeds the bound")
    return events


ADAPTERS = {
    "slack": _slack,
    "teams": _teams,
    "zoom": _zoom,
    "discord": _discord,
}


def normalize(platform, raw, namespace):
    """Return bounded connector-event/v1 rows for one explicit platform export."""
    if platform not in ADAPTERS:
        raise ExportAdapterError("Unsupported export platform")
    if not isinstance(raw, bytes) or len(raw) > MAX_ARCHIVE_BYTES:
        raise ExportAdapterError("Selected export exceeds the compressed/source-byte bound")
    if (not isinstance(namespace, str) or not re.fullmatch(rf"export:{platform}/\S+", namespace)
            or len(namespace) > 256 or any(ord(char) < 0x20 for char in namespace)):
        raise ExportAdapterError("A platform-scoped export namespace is required")
    try:
        events = ADAPTERS[platform](raw, namespace)
    except ExportAdapterError:
        raise
    except (TypeError, KeyError, ValueError, OverflowError) as exc:
        raise ExportAdapterError("Selected platform export has an unsupported or malformed shape") from exc
    lines = []
    total = 0
    for event in events:
        line = (json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(line) > MAX_LINE_BYTES:
            raise ExportAdapterError("Normalized event exceeds connector-event/v1 line bound")
        total += len(line)
        if total > MAX_JSONL_BYTES:
            raise ExportAdapterError("Normalized JSONL exceeds the native host snapshot bound")
        lines.append(line)
    return lines
