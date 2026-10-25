"""Bounded private bindings for compiled and potential MCP read artifacts.

This is host-attested byte evidence for selected files. It is not a Git object
proof, a transactional source-tree snapshot, or evidence for processed text.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from urllib.parse import unquote

from source_receipt import _decode_json

FORMAT = "mimwell-source-artifacts/v1"
MANIFEST_LIMIT = 1024 * 1024
MAX_PATHS = 4096
MAX_PATH_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_PACK_SCHEMA_BYTES = 64 * 1024 * 1024
MAX_SCAN_ENTRIES = 100_000
MAX_PENDING_DIRECTORIES = 512
MAX_DOC_ROOTS = 256
MAX_DOC_ROOT_BYTES = 64 * 1024
MAX_RECEIPT_UID = 0

_EXTENSION = re.compile(r"\.(?:md|json|txt|py|js|toml|html|css)\Z", re.IGNORECASE | re.ASCII)
_ESCAPE = re.compile(r"%[0-9a-f]{2}", re.IGNORECASE | re.ASCII)
_BAD_ESCAPE = re.compile(r"%(?![0-9a-f]{2})", re.IGNORECASE | re.ASCII)
_SCHEME = re.compile(r"[a-z][a-z0-9+.-]*:", re.IGNORECASE | re.ASCII)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_FIXED_LIMITS = {
    "app/brain.json": MAX_PACK_SCHEMA_BYTES,
    "app/knowledge-pack.json": MAX_PACK_SCHEMA_BYTES,
    "brain-schema.json": MAX_PACK_SCHEMA_BYTES,
}
_FIXED = frozenset(_FIXED_LIMITS)


def _safe_doc_path(path: str, roots: tuple[str, ...]) -> bool:
    if not isinstance(path, str) or not path or len(path) > 512 or path.strip() != path:
        return False
    if _BAD_ESCAPE.search(path):
        return False
    try:
        decoded = unquote(path, errors="strict") if _ESCAPE.search(path) else path
    except (UnicodeDecodeError, ValueError):
        return False
    if decoded != path:
        # Runtime canonicalizes escaped request paths before opening. Store only
        # the canonical filesystem spelling so aliases cannot acquire a second
        # manifest identity.
        return False
    if ("\\" in path or _CONTROL.search(path) or _SCHEME.match(path)
            or path.startswith(("~", "//"))):
        return False
    parts = path.split("/")
    if not parts or any(not part or part == "." or part == ".." or part.startswith(".") for part in parts):
        return False
    if not _EXTENSION.search(path):
        return False
    return not roots or any(path == root or path.startswith(root + "/") for root in roots)


def _roots_from_config(config_raw: bytes | None) -> tuple[tuple[str, ...], bool]:
    if config_raw is None:
        return (), False
    try:
        config = _decode_json(config_raw)
    except (ValueError, TypeError):
        return (), False
    if not isinstance(config, dict):
        return (), False
    assistant = config.get("assistant")
    roots = assistant.get("docRoots") if isinstance(assistant, dict) else None
    if roots is None:
        return (), True
    if not isinstance(roots, list) or len(roots) > MAX_DOC_ROOTS:
        return (), False
    normalized = tuple(value for value in (str(item).strip("/") for item in roots) if value)
    try:
        if sum(len(value.encode("utf-8")) for value in normalized) > MAX_DOC_ROOT_BYTES:
            return (), False
    except UnicodeEncodeError:
        return (), False
    if any(len(value) > 512 for value in normalized):
        return (), False
    return normalized, True


def _open_root(root: str | os.PathLike) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(root, flags)
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise ValueError("Artifact source root must be a real directory")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_relative(root_fd: int, relative: str) -> int:
    parts = relative.split("/")
    if not parts or any(not part or part in (".", "..") for part in parts):
        raise ValueError("Artifact path must be canonical and relative")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    current = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = next_fd
        fd = os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0), dir_fd=current)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("Artifact source must be a regular file")
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(current)


def _read_and_hash(root_fd: int, path: str, limit: int, *, keep_bytes: bool = False):
    fd = _open_relative(root_fd, path)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            raise ValueError("Artifact source is not a bounded regular file")
        digest = hashlib.sha256()
        chunks = [] if keep_bytes else None
        total = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ValueError("Artifact source exceeds its byte limit")
            digest.update(chunk)
            if chunks is not None:
                chunks.append(chunk)
        after = os.fstat(fd)
        if _identity(before) != _identity(after) or total != before.st_size:
            raise ValueError("Artifact source changed while hashing")
        item = {"status": "bound", "size": total, "sha256": digest.hexdigest()}
        return item, b"".join(chunks) if chunks is not None else None
    finally:
        os.close(fd)


def _read_config(root_fd: int) -> tuple[bytes | None, dict]:
    try:
        _, raw = _read_and_hash(root_fd, "client.config.json", MAX_DOCUMENT_BYTES, keep_bytes=True)
        return raw, {"status": "bound"}
    except (OSError, ValueError):
        return None, {"status": "unavailable", "reason": "missing-or-unsupported"}


def _candidate_files(root_fd: int, roots: tuple[str, ...], *, max_paths: int, path_bytes: int,
                     exclude: frozenset[str]):
    """Return a bounded path prefix and whether candidate coverage is incomplete."""
    seen = 0
    incomplete = False
    encoded_total = path_bytes
    found = []
    pending = [(os.dup(root_fd), "")]
    try:
        while pending:
            directory_fd, prefix = pending.pop()
            try:
                with os.scandir(directory_fd) as entries:
                    for entry in entries:
                        seen += 1
                        if seen > MAX_SCAN_ENTRIES:
                            incomplete = True
                            return sorted(found), incomplete
                        name = entry.name
                        if not isinstance(name, str) or not name or name.startswith("."):
                            continue
                        relative = f"{prefix}/{name}" if prefix else name
                        try:
                            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        except OSError:
                            incomplete = True
                            continue
                        if stat.S_ISDIR(info.st_mode):
                            if len(pending) >= MAX_PENDING_DIRECTORIES:
                                incomplete = True
                                continue
                            child = None
                            try:
                                child = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                                | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
                                opened = os.fstat(child)
                                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                                    os.close(child)
                                    child = None
                                    incomplete = True
                                    continue
                            except OSError:
                                if child is not None:
                                    os.close(child)
                                incomplete = True
                                continue
                            pending.append((child, relative))
                        elif (stat.S_ISREG(info.st_mode) and relative not in exclude
                              and _safe_doc_path(relative, roots)):
                            if len(found) >= max_paths:
                                incomplete = True
                                return sorted(found), incomplete
                            try:
                                path_size = len(relative.encode("utf-8"))
                            except UnicodeEncodeError:
                                incomplete = True
                                continue
                            if encoded_total + path_size > MAX_PATH_BYTES:
                                incomplete = True
                                return sorted(found), incomplete
                            found.append(relative)
                            encoded_total += path_size
                        elif (stat.S_ISREG(info.st_mode) and relative not in exclude
                              and _EXTENSION.search(relative) and "%" in relative):
                            # The runtime decodes URL escapes once before opening.
                            # Unusual percent-bearing names can therefore have
                            # aliases that this canonical inventory declines.
                            incomplete = True
                        elif relative not in exclude and _safe_doc_path(relative, roots):
                            # Fixed artifacts were already read and bound separately.
                            # Symlinks and other special files are not bound.
                            # The runtime cannot safely evidence these bytes.
                            incomplete = True
            except OSError:
                incomplete = True
            finally:
                os.close(directory_fd)
    finally:
        for directory_fd, _ in pending:
            os.close(directory_fd)
    return sorted(found), incomplete


def create_manifest(source_commit: str, graph_raw: bytes, root: str | os.PathLike) -> bytes:
    """Build a bounded manifest; incomplete source coverage is represented, not guessed."""
    if not isinstance(source_commit, str) or not _COMMIT.fullmatch(source_commit):
        raise ValueError("Artifact manifest needs a full lowercase source commit")
    if not isinstance(graph_raw, bytes) or len(graph_raw) > MAX_PACK_SCHEMA_BYTES:
        raise ValueError("Artifact manifest needs bounded compiled graph bytes")
    root_fd = _open_root(root)
    try:
        config_raw, _config_state = _read_config(root_fd)
        roots, config_ok = _roots_from_config(config_raw)
        fixed = {
            "app/brain.json": {"status": "bound", "size": len(graph_raw),
                               "sha256": hashlib.sha256(graph_raw).hexdigest()},
            "app/knowledge-pack.json": None,
            "brain-schema.json": None,
        }
        for path in ("app/knowledge-pack.json", "brain-schema.json"):
            try:
                fixed[path], _ = _read_and_hash(root_fd, path, MAX_PACK_SCHEMA_BYTES)
            except (OSError, ValueError):
                fixed[path] = {"status": "unavailable", "reason": "missing-or-over-limit"}

        docs = {}
        reasons = set()
        if not config_ok:
            reasons.add("document-roots-unavailable")
        for path in sorted(fixed):
            if (_safe_doc_path(path, roots) and fixed[path].get("status") == "bound"
                    and fixed[path]["size"] <= MAX_DOCUMENT_BYTES):
                docs[path] = fixed[path]
            elif (_safe_doc_path(path, roots) and fixed[path].get("status") == "unavailable"):
                reasons.add("fixed-artifact-unavailable")
        aggregate = sum(entry.get("size", 0) for entry in fixed.values() if entry.get("status") == "bound")
        paths_bytes = sum(len(path.encode("utf-8")) for path in docs)
        candidates, inventory_incomplete = _candidate_files(
            root_fd, roots, max_paths=max(0, MAX_PATHS - len(docs)), path_bytes=paths_bytes,
            exclude=_FIXED)
        if inventory_incomplete:
            reasons.add("inventory-incomplete")
        for relative in candidates:
            try:
                item, _ = _read_and_hash(root_fd, relative, MAX_DOCUMENT_BYTES)
            except (OSError, ValueError):
                reasons.add("unsupported-or-over-limit-document")
                continue
            if aggregate + item["size"] > MAX_TOTAL_BYTES:
                reasons.add("aggregate-byte-limit")
                break
            aggregate += item["size"]
            docs[relative] = item

        if not config_ok:
            reasons.add("inventory-incomplete")
        manifest = {
            "format": FORMAT,
            "sourceCommit": source_commit,
            "graphSha256": hashlib.sha256(graph_raw).hexdigest(),
            "artifacts": fixed,
            "documents": {
                "coverage": "complete" if not reasons else "partial",
                "reasonCodes": sorted(reasons),
                "entries": [{"path": path, **docs[path]} for path in sorted(docs)],
            },
        }
        encoded = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(encoded) > MANIFEST_LIMIT:
            # Preserve only individually bounded entries in a deterministic
            # prefix. The incomplete marker prevents absence claims.
            entries = manifest["documents"]["entries"]
            while entries and len(encoded) > MANIFEST_LIMIT:
                del entries[max(0, len(entries) - 256):]
                reasons.add("manifest-byte-limit")
                manifest["documents"]["coverage"] = "partial"
                manifest["documents"]["reasonCodes"] = sorted(reasons)
                encoded = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(encoded) > MANIFEST_LIMIT:
            raise ValueError("Fixed artifact metadata exceeds its manifest byte limit")
        return encoded
    finally:
        os.close(root_fd)


def _valid_manifest(value, source_attestation, graph_raw: bytes | None):
    if (not isinstance(value, dict) or set(value) != {"format", "sourceCommit", "graphSha256", "artifacts", "documents"}
            or value.get("format") != FORMAT or not isinstance(source_attestation, dict)
            or not isinstance(graph_raw, bytes)):
        return None
    graph_sha = hashlib.sha256(graph_raw).hexdigest()
    if (value.get("sourceCommit") != source_attestation.get("sourceCommit")
            or value.get("graphSha256") != graph_sha
            or value.get("graphSha256") != source_attestation.get("graphSha256")
            or not isinstance(value.get("sourceCommit"), str)
            or not _COMMIT.fullmatch(value["sourceCommit"])):
        return None
    artifacts = value.get("artifacts")
    documents = value.get("documents")
    if not isinstance(artifacts, dict) or set(artifacts) != _FIXED or not isinstance(documents, dict):
        return None
    if set(documents) != {"coverage", "reasonCodes", "entries"}:
        return None
    if documents["coverage"] not in ("complete", "partial"):
        return None
    reason_codes = documents["reasonCodes"]
    if (not isinstance(reason_codes, list) or len(reason_codes) > 16
            or any(not isinstance(reason, str) or not reason or len(reason) > 64 for reason in reason_codes)
            or reason_codes != sorted(set(reason_codes))
            or not isinstance(documents["entries"], list) or len(documents["entries"]) > MAX_PATHS):
        return None
    if ((documents["coverage"] == "complete" and documents["reasonCodes"])
            or (documents["coverage"] == "partial" and not documents["reasonCodes"])):
        return None
    result = {}
    for path, entry in artifacts.items():
        parsed = _valid_entry(entry)
        if parsed is False:
            return None
        result[path] = parsed if parsed is not None else {"status": "unavailable"}
    seen = set()
    path_bytes = 0
    aggregate_bytes = sum(entry["size"] for entry in result.values()
                          if isinstance(entry, dict) and entry.get("status") == "bound")
    for entry in documents["entries"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "status", "size", "sha256"}:
            return None
        path = entry.get("path")
        if not _safe_doc_path(path, ()) or path in seen:
            return None
        try:
            path_size = len(path.encode("utf-8"))
        except UnicodeEncodeError:
            return None
        path_bytes += path_size
        if path_bytes > MAX_PATH_BYTES:
            return None
        parsed = _valid_entry({key: entry[key] for key in ("status", "size", "sha256")})
        if parsed is False:
            return None
        if parsed is not None and parsed["size"] > MAX_DOCUMENT_BYTES:
            return None
        seen.add(path)
        if parsed is not None:
            if path in _FIXED:
                fixed_entry = result.get(path)
                if (fixed_entry is None or parsed != fixed_entry
                        or fixed_entry["size"] > MAX_DOCUMENT_BYTES):
                    return None
            else:
                aggregate_bytes += parsed["size"]
                if aggregate_bytes > MAX_TOTAL_BYTES:
                    return None
                result[path] = parsed
        if path in _FIXED:
            if parsed is None:
                return None
    for path in seen:
        parts = path.split("/")
        if any("/".join(parts[:index]) in seen for index in range(1, len(parts))):
            return None
    graph_entry = result.get("app/brain.json")
    if (not isinstance(graph_entry, dict) or graph_entry.get("status") != "bound"
            or graph_entry.get("sha256") != graph_sha or graph_entry.get("size") != len(graph_raw)):
        return None
    return {"coverage": documents["coverage"],
            "reasonCodes": tuple(documents["reasonCodes"]),
            "entries": result}


def _valid_entry(entry):
    if not isinstance(entry, dict) or entry.get("status") not in ("bound", "unavailable"):
        return False
    if entry["status"] == "unavailable":
        if (set(entry) != {"status", "reason"} or not isinstance(entry.get("reason"), str)
                or not entry["reason"] or len(entry["reason"]) > 64):
            return False
        return None
    if (set(entry) != {"status", "size", "sha256"} or type(entry.get("size")) is not int
            or not 0 <= entry["size"] <= MAX_PACK_SCHEMA_BYTES
            or not isinstance(entry.get("sha256"), str) or not _HEX.fullmatch(entry["sha256"])):
        return False
    return {"status": "bound", "size": entry["size"], "sha256": entry["sha256"]}


def _load_manifest(path, source_attestation, graph_raw: bytes | None, *, owner_uid=MAX_RECEIPT_UID):
    """Return immutable-by-convention byte bindings, or None on any evidence failure."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    directory_path, name = os.path.split(os.fspath(path))
    if not directory_path or not name or name in (".", ".."):
        return None
    try:
        directory_fd = os.open(directory_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                               | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        directory_info = os.fstat(directory_fd)
        if (not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid != owner_uid
                or stat.S_IMODE(directory_info.st_mode) != 0o555):
            return None
        try:
            fd = os.open(name, flags, dir_fd=directory_fd)
        except OSError:
            return None
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner_uid
                    or stat.S_IMODE(before.st_mode) != 0o444 or before.st_nlink != 1
                    or before.st_size > MANIFEST_LIMIT):
                return None
            chunks = []
            total = 0
            while True:
                chunk = os.read(fd, min(65536, MANIFEST_LIMIT + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MANIFEST_LIMIT:
                    return None
            after = os.fstat(fd)
            if _identity(before) != _identity(after) or total != before.st_size:
                return None
            raw = b"".join(chunks)
        finally:
            os.close(fd)
        try:
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            return None
        if _identity(after) != _identity(current):
            return None
    finally:
        os.close(directory_fd)
    try:
        value = _decode_json(raw)
    except (ValueError, TypeError):
        return None
    return _valid_manifest(value, source_attestation, graph_raw)


def load_manifest(path, source_attestation, graph_raw: bytes | None, *, owner_uid=MAX_RECEIPT_UID):
    """Load optional evidence; filesystem failures make evidence unavailable."""
    try:
        return _load_manifest(path, source_attestation, graph_raw, owner_uid=owner_uid)
    except (OSError, ValueError, TypeError, OverflowError):
        return None


def _identity(info):
    return tuple(getattr(info, key) for key in
                 ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"))


def write_manifest(path, encoded: bytes) -> bool:
    if not isinstance(encoded, bytes) or len(encoded) > MANIFEST_LIMIT:
        return False
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o444)
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write creating artifact manifest")
            view = view[written:]
        os.fchmod(fd, 0o444)
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    else:
        os.close(fd)
    return True
