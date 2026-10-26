"""Review-bound local JSON migration, not an authority writer or transaction.

Only explicit regular-file inputs are supported. Writers must be quiescent for
apply/recovery: the revision checks and flock coordinate cooperating operators,
not an arbitrary process ignoring that boundary. Private preimages and durable
per-file intent allow a partial batch to be resumed or explicitly restored.
"""
from __future__ import annotations

from contextlib import contextmanager
from array import array
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import stat
import struct
import sys


PLAN_FORMAT = "operator-json-migration-plan/v1"
STATE_FORMAT = "operator-json-migration-state/v1"
MAX_FILES = 128
MAX_BYTES = 64 * 1024 * 1024
MAX_METADATA_BYTES = 4 * 1024 * 1024
IDENTITY_KEYS = {"device", "inode", "size", "mode", "uid", "gid", "links", "mtimeNs", "ctimeNs"}


class MigrationError(ValueError):
    pass


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")


def encode_document(value, _raw, _kind):
    return encode(value)


def rewrite_root(raw, *, rename=None, replace=None):
    """Splice one declared root identifier, preserving every other UTF-8 byte.

    The caller has already performed strict JSON parsing and kind validation.
    JSONDecoder supplies token boundaries; no regex scans into user payloads.
    """
    text = raw.decode("utf-8")
    decoder = json.JSONDecoder()
    position = len(text) - len(text.lstrip())
    if position >= len(text) or text[position] != "{" or bool(rename) == bool(replace):
        raise MigrationError("root identifier rewrite requires one object operation")
    opening = position
    position += 1
    fields = {}
    while True:
        while text[position].isspace():
            position += 1
        if text[position] == "}":
            break
        key_start = position
        key, key_end = decoder.raw_decode(text, position)
        position = key_end
        while text[position].isspace():
            position += 1
        if not isinstance(key, str) or text[position] != ":":
            raise MigrationError("invalid root JSON member")
        position += 1
        while text[position].isspace():
            position += 1
        value_start = position
        _, value_end = decoder.raw_decode(text, position)
        fields[key] = (key_start, key_end, value_start, value_end)
        position = value_end
        while text[position].isspace():
            position += 1
        if text[position] == "}":
            break
        if text[position] != ",":
            raise MigrationError("invalid root JSON separator")
        position += 1
    if rename:
        old, new = rename
        if old not in fields or new in fields:
            raise MigrationError("root identifier rename collision or missing member")
        start, end, _, _ = fields[old]
        token = json.dumps(new, ensure_ascii=False)
    else:
        key, value = replace
        token = json.dumps(value, ensure_ascii=False, allow_nan=False)
        if key in fields:
            _, _, start, end = fields[key]
        else:
            start = end = opening + 1
            token = json.dumps(key) + ":" + token + ("," if fields else "")
    return (text[:start] + token + text[end:]).encode("utf-8")


def differences(before, after):
    """Exact changed pointers and value digests without dumping unrelated data."""
    missing = object()
    pending, result = [("", before, after)], []
    while pending:
        pointer, left, right = pending.pop()
        if type(left) is type(right) and left == right:
            continue
        if isinstance(left, dict) and isinstance(right, dict):
            for key in sorted(set(left) | set(right), reverse=True):
                segment = key.replace("~", "~0").replace("/", "~1")
                pending.append((pointer + "/" + segment, left.get(key, missing), right.get(key, missing)))
        elif isinstance(left, list) and isinstance(right, list):
            for index in reversed(range(max(len(left), len(right)))):
                pending.append((pointer + "/" + str(index), left[index] if index < len(left) else missing,
                                right[index] if index < len(right) else missing))
        else:
            result.append({"pointer": pointer, "operation": "add" if left is missing else
                           "remove" if right is missing else "replace",
                           "beforeSha256": None if left is missing else sha256(encode(left)),
                           "afterSha256": None if right is missing else sha256(encode(right))})
            if len(result) > 4096:
                raise MigrationError("migration preview exceeds the changed-pointer bound")
    return result


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise MigrationError(f"duplicate JSON field {key!r}")
        result[key] = value
    return result


def _constant(_value):
    raise MigrationError("nonfinite JSON number")


def decode(raw):
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            if depth > 128:
                raise MigrationError("JSON nesting exceeds the migration bound")
            if isinstance(item, float) and not math.isfinite(item):
                raise MigrationError("nonfinite JSON number")
            if isinstance(item, str):
                item.encode("utf-8")
            elif isinstance(item, dict):
                pending.extend((part, depth + 1) for pair in item.items() for part in pair)
            elif isinstance(item, list):
                pending.extend((part, depth + 1) for part in item)
        return value
    except (UnicodeError, RecursionError, ValueError) as exc:
        raise MigrationError(f"invalid strict UTF-8 JSON: {exc}") from None


def _capabilities():
    if not all(type(getattr(os, name, None)) is int and getattr(os, name) > 0
               for name in ("O_NOFOLLOW", "O_DIRECTORY")):
        raise MigrationError("no-follow local migration is unavailable on this platform")


def _absolute(path):
    value = os.fspath(path)
    if not isinstance(value, str) or "\x00" in value:
        raise MigrationError("invalid migration path")
    return os.path.abspath(value)


def _identity(info):
    return {"device": info.st_dev, "inode": info.st_ino, "size": info.st_size,
            "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid,
            "links": info.st_nlink, "mtimeNs": info.st_mtime_ns, "ctimeNs": info.st_ctime_ns}


def _inode(info):
    return {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid}


def _darwin_library():
    """SDK sys/acl.h and sys/xattr.h descriptor APIs; no path re-resolution."""
    import ctypes
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    declarations = {
        "flistxattr": ([ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int], ctypes.c_ssize_t),
        "acl_get_fd_np": ([ctypes.c_int, ctypes.c_int], ctypes.c_void_p),
        "acl_init": ([ctypes.c_int], ctypes.c_void_p),
        "acl_size": ([ctypes.c_void_p], ctypes.c_ssize_t),
        "acl_copy_ext": ([ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ssize_t], ctypes.c_ssize_t),
        "acl_free": ([ctypes.c_void_p], ctypes.c_int),
    }
    for name, (arguments, result) in declarations.items():
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result
    return library


def _darwin_metadata(fd):
    import ctypes
    library = _darwin_library()
    flags = getattr(os.fstat(fd), "st_flags", None)
    if flags != 0:
        raise MigrationError("Darwin file flags are outside the plain JSON mutation profile")
    # XATTR_SHOWCOMPRESSION also exposes otherwise hidden compression xattrs.
    count = library.flistxattr(fd, None, 0, 0x0020)
    if count < 0:
        raise MigrationError("cannot inspect Darwin descriptor extended attributes")
    if count:
        raise MigrationError("extended attributes are outside the plain JSON mutation profile")
    ctypes.set_errno(0)
    actual = library.acl_get_fd_np(fd, 0x00000100)  # ACL_TYPE_EXTENDED
    acl_errno = ctypes.get_errno()
    if not actual:
        # Darwin Libc's FILESEC_ACL lookup reports ENOENT when the held
        # descriptor has no ACL property. Other failures are not empty ACLs.
        if acl_errno == errno.ENOENT:
            return
        raise MigrationError("cannot inspect Darwin descriptor ACL")
    empty = None
    try:
        empty = library.acl_init(0)
        if not empty:
            raise MigrationError("cannot establish the native empty ACL representation")

        def external(acl):
            size = library.acl_size(acl)
            if not 0 < size <= 65536:
                raise MigrationError("cannot bound the native ACL representation")
            buffer = ctypes.create_string_buffer(size)
            if library.acl_copy_ext(buffer, acl, size) != size:
                raise MigrationError("cannot serialize the complete native ACL")
            return buffer.raw

        # Compare the complete SDK external representation with a native empty
        # ACL, including header/private flags; do not guess opaque struct layout
        # or conflate Darwin acl_get_entry's -1/EINVAL with a generic empty ACL.
        if external(actual) != external(empty):
            raise MigrationError("ACLs are outside the plain JSON mutation profile")
    finally:
        free_failed = library.acl_free(actual) != 0
        if empty:
            free_failed = library.acl_free(empty) != 0 or free_failed
        if free_failed:
            raise MigrationError("cannot release the native ACL inspection objects")


def _plain_metadata(fd):
    """Refuse metadata that the byte preimages cannot restore.

    Linux POSIX ACLs are exposed as system.posix_acl_* xattrs. The inode-flag
    ioctl also covers user flags such as nodump/immutable/project inheritance.
    Only extent/inline layout and directory indexing bits may be filesystem-set.
    Darwin uses SDK descriptor ACL/xattr APIs and stat flags. Other platforms
    and unsupported filesystems refuse rather than silently stripping metadata.
    """
    if sys.platform == "darwin":
        try:
            _darwin_metadata(fd)
        except (ImportError, OSError, AttributeError, TypeError) as exc:
            raise MigrationError(f"cannot establish the Darwin plain JSON metadata profile: {exc}") from None
        return
    if (sys.platform != "linux" or os.uname().machine not in ("x86_64", "aarch64")
            or array("L").itemsize != 8 or not hasattr(os, "listxattr")):
        raise MigrationError("plain-metadata apply/recovery requires the declared 64-bit Linux profile")
    try:
        import fcntl
        if os.listxattr(fd):
            raise MigrationError("extended attributes/ACLs are outside the plain JSON mutation profile")
        flags = array("L", [0])
        # Linux _IOR('f', 1, long), only on the explicitly selected ABI above.
        fcntl.ioctl(fd, 0x80086601, flags, True)
        layout_only = 0x00080000 | 0x00001000 | 0x10000000
        if flags[0] & ~layout_only:
            raise MigrationError("inode flags are outside the plain JSON mutation profile")
        # FS_IOC_FSGETXATTR: refuse project IDs or allocation/inheritance policy
        # that replacing a file with a sibling would otherwise silently change.
        extended = bytearray(28)
        fcntl.ioctl(fd, 0x801c581f, extended, True)
        xflags, extent_size, _extent_count, project, cow_extent_size = struct.unpack("=5I", extended[:20])
        if xflags & ~0x80000000 or extent_size or project or cow_extent_size:
            raise MigrationError("extended inode policy is outside the plain JSON mutation profile")
    except (ImportError, OSError, TypeError) as exc:
        raise MigrationError(f"cannot establish the plain JSON metadata profile: {exc}") from None


@contextmanager
def _parent(path):
    """Hold no-follow directory descriptors; never resolve a symlink prefix."""
    _capabilities()
    path = _absolute(path)
    parts = Path(path).parts
    if len(parts) < 2:
        raise MigrationError("a migration file needs a basename")
    fd = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    chain = [_inode(os.fstat(fd))]
    try:
        for part in parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            chain.append(_inode(os.fstat(fd)))
        yield fd, parts[-1], chain
    finally:
        os.close(fd)


def _private_directory(fd):
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise MigrationError("operator metadata requires an owned 0700 directory")
    _plain_metadata(fd)


@contextmanager
def _open_at(parent, name, *, owned=True, private=False, plain=False, max_bytes=MAX_BYTES):
    if type(max_bytes) is not int or not 0 <= max_bytes <= MAX_BYTES:
        raise MigrationError("invalid migration read bound")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(name, flags, dir_fd=parent)
    try:
        first = os.fstat(fd)
        if (not stat.S_ISREG(first.st_mode) or first.st_nlink != 1
                or owned and first.st_uid != os.geteuid()
                or first.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
                or private and stat.S_IMODE(first.st_mode) != 0o600):
            raise MigrationError("migration input is not a supported owned regular file")
        if first.st_size > max_bytes:
            raise MigrationError("migration input exceeds the byte bound")
        if plain or private:
            _plain_metadata(fd)
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise MigrationError("migration input exceeds the byte bound")
        last = os.fstat(fd)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if _identity(first) != _identity(last) or _identity(last) != _identity(named):
            raise MigrationError("migration input changed while reading")
        yield fd, b"".join(chunks), _identity(last)
    finally:
        os.close(fd)


def snapshot(path, *, owned=True, private=False, plain=False, max_bytes=MAX_BYTES):
    path = _absolute(path)
    with _parent(path) as (parent, name, chain):
        with _open_at(parent, name, owned=owned, private=private, plain=plain,
                      max_bytes=max_bytes) as (_, raw, identity):
            return {"path": path, "identity": identity, "parents": chain,
                    "sha256": sha256(raw), "bytes": len(raw)}, raw


def _same(observed, expected):
    return all(observed.get(key) == expected.get(key)
               for key in ("path", "identity", "parents", "sha256", "bytes"))


def _write_fd(fd, raw):
    view = memoryview(raw)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise MigrationError("short migration write")
        view = view[count:]
    os.fsync(fd)


def _new_at(parent, name, raw):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        os.fchmod(fd, 0o600)
        _plain_metadata(fd)
        _write_fd(fd, raw)
    finally:
        os.close(fd)
    os.fsync(parent)


def write_private_new(path, raw):
    if len(raw) > MAX_BYTES:
        raise MigrationError("private migration artifact exceeds its byte bound")
    with _parent(path) as (parent, name, _):
        _private_directory(parent)
        _new_at(parent, name, raw)


def preview(paths, *, tool, transform, serialize=encode_document, tool_files=(), kinds=None):
    if not 1 <= len(paths) <= MAX_FILES:
        raise MigrationError(f"select between 1 and {MAX_FILES} files")
    rows, total, output_total, seen_paths, seen_inodes = [], 0, 0, set(), set()
    if kinds is not None and len(kinds) != len(paths):
        raise MigrationError("migration kind count differs from selected paths")
    for index, path in enumerate(paths):
        observed, raw = snapshot(path)
        inode = (observed["identity"]["device"], observed["identity"]["inode"])
        if observed["path"] in seen_paths or inode in seen_inodes:
            raise MigrationError("duplicate or aliased selected migration input")
        seen_paths.add(observed["path"])
        seen_inodes.add(inode)
        total += len(raw)
        if total > MAX_BYTES:
            raise MigrationError("selected migration batch exceeds the byte bound")
        value, changes, kind = transform(decode(raw), kinds[index] if kinds is not None else None)
        output = serialize(value, raw, kind) if changes else raw
        output_total += len(output)
        if len(output) > MAX_BYTES or output_total > MAX_BYTES:
            raise MigrationError("migration output exceeds the byte bound")
        rows.append({"input": observed, "kind": kind, "changes": changes,
                     "output": {"sha256": sha256(output), "bytes": len(output)}})
    tools = []
    for path in dict.fromkeys([_absolute(__file__), *map(_absolute, tool_files)]):
        observed, _ = snapshot(path, owned=False)
        tools.append({"path": observed["path"], "sha256": observed["sha256"]})
    return {"format": PLAN_FORMAT, "tool": tool, "toolFiles": tools, "files": rows}


def save_plan(path, plan):
    raw = encode(plan)
    if len(raw) > MAX_METADATA_BYTES:
        raise MigrationError("migration plan exceeds the metadata bound")
    write_private_new(path, raw)
    return sha256(raw)


def load_plan(path, expected_sha256, *, tool, tool_files=()):
    if (not isinstance(expected_sha256, str) or len(expected_sha256) != 64
            or any(c not in "0123456789abcdef" for c in expected_sha256)):
        raise MigrationError("the reviewed plan SHA-256 is required")
    _, raw = snapshot(path, private=True, max_bytes=MAX_METADATA_BYTES)
    if sha256(raw) != expected_sha256:
        raise MigrationError("the reviewed migration plan changed")
    plan = decode(raw)
    if (not isinstance(plan, dict) or set(plan) != {"format", "tool", "toolFiles", "files"}
            or plan["format"] != PLAN_FORMAT or plan["tool"] != tool
            or not isinstance(plan["files"], list) or not 1 <= len(plan["files"]) <= MAX_FILES
            or not isinstance(plan["toolFiles"], list) or not 1 <= len(plan["toolFiles"]) <= 8):
        raise MigrationError("invalid migration plan")
    required_tools = list(dict.fromkeys([_absolute(__file__), *map(_absolute, tool_files)]))
    if [item.get("path") if isinstance(item, dict) else None
            for item in plan["toolFiles"]] != required_tools:
        raise MigrationError("migration implementation pins differ from the executing tool")
    for item in plan["toolFiles"]:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise MigrationError("invalid migration implementation pin")
        observed, _ = snapshot(item["path"], owned=False)
        if observed["sha256"] != item["sha256"]:
            raise MigrationError("migration implementation changed after preview")
    seen = set()
    for row in plan["files"]:
        if (not isinstance(row, dict) or set(row) != {"input", "kind", "changes", "output"}
                or not isinstance(row["input"], dict) or not isinstance(row["output"], dict)
                or not isinstance(row["changes"], list) or not isinstance(row["kind"], str)):
            raise MigrationError("invalid migration plan file entry")
        item = row["input"]
        if (set(item) != {"path", "identity", "parents", "sha256", "bytes"}
                or _absolute(item["path"]) != item["path"] or item["path"] in seen
                or not isinstance(item["identity"], dict) or not isinstance(item["parents"], list)
                or set(row["output"]) != {"sha256", "bytes"}):
            raise MigrationError("invalid or duplicate selected migration path")
        if (set(item["identity"]) != IDENTITY_KEYS
                or any(type(value) is not int or key not in ("mtimeNs", "ctimeNs") and value < 0
                       for key, value in item["identity"].items())
                or not item["parents"] or len(item["parents"]) > 1024
                or any(not isinstance(parent, dict) or set(parent) != {"device", "inode", "uid"}
                       or any(type(value) is not int or value < 0 for value in parent.values())
                       for parent in item["parents"])
                or any(type(record["bytes"]) is not int or not 0 <= record["bytes"] <= MAX_BYTES
                       or not isinstance(record["sha256"], str) or len(record["sha256"]) != 64
                       or any(c not in "0123456789abcdef" for c in record["sha256"])
                       for record in (item, row["output"]))):
            raise MigrationError("invalid migration digest or file identity")
        seen.add(item["path"])
    # Structural equality is checked by re-preview before first effects. Recovery
    # validates each saved preimage and recomputes its exact planned output.
    return plan, raw


def _outputs(plan, state_fd, transform, serialize):
    outputs, total = [], 0
    for index, row in enumerate(plan["files"]):
        with _open_at(state_fd, f"before-{index}.json", private=True) as (_, raw, _):
            if sha256(raw) != row["input"]["sha256"] or len(raw) != row["input"]["bytes"]:
                raise MigrationError("a saved migration preimage changed")
            value, changes, kind = transform(decode(raw), row["kind"])
            after = serialize(value, raw, kind) if changes else raw
            if (changes != row["changes"] or kind != row["kind"]
                    or {"sha256": sha256(after), "bytes": len(after)} != row["output"]):
                raise MigrationError("saved preimage no longer matches the reviewed transform")
            total += len(raw) + len(after)
            if total > 2 * MAX_BYTES:
                raise MigrationError("saved migration batch exceeds its bound")
            outputs.append((raw, after))
    return outputs


def _save_state(state_fd, state):
    if len(state["events"]) > 8192:
        raise MigrationError("migration journal event bound exhausted")
    raw = encode(state)
    if len(raw) > MAX_METADATA_BYTES:
        raise MigrationError("migration journal metadata bound exhausted")
    name = ".state-" + secrets.token_hex(12)
    _new_at(state_fd, name, raw)
    try:
        os.replace(name, "state.json", src_dir_fd=state_fd, dst_dir_fd=state_fd)
        os.fsync(state_fd)
    finally:
        try:
            os.unlink(name, dir_fd=state_fd)
        except FileNotFoundError:
            pass


def _event(state_fd, state, index, phase):
    state["events"].append({"sequence": len(state["events"]), "file": index, "phase": phase})
    _save_state(state_fd, state)


@contextmanager
def _locked_state(path):
    try:
        import fcntl
    except ImportError:
        raise MigrationError("owned operator migration requires local flock support") from None
    with _parent(path) as (parent, name, _):
        directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        _private_directory(directory)
        lock = os.open("lock", os.O_RDWR | os.O_NOFOLLOW, dir_fd=directory)
        try:
            info = os.fstat(lock)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
                raise MigrationError("unsafe migration journal lock")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise MigrationError("another operator owns this migration journal") from None
            yield directory
        finally:
            os.close(lock)
    finally:
        os.close(directory)


def _create_state(path, plan, plan_raw):
    _capabilities()
    try:
        import fcntl  # noqa: F401 -- fail before creating state on unsupported platforms
    except ImportError:
        raise MigrationError("owned operator migration requires local flock support") from None
    originals = []
    for row in plan["files"]:
        observed, raw = snapshot(row["input"]["path"], plain=True)
        if not _same(observed, row["input"]):
            raise MigrationError("selected input changed after exact preview")
        originals.append(raw)
    with _parent(path) as (parent, name, _):
        os.mkdir(name, 0o700, dir_fd=parent)
        os.fsync(parent)
    with _parent(Path(path) / "lock") as (directory, name, _):
        _private_directory(directory)
        _new_at(directory, name, b"")
    with _locked_state(path) as directory:
        _new_at(directory, "plan.json", plan_raw)
        for index, raw in enumerate(originals):
            _new_at(directory, f"before-{index}.json", raw)
        state = {"format": STATE_FORMAT, "planSha256": sha256(plan_raw),
                 "nonce": secrets.token_hex(12), "phase": "applying", "events": [],
                 "files": [{"phase": "pending", "stage": None, "applied": None,
                            "restored": None} for _ in originals]}
        _event(directory, state, None, "prepared-all-private-preimages")


def _read_state(directory, plan_sha256):
    with _open_at(directory, "state.json", private=True,
                  max_bytes=MAX_METADATA_BYTES) as (_, raw, _):
        state = decode(raw)
    if (not isinstance(state, dict) or state.get("format") != STATE_FORMAT
            or state.get("planSha256") != plan_sha256
            or state.get("phase") not in ("applying", "applied", "restoring", "restored")
            or not isinstance(state.get("files"), list) or not isinstance(state.get("events"), list)
            or not isinstance(state.get("nonce"), str) or len(state["nonce"]) != 24
            or any(c not in "0123456789abcdef" for c in state["nonce"])
            or set(state) != {"format", "planSha256", "nonce", "phase", "events", "files"}):
        raise MigrationError("migration journal does not match the reviewed plan")
    return state


def _validate_entries(state, plan):
    if len(state["files"]) != len(plan["files"]):
        raise MigrationError("migration journal file count changed")
    for index, (entry, row) in enumerate(zip(state["files"], plan["files"])):
        if (not isinstance(entry, dict) or set(entry) != {"phase", "stage", "applied", "restored"}
                or entry["phase"] not in ("pending", "publish", "applied", "restore", "restored")):
            raise MigrationError("invalid migration journal file state")
        stage = entry["stage"]
        if stage is not None:
            if (not isinstance(stage, dict) or set(stage) != {"name", "operation", "identity"}
                    or stage["operation"] not in ("publish", "restore")
                    or stage["name"] != _stage_name(state, index, stage["operation"])
                    or not isinstance(stage["identity"], dict)
                    or set(stage["identity"]) != {"device", "inode", "uid"}
                    or any(type(value) is not int for value in stage["identity"].values())):
                raise MigrationError("invalid migration staging selector")
        if entry["phase"] in ("publish", "restore") and stage is None:
            raise MigrationError("migration staging identity is missing")
        for name in ("applied", "restored"):
            identity = entry[name]
            if identity is not None and (not isinstance(identity, dict)
                    or set(identity) != set(row["input"]["identity"])
                    or any(type(value) is not int for value in identity.values())):
                raise MigrationError("invalid migration result identity")
        if entry["phase"] in ("applied", "restore") and entry["applied"] is None:
            raise MigrationError("published result identity is missing")
        if entry["phase"] == "restored" and entry["restored"] is None:
            raise MigrationError("restored result identity is missing")


def _stage_name(state, index, operation):
    # Bounded independently of an input basename already at NAME_MAX.
    return f".mimwell.identifier-{state['nonce']}-{index}-{operation}"


def _is_installed(observed, identity, digest, intended_metadata):
    return (identity is not None and observed["sha256"] == digest
            and all(observed["identity"].get(key) == identity.get(key)
                    for key in ("device", "inode", "uid"))
            and all(observed["identity"].get(key) == intended_metadata.get(key)
                    for key in ("mode", "gid")))


def _publish(directory, state, index, row, expected, raw, *, restoring=False):
    entry = state["files"][index]
    wanted = "restore" if restoring else "publish"
    done = "restored" if restoring else "applied"
    path = row["input"]["path"]
    digest = sha256(raw)
    observed, _ = snapshot(path, plain=True)
    if observed["parents"] != row["input"]["parents"]:
        raise MigrationError("selected parent directory changed")
    stage = entry["stage"]
    if (stage and stage["operation"] == wanted
            and _is_installed(observed, stage["identity"], digest, row["input"]["identity"])):
        # The rename happened before an interrupted state update. Re-establish
        # directory durability before recording success, without repeating it.
        with _parent(path) as (parent, _, _):
            os.fsync(parent)
        entry[done] = observed["identity"]
        entry["phase"] = done
        _event(directory, state, index, done)
        return
    if not _same(observed, expected):
        raise MigrationError("per-file revision CAS refused a changed selected input")
    with _parent(path) as (parent, name, chain):
        if chain != row["input"]["parents"]:
            raise MigrationError("selected parent directory changed")
        with _open_at(parent, name, plain=True) as (source_fd, current, identity):
            if identity != expected["identity"] or sha256(current) != expected["sha256"]:
                raise MigrationError("per-file revision CAS refused a changed selected input")
            import fcntl
            try:
                fcntl.flock(source_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise MigrationError("selected file has a cooperating writer") from None
            bind_stage = stage is None or stage["operation"] != wanted
            fd = None
            if not bind_stage:
                try:
                    fd = os.open(stage["name"], os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 dir_fd=parent)
                except FileNotFoundError:
                    # A crash may preserve the durable private intent but not
                    # its newly created sibling name. The source still passed
                    # the exact preimage CAS; bind a fresh exclusive inode.
                    bind_stage = True
            if bind_stage:
                stage_name = _stage_name(state, index, wanted)
                fd = os.open(stage_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
            try:
                if bind_stage:
                    os.fchmod(fd, 0o600)
                    stage = {"name": stage_name, "operation": wanted, "identity": _inode(os.fstat(fd))}
                    entry["stage"], entry["phase"] = stage, wanted
                    _event(directory, state, index, wanted)
                else:
                    info = os.fstat(fd)
                    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                            or _inode(info) != stage["identity"]):
                        raise MigrationError("recorded migration staging identity changed")
                _plain_metadata(fd)
                os.ftruncate(fd, 0)
                _write_fd(fd, raw)
                os.fchown(fd, -1, row["input"]["identity"]["gid"])
                os.fchmod(fd, row["input"]["identity"]["mode"])
                _plain_metadata(fd)
                os.fsync(fd)
            finally:
                os.close(fd)
            # This is a revision CAS under the required quiescent/cooperating
            # writer boundary, not a kernel CAS against arbitrary replacements.
            fresh, _ = snapshot(path, plain=True)
            if not _same(fresh, expected):
                raise MigrationError("selected file changed before publication")
            os.replace(stage["name"], name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
    installed, _ = snapshot(path, plain=True)
    if not _is_installed(installed, stage["identity"], digest, row["input"]["identity"]):
        raise MigrationError("publication outcome is unknown; retain the migration journal")
    entry[done], entry["phase"] = installed["identity"], done
    _event(directory, state, index, done)


def operate(plan_path, expected_sha256, state_path, *, tool, transform, serialize=encode_document,
            tool_files=(), action="apply", attest_quiescent=False):
    if not attest_quiescent:
        raise MigrationError("apply/recovery requires explicit writer-quiescence attestation")
    plan, plan_raw = load_plan(plan_path, expected_sha256, tool=tool, tool_files=tool_files)
    if action == "apply":
        checked = preview([row["input"]["path"] for row in plan["files"]], tool=tool,
                          transform=transform, serialize=serialize,
                          tool_files=tool_files,
                          kinds=[row["kind"] for row in plan["files"]])
        if checked != plan:
            raise MigrationError("exact migration preview no longer matches current input")
        _create_state(state_path, plan, plan_raw)
    elif action not in ("resume", "restore-preimages"):
        raise MigrationError("unknown migration action")
    with _locked_state(state_path) as directory:
        with _open_at(directory, "plan.json", private=True,
                      max_bytes=MAX_METADATA_BYTES) as (_, saved, _):
            if saved != plan_raw:
                raise MigrationError("saved plan differs from the reviewed plan")
        state = _read_state(directory, expected_sha256)
        _validate_entries(state, plan)
        outputs = _outputs(plan, directory, transform, serialize)
        if action == "restore-preimages":
            return _restore(directory, state, plan, outputs)
        if state["phase"] in ("restoring", "restored"):
            raise MigrationError("recovery began; finish restoration and create a new preview to migrate again")
        was_applied = state["phase"] == "applied"
        for index, (row, (_, after)) in enumerate(zip(plan["files"], outputs)):
            entry = state["files"][index]
            if entry["phase"] == "applied":
                observed, _ = snapshot(row["input"]["path"], plain=True)
                expected = {**row["input"], **row["output"], "identity": entry["applied"]}
                if not _same(observed, expected):
                    raise MigrationError("an applied file changed; recovery will not overwrite later writes")
            elif not row["changes"]:
                observed, _ = snapshot(row["input"]["path"], plain=True)
                if not _same(observed, row["input"]):
                    raise MigrationError("an unchanged selected file changed")
            else:
                _publish(directory, state, index, row, row["input"], after)
        for index, row in enumerate(plan["files"]):
            observed, _ = snapshot(row["input"]["path"], plain=True)
            expected = row["input"] if not row["changes"] else {
                **row["input"], **row["output"], "identity": state["files"][index]["applied"]}
            if not _same(observed, expected):
                raise MigrationError("selected input changed before final migration verification")
        state["phase"] = "applied"
        if not was_applied:
            _event(directory, state, None, "batch-applied")
        return {"phase": state["phase"], "files": len(plan["files"]), "planSha256": expected_sha256}


def _restore(directory, state, plan, outputs):
    # Verify all known postimages before the first restoration effect. A file
    # changed by a later writer is never replaced with an old saved copy.
    was_restored = state["phase"] == "restored"
    for index, row in enumerate(plan["files"]):
        entry = state["files"][index]
        observed, _ = snapshot(row["input"]["path"], plain=True)
        if observed["parents"] != row["input"]["parents"]:
            raise MigrationError("restore selected parent directory changed")
        if entry["phase"] == "applied":
            expected = {**row["input"], **row["output"], "identity": entry["applied"]}
            if not _same(observed, expected):
                raise MigrationError("restore CAS refused later writes")
        elif entry["phase"] == "publish" and entry["stage"]:
            after_sha = row["output"]["sha256"]
            if _is_installed(observed, entry["stage"]["identity"], after_sha, row["input"]["identity"]):
                entry["applied"], entry["phase"] = observed["identity"], "applied"
            elif not _same(observed, row["input"]):
                raise MigrationError("interrupted publication has an unknown outcome")
        elif entry["phase"] == "restore":
            expected = {**row["input"], **row["output"], "identity": entry["applied"]}
            if (not _same(observed, expected)
                    and not _is_installed(observed, entry["stage"]["identity"], row["input"]["sha256"],
                                          row["input"]["identity"])):
                raise MigrationError("interrupted restoration has an unknown outcome")
        elif entry["phase"] == "restored":
            expected = {**row["input"], "identity": entry["restored"]}
            if not _same(observed, expected):
                raise MigrationError("a restored file changed")
    if not was_restored:
        state["phase"] = "restoring"
        _event(directory, state, None, "restore-preimages-began")
    for index, (row, (before, _)) in enumerate(zip(plan["files"], outputs)):
        entry = state["files"][index]
        if entry["phase"] == "restored":
            observed, _ = snapshot(row["input"]["path"], plain=True)
            expected = {**row["input"], "identity": entry["restored"]}
            if not _same(observed, expected):
                raise MigrationError("a restored file changed")
        elif entry["phase"] in ("applied", "restore"):
            expected = {**row["input"], **row["output"], "identity": entry["applied"]}
            _publish(directory, state, index, row, expected, before, restoring=True)
        elif entry["phase"] == "publish":
            # The source is still its verified preimage. Remove only this
            # journal's exact recorded staging inode, never an unbound name.
            stage = entry["stage"]
            with _parent(row["input"]["path"]) as (parent, _, _):
                try:
                    info = os.stat(stage["name"], dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    # Either the name was not durable or cleanup completed
                    # before its checkpoint. No source publication occurred.
                    pass
                else:
                    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                            or _inode(info) != stage["identity"]):
                        raise MigrationError("unpublished staging identity changed; retain evidence")
                    os.unlink(stage["name"], dir_fd=parent)
                os.fsync(parent)
            entry["phase"], entry["stage"] = "pending", None
            _event(directory, state, index, "unpublished-owned-stage-removed")
        elif entry["phase"] == "pending":
            with _parent(row["input"]["path"]) as (parent, _, _):
                stage_name = _stage_name(state, index, "publish")
                try:
                    os.stat(stage_name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise MigrationError("unbound staging remains; explicit owner reconciliation is required")
    for index, row in enumerate(plan["files"]):
        entry = state["files"][index]
        if entry["phase"] == "restored":
            observed, _ = snapshot(row["input"]["path"], plain=True)
            expected = {**row["input"], "identity": entry["restored"]}
            if not _same(observed, expected):
                raise MigrationError("a restored file changed before recovery verification")
    state["phase"] = "restored"
    if not was_restored:
        _event(directory, state, None, "batch-preimages-restored")
    return {"phase": state["phase"], "files": len(plan["files"]),
            "restoredFiles": sum(row["phase"] == "restored" for row in state["files"]),
            "neverPublishedFiles": sum(row["phase"] == "pending" for row in state["files"]),
            "planSha256": state["planSha256"]}


def add_operator_arguments(parser):
    parser.add_argument("--plan", type=Path, help="save a new private exact preview plan (no input writes)")
    parser.add_argument("--apply-plan", type=Path, help="apply this already reviewed plan")
    parser.add_argument("--plan-sha256", help="exact SHA-256 printed by the reviewed preview")
    parser.add_argument("--state-dir", type=Path, help="new private preimage/recovery directory for first apply")
    parser.add_argument("--resume", type=Path, help="resume this private partial migration journal")
    parser.add_argument("--restore-preimages", type=Path, help="restore only unchanged tool-written postimages")
    parser.add_argument("--attest-quiescent", action="store_true", help="operator has stopped all selected writers")
    parser.add_argument("--apply", action="store_true", help="obsolete unsafe mode; refuses without effects")


def operator_action(args, *, tool, convert, serialize=encode_document, tool_files=()):
    if args.apply:
        raise MigrationError("--apply is unsafe without a reviewed plan; use --apply-plan and --plan-sha256")
    actions = sum(bool(value) for value in (args.apply_plan, args.resume, args.restore_preimages))
    if actions > 1:
        raise MigrationError("choose one apply or recovery action")
    if not actions:
        if args.plan_sha256 or args.state_dir or args.attest_quiescent:
            raise MigrationError("apply/recovery options require their explicit action")
        return None
    if args.plan:
        raise MigrationError("preview-plan output is separate from apply/recovery")
    if args.apply_plan:
        if args.state_dir is None:
            raise MigrationError("first apply requires a new --state-dir")
        plan_path, state_path, action = args.apply_plan, args.state_dir, "apply"
    else:
        if args.state_dir is not None:
            raise MigrationError("recovery names its existing journal directly")
        state_path = args.resume or args.restore_preimages
        plan_path = state_path / "plan.json"
        action = "resume" if args.resume else "restore-preimages"
    return operate(plan_path, args.plan_sha256, state_path, tool=tool, transform=convert,
                   serialize=serialize, tool_files=tool_files, action=action,
                   attest_quiescent=args.attest_quiescent)


def report_preview(plan, path=None):
    digest = save_plan(path, plan) if path else sha256(encode(plan))
    return {"dryRun": True, "planWritten": path is not None, "planSha256": digest,
            "files": [{"path": row["input"]["path"], "kind": row["kind"],
                       "inputSha256": row["input"]["sha256"],
                       "outputSha256": row["output"]["sha256"], "changes": row["changes"]}
                      for row in plan["files"]]}
