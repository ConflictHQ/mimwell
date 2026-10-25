"""Private, stability-checked upgrade snapshots; restored authorities stay standby."""

from copy import deepcopy
import contextvars
from dataclasses import dataclass
try:
    import fcntl
except ImportError:  # pragma: no cover - v2 capture requires POSIX descriptor flags.
    fcntl = None
import hashlib
import json
import os
from pathlib import Path
import re
import select
import selectors
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from types import MappingProxyType

try:
    import resource
except ImportError:  # pragma: no cover - bounded v2 index writing refuses on Windows.
    resource = None

from knowledge_policy import fingerprint
from owned_process import (
    OwnedProcessError, require_waitid as _owned_require_waitid,
    observe_unreaped_leader as _owned_observe_unreaped_leader,
    wait_unreaped_leader as _owned_wait_unreaped_leader,
    kill_process_group as _owned_kill_process_group,
)
from knowledge_store import SQLiteAuthority, StoreError


class SnapshotError(ValueError):
    pass


@dataclass(frozen=True)
class AdmittedRestoreContext:
    """Trusted host-selected authorization pins for an adopted restore.

    This is an in-process API object; request JSON cannot supply callbacks or identity.
    """
    brain_root: Path
    brain_root_identity: tuple
    actor: str
    restore_grant: str
    host_config_sha256: str
    client_config_sha256: str
    registration_sha256: str
    destination_path: Path
    destination_parent_identity: tuple
    retained_root_id: str
    retained_root_kind: str
    retained_root_path: Path
    retained_root_identity: tuple
    authority_path: Path
    authority_file_identity: tuple
    authority_store_id: str
    authority_binding: str
    authority_instance: str
    authority_checkpoint: dict
    actor_mapping: dict
    actor_mapping_sha256: str
    guard: object

    def __post_init__(self):
        if (not isinstance(self.brain_root, Path) or not self.brain_root.is_absolute()
                or not isinstance(self.authority_path, Path) or not self.authority_path.is_absolute()
                or not isinstance(self.destination_path, Path) or not self.destination_path.is_absolute()
                or not isinstance(self.retained_root_path, Path) or not self.retained_root_path.is_absolute()
                or ".." in self.brain_root.parts or ".." in self.authority_path.parts
                or ".." in self.destination_path.parts or ".." in self.retained_root_path.parts
                or not self.authority_path.is_relative_to(self.brain_root)
                or self.authority_path == self.brain_root
                or self.destination_path == self.retained_root_path
                or not self.destination_path.parent.is_relative_to(self.retained_root_path)):
            raise SnapshotError("Admitted restore context paths must be absolute")
        for identity in (self.brain_root_identity, self.authority_file_identity,
                         self.destination_parent_identity,
                         self.retained_root_identity):
            if (not isinstance(identity, tuple) or len(identity) != 2
                    or any(type(part) is not int or part < 0 for part in identity)):
                raise SnapshotError("Admitted restore context file identity is invalid")
        for value in (self.host_config_sha256, self.client_config_sha256,
                      self.registration_sha256, self.actor_mapping_sha256):
            if not _context_sha256(value):
                raise SnapshotError("Admitted restore context digest is invalid")
        if (not isinstance(self.actor, str) or not self.actor.strip() or len(self.actor) > 512
                or self.restore_grant != "snapshot.restore"
                or not isinstance(self.authority_binding, str) or not self.authority_binding
                or len(self.authority_binding) > 256
                or not isinstance(self.authority_store_id, str) or not self.authority_store_id
                or len(self.authority_store_id) > 256
                or not isinstance(self.retained_root_id, str)
                or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", self.retained_root_id) is None
                or self.retained_root_kind not in ("snapshot", "backup")
                or not isinstance(self.authority_instance, str) or not self.authority_instance
                or len(self.authority_instance) > 256 or not callable(self.guard)):
            raise SnapshotError("Admitted restore context identity is invalid")
        checkpoint = _freeze_restore_json(self.authority_checkpoint)
        mapping = _freeze_restore_json(self.actor_mapping)
        if not isinstance(checkpoint, MappingProxyType) or not isinstance(mapping, MappingProxyType):
            raise SnapshotError("Admitted restore context pins have an invalid shape")
        checkpoint_shape = {"instance", "status", "sequence", "digest"}
        if (set(checkpoint) != checkpoint_shape or checkpoint["status"] != "active"
                or not isinstance(checkpoint["instance"], str)
                or checkpoint["instance"] != self.authority_instance
                or type(checkpoint["sequence"]) is not int or checkpoint["sequence"] < 0
                or not _context_sha256(checkpoint["digest"])):
            raise SnapshotError("Admitted restore context checkpoint is invalid")
        if (any(not uid.isdecimal() or not isinstance(principal, str) or not principal.strip()
                for uid, principal in mapping.items())
                or self.actor not in mapping.values()
                or fingerprint(dict(self.actor_mapping)) != self.actor_mapping_sha256):
            raise SnapshotError("Admitted restore context actor mapping is invalid")
        object.__setattr__(self, "authority_checkpoint", checkpoint)
        object.__setattr__(self, "actor_mapping", mapping)

    def revalidate(self):
        if not callable(self.guard):
            raise SnapshotError("Admitted restore host guard is unavailable")
        self.guard()


def _new_admitted_restore_intent(context, *, snapshot_sha256, source_identity,
                                 destination_identity):
    """Mint the pre-stage ledger payload from a freshly checked host context.

    This records intent only. Callers must durably reserve it before creating the
    empty stage directory, then bind that directory's opened inode before writing.
    """
    if not isinstance(context, AdmittedRestoreContext) or context.restore_grant != "snapshot.restore":
        raise SnapshotError("Admitted restore requires an explicit snapshot.restore host grant")
    context.guard()
    if not _context_sha256(snapshot_sha256):
        raise SnapshotError("Restore snapshot digest is invalid")
    source_keys = {"path", "device", "inode", "size", "mtimeNs", "ctimeNs"}
    destination_keys = {"path", "parentDevice", "parentInode", "parentMtimeNs", "parentCtimeNs"}
    if (not isinstance(source_identity, dict) or set(source_identity) != source_keys
            or not isinstance(destination_identity, dict) or set(destination_identity) != destination_keys):
        raise SnapshotError("Restore source or destination identity is invalid")
    for value, keys in ((source_identity, source_keys), (destination_identity, destination_keys)):
        path = value.get("path")
        if (not isinstance(path, str) or len(path) > 4096 or not Path(path).is_absolute()
                or ".." in Path(path).parts or str(Path(path)) != path or "\x00" in path
                or any(type(value[key]) is not int or not 0 <= value[key] < 2**64
                       for key in keys - {"path"})):
            raise SnapshotError("Restore source or destination identity is invalid")
    destination_path = Path(destination_identity["path"])
    if (destination_path != context.destination_path
            or not destination_path.parent.is_relative_to(context.retained_root_path)
            or context.retained_root_path == destination_path
            or (destination_identity["parentDevice"], destination_identity["parentInode"])
            != context.destination_parent_identity):
        raise SnapshotError("Restore destination is outside its pinned registered root")
    operation_id, stage_token = uuid.uuid4().hex, uuid.uuid4().hex
    stage_path = destination_path.with_name(f".{destination_path.name}.restore-{stage_token}")
    if not stage_path.parent.is_relative_to(context.retained_root_path):
        raise SnapshotError("Restore stage is outside its pinned registered root")
    payload = {
        "protocol": "admitted-restore-intent/v2",
        "phase": "pre-stage",
        "operationId": operation_id,
        "stageToken": stage_token,
        "stagePath": str(stage_path),
        "snapshotSha256": snapshot_sha256,
        "source": dict(source_identity),
        "destination": dict(destination_identity),
        "retainedRoot": {"id": context.retained_root_id, "kind": context.retained_root_kind,
                         "path": str(context.retained_root_path),
                         "device": context.retained_root_identity[0],
                         "inode": context.retained_root_identity[1]},
        "registrationSha256": context.registration_sha256,
        "hostConfigSha256": context.host_config_sha256,
        "clientConfigSha256": context.client_config_sha256,
        "authorityBinding": context.authority_binding,
        "authorityStoreId": context.authority_store_id,
        "authorityInstance": context.authority_instance,
        "authorityCheckpoint": {"sequence": context.authority_checkpoint["sequence"],
                                "digest": context.authority_checkpoint["digest"]},
        "actor": context.actor,
        "actorMapping": dict(context.actor_mapping),
        "actorMappingSha256": context.actor_mapping_sha256,
        "authorizationGrant": context.restore_grant,
    }
    try:
        encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                             allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise SnapshotError("Restore intent is not bounded JSON") from exc
    if len(encoded) > 16 * 1024:
        raise SnapshotError("Restore intent exceeds its fixed byte bound")
    return payload

def _context_sha256(value):
    return (isinstance(value, str) and len(value) == 64
            and all(character in "0123456789abcdef" for character in value))


def _freeze_restore_json(value):
    """Copy a small JSON pin tree into immutable containers for the context lifetime."""
    pending = [(value, 0)]
    total_bytes = 0
    item_count = 0
    while pending:
        item, depth = pending.pop()
        item_count += 1
        if item_count > 4096 or depth > 64:
            raise SnapshotError("Admitted restore context pin exceeds its structural bound")
        if isinstance(item, dict):
            if len(item) > 4096 or any(not isinstance(key, str) for key in item):
                raise SnapshotError("Admitted restore context pin has an invalid object")
            pending.extend((key, depth + 1) for key in item)
            pending.extend((nested, depth + 1) for nested in item.values())
        elif isinstance(item, list):
            if len(item) > 4096:
                raise SnapshotError("Admitted restore context pin has an oversized array")
            pending.extend((nested, depth + 1) for nested in item)
        elif isinstance(item, str):
            if len(item) > 16 * 1024:
                raise SnapshotError("Admitted restore context pin has an oversized string")
            try:
                total_bytes += len(item.encode("utf-8"))
            except UnicodeEncodeError as exc:
                raise SnapshotError("Admitted restore context pin has invalid text") from exc
        elif type(item) is int:
            if item.bit_length() > 4096:
                raise SnapshotError("Admitted restore context pin has an oversized integer")
            total_bytes += max(1, (item.bit_length() + 7) // 8)
        elif item is not None and type(item) is not bool:
            raise SnapshotError("Admitted restore context pin contains an unsupported value")
        if total_bytes > 16 * 1024:
            raise SnapshotError("Admitted restore context pin exceeds its fixed byte bound")
    try:
        raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                         allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise SnapshotError("Admitted restore context pin is not bounded JSON") from exc
    if len(raw) > 16 * 1024:
        raise SnapshotError("Admitted restore context pin exceeds its fixed byte bound")

    def freeze(item):
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise SnapshotError("Admitted restore context pin has a non-string key")
            return MappingProxyType({key: freeze(nested) for key, nested in item.items()})
        if isinstance(item, list):
            return tuple(freeze(nested) for nested in item)
        if item is None or isinstance(item, str) or type(item) in (bool, int):
            return item
        raise SnapshotError("Admitted restore context pin contains an unsupported value")

    return freeze(value)


def _assert_restore_context_basis(context, current):
    expected = {
        "actor": context.actor,
        "restoreGrant": context.restore_grant,
        "actorMapping": dict(context.actor_mapping),
        "actorMappingSha256": context.actor_mapping_sha256,
        "authorityBinding": context.authority_binding,
        "authorityCheckpoint": dict(context.authority_checkpoint),
        "authorityFileIdentity": context.authority_file_identity,
        "authorityInstance": context.authority_instance,
        "authorityPath": context.authority_path,
        "authorityStoreId": context.authority_store_id,
        "brainRoot": context.brain_root,
        "brainRootIdentity": context.brain_root_identity,
        "clientConfigSha256": context.client_config_sha256,
        "hostConfigSha256": context.host_config_sha256,
        "registrationSha256": context.registration_sha256,
        "destinationPath": context.destination_path,
        "destinationParentIdentity": context.destination_parent_identity,
        "retainedRootId": context.retained_root_id,
        "retainedRootKind": context.retained_root_kind,
        "retainedRootPath": context.retained_root_path,
        "retainedRootIdentity": context.retained_root_identity,
    }
    if current != expected:
        raise SnapshotError("Admitted restore context no longer matches its authenticated host pins")


def _sticky_restore_guard(check):
    """Make any observed freshness mismatch permanently invalidate this context."""
    invalidated = False

    def guard():
        nonlocal invalidated
        if invalidated:
            raise SnapshotError("Admitted restore context was previously invalidated")
        try:
            check()
        except BaseException:
            invalidated = True
            raise

    return guard


_HOST_LOCAL_ADMISSION_FILES = {
    "_internal/brain-storage-admission.json",
    "_internal/brain-storage-admission.sqlite3",
    "_internal/brain-storage-admission.lock",
    "_internal/brain-storage-admission-writer.lock",
    "_internal/brain-storage-admission.sqlite3-wal",
    "_internal/brain-storage-admission.sqlite3-shm",
    "_internal/brain-storage-admission.sqlite3-journal",
}

_V2_MANIFEST_LIMIT = 64 * 1024 * 1024
_V2_COMMAND_TIMEOUT = 900
_V2_COMMAND_OUTPUT_LIMIT = 256 * 1024 * 1024
_V2_REF_COUNT_LIMIT = 100_000
_V2_REF_OUTPUT_LIMIT = 16 * 1024 * 1024
_V2_INVENTORY_ENTRY_LIMIT = 250_000
_V2_INVENTORY_OUTPUT_LIMIT = 64 * 1024 * 1024
_V2_INVENTORY_FILE_LIMIT = 512 * 1024 * 1024
_V2_INVENTORY_TREE_LIMIT = 8 * 1024 * 1024 * 1024
_V2_SOURCE_WORKER_TIMEOUT = 900
_V2_ACTIVE_SOURCE_WORKER = contextvars.ContextVar("v2_snapshot_source_worker", default=None)


def _v2_git_command(root, *args, git_dir=None):
    command = ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c",
            "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null", "-c",
            "diff.external=", "-c", "protocol.allow=never", "-c", "protocol.file.allow=never",
            "-c", "pack.threads=1", "-c", "pack.windowMemory=16m"]
    if git_dir is None:
        command.extend(("-C", str(root)))
    else:
        if not isinstance(git_dir, str) or not Path(git_dir).is_absolute():
            raise SnapshotError("Selected Git directory is invalid")
        command.append("--git-dir=" + git_dir)
    command.extend(args)
    return command


def _v2_git_env():
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
                "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
                "LC_ALL": "C", "LANG": "C"})
    return env


_V2_OWNED_PROCESS_ERRORS = {'Safe process-group cleanup is unavailable on this platform': 'Safe Git process-group cleanup is unavailable on this platform', 'Cannot safely confirm ownership of the process group': 'Cannot safely confirm ownership of the Git process group', 'Process wait returned an unrelated child identity': 'Git process wait returned an unrelated child identity', 'Process did not terminate within its cleanup bound': 'Git snapshot process did not terminate within its cleanup bound', 'Process group cleanup failed': 'Git snapshot process group cleanup failed'}


def _v2_kill_process_group(child):
    """Keep the snapshot error interface over shared owned-group cleanup."""
    try:
        _owned_kill_process_group(child)
    except OwnedProcessError as exc:
        raise SnapshotError(_V2_OWNED_PROCESS_ERRORS.get(str(exc), str(exc))) from exc


def _v2_require_waitid():
    """Require the shared owned-process boundary before launching Git."""
    try:
        _owned_require_waitid()
    except OwnedProcessError as exc:
        raise SnapshotError(_V2_OWNED_PROCESS_ERRORS.get(str(exc), str(exc))) from exc


def _v2_observe_unreaped_leader(child):
    """Keep the snapshot error interface over shared non-reaping observation."""
    try:
        return _owned_observe_unreaped_leader(child)
    except OwnedProcessError as exc:
        raise SnapshotError(_V2_OWNED_PROCESS_ERRORS.get(str(exc), str(exc))) from exc


def _v2_wait_unreaped_leader(child, timeout, timeout_message):
    """Wait without reaping; snapshot callers retain the original None return."""
    try:
        _owned_wait_unreaped_leader(child, timeout, timeout_message)
    except OwnedProcessError as exc:
        raise SnapshotError(_V2_OWNED_PROCESS_ERRORS.get(str(exc), str(exc))) from exc


def _v2_git(root, *args, input_path=None, output_limit=_V2_COMMAND_OUTPUT_LIMIT,
            timeout=_V2_COMMAND_TIMEOUT, pass_fds=(), file_size_limit=None,
            cwd_fd=None, git_dir=None):
    """Run a bounded read-only Git command with controlled config and process-group cleanup."""
    if type(output_limit) is not int or output_limit < 0:
        raise SnapshotError("Git output budget is invalid")
    _v2_require_waitid()
    if cwd_fd is not None:
        try:
            info = os.fstat(cwd_fd)
        except OSError as exc:
            raise SnapshotError("Git staging directory descriptor is unavailable") from exc
        if not stat.S_ISDIR(info.st_mode):
            raise SnapshotError("Git staging directory descriptor is invalid")
        if git_dir is None:
            raise SnapshotError("Staged Git command lacks its selected source Git directory")
    command = _v2_git_command(root, *args, git_dir=git_dir)
    if file_size_limit is not None:
        if type(file_size_limit) is not int or file_size_limit <= 0:
            raise SnapshotError("Git file output budget is invalid")
        if not sys.executable or resource is None or not hasattr(resource, "RLIMIT_FSIZE"):
            raise SnapshotError("Bounded Git index writer is unavailable on this platform")
    if cwd_fd is not None or file_size_limit is not None:
        wrapper = ("import os,sys\n"
                   "fd=int(sys.argv[1]); limit=int(sys.argv[2])\n"
                   "if fd >= 0:\n    os.fchdir(fd)\n"
                   "if limit > 0:\n"
                   "    import resource\n"
                   "    soft,hard=resource.getrlimit(resource.RLIMIT_FSIZE)\n"
                   "    limit=min(limit,soft) if soft != resource.RLIM_INFINITY else limit\n"
                   "    limit=min(limit,hard) if hard != resource.RLIM_INFINITY else limit\n"
                   "    resource.setrlimit(resource.RLIMIT_FSIZE,(limit,hard))\n"
                   "os.umask(0o077)\n"
                   "os.execvpe(sys.argv[3],sys.argv[3:],os.environ)\n")
        command = [sys.executable, "-I", "-S", "-c", wrapper,
                   str(cwd_fd if cwd_fd is not None else -1),
                   str(file_size_limit if file_size_limit is not None else 0), *command]
    owns_stdin = input_path is not None and hasattr(input_path, "open")
    stdin = input_path.open("rb") if owns_stdin else input_path or subprocess.DEVNULL
    child = None
    group_cleanup_attempted = False
    output = bytearray()
    try:
        child_pass_fds = set(pass_fds)
        if cwd_fd is not None:
            child_pass_fds.add(cwd_fd)
        child = subprocess.Popen(command, cwd="/", env=_v2_git_env(), stdin=stdin,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 start_new_session=True, pass_fds=tuple(sorted(child_pass_fds)))
        if child.stdout is None:
            raise SnapshotError("Git output stream is unavailable")
        os.set_blocking(child.stdout.fileno(), False)
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SnapshotError("Git snapshot command exceeded its time bound")
                for key, _ in selector.select(min(0.1, remaining)):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if len(output) + len(chunk) > output_limit:
                        raise SnapshotError("Git snapshot command exceeded its output bound")
                    output.extend(chunk)
        _v2_wait_unreaped_leader(
            child, max(0.01, deadline - time.monotonic()), "Git snapshot command exceeded its time bound")
        group_cleanup_attempted = True
        _v2_kill_process_group(child)
        if child.returncode != 0:
            raise SnapshotError("Git snapshot command failed")
        return bytes(output)
    except (OSError, subprocess.SubprocessError) as exc:
        raise SnapshotError("Git snapshot command is unavailable") from exc
    finally:
        try:
            if child is not None and not group_cleanup_attempted:
                group_cleanup_attempted = True
                _v2_kill_process_group(child)
        finally:
            try:
                if child is not None and child.stdout is not None:
                    child.stdout.close()
            finally:
                if owns_stdin:
                    stdin.close()


def _v2_git_to_file(root, output_dir_fd, output_name, max_bytes, *args, input_fd=None,
                    timeout=_V2_COMMAND_TIMEOUT, pass_fds=()):
    """Stream bounded Git stdout to an exclusive file beneath a pinned directory fd."""
    _v2_require_waitid()
    descriptor = None
    child = None
    group_cleanup_attempted = False
    written = 0
    try:
        if input_fd is not None:
            if type(input_fd) is not int:
                raise SnapshotError("Git pack input descriptor is invalid")
            if fcntl is None:
                raise SnapshotError("Git pack input descriptor checks are unavailable")
            try:
                input_info = os.fstat(input_fd)
                input_flags = fcntl.fcntl(input_fd, fcntl.F_GETFL)
            except OSError as exc:
                raise SnapshotError("Git pack input descriptor is unavailable") from exc
            if (not stat.S_ISREG(input_info.st_mode)
                    or input_flags & os.O_ACCMODE == os.O_WRONLY):
                raise SnapshotError("Git pack input descriptor is invalid")
        descriptor, identity = _v2_stage_create(output_dir_fd, output_name)
        child_pass_fds = set(pass_fds)
        if input_fd is not None:
            child_pass_fds.add(input_fd)
        child = subprocess.Popen(_v2_git_command(root, *args), cwd="/", env=_v2_git_env(),
                                 stdin=(input_fd if input_fd is not None else subprocess.DEVNULL),
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 start_new_session=True, pass_fds=tuple(sorted(child_pass_fds)))
        if child.stdout is None:
            raise SnapshotError("Git pack output stream is unavailable")
        os.set_blocking(child.stdout.fileno(), False)
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SnapshotError("Git pack writer exceeded its time bound")
                for key, _ in selector.select(min(0.1, remaining)):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if written + len(chunk) > max_bytes:
                        raise SnapshotError("Git pack writer exceeded its planned byte bound")
                    offset = 0
                    while offset < len(chunk):
                        count = os.write(descriptor, chunk[offset:])
                        if count <= 0:
                            raise SnapshotError("Git pack writer made no output progress")
                        offset += count
                    written += len(chunk)
        os.fsync(descriptor)
        _v2_verify_stage_file(output_dir_fd, output_name, descriptor, identity,
                              expected_size=written, max_bytes=max_bytes)
        _v2_wait_unreaped_leader(
            child, max(0.01, deadline - time.monotonic()), "Git pack writer exceeded its time bound")
        group_cleanup_attempted = True
        _v2_kill_process_group(child)
        if child.returncode != 0:
            raise SnapshotError("Git pack writer failed")
        return written
    except (OSError, subprocess.SubprocessError) as exc:
        raise SnapshotError("Git pack writer is unavailable") from exc
    finally:
        try:
            if child is not None and not group_cleanup_attempted:
                group_cleanup_attempted = True
                _v2_kill_process_group(child)
        finally:
            try:
                if child is not None and child.stdout is not None:
                    child.stdout.close()
            finally:
                if descriptor is not None:
                    os.close(descriptor)


def _v2_git_input(root, input_bytes, *args, output_limit=1024 * 1024, timeout=120):
    """Run a batch request through the bounded Git pipe runner."""
    if not isinstance(input_bytes, bytes) or len(input_bytes) > 32 * 1024 * 1024:
        raise SnapshotError("Git batch input exceeds its fixed byte bound")
    if type(output_limit) is not int or output_limit < 0 or type(timeout) not in (int, float) or timeout <= 0:
        raise SnapshotError("Git batch process bounds are invalid")
    try:
        with tempfile.TemporaryFile(mode="w+b") as input_file:
            input_file.write(input_bytes)
            input_file.flush()
            input_file.seek(0)
            return _v2_git(root, *args, input_path=input_file, output_limit=output_limit,
                           timeout=timeout)
    except OSError as exc:
        raise SnapshotError("Git batch request is unavailable") from exc


def _v2_object_ids(root, refs, head, *, object_format):
    from brain_snapshot_v2 import MAX_GIT_OBJECTS

    _, oid_length = ("sha1", 40) if object_format == "sha1" else ("sha256", 64)
    raw = _v2_git(root, "rev-list", "--objects", "--all", "--no-object-names", "HEAD",
                   output_limit=MAX_G2_OBJECT_LIST_BYTES)
    if raw.count(b"\n") > MAX_GIT_OBJECTS:
        raise SnapshotError("Git reachable-object inventory exceeds its row bound")
    identities = set()
    for line in raw.splitlines():
        if len(line) != oid_length or any(byte not in b"0123456789abcdef" for byte in line):
            raise SnapshotError("Git reachable-object listing is malformed")
        identities.add(line.decode("ascii"))
        if len(identities) > MAX_GIT_OBJECTS:
            raise SnapshotError("Git reachable-object inventory exceeds its count bound")
    identities.add(head)
    for ref in refs:
        identities.add(ref["oid"])
    if len(identities) > MAX_GIT_OBJECTS:
        raise SnapshotError("Git reachable-object inventory exceeds its count bound")
    return sorted(identities)


MAX_G2_OBJECT_LIST_BYTES = 256 * 1024 * 1024
_V2_OBJECT_BATCH_COUNT = 4096
_V2_BLOB_BATCH_BYTES = 16 * 1024 * 1024


def _v2_object_sizes(root, object_ids):
    sizes = {}
    for offset in range(0, len(object_ids), _V2_OBJECT_BATCH_COUNT):
        batch = object_ids[offset:offset + _V2_OBJECT_BATCH_COUNT]
        raw = _v2_git_input(root, ("\n".join(batch) + "\n").encode("ascii"), "cat-file",
                             "--batch-check=%(objectname) %(objecttype) %(objectsize)",
                             output_limit=1024 * 1024)
        rows = raw.splitlines()
        if len(rows) != len(batch):
            raise SnapshotError("Git object-size inventory is incomplete")
        for expected, row in zip(batch, rows):
            fields = row.split(b" ")
            if len(fields) != 3 or fields[0].decode("ascii", "strict") != expected:
                raise SnapshotError("Git object-size inventory is malformed")
            kind = fields[1]
            if kind not in {b"commit", b"tree", b"blob", b"tag"} or not fields[2].isdigit():
                raise SnapshotError("Git object inventory contains a missing or unsupported object")
            size = int(fields[2])
            if size > 512 * 1024 * 1024:
                raise SnapshotError("Git object exceeds its individual size bound")
            sizes[expected] = size
    return sizes


def _v2_cat_file_batch(root, object_ids, sizes):
    """Read only indexed blobs in small batches, bounding subprocess and retained bytes."""
    blobs = {}
    from brain_snapshot_v2 import MAX_STAGED_BLOBS_BYTES, MAX_STAGED_BLOB_BYTES

    total = 0
    batch, batch_bytes = [], 0

    def consume(selected):
        if not selected:
            return
        expected_total = sum(sizes[oid] for oid in selected)
        input_bytes = ("\n".join(selected) + "\n").encode("ascii")
        maximum = expected_total + len(selected) * 128 + 1
        raw = _v2_git_input(root, input_bytes, "cat-file", "--batch",
                            output_limit=maximum, timeout=120)
        cursor = 0
        for oid in selected:
            end = raw.find(b"\n", cursor, min(len(raw), cursor + 129))
            if end < 0:
                raise SnapshotError("Git staged-blob batch header is malformed")
            header = raw[cursor:end].split(b" ")
            if (len(header) != 3 or header[0].decode("ascii", "strict") != oid
                    or header[1] != b"blob" or not header[2].isdigit()):
                raise SnapshotError("Git staged index references an unavailable non-blob object")
            size = int(header[2])
            if size != sizes[oid] or size > MAX_STAGED_BLOB_BYTES:
                raise SnapshotError("Git staged blob differs from its bounded size inventory")
            cursor = end + 1
            stop = cursor + size
            if stop >= len(raw) or raw[stop:stop + 1] != b"\n":
                raise SnapshotError("Git staged-blob batch content is truncated")
            blobs[oid] = raw[cursor:stop]
            cursor = stop + 1
        if cursor != len(raw):
            raise SnapshotError("Git staged-blob batch has trailing output")

    for oid in object_ids:
        size = sizes[oid]
        if size > MAX_STAGED_BLOB_BYTES:
            raise SnapshotError("Git staged blob exceeds its individual size bound")
        if batch and (len(batch) >= 1024 or batch_bytes + size > _V2_BLOB_BATCH_BYTES):
            consume(batch)
            batch, batch_bytes = [], 0
        batch.append(oid)
        batch_bytes += size
        total += size
        if total > MAX_STAGED_BLOBS_BYTES:
            raise SnapshotError("Git staged blobs exceed their aggregate byte bound")
    consume(batch)
    return blobs


def _v2_verify_pack(root, git_dir_pin, stage_fd, pack_name, expected_sizes,
                    max_index_bytes, *, expected_pack_identity=None, pass_fds=()):
    """Index and verify a staged pack by basename from an isolated fd-based cwd."""
    pack_name = _v2_stage_name(pack_name)
    if not pack_name.endswith(".pack"):
        raise SnapshotError("Git pack artifact name is invalid")
    pack_fd, pack_identity = _v2_stage_open(stage_fd, pack_name)
    try:
        pack_info = _v2_verify_stage_file(stage_fd, pack_name, pack_fd, pack_identity,
                                          max_bytes=_V2_COMMAND_OUTPUT_LIMIT)
        if expected_pack_identity is not None and expected_pack_identity != pack_identity:
            raise SnapshotError("Git pack artifact was replaced")
        index_name = pack_name[:-5] + ".idx"
        _v2_stage_require_absent(stage_fd, index_name)
        _v2_verify_git_directory(root, git_dir_pin)
        _v2_git(root, "index-pack", "--strict", "--threads=1", "--no-rev-index",
                f"--max-input-size={pack_info.st_size}", pack_name, output_limit=64 * 1024,
                pass_fds=pass_fds, file_size_limit=max_index_bytes, cwd_fd=stage_fd,
                git_dir=git_dir_pin["path"])
        _v2_verify_git_directory(root, git_dir_pin)
        _v2_verify_stage_file(stage_fd, pack_name, pack_fd, pack_identity,
                              max_bytes=_V2_COMMAND_OUTPUT_LIMIT)
        sealed_index_identity = _v2_stage_seal_generated(stage_fd, index_name, max_index_bytes)
        index_fd, index_identity = _v2_stage_open(stage_fd, index_name, os.O_RDONLY)
        try:
            if index_identity != sealed_index_identity:
                raise SnapshotError("Git index artifact was replaced after sealing")
            _v2_verify_stage_file(stage_fd, index_name, index_fd, index_identity,
                                  max_bytes=max_index_bytes)
        finally:
            os.close(index_fd)
        _v2_verify_git_directory(root, git_dir_pin)
        verified = _v2_git(root, "verify-pack", "-v", index_name,
                           output_limit=MAX_G2_OBJECT_LIST_BYTES, pass_fds=pass_fds,
                           cwd_fd=stage_fd, git_dir=git_dir_pin["path"])
        _v2_verify_git_directory(root, git_dir_pin)
        _v2_verify_stage_file(stage_fd, pack_name, pack_fd, pack_identity,
                              max_bytes=_V2_COMMAND_OUTPUT_LIMIT)
        _v2_verify_stage_named_file(stage_fd, index_name, index_identity,
                                    max_bytes=max_index_bytes)
    finally:
        os.close(pack_fd)
    found = {}
    for line in verified.splitlines():
        fields = line.split()
        if not fields or len(fields[0]) not in (40, 64):
            continue  # verify-pack summary line
        if len(fields) != 5:
            raise SnapshotError("Git pack contains delta entries or an unsupported object row")
        oid = fields[0].decode("ascii", "strict")
        if fields[1] not in {b"commit", b"tree", b"blob", b"tag"} or not fields[2].isdigit():
            raise SnapshotError("Git verified pack inventory is malformed")
        if oid in found:
            raise SnapshotError("Git pack contains a duplicate object")
        found[oid] = int(fields[2])
    if found != expected_sizes:
        raise SnapshotError("Git pack inventory differs from its exact capture manifest")
    return index_name


def _git(root, *args):
    command = ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
               "-c", "diff.external=", "-C", str(root), *args]
    result = subprocess.run(command, capture_output=True)
    if result.returncode:
        raise SnapshotError("Git snapshot operation failed: " + os.fsdecode(result.stderr).strip())
    return result.stdout


def _git_bundle_upper_bound(root, refs):
    """Conservative pack/bundle byte bound derived from every local object size."""
    command = ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
               "-C", str(root), "cat-file", "--batch-all-objects", "--batch-check=%(objectsize)"]
    process = None
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        count = total = 0
        if process.stdout is None:
            raise SnapshotError("Repository object inventory is unavailable")
        with process.stdout:
            for line in process.stdout:
                if len(line) > 32 or not line.strip().isdigit():
                    process.kill()
                    raise SnapshotError("Repository object inventory is malformed")
                size = int(line)
                count += 1
                total += size
                if count > 2_000_000 or total > 2**63 - 1:
                    process.kill()
                    raise SnapshotError("Repository object inventory exceeds its bound")
        if process.wait(timeout=60) != 0:
            raise SnapshotError("Repository object inventory is unavailable")
    except (OSError, subprocess.SubprocessError) as exc:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        raise SnapshotError("Repository object inventory is unavailable") from exc
    # Each packed entry includes an object header and zlib's worst-case growth
    # of the uncompressed object header+content, not an observed compression ratio.
    pack_bound = 12 + 20 + count * 10 + total + (total >> 12) + (total >> 14) + (total >> 25) + count * 13
    return pack_bound + len(refs) + 4096


def _relative(value):
    if not isinstance(value, str) or not value or "\x00" in value:
        raise SnapshotError("Expected a nonempty relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or str(path) == "." or any(p.casefold() == ".git" for p in path.parts):
        raise SnapshotError("Snapshot paths cannot escape a root or include .git")
    return path.as_posix()


def _within(path, parent):
    return path == parent or path.is_relative_to(parent)


def _safe(root, relative):
    relative = _relative(relative)
    path = root / relative
    for parent in path.parents:
        if parent == root:
            break
        if parent.is_symlink():
            raise SnapshotError("Snapshot paths cannot traverse symlink directories")
    return path


def _describe(path, *, allow_link=False, max_bytes=None):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) and allow_link:
        return {"type": "symlink", "target": os.readlink(path)}
    if not stat.S_ISREG(info.st_mode):
        raise SnapshotError("Only regular source files and explicit Git symlinks are supported")
    if max_bytes is not None and info.st_size > max_bytes:
        raise SnapshotError("Snapshot source file exceeds its fixed byte bound")
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            if max_bytes is not None and size + len(chunk) > max_bytes:
                raise SnapshotError("Snapshot source file changed beyond its fixed byte bound")
            digest.update(chunk)
            size += len(chunk)
    return {"type": "file", "sha256": digest.hexdigest(), "bytes": size,
            "mode": stat.S_IMODE(info.st_mode)}


class _V2SourceWorker:
    """Keep raw source opens and their closes in one fresh, bounded process."""

    def __init__(self):
        _v2_require_waitid()
        worker_path = Path(__file__).with_name("brain_snapshot_source_worker.py")
        self.child = None
        started = time.monotonic()
        try:
            info = worker_path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024
                    or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)):
                raise SnapshotError("Safe snapshot source worker is unavailable")
            self.child = subprocess.Popen(
                [sys.executable, "-I", "-S", str(worker_path)], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd="/",
                env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"},
                start_new_session=True, close_fds=True)
            if self.child.stdin is None or self.child.stdout is None:
                raise SnapshotError("Snapshot source worker pipes were not created")
            os.set_blocking(self.child.stdin.fileno(), False)
            os.set_blocking(self.child.stdout.fileno(), False)
        except BaseException as exc:
            child = self.child
            if child is not None:
                for pipe in (child.stdin, child.stdout):
                    if pipe is not None:
                        try:
                            pipe.close()
                        except OSError:
                            pass
                try:
                    cleanup_deadline = time.monotonic() + 8
                    self._stop_and_reap_child(
                        child, cleanup_deadline=cleanup_deadline,
                        graceful_deadline=cleanup_deadline - 1)
                except BaseException as cleanup_error:
                    raise SnapshotError("Snapshot source worker startup cleanup failed") from cleanup_error
            if isinstance(exc, SnapshotError):
                raise
            raise SnapshotError("Safe snapshot source worker could not start") from exc
        self.buffer = bytearray()
        self.closed = False
        self.failed = False
        self.deadline = started + _V2_SOURCE_WORKER_TIMEOUT

    def _check_deadline(self, deadline):
        if time.monotonic() >= deadline:
            self.failed = True
            raise SnapshotError("Snapshot source worker exceeded its time bound")

    @staticmethod
    def _observe_child_exit(child, deadline):
        while True:
            if time.monotonic() >= deadline:
                raise SnapshotError("Snapshot source worker cleanup exceeded its time bound")
            try:
                state = os.waitid(os.P_PID, child.pid,
                                  os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except InterruptedError:
                continue
            except OSError as exc:
                raise SnapshotError(
                    "Snapshot source worker waitability became uncertain") from exc
            if state is not None and state.si_pid not in (0, child.pid):
                raise SnapshotError("Snapshot source worker wait returned another child")
            return state is not None and state.si_pid == child.pid

    @classmethod
    def _stop_and_reap_child(cls, child, *, cleanup_deadline, graceful_deadline):
        """Stop one owned worker, reap its exact PID, and prove its group is gone."""
        graceful_deadline = min(graceful_deadline, cleanup_deadline)
        exited = False
        while time.monotonic() < graceful_deadline:
            if cls._observe_child_exit(child, cleanup_deadline):
                exited = True
                break
            remaining = graceful_deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.01, remaining))
        if not exited:
            # Revalidate ownership immediately before the sole signal. ECHILD or
            # any inspection error stops here; there is no fallback cleanup.
            if cls._observe_child_exit(child, cleanup_deadline):
                exited = True
            else:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError as exc:
                    raise SnapshotError(
                        "Snapshot source worker group cleanup failed") from exc
                while time.monotonic() < cleanup_deadline:
                    if cls._observe_child_exit(child, cleanup_deadline):
                        exited = True
                        break
                    remaining = cleanup_deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    time.sleep(min(0.01, remaining))
        if not exited:
            raise SnapshotError("Snapshot source worker did not exit before cleanup deadline")

        # WNOWAIT pinned the leader until this exact nonblocking waitpid. Never
        # trust Popen.wait(), which may synthesize a zero code after ECHILD.
        while True:
            remaining = cleanup_deadline - time.monotonic()
            if remaining <= 0:
                raise SnapshotError("Snapshot source worker cleanup exceeded its time bound")
            try:
                waited, status = os.waitpid(child.pid, os.WNOHANG)
            except InterruptedError:
                continue
            except OSError as exc:
                raise SnapshotError(
                    "Snapshot source worker waitability became uncertain") from exc
            if waited == 0:
                time.sleep(min(0.01, remaining))
                continue
            if waited != child.pid:
                raise SnapshotError("Snapshot source worker reap returned another child")
            try:
                child.returncode = os.waitstatus_to_exitcode(status)
            except (AttributeError, OSError, ValueError) as exc:
                raise SnapshotError("Snapshot source worker exit status is invalid") from exc
            break

        # This fixed stdlib worker has no subprocess/fork path. After reaping
        # its leader, require the group to be absent; never signal a reused ID.
        try:
            os.killpg(child.pid, 0)
        except ProcessLookupError:
            return child.returncode
        except OSError as exc:
            raise SnapshotError("Snapshot source worker group absence is uncertain") from exc
        raise SnapshotError("Snapshot source worker process group remains after reaping")

    def _read_pipe(self, maximum, deadline):
        if maximum < 1:
            return b""
        self._check_deadline(deadline)
        remaining = deadline - time.monotonic()
        try:
            readable, _, _ = select.select([self.child.stdout], [], [], remaining)
            if not readable:
                self.failed = True
                raise SnapshotError("Snapshot source worker exceeded its time bound")
            chunk = os.read(self.child.stdout.fileno(), min(64 * 1024, maximum))
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            self.failed = True
            raise SnapshotError("Snapshot source worker output is unavailable") from exc
        self._check_deadline(deadline)
        if not chunk:
            self.failed = True
            raise SnapshotError("Snapshot source worker stopped before completing a response")
        return chunk

    def _read(self, maximum, deadline):
        self._check_deadline(deadline)
        if maximum < 1:
            return b""
        if self.buffer:
            chunk = bytes(self.buffer[:maximum])
            del self.buffer[:maximum]
            self._check_deadline(deadline)
            return chunk
        return self._read_pipe(maximum, deadline)

    def _line(self, deadline):
        while True:
            self._check_deadline(deadline)
            offset = self.buffer.find(b"\n")
            if offset >= 0:
                if offset > 4096:
                    self.failed = True
                    raise SnapshotError("Snapshot source worker response exceeded its bound")
                line = bytes(self.buffer[:offset])
                del self.buffer[:offset + 1]
                try:
                    return json.loads(line.decode("ascii", "strict"))
                except (UnicodeDecodeError, ValueError) as exc:
                    self.failed = True
                    raise SnapshotError("Snapshot source worker response is malformed") from exc
            if len(self.buffer) > 4096:
                self.failed = True
                raise SnapshotError("Snapshot source worker response exceeded its bound")
            # Read new kernel bytes directly. _read() also serves already
            # buffered payload bytes and must not be used to extend this same
            # line buffer, or a partial line would loop forever.
            self.buffer.extend(self._read_pipe(min(4096, 4097 - len(self.buffer)), deadline))

    @staticmethod
    def _request_line(value):
        return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n")

    def _write_pipe(self, raw, deadline):
        descriptor = self.child.stdin.fileno()
        view = memoryview(raw)
        offset = 0
        while offset < len(view):
            self._check_deadline(deadline)
            remaining = deadline - time.monotonic()
            try:
                _, writable, _ = select.select([], [descriptor], [], remaining)
                if not writable:
                    self.failed = True
                    raise SnapshotError("Snapshot source worker request exceeded its time bound")
                count = os.write(descriptor, view[offset:])
            except (BlockingIOError, InterruptedError):
                continue
            except SnapshotError:
                # Preserve a deliberate deadline/zero-progress refusal rather than
                # reclassifying our own bounded error as an OS write failure.
                raise
            except (BrokenPipeError, OSError, ValueError, subprocess.SubprocessError) as exc:
                self.failed = True
                raise SnapshotError("Snapshot source worker request could not be sent") from exc
            if count <= 0:
                self.failed = True
                raise SnapshotError("Snapshot source worker request made no progress")
            offset += count
            self._check_deadline(deadline)

    def _request(self, operation, path, limit):
        if self.closed or self.failed:
            raise SnapshotError("Snapshot source worker is unavailable")
        deadline = min(time.monotonic() + _V2_SOURCE_WORKER_TIMEOUT, self.deadline)
        self._check_deadline(deadline)
        if type(limit) is not int or not 0 <= limit <= _V2_INVENTORY_FILE_LIMIT:
            self.failed = True
            raise SnapshotError("Snapshot source worker byte limit is invalid")
        path = Path(path).absolute()
        request = self._request_line({"op": operation, "path": str(path), "limit": limit})
        if len(request) > 16 * 1024:
            raise SnapshotError("Snapshot source worker request exceeded its bound")
        try:
            self._write_pipe(request, deadline)
        except SnapshotError:
            self.failed = True
            raise
        return deadline

    @staticmethod
    def _valid_descriptor(value, *, header=False):
        expected = {"ok", "bytes", "mode"} if header else {
            "ok", "bytes", "mode", "sha256", "sqlite"}
        if (not isinstance(value, dict) or set(value) != expected or value.get("ok") is not True
                or type(value.get("bytes")) is not int or value["bytes"] < 0
                or type(value.get("mode")) is not int or not 0 <= value["mode"] <= 0o7777
                or (not header and (not isinstance(value.get("sha256"), str)
                    or re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is None
                    or type(value.get("sqlite")) is not bool))):
            raise SnapshotError("Snapshot source worker returned invalid file metadata")
        return value

    def describe(self, path, *, max_bytes):
        try:
            deadline = self._request("describe", path, max_bytes)
            value = self._line(deadline)
            if not isinstance(value, dict) or value.get("ok") is not True:
                raise SnapshotError("Snapshot source could not be described safely")
            descriptor = self._valid_descriptor(value)
            if descriptor["bytes"] > max_bytes:
                raise SnapshotError("Snapshot source exceeded its fixed byte bound")
            return descriptor
        except BaseException:
            self.failed = True
            raise

    def stream(self, path, *, max_bytes, sink):
        synchronized_refusal = False
        try:
            deadline = self._request("stream", path, max_bytes)
            response = self._line(deadline)
            if (isinstance(response, dict) and set(response) == {"ok", "reason"}
                    and response.get("ok") is False
                    and isinstance(response.get("reason"), str)
                    and response.get("reason") in {"source-refused", "source-read-failed"}):
                # The worker rejected the request before writing a body. This
                # exact closed response leaves its line protocol synchronized, so
                # scope cleanup can still send the stop command and reap normally.
                synchronized_refusal = True
                raise SnapshotError("Snapshot source worker returned invalid file metadata")
            header = self._valid_descriptor(response, header=True)
            if header["bytes"] > max_bytes:
                raise SnapshotError("Snapshot source exceeded its fixed byte bound")
            remaining = header["bytes"]
            while remaining:
                chunk = self._read(min(64 * 1024, remaining), deadline)
                sink(chunk)
                self._check_deadline(deadline)
                remaining -= len(chunk)
            trailer = self._line(deadline)
            if not isinstance(trailer, dict) or trailer.get("ok") is not True:
                raise SnapshotError("Snapshot source changed while streaming")
            trailer = self._valid_descriptor(trailer)
            if trailer["bytes"] != header["bytes"] or trailer["mode"] != header["mode"]:
                raise SnapshotError("Snapshot source changed while streaming")
            return trailer
        except BaseException:
            if not synchronized_refusal:
                self.failed = True
            raise

    def read_bytes(self, path, *, expected_bytes):
        output = bytearray()
        descriptor = self.stream(path, max_bytes=expected_bytes, sink=output.extend)
        if descriptor["bytes"] != expected_bytes:
            raise SnapshotError("Snapshot source size changed after inventory")
        return bytes(output), descriptor

    def close(self):
        if self.closed:
            return
        self.closed = True
        child = self.child
        cleanup_deadline = time.monotonic() + 8
        graceful_deadline = cleanup_deadline - 1

        try:
            if not self.failed and self.buffer:
                self.failed = True
            if not self.failed:
                try:
                    self._write_pipe(self._request_line({"op": "stop"}), graceful_deadline)
                except SnapshotError:
                    self.failed = True
            try:
                child.stdin.close()
            except OSError:
                self.failed = True
            eof = False
            leader_exited = False
            if not self.failed:
                while time.monotonic() < graceful_deadline:
                    leader_exited = self._observe_child_exit(child, cleanup_deadline)
                    if leader_exited and eof:
                        break
                    remaining = graceful_deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    try:
                        readable, _, _ = select.select([child.stdout], [], [], min(0.05, remaining))
                        if readable:
                            chunk = os.read(child.stdout.fileno(), 4097)
                            if not chunk:
                                eof = True
                            else:
                                self.failed = True
                                break
                    except (OSError, ValueError):
                        self.failed = True
                        break
                if not self.failed:
                    leader_exited = self._observe_child_exit(child, cleanup_deadline)
                    if not (eof and leader_exited):
                        self.failed = True
            self._stop_and_reap_child(
                child, cleanup_deadline=cleanup_deadline,
                graceful_deadline=(graceful_deadline if not self.failed
                                   else time.monotonic()))
            if child.returncode != 0:
                self.failed = True
                raise SnapshotError("Snapshot source worker did not exit cleanly")
            if self.failed:
                raise SnapshotError("Snapshot source worker cleanup or protocol failed")
        finally:
            for pipe in (child.stdin, child.stdout):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:
                        pass


def _v2_source_worker():
    holder = _V2_ACTIVE_SOURCE_WORKER.get()
    if holder is None:
        raise SnapshotError("Bounded snapshot source worker scope is unavailable")
    if not holder:
        holder.append(_V2SourceWorker())
    return holder[0]


def _v2_source_worker_scope():
    """Return a lazy worker scope for isolated bounded-source helper tests."""
    class Scope:
        def __enter__(self):
            self.holder = []
            self.token = _V2_ACTIVE_SOURCE_WORKER.set(self.holder)
            return _v2_source_worker

        def __exit__(self, _kind, _value, _traceback):
            try:
                if self.holder:
                    self.holder[0].close()
            finally:
                _V2_ACTIVE_SOURCE_WORKER.reset(self.token)
            return False
    return Scope()


def _describe_v2(path, *, allow_link=False, max_bytes):
    """Describe a bounded source in a fresh process without parent raw opens."""
    from brain_storage_admission import _open_directory_chain
    path = Path(path).absolute()
    parent_fd = _open_directory_chain(path.parent)
    try:
        info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode) and allow_link:
            target = os.readlink(path.name, dir_fd=parent_fd)
            final = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            current_parent_fd = _open_directory_chain(path.parent)
            try:
                pinned_parent, current_parent = os.fstat(parent_fd), os.fstat(current_parent_fd)
                if ((pinned_parent.st_dev, pinned_parent.st_ino)
                        != (current_parent.st_dev, current_parent.st_ino)):
                    raise SnapshotError("V2 snapshot symlink parent changed while reading")
            finally:
                os.close(current_parent_fd)
            if ((info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)
                    != (final.st_dev, final.st_ino, final.st_mtime_ns, final.st_ctime_ns)):
                raise SnapshotError("V2 snapshot symlink changed while reading")
            return {"type": "symlink", "target": target}
    finally:
        os.close(parent_fd)
    result = _v2_source_worker().describe(path, max_bytes=max_bytes)
    return {"type": "file", "sha256": result["sha256"], "bytes": result["bytes"],
            "mode": result["mode"], "_sqlite": result["sqlite"]}


def _copy_file_v2(source, destination_directory_fd, stage_fd, directory_identity,
                  destination_name, expected, expected_bytes):
    """Copy an exact-size source through the isolated raw-descriptor worker."""
    source = Path(source).absolute()
    output_fd = None
    digest, total = hashlib.sha256(), 0
    try:
        if (type(expected_bytes) is not int or expected_bytes < 0
                or expected_bytes > _V2_INVENTORY_FILE_LIMIT):
            raise SnapshotError("V2 snapshot source size is outside its bound")
        _verify_snapshot_stage(stage_fd, "objects", destination_directory_fd, directory_identity)
        output_fd = os.open(destination_name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                            0o600, dir_fd=destination_directory_fd)
        with os.fdopen(output_fd, "wb") as output:
            output_fd = None
            def write_chunk(chunk):
                nonlocal total
                digest.update(chunk)
                view, offset = memoryview(chunk), 0
                while offset < len(view):
                    _verify_snapshot_stage(stage_fd, "objects", destination_directory_fd, directory_identity)
                    written = output.write(view[offset:])
                    if written is None or written <= 0:
                        raise SnapshotError("V2 snapshot destination write did not complete")
                    offset += written
                    total += written
            result = _v2_source_worker().stream(source, max_bytes=expected_bytes, sink=write_chunk)
            output.flush()
            os.fsync(output.fileno())
        _verify_snapshot_stage(stage_fd, "objects", destination_directory_fd, directory_identity)
        if (total != expected_bytes or result["bytes"] != expected_bytes
                or digest.hexdigest() != expected or result["sha256"] != expected):
            raise SnapshotError("V2 snapshot source changed while copying")
        return total
    finally:
        if output_fd is not None:
            os.close(output_fd)


def _verify_existing_snapshot_object(directory_fd, stage_fd, directory_identity,
                                     name, expected, expected_bytes):
    _verify_snapshot_stage(stage_fd, "objects", directory_fd, directory_identity)
    named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if not stat.S_ISREG(named.st_mode) or named.st_size != expected_bytes:
        raise SnapshotError("Snapshot object deduplication found conflicting bytes")
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    try:
        opened = os.fstat(descriptor)
        identity = (named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns, named.st_ctime_ns)
        if (not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
                != identity):
            raise SnapshotError("Snapshot object changed while verifying deduplication")
        digest, total = hashlib.sha256(), 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, expected_bytes - total + 1))
            if not chunk:
                break
            if total + len(chunk) > expected_bytes:
                raise SnapshotError("Snapshot object exceeded its deduplicated byte bound")
            digest.update(chunk)
            total += len(chunk)
        final = os.fstat(descriptor)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        final_identity = (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns, final.st_ctime_ns)
        current_identity = (current.st_dev, current.st_ino, current.st_size,
                            current.st_mtime_ns, current.st_ctime_ns)
        if (final_identity != identity or current_identity != identity or total != expected_bytes
                or digest.hexdigest() != expected):
            raise SnapshotError("Snapshot object changed while verifying deduplication")
        _verify_snapshot_stage(stage_fd, "objects", directory_fd, directory_identity)
    finally:
        os.close(descriptor)


def _write_snapshot_object_bytes(directory_fd, stage_fd, directory_identity, name, value):
    if not isinstance(value, bytes):
        raise SnapshotError("Snapshot object content is invalid")
    _verify_snapshot_stage(stage_fd, "objects", directory_fd, directory_identity)
    descriptor = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                         0o600, dir_fd=directory_fd)
    try:
        offset = 0
        view = memoryview(value)
        while offset < len(view):
            _verify_snapshot_stage(stage_fd, "objects", directory_fd, directory_identity)
            written = os.write(descriptor, view[offset:])
            if written <= 0 or offset + written > len(view):
                raise SnapshotError("Snapshot object write exceeded its fixed byte bound")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _verify_snapshot_stage(stage_fd, "objects", directory_fd, directory_identity)


def _private_file(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)


def _copy_file(source, destination, expected):
    """Stream evidence/blob bytes rather than load a recording into memory."""
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    digest = hashlib.sha256()
    with os.fdopen(descriptor, "wb") as output, source.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            output.write(chunk)
    if digest.hexdigest() != expected:
        raise SnapshotError("Source object changed while copying")


def _json(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode()


def _validate_plan(plan, *, bounded=False):
    if not isinstance(plan, dict) or set(plan) != {"protocolVersion", "id", "repository", "authorities", "exclusions", "quiescence"}:
        raise SnapshotError("Unexpected snapshot-plan fields")
    if plan["protocolVersion"] != "1.0" or not isinstance(plan["id"], str) or not plan["id"].strip():
        raise SnapshotError("Unsupported snapshot plan")
    if not isinstance(plan["quiescence"], str) or not plan["quiescence"].strip():
        raise SnapshotError("Name the caller-managed writer-quiescence evidence or limitation")
    root = Path(plan["repository"]).resolve(strict=True)

    if bounded:
        deadline = time.monotonic() + _V2_COMMAND_TIMEOUT

        def git(*args, limit=_V2_COMMAND_OUTPUT_LIMIT):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SnapshotError("Git snapshot validation exceeded its common deadline")
            return _v2_git(root, *args, output_limit=limit, timeout=remaining)
    else:
        def git(*args, limit=None):
            return _git(root, *args)

    if Path(os.fsdecode(git("rev-parse", "--show-toplevel", **({"limit": 4096} if bounded else {}))).strip()).resolve() != root:
        raise SnapshotError("Repository must be the exact worktree root")
    shallow = git("rev-parse", "--is-shallow-repository",
                   **({"limit": 32} if bounded else {}))
    if shallow.strip() != b"false":
        raise SnapshotError("Shallow history needs a separate complete-history recovery source")
    unmerged = git("ls-files", "--unmerged", "-z",
                   **({"limit": _V2_INVENTORY_OUTPUT_LIMIT} if bounded else {}))
    if unmerged:
        raise SnapshotError("Unmerged index stages require explicit recovery before snapshotting")
    flags = git("ls-files", "-v", "-z",
                **({"limit": _V2_INVENTORY_OUTPUT_LIMIT} if bounded else {}))
    if bounded and flags.count(b"\0") > _V2_INVENTORY_ENTRY_LIMIT:
        raise SnapshotError("Git index flags exceed their entry-count bound")
    if any(row and (row[:1] == b"S" or row[:1].islower()) for row in flags.split(b"\0")):
        raise SnapshotError("Sparse/assume-unchanged index flags require explicit recovery before snapshotting")
    diff = ("diff", "--cached", "--binary", "--full-index", "--no-ext-diff", "--no-textconv")
    diff_limit = _V2_COMMAND_OUTPUT_LIMIT
    if git(*diff, "HEAD", "--", **({"limit": diff_limit} if bounded else {})) != git(
            *diff, "--ita-visible-in-index", "HEAD", "--",
            **({"limit": diff_limit} if bounded else {})):
        raise SnapshotError("Intent-to-add index entries require explicit staging before snapshotting")
    stages = git("ls-files", "--stage", "-z",
                 **({"limit": _V2_INVENTORY_OUTPUT_LIMIT} if bounded else {}))
    if bounded and stages.count(b"\0") > _V2_INVENTORY_ENTRY_LIMIT:
        raise SnapshotError("Git index stages exceed their entry-count bound")
    if any(row.startswith(b"160000 ") for row in stages.split(b"\0")):
        raise SnapshotError("Submodules require separately declared snapshot units")
    if not isinstance(plan["authorities"], list) or not isinstance(plan["exclusions"], list):
        raise SnapshotError("Authorities and exclusions must be explicit lists")
    authorities, identities, targets = [], set(), []
    for entry in plan["authorities"]:
        if not isinstance(entry, dict) or set(entry) != {"id", "kind", "source", "target", "binding"}:
            raise SnapshotError("Unexpected authority fields")
        identity = entry["id"]
        if not isinstance(identity, str) or not identity.strip() or identity in identities:
            raise SnapshotError("Authority ids must be unique nonempty strings")
        identities.add(identity)
        if entry["kind"] not in ("sqlite-authority", "file", "tree"):
            raise SnapshotError("Unsupported authority adapter")
        source = Path(entry["source"])
        source = source if source.is_absolute() else root / source
        if source.is_symlink():
            raise SnapshotError("Authority roots cannot be symlinks")
        source = source.resolve(strict=True)
        if source != root and _within(root, source):
            raise SnapshotError("An external authority cannot contain the repository")
        if any(_within(source, other["source"]) or _within(other["source"], source) for other in authorities):
            raise SnapshotError("Authority source paths overlap")
        target = Path(_relative(entry["target"]))
        if any(_within(target, other) or _within(other, target) for other in targets):
            raise SnapshotError("Authority restore paths overlap")
        targets.append(target)
        if _within(source, root) and source.relative_to(root) != target:
            raise SnapshotError("In-repository authority paths must be preserved; moves need a migration")
        if entry["kind"] == "tree" and not source.is_dir():
            raise SnapshotError("Tree authority must be a directory")
        if entry["kind"] != "tree" and not source.is_file():
            raise SnapshotError("File/database authority must be a regular file")
        if entry["kind"] == "sqlite-authority" and (not isinstance(entry["binding"], str)
                or len(entry["binding"]) != 64 or any(c not in "0123456789abcdef" for c in entry["binding"])):
            raise SnapshotError("SQLite authority requires its expected contract binding")
        if entry["kind"] != "sqlite-authority" and entry["binding"] is not None:
            raise SnapshotError("File/tree adapters do not validate a knowledge authority contract")
        authorities.append({**deepcopy(entry), "source": source, "target": target.as_posix()})
    exclusions = []
    for entry in plan["exclusions"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "reason"} or not isinstance(entry["reason"], str) or not entry["reason"].strip():
            raise SnapshotError("Exclusions need a path and explicit reason")
        path = Path(_relative(entry["path"]))
        if any(_within(path, target) or _within(target, path) for target in targets):
            raise SnapshotError("Exclusions cannot overlap declared authorities")
        exclusions.append({"path": path.as_posix(), "reason": entry["reason"]})
    return root, authorities, exclusions


def _inventory(root, authorities, exclusions, *, bounded=False):
    def authority_path(path):
        if path.relative_to(root).as_posix() in _HOST_LOCAL_ADMISSION_FILES:
            return True
        for entry in authorities:
            source = entry["source"]
            if path == source or entry["kind"] == "tree" and _within(path, source):
                return True
            if entry["kind"] == "sqlite-authority" and str(path) in {str(source) + suffix for suffix in ("-wal", "-shm", "-journal")}:
                return True
        return False

    def excluded(path):
        return any(_within(path, root / entry["path"]) for entry in exclusions)

    def nul_rows(raw, label):
        count = raw.count(b"\0")
        if count > _V2_INVENTORY_ENTRY_LIMIT:
            raise SnapshotError(f"Repository {label} exceeds its entry-count bound")
        if raw and not raw.endswith(b"\0"):
            raise SnapshotError(f"Repository {label} is not NUL terminated")
        return raw[:-1].split(b"\0") if raw else []

    def inventory_git(*args):
        if bounded:
            return _v2_git(root, *args, output_limit=_V2_INVENTORY_OUTPUT_LIMIT)
        return _git(root, *args)

    files = {}
    total_bytes = 0
    names_raw = inventory_git("ls-files", "--cached", "--others", "--exclude-standard", "-z")
    names = nul_rows(names_raw, "file inventory")
    for name in sorted(set(names)):
        if not name:
            continue
        if len(files) >= _V2_INVENTORY_ENTRY_LIMIT:
            raise SnapshotError("Repository file inventory exceeds its count bound")
        relative = _relative(os.fsdecode(name))
        path = _safe(root, relative)
        if authority_path(path):
            continue
        if excluded(path):
            raise SnapshotError("Tracked/nonignored working files cannot be excluded from repository recovery")
        if not path.exists() and not path.is_symlink():
            continue  # Working-tree deletion; index and Git history remain separately captured.
        remaining = _V2_INVENTORY_TREE_LIMIT - total_bytes
        describe = _describe_v2 if bounded else _describe
        descriptor = describe(path, allow_link=True,
                              max_bytes=min(_V2_INVENTORY_FILE_LIMIT, remaining))
        if descriptor["type"] == "file":
            total_bytes += descriptor["bytes"]
            if total_bytes > _V2_INVENTORY_TREE_LIMIT:
                raise SnapshotError("Repository working files exceed their aggregate byte bound")
            if bounded:
                is_sqlite = descriptor.pop("_sqlite")
            else:
                with path.open("rb") as stream:
                    is_sqlite = stream.read(16) == b"SQLite format 3\x00"
            if is_sqlite:
                raise SnapshotError("Database files require an explicit snapshot adapter")
        files[relative] = descriptor
    ignored_raw = inventory_git("ls-files", "--others", "--ignored", "--exclude-standard",
                                "--directory", "-z")
    ignored = nul_rows(ignored_raw, "ignored-file inventory")
    uncovered = []
    visited = 0
    declared = [entry["source"] for entry in authorities] + [root / entry["path"] for entry in exclusions]

    for name in ignored:
        if name:
            pending = [_safe(root, os.fsdecode(name).rstrip("/"))]
            while pending:
                path = pending.pop()
                visited += 1
                if visited > _V2_INVENTORY_ENTRY_LIMIT:
                    raise SnapshotError("Ignored-file inspection exceeds its entry-count bound")
                if authority_path(path) or excluded(path):
                    continue
                info = path.lstat()
                if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                    # Expand only where a declaration can explain part of an ignored tree.
                    if any(_within(item, path) for item in declared):
                        with os.scandir(path) as children:
                            for child in children:
                                if visited + len(pending) >= _V2_INVENTORY_ENTRY_LIMIT:
                                    raise SnapshotError("Ignored-file inspection exceeds its entry-count bound")
                                pending.append(Path(child.path))
                        continue
                uncovered.append(path.relative_to(root).as_posix())
                if len(uncovered) > _V2_INVENTORY_ENTRY_LIMIT:
                    raise SnapshotError("Ignored-file inspection exceeds its entry-count bound")
    if uncovered:
        raise SnapshotError("Ignored data needs an authority declaration or exclusion")
    return files


def _v2_pin_open_authority_source(path):
    """Pin authority name metadata without opening a raw descriptor for its DB."""
    from brain_storage_admission import _open_directory_chain

    source = Path(path).absolute()
    parent_fd = _open_directory_chain(source.parent)
    try:
        named = os.stat(source.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(named.st_mode):
            raise SnapshotError("SQLite authority source is unsafe before its bounded snapshot")
        identity = (named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns,
                    named.st_ctime_ns, named.st_nlink)
        return parent_fd, identity
    except BaseException:
        os.close(parent_fd)
        raise


def _v2_pin_sqlite_sidecars(path, *, expected_main=None):
    """Require the selected SQLite file and any live sidecars to have no aliases.

    Bounded snapshot inventory uses raw no-follow descriptors for ordinary files.
    A currently visible hard link to the selected authority, WAL, shared-memory
    file, or rollback journal would make an ordinary-looking path name a file
    SQLite owns. The caller's SQLite connection remains open during capture, so
    refuse observed aliases before inventory or object copying starts. The
    caller-managed quiescence contract remains necessary while capture runs.
    """
    from brain_storage_admission import _open_directory_chain

    source = Path(path).absolute()
    parent_fd = _open_directory_chain(source.parent)
    try:
        main_identity = None
        for suffix in ("", "-wal", "-shm", "-journal"):
            name = source.name + suffix
            try:
                info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                if not suffix:
                    raise SnapshotError("SQLite authority source is unavailable") from None
                continue
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_mode & 0o022):
                raise SnapshotError("SQLite authority file or sidecar has an unsafe alias")
            if not suffix:
                main_identity = (info.st_dev, info.st_ino)
        if expected_main is not None and main_identity != expected_main:
            raise SnapshotError("SQLite authority file identity changed during capture")
        return main_identity
    finally:
        os.close(parent_fd)


def _v2_verify_open_authority_source(path, parent_fd, identity):
    """Recheck the pinned authority name and parent without opening the DB file."""
    from brain_storage_admission import _open_directory_chain

    source = Path(path).absolute()
    current_parent_fd = _open_directory_chain(source.parent)
    try:
        pinned_parent = os.fstat(parent_fd)
        current_parent = os.fstat(current_parent_fd)
        if ((pinned_parent.st_dev, pinned_parent.st_ino)
                != (current_parent.st_dev, current_parent.st_ino)):
            raise SnapshotError("SQLite authority parent changed during its bounded snapshot")
    finally:
        os.close(current_parent_fd)
    named = os.stat(source.name, dir_fd=parent_fd, follow_symlinks=False)
    current = (named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns,
               named.st_ctime_ns, named.st_nlink)
    if not stat.S_ISREG(named.st_mode) or current != identity:
        raise SnapshotError("SQLite authority path changed during its bounded snapshot")


def _authority_snapshot(entry, *, bounded=False):
    source = entry["source"]
    if entry["kind"] == "sqlite-authority":
        parent_fd, identity = _v2_pin_open_authority_source(source) if bounded else (None, None)
        store = None
        try:
            store = SQLiteAuthority(source, expected_binding=entry["binding"], readonly=True)
            if (bounded and getattr(store, "authority_file_identity", None) != identity[:2]):
                raise SnapshotError("SQLite authority path changed while opening its snapshot")
            from knowledge_store import (MAX_RESTORE_CELL_BYTES, MAX_RESTORE_SNAPSHOT_BYTES,
                                         MAX_RESTORE_TABLE_ROWS, SNAPSHOT_COLUMNS)
            store.dialect.begin()
            try:
                row_count = cell_bytes = cell_count = row_overhead = 0
                for table, columns in SNAPSHOT_COLUMNS.items():
                    quoted_table = '"' + table + '"'
                    aggregate = store.dialect.execute(
                        "SELECT COUNT(*), " + ",".join(
                            f'SUM(length(CAST("{column}" AS BLOB))), MAX(length(CAST("{column}" AS BLOB)))'
                            for column in columns) + f" FROM {quoted_table}").fetchone()
                    count = aggregate[0]
                    row_count += count
                    if row_count > MAX_RESTORE_TABLE_ROWS:
                        raise SnapshotError("SQLite authority export exceeds its aggregate row bound")
                    row_overhead += count * (sum(len(column.encode("ascii")) + 3 for column in columns)
                                             + max(0, len(columns) - 1) + 2)
                    for offset in range(len(columns)):
                        total_length = aggregate[1 + offset * 2] or 0
                        maximum_length = aggregate[2 + offset * 2] or 0
                        cell_bytes += total_length
                        cell_count += count
                        if maximum_length > MAX_RESTORE_CELL_BYTES:
                            raise SnapshotError("SQLite authority export contains an oversized cell")
                if store.contract.cell["blobs"] == "db-blob":
                    blob_stats = store.dialect.execute(
                        "SELECT COUNT(*), COALESCE(SUM(length(content)),0), COALESCE(MAX(length(content)),0) "
                        "FROM blob_objects").fetchone()
                    if (blob_stats[0] > MAX_RESTORE_TABLE_ROWS or blob_stats[2] > MAX_RESTORE_CELL_BYTES):
                        raise SnapshotError("SQLite authority blob export exceeds its row or cell bound")
                    cell_bytes += blob_stats[1]
                    cell_count += blob_stats[0]
                estimate = cell_bytes * 6 + cell_count * 8 + row_overhead + 4096
                if (cell_bytes > 512 * 1024 * 1024 or estimate > MAX_RESTORE_SNAPSHOT_BYTES):
                    raise SnapshotError("SQLite authority export exceeds its bounded JSON graph")
                value = store._snapshot()
            finally:
                store.dialect.rollback()
            SQLiteAuthority.validate_snapshot(value)
        finally:
            try:
                if store is not None:
                    store.close()
            finally:
                if bounded:
                    try:
                        _v2_verify_open_authority_source(source, parent_fd, identity)
                    finally:
                        os.close(parent_fd)
        return {"kind": entry["kind"], "snapshot": value}
    if entry["kind"] == "file":
        paths = [source]
    else:
        paths = []
        pending = [source]
        total_bytes = 0
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as children:
                for child in children:
                    if len(paths) >= _V2_INVENTORY_ENTRY_LIMIT:
                        raise SnapshotError("Authority tree exceeds its entry-count bound")
                    path = Path(child.path)
                    info = child.stat(follow_symlinks=False)
                    paths.append(path)
                    if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                        pending.append(path)
                    elif stat.S_ISREG(info.st_mode):
                        if (info.st_size > _V2_INVENTORY_FILE_LIMIT
                                or total_bytes + info.st_size > _V2_INVENTORY_TREE_LIMIT):
                            raise SnapshotError("Authority tree exceeds its file or aggregate byte bound")
                        total_bytes += info.st_size
                    else:
                        raise SnapshotError("Authority tree contains an unsupported filesystem object")
        paths.sort()
    files = {}
    directories = []
    total_bytes = 0
    for path in paths:
        relative = "." if entry["kind"] == "file" else path.relative_to(source).as_posix()
        if relative != ".":
            _relative(relative)
        if path.is_dir() and not path.is_symlink():
            directories.append(relative)
        else:
            describe = _describe_v2 if bounded else _describe
            descriptor = describe(path, max_bytes=min(
                _V2_INVENTORY_FILE_LIMIT, _V2_INVENTORY_TREE_LIMIT - total_bytes))
            if bounded:
                is_sqlite = descriptor.pop("_sqlite")
            else:
                with path.open("rb") as stream:
                    is_sqlite = stream.read(16) == b"SQLite format 3\x00"
            if is_sqlite:
                raise SnapshotError("SQLite data requires a database adapter, not a file/tree copy")
            total_bytes += descriptor["bytes"]
            files[relative] = descriptor
    return {"kind": entry["kind"], "files": files, "directories": directories}


def _snapshot_admission(root, authorities, destination):
    """Select the one adopted SQLite brain and require a registered snapshot root."""
    from brain_storage_admission import (
        _open_directory_chain, _relative_authority_route, _selected_authority_path, load_registration,
    )
    root = Path(root).resolve(strict=True)
    registration = load_registration(root)
    if registration is None:
        return None
    from knowledge_store import resolve_store_dsn
    config_parent_fd = _open_directory_chain(root)
    try:
        root_info = os.fstat(config_parent_fd)
        config_info = os.stat("client.config.json", dir_fd=config_parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(config_info.st_mode) or config_info.st_uid != os.geteuid()
                or config_info.st_nlink != 1 or config_info.st_mode & 0o022
                or config_info.st_size > 1024 * 1024):
            raise SnapshotError("Adopted storage client configuration is unsafe or too large")
        config_fd = os.open("client.config.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                            dir_fd=config_parent_fd)
        try:
            opened_config = os.fstat(config_fd)
            named_config = os.stat("client.config.json", dir_fd=config_parent_fd, follow_symlinks=False)
            if ((opened_config.st_dev, opened_config.st_ino, opened_config.st_size,
                 opened_config.st_mtime_ns, opened_config.st_ctime_ns)
                    != (named_config.st_dev, named_config.st_ino, named_config.st_size,
                        named_config.st_mtime_ns, named_config.st_ctime_ns)):
                raise SnapshotError("Adopted storage client configuration changed while opening")
            config_raw = os.read(config_fd, 1024 * 1024 + 1)
            final_config = os.fstat(config_fd)
            named_after = os.stat("client.config.json", dir_fd=config_parent_fd, follow_symlinks=False)
            if (len(config_raw) > 1024 * 1024
                    or (opened_config.st_dev, opened_config.st_ino, opened_config.st_size,
                        opened_config.st_mtime_ns, opened_config.st_ctime_ns)
                    != (final_config.st_dev, final_config.st_ino, final_config.st_size,
                        final_config.st_mtime_ns, final_config.st_ctime_ns)
                    or (final_config.st_dev, final_config.st_ino)
                    != (named_after.st_dev, named_after.st_ino)):
                raise SnapshotError("Adopted storage client configuration changed while reading")
        finally:
            os.close(config_fd)
    finally:
        os.close(config_parent_fd)
    try:
        settings = json.loads(config_raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise SnapshotError("Adopted storage client configuration is invalid") from exc
    location = resolve_store_dsn(settings, registration["authority"]["store"])
    selected_relative = _relative_authority_route(Path(location), root, root, root_info)
    selected_source = root / selected_relative
    if selected_source == root:
        raise SnapshotError("Adopted SQLite authority must be a root-contained local file")
    # Pin the main database inode for the existing SQLiteAuthority route check.
    source_identity = _v2_pin_sqlite_sidecars(selected_source)
    destination = Path(destination)
    if ".." in destination.parts:
        raise SnapshotError("Snapshot destination path is unsafe")
    destination = destination.absolute()
    candidate_parent = Path(os.path.abspath(destination.parent))
    resolved_parent = None
    selected_retained_root = None
    selected_relative_parent = None
    for item in registration["retainedRoots"]:
        if item["kind"] not in ("snapshot", "backup"):
            continue
        registered_spelling = Path(item["path"])
        if ".." in registered_spelling.parts:
            continue
        try:
            registered_root = registered_spelling.resolve(strict=True)
            registered_fd = _open_directory_chain(registered_root)
            try:
                registered_info = os.fstat(registered_fd)
                named_root = registered_spelling.lstat()
                if ((named_root.st_dev, named_root.st_ino) != (registered_info.st_dev, registered_info.st_ino)
                        or not stat.S_ISDIR(registered_info.st_mode)
                        or registered_info.st_uid != os.geteuid() or registered_info.st_mode & 0o022):
                    continue
            finally:
                os.close(registered_fd)
            relative_parent = _relative_authority_route(
                candidate_parent, registered_root, registered_root, registered_info, allow_root=True)
            resolved_parent = registered_root / relative_parent
            selected_retained_root = dict(item)
            selected_relative_parent = relative_parent
            break
        except (OSError, StoreError):
            continue
    if resolved_parent is None:
        raise SnapshotError("Adopted storage admission requires a registered snapshot destination")
    retained_parent_fd = _open_directory_chain(resolved_parent)
    retained_parent_info = os.fstat(retained_parent_fd)
    if (retained_parent_info.st_uid != os.geteuid() or retained_parent_info.st_mode & 0o022):
        os.close(retained_parent_fd)
        raise SnapshotError("Registered snapshot destination parent is not owner-private")
    _verify_snapshot_parent(resolved_parent, retained_parent_fd,
                            (retained_parent_info.st_dev, retained_parent_info.st_ino))
    matches = [entry for entry in authorities if entry["kind"] == "sqlite-authority"
               and Path(entry["source"] if Path(entry["source"]).is_absolute() else root / entry["source"]).resolve()
               == selected_source]
    if len(matches) != 1:
        os.close(retained_parent_fd)
        raise SnapshotError("Adopted storage admission requires its exact registered SQLite authority in the plan")
    store = None
    try:
        store = SQLiteAuthority(selected_source, expected_binding=registration["authority"]["binding"],
                                readonly=True)
        current_parent_fd = _open_directory_chain(selected_source.parent)
        try:
            after_source = os.stat(selected_source.name, dir_fd=current_parent_fd, follow_symlinks=False)
            after_identity = (after_source.st_dev, after_source.st_ino)
        finally:
            os.close(current_parent_fd)
        if after_identity != source_identity or getattr(store, "authority_file_identity", None) != source_identity:
            raise SnapshotError("Adopted SQLite authority path changed while opening")
        if (store.contract.authority != registration["authority"]["store"]
                or store.contract.binding != registration["authority"]["binding"]):
            raise SnapshotError("Adopted SQLite authority does not match its registration")
        helper_path, _ = _selected_authority_path(root, store, registration)
        if Path(helper_path) != selected_source:
            raise SnapshotError("Adopted SQLite authority route changed while opening")
        from brain_storage_admission import validate_registration
        registration_sha = fingerprint(validate_registration(registration))
        config_sha = fingerprint(settings)
        source_path = selected_source

        def route_guard(*, require_active=True):
            current_registration = load_registration(root, required=True)
            current_path, current_settings = _selected_authority_path(root, store, current_registration)
            if (fingerprint(current_registration) != registration_sha
                    or Path(current_path) != source_path
                    or fingerprint(current_settings) != config_sha):
                raise SnapshotError("Adopted storage registration or client route changed during capture")
            parent_fd = _open_directory_chain(source_path.parent)
            try:
                current_source = os.stat(source_path.name, dir_fd=parent_fd, follow_symlinks=False)
                current_identity = (current_source.st_dev, current_source.st_ino)
            finally:
                os.close(parent_fd)
            if current_identity != source_identity:
                raise SnapshotError("Adopted SQLite authority file identity changed during capture")
            _v2_pin_sqlite_sidecars(source_path, expected_main=source_identity)
            if (require_active and (not getattr(store, "_storage_admission_active", False)
                    or getattr(store, "_storage_admission_reservation", None) is None)):
                raise SnapshotError("Matching active storage-admission reservation is unavailable")
            _verify_snapshot_parent(resolved_parent, retained_parent_fd,
                                    (retained_parent_info.st_dev, retained_parent_info.st_ino))

        store._snapshot_route_guard = route_guard
        store._snapshot_parent_fd = retained_parent_fd
        store._snapshot_parent_identity = (retained_parent_info.st_dev, retained_parent_info.st_ino)
        store._snapshot_retained_root_id = selected_retained_root["id"]
        store._snapshot_retained_root_kind = selected_retained_root["kind"]
        store._snapshot_retained_root_path = str(registered_root)
        store._snapshot_retained_relative_parent = str(selected_relative_parent)
    except BaseException:
        if store is not None:
            store.close()
        os.close(retained_parent_fd)
        raise
    return store


def _verify_snapshot_parent(path, pinned_fd, identity):
    """Require the registered directory name to still identify its pinned directory fd."""
    from brain_storage_admission import _open_directory_chain
    pinned = os.fstat(pinned_fd)
    if (pinned.st_dev, pinned.st_ino) != identity:
        raise SnapshotError("Registered snapshot destination parent changed")
    current_fd = _open_directory_chain(path)
    try:
        current = os.fstat(current_fd)
        if (current.st_dev, current.st_ino) != identity:
            raise SnapshotError("Registered snapshot destination parent changed")
    finally:
        os.close(current_fd)


def _verify_snapshot_stage(parent_fd, name, stage_fd, identity):
    """Require the private staging name to still identify its pinned directory fd."""
    opened = os.fstat(stage_fd)
    try:
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise SnapshotError("Snapshot staging directory name changed") from exc
    opened_identity = (opened.st_dev, opened.st_ino)
    if (opened_identity != identity or (named.st_dev, named.st_ino) != identity
            or not stat.S_ISDIR(opened.st_mode) or not stat.S_ISDIR(named.st_mode)
            or opened.st_uid != os.geteuid() or named.st_uid != os.geteuid()
            or opened.st_mode & 0o077 or named.st_mode & 0o077):
        raise SnapshotError("Snapshot staging directory name changed")


def _v2_stage_name(name):
    if (not isinstance(name, str) or not name or name in {".", ".."}
            or "/" in name or "\\" in name or "\x00" in name):
        raise SnapshotError("V2 staging artifact name is invalid")
    return name


def _v2_stage_info_valid(info, *, max_bytes=None):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
            or info.st_mode & 0o077 or (max_bytes is not None and info.st_size > max_bytes)):
        raise SnapshotError("V2 staging artifact is unsafe or exceeds its byte bound")


def _v2_stage_create(directory_fd, name):
    """Exclusively create one private regular file relative to a pinned directory."""
    name = _v2_stage_name(name)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
    except OSError as exc:
        raise SnapshotError("Unable to create exclusive V2 staging artifact") from exc
    try:
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        _v2_stage_info_valid(opened, max_bytes=0)
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise SnapshotError("V2 staging artifact name changed while opening")
        return descriptor, (opened.st_dev, opened.st_ino)
    except BaseException:
        os.close(descriptor)
        raise


def _v2_stage_open(directory_fd, name, flags=os.O_RDONLY):
    """Open an existing regular stage artifact without following a replacement link."""
    name = _v2_stage_name(name)
    try:
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise SnapshotError("V2 staging artifact is unavailable") from exc
    _v2_stage_info_valid(named)
    try:
        descriptor = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    except OSError as exc:
        raise SnapshotError("V2 staging artifact could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        _v2_stage_info_valid(opened)
        if ((opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)):
            raise SnapshotError("V2 staging artifact name changed while opening")
        return descriptor, (opened.st_dev, opened.st_ino)
    except BaseException:
        os.close(descriptor)
        raise


def _v2_stage_open_directory(directory_fd, name):
    name = _v2_stage_name(name)
    try:
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise SnapshotError("V2 staging directory is unavailable") from exc
    if not stat.S_ISDIR(named.st_mode) or named.st_uid != os.geteuid() or named.st_mode & 0o077:
        raise SnapshotError("V2 staging directory is unsafe")
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory_fd)
    except OSError as exc:
        raise SnapshotError("V2 staging directory could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        identity = (opened.st_dev, opened.st_ino)
        if ((named.st_dev, named.st_ino) != identity or (current.st_dev, current.st_ino) != identity
                or not stat.S_ISDIR(opened.st_mode) or opened.st_uid != os.geteuid()
                or opened.st_mode & 0o077):
            raise SnapshotError("V2 staging directory changed while opening")
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _v2_stage_seal_generated(directory_fd, name, max_bytes):
    """Pin a Git-created index file and make it owner-private before normal reads."""
    name = _v2_stage_name(name)
    if type(max_bytes) is not int or max_bytes < 0:
        raise SnapshotError("Generated Git artifact byte bound is invalid")
    try:
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise SnapshotError("Generated Git artifact is unavailable") from exc
    if (not stat.S_ISREG(named.st_mode) or named.st_uid != os.geteuid()
            or named.st_nlink != 1 or named.st_size > max_bytes):
        raise SnapshotError("Generated Git artifact is unsafe or exceeds its byte bound")
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory_fd)
    except OSError as exc:
        raise SnapshotError("Generated Git artifact could not be opened safely") from exc
    identity = (named.st_dev, named.st_ino)
    try:
        opened = os.fstat(descriptor)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        for info in (opened, current):
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_size > max_bytes):
                raise SnapshotError("Generated Git artifact changed or exceeds its byte bound")
        if ((opened.st_dev, opened.st_ino) != identity
                or (current.st_dev, current.st_ino) != identity):
            raise SnapshotError("Generated Git artifact name changed while opening")
        os.fchmod(descriptor, 0o600)
        _v2_verify_stage_file(directory_fd, name, descriptor, identity, max_bytes=max_bytes)
        return identity
    finally:
        os.close(descriptor)


def _v2_stage_stat(directory_fd, name, *, max_bytes=None):
    try:
        info = os.stat(_v2_stage_name(name), dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise SnapshotError("V2 staging artifact is unavailable") from exc
    _v2_stage_info_valid(info, max_bytes=max_bytes)
    return info


def _v2_stage_require_absent(directory_fd, name):
    try:
        os.stat(_v2_stage_name(name), dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise SnapshotError("V2 staging artifact state is unavailable") from exc
    raise SnapshotError("V2 staging artifact already exists")


def _v2_verify_stage_file(directory_fd, name, descriptor, identity, *, expected_size=None, max_bytes=None):
    opened = os.fstat(descriptor)
    named = os.stat(_v2_stage_name(name), dir_fd=directory_fd, follow_symlinks=False)
    _v2_stage_info_valid(opened, max_bytes=max_bytes)
    if ((opened.st_dev, opened.st_ino) != identity
            or (named.st_dev, named.st_ino) != identity
            or (expected_size is not None and opened.st_size != expected_size)):
        raise SnapshotError("V2 staging artifact changed during use")
    return opened


def _v2_verify_stage_named_file(directory_fd, name, identity, *, max_bytes=None):
    descriptor, opened_identity = _v2_stage_open(directory_fd, name)
    try:
        if opened_identity != identity:
            raise SnapshotError("V2 staging artifact was replaced")
        return _v2_verify_stage_file(directory_fd, name, descriptor, identity, max_bytes=max_bytes)
    finally:
        os.close(descriptor)


def _v2_stage_write(directory_fd, name, raw):
    if not isinstance(raw, bytes):
        raise SnapshotError("V2 staging content is invalid")
    descriptor, identity = _v2_stage_create(directory_fd, name)
    try:
        offset = 0
        view = memoryview(raw)
        while offset < len(view):
            count = os.write(descriptor, view[offset:])
            if count <= 0 or offset + count > len(view):
                raise SnapshotError("V2 staging write exceeded its planned byte bound")
            offset += count
        os.fsync(descriptor)
        _v2_verify_stage_file(directory_fd, name, descriptor, identity, expected_size=len(raw),
                              max_bytes=len(raw))
        return identity
    finally:
        os.close(descriptor)


def _v2_stage_digest(directory_fd, name, *, max_bytes):
    descriptor, identity = _v2_stage_open(directory_fd, name)
    digest = hashlib.sha256()
    size = 0
    try:
        while chunk := os.read(descriptor, min(1024 * 1024, max_bytes + 1 - size)):
            size += len(chunk)
            if size > max_bytes:
                raise SnapshotError("V2 staging artifact exceeds its byte bound")
            digest.update(chunk)
        _v2_verify_stage_file(directory_fd, name, descriptor, identity,
                              expected_size=size, max_bytes=max_bytes)
        return {"bytes": size, "sha256": digest.hexdigest()}, identity
    finally:
        os.close(descriptor)


def _v2_stage_unlink(directory_fd, name, identity):
    _v2_verify_stage_named_file(directory_fd, name, identity)
    os.unlink(_v2_stage_name(name), dir_fd=directory_fd)


def _v2_stage_chmod(directory_fd, name, identity, mode):
    descriptor, opened_identity = _v2_stage_open(directory_fd, name)
    try:
        if opened_identity != identity:
            raise SnapshotError("V2 staging artifact was replaced")
        os.fchmod(descriptor, mode)
        _v2_verify_stage_file(directory_fd, name, descriptor, identity)
    finally:
        os.close(descriptor)


def _v2_pin_git_directory(root):
    from brain_storage_admission import _open_directory_chain

    raw = _v2_git(root, "rev-parse", "--absolute-git-dir", output_limit=4096)
    try:
        value = raw.decode("utf-8", "strict").rstrip("\n")
    except UnicodeDecodeError as exc:
        raise SnapshotError("Selected Git directory path is invalid") from exc
    if not value or "\n" in value or "\x00" in value or not Path(value).is_absolute():
        raise SnapshotError("Selected Git directory path is invalid")
    try:
        path = Path(value).resolve(strict=True)
        descriptor = _open_directory_chain(path)
    except (OSError, RuntimeError) as exc:
        raise SnapshotError("Selected Git directory is unavailable") from exc
    try:
        opened = os.fstat(descriptor)
        current = _open_directory_chain(path)
        try:
            named = os.fstat(current)
        finally:
            os.close(current)
        if (not stat.S_ISDIR(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)):
            raise SnapshotError("Selected Git directory changed while opening")
        return {"path": str(path), "fd": descriptor, "identity": (opened.st_dev, opened.st_ino)}
    except BaseException:
        os.close(descriptor)
        raise


def _v2_verify_git_directory(root, pin):
    from brain_storage_admission import _open_directory_chain

    raw = _v2_git(root, "rev-parse", "--absolute-git-dir", output_limit=4096)
    try:
        selected = Path(raw.decode("utf-8", "strict").rstrip("\n")).resolve(strict=True)
    except (UnicodeDecodeError, OSError, RuntimeError) as exc:
        raise SnapshotError("Selected Git directory changed during snapshot capture") from exc
    opened = os.fstat(pin["fd"])
    current = _open_directory_chain(selected)
    try:
        named = os.fstat(current)
        if (str(selected) != pin["path"]
                or (opened.st_dev, opened.st_ino) != pin["identity"]
                or (named.st_dev, named.st_ino) != pin["identity"]):
            raise SnapshotError("Selected Git directory changed during snapshot capture")
    finally:
        os.close(current)


def capture(plan, destination, *, fault=None, protection_adapter=None):
    if not isinstance(plan, dict) or not isinstance(plan.get("repository"), str):
        raise SnapshotError("Snapshot repository path is invalid")
    try:
        selected_root = Path(plan["repository"]).resolve(strict=True)
        from brain_storage_admission import load_registration
        initial_registration = load_registration(selected_root)
    except OSError as exc:
        raise SnapshotError("Snapshot repository path is unavailable") from exc
    initial_registration_sha = (fingerprint(initial_registration)
                                if initial_registration is not None else None)
    if initial_registration is not None:
        from brain_snapshot_protection import SnapshotProtectionAdapter, SnapshotProtectionError
        if not isinstance(protection_adapter, SnapshotProtectionAdapter):
            raise SnapshotError(
                "Adopted snapshot capture is unavailable without a trusted protection adapter")
        try:
            protection_adapter.verify(root=selected_root, registration=initial_registration)
        except SnapshotProtectionError as exc:
            raise SnapshotError("Adopted snapshot protection adapter is unavailable") from exc
    elif protection_adapter is not None:
        raise SnapshotError("Snapshot protection adapters are only valid for an adopted root")
    root, authorities, _ = _validate_plan(plan, bounded=initial_registration is not None)
    current_registration = load_registration(root)
    if ((fingerprint(current_registration) if current_registration is not None else None)
            != initial_registration_sha):
        raise SnapshotError("Storage registration changed during snapshot validation")
    store = _snapshot_admission(root, authorities, destination)
    if store is None:
        if initial_registration is not None or load_registration(root) is not None:
            raise SnapshotError("Adopted storage admission is unavailable; legacy snapshot fallback refused")
        return _capture_impl(plan, destination, fault=fault)
    if initial_registration is None:
        parent_fd = getattr(store, "_snapshot_parent_fd", None)
        if parent_fd is not None:
            os.close(parent_fd)
        store.close()
        raise SnapshotError("Storage adoption changed during snapshot validation")
    source_worker_holder = []
    source_worker_token = _V2_ACTIVE_SOURCE_WORKER.set(source_worker_holder)
    try:
        from brain_snapshot_protected_capture import prepare_effect_details
        snapshot_effect_details = prepare_effect_details(
            plan, destination, store=store, adapter=protection_adapter)
        with store._storage_admission_effect("backup.snapshot.capture",
                                             snapshot_details=snapshot_effect_details) as reservation:
            active = getattr(store, "_storage_admission_reservation", None)
            if (not isinstance(reservation, dict)
                    or not getattr(store, "_storage_admission_active", False)
                    or not isinstance(active, tuple) or len(active) < 4
                    or active[2] != reservation.get("id")
                    or reservation.get("state") != "reserved"):
                raise SnapshotError("Matching active storage-admission reservation is unavailable")
            store._snapshot_route_guard()
            current_effect_details = prepare_effect_details(
                plan, destination, store=store, adapter=protection_adapter)
            if current_effect_details != snapshot_effect_details:
                raise SnapshotError("Protected snapshot source or route changed before reservation")
            from brain_snapshot_protected_capture import capture_v1
            return capture_v1(plan, destination, store=store, reservation=reservation,
                              adapter=protection_adapter, expected_effect_details=snapshot_effect_details,
                              fault=fault)
    finally:
        parent_fd = getattr(store, "_snapshot_parent_fd", None)
        if parent_fd is not None:
            try:
                os.close(parent_fd)
            except OSError:
                pass
        git_dir_pin = getattr(store, "_snapshot_git_dir_pin", None)
        if git_dir_pin is not None:
            try:
                os.close(git_dir_pin["fd"])
            except OSError:
                pass
        try:
            if source_worker_holder:
                source_worker_holder[0].close()
        finally:
            try:
                store.close()
            finally:
                _V2_ACTIVE_SOURCE_WORKER.reset(source_worker_token)


def _valid_v2_refname(value):
    if (not isinstance(value, str) or not value.startswith("refs/") or value.endswith(("/", "."))
            or ".." in value or "@{" in value or "//" in value
            or any(ord(char) <= 32 or ord(char) == 127 or char in "~^:?*[\\" for char in value)):
        return False
    return all(component and not component.startswith(".") and not component.endswith(".lock")
               for component in value.split("/"))


def _v2_git_state(root, object_format):
    from brain_snapshot_v2 import parse_index

    deadline = time.monotonic() + _V2_COMMAND_TIMEOUT

    def run(*args, output_limit=_V2_COMMAND_OUTPUT_LIMIT):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SnapshotError("Git reference/index inspection exceeded its common deadline")
        return _v2_git(root, *args, output_limit=output_limit, timeout=remaining)

    head = run("rev-parse", "--verify", "HEAD", output_limit=1024).decode("ascii").strip()
    symbolic = run("rev-parse", "--symbolic-full-name", "HEAD", output_limit=4096).decode("ascii").strip()
    head_ref = symbolic if symbolic.startswith("refs/") else "HEAD"
    ref_rows = run("for-each-ref", f"--count={_V2_REF_COUNT_LIMIT + 1}",
                   "--format=%(refname)%00%(objectname)", output_limit=_V2_REF_OUTPUT_LIMIT)
    if ref_rows.count(b"\n") > _V2_REF_COUNT_LIMIT:
        raise SnapshotError("Git reference inventory exceeds its row bound")
    refs = []
    for row in ref_rows.splitlines():
        name, separator, oid = row.partition(b"\0")
        if (not separator or b"\0" in oid or len(oid) not in (40, 64)
                or any(byte not in b"0123456789abcdef" for byte in oid)):
            raise SnapshotError("Git reference inventory is malformed")
        try:
            ref = name.decode("ascii", "strict")
            object_id = oid.decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise SnapshotError("Git reference inventory is not ASCII") from exc
        if not _valid_v2_refname(ref):
            raise SnapshotError("Git reference inventory contains an invalid refname")
        refs.append({"name": ref, "oid": object_id})
    if len(refs) > _V2_REF_COUNT_LIMIT:
        raise SnapshotError("Git reference inventory exceeds its row bound")
    refs.sort(key=lambda item: item["name"])
    raw_index = run("ls-files", "--stage", "-z", output_limit=64 * 1024 * 1024)
    parse_index(raw_index, object_format=object_format)
    return {"head": head, "headRef": head_ref, "refs": refs, "index": raw_index}


def _capture_v2_impl(plan, destination, *, store, reservation, fault=None):
    from brain_snapshot_v2 import encode_index, plan_git_artifacts

    root, authorities, exclusions = _validate_plan(plan, bounded=True)
    destination = Path(destination).absolute()
    resolved = destination.resolve()
    if destination.exists() or destination.is_symlink() or _within(resolved, root) or any(
            _within(resolved, entry["source"]) or _within(entry["source"], resolved) for entry in authorities):
        raise SnapshotError("Snapshot destination must be new and outside all sources")
    if not destination.parent.is_dir():
        raise SnapshotError("Snapshot parent must already exist")
    git_dir_pin = _v2_pin_git_directory(root)
    store._snapshot_git_dir_pin = git_dir_pin
    _v2_verify_git_directory(root, git_dir_pin)
    object_format = _v2_git(root, "rev-parse", "--show-object-format=storage").decode("ascii").strip()
    before_git = _v2_git_state(root, object_format)
    from brain_snapshot_v2 import parse_index
    indexed_entries = parse_index(before_git["index"], object_format=object_format)
    staged_oids = {entry["oid"] for entry in indexed_entries}
    object_ids = sorted(set(_v2_object_ids(
        root, before_git["refs"], before_git["head"], object_format=object_format)) | staged_oids)
    sizes = _v2_object_sizes(root, object_ids)
    refs_bytes = "".join(f"{row['oid']} {row['name']}\n" for row in before_git["refs"]).encode("ascii")
    git_plan = plan_git_artifacts(sizes.values(), refs_bytes, pack_representation="non-delta-no-reuse/v1",
                                  object_format=object_format)
    if len(object_ids) != git_plan["objects"]:
        raise SnapshotError("Git object inventory does not match its planned count")
    staged_oids = sorted(staged_oids)
    staged_sizes = {oid: sizes[oid] for oid in staged_oids}
    staged_blobs = _v2_cat_file_batch(root, staged_oids, staged_sizes)
    index_package = encode_index(before_git["index"], staged_blobs, object_format=object_format)
    files = _inventory(root, authorities, exclusions, bounded=True)
    snapshots = [_authority_snapshot(entry, bounded=True) for entry in authorities]
    captured = [{"id": entry["id"], "target": entry["target"], **snapshot}
                for entry, snapshot in zip(authorities, snapshots)]
    unique_objects = {}
    for descriptor in files.values():
        if descriptor["type"] == "file":
            unique_objects[descriptor["sha256"]] = descriptor["bytes"]
    for entry, snapshot in zip(authorities, snapshots):
        if entry["kind"] != "sqlite-authority":
            for descriptor in snapshot["files"].values():
                if descriptor["type"] == "file":
                    unique_objects[descriptor["sha256"]] = descriptor["bytes"]
    for sha, content in index_package["blobs"].items():
        unique_objects[sha] = len(content)
    if len(unique_objects) > 250_000 or sum(unique_objects.values()) > 8 * 1024 * 1024 * 1024:
        raise SnapshotError("Snapshot worktree and staged blobs exceed their fixed count or byte bounds")
    object_ids_raw = ("\n".join(object_ids) + "\n").encode("ascii")
    inventory_raw = object_ids_raw
    unique_blob_bytes = sum(unique_objects.values())
    # The manifest's authority exports and inventory are known before staging.
    # Fixed-width hashes and the maximum pack-byte field make this an upper bound
    # for the one manifest file ultimately retained.
    preflight_manifest = {"protocolVersion": "2.0", "id": plan["id"], "planSha256": fingerprint(plan),
        "git": {"objectFormat": object_format, "head": before_git["head"], "headRef": before_git["headRef"],
                "refs": before_git["refs"], "objectInventorySha256": hashlib.sha256(inventory_raw).hexdigest(),
                "objectInventoryBytes": len(inventory_raw), "objectCount": len(object_ids),
                "objectBytes": git_plan["objectBytes"], "packSha256": "0" * 64,
                "packBytes": git_plan["packBytesUpperBound"],
                "packRepresentation": git_plan["packRepresentation"], "index": index_package["manifest"]},
        "files": files, "authorities": captured, "exclusions": exclusions,
        "consistency": {"mode": "before-after-stability-check", "globalTransaction": False,
                        "quiescence": plan["quiescence"]},
        "restoreMode": "separate-target-with-standby-authorities", "sha256": "0" * 64}
    preflight_manifest_bytes = _json(preflight_manifest)
    if len(preflight_manifest_bytes) > _V2_MANIFEST_LIMIT:
        raise SnapshotError("Snapshot manifest exceeds its fixed byte bound")
    # Reserve peak coexistence: pack, pack index, object-list scratch, inventory,
    # content-addressed files, staged blobs, and the single retained manifest.
    stage_bound = (git_plan["packBytesUpperBound"] + git_plan["indexBytesUpperBound"]
                   + len(object_ids_raw) * 2 + unique_blob_bytes + len(preflight_manifest_bytes))
    def route_guard():
        store._snapshot_route_guard()
        if (not getattr(store, "_storage_admission_active", False)
                or getattr(store, "_storage_admission_reservation", None) is None):
            raise SnapshotError("Storage-admission reservation is no longer active")

    def require(amount):
        route_guard()
        store._storage_admission_require(amount)

    def consume(amount):
        route_guard()
        return store._storage_admission_consume(amount)

    def complete(token, *, actual_bytes):
        route_guard()
        store._storage_admission_complete_external(token, actual_bytes=actual_bytes)

    require(stage_bound)
    if fault:
        fault("after-preflight")

    route_guard()
    parent_fd = store._snapshot_parent_fd
    parent_info = os.fstat(parent_fd)
    if (parent_info.st_dev, parent_info.st_ino) != store._snapshot_parent_identity:
        raise SnapshotError("Registered snapshot destination parent changed")
    stage_name = ".brain-snapshot-v2-" + uuid.uuid4().hex
    stage_created = False
    stage_fd = None
    created_identity = None
    try:
        os.mkdir(stage_name, mode=0o700, dir_fd=parent_fd)
        stage_created = True
        created_info = os.stat(stage_name, dir_fd=parent_fd, follow_symlinks=False)
        created_identity = (created_info.st_dev, created_info.st_ino)
        if not stat.S_ISDIR(created_info.st_mode) or created_info.st_uid != os.geteuid():
            raise SnapshotError("Snapshot staging directory is not owner-private")
        stage_fd = os.open(stage_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        stage_info = os.fstat(stage_fd)
        _verify_snapshot_stage(parent_fd, stage_name, stage_fd, created_identity)
    except (OSError, SnapshotError) as exc:
        if stage_fd is not None:
            try:
                os.close(stage_fd)
            except OSError:
                pass
        if stage_created and created_identity is not None:
            try:
                current = os.stat(stage_name, dir_fd=parent_fd, follow_symlinks=False)
                if ((current.st_dev, current.st_ino) == created_identity and stat.S_ISDIR(current.st_mode)):
                    os.rmdir(stage_name, dir_fd=parent_fd)
            except OSError:
                pass
        if isinstance(exc, SnapshotError):
            raise
        raise SnapshotError("Unable to create private snapshot staging directory") from exc
    if (not stat.S_ISDIR(stage_info.st_mode) or stage_info.st_uid != os.geteuid()
            or stage_info.st_mode & 0o077):
        try:
            _verify_snapshot_stage(parent_fd, stage_name, stage_fd, created_identity)
            os.rmdir(stage_name, dir_fd=parent_fd)
        except (OSError, SnapshotError):
            pass
        os.close(stage_fd)
        raise SnapshotError("Snapshot staging directory is not owner-private")
    stage_identity = (stage_info.st_dev, stage_info.st_ino)
    published = False
    objects_fd = None
    objects_identity = None
    try:
        route_guard()
        os.mkdir("objects", mode=0o700, dir_fd=stage_fd)
        objects_info = os.stat("objects", dir_fd=stage_fd, follow_symlinks=False)
        objects_identity = (objects_info.st_dev, objects_info.st_ino)
        objects_fd = os.open("objects", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=stage_fd)
        _verify_snapshot_stage(stage_fd, "objects", objects_fd, objects_identity)
        charge = consume(len(object_ids_raw))
        object_input_identity = _v2_stage_write(stage_fd, "object-input", object_ids_raw)
        complete(charge, actual_bytes=len(object_ids_raw))
        charge = consume(git_plan["packBytesUpperBound"])
        object_input_fd, opened_object_input_identity = _v2_stage_open(stage_fd, "object-input")
        try:
            if opened_object_input_identity != object_input_identity:
                raise SnapshotError("Git object-list input was replaced")
            _v2_verify_git_directory(root, git_dir_pin)
            pack_bytes = _v2_git_to_file(root, stage_fd, "repository.pack",
                git_plan["packBytesUpperBound"],
            "pack-objects", "--stdout", "--no-reuse-delta", "--no-reuse-object", "--window=0", "--depth=0",
                "--threads=1", "--window-memory=16m", input_fd=object_input_fd,
                pass_fds=(stage_fd,))
        finally:
            os.close(object_input_fd)
        _v2_verify_git_directory(root, git_dir_pin)
        pack_info = _v2_stage_stat(stage_fd, "repository.pack",
                                   max_bytes=git_plan["packBytesUpperBound"])
        pack_identity = (pack_info.st_dev, pack_info.st_ino)
        complete(charge, actual_bytes=pack_bytes)
        index_charge = consume(git_plan["indexBytesUpperBound"])
        index_name = _v2_verify_pack(root, git_dir_pin, stage_fd, "repository.pack", sizes,
                                     git_plan["indexBytesUpperBound"],
                                     expected_pack_identity=pack_identity)
        index_info = _v2_stage_stat(stage_fd, index_name,
                                    max_bytes=git_plan["indexBytesUpperBound"])
        index_identity = (index_info.st_dev, index_info.st_ino)
        actual_index_bytes = index_info.st_size
        complete(index_charge, actual_bytes=actual_index_bytes)
        route_guard()
        _v2_stage_unlink(stage_fd, index_name, index_identity)
        route_guard()
        _v2_stage_unlink(stage_fd, "object-input", object_input_identity)
        inventory_charge = consume(len(inventory_raw))
        inventory_identity = _v2_stage_write(stage_fd, "object-inventory", inventory_raw)
        complete(inventory_charge, actual_bytes=len(inventory_raw))

        def copy_object(source, sha, size):
            _verify_snapshot_stage(stage_fd, "objects", objects_fd, objects_identity)
            try:
                os.stat(sha, dir_fd=objects_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                _verify_existing_snapshot_object(objects_fd, stage_fd, objects_identity, sha, sha, size)
                return
            write_charge = consume(size)
            actual = _copy_file_v2(source, objects_fd, stage_fd, objects_identity, sha, sha, size)
            complete(write_charge, actual_bytes=actual)

        for relative, descriptor in files.items():
            if descriptor["type"] == "file":
                copy_object(root / relative, descriptor["sha256"], descriptor["bytes"])
        for entry, snapshot in zip(authorities, snapshots):
            if entry["kind"] != "sqlite-authority":
                for relative, descriptor in snapshot["files"].items():
                    if descriptor["type"] == "file":
                        copy_object(entry["source"] if relative == "." else entry["source"] / relative,
                                    descriptor["sha256"], descriptor["bytes"])
        for sha, content in index_package["blobs"].items():
            _verify_snapshot_stage(stage_fd, "objects", objects_fd, objects_identity)
            try:
                os.stat(sha, dir_fd=objects_fd, follow_symlinks=False)
            except FileNotFoundError:
                write_charge = consume(len(content))
                _write_snapshot_object_bytes(objects_fd, stage_fd, objects_identity, sha, content)
                complete(write_charge, actual_bytes=len(content))
            else:
                _verify_existing_snapshot_object(objects_fd, stage_fd, objects_identity,
                                                 sha, sha, len(content))

        if fault:
            fault("before-recheck")
        _v2_verify_git_directory(root, git_dir_pin)
        current_git = _v2_git_state(root, object_format)
        current_staged = {entry["oid"] for entry in parse_index(
            current_git["index"], object_format=object_format)}
        current_ids = sorted(set(_v2_object_ids(
            root, current_git["refs"], current_git["head"], object_format=object_format)) | current_staged)
        if (before_git != current_git or object_ids != current_ids or sizes != _v2_object_sizes(root, current_ids)
                or files != _inventory(root, authorities, exclusions, bounded=True)
                or snapshots != [_authority_snapshot(entry, bounded=True) for entry in authorities]):
            raise SnapshotError("Source changed during capture; quiesce writers and capture again")
        _v2_verify_git_directory(root, git_dir_pin)

        pack_digest, digest_identity = _v2_stage_digest(
            stage_fd, "repository.pack", max_bytes=git_plan["packBytesUpperBound"])
        if digest_identity != pack_identity:
            raise SnapshotError("Git pack artifact was replaced before manifest creation")
        manifest = {"protocolVersion": "2.0", "id": plan["id"], "planSha256": fingerprint(plan),
                    "git": {"objectFormat": object_format, "head": before_git["head"],
                            "headRef": before_git["headRef"], "refs": before_git["refs"],
                            "objectInventorySha256": hashlib.sha256(inventory_raw).hexdigest(),
                            "objectInventoryBytes": len(inventory_raw), "objectCount": len(object_ids),
                            "objectBytes": git_plan["objectBytes"],
                            "packSha256": pack_digest["sha256"],
                            "packBytes": pack_bytes, "packRepresentation": git_plan["packRepresentation"],
                            "index": index_package["manifest"]},
                    "files": files, "authorities": captured, "exclusions": exclusions,
                    "consistency": {"mode": "before-after-stability-check", "globalTransaction": False,
                                    "quiescence": plan["quiescence"]},
                    "restoreMode": "separate-target-with-standby-authorities"}
        manifest["sha256"] = fingerprint(manifest)
        manifest_bytes = _json(manifest)
        if len(manifest_bytes) > len(preflight_manifest_bytes):
            raise SnapshotError("Snapshot manifest exceeded its preflight byte bound")
        if len(manifest_bytes) > _V2_MANIFEST_LIMIT:
            raise SnapshotError("Snapshot manifest exceeds its fixed byte bound")
        manifest_charge = consume(len(manifest_bytes))
        _v2_stage_write(stage_fd, "manifest.json", manifest_bytes)
        complete(manifest_charge, actual_bytes=len(manifest_bytes))
        _v2_stage_chmod(stage_fd, "object-inventory", inventory_identity, 0o600)
        stage_bytes = 0
        expected_stage_files = {"repository.pack", "object-inventory", "manifest.json", "objects"}
        for entry in os.listdir(stage_fd):
            if entry not in expected_stage_files:
                raise SnapshotError("Snapshot staging contains an unexpected artifact")
            info = os.stat(entry, dir_fd=stage_fd, follow_symlinks=False)
            if entry == "objects":
                _verify_snapshot_stage(stage_fd, "objects", objects_fd, objects_identity)
                object_count = 0
                with os.scandir(objects_fd) as entries:
                    for child in entries:
                        object_count += 1
                        if object_count > 250_000 or child.name not in unique_objects:
                            raise SnapshotError("Snapshot object directory exceeds its planned inventory")
                        item = os.stat(child.name, dir_fd=objects_fd, follow_symlinks=False)
                        _v2_stage_info_valid(item)
                        stage_bytes += item.st_size
                if object_count != len(unique_objects):
                    raise SnapshotError("Snapshot object directory differs from its planned inventory")
            elif stat.S_ISREG(info.st_mode):
                _v2_stage_info_valid(info)
                stage_bytes += info.st_size
            else:
                raise SnapshotError("Snapshot staging contains an unsupported entry")
        _verify_snapshot_stage(stage_fd, "objects", objects_fd, objects_identity)
        if stage_bytes > stage_bound:
            raise SnapshotError("Snapshot exceeded its preflight peak-byte bound")
        route_guard()
        try:
            os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise SnapshotError("Snapshot destination appeared during capture")
        _verify_snapshot_stage(stage_fd, "objects", objects_fd, objects_identity)
        _verify_snapshot_stage(parent_fd, stage_name, stage_fd, stage_identity)
        os.fsync(stage_fd)
        os.rename(stage_name, destination.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        published = True
        published_info = os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        if (published_info.st_dev, published_info.st_ino) != stage_identity:
            raise SnapshotError("Published snapshot does not match its pinned staging directory")
        store._storage_admission_precommit()
        os.fsync(parent_fd)
        return manifest
    finally:
        if not published:
            try:
                _verify_snapshot_stage(parent_fd, stage_name, stage_fd, stage_identity)
                for entry in os.listdir(stage_fd):
                    info = os.stat(entry, dir_fd=stage_fd, follow_symlinks=False)
                    if entry == "objects":
                        if objects_fd is None:
                            raise SnapshotError("Snapshot object directory identity is unavailable")
                        _verify_snapshot_stage(stage_fd, "objects", objects_fd, objects_identity)
                        object_count = 0
                        with os.scandir(objects_fd) as children:
                            for child in children:
                                object_count += 1
                                if object_count > 250_000:
                                    raise SnapshotError("Snapshot object cleanup exceeds its entry-count bound")
                                child_info = os.stat(child.name, dir_fd=objects_fd, follow_symlinks=False)
                                if not stat.S_ISREG(child_info.st_mode):
                                    raise SnapshotError("Snapshot object directory changed during cleanup")
                                os.unlink(child.name, dir_fd=objects_fd)
                        _verify_snapshot_stage(stage_fd, "objects", objects_fd, objects_identity)
                        os.rmdir(entry, dir_fd=stage_fd)
                    elif stat.S_ISDIR(info.st_mode):
                        raise SnapshotError("Snapshot staging contains an unexpected directory")
                    elif stat.S_ISREG(info.st_mode):
                        os.unlink(entry, dir_fd=stage_fd)
                    else:
                        raise SnapshotError("Snapshot staging contains an unsupported entry")
                _verify_snapshot_stage(parent_fd, stage_name, stage_fd, stage_identity)
                os.rmdir(stage_name, dir_fd=parent_fd)
            except (OSError, SnapshotError):
                # A failed capture retains its charged staging residue for operator recovery.
                pass
        if objects_fd is not None:
            try:
                os.close(objects_fd)
            except OSError:
                pass
        try:
            os.close(stage_fd)
        except OSError:
            pass


def _capture_impl(plan, destination, *, fault=None, admission=None):
    root, authorities, exclusions = _validate_plan(plan)
    destination = Path(destination).absolute()
    resolved = destination.resolve()
    if destination.exists() or destination.is_symlink() or _within(resolved, root) or any(
            _within(resolved, e["source"]) or _within(e["source"], resolved) for e in authorities):
        raise SnapshotError("Snapshot destination must be new and outside all sources")
    if not destination.parent.is_dir():
        raise SnapshotError("Snapshot parent must already exist")
    def git_state():
        return {"head": _git(root, "rev-parse", "HEAD").decode().strip(),
                "headRef": _git(root, "rev-parse", "--symbolic-full-name", "HEAD").decode().strip(),
                "refs": _git(root, "show-ref", "--head").decode(),
                "indexSha256": hashlib.sha256(_git(root, "ls-files", "--stage", "-z")).hexdigest(),
                "indexPatch": _git(root, "diff", "--cached", "--binary", "--full-index", "--no-ext-diff", "--no-textconv", "HEAD", "--")}
    before = git_state()
    files = _inventory(root, authorities, exclusions)
    snapshots = [_authority_snapshot(e) for e in authorities]
    captured = [{"id": entry["id"], "target": entry["target"], **snapshot}
                for entry, snapshot in zip(authorities, snapshots)]
    manifest = {"protocolVersion": "1.0", "id": plan["id"], "planSha256": fingerprint(plan),
                "git": {"head": before["head"], "headRef": before["headRef"], "refs": before["refs"],
                        "indexSha256": before["indexSha256"], "bundleSha256": "0" * 64,
                        "indexPatchSha256": hashlib.sha256(before["indexPatch"]).hexdigest()},
                "files": files, "authorities": captured, "exclusions": exclusions,
                "consistency": {"mode": "before-after-stability-check", "globalTransaction": False,
                                "quiescence": plan["quiescence"]},
                "restoreMode": "separate-target-with-standby-authorities"}
    manifest["sha256"] = fingerprint(manifest)
    manifest_size = len(_json(manifest))
    unique_files = {}
    for descriptor in files.values():
        if descriptor["type"] == "file":
            unique_files[descriptor["sha256"]] = descriptor["bytes"]
    for snapshot in snapshots:
        for descriptor in snapshot.get("files", {}).values():
            if descriptor["type"] == "file":
                unique_files[descriptor["sha256"]] = descriptor["bytes"]
    bundle_bound = _git_bundle_upper_bound(root, before["refs"].encode()) if admission is not None else 0
    stage_bound = bundle_bound + len(before["indexPatch"]) + sum(unique_files.values()) + manifest_size
    if admission is not None:
        store, _ = admission
        # This is an aggregate noncharging bound check. Each materialized
        # object is charged separately immediately before its write below.
        store._storage_admission_require(stage_bound)
    # Admitted staging stays inside the registered retained root, so an
    # interrupted process leaves its exact partial bytes visible to inventory.
    temporary = Path(tempfile.mkdtemp(prefix=".brain-snapshot-", dir=destination.parent))
    try:
        charge = None
        if admission is not None:
            charge = store._storage_admission_consume(bundle_bound)
        _git(root, "bundle", "create", str(temporary / "repository.bundle"), "--all", "HEAD")
        os.chmod(temporary / "repository.bundle", 0o600)
        if (admission is not None
                and (temporary / "repository.bundle").stat().st_size > bundle_bound):
            raise SnapshotError("Repository bundle exceeded its preflight bound")
        if admission is not None:
            store._storage_admission_complete_external(
                charge, actual_bytes=(temporary / "repository.bundle").stat().st_size)
        charge = None
        if admission is not None:
            charge = store._storage_admission_consume(len(before["indexPatch"]))
        _private_file(temporary / "index.patch", before["indexPatch"])
        if admission is not None:
            store._storage_admission_complete_external(
                charge, actual_bytes=len(before["indexPatch"]))
        blobs = temporary / "objects"
        blobs.mkdir(mode=0o700)

        def copy_file(path, descriptor):
            nonlocal charge
            if descriptor["type"] == "symlink":
                return
            target = blobs / descriptor["sha256"]
            if not target.exists():
                if admission is not None:
                    charge = store._storage_admission_consume(descriptor["bytes"])
                _copy_file(path, target, descriptor["sha256"])
                if admission is not None:
                    store._storage_admission_complete_external(
                        charge, actual_bytes=descriptor["bytes"])
        for relative, descriptor in files.items():
            copy_file(root / relative, descriptor)
        for entry, snapshot in zip(authorities, snapshots):
            if entry["kind"] != "sqlite-authority":
                for relative, descriptor in snapshot["files"].items():
                    copy_file(entry["source"] if relative == "." else entry["source"] / relative, descriptor)
        if fault:
            fault("before-recheck")
        if (before != git_state() or files != _inventory(root, authorities, exclusions)
                or snapshots != [_authority_snapshot(e) for e in authorities]):
            raise SnapshotError("Source changed during capture; quiesce writers and capture again")
        manifest["git"]["bundleSha256"] = _describe(temporary / "repository.bundle")["sha256"]
        manifest.pop("sha256", None)
        manifest["sha256"] = fingerprint(manifest)
        manifest_bytes = _json(manifest)
        if len(manifest_bytes) != manifest_size:
            raise SnapshotError("Snapshot manifest exceeded its preflight bound")
        if admission is not None:
            charge = store._storage_admission_consume(len(manifest_bytes))
        _private_file(temporary / "manifest.json", manifest_bytes)
        if admission is not None:
            store._storage_admission_complete_external(
                charge, actual_bytes=len(manifest_bytes))
        # Rename publishes only a complete snapshot; never merge with an existing directory.
        if destination.exists() or destination.is_symlink():
            raise SnapshotError("Snapshot destination appeared during capture")
        if admission is not None:
            staged_bytes = sum(path.stat().st_size for path in temporary.rglob("*")
                               if path.is_file() and not path.is_symlink())
            if staged_bytes > stage_bound:
                raise SnapshotError("Snapshot exceeded its preflight bound")
        temporary.rename(destination)
        if admission is not None:
            store._storage_admission_precommit()
        return manifest
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def restore(snapshot, destination, *, admission=None, context=None):
    """Restore into a new standby tree, optionally under adopted storage admission."""
    if admission is None:
        if context is not None:
            raise SnapshotError("An admitted restore context cannot be used for a legacy restore")
        return _restore_impl(snapshot, destination)
    # Restore currently materializes a full Git tree and SQLite authorities
    # before a trustworthy per-write bound can be enforced. Refuse before
    # creating its staging directory; a final size check would be too late. The
    # host may already have constructed a trusted context, but it has no effect
    # until a bounded v2 writer is implemented and reviewed.
    raise SnapshotError("adopted restore is unavailable until bounded staging is implemented")


def _v2_read_snapshot_file(directory_fd, name, *, max_bytes):
    """Read one bounded snapshot member through a pinned no-follow descriptor."""
    descriptor, identity = _v2_stage_open(directory_fd, name)
    try:
        info = _v2_verify_stage_file(directory_fd, name, descriptor, identity,
                                     max_bytes=max_bytes)
        chunks = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                raise SnapshotError("Snapshot member exceeds its fixed byte bound")
            chunks.append(chunk)
        _v2_verify_stage_file(directory_fd, name, descriptor, identity,
                              expected_size=size, max_bytes=max_bytes)
        final = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        initial_identity = _v2_stat_identity(info)
        final_identity = _v2_stat_identity(final)
        if (size != info.st_size or initial_identity != final_identity
                or _v2_stat_identity(named) != final_identity):
            raise SnapshotError("Snapshot member changed while reading")
        return b"".join(chunks), final_identity
    finally:
        os.close(descriptor)


def _v2_hash_snapshot_pack(directory_fd, max_bytes):
    descriptor, identity = _v2_stage_open(directory_fd, "repository.pack")
    digest = hashlib.sha256()
    size = 0
    try:
        info = _v2_verify_stage_file(directory_fd, "repository.pack", descriptor, identity,
                                     max_bytes=max_bytes)
        if info.st_size < 32:
            raise SnapshotError("Snapshot Git pack is truncated")
        header = os.read(descriptor, 12)
        if len(header) != 12 or header[:4] != b"PACK":
            raise SnapshotError("Snapshot Git pack header is invalid")
        version, count = int.from_bytes(header[4:8], "big"), int.from_bytes(header[8:12], "big")
        if version not in {2, 3}:
            raise SnapshotError("Snapshot Git pack version is unsupported")
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                raise SnapshotError("Snapshot Git pack exceeds its fixed byte bound")
            digest.update(chunk)
        _v2_verify_stage_file(directory_fd, "repository.pack", descriptor, identity,
                              expected_size=size, max_bytes=max_bytes)
        final = os.fstat(descriptor)
        named = os.stat("repository.pack", dir_fd=directory_fd, follow_symlinks=False)
        final_identity = _v2_stat_identity(final)
        if (size != info.st_size or _v2_stat_identity(info) != final_identity
                or _v2_stat_identity(named) != final_identity):
            raise SnapshotError("Snapshot Git pack changed while reading")
        return {"bytes": size, "sha256": digest.hexdigest(), "version": version,
                "objectCount": count}, final_identity
    finally:
        os.close(descriptor)


def _v2_hash_snapshot_object(directory_fd, name, max_bytes):
    descriptor, identity = _v2_stage_open(directory_fd, name)
    digest = hashlib.sha256()
    size = 0
    try:
        info = _v2_verify_stage_file(directory_fd, name, descriptor, identity,
                                     max_bytes=max_bytes)
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                raise SnapshotError("Snapshot content-addressed object exceeds its byte bound")
            digest.update(chunk)
        _v2_verify_stage_file(directory_fd, name, descriptor, identity,
                              expected_size=size, max_bytes=max_bytes)
        final = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        final_identity = _v2_stat_identity(final)
        if (size != info.st_size or _v2_stat_identity(info) != final_identity
                or _v2_stat_identity(named) != final_identity):
            raise SnapshotError("Snapshot content-addressed object changed while reading")
        return size, digest.hexdigest(), final_identity
    finally:
        os.close(descriptor)


def _v2_stat_identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_nlink)


def _v2_verify_snapshot_member_identity(directory_fd, name, identity):
    current = os.stat(_v2_stage_name(name), dir_fd=directory_fd, follow_symlinks=False)
    _v2_stage_info_valid(current)
    if _v2_stat_identity(current) != identity:
        raise SnapshotError("Snapshot member changed during validation")


def _v2_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotError("Snapshot JSON contains a duplicate object key")
        result[key] = value
    return result


def _v2_parse_snapshot_json(raw, label):
    def invalid_constant(value):
        raise SnapshotError(f"Snapshot {label} contains a non-finite number: {value}")
    try:
        return json.loads(raw, object_pairs_hook=_v2_json_object, parse_constant=invalid_constant)
    except SnapshotError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, MemoryError, ValueError) as exc:
        raise SnapshotError(f"Snapshot {label} is invalid or exceeds its parser bound") from exc


def _v2_relative(value, label, *, allow_dot=False):
    if not isinstance(value, str) or len(value) > 4096:
        raise SnapshotError(f"Snapshot {label} path is invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SnapshotError(f"Snapshot {label} path is invalid") from exc
    if len(encoded) > 4096 or (allow_dot and value == "."):
        if allow_dot and value == ".":
            return "."
        raise SnapshotError(f"Snapshot {label} path is invalid")
    normalized = _relative(value)
    if normalized != value:
        raise SnapshotError(f"Snapshot {label} path is not canonical")
    if len(value.split("/")) > 256:
        raise SnapshotError(f"Snapshot {label} path is too deep")
    return normalized


def _v2_descriptor_set(value, label, *, allow_dot=False):
    if not isinstance(value, dict) or len(value) > _V2_INVENTORY_ENTRY_LIMIT:
        raise SnapshotError(f"Snapshot {label} exceeds its path-count bound")
    descriptors, total_bytes = {}, 0
    for relative, descriptor in value.items():
        path = _v2_relative(relative, label, allow_dot=allow_dot)
        if (not isinstance(descriptor, dict) or descriptor.get("type") not in {"file", "symlink"}
                or set(descriptor) != ({"type", "sha256", "bytes", "mode"}
                    if descriptor.get("type") == "file" else {"type", "target"})):
            raise SnapshotError(f"Snapshot {label} descriptor has an unsupported shape")
        if descriptor["type"] == "file":
            size, digest, mode = descriptor["bytes"], descriptor["sha256"], descriptor["mode"]
            if (type(size) is not int or not 0 <= size <= _V2_INVENTORY_FILE_LIMIT
                    or type(mode) is not int or not 0 <= mode <= 0o777
                    or not isinstance(digest, str) or len(digest) != 64
                    or any(char not in "0123456789abcdef" for char in digest)):
                raise SnapshotError(f"Snapshot {label} file descriptor is invalid")
            total_bytes += size
            if total_bytes > _V2_INVENTORY_TREE_LIMIT:
                raise SnapshotError(f"Snapshot {label} exceeds its aggregate byte bound")
        else:
            target = descriptor["target"]
            try:
                target_bytes = target.encode("utf-8") if isinstance(target, str) else b""
            except UnicodeEncodeError as exc:
                raise SnapshotError(f"Snapshot {label} symlink descriptor is invalid") from exc
            if (not isinstance(target, str) or len(target) > 4096
                    or len(target_bytes) > 4096 or "\x00" in target):
                raise SnapshotError(f"Snapshot {label} symlink descriptor is invalid")
        descriptors[path] = dict(descriptor)
    _v2_validate_tree_paths(descriptors)
    return descriptors, total_bytes


def _v2_validate_tree_paths(descriptors, directories=()):
    node_paths = set(descriptors)
    for path in node_paths:
        parts = path.split("/")
        for index in range(1, len(parts)):
            if "/".join(parts[:index]) in node_paths:
                raise SnapshotError("Snapshot file or symlink path is an ancestor of another path")
    directory_paths = set(directories)
    if node_paths & directory_paths:
        raise SnapshotError("Snapshot path is both a file and a directory")
    for path in directory_paths:
        parts = path.split("/")
        for index in range(1, len(parts) + 1):
            if "/".join(parts[:index]) in node_paths:
                raise SnapshotError("Snapshot directory is below a file or symlink path")


def _v2_validate_index_manifest(manifest, object_format):
    from brain_snapshot_v2 import (MAX_INDEX_ENTRIES, MAX_INDEX_PATH_BYTES,
                                   MAX_INDEX_PATH_TOTAL, MAX_INDEX_RAW_BYTES, MAX_STAGED_BLOB_BYTES,
                                   MAX_STAGED_BLOBS_BYTES, PROTOCOL)

    required = {"protocolVersion", "objectFormat", "indexSha256", "entries", "blobs", "sha256"}
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise SnapshotError("Snapshot Git index manifest has unsupported fields")
    oid_length = 40 if object_format == "sha1" else 64
    if (manifest["protocolVersion"] != PROTOCOL or manifest["objectFormat"] != object_format
            or any(not isinstance(manifest[key], str) or len(manifest[key]) != 64
                   or any(char not in "0123456789abcdef" for char in manifest[key])
                   for key in ("indexSha256", "sha256"))):
        raise SnapshotError("Snapshot Git index manifest identity is invalid")
    entries, blobs = manifest["entries"], manifest["blobs"]
    if (not isinstance(entries, list) or len(entries) > MAX_INDEX_ENTRIES
            or not isinstance(blobs, dict) or len(blobs) > MAX_INDEX_ENTRIES
            or len(blobs) > len(entries)):
        raise SnapshotError("Snapshot Git index manifest exceeds its structural bound")
    encoded_path_total = 0
    for entry in entries:
        if (not isinstance(entry, dict) or set(entry) != {"mode", "oid", "pathB64"}
                or not isinstance(entry["mode"], str) or entry["mode"] not in {"100644", "100755", "120000"}
                or not isinstance(entry["oid"], str) or len(entry["oid"]) != oid_length
                or any(char not in "0123456789abcdef" for char in entry["oid"])
                or not isinstance(entry["pathB64"], str)
                or len(entry["pathB64"]) > 4 * ((MAX_INDEX_PATH_BYTES + 2) // 3)):
            raise SnapshotError("Snapshot Git index entry exceeds its structural bound")
        encoded_path_total += len(entry["pathB64"])
        if encoded_path_total > (MAX_INDEX_PATH_TOTAL * 4 + 2) // 3 + MAX_INDEX_ENTRIES * 4:
            raise SnapshotError("Snapshot Git index paths exceed their aggregate bound")
    blob_bytes = 0
    for oid, descriptor in blobs.items():
        if (not isinstance(oid, str) or len(oid) != oid_length
                or any(char not in "0123456789abcdef" for char in oid)
                or not isinstance(descriptor, dict) or set(descriptor) != {"sha256", "bytes"}
                or not isinstance(descriptor["sha256"], str) or len(descriptor["sha256"]) != 64
                or any(char not in "0123456789abcdef" for char in descriptor["sha256"])
                or type(descriptor["bytes"]) is not int
                or not 0 <= descriptor["bytes"] <= MAX_STAGED_BLOB_BYTES):
            raise SnapshotError("Snapshot Git staged-blob descriptor is invalid")
        blob_bytes += descriptor["bytes"]
        if blob_bytes > MAX_STAGED_BLOBS_BYTES:
            raise SnapshotError("Snapshot Git staged blobs exceed their aggregate bound")
    try:
        encoded_manifest = json.dumps(manifest, ensure_ascii=True, sort_keys=True,
                                      separators=(",", ":"), allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise SnapshotError("Snapshot Git index manifest is invalid JSON") from exc
    if (len(encoded_manifest) > MAX_INDEX_RAW_BYTES
            or fingerprint({key: value for key, value in manifest.items() if key != "sha256"})
            != manifest["sha256"]):
        raise SnapshotError("Snapshot Git index manifest digest or size is invalid")
    return blob_bytes


def _v2_validate_object_inventory(raw, git, required_oids):
    from brain_snapshot_v2 import MAX_GIT_OBJECTS

    expected_bytes = git["objectInventoryBytes"]
    if (type(expected_bytes) is not int or not 1 <= expected_bytes <= MAX_GIT_OBJECTS * 65
            or len(raw) != expected_bytes
            or hashlib.sha256(raw).hexdigest() != git["objectInventorySha256"]):
        raise SnapshotError("Snapshot Git object inventory digest or byte count is invalid")
    oid_length = 40 if git["objectFormat"] == "sha1" else 64
    count, previous, offset = 0, None, 0
    remaining = set(required_oids)
    while offset < len(raw):
        end = raw.find(b"\n", offset, min(len(raw), offset + oid_length + 2))
        if end < 0:
            raise SnapshotError("Snapshot Git object inventory is malformed")
        oid = raw[offset:end]
        if (len(oid) != oid_length or any(byte not in b"0123456789abcdef" for byte in oid)
                or (previous is not None and oid <= previous)):
            raise SnapshotError("Snapshot Git object inventory is invalid or unsorted")
        count += 1
        if count > MAX_GIT_OBJECTS:
            raise SnapshotError("Snapshot Git object inventory exceeds its count bound")
        remaining.discard(oid.decode("ascii"))
        previous, offset = oid, end + 1
    if count != git["objectCount"] or remaining:
        raise SnapshotError("Snapshot Git object inventory count differs from its manifest")
    return count


def validate_v2_snapshot(snapshot):
    """Read-only v2 archive validation; raw pack hash is not semantic Git verification."""
    from brain_storage_admission import _open_directory_chain
    from bisect import bisect_left
    from brain_snapshot_v2 import MAX_BUNDLE_BYTES, MAX_GIT_OBJECTS, validate_index_package
    from knowledge_store import SQLiteAuthority, _bounded_restore_snapshot

    path = Path(snapshot).absolute()
    if not path.name or path.name in {".", ".."}:
        raise SnapshotError("Snapshot directory path is invalid")
    try:
        parent_fd = _open_directory_chain(path.parent)
    except (OSError, RuntimeError) as exc:
        raise SnapshotError("Snapshot directory parent is unavailable") from exc
    directory_fd = None
    try:
        parent_identity = _v2_stat_identity(os.fstat(parent_fd))
        named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(named.st_mode) or named.st_uid != os.geteuid() or named.st_mode & 0o077:
            raise SnapshotError("Snapshot directory is not owner-private")
        directory_fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                               dir_fd=parent_fd)
        identity = (named.st_dev, named.st_ino)
        opened, current = os.fstat(directory_fd), os.stat(path.name, dir_fd=parent_fd,
                                                          follow_symlinks=False)
        if ((opened.st_dev, opened.st_ino) != identity or (current.st_dev, current.st_ino) != identity
                or not stat.S_ISDIR(opened.st_mode) or opened.st_uid != os.geteuid()
                or opened.st_mode & 0o077):
            raise SnapshotError("Snapshot directory changed while opening")
        directory_full_identity = _v2_stat_identity(opened)
        names = []
        with os.scandir(directory_fd) as children:
            for child in children:
                names.append(child.name)
                if len(names) > 4:
                    raise SnapshotError("Snapshot directory contains too many top-level entries")
        if set(names) != {"manifest.json", "repository.pack", "object-inventory", "objects"}:
            raise SnapshotError("Snapshot directory contents do not match the v2 format")

        manifest_raw, manifest_identity = _v2_read_snapshot_file(
            directory_fd, "manifest.json", max_bytes=_V2_MANIFEST_LIMIT)
        manifest = _v2_parse_snapshot_json(manifest_raw, "manifest")
        required = {"protocolVersion", "id", "planSha256", "git", "files", "authorities",
                    "exclusions", "consistency", "restoreMode", "sha256"}
        if (not isinstance(manifest, dict) or set(manifest) != required
                or manifest.get("protocolVersion") != "2.0"
                or not isinstance(manifest.get("id"), str) or not manifest["id"]
                or len(manifest["id"]) > 256
                or not isinstance(manifest.get("planSha256"), str) or len(manifest["planSha256"]) != 64
                or any(char not in "0123456789abcdef" for char in manifest["planSha256"])
                or not isinstance(manifest.get("sha256"), str) or len(manifest["sha256"]) != 64
                or any(char not in "0123456789abcdef" for char in manifest["sha256"])):
            raise SnapshotError("Snapshot v2 manifest has an unsupported shape")
        try:
            manifest_digest = fingerprint({key: value for key, value in manifest.items()
                                           if key != "sha256"})
        except (RecursionError, TypeError, ValueError) as exc:
            raise SnapshotError("Snapshot v2 manifest exceeds its canonicalization bound") from exc
        if manifest_digest != manifest["sha256"]:
            raise SnapshotError("Snapshot v2 manifest digest is invalid")
        git = manifest["git"]
        git_keys = {"objectFormat", "head", "headRef", "refs", "objectInventorySha256",
                    "objectInventoryBytes", "objectCount", "objectBytes", "packSha256",
                    "packBytes", "packRepresentation", "index"}
        if not isinstance(git, dict) or set(git) != git_keys:
            raise SnapshotError("Snapshot v2 Git manifest has an unsupported shape")
        object_format = git["objectFormat"]
        if not isinstance(object_format, str):
            raise SnapshotError("Snapshot v2 Git object format is invalid")
        if object_format not in {"sha1", "sha256"}:
            raise SnapshotError("Snapshot v2 Git object format is unsupported")
        oid_length = 40 if object_format == "sha1" else 64
        head = git["head"]
        if (not isinstance(head, str) or len(head) != oid_length
                or any(char not in "0123456789abcdef" for char in head)):
            raise SnapshotError("Snapshot v2 Git object ID is invalid")
        if git["headRef"] != "HEAD" and not _valid_v2_refname(git["headRef"]):
            raise SnapshotError("Snapshot v2 HEAD reference is invalid")
        if (type(git["objectCount"]) is not int or not 1 <= git["objectCount"] <= MAX_GIT_OBJECTS
                or type(git["objectBytes"]) is not int or not 0 <= git["objectBytes"] <= 8 * 1024**3
                or type(git["packBytes"]) is not int or not 32 <= git["packBytes"] <= MAX_BUNDLE_BYTES
                or git["packRepresentation"] != "non-delta-no-reuse/v1"
                or not isinstance(git["packSha256"], str) or len(git["packSha256"]) != 64
                or any(char not in "0123456789abcdef" for char in git["packSha256"])
                or not isinstance(git["objectInventorySha256"], str)
                or len(git["objectInventorySha256"]) != 64
                or any(char not in "0123456789abcdef" for char in git["objectInventorySha256"])):
            raise SnapshotError("Snapshot v2 Git manifest exceeds its fixed bounds")
        refs = git["refs"]
        if not isinstance(refs, list) or len(refs) > _V2_REF_COUNT_LIMIT:
            raise SnapshotError("Snapshot v2 Git references exceed their count bound")
        previous_ref = None
        for ref in refs:
            if (not isinstance(ref, dict) or set(ref) != {"name", "oid"}
                    or not _valid_v2_refname(ref["name"])
                    or not isinstance(ref["oid"], str) or len(ref["oid"]) != oid_length
                    or any(char not in "0123456789abcdef" for char in ref["oid"])
                    or (previous_ref is not None and ref["name"] <= previous_ref)):
                raise SnapshotError("Snapshot v2 Git reference is malformed or unsorted")
            previous_ref = ref["name"]

        files, file_bytes = _v2_descriptor_set(manifest["files"], "working-file inventory")
        authorities = manifest["authorities"]
        if not isinstance(authorities, list) or len(authorities) > 1024:
            raise SnapshotError("Snapshot authority list exceeds its count bound")
        exclusions = manifest["exclusions"]
        if not isinstance(exclusions, list) or len(exclusions) > _V2_INVENTORY_ENTRY_LIMIT:
            raise SnapshotError("Snapshot exclusions exceed their count bound")
        targets, expected_objects = [], {}
        root_paths = sorted(files)
        total_descriptor_count = len(files)

        def overlaps_root_path(candidate):
            offset = bisect_left(root_paths, candidate)
            nearby = root_paths[max(0, offset - 1):min(len(root_paths), offset + 1)]
            return any(candidate == other or candidate.startswith(other + "/")
                       or other.startswith(candidate + "/") for other in nearby)

        authority_ids = set()

        def add_descriptors(descriptors):
            for descriptor in descriptors.values():
                if descriptor["type"] == "file":
                    digest, size = descriptor["sha256"], descriptor["bytes"]
                    previous = expected_objects.setdefault(digest, size)
                    if previous != size:
                        raise SnapshotError("Snapshot content address has conflicting file sizes")

        add_descriptors(files)
        total_retained = file_bytes
        for entry in authorities:
            if (not isinstance(entry, dict) or set(entry) not in (
                    {"id", "target", "kind", "snapshot"},
                    {"id", "target", "kind", "files", "directories"})
                    or not isinstance(entry.get("id"), str) or not entry["id"] or len(entry["id"]) > 256):
                raise SnapshotError("Snapshot authority descriptor is malformed")
            if entry["id"] in authority_ids:
                raise SnapshotError("Snapshot authority IDs are duplicated")
            authority_ids.add(entry["id"])
            target = _v2_relative(entry["target"], "authority target")
            if (not isinstance(entry["kind"], str) or target in targets
                    or overlaps_root_path(target)
                    or any(_within(Path(target), Path(other)) or _within(Path(other), Path(target))
                           for other in targets)):
                raise SnapshotError("Snapshot authority targets overlap retained paths")
            targets.append(target)
            if entry["kind"] == "sqlite-authority":
                if set(entry) != {"id", "target", "kind", "snapshot"}:
                    raise SnapshotError("Snapshot SQLite authority descriptor is malformed")
                _bounded_restore_snapshot(entry["snapshot"])
                SQLiteAuthority.validate_snapshot(entry["snapshot"])
            elif entry["kind"] in {"file", "tree"}:
                if set(entry) != {"id", "target", "kind", "files", "directories"}:
                    raise SnapshotError("Snapshot file authority descriptor is malformed")
                descriptors, used = _v2_descriptor_set(
                    entry["files"], f"authority {entry['id']} file inventory", allow_dot=True)
                if entry["kind"] == "file":
                    if (set(descriptors) != {"."} or descriptors["."]["type"] != "file"
                            or entry["directories"] != []):
                        raise SnapshotError("Snapshot file authority must contain one regular root file")
                elif "." in descriptors:
                    raise SnapshotError("Snapshot tree authority cannot describe its root as a file")
                total_descriptor_count += len(descriptors)
                if total_descriptor_count > 1_000_000:
                    raise SnapshotError("Snapshot aggregate file-descriptor count exceeds its bound")
                directories = entry["directories"]
                if not isinstance(directories, list) or len(directories) > _V2_INVENTORY_ENTRY_LIMIT:
                    raise SnapshotError("Snapshot authority directory inventory exceeds its count bound")
                previous_directory = None
                for relative in directories:
                    relative = _v2_relative(relative, "authority directory", allow_dot=True)
                    if previous_directory is not None and relative <= previous_directory:
                        raise SnapshotError("Snapshot authority directories are malformed or unsorted")
                    previous_directory = relative
                _v2_validate_tree_paths(descriptors, directories)
                total_descriptor_count += len(directories)
                if total_descriptor_count > 1_000_000:
                    raise SnapshotError("Snapshot aggregate path count exceeds its bound")
                total_retained += used
                add_descriptors(descriptors)
            else:
                raise SnapshotError("Snapshot authority adapter is unsupported")
        if total_retained > _V2_INVENTORY_TREE_LIMIT:
            raise SnapshotError("Snapshot retained file data exceeds its aggregate byte bound")
        consistency = manifest["consistency"]
        if (not isinstance(consistency, dict)
                or set(consistency) != {"mode", "globalTransaction", "quiescence"}
                or consistency["mode"] != "before-after-stability-check"
                or consistency["globalTransaction"] is not False
                or not isinstance(consistency["quiescence"], str)
                or not consistency["quiescence"].strip() or len(consistency["quiescence"]) > 4096
                or manifest["restoreMode"] != "separate-target-with-standby-authorities"):
            raise SnapshotError("Snapshot consistency declaration is invalid")
        for exclusion in exclusions:
            if (not isinstance(exclusion, dict) or set(exclusion) != {"path", "reason"}
                    or not isinstance(exclusion["reason"], str) or not exclusion["reason"].strip()):
                raise SnapshotError("Snapshot exclusion declaration is invalid")
            exclusion_path = _v2_relative(exclusion["path"], "exclusion")
            if overlaps_root_path(exclusion_path) or any(
                    _within(Path(exclusion_path), Path(target))
                    or _within(Path(target), Path(exclusion_path)) for target in targets):
                raise SnapshotError("Snapshot exclusions overlap retained paths or authorities")

        index_manifest = git["index"]
        _v2_validate_index_manifest(index_manifest, object_format)
        index_blob_sizes = {}
        for descriptor in index_manifest["blobs"].values():
            sha, size = descriptor["sha256"], descriptor["bytes"]
            previous = expected_objects.setdefault(sha, size)
            if previous != size:
                raise SnapshotError("Snapshot staged blob conflicts with a retained file size")
            index_blob_sizes[sha] = size
        if len(expected_objects) > 250_000 or sum(expected_objects.values()) > _V2_INVENTORY_TREE_LIMIT:
            raise SnapshotError("Snapshot content-addressed objects exceed their aggregate bounds")

        required_oids = {git["head"], *(ref["oid"] for ref in refs),
                         *(descriptor_oid for descriptor_oid in index_manifest["blobs"])}
        if len(required_oids) > MAX_GIT_OBJECTS:
            raise SnapshotError("Snapshot required Git object set exceeds its count bound")
        raw_inventory, inventory_identity = _v2_read_snapshot_file(
            directory_fd, "object-inventory", max_bytes=min(MAX_GIT_OBJECTS * 65,
                                                             _V2_COMMAND_OUTPUT_LIMIT))
        object_count = _v2_validate_object_inventory(raw_inventory, git, required_oids)
        pack, pack_identity = _v2_hash_snapshot_pack(directory_fd, MAX_BUNDLE_BYTES)
        if (pack["bytes"] != git["packBytes"] or pack["sha256"] != git["packSha256"]
                or pack["objectCount"] != object_count):
            raise SnapshotError("Snapshot Git pack header or raw digest differs from its manifest")

        object_fd, objects_directory_identity = _v2_stage_open_directory(directory_fd, "objects")
        try:
            object_directory_full_identity = _v2_stat_identity(os.fstat(object_fd))
            object_names = []
            with os.scandir(object_fd) as children:
                for child in children:
                    object_names.append(child.name)
                    if len(object_names) > 250_000:
                        raise SnapshotError("Snapshot object directory exceeds its count bound")
            if set(object_names) != set(expected_objects):
                raise SnapshotError("Snapshot object directory differs from its manifest references")
            index_blobs = {}
            object_identities = []
            for name, expected_size in expected_objects.items():
                if name in index_blob_sizes:
                    raw, member_identity = _v2_read_snapshot_file(
                        object_fd, name, max_bytes=expected_size)
                    actual_size, actual_digest = len(raw), hashlib.sha256(raw).hexdigest()
                    index_blobs[name] = raw
                else:
                    actual_size, actual_digest, member_identity = _v2_hash_snapshot_object(
                        object_fd, name, max_bytes=expected_size)
                if actual_size != expected_size or actual_digest != name:
                    raise SnapshotError("Snapshot content-addressed file is corrupt")
                object_identities.append((name, member_identity))
            package = validate_index_package({"manifest": index_manifest, "blobs": index_blobs})
            if len(package) != len(index_manifest["blobs"]):
                raise SnapshotError("Snapshot staged-blob package differs from its manifest")
            for name, member_identity in object_identities:
                _v2_verify_snapshot_member_identity(object_fd, name, member_identity)
            if _v2_stat_identity(os.fstat(object_fd)) != object_directory_full_identity:
                raise SnapshotError("Snapshot object directory changed during validation")
            _verify_snapshot_stage(directory_fd, "objects", object_fd, objects_directory_identity)
        finally:
            os.close(object_fd)

        _v2_verify_snapshot_member_identity(directory_fd, "manifest.json", manifest_identity)
        _v2_verify_snapshot_member_identity(directory_fd, "object-inventory", inventory_identity)
        _v2_verify_snapshot_member_identity(directory_fd, "repository.pack", pack_identity)
        if _v2_stat_identity(os.fstat(directory_fd)) != directory_full_identity:
            raise SnapshotError("Snapshot directory contents changed during validation")
        _verify_snapshot_stage(parent_fd, path.name, directory_fd, identity)
        _verify_snapshot_parent(path.parent, parent_fd, parent_identity[:2])
        return {"manifest": manifest, "manifestSha256": manifest["sha256"],
                "packBytes": pack["bytes"], "packSha256": pack["sha256"],
                "packObjectCount": pack["objectCount"], "packObjectSemanticsVerified": False,
                "objectCount": object_count, "contentObjectCount": len(expected_objects),
                "contentBytes": sum(expected_objects.values()), "readOnly": True}
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
        os.close(parent_fd)


def _restore_tree_bytes(root):
    total = 0
    for path in Path(root).rglob("*"):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise SnapshotError("Admitted restore contains an unsafe retained directory")
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
            raise SnapshotError("Admitted restore contains an unsupported or unsafe retained object")
        total += info.st_size
    return total


def _restore_impl(snapshot, destination, *, admission=None):
    snapshot, destination = Path(snapshot).resolve(strict=True), Path(destination).absolute()
    if destination.exists() or destination.is_symlink() or _within(destination.resolve(), snapshot):
        raise SnapshotError("Restore target must be new and outside the snapshot")
    _describe(snapshot / "manifest.json")  # Refuse a manifest symlink before reading it.
    manifest = json.loads((snapshot / "manifest.json").read_text())
    if manifest.get("protocolVersion") != "1.0" or manifest.get("sha256") != fingerprint(
            {k: v for k, v in manifest.items() if k != "sha256"}):
        raise SnapshotError("Snapshot manifest is corrupt or unsupported")
    for name, key in (("repository.bundle", "bundleSha256"), ("index.patch", "indexPatchSha256")):
        if _describe(snapshot / name)["sha256"] != manifest["git"][key]:
            raise SnapshotError("Repository snapshot artifact is corrupt")
    # Validate data and path boundaries before creating a restore target.
    paths = set()
    for relative in manifest["files"]:
        paths.add(_relative(relative))
    for entry in manifest["authorities"]:
        target = _relative(entry["target"])
        if any(_within(Path(p), Path(target)) or _within(Path(target), Path(p)) for p in paths):
            raise SnapshotError("Restored paths overlap")
        paths.add(target)
        if entry["kind"] == "sqlite-authority":
            SQLiteAuthority.validate_snapshot(entry["snapshot"])
        elif entry["kind"] not in ("file", "tree"):
            raise SnapshotError("Unsupported restore adapter")
    for path in paths:
        if any(parent.as_posix() in paths for parent in Path(path).parents if str(parent) != "."):
            raise SnapshotError("Restored file paths overlap")
    descriptors = list(manifest["files"].values())
    for entry in manifest["authorities"]:
        if entry["kind"] in ("file", "tree"):
            for relative in entry["files"]:
                if relative != ".":
                    _relative(relative)
            for relative in entry["directories"]:
                _relative(relative)
            descriptors.extend(entry["files"].values())
    for descriptor in descriptors:
        if descriptor["type"] == "symlink":
            if not isinstance(descriptor["target"], str) or "\x00" in descriptor["target"]:
                raise SnapshotError("Invalid restored symlink")
            continue
        digest = descriptor["sha256"]
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise SnapshotError("Invalid object digest")
        actual = _describe(_safe(snapshot, "objects/" + digest))
        if actual["sha256"] != digest or actual["bytes"] != descriptor["bytes"]:
            raise SnapshotError("Snapshot object is corrupt")
    temporary = Path(tempfile.mkdtemp(prefix=".brain-restore-", dir=destination.parent))
    try:
        target = temporary / "repository"
        _git(temporary, "clone", "--quiet", "--no-checkout", "--", str(snapshot / "repository.bundle"), str(target))
        _git(target, "config", "core.hooksPath", "/dev/null")
        _git(target, "config", "core.fsmonitor", "false")
        _git(target, "update-ref", "--no-deref", "HEAD", manifest["git"]["head"])
        # Clone creates its own origin tracking refs. Restore the captured ref
        # names/values so custom refs and other branches remain recoverable too.
        for ref in _git(target, "for-each-ref", "--format=%(refname)").decode().splitlines():
            _git(target, "update-ref", "-d", ref)
        for row in manifest["git"]["refs"].splitlines():
            digest, ref = row.split(" ", 1)
            if ref != "HEAD":
                _git(target, "check-ref-format", ref)
                _git(target, "update-ref", ref, digest)
        if manifest["git"]["headRef"] != "HEAD":
            _git(target, "symbolic-ref", "HEAD", manifest["git"]["headRef"])
        _git(target, "read-tree", "HEAD")
        if (snapshot / "index.patch").stat().st_size:
            _git(target, "apply", "--cached", "--binary", str(snapshot / "index.patch"))

        def materialize(path, descriptor):
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if descriptor["type"] == "symlink":
                path.symlink_to(descriptor["target"])
            else:
                _copy_file(snapshot / "objects" / descriptor["sha256"], path, descriptor["sha256"])
                os.chmod(path, descriptor["mode"] & 0o777)
        for relative, descriptor in manifest["files"].items():
            materialize(_safe(target, relative), descriptor)
        authority_receipts = []
        for entry in manifest["authorities"]:
            path = _safe(target, entry["target"])
            if entry["kind"] == "sqlite-authority":
                store = SQLiteAuthority.restore(path, entry["snapshot"])
                try:
                    authority_receipts.append({"id": entry["id"], "sourceSha256": entry["snapshot"]["sha256"],
                                               "restoredSha256": store.export()["sha256"], "state": "standby"})
                finally:
                    store.close()
            else:
                if entry["kind"] == "tree":
                    path.mkdir(parents=True, mode=0o700)
                for relative in entry["directories"]:
                    _safe(path, relative).mkdir(parents=True, exist_ok=True, mode=0o700)
                for relative, descriptor in entry["files"].items():
                    materialize(path if relative == "." else _safe(path, relative), descriptor)
        if hashlib.sha256(_git(target, "ls-files", "--stage", "-z")).hexdigest() != manifest["git"]["indexSha256"]:
            raise SnapshotError("Restored Git index differs from the captured staged state")
        if destination.exists() or destination.is_symlink():
            raise SnapshotError("Restore target appeared during restore")
        if admission is not None:
            store, _reservation = admission
            store._storage_admission_require(_restore_tree_bytes(target))
        os.chmod(target, 0o700)
        target.rename(destination)
        if admission is not None:
            store._storage_admission_precommit()
        return {"protocolVersion": "1.0", "snapshotSha256": manifest["sha256"],
                "head": manifest["git"]["head"], "authorities": authority_receipts,
                "activated": False, "cutoverVerified": False}
    finally:
        shutil.rmtree(temporary)
