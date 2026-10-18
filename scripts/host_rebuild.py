"""One-off generation in a private clone of an explicitly trusted file brain.

This is an operator CLI, not an untrusted-code sandbox or native database writer.
The source checkout is never a generation destination.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

from knowledge_store import adopted_authority

MAX_CONFIG = 1024 * 1024
MAX_GRAPH = 16 * 1024 * 1024
MAX_LOG = 64 * 1024
MAX_INPUT_FILE = 64 * 1024 * 1024
MAX_INPUT_TOTAL = 256 * 1024 * 1024
MAX_INPUT_FILES = 1000


class RebuildError(ValueError):
    pass


def environment(names, source=None):
    source = os.environ if source is None else source
    result = {key: source[key] for key in ("PATH", "LANG", "LC_ALL") if key in source}
    result.update(PYTHONUNBUFFERED="1", PYTHONDONTWRITEBYTECODE="1", BRAIN_REFRESH_STRICT="1",
                  GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                  GIT_NO_REPLACE_OBJECTS="1")
    for name in names:
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", name)
                or name in {"HOME", "CODEX_HOME", "PATH", "ENV", "BASH_ENV", "SHELLOPTS", "CDPATH"}
                or name.startswith(("GIT_", "PYTHON", "LD_", "DYLD_", "BRAIN_"))):
            raise RebuildError("invalid-environment-name")
        if name not in source:
            raise RebuildError("missing-environment-value")
        result[name] = source[name]
    return result


def _git(root, args, env, *, limit=8 * 1024 * 1024):
    return _process(["git", "--no-replace-objects", "--no-lazy-fetch", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-C", str(root), *args],
                    cwd=root, env=env, deadline=time.monotonic() + 30, limit=limit)


def _file_config(raw):
    if len(raw) > MAX_CONFIG:
        raise RebuildError("invalid-config")
    from context_host import decode
    try:
        config = decode(raw)
        if not isinstance(config, dict) or not isinstance(config.get("brain", {}), dict):
            raise ValueError("invalid shape")
        if adopted_authority(config) is not None:
            raise RebuildError("native-authority-requires-native-writer")
    except RebuildError:
        raise
    except (ValueError, TypeError, KeyError):
        raise RebuildError("invalid-config") from None
    return config


def _source(root, env):
    if root.is_symlink() or not root.is_dir():
        raise RebuildError("invalid-source-root")
    top = Path(_git(root, ["rev-parse", "--show-toplevel"], env).decode().strip())
    if top.resolve() != root.resolve() or _git(root, ["status", "--porcelain=v1", "-z", "--untracked-files=normal"], env):
        raise RebuildError("source-must-be-clean-repository-root")
    commit = _git(root, ["rev-parse", "--verify", "HEAD"], env).decode().strip()
    if not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit):
        raise RebuildError("invalid-source-revision")
    config = _git(root, ["show", f"{commit}:client.config.json"], env, limit=MAX_CONFIG)
    _file_config(config)
    tree = _git(root, ["ls-tree", "-rz", "-l", "--full-tree", commit], env)
    entries = list(filter(None, tree.split(b"\0")))
    if len(entries) > 25000:
        raise RebuildError("source-file-limit")
    total = 0
    for row in entries:
        header, path = row.split(b"\t", 1)
        if header.split()[0] not in (b"100644", b"100755"):
            raise RebuildError("source-links-and-submodules-unsupported")
        size = int(header.split()[3])
        total += size
        if size > 256 * 1024 * 1024 or total > 512 * 1024 * 1024:
            raise RebuildError("source-byte-limit")
        parts = path.decode("utf-8").split("/")
        if any(part in ("", ".", "..", ".git") for part in parts):
            raise RebuildError("invalid-source-path")
    return commit, config


def _new_output(output, source):
    output = output.absolute()
    if ".." in output.parts:
        raise RebuildError("unsafe-output-path")
    parent = output.parent
    if any(path.is_symlink() for path in (output, *output.parents)):
        raise RebuildError("unsafe-output-path")
    try:
        output.relative_to(source.resolve())
    except ValueError:
        pass
    else:
        raise RebuildError("output-must-be-outside-source")
    info = parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise RebuildError("output-parent-must-be-private")
    # Exclusive creation is the job claim: two callers cannot share a workspace.
    try:
        output.mkdir(mode=0o700)
    except FileExistsError:
        raise RebuildError("output-must-be-new") from None
    return output


def _process(command, *, cwd, env, deadline, limit, diagnostic=None):
    """Bound both capture and private logs; reap the complete process group."""
    if time.monotonic() >= deadline:
        raise RebuildError("job-deadline")
    child = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT if diagnostic is not None else subprocess.DEVNULL,
                             start_new_session=True)
    truncated = False
    captured = bytearray()
    try:
        os.set_blocking(child.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise RebuildError("job-deadline")
                for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                    part = os.read(key.fd, 65536)
                    if not part:
                        selector.unregister(key.fileobj)
                        continue
                    if diagnostic is None:
                        if len(captured) + len(part) > limit:
                            raise RebuildError("git-output-limit")
                        captured.extend(part)
                    else:
                        available = max(0, limit - diagnostic.tell())
                        diagnostic.write(part[:available])
                        truncated = truncated or len(part) > available
            remaining = max(0.01, deadline - time.monotonic())
            try:
                code = child.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                raise RebuildError("job-deadline") from None
        if code:
            raise RebuildError("stage-failed" if diagnostic is not None else "git-preflight-failed")
        return truncated if diagnostic is not None else bytes(captured)
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        child.stdout.close()


def _run(command, *, cwd, env, deadline, diagnostic):
    return _process(command, cwd=cwd, env=env, deadline=deadline, limit=MAX_LOG, diagnostic=diagnostic)


def _config_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise RebuildError("invalid-config")
        raw = stream.read(MAX_CONFIG + 1)
    _file_config(raw)
    return raw


def _inputs(source, destination):
    """Copy only an explicit bounded recording tree, without archive extraction."""
    if source is None:
        return
    source = source.absolute()
    if not source.is_dir() or any(path.is_symlink() for path in (source, *source.parents)):
        raise RebuildError("invalid-recording-input")
    count = total = entries = 0
    for directory, dirs, files in os.walk(source, followlinks=False):
        base = Path(directory)
        entries += len(dirs) + len(files)
        if entries > 10000:
            raise RebuildError("recording-input-limit")
        for name in dirs:
            if (base / name).is_symlink() or name in ("_internal", ".git"):
                raise RebuildError("unsafe-recording-input")
        for name in files:
            count += 1
            if count > MAX_INPUT_FILES:
                raise RebuildError("recording-input-limit")
            path = base / name
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_INPUT_FILE:
                    raise RebuildError("unsafe-recording-input")
                raw = stream.read(MAX_INPUT_FILE + 1)
                after = os.fstat(stream.fileno())
            def stamp(value):
                return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
            if len(raw) > MAX_INPUT_FILE or stamp(before) != stamp(after) or stamp(after) != stamp(path.lstat()):
                raise RebuildError("recording-input-changed")
            total += len(raw)
            if total > MAX_INPUT_TOTAL:
                raise RebuildError("recording-input-limit")
            target = destination / path.relative_to(source)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with target.open("xb") as output:
                output.write(raw)
            target.chmod(0o600)


def _count(root):
    path = root / "app/brain.json"
    if not path.exists():
        raise RebuildError("missing-generated-projection")
    if path.parent.is_symlink() or path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_GRAPH:
        raise RebuildError("invalid-generated-projection")
    with path.open("rb") as stream:
        raw = stream.read(MAX_GRAPH + 1)
    if len(raw) > MAX_GRAPH:
        raise RebuildError("invalid-generated-projection")
    try:
        from context_host import decode
        value = decode(raw)
        if not isinstance(value, dict) or not isinstance(value.get("nodes"), list):
            raise ValueError("invalid graph shape")
    except (ValueError, UnicodeError, RecursionError):
        raise RebuildError("invalid-generated-projection") from None
    return len(value["nodes"])


def run_job(source, output=None, *, mode="build", execute=False, timeout=900, pass_env=(), recordings=None):
    result = {"format": "mimwell-rebuild/v1", "status": "refused", "mode": mode,
              "records": None, "changed": False, "commit": None, "executed": False,
              "outputsRetained": False, "diagnosticsTruncated": False}
    workspace = None
    try:
        if mode not in ("build", "ingest") or type(timeout) is not int or not 1 <= timeout <= 3600:
            raise RebuildError("invalid-job-options")
        if recordings is not None and mode != "ingest":
            raise RebuildError("recordings-require-ingest-mode")
        env = environment(pass_env)
        source = Path(source).absolute()
        commit, config = _source(source, env)
        result["commit"] = commit
        if not execute:
            result["status"] = "preview"
            return 0, result
        if output is None:
            raise RebuildError("execution-requires-output")
        output = _new_output(Path(output), source)
        result["outputsRetained"] = True
        workspace = output / "brain"
        deadline = time.monotonic() + timeout
        fd = os.open(output / "diagnostics.log", os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as diagnostic:
            for command in (["git", "--no-replace-objects", "--no-lazy-fetch", "-c", "core.hooksPath=/dev/null", "clone", "--no-hardlinks", "--no-checkout", "--", str(source), str(workspace)],
                            ["git", "--no-replace-objects", "--no-lazy-fetch", "-c", "core.hooksPath=/dev/null", "-C", str(workspace), "checkout", "--detach", commit]):
                result["diagnosticsTruncated"] |= _run(command, cwd=output, env=env, deadline=deadline, diagnostic=diagnostic)
            captured = _config_file(workspace / "client.config.json")
            if _file_config(captured) != _file_config(config):
                raise RebuildError("captured-config-changed")
            _inputs(Path(recordings) if recordings is not None else None, workspace / "knowledge-base/recordings")
            before = hashlib.sha256(captured).hexdigest()
            result["executed"] = True
            result["status"] = "failed"
            for command in (["make", "--no-print-directory", mode],
                            ["python3", "scripts/check-projection-receipts.py", "--fail-on-lag"]):
                if hashlib.sha256(_config_file(workspace / "client.config.json")).hexdigest() != before:
                    raise RebuildError("captured-config-changed")
                result["diagnosticsTruncated"] |= _run(command, cwd=workspace, env=env, deadline=deadline, diagnostic=diagnostic)
                if hashlib.sha256(_config_file(workspace / "client.config.json")).hexdigest() != before:
                    raise RebuildError("captured-config-changed")
            current = _config_file(workspace / "client.config.json")
            if hashlib.sha256(current).hexdigest() != before:
                raise RebuildError("captured-config-changed")
            _file_config(current)
            result["records"] = _count(workspace)
            result["status"] = "ok"
        return 0, result
    except KeyboardInterrupt:
        result["status"] = "failed"
        result["reason"] = "job-interrupted"
        return 130, result
    except (RebuildError, OSError, ValueError, subprocess.SubprocessError) as exc:
        result["reason"] = str(exc) if isinstance(exc, RebuildError) else "job-unavailable"
        return (1 if result["executed"] else 2), result
    finally:
        if workspace is not None and (workspace / ".git").is_dir():
            try:
                result["changed"] = bool(_git(workspace, ["status", "--porcelain=v1", "-z", "--untracked-files=normal"], env))
            except (RebuildError, OSError, subprocess.SubprocessError):
                result["changed"] = None
