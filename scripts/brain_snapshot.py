"""Private, stability-checked upgrade snapshots; restored authorities stay standby."""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

from knowledge_policy import fingerprint
from knowledge_store import SQLiteAuthority


class SnapshotError(ValueError):
    pass


def _git(root, *args):
    command = ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
               "-c", "diff.external=", "-C", str(root), *args]
    result = subprocess.run(command, capture_output=True)
    if result.returncode:
        raise SnapshotError("Git snapshot operation failed: " + os.fsdecode(result.stderr).strip())
    return result.stdout


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


def _describe(path, *, allow_link=False):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) and allow_link:
        return {"type": "symlink", "target": os.readlink(path)}
    if not stat.S_ISREG(info.st_mode):
        raise SnapshotError("Only regular source files and explicit Git symlinks are supported")
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return {"type": "file", "sha256": digest.hexdigest(), "bytes": size,
            "mode": stat.S_IMODE(info.st_mode)}


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


def _validate_plan(plan):
    if not isinstance(plan, dict) or set(plan) != {"protocolVersion", "id", "repository", "authorities", "exclusions", "quiescence"}:
        raise SnapshotError("Unexpected snapshot-plan fields")
    if plan["protocolVersion"] != "1.0" or not isinstance(plan["id"], str) or not plan["id"].strip():
        raise SnapshotError("Unsupported snapshot plan")
    if not isinstance(plan["quiescence"], str) or not plan["quiescence"].strip():
        raise SnapshotError("Name the caller-managed writer-quiescence evidence or limitation")
    root = Path(plan["repository"]).resolve(strict=True)
    if Path(os.fsdecode(_git(root, "rev-parse", "--show-toplevel")).strip()).resolve() != root:
        raise SnapshotError("Repository must be the exact worktree root")
    if _git(root, "rev-parse", "--is-shallow-repository").strip() != b"false":
        raise SnapshotError("Shallow history needs a separate complete-history recovery source")
    if _git(root, "ls-files", "--unmerged", "-z"):
        raise SnapshotError("Unmerged index stages require explicit recovery before snapshotting")
    if any(row and (row[:1] == b"S" or row[:1].islower())
           for row in _git(root, "ls-files", "-v", "-z").split(b"\0")):
        raise SnapshotError("Sparse/assume-unchanged index flags require explicit recovery before snapshotting")
    diff = ("diff", "--cached", "--binary", "--full-index", "--no-ext-diff", "--no-textconv")
    if _git(root, *diff, "HEAD", "--") != _git(root, *diff, "--ita-visible-in-index", "HEAD", "--"):
        raise SnapshotError("Intent-to-add index entries require explicit staging before snapshotting")
    if any(row.startswith(b"160000 ") for row in _git(root, "ls-files", "--stage", "-z").split(b"\0")):
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


def _inventory(root, authorities, exclusions):
    def authority_path(path):
        for entry in authorities:
            source = entry["source"]
            if path == source or entry["kind"] == "tree" and _within(path, source):
                return True
            if entry["kind"] == "sqlite-authority" and str(path) in {str(source) + suffix for suffix in ("-wal", "-shm", "-journal")}:
                return True
        return False

    def excluded(path):
        return any(_within(path, root / entry["path"]) for entry in exclusions)

    files = {}
    names = _git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0")
    for name in sorted(set(names)):
        if not name:
            continue
        relative = _relative(os.fsdecode(name))
        path = _safe(root, relative)
        if authority_path(path):
            continue
        if excluded(path):
            raise SnapshotError("Tracked/nonignored working files cannot be excluded from repository recovery")
        if not path.exists() and not path.is_symlink():
            continue  # Working-tree deletion; index and Git history remain separately captured.
        descriptor = _describe(path, allow_link=True)
        if descriptor["type"] == "file":
            with path.open("rb") as stream:
                if stream.read(16) == b"SQLite format 3\x00":
                    raise SnapshotError("Database files require an explicit snapshot adapter")
        files[relative] = descriptor
    ignored = _git(root, "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z").split(b"\0")
    uncovered = []

    def inspect(path):
        if authority_path(path) or excluded(path):
            return
        if path.is_dir() and not path.is_symlink():
            # Expand only where a declaration can explain part of an ignored tree.
            declared = [entry["source"] for entry in authorities] + [root / e["path"] for e in exclusions]
            if any(_within(item, path) for item in declared):
                for child in sorted(path.iterdir()):
                    inspect(child)
                return
        uncovered.append(path.relative_to(root).as_posix())
    for name in ignored:
        if name:
            inspect(_safe(root, os.fsdecode(name).rstrip("/")))
    if uncovered:
        raise SnapshotError("Ignored data needs an authority declaration or exclusion: " + ", ".join(sorted(uncovered)))
    return files


def _authority_snapshot(entry):
    source = entry["source"]
    if entry["kind"] == "sqlite-authority":
        store = SQLiteAuthority(source, expected_binding=entry["binding"], readonly=True)
        try:
            value = store.export()
            SQLiteAuthority.validate_snapshot(value)
        finally:
            store.close()
        return {"kind": entry["kind"], "snapshot": value}
    paths = [source] if entry["kind"] == "file" else sorted(source.rglob("*"))
    files = {}
    directories = []
    for path in paths:
        relative = "." if entry["kind"] == "file" else path.relative_to(source).as_posix()
        if relative != ".":
            _relative(relative)
        if path.is_dir() and not path.is_symlink():
            directories.append(relative)
        else:
            descriptor = _describe(path)
            with path.open("rb") as stream:
                if stream.read(16) == b"SQLite format 3\x00":
                    raise SnapshotError("SQLite data requires a database adapter, not a file/tree copy")
            files[relative] = descriptor
    return {"kind": entry["kind"], "files": files, "directories": directories}


def capture(plan, destination, *, fault=None):
    root, authorities, exclusions = _validate_plan(plan)
    destination = Path(destination).absolute()
    resolved = destination.resolve()
    if destination.exists() or destination.is_symlink() or _within(resolved, root) or any(
            _within(resolved, e["source"]) or _within(e["source"], resolved) for e in authorities):
        raise SnapshotError("Snapshot destination must be new and outside all sources")
    if not destination.parent.is_dir():
        raise SnapshotError("Snapshot parent must already exist")
    temporary = Path(tempfile.mkdtemp(prefix=".brain-snapshot-", dir=destination.parent))
    try:
        def git_state():
            return {"head": _git(root, "rev-parse", "HEAD").decode().strip(),
                    "headRef": _git(root, "rev-parse", "--symbolic-full-name", "HEAD").decode().strip(),
                    "refs": _git(root, "show-ref", "--head").decode(),
                    "indexSha256": hashlib.sha256(_git(root, "ls-files", "--stage", "-z")).hexdigest(),
                    "indexPatch": _git(root, "diff", "--cached", "--binary", "--full-index", "--no-ext-diff", "--no-textconv", "HEAD", "--")}
        before = git_state()
        files = _inventory(root, authorities, exclusions)
        snapshots = [_authority_snapshot(e) for e in authorities]
        _git(root, "bundle", "create", str(temporary / "repository.bundle"), "--all", "HEAD")
        os.chmod(temporary / "repository.bundle", 0o600)
        _private_file(temporary / "index.patch", before["indexPatch"])
        blobs = temporary / "objects"
        blobs.mkdir(mode=0o700)

        def copy_file(path, descriptor):
            if descriptor["type"] == "symlink":
                return
            target = blobs / descriptor["sha256"]
            if not target.exists():
                _copy_file(path, target, descriptor["sha256"])
        for relative, descriptor in files.items():
            copy_file(root / relative, descriptor)
        captured = []
        for entry, snapshot in zip(authorities, snapshots):
            if entry["kind"] != "sqlite-authority":
                for relative, descriptor in snapshot["files"].items():
                    copy_file(entry["source"] if relative == "." else entry["source"] / relative, descriptor)
            captured.append({"id": entry["id"], "target": entry["target"], **snapshot})
        if fault:
            fault("before-recheck")
        if (before != git_state() or files != _inventory(root, authorities, exclusions)
                or snapshots != [_authority_snapshot(e) for e in authorities]):
            raise SnapshotError("Source changed during capture; quiesce writers and capture again")
        manifest = {"protocolVersion": "1.0", "id": plan["id"], "planSha256": fingerprint(plan),
                    "git": {"head": before["head"], "headRef": before["headRef"], "refs": before["refs"],
                            "indexSha256": before["indexSha256"],
                            "bundleSha256": _describe(temporary / "repository.bundle")["sha256"],
                            "indexPatchSha256": hashlib.sha256(before["indexPatch"]).hexdigest()},
                    "files": files, "authorities": captured, "exclusions": exclusions,
                    "consistency": {"mode": "before-after-stability-check", "globalTransaction": False,
                                    "quiescence": plan["quiescence"]},
                    "restoreMode": "separate-target-with-standby-authorities"}
        manifest["sha256"] = fingerprint(manifest)
        _private_file(temporary / "manifest.json", _json(manifest))
        # Rename publishes only a complete snapshot; never merge with an existing directory.
        if destination.exists() or destination.is_symlink():
            raise SnapshotError("Snapshot destination appeared during capture")
        temporary.rename(destination)
        return manifest
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def restore(snapshot, destination):
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
        os.chmod(target, 0o700)
        target.rename(destination)
        return {"protocolVersion": "1.0", "snapshotSha256": manifest["sha256"],
                "head": manifest["git"]["head"], "authorities": authority_receipts,
                "activated": False, "cutoverVerified": False}
    finally:
        shutil.rmtree(temporary)
