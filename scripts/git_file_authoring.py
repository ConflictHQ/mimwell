"""Bounded local Git review-branch writer for one declared JSON tracker file.

This is the files-cell writer only. It does not write structured/native-owned
collections, call a remote Git service, or merge a review branch into its source.
"""
from __future__ import annotations

import hashlib
import json
import difflib
import base64
import binascii
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid
from decimal import Decimal

from context_host import decode
from knowledge_policy import fingerprint
from knowledge_store import StoreError

MAX_FILE_BYTES = 256 * 1024
MAX_HISTORY = 50
MAX_HISTORY_SUBJECT_BYTES = 200
MAX_HISTORY_COMMIT_BYTES = 64 * 1024
MAX_MARKDOWN_LINES = 2000
MAX_MARKDOWN_DIFF_BYTES = 128 * 1024
MAX_BINARY_ASSET_BYTES = 512 * 1024
OPERATIONS = frozenset({
    "file.inspect", "file.history", "file.propose", "file.proposal-inspect",
    "file.review", "file.publish", "file.propose-binary",
})
ARGUMENTS = {
    "file.inspect": (),
    "file.history": ("limit",),
    "file.propose": ("expectedRevision", "requestId", "reason", "documentWire"),
    "file.proposal-inspect": ("proposal",),
    "file.review": ("proposal", "expectedProposalSha256", "reason"),
    "file.publish": ("proposal", "expectedProposalSha256"),
    "file.propose-binary": ("expectedRevision", "requestId", "reason", "contentBase64"),
}
_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_SCHEMA_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_ACTOR = re.compile(r"^[0-9a-f]{64}$")


def _git(repo: Path, *args: str, env_extra=None, input_bytes=None) -> bytes:
    """Run only fixed local Git plumbing with ambient Git configuration disabled."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_LAZY_FETCH": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C",
    })
    if env_extra:
        env.update(env_extra)
    command = ["git", "--no-replace-objects", "--git-dir", str(repo),
               "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
               "-c", "commit.gpgSign=false", "-c", "protocol.allow=never",
               "-c", "gc.auto=0", "-c", "maintenance.auto=false", *args]
    try:
        result = subprocess.run(command, input=input_bytes, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=env, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StoreError("Local Git writer unavailable") from exc
    if result.returncode:
        raise StoreError("Local Git writer refused the operation")
    return result.stdout


def _relative_path(value: str) -> Path:
    if (not isinstance(value, str) or not value.startswith("_internal/") or
            "\\" in value or any(part in ("", ".", "..") for part in value.split("/"))):
        raise StoreError("Git writer repository must be under private _internal state")
    return Path(value)


def _safe_repo(root: Path, relative: str) -> Path:
    relative_path = _relative_path(relative)
    current = root
    root_info = root.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.geteuid() or root_info.st_mode & 0o077:
        raise StoreError("Git writer root must be private and operator-owned")
    for part in relative_path.parts:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise StoreError("Git writer repository path is not private and operator-owned")
    if not stat.S_ISDIR(current.lstat().st_mode):
        raise StoreError("Git writer repository is unavailable")
    _check_repo_tree(current)
    return current


def _check_repo_tree(repo: Path) -> None:
    entries = 0
    for directory, dirs, files in os.walk(repo, followlinks=False):
        relative = Path(directory).relative_to(repo)
        if len(relative.parts) > 16:
            raise StoreError("Git writer repository is too deeply nested")
        for name in [*dirs, *files]:
            entries += 1
            if entries > 100_000:
                raise StoreError("Git writer repository exceeds its file bound")
            path = Path(directory) / name
            info = path.lstat()
            if (stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or
                    not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))):
                raise StoreError("Git writer repository contains a link or unowned file")


def _stable_bytes(path: Path, limit: int) -> bytes:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
            info.st_mode & 0o022 or info.st_nlink != 1):
        raise StoreError("Git writer input must be an operator-owned regular file")
    if info.st_size > limit:
        raise StoreError("Git writer input exceeds its limit")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise StoreError("Git writer input cannot be opened without following links") from exc
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    latest = path.lstat()
    def key(stat_result):
        return (stat_result.st_dev, stat_result.st_ino, stat_result.st_size,
                stat_result.st_mtime_ns, stat_result.st_ctime_ns)
    if (len(raw) > limit or key(info) != key(opened) or key(opened) != key(after) or
            key(after) != key(latest)):
        raise StoreError("Git writer registration changed while being read")
    return raw


def _load_pins(root: Path, entry: dict) -> dict:
    """Verify selected writer against current config/schema and exact pinned hashes."""
    writer = entry.get("writer") if isinstance(entry, dict) else None
    json_fields = {"writer", "repository", "sourceRef", "reviewPrefix", "path", "schema",
                   "schemaSha256", "configSha256", "maxBytes", "grants"}
    markdown_fields = {"writer", "repository", "sourceRef", "reviewPrefix", "path", "contentProfile",
                       "contentProfileSha256", "configSha256", "maxBytes", "grants"}
    binary_fields = markdown_fields | {"mediaType"}
    if set(entry) != (json_fields if writer == "json-commit" else
                      markdown_fields if writer == "markdown-commit" else
                      binary_fields if writer == "binary-commit" else set()):
        raise StoreError("Invalid Git writer registration")
    if type(entry["maxBytes"]) is not int:
        raise StoreError("Unsupported Git writer")
    path = entry["path"]
    if writer == "json-commit":
        if entry["maxBytes"] > MAX_FILE_BYTES or entry["maxBytes"] < 1:
            raise StoreError("Unsupported Git writer")
        if not _SCHEMA_ID.fullmatch(entry["schema"]):
            raise StoreError("Invalid selected file schema")
        if path != f"app/{entry['schema']}.json":
            raise StoreError("Git writer path must match its declared artifact schema")
        policy_path = root / "schemas" / f"{entry['schema']}.schema.json"
        policy_hash = entry["schemaSha256"]
    elif writer == "markdown-commit":
        if entry["maxBytes"] > 65536 or entry["maxBytes"] < 1:
            raise StoreError("Unsupported Markdown writer size limit")
        if (entry["contentProfile"] != "markdown-frontmatter/v1" or
                not re.fullmatch(r"knowledge/docs/(?!.*(?:^|/)(?:\.|\.\.)(?:/|$))(?!.*//)[A-Za-z0-9][A-Za-z0-9._/-]{0,140}\.md", path)):
            raise StoreError("Markdown writer path or profile is invalid")
        policy_path = root / "schemas" / "markdown-frontmatter-v1.schema.json"
        policy_hash = entry["contentProfileSha256"]
    else:
        if entry["maxBytes"] > MAX_BINARY_ASSET_BYTES or entry["maxBytes"] < 1:
            raise StoreError("Unsupported binary asset size limit")
        if (entry["contentProfile"] != "binary-asset/v1" or
                not isinstance(entry["mediaType"], str) or
                not re.fullmatch(r"knowledge/assets/(?!.*(?:^|/)(?:\.|\.\.)(?:/|$))(?!.*//)[A-Za-z0-9][A-Za-z0-9._/-]{0,140}", path) or
                not re.fullmatch(r"[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*", entry["mediaType"])):
            raise StoreError("Binary asset path, profile or media type is invalid")
        policy_path = root / "schemas" / "binary-asset-v1.schema.json"
        policy_hash = entry["contentProfileSha256"]
    if not re.fullmatch(r"refs/heads/[A-Za-z0-9._/-]{1,120}", entry["sourceRef"]):
        raise StoreError("Git writer source ref is invalid")
    if entry["sourceRef"].endswith("/") or ".." in entry["sourceRef"].split("/") or "//" in entry["sourceRef"]:
        raise StoreError("Git writer source ref is invalid")
    prefix = entry["reviewPrefix"]
    if (not isinstance(prefix, str) or not re.fullmatch(r"refs/heads/authoring(?:/[A-Za-z0-9._/-]{1,80})?", prefix)
            or ".." in prefix or "//" in prefix or prefix == entry["sourceRef"]
            or entry["sourceRef"].startswith(prefix + "/") or prefix.startswith(entry["sourceRef"] + "/")):
        raise StoreError("Git writer review branch prefix is invalid")
    for key in (("schemaSha256", "configSha256") if writer == "json-commit"
                else ("contentProfileSha256", "configSha256")):
        if not isinstance(entry[key], str) or not re.fullmatch(r"[0-9a-f]{64}", entry[key]):
            raise StoreError("Git writer source pins are invalid")

    config_path = root / "client.config.json"
    config_bytes = _stable_bytes(config_path, 2 * 1024 * 1024)
    if hashlib.sha256(config_bytes).hexdigest() != entry["configSha256"]:
        raise StoreError("Git writer configuration pin changed")
    config = decode(config_bytes)
    authoring = config.get("authoring", {})
    if (config.get("features", {}).get("authoring") is not True or
            authoring.get("editorial") != "pr" or
            "authority" in config.get("brain", {})):
        raise StoreError("Configured writer does not own an editable files cell" if writer == "json-commit"
                         else "Configured writer does not own an editable source")
    if writer == "json-commit":
        if authoring.get("storage_mode") != "json-commit":
            raise StoreError("Configured tracker writer differs from selected configuration")
        branch = entry["sourceRef"].removeprefix("refs/heads/")
        if authoring.get("branch") != branch:
            raise StoreError("Git writer source branch differs from selected configuration")
    else:
        declared = config.get("knowledge", {}).get("sources", [])
        if not any(isinstance(source, dict) and source.get("recursive") is True and
                   isinstance(source.get("path"), str) and
                   (path.startswith(source["path"].rstrip("/") + "/"))
                   for source in declared):
            raise StoreError("Markdown writer path is not under a declared recursive knowledge source")

    schema_bytes = _stable_bytes(policy_path, 1024 * 1024)
    if hashlib.sha256(schema_bytes).hexdigest() != policy_hash:
        raise StoreError("Git writer content policy pin changed")
    schema = decode(schema_bytes)
    if writer == "json-commit":
        marker = schema.get("x-mimwell", {})
        if marker.get("editable") is not True or marker.get("source") != path:
            raise StoreError("Selected artifact is generated, uneditable or owned by another source")
    else:
        expected_profile = ("conflict:schema/markdown-frontmatter/v1" if writer == "markdown-commit"
                            else "conflict:schema/binary-asset/v1")
        if schema.get("$id") != expected_profile:
            raise StoreError("Selected file content policy is invalid")
    # Any declared structured brain authority owns its collections through its
    # native writer. The legacy files-cell writer must not shadow it.
    repo = _safe_repo(root, entry["repository"])
    _git(repo, "check-ref-format", entry["sourceRef"])
    _git(repo, "check-ref-format", prefix)
    if _git(repo, "rev-parse", "--is-bare-repository").strip() != b"true":
        raise StoreError("Git writer requires a bare local repository")
    if (repo / "objects/info/alternates").exists() or (repo / "shallow").exists():
        raise StoreError("Git writer refuses incomplete or borrowed object stores")
    if _git(repo, "for-each-ref", "--format=%(refname)", "refs/replace"):
        raise StoreError("Git writer refuses replacement refs")
    # Git normalizes section/variable keys to lowercase. Use lowercase
    # alternatives: its key-regexp normalization only folds the first/last
    # pieces of a compound pattern, not each alternative independently.
    blocked = subprocess.run(["git", "--no-replace-objects", "--git-dir", str(repo), "config", "--local",
                              "--null", "--name-only", "--get-regexp",
                              r"^(include\.|includeif\.|core\.worktree$|extensions\.worktreeconfig$|remote\.)"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=_git_environment(), timeout=5, check=False)
    if blocked.returncode == 0:
        keys = blocked.stdout.split(b"\0")
        if not keys[-1] == b"" or not any(keys):
            raise StoreError("Git writer repository configuration is invalid")
        if any(not key.startswith(b"remote.") for key in keys if key):
            raise StoreError("Git writer refuses included or worktree configuration")
        raise StoreError("Git writer refuses a repository configured with remote services")
    if blocked.returncode != 1:
        raise StoreError("Git writer repository configuration is invalid")
    source_commit = _git(repo, "rev-parse", "--verify", entry["sourceRef"]).decode().strip()
    return {"repo": repo, "config": config, "schema": schema, "schemaBytes": schema_bytes,
            "path": path, "sourceCommit": source_commit, "entry": entry}


def _tree_entry(pin: dict, commit: str) -> tuple[str, bytes]:
    rows = _git(pin["repo"], "ls-tree", "-z", commit, "--", pin["path"]).split(b"\0")
    rows = [row for row in rows if row]
    if len(rows) != 1:
        raise StoreError("Registered Git source file is unavailable")
    header, separator, found_path = rows[0].partition(b"\t")
    fields = header.split()
    if (not separator or found_path.decode("utf-8", "strict") != pin["path"] or len(fields) != 3 or
            fields[0] != b"100644" or fields[1] != b"blob"):
        raise StoreError("Registered Git source must be a regular non-symlink file")
    blob = fields[2].decode("ascii")
    size = _git(pin["repo"], "cat-file", "-s", blob)
    if not size.strip().isdigit() or int(size.strip()) > pin["entry"]["maxBytes"]:
        raise StoreError("Registered Git source exceeds its limit")
    raw = _git(pin["repo"], "cat-file", "blob", blob)
    if len(raw) > pin["entry"]["maxBytes"]:
        raise StoreError("Registered Git source exceeds its limit")
    return blob, raw


def _history_subject(pin: dict, commit: str) -> str:
    size_bytes = _git(pin["repo"], "cat-file", "-s", commit).strip()
    if not size_bytes.isdigit() or int(size_bytes) > MAX_HISTORY_COMMIT_BYTES:
        return "(subject unavailable: commit metadata exceeds limit)"
    raw = _git(pin["repo"], "cat-file", "commit", commit)
    if len(raw) != int(size_bytes):
        raise StoreError("Git commit metadata changed while being read")
    _, separator, message = raw.partition(b"\n\n")
    if not separator:
        return "(subject unavailable: commit metadata is invalid)"
    line = message.splitlines()[0] if message else b""
    decoded = line.decode("utf-8", "replace")
    output = []
    used_bytes = 0
    truncated = False
    for character in decoded:
        width = len(character.encode("utf-8"))
        if used_bytes + width > MAX_HISTORY_SUBJECT_BYTES:
            truncated = True
            break
        output.append(character)
        used_bytes += width
    if truncated and used_bytes + len("…".encode("utf-8")) <= MAX_HISTORY_SUBJECT_BYTES:
        output.append("…")
    return "".join(output)


def _document(pin: dict, raw: bytes) -> dict:
    if pin["entry"]["writer"] == "markdown-commit":
        return _markdown_document(pin, raw)
    if pin["entry"]["writer"] == "binary-commit":
        if len(raw) > pin["entry"]["maxBytes"]:
            raise StoreError("Binary asset exceeds its registered limit")
        return {"mediaType": pin["entry"]["mediaType"], "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest()}
    value = _parse_document(raw)
    _reject_decimals(value)
    from jsonschema import Draft202012Validator
    Draft202012Validator.check_schema(pin["schema"])
    def local_refs(value):
        if isinstance(value, dict):
            ref = value.get("$ref")
            if ref is not None and (not isinstance(ref, str) or not ref.startswith("#")):
                raise StoreError("Selected file schema cannot resolve remote references")
            return all(local_refs(child) for child in value.values())
        if isinstance(value, list):
            return all(local_refs(child) for child in value)
        return True
    if not local_refs(pin["schema"]):
        raise StoreError("Selected file schema cannot resolve remote references")
    errors = list(Draft202012Validator(pin["schema"]).iter_errors(value))
    if errors:
        raise StoreError("Selected file does not match its declared schema")
    return value


def _markdown_document(pin: dict, raw: bytes) -> dict:
    limit = pin["entry"]["maxBytes"]
    if len(raw) > limit or b"\x00" in raw or b"\r" in raw or not raw.endswith(b"\n"):
        raise StoreError("Markdown source must be bounded UTF-8 with LF endings and one final newline")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise StoreError("Markdown source is not valid UTF-8") from exc
    if text.count("\n") > MAX_MARKDOWN_LINES:
        raise StoreError("Markdown source exceeds its line limit")
    lines = text.split("\n")
    if len(lines) < 6 or lines[0] != "---" or lines[3] != "---" or lines[4] != "":
        raise StoreError("Markdown source requires the markdown-frontmatter/v1 header")
    if not lines[1].startswith("title: ") or not lines[2].startswith("description: "):
        raise StoreError("Markdown frontmatter must contain title then description")
    try:
        title = json.loads(lines[1][len("title: "):])
        description = json.loads(lines[2][len("description: "):])
    except (json.JSONDecodeError, TypeError) as exc:
        raise StoreError("Markdown frontmatter values must be quoted strings") from exc
    from jsonschema import Draft202012Validator
    profile = pin["schema"]
    Draft202012Validator.check_schema(profile)
    frontmatter = {"title": title, "description": description}
    errors = list(Draft202012Validator(profile).iter_errors(frontmatter))
    if errors:
        raise StoreError("Markdown frontmatter does not match its pinned profile")
    if any(ord(char) < 0x20 for value in frontmatter.values() for char in value):
        raise StoreError("Markdown frontmatter must not contain control characters")
    return {"frontmatter": frontmatter, "body": "\n".join(lines[5:-1])}


def _markdown_diff(pin: dict, before: bytes, after: bytes) -> str:
    before_text = before.decode("utf-8", "strict")
    after_text = after.decode("utf-8", "strict")
    diff = "".join(difflib.unified_diff(
        before_text.splitlines(keepends=True), after_text.splitlines(keepends=True),
        fromfile="registered source", tofile="proposed source", n=3,
    ))
    if len(diff.encode("utf-8")) > MAX_MARKDOWN_DIFF_BYTES:
        raise StoreError("Markdown review diff exceeds its limit")
    return diff


def _parse_document(raw: bytes) -> dict:
    def pairs(items):
        value = {}
        for key, child in items:
            if key in value:
                raise StoreError("Selected JSON has duplicate object keys")
            value[key] = child
        return value
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                           parse_float=Decimal,
                           parse_constant=lambda _: (_ for _ in ()).throw(StoreError("Nonfinite JSON number")))
    except StoreError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise StoreError("Selected file is not bounded valid JSON") from exc
    if not isinstance(value, dict):
        raise StoreError("Selected file is not a JSON object")
    return value


def _reject_decimals(value):
    if isinstance(value, Decimal):
        raise StoreError("This file writer does not accept fractional JSON numbers")
    if isinstance(value, dict):
        for child in value.values():
            _reject_decimals(child)
    elif isinstance(value, list):
        for child in value:
            _reject_decimals(child)


def _revision(commit: str, blob_bytes: bytes) -> str:
    return fingerprint({"commit": commit, "blobSha256": hashlib.sha256(blob_bytes).hexdigest()})


def _actor_hash(actor: str) -> str:
    return hashlib.sha256(actor.encode("utf-8")).hexdigest()


def _ref(kind: str, proposal: str, actor: str | None = None, *, review_prefix: str | None = None) -> str:
    if kind == "review-branches":
        return f"{review_prefix}/{proposal}"
    suffix = "/" + _actor_hash(actor) if actor is not None else ""
    return f"refs/mimwell-authoring/{kind}/{proposal}{suffix}"


def _ref_value(pin: dict, ref: str) -> str | None:
    result = subprocess.run(["git", "--no-replace-objects", "--git-dir", str(pin["repo"]),
                             "-c", "core.hooksPath=/dev/null", "rev-parse", "--verify", ref],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env=_git_environment(), timeout=5, check=False)
    if result.returncode:
        return None
    return result.stdout.decode().strip()


def _git_environment():
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1", "GIT_LAZY_FETCH": "0",
                "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"})
    return env


def _proposal(pin: dict, request_id: str, actors: dict) -> dict:
    if not _ID.fullmatch(request_id):
        raise StoreError("Invalid file proposal identity")
    commit = _ref_value(pin, _ref("proposals", request_id))
    if not commit:
        raise StoreError("File proposal unavailable")
    body = _git(pin["repo"], "show", "-s", "--format=%B", commit).decode("utf-8", "strict")
    metadata = {}
    for line in body.splitlines():
        if line.startswith("Mimwell-") and ": " in line:
            key, value = line.split(": ", 1)
            metadata[key] = value
    if metadata.get("Mimwell-Proposal") != request_id:
        raise StoreError("File proposal metadata is invalid")
    if metadata.get("Mimwell-Writer") not in (None, pin["entry"]["writer"]):
        raise StoreError("File proposal belongs to a different registered writer")
    if pin["entry"]["writer"] in ("markdown-commit", "binary-commit") and (
            metadata.get("Mimwell-Writer") != pin["entry"]["writer"] or
            metadata.get("Mimwell-PathSha256") != hashlib.sha256(pin["path"].encode()).hexdigest() or
            metadata.get("Mimwell-ProfileSha256") != pin["entry"]["contentProfileSha256"]):
        raise StoreError("File proposal registration does not match the current writer")
    if pin["entry"]["writer"] == "binary-commit" and metadata.get("Mimwell-MediaType") != pin["entry"]["mediaType"]:
        raise StoreError("Binary asset media type differs from its registered assertion")
    parents = _git(pin["repo"], "rev-list", "--parents", "-n", "1", commit).decode().split()
    if len(parents) != 2 or parents[1] != metadata.get("Mimwell-BaseCommit"):
        raise StoreError("File proposal base is invalid")
    base_commit = parents[1]
    _, before_raw = _tree_entry(pin, base_commit)
    _, after_raw = _tree_entry(pin, commit)
    if hashlib.sha256(after_raw).hexdigest() != metadata.get("Mimwell-ContentSha256"):
        raise StoreError("File proposal content changed")
    actor = next((candidate for candidate in actors if _actor_hash(candidate) == metadata.get("Mimwell-AuthorSha256")), None)
    proposal = {
        "id": request_id,
        "commit": commit,
        "baseCommit": base_commit,
        "baseRevision": metadata.get("Mimwell-BaseRevision"),
        "author": actor,
        "writer": pin["entry"]["writer"],
        "path": pin["path"],
        "contentSha256": metadata["Mimwell-ContentSha256"],
        "requestSha256": metadata["Mimwell-RequestSha256"],
        "before": _document(pin, before_raw),
        "after": _document(pin, after_raw),
    }
    if pin["entry"]["writer"] == "markdown-commit":
        proposal["beforeWire"] = before_raw.decode("utf-8", "strict")
        proposal["afterWire"] = after_raw.decode("utf-8", "strict")
        proposal["diff"] = _markdown_diff(pin, before_raw, after_raw)
        proposal["beforeSha256"] = hashlib.sha256(before_raw).hexdigest()
        proposal["afterSha256"] = hashlib.sha256(after_raw).hexdigest()
    elif pin["entry"]["writer"] == "binary-commit":
        proposal["mediaType"] = pin["entry"]["mediaType"]
        proposal["beforeBytes"] = len(before_raw)
        proposal["afterBytes"] = len(after_raw)
    proposal["proposalSha256"] = fingerprint(proposal)
    proposal_ref = _ref_value(pin, _ref("review-branches", request_id, review_prefix=pin["entry"]["reviewPrefix"]))
    proposal["published"] = proposal_ref == commit
    proposal["reviewers"] = [candidate for candidate in actors
                             if candidate != actor and
                             _review_commit(pin, request_id, candidate, commit) is not None]
    proposal["stale"] = _git(pin["repo"], "rev-parse", "--verify", pin["entry"]["sourceRef"]).decode().strip() != base_commit
    return proposal


def _review_commit(pin: dict, proposal_id: str, actor: str, proposal_commit: str) -> str | None:
    review = _ref_value(pin, _ref("reviews", proposal_id, actor))
    if not review:
        return None
    parents = _git(pin["repo"], "rev-list", "--parents", "-n", "1", review).decode().split()
    return review if len(parents) == 2 and parents[1] == proposal_commit else None


def _create_ref_cas(pin: dict, ref: str, new: str, expected_source: str) -> None:
    # Source verification and the proposal/review ref creation are one Git ref
    # transaction, so a competing source update cannot slip between CAS and write.
    source_ref = pin["entry"]["sourceRef"]
    transaction = f"start\nverify {source_ref} {expected_source}\ncreate {ref} {new}\nprepare\ncommit\n".encode()
    try:
        _git(pin["repo"], "update-ref", "--stdin", input_bytes=transaction)
    except StoreError as exc:
        raise StoreError("Git ref changed concurrently") from exc


def _write_document(pin: dict, current: dict, proposed: dict, now: str, reason: str) -> tuple[dict, bytes]:
    if pin["entry"]["writer"] == "markdown-commit":
        if not isinstance(proposed, str):
            raise StoreError("Markdown proposal must be text")
        try:
            raw = proposed.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise StoreError("Markdown proposal is not valid UTF-8 text") from exc
        value = _markdown_document(pin, raw)
        _markdown_diff(pin, "".encode(), raw)
        return value, raw
    if pin["entry"]["writer"] == "binary-commit":
        if not isinstance(proposed, bytes) or len(proposed) > pin["entry"]["maxBytes"]:
            raise StoreError("Proposed binary asset exceeds its registered limit")
        return _document(pin, proposed), proposed
    if not isinstance(proposed, dict):
        raise StoreError("Proposed tracker must be a JSON object")
    _reject_decimals(proposed)
    if type(current.get("version")) is int:
        version = current["version"] + 1
    elif "version" not in current:
        version = 1
    else:
        raise StoreError("Tracker version must be an integer")
    date = now[:10]
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        raise StoreError("Host clock did not provide a usable date")
    changelog = current.get("changelog", [])
    if not isinstance(changelog, list):
        raise StoreError("Tracker changelog must be an array")
    value = dict(proposed)
    value["version"] = version
    value["updated"] = date
    value["changelog"] = [*changelog, {"version": version, "date": date, "note": reason.strip()[:200]}]
    record_keys = [key for key, schema in pin["schema"].get("properties", {}).items()
                   if key not in ("changelog",) and schema.get("type") == "array"]
    if len(record_keys) != 1 or not isinstance(value.get(record_keys[0]), list):
        raise StoreError("Selected tracker schema must declare exactly one records array")
    if "count" in current or "count" in value:
        value["count"] = len(value[record_keys[0]])
    raw = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False).encode("utf-8") + b"\n"
    if len(raw) > pin["entry"]["maxBytes"]:
        raise StoreError("Proposed tracker exceeds its limit")
    _document(pin, raw)
    return value, raw


def capabilities(entry: dict, actor: str) -> list[str]:
    granted = set(entry["grants"].get(actor, []))
    operations = {"file.propose-binary": "file.propose"}
    return sorted(operation for operation in OPERATIONS if operations.get(operation, operation) in granted)


def run_operation(root: Path, entry: dict, operation: str, args: dict, *, actor: str,
                  actors: dict, clock, guard, record_mode=None):
    if record_mode == "registered-json-record/v2":
        if operation not in ("file.inspect", "file.propose") or entry["writer"] != "json-commit":
            raise StoreError("Unsupported JSON value mode")
    elif record_mode is not None and (record_mode != "registered-json-record/v1" or
                                    operation not in ("file.inspect", "file.propose") or
                                    entry["writer"] != "json-commit"):
        raise StoreError("Unsupported registered record mode")
    pin = _load_pins(root, entry)
    if operation == "file.inspect":
        blob, raw = _tree_entry(pin, pin["sourceCommit"])
        if record_mode == "registered-json-record/v2":
            from knowledge_file_json_values import preview_field_wires, value_profile
            return (preview_field_wires(pin, raw, args) if "fieldWires" in args
                    else value_profile(pin, raw, args["recordIndex"]))
        if record_mode is not None:
            from knowledge_file_record_patch import record_profile
            return record_profile(pin, raw, args["recordIndex"])
        document = _document(pin, raw)
        result = {"path": pin["path"], "writer": entry["writer"],
                "sourceCommit": pin["sourceCommit"], "blobSha256": hashlib.sha256(raw).hexdigest(),
                "revision": _revision(pin["sourceCommit"], raw), "bytes": len(raw), "document": document}
        if entry["writer"] != "binary-commit":
            result["documentWire"] = raw.decode("utf-8", "strict")
        if entry["writer"] == "json-commit":
            result["schema"] = entry["schema"]
        elif entry["writer"] == "binary-commit":
            result["mediaType"] = entry["mediaType"]
        else:
            result["contentProfile"] = entry["contentProfile"]
        return result
    if operation == "file.history":
        limit = args["limit"]
        if type(limit) is not int or not 1 <= limit <= MAX_HISTORY:
            raise StoreError("Invalid bounded file history limit")
        rows = _git(pin["repo"], "log", f"-{limit}", "--format=%H%x00%ct",
                    pin["entry"]["sourceRef"], "--", pin["path"])
        entries = []
        for row in rows.splitlines():
            fields = row.split(b"\0", 2)
            if len(fields) == 2:
                commit = fields[0].decode("ascii", "strict")
                entries.append({"commit": commit, "unixTime": int(fields[1]),
                                "subject": _history_subject(pin, commit)})
        return {"path": pin["path"], "sourceRef": pin["entry"]["sourceRef"], "entries": entries,
                "truncated": len(entries) == limit}
    if operation in ("file.propose", "file.propose-binary"):
        request_id = args["requestId"]
        if not isinstance(request_id, str) or not _ID.fullmatch(request_id):
            raise StoreError("File requestId must be a UUID")
        if record_mode == "registered-json-record/v2":
            from knowledge_operation_json_values import validate_value_arguments
            validate_value_arguments(operation, args)
            request_content = {"recordValueCorrection": {key: args[key] for key in (
                "requestId", "expectedSelectionSha256", "recordIndex", "expectedRecordSha256", "fieldWires")}}
        elif record_mode is not None:
            # Hash ORIGINAL typed request, not a candidate recomputed from a later head.
            from knowledge_operation_file_records import validate_record_arguments
            validate_record_arguments(operation, args)
            request_content = {"recordCorrection": {key: args[key] for key in (
                "requestId", "expectedSelectionSha256", "recordIndex", "expectedRecordSha256", "fields")}}
        else:
            if operation == "file.propose-binary":
                if entry["writer"] != "binary-commit" or not isinstance(args["contentBase64"], str):
                    raise StoreError("Binary proposal does not match the registered writer")
                encoded_content = args["contentBase64"]
                if len(encoded_content) > 699052:
                    raise StoreError("Encoded binary asset exceeds its limit")
                try:
                    document_bytes = base64.b64decode(encoded_content, validate=True)
                except (binascii.Error, ValueError) as exc:
                    raise StoreError("Binary asset must use canonical Base64") from exc
                if base64.b64encode(document_bytes).decode("ascii") != encoded_content:
                    raise StoreError("Binary asset must use canonical Base64")
            else:
                document_wire = args["documentWire"]
                if not isinstance(document_wire, str):
                    raise StoreError("Proposed file content must be text")
                try:
                    document_bytes = document_wire.encode("utf-8", "strict")
                except UnicodeEncodeError as exc:
                    raise StoreError("Proposed file content is not valid UTF-8") from exc
                if entry["writer"] == "binary-commit":
                    raise StoreError("Binary assets require the binary proposal operation")
            if len(document_bytes) > pin["entry"]["maxBytes"]:
                raise StoreError("Proposed file content exceeds its limit")
            if entry["writer"] == "binary-commit":
                proposed_document = document_bytes
            else:
                proposed_document = (document_wire if pin["entry"]["writer"] == "markdown-commit"
                                     else _parse_document(document_bytes))
            request_content = ({"contentSha256": hashlib.sha256(document_bytes).hexdigest()}
                               if entry["writer"] == "binary-commit" else {"documentWire": document_wire})
        request_digest = fingerprint({"expectedRevision": args["expectedRevision"], "reason": args["reason"],
                                      **request_content, "actorSha256": _actor_hash(actor)})
        existing = _ref_value(pin, _ref("proposals", request_id))
        if existing:
            current = _proposal(pin, request_id, actors)
            if current["requestSha256"] != request_digest:
                raise StoreError("File request ID was already used for different content")
            return current
        base_commit = pin["sourceCommit"]
        blob, current_raw = _tree_entry(pin, base_commit)
        current_document = _document(pin, current_raw)
        current_revision = _revision(base_commit, current_raw)
        if args["expectedRevision"] != current_revision:
            raise StoreError("File source changed; inspect and draft again")
        if not isinstance(args["reason"], str) or not args["reason"].strip() or len(args["reason"]) > 2000:
            raise StoreError("A bounded file change reason is required")
        if record_mode == "registered-json-record/v2":
            from knowledge_file_json_values import apply_field_wires
            proposed_document = apply_field_wires(pin, current_raw, args["recordIndex"],
                                                 args["expectedRecordSha256"], args["fieldWires"])
        elif record_mode is not None:
            from knowledge_file_record_patch import apply_record_fields
            proposed_document = apply_record_fields(pin, current_raw, args["recordIndex"],
                                                    args["expectedRecordSha256"], args["fields"])
        value, raw = _write_document(pin, current_document, proposed_document, clock(), args["reason"])
        content_sha = hashlib.sha256(raw).hexdigest()
        new_blob = _git(pin["repo"], "hash-object", "-w", "--stdin", input_bytes=raw).decode().strip()
        index_path = root / "_internal" / ("git-file-index-" + uuid.uuid4().hex)
        index_path.touch(mode=0o600)
        try:
            env = {"GIT_INDEX_FILE": str(index_path)}
            _git(pin["repo"], "read-tree", base_commit, env_extra=env)
            _git(pin["repo"], "update-index", "--add", "--cacheinfo", "100644," + new_blob + "," + pin["path"], env_extra=env)
            tree = _git(pin["repo"], "write-tree", env_extra=env).decode().strip()
        finally:
            index_path.unlink(missing_ok=True)
            (Path(str(index_path) + ".lock")).unlink(missing_ok=True)
        metadata = (f"Mimwell-Proposal: {request_id}\nMimwell-Writer: {entry['writer']}\n"
                    f"Mimwell-PathSha256: {hashlib.sha256(pin['path'].encode()).hexdigest()}\n"
                    + (f"Mimwell-ProfileSha256: {entry['contentProfileSha256']}\n"
                       if entry["writer"] in ("markdown-commit", "binary-commit") else "")
                    + (f"Mimwell-MediaType: {entry['mediaType']}\n"
                       if entry["writer"] == "binary-commit" else "")
                    + f"Mimwell-BaseCommit: {base_commit}\n"
                    f"Mimwell-BaseRevision: {current_revision}\nMimwell-AuthorSha256: {_actor_hash(actor)}\n"
                    f"Mimwell-RequestSha256: {request_digest}\nMimwell-ContentSha256: {content_sha}\n")
        ident_env = {"GIT_AUTHOR_NAME": "Mimwell Authoring Host", "GIT_AUTHOR_EMAIL": "authoring@localhost",
                     "GIT_COMMITTER_NAME": "Mimwell Authoring Host", "GIT_COMMITTER_EMAIL": "authoring@localhost"}
        commit = _git(pin["repo"], "commit-tree", tree, "-p", base_commit, "-m", "Mimwell reviewed file proposal\n\n" + metadata,
                      env_extra=ident_env).decode().strip()
        guard()
        latest = _load_pins(root, entry)
        if latest["sourceCommit"] != base_commit:
            raise StoreError("File source changed before proposal was staged")
        guard()
        _create_ref_cas(pin, _ref("proposals", request_id), commit, base_commit)
        return _proposal(pin, request_id, actors)
    if operation == "file.proposal-inspect":
        return _proposal(pin, args["proposal"], actors)
    if operation == "file.review":
        proposal = _proposal(pin, args["proposal"], actors)
        if (args["expectedProposalSha256"] != proposal["proposalSha256"] or proposal["author"] == actor or
                proposal["stale"]):
            raise StoreError("File proposal is stale or independent review is unavailable")
        if not isinstance(args["reason"], str) or not args["reason"].strip() or len(args["reason"]) > 2000:
            raise StoreError("A bounded review reason is required")
        ref = _ref("reviews", proposal["id"], actor)
        existing = _ref_value(pin, ref)
        if existing:
            if _review_commit(pin, proposal["id"], actor, proposal["commit"]) != existing:
                raise StoreError("Existing file review is inconsistent")
            return {"proposal": proposal["id"], "reviewer": actor, "commit": existing, "state": "reviewed"}
        tree = _git(pin["repo"], "rev-parse", proposal["commit"] + "^{tree}").decode().strip()
        metadata = (f"Mimwell-Review: {proposal['id']}\nMimwell-Proposal: {proposal['commit']}\n"
                    f"Mimwell-ReviewerSha256: {_actor_hash(actor)}\n"
                    f"Mimwell-ReasonSha256: {hashlib.sha256(args['reason'].encode()).hexdigest()}\n")
        ident_env = {"GIT_AUTHOR_NAME": "Mimwell Reviewer", "GIT_AUTHOR_EMAIL": "reviewer@localhost",
                     "GIT_COMMITTER_NAME": "Mimwell Reviewer", "GIT_COMMITTER_EMAIL": "reviewer@localhost"}
        review_commit = _git(pin["repo"], "commit-tree", tree, "-p", proposal["commit"],
                             "-m", "Mimwell independent file review\n\n" + metadata, env_extra=ident_env).decode().strip()
        guard()
        latest = _load_pins(root, entry)
        if latest["sourceCommit"] != proposal["baseCommit"]:
            raise StoreError("File source changed before review")
        guard()
        _create_ref_cas(pin, ref, review_commit, proposal["baseCommit"])
        return {"proposal": proposal["id"], "reviewer": actor, "commit": proposal["commit"], "reviewCommit": review_commit, "state": "reviewed"}
    if operation == "file.publish":
        proposal = _proposal(pin, args["proposal"], actors)
        if args["expectedProposalSha256"] != proposal["proposalSha256"] or proposal["stale"]:
            raise StoreError("File proposal is stale; inspect before publishing")
        if not any(reviewer != proposal["author"] for reviewer in proposal["reviewers"]):
            raise StoreError("Independent file review is required")
        ref = _ref("review-branches", proposal["id"], review_prefix=entry["reviewPrefix"])
        existing = _ref_value(pin, ref)
        if existing:
            if existing != proposal["commit"]:
                raise StoreError("Review branch already has different content")
            return {"proposal": proposal["id"], "branch": ref.removeprefix("refs/heads/"),
                    "commit": existing, "sourceRefUnchanged": True, "state": "published-to-review-branch"}
        guard()
        latest = _load_pins(root, entry)
        if latest["sourceCommit"] != proposal["baseCommit"]:
            raise StoreError("File source changed before review branch publication")
        guard()
        _create_ref_cas(pin, ref, proposal["commit"], proposal["baseCommit"])
        return {"proposal": proposal["id"], "branch": ref.removeprefix("refs/heads/"),
                "commit": proposal["commit"], "sourceRefUnchanged": True, "state": "published-to-review-branch"}
    raise StoreError("Unsupported Git file operation")
