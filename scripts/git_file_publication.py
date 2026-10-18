"""Bounded local Git publication groups layered on declared file writers.

Each target ref is an independent CAS. A private operational ledger lets a later
request reconcile an uncertain result before it offers another destination write.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from knowledge_policy import fingerprint
from knowledge_store import StoreError
from git_file_authoring import (
    _actor_hash, _create_ref_cas, _document, _git, _load_pins, _ref_value,
    _revision, _tree_entry,
)

MAX_LEDGER_BYTES = 1024 * 1024
MAX_LEDGER_RECORDS = 128
MAX_GROUP_DESTINATIONS = 4
_GROUP_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_OBJECT_ID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _pairs(pairs):
    value = {}
    for key, child in pairs:
        if key in value:
            raise StoreError("Publication ledger has duplicate keys")
        value[key] = child
    return value


def _canonical_asset(value, limit):
    if not isinstance(value, str) or len(value) > 699052:
        raise StoreError("Encoded binary asset exceeds its limit")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise StoreError("Binary asset must use canonical Base64") from exc
    if base64.b64encode(raw).decode("ascii") != value:
        raise StoreError("Binary asset must use canonical Base64")
    if len(raw) > limit:
        raise StoreError("Binary asset exceeds its registered limit")
    return raw


def _ledger_paths(root: Path):
    directory = root / "_internal"
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise StoreError("Publication ledger requires private operator-owned state")
    return directory / "file-publication-ledger.json", directory / "file-publication-ledger.lock"


def _read_fd(fd):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or
            info.st_nlink != 1 or info.st_size > MAX_LEDGER_BYTES):
        raise StoreError("Publication ledger is not a bounded private regular file")
    os.lseek(fd, 0, os.SEEK_SET)
    raw = bytearray()
    while len(raw) <= MAX_LEDGER_BYTES:
        chunk = os.read(fd, min(65536, MAX_LEDGER_BYTES + 1 - len(raw)))
        if not chunk:
            break
        raw.extend(chunk)
    after = os.fstat(fd)
    if (len(raw) > MAX_LEDGER_BYTES or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) !=
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
        raise StoreError("Publication ledger changed while being read")
    return bytes(raw)


class _Ledger:
    def __init__(self, root: Path):
        self.root = root
        self.path, self.lock_path = _ledger_paths(root)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        self.fd = os.open(self.lock_path, flags, 0o600)
        info = os.fstat(self.fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or
                info.st_nlink != 1):
            os.close(self.fd)
            raise StoreError("Publication ledger lock is not private")
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        try:
            self.data = self._load()
        except Exception:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            raise

    def _load(self):
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            return {"format": "file-publication-ledger/v1", "records": {}}
        except OSError as exc:
            raise StoreError("Publication ledger cannot be opened safely") from exc
        try:
            raw = _read_fd(fd)
        finally:
            os.close(fd)
        try:
            data = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
            raise StoreError("Publication ledger is invalid") from exc
        if (not isinstance(data, dict) or set(data) != {"format", "records"} or
                data["format"] != "file-publication-ledger/v1" or not isinstance(data["records"], dict) or
                len(data["records"]) > MAX_LEDGER_RECORDS):
            raise StoreError("Publication ledger has an invalid shape")
        for key, record in data["records"].items():
            if (not isinstance(key, str) or key.count("/") != 1 or
                    not _GROUP_ID.fullmatch(key.partition("/")[0]) or
                    not _UUID.fullmatch(key.partition("/")[2]) or not isinstance(record, dict) or
                    set(record) != {"groupSha256", "authorizationSha256", "proposalCommit", "proposalSha256",
                                    "requestSha256", "authorSha256", "destinations"} or
                    any(not isinstance(record.get(name), str) or not _SHA256.fullmatch(record[name])
                        for name in ("groupSha256", "authorizationSha256", "requestSha256", "authorSha256")) or
                    not isinstance(record["proposalCommit"], str) or not _OBJECT_ID.fullmatch(record["proposalCommit"]) or
                    record["proposalSha256"] is not None and
                    (not isinstance(record["proposalSha256"], str) or not _SHA256.fullmatch(record["proposalSha256"])) or
                    not isinstance(record["destinations"], dict) or
                    not 2 <= len(record["destinations"]) <= MAX_GROUP_DESTINATIONS):
                raise StoreError("Publication ledger record has an invalid shape")
            for destination, result in record["destinations"].items():
                if (not isinstance(destination, str) or not _GROUP_ID.fullmatch(destination) or
                        not isinstance(result, dict) or result.get("state") not in
                        ("pending", "attempting", "published", "refused", "outcome-unknown") or
                        set(result) - {"state", "ref", "expectedCommit", "expectedSourceCommit", "commit",
                                       "reason", "reconciliation"} or
                        any(not isinstance(value, str) or len(value) > 512 for value in result.values())):
                    raise StoreError("Publication ledger destination has an invalid shape")
        return data

    def save(self):
        raw = json.dumps(self.data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(raw) > MAX_LEDGER_BYTES or len(self.data["records"]) > MAX_LEDGER_RECORDS:
            raise StoreError("Publication ledger exceeds its limit")
        temp = self.path.with_name(self.path.name + ".tmp-" + uuid.uuid4().hex)
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temp, self.path)
        directory_fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def close(self):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


def _manifest_path(group_id, proposal_id):
    return f"_internal/group-proposals/{group_id}/{proposal_id}.json"


def _ref(kind, group_id, proposal_id, actor=None):
    suffix = "/" + _actor_hash(actor) if actor is not None else ""
    return f"refs/mimwell-authoring/{kind}/{group_id}/{proposal_id}{suffix}"


def _source_snapshot(root, host, group, group_id):
    from git_file_authoring import _load_pins

    pins = []
    for target_id in group["targets"]:
        entry = host["fileAuthorities"][target_id]
        pins.append(_load_pins(root, entry))
    profile = (pins[0]["entry"]["writer"], pins[0]["entry"].get("contentProfile"),
               pins[0]["entry"].get("contentProfileSha256"), pins[0]["entry"].get("mediaType"))
    if any((pin["entry"]["writer"], pin["entry"].get("contentProfile"),
            pin["entry"].get("contentProfileSha256"), pin["entry"].get("mediaType")) != profile for pin in pins):
        raise StoreError("Publication group target profiles changed")
    for pin in pins:
        _git(pin["repo"], "check-ref-format", pin["entry"]["reviewPrefix"])
    if pins[0]["entry"]["repository"] != group["controlRepository"] or pins[0]["entry"]["sourceRef"] != group["controlRef"]:
        raise StoreError("Publication control basis changed")
    files = []
    full_entries = []
    for target_id, pin in zip(group["targets"], pins):
        blob, raw = _tree_entry(pin, pin["sourceCommit"])
        _document(pin, raw)
        entry_basis = {key: value for key, value in pin["entry"].items() if key != "grants"}
        full_entries.append({"id": target_id, "entry": pin["entry"]})
        files.append({"id": target_id, "entrySha256": fingerprint(entry_basis),
                      "repository": pin["entry"]["repository"], "sourceRef": pin["entry"]["sourceRef"],
                      "reviewPrefix": pin["entry"]["reviewPrefix"], "path": pin["path"],
                      "baseCommit": pin["sourceCommit"], "baseBlobSha256": hashlib.sha256(raw).hexdigest(),
                      "baseRevision": _revision(pin["sourceCommit"], raw), "baseBytes": len(raw)})
    group_basis = fingerprint({"group": group_id, "registration": group,
                               "targets": [{"id": target,
                                            "entry": {key: value for key, value in host["fileAuthorities"][target].items()
                                                      if key != "grants"}}
                                           for target in group["targets"]]})
    authorization_sha = fingerprint({"group": group_id, "registration": group, "targets": full_entries})
    revision = fingerprint({"groupSha256": group_basis,
                            "targets": [{"id": row["id"], "revision": row["baseRevision"]} for row in files]})
    return pins, files, group_basis, revision, authorization_sha


def inspect(root, host, group, group_id):
    pins, files, basis, revision, authorization_sha = _source_snapshot(root, host, group, group_id)
    return {"group": group_id, "writer": pins[0]["entry"]["writer"],
            "contentProfile": pins[0]["entry"]["contentProfile"], "groupSha256": basis,
            "groupRevision": revision, "authorizationSha256": authorization_sha, "destinations": files}


def _proposal(root, host, group, group_id, proposal_id):
    if not _UUID.fullmatch(proposal_id):
        raise StoreError("Invalid file group proposal identity")
    pins, current_files, group_basis, _, authorization_sha = _source_snapshot(root, host, group, group_id)
    control = pins[0]
    commit = _ref_value(control, _ref("group-proposals", group_id, proposal_id))
    if not commit:
        raise StoreError("File group proposal unavailable")
    body = _git(control["repo"], "show", "-s", "--format=%B", commit).decode("utf-8", "strict")
    metadata = {}
    for line in body.splitlines():
        if line.startswith("Mimwell-Group-") and ": " in line:
            key, value = line.split(": ", 1)
            metadata[key] = value
    if metadata.get("Mimwell-Group-Proposal") != proposal_id:
        raise StoreError("File group proposal metadata is invalid")
    try:
        manifest = json.loads(base64.b64decode(metadata["Mimwell-Group-Manifest"], validate=True).decode("utf-8", "strict"),
                              object_pairs_hook=_pairs)
    except (KeyError, ValueError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise StoreError("File group proposal manifest is invalid") from exc
    current_map = {row["id"]: row for row in current_files}
    registration_matches = (manifest.get("group") == group_id and manifest.get("groupSha256") == group_basis and
                            len(current_files) == len(manifest.get("targets", [])) and
                            all(row["id"] in current_map and
                                {key: current_map[row["id"]].get(key) for key in ("entrySha256", "repository", "sourceRef", "reviewPrefix", "path")} ==
                                {key: row.get(key) for key in ("entrySha256", "repository", "sourceRef", "reviewPrefix", "path")}
                                for row in manifest.get("targets", [])))
    if (not registration_matches or manifest.get("writer") != pins[0]["entry"]["writer"] or
            manifest.get("requestSha256") != metadata.get("Mimwell-Group-RequestSha256") or
            not isinstance(manifest.get("reason"), str) or not manifest["reason"].strip() or
            len(manifest["reason"]) > 2000):
        raise StoreError("File group proposal no longer matches its registered targets")
    parents = _git(control["repo"], "rev-list", "--parents", "-n", "1", commit).decode().split()
    if len(parents) != 2 or parents[1] != manifest["targets"][0]["baseCommit"]:
        raise StoreError("File group proposal control basis is invalid")
    _, after_raw = _tree_entry(control, commit)
    if hashlib.sha256(after_raw).hexdigest() != manifest.get("contentSha256"):
        raise StoreError("File group proposal bytes changed")
    target_refs = {row["id"]: row["reviewPrefix"].rstrip("/") + "/group-" + group_id + "/" + proposal_id
                   for row in manifest["targets"]}
    author = next((candidate for target in manifest["targets"]
                   for candidate in host["fileAuthorities"][target["id"]]["grants"]
                   if _actor_hash(candidate) == manifest.get("authorSha256")), None)
    reviewers = []
    for candidate in {actor for target in manifest["targets"]
                      for actor in host["fileAuthorities"][target["id"]]["grants"]}:
        if candidate == author:
            continue
        review = _ref_value(control, _ref("group-reviews", group_id, proposal_id, candidate))
        if review:
            parents = _git(control["repo"], "rev-list", "--parents", "-n", "1", review).decode().split()
            if len(parents) == 2 and parents[1] == commit:
                reviewers.append(candidate)
    value = {"id": proposal_id, "commit": commit, "group": group_id, "groupSha256": group_basis,
             "writer": manifest["writer"], "author": author, "requestSha256": manifest["requestSha256"],
             "reason": manifest["reason"],
             "contentSha256": manifest["contentSha256"], "contentBytes": manifest["contentBytes"],
             "destinations": [{**row, "reviewRef": target_refs[row["id"]]} for row in manifest["targets"]],
             "reviewers": sorted(reviewers), "authorizationChanged": authorization_sha != manifest.get("authorizationSha256"),
             "stale": (any(pin["sourceCommit"] != row["baseCommit"]
                           for pin, row in zip(pins, manifest["targets"])) or
                       authorization_sha != manifest.get("authorizationSha256"))}
    if manifest["writer"] == "markdown-commit":
        value["afterWire"] = after_raw.decode("utf-8", "strict")
        value["mediaType"] = "text/markdown"
    else:
        value["mediaType"] = pins[0]["entry"]["mediaType"]
    value["proposalSha256"] = fingerprint({"commit": commit, "manifest": manifest})
    return value, manifest, pins, after_raw


def _base64_manifest(manifest):
    return base64.b64encode(json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).decode()


def _write_blob_commit(root, pin, base_commit, raw, message):
    new_blob = _git(pin["repo"], "hash-object", "-w", "--stdin", input_bytes=raw).decode().strip()
    index_path = root / "_internal" / ("git-file-group-index-" + uuid.uuid4().hex)
    index_path.touch(mode=0o600)
    try:
        env = {"GIT_INDEX_FILE": str(index_path)}
        _git(pin["repo"], "read-tree", base_commit, env_extra=env)
        _git(pin["repo"], "update-index", "--add", "--cacheinfo", "100644," + new_blob + "," + pin["path"], env_extra=env)
        tree = _git(pin["repo"], "write-tree", env_extra=env).decode().strip()
    finally:
        index_path.unlink(missing_ok=True)
        Path(str(index_path) + ".lock").unlink(missing_ok=True)
    env = {"GIT_AUTHOR_NAME": "Mimwell Authoring Host", "GIT_AUTHOR_EMAIL": "authoring@localhost",
           "GIT_COMMITTER_NAME": "Mimwell Authoring Host", "GIT_COMMITTER_EMAIL": "authoring@localhost"}
    return _git(pin["repo"], "commit-tree", tree, "-p", base_commit, "-m", message, env_extra=env).decode().strip()


def _ledger_key(group_id, proposal_id):
    return group_id + "/" + proposal_id


def _ledger_update(root, key, mutate):
    ledger = _Ledger(root)
    try:
        current = ledger.data["records"].get(key)
        result = mutate(current)
        if result is not None:
            ledger.data["records"][key] = result
        ledger.save()
        return result
    finally:
        ledger.close()


def _ledger_read(root, key):
    ledger = _Ledger(root)
    try:
        return ledger.data["records"].get(key)
    finally:
        ledger.close()


def run_group(root, host, group, group_id, operation, args, *, actor, guard):
    if operation == "file.group.inspect":
        return inspect(root, host, group, group_id)
    if operation in ("file.group.propose", "file.group.propose-binary"):
        pins, targets, group_basis, group_revision, authorization_sha = _source_snapshot(root, host, group, group_id)
        if args["expectedGroupRevision"] != group_revision:
            raise StoreError("Registered publication group changed; inspect again")
        if args["expectedAuthorizationSha256"] != authorization_sha:
            raise StoreError("Publication group authorization changed; inspect again")
        writer = pins[0]["entry"]["writer"]
        if operation == "file.group.propose-binary":
            if writer != "binary-commit":
                raise StoreError("Binary proposal does not match the registered group writer")
            raw = _canonical_asset(args["contentBase64"], min(pin["entry"]["maxBytes"] for pin in pins))
        else:
            if writer != "markdown-commit" or not isinstance(args["documentWire"], str):
                raise StoreError("Text proposal does not match the registered group writer")
            raw = args["documentWire"].encode("utf-8", "strict")
            if len(raw) > min(pin["entry"]["maxBytes"] for pin in pins):
                raise StoreError("File group content exceeds its registered limit")
            _document(pins[0], raw)
        request_sha = fingerprint({"groupSha256": group_basis, "authorizationSha256": authorization_sha, "targets": targets,
                                  "contentSha256": hashlib.sha256(raw).hexdigest(), "reason": args["reason"],
                                  "authorSha256": _actor_hash(actor)})
        key = _ledger_key(group_id, args["requestId"])
        proposal_ref = _ref("group-proposals", group_id, args["requestId"])
        existing = _ref_value(pins[0], proposal_ref)
        ledger_record = _ledger_read(root, key)
        if existing:
            proposal, manifest, _, _ = _proposal(root, host, group, group_id, args["requestId"])
            if manifest["requestSha256"] != request_sha:
                raise StoreError("File group request ID was already used for different content")
            if ledger_record is None:
                _ledger_update(root, key, lambda prior: {
                    "groupSha256": group_basis, "authorizationSha256": authorization_sha,
                    "proposalCommit": existing, "proposalSha256": proposal["proposalSha256"],
                    "requestSha256": request_sha, "authorSha256": _actor_hash(actor),
                    "destinations": {target["id"]: {"state": "pending"} for target in targets}})
            return proposal
        if ledger_record is not None:
            if ledger_record.get("requestSha256") != request_sha:
                raise StoreError("File group request ID ledger conflicts")
            staged_commit = ledger_record.get("proposalCommit")
            if isinstance(staged_commit, str) and re.fullmatch(r"[0-9a-f]{40,64}", staged_commit):
                guard()
                _create_ref_cas(pins[0], proposal_ref, staged_commit, targets[0]["baseCommit"])
                proposal = _proposal(root, host, group, group_id, args["requestId"])[0]
                _ledger_update(root, key, lambda prior: {**prior, "proposalSha256": proposal["proposalSha256"]})
                return proposal
            raise StoreError("File group proposal staging is incomplete; inspect before retry")
        manifest = {"format": "file-publication-proposal/v1", "group": group_id,
                    "groupSha256": group_basis, "authorizationSha256": authorization_sha,
                    "targets": targets, "writer": writer,
                    "reason": args["reason"],
                    "contentSha256": hashlib.sha256(raw).hexdigest(), "contentBytes": len(raw),
                    "authorSha256": _actor_hash(actor), "requestSha256": request_sha}
        base = targets[0]["baseCommit"]
        control = pins[0]
        commit = _write_blob_commit(root, control, base, raw,
            "Mimwell multi-destination file proposal\n\nMimwell-Group-Proposal: " + args["requestId"] +
            "\nMimwell-Group-Manifest: " + _base64_manifest(manifest) +
            "\nMimwell-Group-RequestSha256: " + request_sha + "\n")
        guard()
        current_pins, current_targets, current_group_sha, _, current_auth_sha = _source_snapshot(root, host, group, group_id)
        if current_group_sha != group_basis or current_targets != targets or current_auth_sha != authorization_sha:
            raise StoreError("File group registration or source changed before proposal staging")
        initial_record = {"groupSha256": group_basis, "authorizationSha256": authorization_sha,
                          "proposalCommit": commit, "proposalSha256": None, "requestSha256": request_sha,
                          "authorSha256": _actor_hash(actor),
                          "destinations": {target["id"]: {"state": "pending"} for target in targets}}
        _ledger_update(root, key, lambda previous: previous or initial_record)
        guard()
        _create_ref_cas(control, proposal_ref, commit, base)
        proposal = _proposal(root, host, group, group_id, args["requestId"])[0]
        _ledger_update(root, key, lambda previous: {**previous, "proposalSha256": proposal["proposalSha256"]})
        return proposal
    if operation == "file.group.proposal-inspect":
        proposal, manifest, pins, raw = _proposal(root, host, group, group_id, args["proposal"])
        ledger = _ledger_read(root, _ledger_key(group_id, proposal["id"]))
        if ledger is None:
            raise StoreError("File group operational ledger is unavailable")
        return {**proposal, "destinationStates": ledger["destinations"]}
    if operation == "file.group.review":
        proposal, manifest, pins, raw = _proposal(root, host, group, group_id, args["proposal"])
        if proposal["proposalSha256"] != args["expectedProposalSha256"] or proposal["stale"] or proposal["author"] == actor:
            raise StoreError("File group proposal is stale or independent review is unavailable")
        review_ref = _ref("group-reviews", group_id, proposal["id"], actor)
        existing = _ref_value(pins[0], review_ref)
        if existing:
            return {"proposal": proposal["id"], "reviewer": actor, "reviewCommit": existing, "state": "reviewed"}
        parent = proposal["commit"]
        tree = _git(pins[0]["repo"], "rev-parse", parent + "^{tree}").decode().strip()
        meta = ("Mimwell-Group-Review: " + proposal["id"] + "\nMimwell-Group-ReviewerSha256: " +
                _actor_hash(actor) + "\nMimwell-Group-ProposalSha256: " + proposal["proposalSha256"] + "\n")
        ident = {"GIT_AUTHOR_NAME": "Mimwell Group Reviewer", "GIT_AUTHOR_EMAIL": "reviewer@localhost",
                 "GIT_COMMITTER_NAME": "Mimwell Group Reviewer", "GIT_COMMITTER_EMAIL": "reviewer@localhost"}
        review_commit = _git(pins[0]["repo"], "commit-tree", tree, "-p", parent,
                             "-m", "Mimwell group review\n\n" + meta, env_extra=ident).decode().strip()
        guard()
        latest, targets_now, group_now, _, current_auth_sha = _source_snapshot(root, host, group, group_id)
        if (group_now != proposal["groupSha256"] or current_auth_sha != manifest.get("authorizationSha256") or
                any(p["sourceCommit"] != row["baseCommit"] for p, row in zip(latest, manifest["targets"]))):
            raise StoreError("File group basis changed before review")
        _create_ref_cas(pins[0], review_ref, review_commit, pins[0]["sourceCommit"])
        return {"proposal": proposal["id"], "reviewer": actor, "reviewCommit": review_commit, "state": "reviewed"}
    if operation in ("file.group.status", "file.group.destination-publish"):
        proposal, manifest, pins, raw = _proposal(root, host, group, group_id, args["proposal"])
        key = _ledger_key(group_id, proposal["id"])
        ledger = _ledger_read(root, key)
        if (not ledger or ledger.get("groupSha256") != proposal["groupSha256"] or
                ledger.get("authorizationSha256") != manifest.get("authorizationSha256")):
            raise StoreError("File group operational ledger does not match the proposal")
        statuses = _reconcile(root, proposal, manifest, pins, ledger, key)
        if operation == "file.group.status":
            return {"proposal": proposal["id"], "proposalSha256": proposal["proposalSha256"],
                    "destinations": statuses, "partial": any(row["state"] == "published" for row in statuses) and
                    any(row["state"] != "published" for row in statuses)}
        if args["expectedProposalSha256"] != proposal["proposalSha256"] or proposal["stale"]:
            raise StoreError("File group proposal basis is stale")
        if not any(reviewer != proposal["author"] for reviewer in proposal["reviewers"]):
            raise StoreError("Independent file group review is required")
        target_id = args["destination"]
        try:
            index = group["targets"].index(target_id)
        except ValueError as exc:
            raise StoreError("Destination is not selected by the host group") from exc
        status = next(row for row in statuses if row["id"] == target_id)
        if status["state"] == "published":
            return {"proposal": proposal["id"], **status}
        if status["state"] != "pending":
            raise StoreError("Destination is not reconciled as pending; inspect group status")
        pin, target = pins[index], manifest["targets"][index]
        if pin["sourceCommit"] != target["baseCommit"]:
            _set_destination_state(root, key, target_id, {"state": "refused", "reason": "source-changed"})
            raise StoreError("Destination source changed after proposal")
        ref = proposal["destinations"][index]["reviewRef"]
        current = _ref_value(pin, ref)
        if current:
            if status.get("expectedCommit") == current:
                _set_destination_state(root, key, target_id, {**status, "state": "published", "commit": current})
                return {"proposal": proposal["id"], "id": target_id, "state": "published", "ref": ref, "commit": current}
            _set_destination_state(root, key, target_id, {"state": "refused", "reason": "ref-collision"})
            raise StoreError("Destination review ref already contains different content")
        expected_commit = status.get("expectedCommit")
        if not expected_commit:
            metadata = ("Mimwell-Group-Publish: " + proposal["id"] + "\nMimwell-Group-Destination: " + target_id +
                        "\nMimwell-Group-Sha256: " + proposal["groupSha256"] +
                        "\nMimwell-ContentSha256: " + proposal["contentSha256"] + "\n")
            expected_commit = _write_blob_commit(root, pin, target["baseCommit"], raw,
                "Mimwell reviewed group destination\n\n" + metadata)
        _set_destination_state(root, key, target_id,
                               {"state": "attempting", "ref": ref, "expectedCommit": expected_commit,
                                "expectedSourceCommit": target["baseCommit"]})
        try:
            guard()
            latest = _load_pins(root, pin["entry"])
            if latest["sourceCommit"] != target["baseCommit"]:
                raise StoreError("Destination source changed before compare-and-swap")
            _create_ref_cas(pin, ref, expected_commit, target["baseCommit"])
            if _ref_value(pin, ref) != expected_commit:
                raise StoreError("Destination ref did not retain the expected commit")
            _set_destination_state(root, key, target_id,
                                   {"state": "published", "ref": ref, "expectedCommit": expected_commit,
                                    "expectedSourceCommit": target["baseCommit"], "commit": expected_commit})
            return {"proposal": proposal["id"], "id": target_id, "state": "published", "ref": ref,
                    "commit": expected_commit}
        except Exception:
            current = None
            try:
                current = _ref_value(pin, ref)
            except Exception:
                pass
            if current == expected_commit:
                _set_destination_state(root, key, target_id,
                                       {"state": "published", "ref": ref, "expectedCommit": expected_commit,
                                        "expectedSourceCommit": target["baseCommit"], "commit": current})
            elif current is None:
                _set_destination_state(root, key, target_id,
                                       {"state": "outcome-unknown", "ref": ref, "expectedCommit": expected_commit,
                                        "expectedSourceCommit": target["baseCommit"]})
            raise
    raise StoreError("Unsupported file publication group operation")


def _set_destination_state(root, key, destination, value):
    def mutate(record):
        if record is None:
            raise StoreError("Publication group ledger record is missing")
        record["destinations"][destination] = value
        return record
    return _ledger_update(root, key, mutate)


def _reconcile(root, proposal, manifest, pins, ledger, key):
    statuses = []
    for target, pin, destination in zip(manifest["targets"], pins, proposal["destinations"]):
        row = dict(ledger["destinations"].get(target["id"], {"state": "refused", "reason": "ledger-target-missing"}))
        ref = destination["reviewRef"]
        try:
            current = _ref_value(pin, ref)
        except Exception:
            row["state"] = "outcome-unknown"
            current = None
        if row["state"] == "published":
            if current != row.get("expectedCommit"):
                row = {"state": "refused", "reason": "published-ref-no-longer-matches", "ref": ref}
                _set_destination_state(root, key, target["id"], row)
        elif current:
            if current == row.get("expectedCommit"):
                row.update(state="published", commit=current, ref=ref)
                _set_destination_state(root, key, target["id"], row)
            else:
                row = {"state": "refused", "reason": "ref-collision", "ref": ref}
                _set_destination_state(root, key, target["id"], row)
        elif row["state"] in ("attempting", "outcome-unknown"):
            if pin["sourceCommit"] == target["baseCommit"]:
                row.update(state="pending", ref=ref, reconciliation="expected-ref-absent-and-source-basis-current")
                _set_destination_state(root, key, target["id"], row)
            else:
                row = {"state": "refused", "reason": "source-changed-during-unknown-outcome", "ref": ref}
                _set_destination_state(root, key, target["id"], row)
        elif pin["sourceCommit"] != target["baseCommit"]:
            row = {"state": "refused", "reason": "source-changed", "ref": ref}
            _set_destination_state(root, key, target["id"], row)
        else:
            row.update(state="pending", ref=ref)
        statuses.append({"id": target["id"], **row})
    return statuses
