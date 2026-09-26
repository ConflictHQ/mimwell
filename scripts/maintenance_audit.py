"""Private operations journal shared by local maintenance host commands."""
import datetime as dt
import fcntl
import json
import os
import stat


def audit(root):
    """Private append-only operations journal; no report/claim text is logged.

    Local operator path, not a producer-selected path. Parent directories must be
    owned by this process user without group/other writes; the maintenance
    directory and log additionally deny group/other reads. Refuse broad existing
    permissions instead of changing an operator's directory.
    """
    root = root.resolve(strict=True)
    directory = root
    for part in ("_internal", "maintenance"):
        directory = directory / part
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & (0o077 if part == "maintenance" else 0o022):
            raise ValueError("Unsafe maintenance audit directory")
    descriptor = os.open(directory / "operations.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
        os.close(descriptor)
        raise ValueError("Unsafe maintenance audit file")
    return os.fdopen(descriptor, "a", encoding="utf-8")



def operation(journal, op, actor, subject, detail):
    entry = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
             "op": op, "actor": actor, "subject": subject, "detail": detail}
    fcntl.flock(journal, fcntl.LOCK_EX)
    try:
        journal.write(json.dumps(entry, sort_keys=True) + "\n")
        journal.flush()
        os.fsync(journal.fileno())
    finally:
        fcntl.flock(journal, fcntl.LOCK_UN)
