#!/usr/bin/env python3
"""Build the Cloudflare assets directory for the portal.

Wrangler serves static assets from `_site/`; this script stages tracked portal
assets there so local caches, git metadata, secrets, and process files never
enter the asset namespace.

The set of published files is `git ls-files` minus everything matched by
`.assetsignore`. That matcher (`ignored()`) is the single source of truth for
"what deploys" — the publish-safety gate (check-no-internal-published.py) imports
and reuses it so an `.assetsignore` regression can't silently leak internal
material. Only regular tracked files reached without symlinks may be staged.
Submodule contents are separate publication units. Use a quiescent source tree;
this is not a transactional filesystem snapshot or atomic deployed cutover.

Run from repo root:  python3 scripts/build-portal-site.py
"""

from __future__ import annotations

from contextlib import contextmanager
import fnmatch
import os
import stat
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "_site"
IGNORE = ROOT / ".assetsignore"


def load_patterns() -> list[str]:
    if not IGNORE.exists():
        return []
    patterns = []
    for line in IGNORE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            patterns.append(stripped.rstrip("/"))
    return patterns


def ignored(path: str, patterns: list[str]) -> bool:
    parts = path.split("/")
    for pattern in patterns:
        if path == pattern or path.startswith(pattern + "/"):
            return True
        if fnmatch.fnmatch(path, pattern):
            return True
        # Directory pattern (possibly globbed, e.g. analysis/sessions/*/cache):
        # also exclude everything nested under it. fnmatch '*' spans '/', so a
        # single trailing '/*' covers any depth.
        if fnmatch.fnmatch(path, pattern + "/*"):
            return True
        # A leading '**/' must also match at the repo root (fnmatch's '**/' needs
        # at least one dir segment), so '**/*.pyc' also excludes a root 'x.pyc'.
        if pattern.startswith("**/") and fnmatch.fnmatch(path, pattern[3:]):
            return True
        if "/" not in pattern and any(part == pattern for part in parts):
            return True
    return False


def git_files(cwd: Path, prefix: str = "") -> list[str]:
    output = subprocess.check_output(["git", "-C", str(cwd), "ls-files", "--stage", "-z"])
    files = []
    for item in output.split(b"\0"):
        if not item:
            continue
        header, path = item.split(b"\t", 1)
        mode, _, stage = header.decode().split()
        if stage != "0":
            raise ValueError("Resolve index conflicts before staging portal assets")
        # A submodule is another publication unit, never an implicit asset tree.
        if mode == "160000":
            continue
        files.append(prefix + path.decode("utf-8"))
    return files


@contextmanager
def asset_source(relative):
    """Open only regular files through non-symlink directories inside ROOT."""
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != relative or not path.parts:
        raise ValueError("Asset path must be a normalized relative path")
    descriptors = []
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptors.append(os.open(ROOT, directory_flags))
        for part in path.parts[:-1]:
            descriptors.append(os.open(part, directory_flags, dir_fd=descriptors[-1]))
        fd = os.open(path.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=descriptors[-1])
        descriptors.append(fd)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Asset source is not a regular file")
        with os.fdopen(os.dup(fd), "rb") as stream:
            yield stream
    except OSError as exc:
        raise ValueError("Asset source is missing, unreadable or uses a symlink: " + relative) from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def tracked_asset_files(patterns: list[str]) -> list[str]:
    files = [path for path in sorted(git_files(ROOT)) if not ignored(path, patterns)]
    for path in files:
        # Share the source boundary with the publication gate, before reading bytes.
        with asset_source(path):
            pass
    return files


def main() -> int:
    patterns = load_patterns()
    files = tracked_asset_files(patterns)
    # Failed source reads never replace a previously staged snapshot. Staging is
    # outside the asset root and cannot itself become a source asset.
    with tempfile.TemporaryDirectory(prefix="portal-assets-") as directory:
        staged = Path(directory) / "site"
        staged.mkdir()
        for rel in files:
            dst = staged / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            with asset_source(rel) as source, dst.open("wb") as output:
                before = os.fstat(source.fileno())
                shutil.copyfileobj(source, output)
                after = os.fstat(source.fileno())
                if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                        after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise ValueError("Asset source changed while copying: " + rel)
                os.fchmod(output.fileno(), stat.S_IMODE(before.st_mode))
        if OUT.is_symlink():
            raise ValueError("Asset output must not be a symlink")
        if OUT.exists():
            shutil.rmtree(OUT)
        shutil.move(str(staged), str(OUT))
    print(f"Wrote {OUT} ({len(files)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
