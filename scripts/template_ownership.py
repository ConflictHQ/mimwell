"""Shared ownership matching for template updates and release completeness checks."""

import fnmatch


def matches(path: str, patterns: list[str]) -> bool:
    """Directory suffixes match a subtree; other patterns use full-path fnmatch.

    Keep the updater's established semantics: fnmatch '*' can span '/'.
    """
    for pattern in patterns:
        if pattern.endswith("/"):
            if path == pattern[:-1] or path.startswith(pattern):
                return True
        elif fnmatch.fnmatch(path, pattern):
            return True
    return False


def classify(path: str, manifest: dict) -> str:
    """Ignore first, then engagement overrides, then template; otherwise untracked."""
    for owner in ("ignore", "engagement", "template"):
        if matches(path, manifest.get(owner, {}).get("paths", [])):
            return owner
    return "untracked"
