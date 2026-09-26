"""Local source-path declarations shared by producers and provenance checks."""
from urllib.parse import parse_qs, unquote, urlsplit


def record_slug(text):
    """Stable id fragment from free text, shared by compilation and audits."""
    out = []
    for char in str(text).strip().lower():
        if char.isalnum():
            out.append(char)
        elif out and out[-1] != "-":
            out.append("-")
    return "".join(out).strip("-") or "item"


def deliverable_identity(record):
    return "deliverable:" + str(record.get("id") or record_slug(record.get("title")))


def deliverable_source_paths(record):
    """Retain local document provenance, including links through the reader UI."""
    paths = set()
    for value in (record.get("doc"), record.get("link")):
        if not isinstance(value, str) or not value:
            continue
        parsed = urlsplit(value)
        if parsed.scheme or parsed.netloc:
            continue  # External references require their own authority.
        query = parse_qs(parsed.query)
        targets = [target for key in ("f", "doc", "path", "file") for target in query.get(key, [])]
        for target in targets or [parsed.path]:
            for _ in range(3):
                decoded = unquote(target)
                if decoded == target:
                    break
                target = decoded
            parts = []
            for part in target.replace("\\", "/").split("/"):
                if part in ("", "."):
                    continue
                if part == "..":
                    if parts:
                        parts.pop()
                else:
                    parts.append(part)
            if parts:
                paths.add("/".join(parts))
    return sorted(paths)
