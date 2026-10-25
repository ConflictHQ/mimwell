"""Bounded edits over the current native record; never a second writer."""
from copy import deepcopy
from knowledge_store import StoreError

PATCH_FIELDS = {"title", "text", "addRelations", "removeRelations"}


def validate_patch(patch):
    if not isinstance(patch, dict) or not patch or set(patch) - PATCH_FIELDS:
        raise StoreError("Unsupported record patch")
    for key, limit in (("title", 2000), ("text", 65536)):
        if key in patch and (not isinstance(patch[key], str) or len(patch[key]) > limit):
            raise StoreError("Invalid record patch content")
    pairs = {}
    for key in ("addRelations", "removeRelations"):
        if key not in patch:
            continue
        rows = patch[key]
        if not isinstance(rows, list) or not 1 <= len(rows) <= 64:
            raise StoreError("Invalid bounded relationship patch")
        keys = []
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"rel", "target"} or any(
                not isinstance(row[name], str) or not row[name].strip() or len(row[name]) > 2000
                for name in ("rel", "target")
            ):
                raise StoreError("Invalid relationship patch")
            keys.append((row["rel"], row["target"]))
        if len(set(keys)) != len(keys):
            raise StoreError("Duplicate relationship patch")
        pairs[key] = set(keys)
    if pairs.get("addRelations", set()) & pairs.get("removeRelations", set()):
        raise StoreError("Conflicting relationship patch")


def patched_record(current, patch):
    validate_patch(patch)
    value = deepcopy(current)
    for key in ("title", "text"):
        if key in patch:
            value["content"][key] = patch[key]
    remove = {(row["rel"], row["target"]) for row in patch.get("removeRelations", [])}
    existing = {(row["rel"], row["target"]) for row in value["relations"]}
    if not remove <= existing:
        raise StoreError("Relationship changed; inspect before editing")
    value["relations"] = [row for row in value["relations"] if (row["rel"], row["target"]) not in remove]
    for row in patch.get("addRelations", []):
        if (row["rel"], row["target"]) in existing:
            raise StoreError("Relationship already exists; inspect before editing")
        value["relations"].append(deepcopy(row))
    return value
