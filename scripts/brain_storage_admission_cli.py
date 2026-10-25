"""Explicit owner preview/apply and reconciliation CLI for #536 admission."""
import argparse
import json
import os
from pathlib import Path
import stat
import sys

from brain_storage_admission import (
    AdmissionLedger, apply_adoption, configured_admission, load_registration,
    preview_adoption, validate_selection,
)
from knowledge_store import SQLiteAuthority, StoreError, resolve_store_dsn

MAX_INPUT = 64 * 1024


def _read_json(path, *, private=False):
    path = Path(path)
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_size > MAX_INPUT
                or private and info.st_mode & 0o077):
            raise StoreError("Storage admission input is unsafe or exceeds its bound")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            before = os.fstat(fd)
            def identity(item):
                return (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
            if (identity(before) != identity(info) or not stat.S_ISREG(before.st_mode)
                    or before.st_uid != os.geteuid() or before.st_nlink != 1
                    or before.st_size > MAX_INPUT or private and before.st_mode & 0o077):
                raise StoreError("Storage admission input changed while opening")
            raw = os.read(fd, MAX_INPUT + 1)
            after = os.fstat(fd)
            named = path.lstat()
            if (len(raw) > MAX_INPUT or identity(before) != identity(after)
                    or identity(after) != identity(named) or not stat.S_ISREG(after.st_mode)
                    or after.st_uid != os.geteuid() or after.st_nlink != 1
                    or after.st_size > MAX_INPUT or private and after.st_mode & 0o077):
                raise StoreError("Storage admission input changed while reading")
        finally:
            os.close(fd)
        return json.loads(raw)
    except StoreError:
        raise
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise StoreError("Storage admission input is unavailable or malformed") from exc


def _owner_store(root):
    root = Path(root).resolve(strict=True)
    config = _read_json(root / "client.config.json")
    brain = config.get("brain")
    authority = brain.get("authority") if isinstance(brain, dict) else None
    uid = str(os.geteuid())
    if (not isinstance(authority, dict) or uid not in authority.get("operatorUids", [])
            or not isinstance(authority.get("principalsByUid"), dict)
            or not authority["principalsByUid"].get(uid)):
        raise StoreError("Current OS identity is not an owner operator for this brain")
    store_id, binding = authority.get("store"), authority.get("binding")
    stores = brain.get("stores")
    matches = [row for row in stores if isinstance(row, dict) and row.get("id") == store_id]
    if len(matches) != 1:
        raise StoreError("Current canonical authority is unavailable")
    location = resolve_store_dsn(config, store_id)
    path = Path(location)
    path = path if path.is_absolute() else root / path
    store = SQLiteAuthority(path, expected_binding=binding)
    if store.contract.authority != store_id or store.contract.binding != binding:
        store.close()
        raise StoreError("Current canonical authority changed")
    from knowledge_store import blob_store_for
    blob = blob_store_for(root, config, store.contract)
    return store, getattr(blob, "root", None)


def _emit(value):
    sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def run(args):
    root = Path(args.root).resolve(strict=True)
    selection = _read_json(args.selection, private=True) if getattr(args, "selection", None) else None
    if args.operation == "preview":
        selection = validate_selection(selection)
        store, blob_root = _owner_store(root)
        try:
            _emit(preview_adoption(root, store, selection, blob_root=blob_root))
        finally:
            store.close()
        return 0
    if args.operation == "apply":
        selection = validate_selection(selection)
        store, blob_root = _owner_store(root)
        try:
            receipt = apply_adoption(root, store, selection,
                expected_preview_sha256=args.preview_sha256,
                expected_authority_revision=args.authority_revision, blob_root=blob_root)
            _emit(receipt)
        finally:
            store.close()
        return 0
    if args.operation == "reconcile":
        registration = load_registration(root, required=True)
        ledger = AdmissionLedger(root, registration)
        store, _blob_root = _owner_store(root)
        try:
            configured = configured_admission(root, store)
            if configured is None:
                raise StoreError("Storage admission is unavailable")
            _ledger, inventory_now = configured
            current = inventory_now()
            if current["basisSha256"] != args.basis_sha256:
                raise StoreError("Review the current inventory and retry reconciliation")
            ledger.reconcile_unknown(args.reservation, expected_basis_sha256=args.basis_sha256,
                                     inventory_now=inventory_now)
            _emit({"format": "brain-storage-reconciliation/v1", "reservation": args.reservation,
                   "basisSha256": args.basis_sha256, "state": "settled"})
        finally:
            store.close()
        return 0
    if args.operation == "recover-stale":
        registration = load_registration(root, required=True)
        ledger = AdmissionLedger(root, registration)
        store, _blob_root = _owner_store(root)
        try:
            configured = configured_admission(root, store)
            if configured is None:
                raise StoreError("Storage admission is unavailable")
            _ledger, inventory_now = configured
            current = inventory_now()
            if current["basisSha256"] != args.basis_sha256:
                raise StoreError("Review the current inventory and retry recovery")
            result = ledger.recover_stale_reserved(args.reservation,
                expected_basis_sha256=args.basis_sha256, inventory_now=inventory_now)
            _emit({"format": "brain-storage-reconciliation/v1", **result})
        finally:
            store.close()
        return 0
    raise StoreError("Unknown storage admission operation")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    for operation in ("preview", "apply"):
        command = sub.add_parser(operation)
        command.add_argument("--root", required=True, type=Path)
        command.add_argument("--selection", required=True, type=Path,
                             help="owner-reviewed private JSON selection; contains no keys or grants")
        if operation == "apply":
            command.add_argument("--preview-sha256", required=True)
            command.add_argument("--authority-revision", required=True)
    reconcile = sub.add_parser("reconcile")
    reconcile.add_argument("--root", required=True, type=Path)
    reconcile.add_argument("--reservation", required=True)
    reconcile.add_argument("--basis-sha256", required=True,
                           help="exact fresh inventory basis inspected by the owner")
    recover = sub.add_parser("recover-stale")
    recover.add_argument("--root", required=True, type=Path)
    recover.add_argument("--reservation", required=True)
    recover.add_argument("--basis-sha256", required=True,
                         help="exact fresh inventory basis inspected by the owner")
    args = parser.parse_args(argv)
    try:
        return run(args)
    except (StoreError, OSError, ValueError) as exc:
        sys.stderr.write(str(exc) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
