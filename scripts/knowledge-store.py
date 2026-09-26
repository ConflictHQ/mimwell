#!/usr/bin/env python3
"""Authenticated local verbs for an explicitly adopted record authority."""

import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys

from knowledge_store import (
    ROOT, DB_VERSION, LOCAL_DRIVERS, Contract, CutoverLoss, FileReference, StoreError, adopted_authority,
    atomic_projection, authority_class, blob_store_for, cell_name, conformance, cutover, example_bundle, private_path,
    resolve_store_dsn, resume, vector_store_for,
)
from sql_dialect import driver_errors
import vector_role


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--check-example", action="store_true")
    parser.add_argument("--contract", type=Path, help="with --check-example: a contract.json to check in place of the example")
    parser.add_argument("--store", help="with conformance: the brain.stores id of a disposable store naming the cell")
    parser.add_argument("--receipt", type=Path, help="with conformance: also write the receipt to this path")
    parser.add_argument("--to", help="with cutover and resume: the brain.stores id of the successor store, of any "
                                     "authority driver")
    parser.add_argument(
        "command",
        nargs="?",
        choices=[
            "example",
            "describe",
            "inspect",
            "init",
            "get",
            "context",
            "search",
            "path",
            "propose",
            "review",
            "dispose",
            "commit",
            "export",
            "restore",
            "cutover",
            "resume",
            "migrate",
            "deliver",
            "project",
            "reindex",
            "nearest",
            "conformance",
        ],
    )
    parser.add_argument("arguments", nargs="*")
    args = parser.parse_args(argv)
    store = target = vectors = None
    try:
        if args.check_example or args.command == "example":
            bundle = example_bundle(args.root, args.contract)
            contract = Contract(bundle)
            print(
                json.dumps(
                    {"binding": contract.binding, "cell": cell_name(contract.cell), "runtimeVerified": False}
                    if args.check_example
                    else {"bundle": bundle, "records": []},
                    indent=2,
                )
            )
            return 0
        if args.command == "conformance":
            receipt = conformance(args.root, args.store)
            text = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
            if args.receipt:
                args.receipt.write_text(text)
            print(text, end="")
            return 0 if receipt["result"] == "green" else 1
        settings = json.loads((args.root / "client.config.json").read_text())
        config = adopted_authority(settings)
        if config is None:
            raise StoreError("brain.authority is not configured")
        actor = config["principalsByUid"].get(str(os.geteuid()))
        if not actor:
            raise StoreError("host identity is not configured")
        command, values = args.command, args.arguments
        arity = {
            "describe": 0,
            "inspect": 1,
            "init": 1,
            "get": 1,
            "context": 0,
            "search": 1,
            "path": 2,
            "propose": 1,
            "review": 2,
            "dispose": 4,
            "commit": 1,
            "export": 0,
            "restore": 1,
            "cutover": 0,
            "resume": 0,
            "migrate": 0,
            "deliver": 2,
            "project": 1,
            "reindex": 0,
            "nearest": 1,
        }
        if command not in arity or len(values) != arity[command] or (command in ("cutover", "resume")) != bool(args.to):
            raise StoreError("invalid command arguments; use --help")
        if (
            command in ("init", "export", "restore", "cutover", "resume", "migrate", "deliver", "project")
            and str(os.geteuid()) not in config["operatorUids"]
        ):
            raise StoreError("administrative operation requires a configured host operator")

        def located(dsn):
            """(adapter, driver, location) of a resolved store dsn; a local driver's location is a private path."""
            adapter = authority_class(dsn)
            driver = adapter.driver if adapter is FileReference else adapter.dialect_class.driver
            return adapter, driver, private_path(args.root, dsn, driver) if driver in LOCAL_DRIVERS else dsn

        adapter, driver, path = located(resolve_store_dsn(settings, config["store"]))
        if adapter is FileReference and command not in ("get", "context", "export", "restore", "cutover", "resume"):
            raise StoreError("a files authority is read-only; cut over to a database store (cutover --to <store id>)")
        if command == "init":
            source = json.loads(Path(values[0]).read_text())
            initial = Contract(source["bundle"])
            if initial.binding != config["binding"]:
                raise StoreError("initial contract differs from the adopted binding")
            if initial.authority != config["store"]:
                raise StoreError("brain.authority.store is not the contract's authority store")
            store = adapter.initialize(
                path, source["bundle"], source["records"], prior_history=source.get("priorHistory")
            )
            result = {"initialized": True, "binding": store.contract.binding}
        elif command == "restore":
            snapshot = json.loads(Path(values[0]).read_text())
            metadata = {row["key"]: row["value"] for row in snapshot["tables"]["metadata"]}
            if Contract(json.loads(metadata["bundle"])).binding != config["binding"]:
                raise StoreError("backup contract differs from the adopted binding")
            blobs = blob_store_for(args.root, settings, Contract(json.loads(metadata["bundle"])))
            store = adapter.restore(path, snapshot, blob_store=blobs)
            result = {"restored": True, "status": "standby"}
        else:
            if command == "migrate":
                store = adapter.migrate(path, expected_binding=config["binding"])
                result = {"migrated": True, "schemaVersion": DB_VERSION}
                if store.contract.binding != config["binding"]:
                    if config["binding"] not in store.contract.legacy_bindings:
                        raise StoreError("migrated authority differs from adopted binding")
                    # Schema 11 leaves the driver out of the binding: move the adopted pin once.
                    settings["brain"]["authority"]["binding"] = store.contract.binding
                    (args.root / "client.config.json").write_text(json.dumps(settings, indent=2, ensure_ascii=False) + "\n")
                    result["binding"] = store.contract.binding
            else:
                store = adapter(path, expected_binding=config["binding"])
                if store.contract.authority != config["store"]:
                    raise StoreError("brain.authority.store is not the contract's authority store")
                if command == "describe":
                    result = store.describe(actor)
                elif command == "inspect":
                    result = store.inspect(values[0], actor)
                elif command == "get":
                    result = store.get(values[0], actor)
                elif command == "context":
                    result = store.context(actor)
                elif command == "search":
                    result = store.search(values[0], actor)
                elif command == "path":
                    result = store.path_between(values[0], values[1], actor)
                elif command == "propose":
                    source = json.loads(Path(values[0]).read_text())
                    if set(source) != {"request", "record"}:
                        raise StoreError(
                            "proposal requires only request and record; host identity is not a payload field"
                        )
                    result = store.propose(source["request"], source["record"], actor)
                elif command == "review":
                    result = store.review(values[0], actor, values[1])
                elif command == "dispose":
                    result = store.dispose(values[0], actor, values[1], values[3],
                                           expected_proposal_sha256=values[2])
                elif command == "commit":
                    result = store.commit(values[0], actor)
                elif command == "export":
                    result = store.export()
                elif command == "deliver":
                    destination = private_path(args.root, values[1], "files")
                    result = store.deliver(values[0], actor, lambda payload: atomic_projection(destination, payload))
                elif command == "project":
                    from projection_receipts import paths, write_receipt
                    if config.get("projections") != "committed":
                        raise StoreError("project requires brain.authority.projections = committed")
                    destination, _ = paths(args.root, values[0])
                    result = store.deliver(values[0], actor, lambda payload: atomic_projection(destination, payload))
                    result["receipt"] = write_receipt(args.root, values[0])
                elif command == "cutover":
                    successor, _, location = located(resolve_store_dsn(settings, args.to))
                    target = cutover(store, successor, location, store=args.to,
                                     blob_store=blob_store_for(args.root, settings, store.contract))
                    result = {
                        "source": "frozen",
                        "successor": args.to,
                        "binding": target.contract.binding,
                        "instruction": f"Point brain.stores {config['store']} at the dsn of {args.to} "
                                       "before resuming clients.",
                    }
                elif command == "resume":
                    successor, _, location = located(resolve_store_dsn(settings, args.to))
                    target = successor(location, expected_binding=config["binding"])
                    resume(store, target, store=args.to)
                    result = {"source": "frozen", "successor": args.to, "status": "active"}
                elif command in ("reindex", "nearest"):
                    vectors = vector_store_for(args.root, settings, store.contract, driver, str(path))
                    if command == "reindex":
                        result = vector_role.rebuild(store, actor, vectors)
                        if result["stored"] != result["digest"]:
                            raise StoreError("the vectors store does not hold the index rebuilt from the authority")
                    else:
                        # The index is derived: a hit the actor can no longer read is dropped, not served.
                        readable = {node["id"] for node in store.context(actor)["nodes"]}
                        hits = vector_role.search(vectors, vector_role.namespace(store.contract.binding, actor),
                                                  values[0], 10)
                        result = [hit for hit in hits if hit["id"] in readable]
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except CutoverLoss as exc:
        print(json.dumps({"cutover": "refused", "losses": exc.losses}, ensure_ascii=False, indent=2))
        print(f"knowledge-store: {exc}", file=sys.stderr)
        return 1
    except (ValueError, OSError, KeyError, TypeError, sqlite3.Error, *driver_errors()) as exc:
        print(f"knowledge-store: {exc}", file=sys.stderr)
        return 1
    finally:
        if vectors:
            vectors.close()
        if target:
            target.close()
        if store:
            store.close()


if __name__ == "__main__":
    raise SystemExit(main())
