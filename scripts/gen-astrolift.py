#!/usr/bin/env python3
"""Emit astrolift.toml — deploy this brain onto an Astrolift install (W6/W1.8).

The brain is portable across targets because canon is git and every projection
is rebuildable; the target only decides which projections may exist. On
Cloudflare the portal is one Worker (wrangler.toml, the default). On Astrolift
it is a container workload (`deploy.image`, `deploy.port`) behind the install's
login gate, since a brain is private: a `statefulset` when a `sqlite-volume` is
attached, so each pod owns its claim, a `deployment` otherwise. Only a brain with
`deploy.public = true` and no volume renders a `static_site` (CDN-served from
`_site/`, scripts/build-portal-site.py, never login-gated; Astrolift's parser
rejects containers and volumes on it). Persistence `deploy.persistence` declares
lets the substrate graduate without leaving the platform:

    deploy.persistence   ->  manifest
    sqlite-volume            [[workloads.volumes]] pvc ReadWriteOnce at /data (brain.db)
    efs                      [[workloads.volumes]] pvc ReadWriteMany  at /shared
    postgres                 [[managed_services]] kind=postgres (DATABASE_URL envelope);
                             `age = true` when the contract's graph role is `age`
    s3                       a comment naming the secret-bundle binding; buckets are
                             bound outside the manifest (docs: managed-service bindings)
    d1 / kv / none           nothing — those belong to the Worker path

With --contract (the brain's knowledge-store contract.json), the manifest renders that
cell (#233): the graph role `age` asks for the AGE extension on the postgres service,
and a blobs store with driver `s3` binds by its `brain.stores[].dsn.secret` reference
only; an `env` dsn is refused, so no bucket credential reaches the manifest.

No-op unless client.config.json deploy.target == "astrolift", so a Worker-only
instance never grows a manifest it does not use. Reference:
https://astrolift.dev/reference/astrolift-toml/

Stdlib only. Run from anywhere:  python3 scripts/gen-astrolift.py [--contract PATH]
"""
from __future__ import annotations

import argparse
import json
import os

from config import settings

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "astrolift.toml")


def _q(s: str) -> str:
    return '"' + str(s).replace('\\', '\\\\').replace('"', '\\"') + '"'


def _role(contract, role):
    """The store a contract.json places `role` on, or None."""
    return next((s for s in (contract or {}).get("stores", ()) if role in s["roles"]), None)


def _secret_ref(cfg, store_id):
    """The secret-bundle reference `brain.stores` gives store_id; refuses any other dsn."""
    dsn = next((s["dsn"] for s in cfg.get("brain", "stores", default=()) or () if s["id"] == store_id), None)
    if dsn is None or "secret" not in dsn:
        raise SystemExit(f"gen-astrolift: blobs store {store_id} binds by secret-bundle reference only; "
                         f'set brain.stores {{"id": "{store_id}", "dsn": {{"secret": "<bundle>"}}}}')
    return dsn["secret"]


def _workload(dep, persistence, replicas):
    """The portal workload: a CDN static_site only for a public brain with no volume,
    otherwise a container behind the install's login gate carrying the volumes."""
    volumes = []
    if "sqlite-volume" in persistence:
        volumes += ["", "  [[workloads.volumes]]", '  name = "brain-data"', '  kind = "pvc"',
                    '  mount_path = "/data"', '  size = "5Gi"', '  access_mode = "ReadWriteOnce"',
                    '  # app/brain.db (substrate tier: indexed) lives here across deploys']
    if "efs" in persistence:
        volumes += ["", "  [[workloads.volumes]]", '  name = "brain-shared"', '  kind = "pvc"',
                    '  mount_path = "/shared"', '  size = "20Gi"', '  access_mode = "ReadWriteMany"',
                    '  # blobs (substrate.blobs = efs): recordings, media, exports shared across replicas']
    if dep.get("public", False) and not volumes:
        return ["[[workloads]]", 'name = "portal"', 'kind = "static_site"', f"replicas = {replicas}",
                "is_public = true", 'static_build_command = "make build portal-site"',
                'static_output_dir = "_site"', 'static_index = "index.html"']
    image = dep.get("image", None)
    if not image:
        raise SystemExit("gen-astrolift: a private brain (or one with a volume) runs as a container; "
                         "set deploy.image to the image that serves it (e.g. the context service)")
    port = int(dep.get("port", None) or 8080)
    kind = "statefulset" if "sqlite-volume" in persistence else "deployment"
    return ["[[workloads]]", 'name = "brain"', f"kind = {_q(kind)}", f"replicas = {replicas}",
            "# exposed on the install's managed subdomain, behind its login gate",
            "is_public = true", "", "  [[workloads.containers]]", '  name = "brain"',
            "  is_primary = true", f"  image_ref = {_q(image)}", f"  port = {port}", "",
            "    [workloads.containers.healthcheck]", '    kind = "http"', '    value = "/health"',
            f"    port = {port}"] + volumes


def render(cfg=settings, contract=None) -> str:
    client = {"slug": cfg.get("client", "slug", default="brain") or "brain",
              "name": cfg.get("brain", "name", default="") or cfg.get("client", "name", default="") or "Brain"}
    dep = cfg.deploy
    persistence = set(dep.get("persistence", ()) or ())
    graph, blobs = _role(contract, "graph"), _role(contract, "blobs")
    age = bool(graph and graph["driver"] == "age")
    if age and "postgres" not in persistence:
        raise SystemExit("gen-astrolift: the contract's graph role is age; add postgres to deploy.persistence")
    s3 = blobs if blobs and blobs["driver"] == "s3" else None
    if s3 and "s3" not in persistence:
        raise SystemExit("gen-astrolift: the contract's blobs store is s3; add s3 to deploy.persistence")
    replicas = dep.get("replicas", None) or 1
    slug = f"{client['slug']}-brain"
    lines = [
        "# astrolift.toml — GENERATED by scripts/gen-astrolift.py from client.config.json",
        "# (client.*, deploy.*). Edit the config, not this file. Reference:",
        "# https://astrolift.dev/reference/astrolift-toml/",
        "#",
        "# The brain as an Astrolift app: a container behind the install's login gate",
        "# (a static_site only when deploy.public and no volume), plus the persistence",
        "# deploy.persistence declares. Canon stays in git; every projection is rebuilt",
        "# at deploy time.",
        "",
        "astrolift_version = 1",
        f"name = {_q(slug)}",
        "",
        "[app]",
        f"slug = {_q(slug)}",
        f"display_name = {_q(client['name'] + ' — Brain')}",
        "",
        "[environments.production]",
        "",
    ] + _workload(dep, persistence, int(replicas))
    if "postgres" in persistence:
        lines += ["", "[[managed_services]]", 'kind = "postgres"', 'name = "brain"',
                  "  [managed_services.config]", '  version = "17"', '  size = "small"',
                  "  # exposed as DATABASE_URL — the server-db substrate tier for a graph past edge-db"]
        if age:
            lines += ["  # contract.json graph role = age: the AGE extension for the derived graph projection",
                      "  age = true"]
    if s3:
        lines += ["", f"# s3: blobs store {_q(s3['id'])} (contract.json role blobs) binds by secret-bundle",
                  f"# reference {_q(_secret_ref(cfg, s3['id']))} (brain.stores dsn.secret) only; the bucket",
                  "# and its credentials never appear in this manifest."]
    elif "s3" in persistence:
        lines += ["", "# s3: object storage for blobs (substrate.blobs = s3). Buckets are bound outside",
                  "# the manifest (managed-service binding / secret bundle), never as env credentials."]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Emit astrolift.toml from client.config.json deploy.*")
    parser.add_argument("--contract", help="the brain's knowledge-store contract.json; renders its cell")
    args = parser.parse_args(argv)
    if settings.deploy.get("target", "cloudflare-worker") != "astrolift":
        print("gen-astrolift: deploy.target is not 'astrolift' — no manifest emitted (Worker path).")
        return 0
    contract = None
    if args.contract:
        with open(os.path.join(ROOT, args.contract), encoding="utf-8") as f:
            contract = json.load(f)
    text = render(contract=contract)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"Wrote astrolift.toml ({len(text.splitlines())} lines; persistence: "
          f"{', '.join(sorted(settings.deploy.get('persistence', ()) or ())) or 'none'}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
