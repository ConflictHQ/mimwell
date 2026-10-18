#!/usr/bin/env python3
"""Emit astrolift.toml — deploy this brain onto an Astrolift install (W6/W1.8).

The brain is portable across targets because canon is git and every projection
is rebuildable; the target only decides which projections may exist. On
Cloudflare the portal is one Worker (wrangler.toml, the default). On Astrolift
it is a container workload behind the install's login gate, since a brain is
private: the image `deploy.image` names, or else the engine's portal container
(runtime/portal-container/Dockerfile: the static portal plus the brain's MCP
endpoint at /mcp, #459), built by the platform from this repo. It is a
`statefulset` when a `sqlite-volume` is attached, so each pod owns its claim, a
`deployment` otherwise. Only a brain with
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
and an s3 blobs store binds by a non-resolved `brain.stores[].dsn.secret` or
`dsn.env` location reference. Environment values and credentials are never rendered.
Explicit --native-private-volume selects /srv/brain/_internal for native local
authority volumes; it does not move data. /data remains the
legacy compiled-graph volume placement.

The app is named `<client.slug>-brain`. `deploy.app_slug` names it instead, used
verbatim as `name` and `[app] slug`, so a brain an install registered under any slug
keeps that name; it must be an Astrolift slug (a letter, then lowercase letters, digits
and hyphens, 1 to 63 characters, not ending in a hyphen).

No-op unless client.config.json deploy.target == "astrolift", so a Worker-only
instance never grows a manifest it does not use. Reference:
https://astrolift.dev/reference/astrolift-toml/

Stdlib only. Run from anywhere:  python3 scripts/gen-astrolift.py [--contract PATH]
"""
from __future__ import annotations

import argparse
from collections.abc import Mapping
import json
import os
import re

from config import settings

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "astrolift.toml")
# An Astrolift app slug (a DNS label that starts with a letter); deploy.app_slug must be one.
APP_SLUG = re.compile(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?")
# The engine's portal image, built by the platform when deploy.image names none.
PORTAL_DOCKERFILE = "runtime/portal-container/Dockerfile"


def _q(s: str) -> str:
    return '"' + str(s).replace('\\', '\\\\').replace('"', '\\"') + '"'


def _role(contract, role):
    """One declared role route; ambiguity never selects the first store."""
    matches = [s for s in (contract or {}).get("stores", ()) if role in s["roles"]]
    if len(matches) > 1:
        raise SystemExit(f"gen-astrolift: contract declares more than one {role} store")
    return matches[0] if matches else None


def _location_ref(cfg, store_id):
    """Return a non-resolved secret or environment reference, never its value."""
    entries = cfg.get("brain", "stores", default=()) or ()
    matches = [s for s in entries if isinstance(s, Mapping) and s.get("id") == store_id]
    if len(matches) != 1:
        raise SystemExit(f"gen-astrolift: blobs store {store_id} needs one unambiguous secret-bundle or env location reference")
    dsn = matches[0].get("dsn")
    if not isinstance(dsn, Mapping) or len(dsn) != 1:
        raise SystemExit("gen-astrolift: invalid blob location reference")
    key, value = next(iter(dsn.items()))
    if (key not in ("secret", "env") or not isinstance(value, str) or not 1 <= len(value) <= 512
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or key == "env" and not re.fullmatch(r"[A-Z_][A-Z0-9_]*", value)):
        raise SystemExit("gen-astrolift: invalid blob location reference")
    return key, value


def _app_slug(client, dep):
    """The app's name and slug: deploy.app_slug verbatim when set, else <client.slug>-brain."""
    slug = dep.get("app_slug", None)
    if slug is None:
        return f"{client['slug']}-brain"
    if not isinstance(slug, str) or not APP_SLUG.fullmatch(slug):
        raise SystemExit(f"gen-astrolift: deploy.app_slug {slug!r} is not an Astrolift slug: a letter, then "
                         "lowercase letters, digits and hyphens, 1 to 63 characters, not ending in a hyphen")
    return slug


def _workload(dep, persistence, replicas, *, native_local=False):
    """The portal workload: a CDN static_site only for a public brain with no volume,
    otherwise a container behind the install's login gate carrying the volumes."""
    volumes = []
    if "sqlite-volume" in persistence:
        volumes += ["", "  [[workloads.volumes]]", '  name = "brain-data"', '  kind = "pvc"',
                    f'  mount_path = { _q("/srv/brain/_internal" if native_local else "/data") }',
                    '  size = "5Gi"', '  access_mode = "ReadWriteOnce"',
                    ('  # native authority state; BRAIN_ROOT=/srv/brain and private relative DSN under _internal/'
                     if native_local else '  # app/brain.db (substrate tier: indexed) lives here across deploys')]
    if "efs" in persistence:
        volumes += ["", "  [[workloads.volumes]]", '  name = "brain-shared"', '  kind = "pvc"',
                    '  mount_path = "/shared"', '  size = "20Gi"', '  access_mode = "ReadWriteMany"',
                    '  # blobs (substrate.blobs = efs): recordings, media, exports shared across replicas']
    if dep.get("public", False) and not volumes:
        return ["[[workloads]]", 'name = "portal"', 'kind = "static_site"', f"replicas = {replicas}",
                "is_public = true", 'static_build_command = "make build portal-site"',
                'static_output_dir = "_site"', 'static_index = "index.html"']
    image = dep.get("image", None)
    if image:
        source = [f"  image_ref = {_q(image)}"]
    elif os.path.isfile(os.path.join(ROOT, PORTAL_DOCKERFILE)):
        source = ["  # the portal and its MCP endpoint (/mcp), built from this repo",
                  f"  dockerfile_path = {_q(PORTAL_DOCKERFILE)}", '  build_context = "."']
    else:
        raise SystemExit("gen-astrolift: a private brain (or one with a volume) runs as a container; "
                         f"set deploy.image to the image that serves it, or keep {PORTAL_DOCKERFILE} "
                         "for the platform to build")
    port = int(dep.get("port", None) or 8080)
    kind = "statefulset" if "sqlite-volume" in persistence else "deployment"
    return ["[[workloads]]", 'name = "brain"', f"kind = {_q(kind)}", f"replicas = {replicas}",
            "# exposed on the install's managed subdomain, behind its login gate",
            "is_public = true", "", "  [[workloads.containers]]", '  name = "brain"',
            "  is_primary = true", *source, f"  port = {port}", "",
            "    [workloads.containers.healthcheck]", '    kind = "http"', '    value = "/health"',
            f"    port = {port}"] + volumes


def render(cfg=settings, contract=None, *, native_private_volume=False) -> str:
    client = {"slug": cfg.get("client", "slug", default="brain") or "brain",
              "name": cfg.get("brain", "name", default="") or cfg.get("client", "name", default="") or "Brain"}
    dep = cfg.deploy
    persistence = set(dep.get("persistence", ()) or ())
    graph, blobs = _role(contract, "graph"), _role(contract, "blobs")
    records = _role(contract, "records")
    native_local = bool(records and records.get("id") == (contract or {}).get("authority")
                        and records.get("driver") in ("sqlite", "files"))
    if native_local and not native_private_volume:
        raise SystemExit("gen-astrolift: native local authority requires explicit --native-private-volume; "
                         "review existing volume data before selecting /srv/brain/_internal; no migration is performed")
    if native_private_volume and not native_local:
        raise SystemExit("gen-astrolift: --native-private-volume requires a selected native local authority contract")
    if native_local and "sqlite-volume" not in persistence:
        raise SystemExit("gen-astrolift: a native local authority requires sqlite-volume private persistence")
    age = bool(graph and graph["driver"] == "age")
    if age and "postgres" not in persistence:
        raise SystemExit("gen-astrolift: the contract's graph role is age; add postgres to deploy.persistence")
    s3 = blobs if blobs and blobs["driver"] == "s3" else None
    if s3 and "s3" not in persistence:
        raise SystemExit("gen-astrolift: the contract's blobs store is s3; add s3 to deploy.persistence")
    replicas = dep.get("replicas", None) or 1
    if native_local and replicas != 1:
        raise SystemExit("gen-astrolift: native local authority requires exactly one replica; no independent database copies")
    slug = _app_slug(client, dep)
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
        'kind = "mimwell"',
        f"slug = {_q(slug)}",
        f"display_name = {_q(client['name'] + ' — Brain')}",
        "",
        "[environments.production]",
        "",
    ] + _workload(dep, persistence, int(replicas), native_local=native_local)
    if "postgres" in persistence:
        lines += ["", "[[managed_services]]", 'kind = "postgres"', 'name = "brain"',
                  "  [managed_services.config]", '  version = "17"', '  size = "small"',
                  "  # exposed as DATABASE_URL — the server-db substrate tier for a graph past edge-db"]
        if age:
            lines += ["  # contract.json graph role = age: the AGE extension for the derived graph projection",
                      "  age = true"]
    if s3:
        kind, reference = _location_ref(cfg, s3["id"])
        if kind == "secret":
            lines += ["", f"# s3: blobs store {_q(s3['id'])} (contract.json role blobs) binds by secret-bundle",
                      f"# reference {_q(reference)} (brain.stores dsn.secret) only; the bucket",
                      "# and its credentials never appear in this manifest."]
        else:
            lines += ["", f"# s3: blobs store {_q(s3['id'])} location comes from env reference {_q(reference)}",
                      "# Host supplies s3://<bucket>/<prefix> in that variable and region in AWS_DEFAULT_REGION.",
                      "# Values are not resolved here. Boto3 uses its default credential chain; workload identity is expected.",
                      "# No bucket value, static credential or identity token is emitted by this generator."]
    elif "s3" in persistence:
        lines += ["", "# s3: object storage for blobs (substrate.blobs = s3). Buckets are bound outside",
                  "# the manifest (managed-service binding / secret bundle), never as env credentials."]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Emit astrolift.toml from client.config.json deploy.*")
    parser.add_argument("--contract", help="the brain's knowledge-store contract.json; renders its cell")
    parser.add_argument("--native-private-volume", action="store_true",
                        help="explicitly select /srv/brain/_internal persistence for an existing native local authority; never migrates data")
    args = parser.parse_args(argv)
    if settings.deploy.get("target", "cloudflare-worker") != "astrolift":
        print("gen-astrolift: deploy.target is not 'astrolift' — no manifest emitted (Worker path).")
        return 0
    contract = None
    if args.contract:
        with open(os.path.join(ROOT, args.contract), encoding="utf-8") as f:
            contract = json.load(f)
    text = render(contract=contract, native_private_volume=args.native_private_volume)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"Wrote astrolift.toml ({len(text.splitlines())} lines; persistence: "
          f"{', '.join(sorted(settings.deploy.get('persistence', ()) or ())) or 'none'}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
